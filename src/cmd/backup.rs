//! Creating an archive.
//!
//! The order of work is the order of risk. Everything that can fail cheaply (reading the key,
//! working out the inventory, asking for a passphrase) happens before a single byte is
//! written, so that a run that is going to fail does so before it has touched anything.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::archive::{DOC_MODE, SECRET_MODE, Writer, create_private};
use crate::cli::Create;
use crate::cmd::{Ctx, Scratch, archive_name, file_stamp, fill, iso_stamp, sidecar_path};
use crate::crypt::{self, Encryption};
use crate::db;
use crate::error::{Error, Result};
use crate::git::{self, Git};
use crate::home::NodeState;
use crate::inventory::{self, Inventory};
use crate::key::{Identity, SecretKey};
use crate::manifest::{
    self, IdentityInfo, Manifest, NodeInfo, PolicySummary, RepoSelection, SourceInfo, Tier,
    ToolInfo,
};
use crate::rad::Rad;
use crate::state;
use crate::term;

const RESTORE_DOC: &str = include_str!("../../assets/RESTORE.md");
const RESTORE_SCRIPT: &str = include_str!("../../assets/restore.sh");
const SIDECAR: &str = include_str!("../../assets/sidecar.txt");

/// How long to wait for a node to let go of its control socket after being asked to stop.
const NODE_STOP_TIMEOUT: Duration = Duration::from_secs(20);
const NODE_STOP_POLL: Duration = Duration::from_millis(200);

/// Permissions for the restore script, which is meant to be run straight out of the archive.
const SCRIPT_MODE: u32 = 0o755;

pub fn run(ctx: &Ctx, args: &Create) -> Result<Option<PathBuf>> {
    ctx.home.require()?;
    let home = &ctx.home;
    let term = &ctx.term;

    let identity = Identity::read(home.public_key())?;
    let secret = SecretKey::read(home.secret_key())?;
    let node_id = identity.node_id();

    let tier: Tier = args.tier.into();
    let selection: RepoSelection = args
        .repos
        .map(Into::into)
        .unwrap_or_else(|| args.tier.default_repos());

    let git = Git::new();
    let rad = Rad::new(home.path());
    let rad = rad.is_available().then_some(rad);

    if selection != RepoSelection::None && !git.is_available() {
        return Err(Error::refused(
            "repositories were asked for, but git is not on PATH",
            "install git, or pass --repos none",
        ));
    }

    let mut warnings = Vec::new();
    let node = quiesce(ctx, args, rad.as_ref(), &mut warnings)?;

    term.step("reading policies and inventory");
    let policies = db::read_policies(&home.policies_db())?;
    let routing = db::routing_counts(&home.node_db(), &node_id)?;
    let aliases = db::alias_book(&home.node_db())?;
    let inventory = inventory::collect(
        home,
        &git,
        rad.as_ref(),
        selection,
        &node_id,
        &policies,
        &routing,
    )?;
    warnings.extend(inventory.warnings.iter().cloned());

    let encryption = encryption_for(ctx, args)?;
    let now = jiff::Timestamp::now();
    let destination = destination(args, &identity, home.alias()?.as_deref(), &now, &encryption)?;

    let scratch_parent = args
        .scratch_dir
        .clone()
        .or_else(|| destination.directory())
        .unwrap_or_else(std::env::temp_dir);
    let scratch = Scratch::create(&scratch_parent)?;

    let mut manifest = Manifest {
        format: manifest::FORMAT_VERSION,
        tool: ToolInfo::default(),
        created: iso_stamp(now),
        tier,
        repo_selection: selection,
        identity: IdentityInfo {
            did: identity.did(),
            node_id: node_id.clone(),
            alias: home.alias()?,
            public_key: identity.to_openssh()?,
            fingerprint: identity.fingerprint(),
            key_encrypted: secret.protection().is_encrypted(),
        },
        source: SourceInfo {
            host: hostname(),
            rad_home: home.path().display().to_string(),
            rad_version: rad.as_ref().and_then(|rad| rad.version().ok()),
            git_version: git.version().ok(),
            os: std::env::consts::OS.to_string(),
        },
        node: NodeInfo {
            was_running: node.was_running,
            stopped_by_backup: node.stopped_by_backup,
        },
        entries: Vec::new(),
        repos: inventory.records.clone(),
        policies: PolicySummary {
            seeded: policies.seeded().count(),
            blocked_repos: policies.blocked_repos().count(),
            followed: policies.followed().count(),
            blocked_peers: policies.blocked_peers().count(),
        },
        warnings: Vec::new(),
    };

    let output = destination.open()?;
    let mut writer = Writer::create(output, &encryption)?;

    term.step("archiving the identity");
    writer.add_file("keys/radicle", &home.secret_key(), SECRET_MODE)?;
    writer.add_file("keys/radicle.pub", &home.public_key(), DOC_MODE)?;
    if home.config().is_file() {
        writer.add_file("config.json", &home.config(), DOC_MODE)?;
    } else {
        warnings.push("there is no config.json in this home".to_string());
    }

    if tier != Tier::Identity {
        term.step("archiving policies, aliases and inbox state");
        writer.add_bytes(
            "policies.json",
            &serde_json::to_vec_pretty(&policies)?,
            DOC_MODE,
        )?;
        writer.add_bytes(
            "aliases.json",
            &serde_json::to_vec_pretty(&aliases)?,
            DOC_MODE,
        )?;
        snapshot_into(
            &mut writer,
            &scratch,
            &home.policies_db(),
            "node/policies.db",
        )?;
        snapshot_into(
            &mut writer,
            &scratch,
            &home.notifications_db(),
            "node/notifications.db",
        )?;
        if args.with_node_db {
            snapshot_into(&mut writer, &scratch, &home.node_db(), "node/node.db")?;
        }
    }

    let archived =
        archive_repositories(ctx, &mut writer, &scratch, &git, &inventory, &mut manifest)?;

    let restore_doc = fill(
        RESTORE_DOC,
        &[
            ("CREATED", &manifest.created),
            ("RAD_HOME", &manifest.source.rad_home),
            (
                "HOST",
                manifest.source.host.as_deref().unwrap_or("a machine"),
            ),
            (
                "ALIAS",
                manifest.identity.alias.as_deref().unwrap_or("unnamed"),
            ),
            ("DID", &manifest.identity.did),
            ("FINGERPRINT", &manifest.identity.fingerprint),
        ],
    );
    writer.add_bytes(
        manifest::RESTORE_DOC_ENTRY,
        restore_doc.as_bytes(),
        DOC_MODE,
    )?;
    writer.add_bytes(
        manifest::RESTORE_SCRIPT_ENTRY,
        RESTORE_SCRIPT.as_bytes(),
        SCRIPT_MODE,
    )?;

    manifest.warnings = warnings;
    writer.finish(&mut manifest)?;
    let path = destination.commit()?;

    if let Some(path) = &path {
        write_sidecar(path, &manifest, &encryption, archived)?;
    }
    if node.stopped_by_backup {
        term.step("starting the node again");
        if let Some(rad) = &rad {
            rad.start_node()?;
        }
    }
    if let (Some(path), Some(keep)) = (&path, args.keep) {
        prune(ctx, path, &manifest, keep)?;
    }
    remember(ctx, &manifest, path.as_deref(), &node_id, &encryption);

    report(ctx, &manifest, &inventory, archived, path.as_deref())?;
    Ok(path)
}

/// Record what was written, for `doctor` and `diff` to read later.
///
/// A state file that cannot be written does not undo an archive that can, so this warns and
/// carries on rather than failing a run that has already succeeded.
fn remember(
    ctx: &Ctx,
    manifest: &Manifest,
    path: Option<&Path>,
    node_id: &str,
    encryption: &Encryption,
) {
    let record = state::Record::of(manifest, path, node_id, encryption.is_encrypted());
    if let Err(e) = state::write(&record) {
        ctx.term.warn(&format!(
            "the archive is written, but this tool could not remember it: {e}"
        ));
    }
}

/// What the node was doing, and what we did about it.
struct NodeHandling {
    was_running: bool,
    stopped_by_backup: bool,
}

/// Stop the node if asked, and say so plainly if it is running and we were not.
///
/// Only git storage is at risk from a running node: the databases are snapshotted through
/// SQLite's own backup API, and keys and config do not change. So a running node is a warning
/// with a reason attached, not a refusal.
fn quiesce(
    ctx: &Ctx,
    args: &Create,
    rad: Option<&Rad>,
    warnings: &mut Vec<String>,
) -> Result<NodeHandling> {
    let was_running = ctx.home.node_state() == NodeState::Running;
    if !was_running {
        return Ok(NodeHandling {
            was_running: false,
            stopped_by_backup: false,
        });
    }
    if !args.stop_node {
        warnings.push(
            "the node was running: databases were snapshotted consistently, but a repository \
             fetched during the run may be missing its newest refs"
                .to_string(),
        );
        ctx.term
            .warn("the node is running; pass --stop-node for a guaranteed-clean copy");
        return Ok(NodeHandling {
            was_running: true,
            stopped_by_backup: false,
        });
    }

    let rad = rad.ok_or_else(|| {
        Error::refused(
            "--stop-node was passed but rad is not on PATH",
            "install rad, or stop the node yourself and run again",
        )
    })?;
    ctx.term.step("stopping the node");
    rad.stop_node()?;

    let deadline = Instant::now() + NODE_STOP_TIMEOUT;
    while Instant::now() < deadline {
        if ctx.home.node_state() == NodeState::Stopped {
            return Ok(NodeHandling {
                was_running: true,
                stopped_by_backup: true,
            });
        }
        std::thread::sleep(NODE_STOP_POLL);
    }
    Err(Error::refused(
        "the node is still serving its control socket after being asked to stop",
        "stop it by hand and run again, or run without --stop-node",
    ))
}

fn encryption_for(ctx: &Ctx, args: &Create) -> Result<Encryption> {
    if args.plaintext {
        ctx.term
            .warn("--plaintext: this archive will hold your private key unencrypted");
        return Ok(Encryption::None);
    }
    if !args.recipient.is_empty() {
        return Ok(Encryption::Recipients(args.recipient.clone()));
    }
    let passphrase = crypt::passphrase(
        crypt::PASSPHRASE_ENV,
        ctx.global.passphrase_file.as_deref(),
        "Passphrase for the archive: ",
        true,
        ctx.term.is_interactive(),
    )?;
    Ok(Encryption::Passphrase(passphrase))
}

/// Where the archive is going, and how it gets there safely.
///
/// A file is written under a `.partial` name and renamed once it is complete, so an
/// interrupted run cannot leave something that looks like a usable backup.
enum Destination {
    Stdout,
    File {
        final_path: PathBuf,
        partial: PathBuf,
    },
}

impl Destination {
    fn directory(&self) -> Option<PathBuf> {
        match self {
            Self::Stdout => None,
            Self::File { final_path, .. } => final_path.parent().map(Path::to_path_buf),
        }
    }

    fn open(&self) -> Result<Box<dyn Write>> {
        match self {
            Self::Stdout => Ok(Box::new(std::io::stdout())),
            Self::File { partial, .. } => Ok(Box::new(create_private(partial)?)),
        }
    }

    fn commit(&self) -> Result<Option<PathBuf>> {
        match self {
            Self::Stdout => Ok(None),
            Self::File {
                final_path,
                partial,
            } => {
                std::fs::rename(partial, final_path).map_err(|e| Error::io(final_path, e))?;
                Ok(Some(final_path.clone()))
            }
        }
    }
}

fn destination(
    args: &Create,
    identity: &Identity,
    alias: Option<&str>,
    now: &jiff::Timestamp,
    encryption: &Encryption,
) -> Result<Destination> {
    if args.stdout {
        return Ok(Destination::Stdout);
    }
    let name = archive_name(
        alias,
        &identity.node_id(),
        &file_stamp(*now),
        encryption.is_encrypted(),
    );
    let chosen = args
        .output
        .clone()
        .or_else(|| std::env::var_os("RAD_BACKUP_DIR").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."));

    let final_path = if names_an_archive(&chosen) {
        if let Some(parent) = chosen.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
        }
        chosen
    } else {
        std::fs::create_dir_all(&chosen).map_err(|e| Error::io(&chosen, e))?;
        chosen.join(name)
    };
    let partial = final_path.with_extension("partial");
    Ok(Destination::File {
        final_path,
        partial,
    })
}

/// Whether a path names the archive itself rather than a directory to put it in.
///
/// An existing directory is a directory. Otherwise the extension decides: someone naming a
/// file names it `.tar.zst` or `.age`, and someone naming a directory that does not exist yet
/// does not. Guessing "file" for a bare name is the worse mistake, because it writes what the
/// user reads as a folder as a single archive, and the next run silently replaces it.
fn names_an_archive(path: &Path) -> bool {
    const ARCHIVE_SUFFIXES: [&str; 3] = [".age", ".zst", ".tar"];

    if path.is_dir() {
        return false;
    }
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    ARCHIVE_SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
}

/// Take a consistent copy of a database, then archive that copy.
fn snapshot_into(writer: &mut Writer, scratch: &Scratch, source: &Path, entry: &str) -> Result<()> {
    if !source.is_file() {
        return Ok(());
    }
    let name = source
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "database.db".to_string());
    let copy = scratch.file(&name);
    db::snapshot(source, &copy)?;
    writer.add_file(entry, &copy, SECRET_MODE)?;
    std::fs::remove_file(&copy).map_err(|e| Error::io(&copy, e))?;
    Ok(())
}

/// Bundle each selected repository and record what went in.
fn archive_repositories(
    ctx: &Ctx,
    writer: &mut Writer,
    scratch: &Scratch,
    git: &Git,
    inventory: &Inventory,
    manifest: &mut Manifest,
) -> Result<usize> {
    if inventory.selected.is_empty() {
        return Ok(0);
    }
    ctx.term.step(&format!(
        "bundling {} repositor{}",
        inventory.selected.len(),
        if inventory.selected.len() == 1 {
            "y"
        } else {
            "ies"
        }
    ));

    let mut archived = 0;
    for rid in &inventory.selected {
        let repo = ctx.home.repository_path(rid);
        let bundle = scratch.file("repository.bundle");
        git.bundle(&repo, &bundle)?;

        let entry = git::bundle_entry(rid);
        let stored = writer.add_file(&entry.to_string_lossy(), &bundle, SECRET_MODE)?;
        std::fs::remove_file(&bundle).map_err(|e| Error::io(&bundle, e))?;

        let config = repo.join("config");
        if config.is_file() {
            writer.add_file(&git::config_entry(rid).to_string_lossy(), &config, DOC_MODE)?;
        }

        if let Some(record) = manifest.repos.iter_mut().find(|record| &record.rid == rid) {
            record.bundle = Some(stored);
        }
        archived += 1;
    }
    Ok(archived)
}

fn write_sidecar(
    archive: &Path,
    manifest: &Manifest,
    encryption: &Encryption,
    archived: usize,
) -> Result<()> {
    let file_name = archive
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let manual = match encryption {
        Encryption::None => format!("zstd -dc {file_name} | tar -x"),
        _ => format!("age -d {file_name} | zstd -dc | tar -x"),
    };
    let summary = format!(
        "the {} tier: {} entries, {}, {}",
        manifest.tier.as_str(),
        manifest.entries.len(),
        term::count(archived, "repository", "repositories"),
        term::bytes(manifest.total_bytes())
    );
    let text = fill(
        SIDECAR,
        &[
            ("FILE", &file_name),
            (
                "ALIAS",
                manifest.identity.alias.as_deref().unwrap_or("unnamed"),
            ),
            ("DID", &manifest.identity.did),
            ("CREATED", &manifest.created),
            ("SUMMARY", &summary),
            ("ENCRYPTION", encryption.label()),
            ("MANUAL", &manual),
        ],
    );
    let path = sidecar_path(archive);
    std::fs::write(&path, text).map_err(|e| Error::io(&path, e))
}

/// Delete older archives of the same identity, keeping the newest `keep` of them.
///
/// Only files this tool named, for this identity, in this directory are ever considered. A
/// retention rule that could reach anything else is a deletion bug waiting for a bad argument.
fn prune(ctx: &Ctx, current: &Path, manifest: &Manifest, keep: usize) -> Result<()> {
    let Some(directory) = current.parent() else {
        return Ok(());
    };
    let short: String = manifest.identity.node_id.chars().take(12).collect();
    let alias = manifest.identity.alias.as_deref().unwrap_or("radicle");
    let prefix = format!("{alias}-{short}-");

    let mut archives: Vec<PathBuf> = std::fs::read_dir(directory)
        .map_err(|e| Error::io(directory, e))?
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            let name = path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            name.starts_with(&prefix)
                && (name.ends_with(".tar.zst") || name.ends_with(".tar.zst.age"))
        })
        .collect();
    // The name carries a sortable UTC stamp, so sorting by name is sorting by age.
    archives.sort();

    if archives.len() <= keep {
        return Ok(());
    }
    for path in &archives[..archives.len() - keep] {
        if path == current {
            continue;
        }
        std::fs::remove_file(path).map_err(|e| Error::io(path, e))?;
        let _ = std::fs::remove_file(sidecar_path(path));
        ctx.term.step(&format!(
            "removed the older archive {}",
            path.file_name().unwrap_or_default().to_string_lossy()
        ));
    }
    Ok(())
}

fn report(
    ctx: &Ctx,
    manifest: &Manifest,
    inventory: &Inventory,
    archived: usize,
    path: Option<&Path>,
) -> Result<()> {
    if ctx.global.json {
        let mut value = serde_json::to_value(manifest)?;
        if let (Some(object), Some(path)) = (value.as_object_mut(), path) {
            object.insert(
                "archive".to_string(),
                serde_json::Value::String(path.display().to_string()),
            );
        }
        return ctx.term.print_json(&value);
    }

    let term = &ctx.term;
    term.blank();
    match path {
        Some(path) => term.ok(&format!("wrote {}", path.display())),
        None => term.ok("wrote the archive to stdout"),
    }
    term.hint(&format!(
        "{} ({}), {} entries, {} of content",
        manifest.identity.alias.as_deref().unwrap_or("unnamed"),
        manifest.identity.did,
        manifest.entries.len(),
        term::bytes(manifest.total_bytes())
    ));
    term.hint(&format!(
        "tier {}, repositories {} ({archived} carried), policies {} seeded / {} followed",
        manifest.tier.as_str(),
        manifest.repo_selection.as_str(),
        manifest.policies.seeded,
        manifest.policies.followed
    ));

    if !manifest.identity.key_encrypted {
        term.warn("the archived key has no passphrase of its own");
    }
    let unarchived_private = inventory
        .private()
        .filter(|record| record.bundle.is_none() && !inventory.selected.contains(&record.rid))
        .count();
    if unarchived_private > 0 {
        term.warn(&format!(
            "{unarchived_private} private repositor{} not in this archive and exist nowhere else",
            if unarchived_private == 1 {
                "y is"
            } else {
                "ies are"
            }
        ));
        term.hint("include them with --repos private");
    }
    for warning in &manifest.warnings {
        term.warn(warning);
    }
    if let Some(path) = path {
        term.blank();
        term.hint(&format!("check it: rad-backup verify {}", path.display()));
    }
    Ok(())
}

fn hostname() -> Option<String> {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .or_else(|| std::env::var("HOSTNAME").ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_directory_output_gets_a_generated_name_and_a_file_output_is_taken_as_given() {
        let identity = Identity::parse(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOlfJT4YlvXMI9h98D4SSswNV5S0voNrQaUZMCq0s0zK",
        )
        .expect("the vector parses");
        let now = jiff::Timestamp::from_second(1_786_000_000).expect("a valid instant");

        let into_directory = Create {
            output: Some(PathBuf::from("/tmp")),
            ..blank_create()
        };
        let destination = destination(
            &into_directory,
            &identity,
            Some("maninak"),
            &now,
            &Encryption::None,
        )
        .expect("a directory is a destination");
        match destination {
            Destination::File { final_path, .. } => {
                assert!(final_path.starts_with("/tmp"));
                assert!(
                    final_path
                        .file_name()
                        .expect("it has a name")
                        .to_string_lossy()
                        .starts_with("maninak-z6MkvAFBkdph-")
                );
            }
            Destination::Stdout => panic!("a path is not stdout"),
        }
    }

    #[test]
    fn a_path_is_a_directory_unless_it_is_named_like_an_archive() {
        assert!(names_an_archive(Path::new("/backups/mine.tar.zst")));
        assert!(names_an_archive(Path::new("/backups/mine.tar.zst.age")));
        assert!(names_an_archive(Path::new("mine.age")));
        // The trap this guards: a directory that does not exist yet, named like a directory.
        assert!(!names_an_archive(Path::new("/backups")));
        assert!(!names_an_archive(Path::new("backups/radicle")));
        assert!(!names_an_archive(Path::new("/tmp")));
    }

    #[test]
    fn asking_for_stdout_never_touches_the_filesystem() {
        let identity = Identity::parse(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOlfJT4YlvXMI9h98D4SSswNV5S0voNrQaUZMCq0s0zK",
        )
        .expect("the vector parses");
        let now = jiff::Timestamp::from_second(1_786_000_000).expect("a valid instant");
        let args = Create {
            stdout: true,
            ..blank_create()
        };
        let destination = destination(&args, &identity, None, &now, &Encryption::None)
            .expect("stdout is a destination");
        assert!(matches!(destination, Destination::Stdout));
        assert!(destination.directory().is_none());
    }

    fn blank_create() -> Create {
        Create {
            output: None,
            tier: crate::cli::TierArg::State,
            repos: None,
            stdout: false,
            plaintext: false,
            recipient: Vec::new(),
            stop_node: false,
            with_node_db: false,
            keep: None,
            scratch_dir: None,
        }
    }
}
