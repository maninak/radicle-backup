//! Creating an archive.
//!
//! The order of work is the order of risk. Everything that can fail cheaply (reading the key,
//! working out the inventory, asking for a passphrase) happens before a single byte is
//! written, so that a run that is going to fail does so before it has touched anything.

use std::collections::BTreeSet;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use crate::archives::sidecar_path;
use crate::cli::Create;
use crate::cmd::{Ctx, Scratch, fill, rfc3339_stamp};
use crate::container::{MODE_DOC, MODE_SECRET, Writer};
use crate::crypt::{self, Encryption};
use crate::db;
use crate::error::{Error, Result};
use crate::git::{self, Git};
use crate::inventory::{self, Inventory};
use crate::key::{Identity, SecretKey};
use crate::manifest::{
    self, IdentityInfo, Manifest, NodeInfo, PolicySummary, RepoSelection, SourceInfo, Tier,
    ToolInfo,
};
use crate::rad::Rad;
use crate::state;
use crate::term;

mod destination;
mod node;

use destination::prepare;
use node::quiesce;

const RESTORE_DOC: &str = include_str!("../../../assets/RESTORE.md");
const RESTORE_SCRIPT: &str = include_str!("../../../assets/restore.sh");
const SIDECAR: &str = include_str!("../../../assets/sidecar.txt");

/// Permissions for the restore script, which is meant to be run straight out of the archive.
const SCRIPT_MODE: u32 = 0o755;

/// What a run produced, and whether it produced all of it.
///
/// `is_incomplete` exists because a backup that lost a repository still writes a usable archive:
/// refusing the whole run over one damaged repository is worse for the user than carrying the
/// rest. So the loss travels out as a flag and becomes exit 3, which is what an unattended
/// timer can actually see. Without it, `rad backup` exited 0 on a run that dropped the one
/// repository nothing else has a copy of.
pub struct Outcome {
    pub path: Option<PathBuf>,
    pub is_incomplete: bool,
}

/// Why an archive is being written, which decides what its manifest says about the fate of the
/// machine writing it.
///
/// An enum rather than a flag on `Create`, because it is not something a user types: it is
/// which of this tool's own commands is asking, and `move` is the only one that answers
/// differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// An ordinary backup. The key stays on this machine, and so may a node running it.
    Backup,
    /// A move. This machine's key is retired once the archive is verified, so the home
    /// restored from it is meant to be the only one holding the identity.
    Move,
    /// A move under `--keep-source`, where this machine keeps its key. The archive says so,
    /// because the home restored from it has to be warned about the copy left behind: written
    /// as a plain `Move` it told the far end "a move retires the key on the machine it came
    /// from" about a machine that still had it, which is the exact fork this tool exists to
    /// prevent, announced as safe.
    MoveKeepingSource,
}

impl Purpose {
    /// Whether the machine this archive is being taken from gives up its key.
    ///
    /// Its own function because the answer is written into the archive and read on another
    /// machine, months later, to decide whether to warn somebody that two homes hold one
    /// identity. Nothing else in a manifest is acted on that far from where it was written.
    fn retires_key(self) -> bool {
        match self {
            Self::Backup | Self::MoveKeepingSource => false,
            Self::Move => true,
        }
    }
}

pub fn run(ctx: &Ctx, args: &Create, purpose: Purpose) -> Result<Outcome> {
    ctx.home.require_identity()?;
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

    // Before anything is stopped or written: a retention that would empty the directory is a
    // refusal, not something to discover after the archive is on disk.
    if let Some(keep) = args.keep {
        crate::cmd::refuse_keep_zero(keep)?;
    }

    // Asked for before the node is stopped, not after. Asking afterwards left the node down
    // for as long as it took somebody to find their passphrase, and a run they then abandoned
    // had stopped it for nothing. A dry run writes no archive, so it is never asked.
    let encryption = match args.dry_run {
        true => None,
        false => Some(ask_encryption(ctx, args)?),
    };

    let mut warnings = Vec::new();
    let mut node = quiesce(ctx, args, rad.as_ref(), &mut warnings)?;

    term.step("reading policies and inventory");
    let policies = db::read_policies(&home.policies_db())?;
    let routing = db::read_routing_counts(&home.node_db(), &node_id)?;
    let aliases = db::read_alias_book(&home.node_db())?;
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

    if args.dry_run {
        dry_run(ctx, &inventory, tier, selection, &warnings)?;
        // `quiesce` already ran, so a dry run with `--stop-node` really did stop the node.
        // Put it back before returning, or `--dry-run` leaves the thing it promised not to
        // touch switched off.
        node.restart();
        return Ok(Outcome {
            path: None,
            is_incomplete: false,
        });
    }

    let encryption = encryption.expect("a run that is not a dry run has returned by now");
    let now = jiff::Timestamp::now();
    let destination = prepare(
        args,
        &identity,
        home.read_alias()?.as_deref(),
        &now,
        &encryption,
        std::io::stdout().is_terminal(),
    )?;

    let scratch_parent = ctx
        .global
        .scratch_dir
        .clone()
        .or_else(|| destination.directory())
        .unwrap_or_else(std::env::temp_dir);
    let scratch = Scratch::create(&scratch_parent)?;

    let mut manifest = Manifest {
        format: manifest::FORMAT_VERSION,
        tool: ToolInfo::default(),
        created: rfc3339_stamp(now),
        tier,
        repo_selection: selection,
        identity: IdentityInfo {
            did: identity.did(),
            node_id: node_id.clone(),
            alias: home.read_alias()?,
            public_key: identity.to_openssh()?,
            fingerprint: identity.fingerprint(),
            key_is_encrypted: secret.protection().is_encrypted(),
        },
        source: SourceInfo {
            host: read_hostname(),
            rad_home: home.path().display().to_string(),
            rad_version: rad.as_ref().and_then(|rad| rad.version().ok()),
            git_version: git.version().ok(),
            os: std::env::consts::OS.to_string(),
            retires_key: Some(purpose.retires_key()),
        },
        node: NodeInfo {
            was_running: node.was_running,
            why_running_is_unknown: node.why_running_is_unknown.clone(),
            was_stopped_by_backup: node.was_stopped_by_backup,
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
    writer.add_file("keys/radicle", &home.secret_key(), MODE_SECRET)?;
    writer.add_file("keys/radicle.pub", &home.public_key(), MODE_DOC)?;
    if home.config().is_file() {
        writer.add_file("config.json", &home.config(), MODE_DOC)?;
    } else {
        warnings.push("there is no config.json in this home".to_string());
    }

    if tier != Tier::Identity {
        term.step("archiving policies, aliases and inbox state");
        writer.add_bytes(
            "policies.json",
            &serde_json::to_vec_pretty(&policies)?,
            MODE_DOC,
        )?;
        writer.add_bytes(
            "aliases.json",
            &serde_json::to_vec_pretty(&aliases)?,
            MODE_DOC,
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

    let bundled = archive_repositories(
        ctx,
        &mut writer,
        &scratch,
        &git,
        &inventory,
        &mut manifest,
        &mut warnings,
    )?;
    let archived = bundled.archived;

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
        MODE_DOC,
    )?;
    writer.add_bytes(
        manifest::RESTORE_SCRIPT_ENTRY,
        RESTORE_SCRIPT.as_bytes(),
        SCRIPT_MODE,
    )?;

    // Drained here rather than at each read, because a file created inside the home is a fact
    // about the whole run and the archive should carry it: a reader of this manifest deserves
    // to know that taking it wrote into a home this tool says it only reads.
    for path in crate::db::drain_touched() {
        let warning = crate::db::touched_warning(&path);
        ctx.term.warn(&warning);
        warnings.push(warning);
    }

    manifest.warnings = warnings;
    writer.finish(&mut manifest)?;
    let path = destination.commit(&ctx.term)?;

    // Past this point the archive exists and is complete, so nothing below may fail the
    // run: a full disk that stopped the sidecar being written used to exit 1 over a good
    // archive, and skip both the state record and the report that names it. The same
    // reasoning `remember` states for itself, applied to everything after the commit.
    if let Some(path) = &path
        && let Err(e) = write_sidecar(path, &manifest, &encryption, archived)
    {
        ctx.term.warn(&format!(
            "the archive is written, but its note beside it is not: {e}"
        ));
    }
    node.restart();
    if let (Some(path), Some(keep)) = (&path, args.keep)
        && let Err(e) = prune(ctx, path, &manifest, keep)
    {
        ctx.term.warn(&format!(
            "the archive is written, but older ones were not swept: {e}"
        ));
    }
    remember(ctx, &manifest, path.as_deref(), &node_id, &encryption);

    report(
        ctx,
        &manifest,
        &inventory,
        archived,
        path.as_deref(),
        &encryption,
    )?;
    Ok(Outcome {
        path,
        is_incomplete: bundled.dropped > 0,
    })
}

/// Say what a run would carry, and how much of it, without writing anything.
///
/// The sizes are what the repositories occupy in storage, not what the bundles will weigh: a
/// bundle is compressed and holds only reachable objects, so the real archive comes out
/// smaller. An over-estimate is the safe direction for "will this fit".
fn dry_run(
    ctx: &Ctx,
    inventory: &Inventory,
    tier: Tier,
    selection: RepoSelection,
    warnings: &[String],
) -> Result<()> {
    let term = &ctx.term;
    let mut total = 0;
    let mut unreadable = 0;
    let mut selected = Vec::new();
    for record in &inventory.records {
        if !inventory.selected.contains(&record.rid) {
            continue;
        }
        let (bytes, missed) = directory_size(&ctx.home.repository_path(&record.rid));
        total += bytes;
        unreadable += missed;
        selected.push((record, bytes));
    }

    // A dry run is a report like every other, and `--json` used to be the one flag it ignored:
    // a consumer asking what a backup would carry got the human table on stdout and no object
    // at all, which is worse than an error because it parses as far as the first line.
    if ctx.global.json {
        let repos: Vec<serde_json::Value> = selected
            .iter()
            .map(|(record, bytes)| {
                serde_json::json!({
                    "rid": record.rid,
                    "name": record.display_name(),
                    "bytes": bytes,
                    "private": record.is_private(),
                })
            })
            .collect();
        return term.print_json(&serde_json::json!({
            "dryRun": true,
            "tier": tier.as_str(),
            "selection": selection.as_str(),
            "repos": repos,
            "bytes": total,
            "warnings": warnings,
        }));
    }

    term.headline(&format!(
        "a {} archive, carrying {} repositories, would hold:",
        tier.as_str(),
        selection.as_str()
    ));
    term.blank();

    for (record, bytes) in &selected {
        term.print(&format!(
            "  {:<40} {:>9}{}",
            record.display_name(),
            term::human_bytes(*bytes),
            if record.is_private() { "  private" } else { "" }
        ))?;
    }
    if selected.is_empty() {
        term.print("  no repositories, only the identity and its paperwork")?;
    }
    term.blank();
    term.ok(&format!(
        "{} selected, about {} of git storage before compression",
        term::count(inventory.selected.len(), "repository", "repositories"),
        term::human_bytes(total)
    ));
    // The estimate is meant to run high, so a part of storage nobody could measure has to be
    // said out loud: silently, it is the one thing that makes the number run low.
    if unreadable > 0 {
        term.warn(&format!(
            "{} could not be measured, so that size is a floor and not an estimate",
            term::count(unreadable, "directory or file", "directories and files")
        ));
    }
    for warning in warnings {
        term.warn(warning);
    }
    term.hint("nothing was written; drop --dry-run to take it");
    Ok(())
}

/// What a directory occupies, and how many directories under it could not be read.
///
/// Following no symlinks and crossing no filesystems it was not pointed at. Used only for the
/// estimate a dry run prints, which over-estimates on purpose because "will this fit" is the
/// question and over is the safe side of it. A directory that cannot be read is the other
/// direction, so it is counted and said rather than silently costing bytes off the total.
fn directory_size(path: &Path) -> (u64, usize) {
    let Ok(entries) = std::fs::read_dir(path) else {
        return (0, 1);
    };
    let mut bytes = 0;
    let mut unreadable = 0;
    for entry in entries {
        // An entry the directory would not even name, which is one more thing this estimate
        // has not seen. Dropped silently, it came off the total as if it were not there.
        let Ok(entry) = entry else {
            unreadable += 1;
            continue;
        };
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => {
                let (under, missed) = directory_size(&entry.path());
                bytes += under;
                unreadable += missed;
            }
            Ok(kind) if kind.is_file() => match entry.metadata() {
                Ok(meta) => bytes += meta.len(),
                Err(_) => unreadable += 1,
            },
            // A symlink, a socket or a fifo. The archive does not carry one either, so it
            // costs nothing and is not something this could not read.
            Ok(_) => {}
            Err(_) => unreadable += 1,
        }
    }
    (bytes, unreadable)
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
    let record = state::Record::from_manifest(manifest, path, node_id, encryption.is_encrypted());
    if let Err(e) = state::write(&record) {
        ctx.term.warn(&format!(
            "the archive is written, but this tool could not remember it: {e}"
        ));
    }
}

fn ask_encryption(ctx: &Ctx, args: &Create) -> Result<Encryption> {
    if args.plaintext {
        ctx.term
            .warn("--plaintext: this archive will hold your private key unencrypted");
        return Ok(Encryption::Plaintext);
    }
    if !args.recipient.is_empty() {
        return Ok(Encryption::Recipients(args.recipient.clone()));
    }
    let passphrase = crypt::read_passphrase(
        crypt::Protects::Archive,
        ctx.global.passphrase_file.as_deref(),
        "Passphrase for the archive: ",
        crypt::Purpose::Sealing,
        ctx.term.is_interactive(),
    )?;
    Ok(Encryption::Passphrase(passphrase))
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
    let copy = scratch.path_of(&name);
    db::snapshot(source, &copy)?;
    writer.add_file(entry, &copy, MODE_SECRET)?;
    std::fs::remove_file(&copy).map_err(|e| Error::io(&copy, e))?;
    Ok(())
}

/// How many repositories reached the archive, and how many were selected but could not.
struct Bundled {
    archived: usize,
    dropped: usize,
}

/// Bundle each selected repository and record what went in.
fn archive_repositories(
    ctx: &Ctx,
    writer: &mut Writer,
    scratch: &Scratch,
    git: &Git,
    inventory: &Inventory,
    manifest: &mut Manifest,
    warnings: &mut Vec<String>,
) -> Result<Bundled> {
    if inventory.selected.is_empty() {
        return Ok(Bundled {
            archived: 0,
            dropped: 0,
        });
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
    let mut bundle_failures = Vec::new();
    // Where each record sits, indexed once, because a scan of `manifest.repos` per bundle is
    // quadratic in the repository count and a seed carries thousands.
    let by_rid: std::collections::BTreeMap<String, usize> = manifest
        .repos
        .iter()
        .enumerate()
        .map(|(at, record)| (record.rid.clone(), at))
        .collect();

    for rid in &inventory.selected {
        let repo_path = ctx.home.repository_path(rid);
        let bundle = scratch.path_of("repository.bundle");
        // One broken repository does not cost the user every other one. A `fatal: bad object`
        // out of `git bundle create` used to abort the whole run, so a home with a single
        // damaged repository could not be backed up at all, which is the opposite of what a
        // backup tool is for. The failure is named, carried into the manifest, and reflected
        // in the exit code, so it can be neither missed nor mistaken for success.
        if let Err(error) = git.bundle(&repo_path, &bundle) {
            ctx.term
                .fail(&format!("{}: {error}", inventory.display_name(rid)));
            bundle_failures.push(format!("{rid} could not be bundled: {error}"));
            let _ = std::fs::remove_file(&bundle);
            continue;
        }

        let entry = git::bundle_entry(rid);
        let stored = writer.add_file(&entry, &bundle, MODE_SECRET)?;
        std::fs::remove_file(&bundle).map_err(|e| Error::io(&bundle, e))?;

        let config = repo_path.join("config");
        if config.is_file() {
            writer.add_file(&git::config_entry(rid), &config, MODE_DOC)?;
        }

        if let Some(record) = by_rid.get(rid).and_then(|at| manifest.repos.get_mut(*at)) {
            record.bundle = Some(stored);
        }
        archived += 1;
    }

    // Into the run's own vec, NOT `manifest.warnings`: `run` assigns that field wholesale
    // just before `finish`, so anything put there here was dropped on the floor and the
    // archive recorded nothing about the repositories it had lost.
    warnings.extend(bundle_failures.iter().cloned());
    if !bundle_failures.is_empty() {
        ctx.term.warn(&format!(
            "{} of {} selected repositories could not be bundled and are NOT in this archive",
            bundle_failures.len(),
            inventory.selected.len()
        ));
    }
    Ok(Bundled {
        archived,
        dropped: bundle_failures.len(),
    })
}

/// The two lines of the sidecar that depend on how the archive was sealed: the shell command
/// that opens it, and the paragraph above it saying what that command will want.
///
/// `age -d` with nothing else asks for a passphrase, which an archive encrypted to a recipient
/// does not have: printed for one of those, the line fails for a reason that reads like the
/// archive is broken. Each kind gets the line that actually opens it.
///
/// Pure, and separate from writing the note, because this is the part that has been wrong
/// twice and the part a test can hold still.
fn opening_lines(encryption: &Encryption, file_name: &str) -> (String, String) {
    match encryption {
        Encryption::Plaintext => (
            format!("zstd -dc {file_name} | tar -x"),
            "This archive is not encrypted. Whoever holds the file holds the key inside it."
                .to_string(),
        ),
        Encryption::Passphrase(_) => (
            format!("age -d {file_name} | zstd -dc | tar -x"),
            "Each of those asks for the passphrase this archive was sealed with.".to_string(),
        ),
        // KEYFILE and PASSFILE, never `<key file>`: a reader pastes these lines into a shell,
        // and `age -d -i <key file> archive.tar.zst.age` is not a template with a placeholder
        // in it, it is an input redirect from `key`, the word `file`, and an OUTPUT redirect
        // that truncates the archive to nothing. The one file holding a key that cannot be
        // reissued must not be destroyed by following its own instructions.
        Encryption::Recipients(recipients) => (
            format!("age -d -i KEYFILE {file_name} | zstd -dc | tar -x"),
            format!(
                "Each of those needs --identity KEYFILE, naming the private half of one of the \
                 keys this archive was encrypted to:\n\n{}\n\nAdd --identity-passphrase-file \
                 PASSFILE when that key has a passphrase of its own, which is a different \
                 secret from an archive passphrase.",
                recipients
                    .iter()
                    .map(|recipient| format!("    {recipient}"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
        ),
    }
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
    let (manual, opening) = opening_lines(encryption, &file_name);
    let summary = format!(
        "the {} tier: {} entries, {}, {}",
        manifest.tier.as_str(),
        manifest.entries.len(),
        term::count(archived, "repository", "repositories"),
        term::human_bytes(manifest.total_bytes())
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
            ("OPENING", &opening),
            ("MANUAL", &manual),
        ],
    );
    let path = sidecar_path(archive);
    std::fs::write(&path, text).map_err(|e| Error::io(&path, e))
}

/// Delete older archives of the same identity, keeping the newest `keep` of them.
///
/// The same rule `rad backup prune` applies, from the same listing, so a retention policy
/// cannot mean two different things depending on which command enforced it.
fn prune(ctx: &Ctx, current: &Path, manifest: &Manifest, keep: usize) -> Result<()> {
    let Some(directory) = current.parent() else {
        return Ok(());
    };
    let archives = crate::archives::in_dir(directory, &manifest.identity.node_id)?;
    for archive in archives.iter().skip(keep) {
        if archive.path == current {
            continue;
        }
        std::fs::remove_file(&archive.path).map_err(|e| Error::io(&archive.path, e))?;
        let _ = std::fs::remove_file(sidecar_path(&archive.path));
        ctx.term
            .step(&format!("removed the older archive {}", archive.name()));
    }
    Ok(())
}

fn report(
    ctx: &Ctx,
    manifest: &Manifest,
    inventory: &Inventory,
    archived: usize,
    path: Option<&Path>,
    encryption: &Encryption,
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
        term::human_bytes(manifest.total_bytes())
    ));
    term.hint(&format!(
        "tier {}, repositories {} ({archived} carried), policies {} seeded / {} followed",
        manifest.tier.as_str(),
        manifest.repo_selection.as_str(),
        manifest.policies.seeded,
        manifest.policies.followed
    ));

    // Named here as well as in the note beside the archive, because the note is read during a
    // recovery and this is read while somebody is still watching. A recipient archive opens
    // with a private key that need not be anywhere near this machine, and this run is the last
    // moment anyone is in a position to go and check they still have it.
    if let Encryption::Recipients(recipients) = encryption {
        term.hint(&format!(
            "opens only with the private half of {}",
            if recipients.len() == 1 {
                "this key"
            } else {
                "one of these keys"
            }
        ));
        for recipient in recipients {
            term.detail(recipient);
        }
    }

    if !manifest.identity.key_is_encrypted {
        term.warn("the archived key has no passphrase of its own");
    }
    // A private repository left out of the archive is only lost if nobody else has it: the
    // owner may have allowed a peer to hold it, and a peer that holds it can hand it back.
    //
    // Judged on what REACHED the archive, not on what was selected for it. `bundle` is set on
    // `manifest.repos`, never on `inventory.records`, so a check against the inventory was a
    // constant, and a repository whose bundle failed stayed in `selected` and counted as
    // carried. The one repository that had just become unrecoverable was the one this warning
    // stayed silent about.
    let carried: BTreeSet<&str> = manifest
        .repos
        .iter()
        .filter(|record| record.bundle.is_some())
        .map(|record| record.rid.as_str())
        .collect();
    let stranded = inventory
        .private()
        .filter(|record| !carried.contains(record.rid.as_str()))
        .filter(|record| !record.has_another_holder())
        .count();
    if stranded > 0 {
        term.warn(&format!(
            "{} not in this archive and on no other node",
            term::count(
                stranded,
                "private repository is",
                "private repositories are"
            )
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

fn read_hostname() -> Option<String> {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .or_else(|| {
            std::env::var("HOSTNAME")
                .ok()
                .filter(|name| !name.is_empty())
        })
        // Neither of the two above exists on macOS or the BSDs, so every manifest written
        // there recorded `host: null` and an archive could not say which machine it came
        // from. `uname -n` is POSIX and answers on all three.
        .or_else(|| {
            crate::exec::Tool::on_path("uname")
                .spoken(&["-n"])
                .ok()
                .map(|said| said.stdout)
                .filter(|name| !name.is_empty())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `--keep-source` was written into the archive as a plain move, so the home restored from
    /// it was told the key on the machine it came from had been retired, about a machine that
    /// still had it. Spelled out per variant, because a fourth one added to the enum has to
    /// answer this question on purpose rather than fall into whichever arm was the default.
    #[test]
    fn only_a_move_that_gives_up_the_key_says_so_in_the_archive() {
        assert!(!Purpose::Backup.retires_key());
        assert!(Purpose::Move.retires_key());
        assert!(!Purpose::MoveKeepingSource.retires_key());
    }

    /// A directory the estimate could not read is what makes it under-estimate, and under is
    /// the wrong side of "will this fit".
    ///
    /// The other two ways an entry goes unread, a `read_dir` iterator that yields an error and
    /// a `file_type` that cannot be determined, are counted in the same tally but are not
    /// reachable from a fixture: on Linux both come from the filesystem giving up mid-walk.
    #[cfg(unix)]
    #[test]
    fn a_directory_the_estimate_could_not_read_is_counted_rather_than_costed_off_the_total() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = std::env::temp_dir().join(format!("rad-backup-size-{}", std::process::id()));
        let shut = root.join("shut");
        std::fs::create_dir_all(&shut).expect("scratch directories are creatable");
        std::fs::write(root.join("kept"), vec![0u8; 512]).expect("scratch file is writable");
        std::fs::write(shut.join("hidden"), vec![0u8; 4096]).expect("scratch file is writable");

        let (open_bytes, open_misses) = directory_size(&root);
        assert_eq!(open_bytes, 512 + 4096);
        assert_eq!(open_misses, 0);

        std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o000))
            .expect("mode is settable");
        let (bytes, missed) = directory_size(&root);
        let walks_through_any_mode = std::fs::read_dir(&shut).is_ok();
        std::fs::set_permissions(&shut, std::fs::Permissions::from_mode(0o700))
            .expect("mode is settable back");

        if !walks_through_any_mode {
            assert_eq!(
                bytes, 512,
                "the unreadable directory costs nothing to the total"
            );
            assert_eq!(missed, 1, "and is counted rather than passed over");
        }

        let _ = std::fs::remove_dir_all(root);
    }

    /// The bug: the recipient line read `age -d -i <key file> archive.tar.zst.age`, which a
    /// shell does not read as a template. `<key` redirects input, `file` is an argument, and
    /// `>archive.tar.zst.age` TRUNCATES the archive. Somebody following the note beside their
    /// only copy of an unreissuable key would have destroyed it.
    #[test]
    fn nothing_the_sidecar_offers_to_run_carries_a_shell_redirect() {
        let sealed = Encryption::Passphrase(zeroize::Zeroizing::new("hunter2".to_string()));
        let keyed = Encryption::Recipients(vec![
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample backup@laptop".to_string(),
        ]);
        for encryption in [Encryption::Plaintext, sealed, keyed] {
            let (manual, _) = opening_lines(&encryption, "alice-z6MkAAA-20260901T000000Z.tar.zst");
            for redirect in ['<', '>'] {
                assert!(
                    !manual.contains(redirect),
                    "{manual:?} would redirect when pasted into a shell"
                );
            }
        }
    }

    /// The other half of the same bug: the paragraph was built from a `format!` whose source
    /// indentation went into the string, so the note printed a line of prose followed by
    /// seventeen spaces. Only the recipient arm was ever wrapped, so only it could drift.
    #[test]
    fn the_note_beside_the_archive_is_not_indented_by_the_source_that_wrote_it() {
        let keyed = Encryption::Recipients(vec!["ssh-ed25519 AAAAExample me@laptop".to_string()]);
        let (_, opening) = opening_lines(&keyed, "alice.tar.zst.age");
        for line in opening.lines() {
            // The recipients themselves are indented on purpose, as a block to read down.
            assert!(
                !line.starts_with("     ") && line.trim_end() == line,
                "{line:?} carries the layout of the code that built it"
            );
        }
    }
}
