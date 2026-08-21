//! Creating an archive.
//!
//! The order of work is the order of risk. Everything that can fail cheaply (reading the key,
//! working out the inventory, asking for a passphrase) happens before a single byte is
//! written, so that a run that is going to fail does so before it has touched anything.

use std::collections::BTreeSet;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::archives::{archive_name, file_stamp, sidecar_path};
use crate::cli::Create;
use crate::cmd::{Ctx, Scratch, fill, iso_stamp};
use crate::container::{DOC_MODE, SECRET_MODE, Writer};
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
use crate::perms::create_private;
use crate::rad::Rad;
use crate::state;
use crate::term::{self, Term};

const RESTORE_DOC: &str = include_str!("../../assets/RESTORE.md");
const RESTORE_SCRIPT: &str = include_str!("../../assets/restore.sh");
const SIDECAR: &str = include_str!("../../assets/sidecar.txt");

/// How long to wait for a node to let go of its control socket after being asked to stop.
const NODE_STOP_TIMEOUT: Duration = Duration::from_secs(20);
const NODE_STOP_POLL: Duration = Duration::from_millis(200);

/// Permissions for the restore script, which is meant to be run straight out of the archive.
const SCRIPT_MODE: u32 = 0o755;

/// What a run produced, and whether it produced all of it.
///
/// `incomplete` exists because a backup that lost a repository still writes a usable archive:
/// refusing the whole run over one damaged repository is worse for the user than carrying the
/// rest. So the loss travels out as a flag and becomes exit 3, which is what an unattended
/// timer can actually see. Without it, `rad backup` exited 0 on a run that dropped the one
/// repository nothing else has a copy of.
pub struct Outcome {
    pub path: Option<PathBuf>,
    pub incomplete: bool,
}

pub fn run(ctx: &Ctx, args: &Create) -> Result<Outcome> {
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

    // Before anything is stopped or written: a retention that would empty the directory is a
    // refusal, not something to discover after the archive is on disk.
    if let Some(keep) = args.keep {
        crate::cmd::refuse_keep_zero(keep)?;
    }

    // Asked for before the node is stopped, not after. Asking afterwards left the node down
    // for as long as it took somebody to find their passphrase, and a run they then abandoned
    // had stopped it for nothing. A rehearsal writes no archive, so it is never asked.
    let encryption = match args.dry_run {
        true => None,
        false => Some(encryption_for(ctx, args)?),
    };

    let mut warnings = Vec::new();
    let mut node = quiesce(ctx, args, rad.as_ref(), &mut warnings)?;

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

    if args.dry_run {
        rehearse(ctx, &inventory, tier, selection, &warnings)?;
        // `quiesce` already ran, so a rehearsal with `--stop-node` really did stop the node.
        // Put it back before returning, or `--dry-run` leaves the thing it promised not to
        // touch switched off.
        node.restart();
        return Ok(Outcome {
            path: None,
            incomplete: false,
        });
    }

    let encryption = encryption.expect("a run that is not a rehearsal has returned by now");
    let now = jiff::Timestamp::now();
    let destination = destination(
        args,
        &identity,
        home.alias()?.as_deref(),
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
        DOC_MODE,
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

    report(ctx, &manifest, &inventory, archived, path.as_deref())?;
    Ok(Outcome {
        path,
        incomplete: bundled.dropped > 0,
    })
}

/// Say what a run would carry, and how much of it, without writing anything.
///
/// The sizes are what the repositories occupy in storage, not what the bundles will weigh: a
/// bundle is compressed and holds only reachable objects, so the real archive comes out
/// smaller. An over-estimate is the safe direction for "will this fit".
fn rehearse(
    ctx: &Ctx,
    inventory: &Inventory,
    tier: Tier,
    selection: RepoSelection,
    warnings: &[String],
) -> Result<()> {
    let term = &ctx.term;
    let mut total = 0;
    let mut selected = Vec::new();
    for record in &inventory.records {
        if !inventory.selected.contains(&record.rid) {
            continue;
        }
        let bytes = directory_size(&ctx.home.repository_path(&record.rid));
        total += bytes;
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
            term::bytes(*bytes),
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
        term::bytes(total)
    ));
    for warning in warnings {
        term.warn(warning);
    }
    term.hint("nothing was written; drop --dry-run to take it");
    Ok(())
}

/// What a directory occupies, following no symlinks and crossing no filesystems it was not
/// pointed at. Used only for the estimate a dry run prints.
fn directory_size(path: &Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    entries
        .filter_map(std::result::Result::ok)
        .map(|entry| match entry.file_type() {
            Ok(kind) if kind.is_dir() => directory_size(&entry.path()),
            Ok(kind) if kind.is_file() => entry.metadata().map(|meta| meta.len()).unwrap_or(0),
            _ => 0,
        })
        .sum()
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

/// A node this run may have stopped, and the promise to put it back.
///
/// A guard rather than a pair of booleans and a call at the end, because `run` has about
/// fifteen `?` sites between the stop and the restart: a passphrase that cannot be read, a
/// repository that changes size mid-read, a full disk. Every one of them used to unwind past
/// the restart and leave a seed offline until somebody noticed. `Drop` runs on all of them.
struct NodeHandling<'a> {
    ctx: &'a Ctx,
    rad: Option<&'a Rad>,
    was_running: bool,
    stopped_by_backup: bool,
}

impl NodeHandling<'_> {
    /// Put the node back now rather than at the end of the scope, for the paths that want to
    /// report it in order. Idempotent: the flag is cleared, so `Drop` then does nothing.
    fn restart(&mut self) {
        if !self.stopped_by_backup {
            return;
        }
        self.stopped_by_backup = false;
        self.ctx.term.step("starting the node again");
        let Some(rad) = self.rad else {
            self.ctx
                .term
                .warn("rad is no longer on PATH, so the node this run stopped is still stopped");
            return;
        };
        if !matches!(rad.start_node(), Ok(true)) {
            self.ctx
                .term
                .warn("`rad node start` failed, so the node this run stopped is still stopped");
            self.ctx.term.detail("start it with `rad node start`");
        }
    }
}

impl Drop for NodeHandling<'_> {
    fn drop(&mut self) {
        self.restart();
    }
}

/// Stop the node if asked, and say so plainly if it is running and we were not.
///
/// Only git storage is at risk from a running node: the databases are snapshotted through
/// SQLite's own backup API, and keys and config do not change. So a running node is a warning
/// with a reason attached, not a refusal.
fn quiesce<'a>(
    ctx: &'a Ctx,
    args: &Create,
    rad: Option<&'a Rad>,
    warnings: &mut Vec<String>,
) -> Result<NodeHandling<'a>> {
    let was_running = ctx.home.node_state() == NodeState::Running;
    if !was_running {
        return Ok(NodeHandling {
            ctx,
            rad,
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
            ctx,
            rad,
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
    // The exit status, not just the spawn. A `rad node stop` that fails outright used to be
    // discarded here, and the run then spent the whole timeout watching a socket that was
    // never going to close before blaming the node for not stopping.
    let stopped = rad.stop_node()?;

    // The guard exists from the moment the stop is asked for, not from the moment it is
    // confirmed. `rad node stop` can succeed and the socket still be up when the deadline
    // passes, and that path returned an error with nothing recorded as owing a restart.
    let mut node = NodeHandling {
        ctx,
        rad: Some(rad),
        was_running: true,
        stopped_by_backup: true,
    };

    // A stop that failed outright is asked about once and no more: there is nothing in
    // flight to wait for, and spending the whole timeout on it only delays the refusal by
    // twenty seconds. A stop that was accepted gets the full deadline, because the node closes
    // its socket when it is done serving and that is not instant.
    let deadline = Instant::now()
        + if stopped {
            NODE_STOP_TIMEOUT
        } else {
            Duration::ZERO
        };
    loop {
        if ctx.home.node_state() == NodeState::Stopped {
            return Ok(node);
        }
        if Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(NODE_STOP_POLL);
    }
    // It never went down, so there is nothing this run stopped and nothing to put back.
    node.stopped_by_backup = false;
    Err(if stopped {
        Error::refused(
            "the node is still serving its control socket after being asked to stop",
            "stop it by hand and run again, or run without --stop-node",
        )
    } else {
        Error::refused(
            "`rad node stop` failed, and the node is still serving its control socket",
            "read what it said above, stop it by hand, or run without --stop-node",
        )
    })
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
    let passphrase = crypt::read_passphrase(
        crypt::PASSPHRASE_ENV,
        ctx.global.passphrase_file.as_deref(),
        "Passphrase for the archive: ",
        crypt::Purpose::Sealing,
        ctx.term.is_interactive(),
    )?;
    Ok(Encryption::Passphrase(passphrase))
}

/// Where the archive is going, and how it gets there safely.
///
/// A file is written under a `.partial` name and renamed once it is complete, so an
/// interrupted run cannot leave something that looks like a usable backup.
///
/// The `.partial` is removed on drop when it was never committed. Nothing lists or prunes
/// those files, so every failed run left one behind: a directory of encrypted-looking rubble
/// beside the real archives, growing without limit and impossible to tell apart by eye.
enum Destination {
    Stdout,
    File {
        final_path: PathBuf,
        partial: PathBuf,
        committed: std::cell::Cell<bool>,
    },
}

impl Drop for Destination {
    fn drop(&mut self) {
        if let Self::File {
            partial, committed, ..
        } = self
            && !committed.get()
        {
            let _ = std::fs::remove_file(partial);
        }
    }
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

    fn commit(&self, term: &Term) -> Result<Option<PathBuf>> {
        match self {
            Self::Stdout => Ok(None),
            Self::File {
                final_path,
                partial,
                committed,
            } => {
                // Flushed is not durable: `Write::flush` on a `File` is a no-op, so without
                // this the rename could land before the bytes and a crash would leave an empty
                // file under the finished name, which is what `.partial` exists to stop.
                // Opened for WRITING, because Windows refuses FlushFileBuffers on a read-only
                // handle, which failed every backup there after the whole archive was written.
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(partial)
                    .and_then(|file| file.sync_all())
                    .map_err(|e| Error::io(partial, e))?;
                std::fs::rename(partial, final_path).map_err(|e| Error::io(final_path, e))?;
                sync_directory(term, final_path.parent());
                committed.set(true);
                Ok(Some(final_path.clone()))
            }
        }
    }
}

/// Fsync the directory, so the rename that just happened survives a crash.
///
/// Unix only: there is no portable way to open a directory as a file, and Windows does not
/// need one, since NTFS orders the rename against the file's own flushed data. A failure is
/// reported rather than swallowed, because the whole point of the rename was durability.
fn sync_directory(term: &Term, directory: Option<&Path>) {
    #[cfg(unix)]
    {
        if let Some(directory) = directory
            && let Err(error) = std::fs::File::open(directory).and_then(|dir| dir.sync_all())
        {
            term.warn(&format!(
                "{}: the directory entry could not be flushed, so a crash now could lose the \
                 archive that was just written ({error})",
                directory.display()
            ));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (term, directory);
    }
}

fn destination(
    args: &Create,
    identity: &Identity,
    alias: Option<&str>,
    now: &jiff::Timestamp,
    encryption: &Encryption,
    stdout_is_terminal: bool,
) -> Result<Destination> {
    if args.stdout {
        // An archive is compressed bytes, and a `--plaintext` one is the key among them. A
        // terminal keeps what it is shown in scrollback that no zeroized buffer can reach, and
        // some emulators log it to disk. Taken as a parameter rather than read here, so both
        // answers are reachable from a test.
        if stdout_is_terminal {
            return Err(Error::refused(
                "an archive is binary, and stdout is a terminal",
                "redirect it to a file or pipe it into something, or drop --stdout",
            ));
        }
        return Ok(Destination::Stdout);
    }
    let name = archive_name(
        alias,
        &identity.node_id(),
        &file_stamp(*now),
        encryption.is_encrypted(),
    );
    let chosen = args.output.clone().unwrap_or_else(|| PathBuf::from("."));

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
        committed: std::cell::Cell::new(false),
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
    let mut failed = Vec::new();
    // Where each record sits, looked up once. Finding it by scanning the whole vec per
    // bundle is a scan per repository, and a seed archiving thousands of them pays for that
    // twice over: once here and once in whatever reads the result.
    let by_rid: std::collections::BTreeMap<String, usize> = manifest
        .repos
        .iter()
        .enumerate()
        .map(|(at, record)| (record.rid.clone(), at))
        .collect();

    for rid in &inventory.selected {
        let repo = ctx.home.repository_path(rid);
        let bundle = scratch.file("repository.bundle");
        // One broken repository does not cost the user every other one. A `fatal: bad object`
        // out of `git bundle create` used to abort the whole run, so a home with a single
        // damaged repository could not be backed up at all, which is the opposite of what a
        // backup tool is for. The failure is named, carried into the manifest, and reflected
        // in the exit code, so it can be neither missed nor mistaken for success.
        if let Err(error) = git.bundle(&repo, &bundle) {
            ctx.term
                .fail(&format!("{}: {error}", inventory.display_name(rid)));
            failed.push(format!("{rid} could not be bundled: {error}"));
            let _ = std::fs::remove_file(&bundle);
            continue;
        }

        let entry = git::bundle_entry(rid);
        let stored = writer.add_file(&entry, &bundle, SECRET_MODE)?;
        std::fs::remove_file(&bundle).map_err(|e| Error::io(&bundle, e))?;

        let config = repo.join("config");
        if config.is_file() {
            writer.add_file(&git::config_entry(rid), &config, DOC_MODE)?;
        }

        if let Some(record) = by_rid.get(rid).and_then(|at| manifest.repos.get_mut(*at)) {
            record.bundle = Some(stored);
        }
        archived += 1;
    }

    // Into the run's own vec, NOT `manifest.warnings`: `run` assigns that field wholesale
    // just before `finish`, so anything put there here was dropped on the floor and the
    // archive recorded nothing about the repositories it had lost.
    warnings.extend(failed.iter().cloned());
    if !failed.is_empty() {
        ctx.term.warn(&format!(
            "{} of {} selected repositories could not be bundled and are NOT in this archive",
            failed.len(),
            inventory.selected.len()
        ));
    }
    Ok(Bundled {
        archived,
        dropped: failed.len(),
    })
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
    // A private repository left out of the archive is only lost if nobody else has it: the
    // owner may have allowed a peer to hold it, and a peer that holds it can hand it back.
    //
    // Judged on what REACHED the archive, not on what was selected for it. `inventory.records`
    // never has its `bundle` set (that field is filled on `manifest.repos`, a different
    // collection), so the old first clause was a constant true, and a repository whose bundle
    // failed stayed in `selected` and was therefore counted as carried. The one repository
    // that had just become unrecoverable was the one this line stayed silent about.
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

fn hostname() -> Option<String> {
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
            false,
        )
        .expect("a directory is a destination");
        match destination {
            Destination::File { ref final_path, .. } => {
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
    fn an_archive_is_refused_to_a_terminal_and_allowed_to_a_pipe() {
        let identity = Identity::parse(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOlfJT4YlvXMI9h98D4SSswNV5S0voNrQaUZMCq0s0zK",
        )
        .expect("the vector parses");
        let now = jiff::Timestamp::from_second(1_786_000_000).expect("a valid instant");
        let args = Create {
            stdout: true,
            ..blank_create()
        };

        // A terminal keeps the bytes in scrollback, so the archive never goes there.
        // `matches!` rather than `expect_err`, which would want Debug on Destination.
        let refused = destination(&args, &identity, None, &now, &Encryption::None, true);
        assert!(
            matches!(refused, Err(Error::Refused { .. })),
            "a terminal should be refused"
        );

        // A pipe or a redirect is the whole point of --stdout and must keep working.
        let allowed = destination(&args, &identity, None, &now, &Encryption::None, false)
            .expect("a pipe is a destination");
        assert!(matches!(allowed, Destination::Stdout));
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
        let destination = destination(&args, &identity, None, &now, &Encryption::None, false)
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
            dry_run: false,
        }
    }
}
