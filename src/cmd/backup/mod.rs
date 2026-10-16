//! Creating an archive, with every cheap failure checked before a byte is written.

use std::collections::BTreeSet;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use crate::archives::{self, Fate, Missing, Settings, sidecar_path};
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

/// The mode of the restore script, executable so it runs straight out of the archive.
const SCRIPT_MODE: u32 = 0o755;

/// What a run produced, and whether it produced all of it.
///
/// A run that lost a repository still writes a usable archive, and `is_incomplete` turns the
/// loss into exit 3, which an unattended timer can see.
pub struct Outcome {
    pub path: Option<PathBuf>,
    pub is_incomplete: bool,
}

/// Why an archive is being written, which decides what its manifest says about the source
/// machine's key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// An ordinary backup. The key stays on this machine, and so may a node running it.
    Backup,
    /// A move. This machine's key is retired once the archive is verified, so the restored
    /// home is meant to be the only one holding the identity.
    Move,
    /// A move under `--keep-source`, where this machine keeps its key.
    ///
    /// The archive records that, so the restored home warns about the copy left behind.
    /// Recorded as a plain `Move`, it would announce a forked identity as safe.
    MoveKeepingSource,
}

impl Purpose {
    /// Whether the source machine gives up its key.
    ///
    /// The answer is written into the archive and read on another machine, to decide whether
    /// to warn that two homes hold one identity.
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

    // A retention that would empty the directory is refused before anything is touched
    if let Some(keep) = args.keep {
        crate::cmd::refuse_keep_zero(keep)?;
    }

    // The passphrase is asked before the node stops, so finding it never keeps the node down.
    // A dry run writes no archive and is never asked.
    let encryption = match args.dry_run {
        true => None,
        false => Some(ask_encryption(ctx, args)?),
    };

    let mut node = quiesce(ctx, args, rad.as_ref())?;

    term.step("reading policies and inventory");
    let policies = db::read_policies(&home.policies_db())?;
    let routing = db::read_routing_counts(&home.node_db(), &node_id)?;
    let aliases = db::read_alias_book(&home.node_db())?;
    let (inventory, sight) = inventory::collect_with_sight(
        home,
        &git,
        rad.as_ref(),
        selection,
        inventory::Purpose::Archive,
        &node_id,
        &policies,
        &routing,
    )?;
    // The warnings printed at the end and kept in the archive. A warning already printed as it
    // happened goes into `said`, so the closing report does not repeat it.
    let mut warnings = inventory.warnings.clone();

    if args.dry_run {
        dry_run(ctx, &inventory, tier, selection, &warnings)?;
        // `quiesce` already ran, so a dry run with `--stop-node` did stop the node, and the
        // node must start again before returning
        node.restart();
        return Ok(Outcome {
            path: None,
            is_incomplete: false,
        });
    }

    let encryption = encryption.expect("a run that is not a dry run has returned by now");
    let now = jiff::Timestamp::now();
    // The alias is read once, so the file name and the manifest cannot disagree after an edit
    // to `config.json` between two reads
    let alias = home.read_alias()?;
    let destination = prepare(
        args,
        &identity,
        alias.as_deref(),
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
            alias,
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
        warnings.push(format!(
            "{} does not exist, so the archive has no node settings",
            home.config().display()
        ));
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

    let bundled =
        archive_repositories(ctx, &mut writer, &scratch, &git, &inventory, &mut manifest)?;
    let archived = bundled.archived;
    let dropped = bundled.failures.len();
    let mut said = bundled.failures;

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

    // A count recorded as zero because its table was renamed would mislead a restore, so the
    // manifest carries the warning for whoever reads the archive
    for drift in crate::db::drain_schema_drift() {
        let warning = crate::db::schema_drift_warning(&drift);
        ctx.term.warn(&warning);
        said.push(warning);
    }

    manifest.warnings = warnings.iter().chain(&said).cloned().collect();
    writer.finish(&mut manifest)?;
    let path = destination.commit(&ctx.term)?;

    // A private selection blind to visibility carried none of them, and a timer reading only
    // the exit status must hear about it
    let is_incomplete = dropped > 0 || sight == inventory::PrivateSight::Blind;
    // The note is stricter than the exit status, because a selection judged by refs alone
    // exits 0 and its archive still must not stand in for one judged in full
    let missing = match dropped > 0 || sight != inventory::PrivateSight::Seen {
        true => Missing::Repositories,
        false => Missing::Nothing,
    };

    // The archive is committed, so nothing below may fail the run. The note goes first,
    // because pruning reads it to tell which archives it may delete.
    if let Some(path) = &path
        && let Err(e) = write_sidecar(path, &manifest, &encryption, archived, missing)
    {
        ctx.term.warn(&format!(
            "the archive is written, but its note beside it is not: {e}"
        ));
        // A note an earlier archive left at this path would describe this one wrongly
        let stale = sidecar_path(path);
        if let Some(e) = crate::cmd::prune::unremoved_sidecar(&stale) {
            ctx.term
                .warn(&format!("{} could not be removed: {e}", stale.display()));
        }
    }
    node.restart();
    if let (Some(path), Some(keep)) = (&path, args.keep)
        && let Err(e) = prune(ctx, path, &manifest, keep)
    {
        ctx.term.warn(&format!(
            "the archive is written, but older ones were not swept: {e}"
        ));
    }
    remember(
        ctx,
        &manifest,
        &policies,
        path.as_deref(),
        &node_id,
        &encryption,
    );

    report(
        ctx,
        &manifest,
        &inventory,
        archived,
        path.as_deref(),
        &encryption,
        &warnings,
    )?;
    Ok(Outcome {
        path,
        is_incomplete,
    })
}

/// Prints what a run would carry, and how much, without writing anything.
///
/// The sizes are storage sizes, which over-estimate the compressed bundles. Over is the safe
/// side of "will this fit".
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

    // A dry run honours `--json`, because a consumer handed the human table parses it only as
    // far as the first line
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
    // The estimate runs high on purpose, and an unmeasured part makes it run low, so the
    // unmeasured part is printed
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

/// The bytes a directory occupies, and how many entries under it could not be read.
///
/// The walk follows no symlinks. An unreadable entry is counted, because it is what makes the
/// dry run's estimate run low.
fn directory_size(path: &Path) -> (u64, usize) {
    let Ok(entries) = std::fs::read_dir(path) else {
        return (0, 1);
    };
    let mut bytes = 0;
    let mut unreadable = 0;
    for entry in entries {
        // An entry the directory would not name is one more thing the estimate has not seen
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
            // A symlink, a socket or a fifo, which the archive does not carry either
            Ok(_) => {}
            Err(_) => unreadable += 1,
        }
    }
    (bytes, unreadable)
}

/// Records what was written, for `doctor` and `diff` to read later.
///
/// A failed state write prints a warning and never fails a run whose archive is written.
fn remember(
    ctx: &Ctx,
    manifest: &Manifest,
    policies: &db::Policies,
    path: Option<&Path>,
    node_id: &str,
    encryption: &Encryption,
) {
    let mut record =
        state::Record::from_manifest(manifest, path, node_id, encryption.is_encrypted());
    record.policies = Some(state::PolicySets::of(policies));
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
/// Takes a consistent copy of a database, then archives that copy.
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

/// How many repositories reached the archive, and a reason for each selected one that did not.
struct Bundled {
    archived: usize,
    failures: Vec<String>,
}

/// Bundles each selected repository and records what went in.
fn archive_repositories(
    ctx: &Ctx,
    writer: &mut Writer,
    scratch: &Scratch,
    git: &Git,
    inventory: &Inventory,
    manifest: &mut Manifest,
) -> Result<Bundled> {
    if inventory.selected.is_empty() {
        return Ok(Bundled {
            archived: 0,
            failures: Vec::new(),
        });
    }
    ctx.term.step(&format!(
        "bundling {}",
        crate::term::count(inventory.selected.len(), "repository", "repositories")
    ));

    let mut archived = 0;
    let mut bundle_failures = Vec::new();
    // The index keeps each bundle's lookup cheap, because a seed carries thousands of
    // repositories
    let by_rid: std::collections::BTreeMap<String, usize> = manifest
        .repos
        .iter()
        .enumerate()
        .map(|(at, record)| (record.rid.clone(), at))
        .collect();

    for rid in &inventory.selected {
        let repo_path = ctx.home.repository_path(rid);
        let bundle = scratch.path_of("repository.bundle");
        // One broken repository must not cost the user every other one. Its failure is
        // printed, carried into the manifest and reflected in the exit code.
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

    // The failures go back to `run`, which assigns `manifest.warnings` wholesale before
    // `finish`. Each is printed here, so `run` keeps them out of the report.
    if !bundle_failures.is_empty() {
        ctx.term.warn(&format!(
            "{} of {} could not be bundled and {} NOT in this archive",
            bundle_failures.len(),
            term::count(
                inventory.selected.len(),
                "selected repository",
                "selected repositories"
            ),
            term::is_or_are(bundle_failures.len())
        ));
    }
    Ok(Bundled {
        archived,
        failures: bundle_failures,
    })
}

/// The sidecar's shell command that opens the archive, and the paragraph saying what that
/// command will want.
///
/// `age -d` alone asks for a passphrase, which a recipient archive does not have, so each kind
/// of encryption gets the line that opens it.
fn opening_lines(encryption: &Encryption, file_name: &str) -> (String, String) {
    match encryption {
        Encryption::Plaintext => (
            format!("zstd -dc {file_name} | tar -x"),
            "This archive is not encrypted. Whoever holds the file holds the key inside it."
                .to_string(),
        ),
        Encryption::Passphrase(_) => (
            format!("age -d {file_name} | zstd -dc | tar -x"),
            "Each rad-backup command above asks for the passphrase this archive was sealed with."
                .to_string(),
        ),
        // KEYFILE and PASSFILE carry no angle brackets, because a pasted `<key file>` is a
        // shell redirect whose `>` truncates the archive to nothing
        Encryption::Recipients(recipients) => (
            format!("age -d -i KEYFILE {file_name} | zstd -dc | tar -x"),
            format!(
                "Each rad-backup command above needs --identity KEYFILE, naming the private \
                 half of one of the keys this archive was encrypted to:\n\n{}\n\nAdd \
                 --identity-passphrase-file \
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
    missing: Missing,
) -> Result<()> {
    let settings = Settings::new(manifest.tier.as_str(), manifest.repo_selection.as_str());
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
            ("SETTINGS", settings.note_value()),
            ("MISSING_REPOS", missing.note_value()),
            ("OPENING", &opening),
            ("MANUAL", &manual),
        ],
    );
    // The note is staged and renamed over its path, because writing through a symlink planted
    // at its name truncates the target. The note is owner-only, like the archive.
    crate::perms::write_atomically(&sidecar_path(archive), text.as_bytes(), MODE_SECRET)
}

/// Deletes older archives of the same identity, keeping the newest `keep` and the newest one
/// that holds every selected repository.
///
/// The rule and the listing are `rad backup prune`'s, so a retention means the same thing
/// whichever command enforces it.
fn prune(ctx: &Ctx, current: &Path, manifest: &Manifest, keep: usize) -> Result<()> {
    let Some(directory) = current.parent() else {
        return Ok(());
    };
    let present = archives::in_dir(directory, &manifest.identity.node_id)?;
    let (completeness, unreadable) = archives::completeness(&present);
    for e in &unreadable {
        ctx.term.warn(&format!(
            "could not read {e}. rad-backup cannot tell whether the archive beside that note \
             is missing repositories"
        ));
    }
    for (archive, fate) in present.iter().zip(archives::fates(&completeness, keep)) {
        if archive.path == current || fate == Fate::Kept {
            continue;
        }
        if fate == Fate::Spared {
            ctx.term.step(&format!(
                "kept the older archive {}. No newer archive is known to have everything it \
                 may have",
                archive.name()
            ));
            continue;
        }
        std::fs::remove_file(&archive.path).map_err(|e| Error::io(&archive.path, e))?;
        ctx.term
            .step(&format!("removed the older archive {}", archive.name()));
        // The warning follows the line naming the archive, so it reads as being about it.
        // `prune`'s own helper reports a note left standing over a deleted archive.
        let sidecar = sidecar_path(&archive.path);
        if let Some(e) = crate::cmd::prune::unremoved_sidecar(&sidecar) {
            ctx.term
                .warn(&format!("{} could not be removed: {e}", sidecar.display()));
        }
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
    unsaid: &[String],
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
    // The labels mark these lines as what the archive holds, so they never read as diagnostics
    term.hint(&format!(
        "identity: {} ({})",
        manifest.identity.alias.as_deref().unwrap_or("unnamed"),
        manifest.identity.did,
    ));
    let mut saved = vec!["your key".to_string()];
    if manifest.repo_selection != RepoSelection::None {
        saved.push(match manifest.repo_selection {
            RepoSelection::Private => {
                term::count(archived, "private repository", "private repositories")
            }
            _ => term::count(archived, "repository", "repositories"),
        });
    }
    // Policies show only above the identity tier, because only those tiers carry the policy
    // database
    if manifest.tier != Tier::Identity {
        saved.push(format!(
            "{} seeded and {} followed policies",
            manifest.policies.seeded, manifest.policies.followed
        ));
    }
    let saved = saved.join(", ");
    term.hint(&format!(
        "saved: {saved} ({})",
        term::human_bytes(manifest.total_bytes())
    ));
    term.hint(&format!(
        "settings: --tier {} --repos {}",
        manifest.tier.as_str(),
        manifest.repo_selection.as_str(),
    ));

    // The recipient keys are named here as well as in the note, because this run is the last
    // moment the user can check they still hold a matching private key
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
    // A private repository left out is lost only if no peer holds it. The check reads `bundle`
    // on `manifest.repos`, because a selected repository whose bundle failed is not carried.
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
    // Only what was not printed as it happened. The manifest keeps every one of them.
    for warning in unsaid {
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
        // macOS and the BSDs have neither of the two above, and `uname -n` is POSIX
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

    /// Spelled out per variant, so a new variant answers this on purpose.
    #[test]
    fn only_a_move_that_gives_up_the_key_says_so_in_the_archive() {
        assert!(!Purpose::Backup.retires_key());
        assert!(Purpose::Move.retires_key());
        assert!(!Purpose::MoveKeepingSource.retires_key());
    }

    /// An erroring `read_dir` iterator and an undeterminable `file_type` count in the same
    /// tally, but no fixture reaches them on Linux.
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

    /// A `format!` whose source indentation leaks into the string prints prose followed by
    /// spaces.
    #[test]
    fn the_note_beside_the_archive_is_not_indented_by_the_source_that_wrote_it() {
        let keyed = Encryption::Recipients(vec!["ssh-ed25519 AAAAExample me@laptop".to_string()]);
        let (_, opening) = opening_lines(&keyed, "alice.tar.zst.age");
        for line in opening.lines() {
            // The recipients themselves are indented on purpose, as a block to read down
            assert!(
                !line.starts_with("     ") && line.trim_end() == line,
                "{line:?} carries the layout of the code that built it"
            );
        }
    }
}
