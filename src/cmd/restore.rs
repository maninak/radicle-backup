//! Restores a home by unpacking into staging and installing only what checks out.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::cli::Restore;
use crate::cmd::{Ctx, Scratch};
use crate::container::Reader;
use crate::crypt;
use crate::db::Policies;
use crate::error::{EXIT_CHECKS_FAILED, Error, Result};
use crate::exec::Answer;
use crate::git::{self, Git};
use crate::home::{Home, is_a_link};
use crate::key::{Identity, SecretKey};
use crate::manifest::{Manifest, RepoRecord};
use crate::perms::{copy_doc, copy_secret, set_dir_owner_only};
use crate::rad::{Cached, Rad};
use crate::state;
use crate::term;

// The deadline and interval for `wait_for_node`, which `rad node start` needs because it
// returns before the daemon answers. Both are unix-only, like the socket poll that reads them.
#[cfg(unix)]
const NODE_START_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
#[cfg(unix)]
const NODE_START_POLL: std::time::Duration = std::time::Duration::from_millis(200);

/// How a restored repository stands against what other nodes hold of its signed refs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// No node has said it holds anything other than what the archive holds.
    ///
    /// Agreement is silent. Heartwood rewrites a peer's row only when that peer announces a
    /// different head, so an agreeing row may be the archive's own and proves nothing.
    NothingSaysOtherwise,
    /// The archive holds work that no node answering during this restore has. Push it first.
    ///
    /// This standing can come alongside a row `git` could not read, so it claims only the
    /// nodes that answered.
    ArchiveIsAhead,
    /// The archive holds work the only reporting node lacked, on a row older than the backup.
    ///
    /// The node has had since the backup to pass this copy, and a row that agrees is never
    /// rewritten. The report withholds `rad sync --announce`, which could publish the fork.
    ArchiveIsAheadOfAStaleRecord,
    /// Another node holds signed refs under this identity that the restored copy does not
    /// have. Writing here signs a second history for one peer id, which is the fork.
    PeerHoldsOther,
    /// No node can hold signed refs of this identity for the repository. It is announced to
    /// nobody, delegated to this identity alone, and allowed to nobody.
    ///
    /// The archive's identity document decides this, so a delegate added since the backup is
    /// missed. The report names which repositories earned this standing and why.
    NothingToCompare,
    /// Nothing came back to compare against. The fetch failed, `git` could not answer, or the
    /// node's record could not be read, and a later fetch with the node running may answer.
    ///
    /// A record that was read and holds nothing against this copy is `NothingSaysOtherwise`,
    /// and a repository no node can hold is `NothingToCompare`. A refetch fixes neither.
    CouldNotAsk,
}

impl Standing {
    fn as_str(self) -> &'static str {
        match self {
            Self::NothingSaysOtherwise => {
                "no other node reported work of yours missing from the restored repository"
            }
            Self::ArchiveIsAhead => "holds work the nodes that answered do not have",
            Self::ArchiveIsAheadOfAStaleRecord => {
                "holds work no other node had when the backup was taken"
            }
            Self::PeerHoldsOther => {
                "another node holds work of yours missing from the restored repository"
            }
            Self::NothingToCompare => "nothing to compare it with",
            Self::CouldNotAsk => "could not be compared",
        }
    }

    /// The id a script matches on as `standingId`, frozen once released. `as_str` is wording
    /// and may change. Ids follow the matching list in `restore --json` where one exists.
    fn id(self) -> &'static str {
        match self {
            Self::NothingSaysOtherwise => "nothing-reported-otherwise",
            Self::ArchiveIsAhead => "ahead",
            Self::ArchiveIsAheadOfAStaleRecord => "ahead-of-a-stale-record",
            Self::PeerHoldsOther => "at-risk",
            Self::NothingToCompare => "nothing-to-compare",
            Self::CouldNotAsk => "not-checked",
        }
    }

    /// Ranks standings by what ignoring them costs, so a repository several nodes disagree
    /// about reports the answer that most needs acting on. `Comparison` carries push-first.
    ///
    /// `CouldNotAsk` outranks both benign answers so an unknown never hides behind another
    /// node's agreement. `classify` never produces `NothingToCompare`, so it never folds.
    fn severity(self) -> u8 {
        match self {
            Self::NothingToCompare => 0,
            Self::NothingSaysOtherwise => 1,
            Self::ArchiveIsAheadOfAStaleRecord => 2,
            Self::ArchiveIsAhead => 3,
            Self::CouldNotAsk => 4,
            Self::PeerHoldsOther => 5,
        }
    }

    fn worse_of(self, other: Self) -> Self {
        if other.severity() > self.severity() {
            other
        } else {
            self
        }
    }
}

/// Asks whether to restore through a link at one of the home's own directories, and returns
/// each one with where it led when the user answered.
///
/// Every writer follows such a link, so `keys` aimed elsewhere takes the private key and
/// `storage` takes every repository. `--yes` consents, which a second-disk layout needs. A
/// run with nobody to ask refuses. `--force` never covers writing outside the home.
fn settle_directories_that_point_elsewhere(ctx: &Ctx) -> Result<Vec<Settled>> {
    let elsewhere = ctx.home.directories_that_point_elsewhere();
    if elsewhere.is_empty() {
        return Ok(Vec::new());
    }
    let mut settled = Vec::with_capacity(elsewhere.len());
    for name in &elsewhere {
        let here = ctx.home.path().join(name);
        let there = std::fs::read_link(&here);
        let where_to = match &there {
            Ok(there) => there.display().to_string(),
            Err(e) => format!("a place that could not be read ({e})"),
        };
        ctx.term
            .warn(&format!("{} is a symlink to {where_to}", here.display()));
        settled.push(Settled {
            name,
            leads_to: there.ok(),
        });
    }
    ctx.term.detail(&format!(
        "anything restored through a symlink lands where it leads, not in {}",
        ctx.home.path().display()
    ));
    if ctx.term.confirm("restore through them anyway?")? {
        return Ok(settled);
    }
    // Only a run with nobody to ask is told to pass --yes, never a user who answered `n`
    let (links, them) = match elsewhere.len() {
        1 => ("is a symlink", "it"),
        _ => ("are symlinks", "them"),
    };
    let (why, remedy) = match ctx.term.is_interactive() {
        true => (
            format!("You chose not to restore through {them}."),
            format!("move {them} aside, or restore into a different --home"),
        ),
        false => (
            format!("rad-backup could not ask whether to restore through {them}."),
            format!("pass --yes to restore through {them}, or move {them} aside"),
        ),
    };
    Err(Error::refused(
        format!(
            "{} in {} {links} to somewhere else. {why}",
            term::shortlist(&elsewhere),
            ctx.home.path().display(),
        ),
        remedy,
    ))
}

/// One of the home's own directories that leads elsewhere, and where it led at consent.
///
/// `leads_to` is `None` for a link that could not be resolved, which matches no later reading
/// and so is always refused.
struct Settled {
    name: &'static str,
    leads_to: Option<std::path::PathBuf>,
}

/// Refuses a link at one of the home's own directories that does not lead where it did when
/// the user consented.
///
/// Unpacking takes minutes, and a link swapped mid-run is a question nobody answered, so
/// `--yes` does not cover it. `ci/pins.sh` pins both call sites, since no test can do it.
fn refuse_a_link_that_appeared_mid_restore(home: &Home, settled: &[Settled]) -> Result<()> {
    let elsewhere: Vec<&'static str> = home
        .directories_that_point_elsewhere()
        .into_iter()
        .filter(|name| {
            let leads_to = std::fs::read_link(home.path().join(name)).ok();
            !settled
                .iter()
                .any(|was| was.name == *name && was.leads_to.is_some() && was.leads_to == leads_to)
        })
        .collect();
    if elsewhere.is_empty() {
        return Ok(());
    }
    Err(Error::refused(
        format!(
            "{} in {} changed while the restore was running",
            term::shortlist(&elsewhere),
            home.path().display()
        ),
        "something else is writing to the home you are restoring into. Find out what, then \
         restore again",
    ))
}

pub fn run(ctx: &Ctx, args: &Restore) -> Result<std::process::ExitCode> {
    // The links are settled before the `--words` branch, which also writes a key into `keys`
    let settled = settle_directories_that_point_elsewhere(ctx)?;
    if args.words {
        return crate::cmd::words::restore(ctx).map(|()| std::process::ExitCode::SUCCESS);
    }

    let Some(archive) = &args.archive else {
        return Err(Error::refused(
            "no archive was named",
            "give a path to one, or pass --words to restore from a recovery sheet",
        ));
    };
    let home = &ctx.home;
    let term = &ctx.term;

    // A home whose key `move` retired holds no identity yet still holds every repository, and
    // a restore rewinds all of their refs with a `--force` fetch
    if !args.force {
        if home.holds_identity()? {
            return Err(Error::refused(
                format!("{} already holds an identity", home.path().display()),
                "move it aside, restore into a different --home, or pass --force to overwrite it",
            ));
        }
        let occupied = home.what_a_restore_would_overwrite();
        if !occupied.is_empty() {
            return Err(Error::refused(
                format!(
                    "{} already holds {}, which a restore would overwrite",
                    home.path().display(),
                    occupied.join(", ")
                ),
                "restore into a different --home, or pass --force to overwrite what is there",
            ));
        }
    }
    // Only a node proven stopped passes. An unreachable socket may still belong to a running
    // node, and installing under one corrupts the home.
    let state = home.probe_node_state();
    if !state.is_stopped() {
        return Err(match state.doubt() {
            Some(doubt) => Error::refused(
                format!(
                    "cannot tell whether a node is running for {}: {doubt}",
                    home.path().display()
                ),
                "make sure no node is running, then restore again",
            ),
            None => match home.borrowed_socket() {
                Some(socket) => Error::refused(
                    format!(
                        "a node is running on {}, the socket RAD_SOCKET points to",
                        socket.display()
                    ),
                    "stop that node, or unset RAD_SOCKET if it belongs to another home. Then \
                     restore again",
                ),
                None => Error::refused(
                    format!("the node for {} is running", home.path().display()),
                    "run `rad node stop`, then restore again. A running node can damage your \
                     Radicle data during a restore",
                ),
            },
        });
    }

    // Read now, while the archive is certainly present. After a multi-gigabyte unpack the file
    // may have moved, and a wrong "unencrypted" in the record makes `doctor` fail the archive.
    let encrypted = crypt::looks_encrypted(archive)?;
    let passphrase = crate::cmd::read_archive_passphrase(ctx, archive)?;

    // Staging sits beside the home by default, so the filesystem that has to hold the
    // restored data is the one proven to have room for it before anything is installed
    let parent = ctx.global.scratch_dir.clone().unwrap_or_else(|| {
        home.path()
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    });
    std::fs::create_dir_all(&parent).map_err(|e| Error::io(&parent, e))?;
    let scratch = Scratch::create(&parent)?;
    let staging = scratch.path_of("home");

    term.step(&format!("unpacking {}", archive.display()));
    let scan =
        Reader::open(archive, passphrase.as_ref(), &ctx.identities())?.unpack(archive, &staging)?;

    let problems = scan.mismatches();
    if !problems.is_empty() {
        for problem in &problems {
            term.fail(problem);
        }
        return Err(Error::refused(
            "the files in this archive do not match its own record of them. Nothing was installed",
            "check the file transferred completely, or restore an older archive",
        ));
    }
    let manifest = scan.manifest;
    prove_identity(&staging, &manifest)?;
    term.ok(&format!(
        "the archive holds {} ({})",
        manifest.identity.alias.as_deref().unwrap_or("unnamed"),
        manifest.identity.did
    ));

    // Checked before a byte is written, because exit 4 promises that nothing was written. From
    // inside `replay_policies` it would exit 4 over a home already rewritten.
    if args.replay_policies && !Rad::new(ctx.home.path()).is_available() {
        return Err(Error::refused(
            "--replay-policies needs rad on PATH",
            "install rad, or drop the flag and let the database be copied instead",
        ));
    }

    install(ctx, &staging, &settled)?;
    let restored = restore_repositories(ctx, &staging, &manifest, &settled)?;
    rebuild_caches(ctx, &restored.repos);

    let policies_missed = if args.replay_policies {
        replay_policies(ctx, &staging)?
    } else {
        Vec::new()
    };

    // The record is written before the comparison's error propagates, because the identity,
    // repositories and policies are on disk by now. A failed `rad node start` must not leave a
    // fully restored home that has no record of its archive.
    let comparison = if args.no_reconcile {
        term.warn("--no-reconcile: nothing was compared with the network");
        Ok(nothing_compared(&restored.repos, NetworkCheck::Declined))
    } else {
        reconcile(ctx, &manifest, &restored.repos)
    };
    remember(ctx, &manifest, &restored.repos, archive, encrypted);
    let reconciled = comparison?;

    report(ctx, &manifest, &restored, &reconciled, &policies_missed)
}

/// Records the archive this home came from.
///
/// Without the record, a machine that has only ever restored fails `doctor`'s backup check and
/// gives `diff` nothing to compare against.
fn remember(
    ctx: &Ctx,
    manifest: &Manifest,
    restored: &[RepoRecord],
    archive: &Path,
    is_encrypted: bool,
) {
    let mut record = state::Record::from_manifest(
        manifest,
        Some(archive),
        &manifest.identity.node_id,
        is_encrypted,
    );
    // The archive describes public repositories it did not carry. Recording those as present
    // makes the next `diff` report them as newly missing.
    let present: BTreeSet<String> = restored.iter().map(|repo| repo.rid.clone()).collect();
    record.sigrefs.retain(|rid, _| present.contains(rid));
    record.carried.clone_from(&present);
    record.described = present;
    // The counts come from the installed database, because the manifest's policy summary rides
    // in every tier and `policies.db` only in tiers above `identity`. A database that will not
    // open leaves the manifest's numbers, which is not worth failing a finished restore over.
    if let Ok(installed) = crate::db::read_policies(&ctx.home.policies_db()) {
        record.seeded = installed.seeded().count();
        record.followed = installed.followed().count();
        record.policies = Some(state::PolicySets::of(&installed));
    }
    // `doctor` reads this to warn that another machine may still run this identity. By the
    // time `doctor` runs, the archive and its source machine are gone.
    record.restored = Some(state::Restored {
        source_retires_key: manifest.source.retires_key,
        source_node_was_running: manifest.node.was_running,
        source_node_state_was_guessed: manifest.node.why_running_is_unknown.is_some(),
    });
    if let Err(e) = state::write(&record) {
        ctx.term.warn(&format!(
            "the restore is done, but it could not be recorded: {e}"
        ));
    }
}

/// Refuses a key that is not the one the manifest names, or whose halves are not a pair.
fn prove_identity(staging: &Path, manifest: &Manifest) -> Result<()> {
    let identity = Identity::read(staging.join("keys/radicle.pub"))?;
    describes_this_key(
        &identity.did(),
        &manifest.identity.did,
        &manifest.identity.node_id,
    )?;
    let secret = SecretKey::read(staging.join("keys/radicle"))?;
    if secret.identity()?.did() != manifest.identity.did {
        return Err(Error::refused(
            "the archived private and public keys are not a pair",
            "this archive is inconsistent; do not install it",
        ));
    }
    Ok(())
}

/// Refuses a manifest whose DID or node id is not the key the archive carries.
///
/// The node id picks the namespace the signed-refs comparison reads. One that disagrees makes
/// every repository "nothing to compare", and the restore exits 0 having compared nothing.
fn describes_this_key(did: &str, claimed_did: &str, claimed_node_id: &str) -> Result<()> {
    if did != claimed_did {
        return Err(Error::refused(
            format!("the key in the archive is {did}, but the archive's record says {claimed_did}"),
            "this archive is inconsistent; do not install it",
        ));
    }
    if did.strip_prefix("did:key:") != Some(claimed_node_id) {
        return Err(Error::refused(
            format!(
                "the key in the archive is {did}, but the archive's record names its node \
                 {claimed_node_id}"
            ),
            "this archive is inconsistent; do not install it",
        ));
    }
    Ok(())
}

/// The DID of the key at `path`, when a readable one is there.
fn read_did_at(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    crate::key::Identity::parse(&text).ok().map(|id| id.did())
}

/// Moves a private key that is not the archive's aside, once the user confirms, and leaves a
/// note beside it saying what it is.
///
/// Fails closed. A home whose public key is missing or unreadable cannot be shown to hold the
/// archive's identity, so its key is treated as a different one.
fn retire_any_displaced_key(ctx: &Ctx, staging: &Path) -> Result<()> {
    let existing = ctx.home.secret_key();
    if !existing.exists() {
        return Ok(());
    }

    let here = read_did_at(&ctx.home.public_key());
    let incoming = read_did_at(&staging.join("keys/radicle.pub"));
    // Equal DIDs prove the archive carries the key already here, so nothing is displaced, and
    // retiring it would file a fresh copy of the key on every restore
    if let (Some(here), Some(incoming)) = (&here, &incoming)
        && here == incoming
    {
        return Ok(());
    }

    match (&here, &incoming) {
        (Some(here), Some(incoming)) => ctx.term.warn(&format!(
            "{} holds {here}, and this archive holds {incoming}",
            ctx.home.path().display()
        )),
        _ => ctx.term.warn(&format!(
            "{} holds a key that could not be read, so it may not be the one in this archive",
            ctx.home.path().display()
        )),
    }
    if !ctx
        .term
        .confirm("Restore over the key that is already there?")?
    {
        return Err(Error::refused(
            "the home holds a key this archive does not account for",
            "restore into a different --home, or pass --yes if replacing it is the intent",
        ));
    }

    let to = crate::cmd::migrate::retired_path(&ctx.home.keys_dir());
    std::fs::rename(&existing, &to).map_err(|e| Error::io(&existing, e))?;
    // The public half goes with it. Without it the retired file is a private key nobody can
    // identify, and `install` overwrites keys/radicle.pub moments later.
    let public = ctx.home.public_key();
    let mut kept = None;
    if public.exists() {
        // `.pub` is appended, never set with `with_extension`, which turns `radicle.retired`
        // into `radicle.pub` and `radicle.retired.2` into the first retirement's public half
        let mut public_to = to.as_os_str().to_os_string();
        public_to.push(".pub");
        let public_to = std::path::PathBuf::from(public_to);
        match std::fs::rename(&public, &public_to) {
            Ok(()) => kept = Some(public_to),
            Err(error) => ctx.term.warn(&format!(
                "{}: the public half of the displaced key could not be kept ({error})",
                public.display()
            )),
        }
    }
    write_displaced_note(ctx, &to, here.as_deref(), kept.as_deref())?;
    ctx.term
        .step(&format!("kept the displaced key as {}", to.display()));
    Ok(())
}

/// Appends a note to `keys/DISPLACED.txt` saying what the displaced key beside it is.
fn write_displaced_note(
    ctx: &Ctx,
    retired: &Path,
    former_did: Option<&str>,
    public: Option<&Path>,
) -> Result<()> {
    let name = retired
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    // The public half is named only when it exists, because a missing file sends the reader
    // hunting, and `ssh-keygen -y` re-derives it from the private key anyway
    let half = match public.and_then(Path::file_name) {
        Some(name) => format!(", and its public half as {}", name.to_string_lossy()),
        None => String::new(),
    };
    let note = format!(
        "A restore on {} put another identity into {}.\n\
         \n\
         The key that used to be at keys/radicle is now beside this note as {name}{half}.\n\
         It was {}.\n\
         \n\
         It still works. Put it back only into a home of its own, and never start a node with\n\
         it while another machine is running one under the same peer id.\n",
        crate::cmd::rfc3339_stamp(jiff::Timestamp::now()),
        ctx.home.path().display(),
        former_did.unwrap_or("an identity this tool could not read"),
    );
    let path = ctx.home.keys_dir().join("DISPLACED.txt");
    // The note appends, because `retired_path` never reuses a freed name. A second
    // displacement leaves `radicle.retired` and `radicle.retired.2`, each with its paragraph.
    let existing = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(Error::io(&path, e)),
    };
    crate::perms::write_atomically(
        &path,
        appended(&existing, &note).as_bytes(),
        crate::perms::MODE_DOC,
    )
}

/// Joins notes oldest first, with a blank line between them.
fn appended(existing: &str, note: &str) -> String {
    if existing.is_empty() {
        return note.to_string();
    }
    // Every note ends in a newline, so one more makes the blank line
    format!("{existing}\n{note}")
}

/// Moves the identity, the config and the databases into place.
fn install(ctx: &Ctx, staging: &Path, settled: &[Settled]) -> Result<()> {
    let home = &ctx.home;
    // Asked again after the unpack, which takes long enough for a node to start. A node
    // writing to the home while its databases are copied over corrupts both.
    refuse_a_link_that_appeared_mid_restore(home, settled)?;
    let state = home.probe_node_state();
    if !state.is_stopped() {
        return Err(match state.doubt() {
            Some(doubt) => Error::refused(
                format!(
                    "cannot tell whether a node started for {} while the archive was \
                     unpacking: {doubt}",
                    home.path().display()
                ),
                "make sure no node is running, then restore again. Nothing has been written yet",
            ),
            None => match home.borrowed_socket() {
                Some(socket) => Error::refused(
                    format!(
                        "a node started on {} while the archive was unpacking. RAD_SOCKET \
                         points to that socket",
                        socket.display()
                    ),
                    "stop that node, or unset RAD_SOCKET if it belongs to another home. Then \
                     restore again. Nothing has been written yet",
                ),
                None => Error::refused(
                    format!(
                        "the node for {} started while the archive was unpacking",
                        home.path().display()
                    ),
                    "run `rad node stop` and restore again. Nothing has been written yet",
                ),
            },
        });
    }
    for directory in [home.path().to_path_buf(), home.keys_dir(), home.node_dir()] {
        std::fs::create_dir_all(&directory).map_err(|e| Error::io(&directory, e))?;
    }
    set_dir_owner_only(home.path())?;

    retire_any_displaced_key(ctx, staging)?;
    copy_secret(&staging.join("keys/radicle"), &home.secret_key())?;
    copy_doc(&staging.join("keys/radicle.pub"), &home.public_key())?;
    copy_doc(&staging.join("config.json"), &home.config())?;
    copy_secret(&staging.join("node/policies.db"), &home.policies_db())?;
    copy_secret(
        &staging.join("node/notifications.db"),
        &home.notifications_db(),
    )?;
    copy_secret(&staging.join("node/node.db"), &home.node_db())?;

    ctx.term.ok(&format!(
        "installed the identity into {}",
        home.path().display()
    ));
    Ok(())
}

/// The repository config settings a restore takes out of an archive.
///
/// Git RUNS the values of settings such as `core.fsmonitor`, `core.pager` and an `ext::`
/// remote url, and an archive is a file somebody handed you. The rest of a real Radicle
/// storage config is `CONFIG_FROM_INIT`, which leaves the node's own name and DID.
const CONFIG_ALLOWED: &[&str] = &["user.email", "user.name"];

/// The settings `git init` works out for itself, which a restore drops without a warning.
///
/// These describe the filesystem the repository is on now, so an archive's values can only be
/// wrong or hostile. An honest archive carries three of them, and warning on those buries the
/// warning that matters.
///
/// `extensions.objectformat` stays here because a sha256 bundle already fails to unbundle into
/// the sha1 repository `git init` made. Revisit if Radicle storage moves off sha1.
const CONFIG_FROM_INIT: &[&str] = &[
    "core.bare",
    "core.filemode",
    "core.ignorecase",
    "core.logallrefupdates",
    "core.precomposeunicode",
    "core.repositoryformatversion",
    "core.symlinks",
    "extensions.compatobjectformat",
    "extensions.objectformat",
];

/// The settings kept from an archived repository config, and the names of those dropped.
struct AllowedConfig {
    kept: Vec<(String, String)>,
    /// Names of the dropped settings, so the user can judge whether one mattered. Settings in
    /// `CONFIG_FROM_INIT` are never listed, so an honest archive names nothing.
    dropped: Vec<String>,
}

/// Splits the output of `git config --list -z` into the allowlisted settings and the names
/// of the rest.
///
/// Git's own listing resolves quoting, continuations and case folding, so this reader and the
/// shipped restore script, which asks git the same question, agree by construction. Each entry
/// is `name\nvalue\0`, and a setting with no value prints its name alone and is dropped.
fn allowed_config(listed: &str) -> AllowedConfig {
    let mut kept = Vec::new();
    let mut dropped = Vec::new();
    for entry in listed.split('\0').filter(|entry| !entry.is_empty()) {
        match entry.split_once('\n') {
            Some((name, value)) if CONFIG_ALLOWED.contains(&name) => {
                kept.push((name.to_string(), value.to_string()));
            }
            Some((name, _)) if CONFIG_FROM_INIT.contains(&name) => {}
            Some((name, _)) => dropped.push(name.to_string()),
            None if CONFIG_FROM_INIT.contains(&entry) => {}
            None => dropped.push(entry.to_string()),
        }
    }
    dropped.sort();
    dropped.dedup();
    AllowedConfig { kept, dropped }
}

/// Rebuild the cache `rad issue list` and `rad patch list` read, for every restored
/// repository. Failures only warn, because every repository is already on disk.
fn rebuild_caches(ctx: &Ctx, restored: &[RepoRecord]) {
    if restored.is_empty() {
        return;
    }
    let home = format!("RAD_HOME='{}'", ctx.home.path().display());
    let by_hand = &format!(
        "run `{home} rad cob migrate`, then `{home} rad issue cache --repo <rid>` and \
         `{home} rad patch cache --repo <rid>` for each repository"
    );
    let rad = Rad::new(ctx.home.path());
    if !rad.is_available() {
        ctx.term.warn(&format!(
            "{}, so your issues and patches will not show yet",
            crate::exec::rad_missing(crate::exec::rad_override_from_env().as_deref())
        ));
        ctx.term.detail(by_hand);
        return;
    }
    ctx.term.step(&format!(
        "rebuilding the lists of issues and patches of {}",
        term::count(restored.len(), "repository", "repositories")
    ));
    if let Some(why) = rad.migrate_cobs().unwrap_or_else(|e| Some(e.one_line())) {
        ctx.term.warn("your issues and patches will not show yet");
        ctx.term.detail(&format!("`rad cob migrate` failed: {why}"));
        ctx.term.detail(by_hand);
        return;
    }
    let mut failed = Vec::new();
    for repo in restored {
        for kind in Cached::ALL {
            if let Some(why) = rad
                .recache(kind, &repo.rid)
                .unwrap_or_else(|e| Some(e.one_line()))
            {
                failed.push(format!("{}, {}: {why}", repo.display_name(), kind.noun()));
            }
        }
    }
    if !failed.is_empty() {
        ctx.term.warn("some issues or patches will not show yet");
        for line in &failed {
            ctx.term.detail(line);
        }
        ctx.term.detail(by_hand);
    }
}

/// What came back out of the bundles, and what did not.
struct Restored {
    repos: Vec<RepoRecord>,
    /// Repositories the archive carried that are not in the home now. Tracked explicitly, so a
    /// restore that lost one cannot report success.
    dropped: Vec<String>,
}

/// The warning a restore gives about the object check before opening the first bundle, if any.
///
/// A git too old to check objects on a bundle accepts the setting and ignores it. `None` from
/// the version reader means the version is unknown, which is a weaker claim than "did not
/// check". The function is pure so tests can see all three answers on any one machine.
fn bundle_check_notice(reaches: Option<bool>) -> Option<(String, Option<String>)> {
    match reaches {
        Some(true) => None,
        Some(false) => Some((
            "the installed git cannot check the archived repositories for damage. They are \
             restored without that check"
                .to_string(),
            Some(format!(
                "git {}.{} or newer checks them. Until then, restore only archives you trust",
                crate::git::FSCK_ON_A_BUNDLE_SINCE.0,
                crate::git::FSCK_ON_A_BUNDLE_SINCE.1
            )),
        )),
        None => Some((
            "the git version could not be read, so the objects inside each bundle may not be \
             checked"
                .to_string(),
            None,
        )),
    }
}

/// Rebuilds each archived repository from its bundle.
///
/// A repository that fails to restore is reported and skipped, so one malformed object in old
/// history does not cost every repository after it, the state record and the report.
fn restore_repositories(
    ctx: &Ctx,
    staging: &Path,
    manifest: &Manifest,
    settled: &[Settled],
) -> Result<Restored> {
    let carried: Vec<&RepoRecord> = manifest
        .repos
        .iter()
        .filter(|repo| repo.bundle.is_some())
        .collect();
    if carried.is_empty() {
        return Ok(Restored {
            repos: Vec::new(),
            dropped: Vec::new(),
        });
    }

    let git = Git::new();
    if !git.is_available() {
        ctx.term
            .warn("git is not on PATH, so no repositories were restored");
        // The staging directory is not offered, because it lives in this run's scratch and is
        // deleted on exit. The archive still holds the bundles.
        ctx.term
            .detail("the identity and its policies are in place");
        ctx.term.detail(
            "install git and run this same restore again, or follow RESTORE.md inside \
                     the archive itself",
        );
        return Ok(Restored {
            repos: Vec::new(),
            dropped: carried.iter().map(|repo| repo.rid.clone()).collect(),
        });
    }

    // Said once, before the first bundle, and only when there is a bundle to open
    if let Some((warning, detail)) = bundle_check_notice(git.fsck_reaches_a_bundle()) {
        ctx.term.warn(&warning);
        if let Some(detail) = detail {
            ctx.term.detail(&detail);
        }
    }

    // Asked a third time, because a link planted at `storage` after `install` asked is one
    // this `create_dir_all` would walk straight through
    refuse_a_link_that_appeared_mid_restore(&ctx.home, settled)?;
    let storage = ctx.home.storage();
    std::fs::create_dir_all(&storage).map_err(|e| Error::io(&storage, e))?;
    ctx.term.step(&format!(
        "restoring {}",
        term::count(carried.len(), "repository", "repositories")
    ));

    let mut restored = Vec::new();
    let mut dropped = Vec::new();
    for repo in carried {
        match restore_one(ctx, &git, staging, repo) {
            Ok(()) => restored.push(repo.clone()),
            Err(e) => {
                ctx.term
                    .fail(&format!("{} could not be restored", repo.display_name()));
                ctx.term.detail(&e.to_string());
                dropped.push(repo.rid.clone());
            }
        }
    }
    Ok(Restored {
        repos: restored,
        dropped,
    })
}

/// Restores one repository, leaving the caller to decide what a failure costs.
fn restore_one(ctx: &Ctx, git: &Git, staging: &Path, repo: &RepoRecord) -> Result<()> {
    let bundle = staging.join(git::bundle_entry(&repo.rid));
    let target = ctx.home.repository_path(&repo.rid);
    // A link at the repository's own name is refused before anything resolves it. `exists`
    // follows a link, `git init --bare` initialises wherever it points, and the archive names
    // the repository, so whoever wrote it knows which name to plant.
    if is_a_link(&target) {
        return Err(Error::refused(
            format!(
                "{} is a symlink, so this repository would be restored outside the home",
                target.display()
            ),
            "move it aside, or restore into a different --home",
        ));
    }
    // Under `--force` the home can hold a copy this run did not create, and a failed unbundle
    // must not delete it
    let existed = target.exists();

    let put_back = || -> Result<()> {
        git.init_bare(&target)?;
        git.unbundle(&target, &bundle)?;
        if let Some(head) = &repo.head {
            // A bad HEAD is skipped, as the shipped script does, because the history is
            // already unbundled and a wrong pointer must not cost the refs it points at
            if git::names_a_ref(head) {
                git.set_head(&target, head)?;
            } else {
                // A warning and not a failed check, because git rebuilds `HEAD` from the
                // default branch and no signed history rides on it
                ctx.term.warn(&format!(
                    "{}: `{head}` does not name a ref, so it came back without its HEAD",
                    repo.display_name()
                ));
            }
        }
        let config = staging.join(git::config_entry(&repo.rid));
        if config.is_file() {
            match git.config_listing(&config)? {
                Some(listed) => {
                    let allowed = allowed_config(&listed);
                    if !allowed.dropped.is_empty() {
                        let dropped: Vec<&str> =
                            allowed.dropped.iter().map(String::as_str).collect();
                        ctx.term.warn(&format!(
                            "{}: {} left out of the restored config",
                            repo.display_name(),
                            term::shortlist(&dropped)
                        ));
                        ctx.term.detail(
                            "a config can make git run commands, so a restore keeps only \
                             user.name and user.email",
                        );
                    }
                    for (name, value) in &allowed.kept {
                        if let Some(why) = git.set_config(&target, name, value)? {
                            ctx.term.warn(&format!(
                                "{}: `{name}` could not be restored from the archive's config: \
                                 {why}",
                                repo.display_name()
                            ));
                        }
                    }
                }
                // The repository keeps the working config `git init` gave it, so a config the
                // archive mangled costs a line and not a repository
                None => ctx.term.warn(&format!(
                    "{}: the config in the archive could not be read, so its name and DID \
                     did not come back",
                    repo.display_name()
                )),
            }
        }
        Ok(())
    };

    match put_back() {
        Ok(()) => Ok(()),
        Err(e) => {
            // An empty bare repository left behind would be counted and archived, and `rad`
            // would read it as a repository with no history
            if !existed
                && let Err(swept) = std::fs::remove_dir_all(&target)
                // No directory exists to sweep when `git init` itself failed
                && swept.kind() != std::io::ErrorKind::NotFound
            {
                ctx.term.detail(&format!(
                    "the partly restored {} could not be removed either: {swept}",
                    target.display()
                ));
            }
            Err(e)
        }
    }
}

/// What a whole run's comparison found.
///
/// `ahead_of_someone` is a second answer per repository, which a single standing cannot
/// carry. See `Comparison`.
#[derive(Default)]
struct Reconciled {
    standings: BTreeMap<String, Standing>,
    ahead_of_someone: BTreeSet<String>,
    wanted: NetworkCheck,
}

/// Whether this run meant to ask the network anything.
///
/// A repository nothing came back for costs the exit code, unless `--no-reconcile` asked for
/// no comparison. The standings look the same either way, so the intent is carried here.
#[derive(Default, Debug, PartialEq, Eq)]
enum NetworkCheck {
    /// The run put the repositories to the network, or tried to.
    #[default]
    Wanted,
    /// Nothing was compared, as `--no-reconcile` asked.
    Declined,
}

/// Compares each restored repository with what other nodes hold of its signed refs.
///
/// Signed refs are a chain. Writing on top of an archived copy that is behind the network
/// signs a second history for the user's own namespace, a fork that never resolves. The fetch
/// only makes the node's record current, and `classify` reads the verdict from that record.
fn reconcile(ctx: &Ctx, manifest: &Manifest, restored: &[RepoRecord]) -> Result<Reconciled> {
    if restored.is_empty() {
        return Ok(Reconciled::default());
    }
    let node_id = &manifest.identity.node_id;

    let rad = Rad::new(ctx.home.path());
    if !rad.is_available() {
        ctx.term.warn(&format!(
            "{}, so nothing was compared with the network",
            crate::exec::rad_missing(crate::exec::rad_override_from_env().as_deref())
        ));
        ctx.term.detail(
            "install rad. Before you write, clone each repository into a new, empty RAD_HOME \
                 to check what the network holds",
        );
        return Ok(nothing_compared(restored, NetworkCheck::Wanted));
    }
    let mut standings = Reconciled::default();

    // The baseline is the home's record before the node started below writes to it, never
    // staging's, because `node.db` rides in an archive only under `--with-node-db`. An empty
    // baseline reads stale rows as fresh, and the report asks for an announce that could
    // publish a fork. A fresh node replays a day of gossip, an old one months
    // (`INITIAL_SUBSCRIBE_BACKLOG_DELTA`). Revisit if heartwood makes either window unbounded.
    let baseline = match crate::db::read_synced_heads(&ctx.home.node_db(), node_id) {
        Ok(baseline) => Some(baseline),
        Err(e) => {
            ctx.term.warn(&format!(
                "rad-backup could not read what your node recorded before the restore ({e}). \
                 It will not list any repository as holding work to announce."
            ));
            None
        }
    };
    // Restore refuses to begin under a running node and the comparison needs one, so the node
    // is started here and stopped afterwards. It starts only when known to be down, because a
    // second node on one key is the fork this comparison exists to prevent.
    let started_here = if !ctx.home.probe_node_state().is_stopped() {
        false
    } else {
        ctx.term
            .step("starting the node to compare the restored repositories with the network");
        // Reported, never propagated, because the identity, repositories and policies are on
        // disk and an escaping error would lose the report of what did not come back
        let started = match rad.start_node() {
            Ok(started) => started,
            Err(e) => {
                ctx.term
                    .warn(&format!("`rad node start` could not be run: {e}"));
                false
            }
        };
        if !started || !wait_for_node(ctx) {
            ctx.term
                .warn("the node would not start, so nothing was compared with the network");
            ctx.term.detail(
                "before you write, clone each repository into a new, empty RAD_HOME to check \
                     what the network holds",
            );
            return Ok(nothing_compared(restored, NetworkCheck::Wanted));
        }
        true
    };

    compare_with_network(
        ctx,
        manifest,
        restored,
        baseline.as_ref(),
        &rad,
        &mut standings.standings,
        &mut standings.ahead_of_someone,
    );

    if started_here {
        ctx.term.step("stopping the node again");
        // Reported, never propagated, because the standings are this function's answer and a
        // failed stop must not stand in front of them
        if !matches!(rad.stop_node(), Ok(true)) {
            ctx.term
                .warn("the node started for this check would not stop");
            ctx.term
                .detail("stop it with `rad node stop` if you meant it to stay down");
        }
    }
    Ok(standings)
}

/// Whether the node answered on its control socket before `NODE_START_TIMEOUT` elapsed.
///
/// `rad node start` returns as soon as the daemon forks, so a query fired straight after it
/// fails, and every repository would read `CouldNotAsk` on a node that is merely slow.
#[cfg(unix)]
fn wait_for_node(ctx: &Ctx) -> bool {
    let deadline = std::time::Instant::now() + NODE_START_TIMEOUT;
    while std::time::Instant::now() < deadline {
        if ctx.home.probe_node_state().is_running() {
            return true;
        }
        std::thread::sleep(NODE_START_POLL);
    }
    false
}

/// Returns `true` at once, because without a control socket to poll the unix wait could only
/// time out on a node that may be up. The fetches then fail per repository, each saying so.
#[cfg(not(unix))]
fn wait_for_node(_ctx: &Ctx) -> bool {
    true
}

/// What one repository's comparison found.
///
/// The two answers are facts about different nodes. A repository can be ahead of one seed and
/// unknown to another, and keeping only the worse would drop work whose only other copy is the
/// archive from the push-first list.
struct Comparison {
    standing: Standing,
    /// Whether some node's recorded head is an ancestor of the archive's, so the archive holds
    /// work that node lacks.
    someone_is_behind: bool,
}

/// Where a row in the node's record came from, which decides what may be read out of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    /// Some node wrote it while this restore was running.
    AnnouncedSinceRestore,
    /// The home held it before this run began, from the archive's or the machine's node.db.
    CameWithTheArchive,
}

/// Decides where the archive's signed refs stand against what other nodes say they hold.
///
/// `held` comes from the node's record of announcements, never from local storage. A fetch
/// over a repository already in storage ignores the local peer's own key, so local refs stay
/// as the archive wrote them however far the network has moved. Writing on top of a copy
/// another node has moved past forks the user's peer history, with no undo.
///
/// `is_ancestor` is a closure so tests need no repository on disk.
fn classify<F>(held: &Evidence, mut is_ancestor: F) -> Result<Comparison>
where
    F: FnMut(&str) -> Result<Answer>,
{
    // The record was read and holds nothing against this copy, which is exactly what
    // `NothingSaysOtherwise` claims
    let mut standing = Standing::NothingSaysOtherwise;
    let mut someone_is_behind = false;
    for (origin, head) in held.rows() {
        standing = standing.worse_of(if !git::names_an_oid(head) {
            // `merge-base` takes no `--`, so a row shaped like a flag would be read as one. A
            // malformed row is an unreadable database, not evidence of a fork.
            Standing::CouldNotAsk
        } else {
            match is_ancestor(head)? {
                // The peer's head is in the archived history, so the archive holds work it
                // lacks. A row the archive carried may be stale, since that node can pass this
                // copy without a word, so only a fresh row earns "push this first".
                Answer::Yes => match origin {
                    Origin::AnnouncedSinceRestore => {
                        someone_is_behind = true;
                        Standing::ArchiveIsAhead
                    }
                    Origin::CameWithTheArchive => Standing::ArchiveIsAheadOfAStaleRecord,
                },
                // The peer's head is not in the archived history, so work signed under this
                // key is missing here. That reading never decays, so a row of any age counts.
                // `resolve_git_failure` maps a head proven absent to this answer.
                Answer::No => Standing::PeerHoldsOther,
                // `git` could not run or open the repository, which says nothing about any
                // peer and must not cost exit 3 and a fork warning
                Answer::CouldNotAsk { .. } => Standing::CouldNotAsk,
            }
        });
    }
    Ok(Comparison {
        standing,
        someone_is_behind,
    })
}

/// What other nodes have said they hold of one repository's signed refs that differs from
/// the archive, split by whether the row predates this run.
///
/// A row that agrees with the archive is left out, because heartwood rewrites a row only when
/// a peer announces a different head, so an agreeing row may be the archive's own. Only the
/// fork reading, which cannot decay, may be taken from a row that predates this run.
#[derive(Default)]
struct Evidence {
    announced_since_restore: BTreeSet<String>,
    came_with_the_archive: BTreeSet<String>,
}

impl Evidence {
    /// Every row worth asking `git` about, with its origin.
    fn rows(&self) -> impl Iterator<Item = (Origin, &String)> {
        self.announced_since_restore
            .iter()
            .map(|head| (Origin::AnnouncedSinceRestore, head))
            .chain(
                self.came_with_the_archive
                    .iter()
                    .map(|head| (Origin::CameWithTheArchive, head)),
            )
    }
}

/// What the node's record held for one repository before this run could add to it.
enum Before<'a> {
    /// These heads and no others, read from the home before the node was started.
    Held(Option<&'a BTreeSet<String>>),
    /// Not known, so every row reads as already there. That reading claims less, withholding
    /// "push this first" and keeping the fork verdict.
    Unknown,
}

impl Before<'_> {
    fn holds(&self, head: &str) -> bool {
        match self {
            Self::Held(heads) => heads.is_some_and(|heads| heads.contains(head)),
            Self::Unknown => true,
        }
    }
}

/// Splits the rows `recorded` holds for one repository by whether `before` already held
/// them, leaving out rows that agree with `archived`.
///
/// The split is on the head alone, because `read_synced_heads` drops the node column. A
/// second node announcing a head already on record then reads as old, which only withholds
/// "push this first", the safe direction.
fn evidence_against(
    archived: &str,
    recorded: Option<&BTreeSet<String>>,
    before: Before,
) -> Evidence {
    let Some(recorded) = recorded else {
        return Evidence::default();
    };
    let mut evidence = Evidence::default();
    for head in recorded {
        // Two spellings of one commit are one commit, and comparing them would report
        // unpushed work that does not exist
        if git::same_oid(head, archived) {
            continue;
        }
        if before.holds(head) {
            evidence.came_with_the_archive.insert(head.clone());
        } else {
            evidence.announced_since_restore.insert(head.clone());
        }
    }
    evidence
}

/// The repository id in the form heartwood's tables use, with the `rad:` prefix.
///
/// A manifest can carry bare `z...` rids, which `rad::is_identifier` accepts, and an
/// unprefixed lookup matches no row, so every repository would read "could not be compared".
fn prefixed_rid(rid: &str) -> String {
    if rid.starts_with(RID_PREFIX) {
        rid.to_string()
    } else {
        format!("{RID_PREFIX}{rid}")
    }
}

/// How heartwood's own tables spell a repository id.
const RID_PREFIX: &str = "rad:";

/// How long to let other nodes say what they hold, once the fetches are done.
const GOSSIP_WINDOW: std::time::Duration = std::time::Duration::from_secs(20);

/// What other nodes have told this one they hold, after a moment for them to say it.
///
/// A refs announcement arrives on its own schedule after `rad sync --fetch` returns, and a
/// read made at once sees only what the archive carried. The wait is flat because a peer that
/// agrees writes no row, so nothing ever signals that the answers are in.
fn what_others_hold(ctx: &Ctx, node_id: &str) -> Option<BTreeMap<String, BTreeSet<String>>> {
    ctx.term.step(&format!(
        "waiting {} seconds for other nodes to report what they hold",
        GOSSIP_WINDOW.as_secs()
    ));
    std::thread::sleep(GOSSIP_WINDOW);
    read_what_others_hold(&ctx.term, &ctx.home.node_db(), node_id)
}

/// Reads what other nodes have said they hold, without the wait.
///
/// Returns `None` when the record cannot be read or matched, because an error would cost the
/// report of which repositories did not come back, which no later command can reconstruct.
fn read_what_others_hold(
    term: &term::Term,
    node_db: &Path,
    node_id: &str,
) -> Option<BTreeMap<String, BTreeSet<String>>> {
    match crate::db::read_synced_heads(node_db, node_id) {
        // A table that reads but whose repository ids this build does not spell would miss
        // every lookup, and every miss reads as "nothing reported otherwise"
        Ok(held) if !held.is_empty() && !held.keys().any(|repo| repo.starts_with(RID_PREFIX)) => {
            term.warn(
                "the node's database spells repository ids in a way this rad-backup does not \
                 recognise, so nothing was compared",
            );
            None
        }
        // A table this build cannot read comes back empty, which would also reassure. The
        // drift is asked about for this read alone, so another reader's drift cannot discard
        // a good record. `main` prints which table moved.
        Ok(_) if crate::db::saw_schema_drift_in(node_db, "sync status table") => {
            term.warn(
                "this rad-backup cannot read part of the node's database, so nothing was compared",
            );
            None
        }
        Ok(held) => Some(held),
        Err(e) => {
            term.warn(&format!(
                "what other nodes reported holding could not be read: {e}"
            ));
            None
        }
    }
}

/// Reads a `git` failure as either the peer's head being absent or this disk being unreadable.
///
/// `merge-base` exits 128 both for a peer head missing here, which is the fork hazard, and for
/// a broken repository. The archived head is the control, so a store that cannot produce it
/// either is read as broken. `merge-base --is-ancestor A A` is no control, because it answers
/// on equality without opening an object.
///
/// A fetch that wrote a second pack holding only the peer's head still reads as the fork.
/// Revisit if `git` grows a cheap way to tell a failed lookup from an empty one.
fn resolve_git_failure(
    git: &Git,
    git_dir: &Path,
    head: &str,
    store_holds_the_archived_head: bool,
    answer: Answer,
) -> Result<Answer> {
    if !matches!(answer, Answer::CouldNotAsk { .. }) {
        return Ok(answer);
    }
    if git.holds_object(git_dir, head)? != Answer::No {
        return Ok(answer);
    }
    if store_holds_the_archived_head {
        return Ok(Answer::No);
    }
    Ok(answer)
}

/// Every restored repository, with nothing compared about it.
///
/// Each repository gets a standing, so `--json` never shows empty lists for a run that asked
/// the network nothing.
fn nothing_compared(restored: &[RepoRecord], wanted: NetworkCheck) -> Reconciled {
    Reconciled {
        wanted,
        standings: restored
            .iter()
            .map(|repo| {
                // Private repositories stay `NothingToCompare`, so a home of them is not told
                // every comparison failed and sent to run a fetch that cannot succeed
                let standing = if no_node_can_hold(repo) {
                    Standing::NothingToCompare
                } else {
                    Standing::CouldNotAsk
                };
                (repo.rid.clone(), standing)
            })
            .collect(),
        ahead_of_someone: BTreeSet::new(),
    }
}

/// The standing for a repository the archive holds no signed refs of this identity for.
///
/// Any row says a node holds signed refs under this key that this copy lacks, which is the
/// fork hazard whatever the heads. A repository first written after the backup has this shape.
fn without_a_head_of_ours(recorded: Option<&BTreeSet<String>>) -> Standing {
    match recorded {
        Some(heads) if !heads.is_empty() => Standing::PeerHoldsOther,
        _ => Standing::NothingSaysOtherwise,
    }
}

/// Whether no node will ever hold signed refs of this identity for the repository, because it
/// is announced to nobody, delegated to this identity alone and allowed to nobody.
///
/// An archive holding no signed refs of this identity does not qualify, because a repository
/// first written after the backup can have them on a seed. The archive's identity document is
/// read, so a delegate added since is missed, and the report says who was not asked.
fn no_node_can_hold(repo: &RepoRecord) -> bool {
    // Private alone is not enough, because `rad sync --fetch` reaches a private repository's
    // delegates and allowed peers, and a collaborator's copy can be ahead of this one
    repo.has_nowhere_to_fetch_from()
}

/// Compares each restored repository with the network, recording a standing for every one.
///
/// Never returns an error, because it runs after everything is on disk, and an error escaping
/// would lose the report of which repositories did not come back.
fn compare_with_network(
    ctx: &Ctx,
    manifest: &Manifest,
    restored: &[RepoRecord],
    baseline: Option<&BTreeMap<String, BTreeSet<String>>>,
    rad: &Rad,
    standings: &mut BTreeMap<String, Standing>,
    ahead_of_someone: &mut BTreeSet<String>,
) {
    let git = Git::new();
    let node_id = &manifest.identity.node_id;

    ctx.term.step(&format!(
        "comparing {} with the network",
        term::count(restored.len(), "repository", "repositories")
    ));
    let mut fetched = Vec::new();
    for repo in restored {
        // A repository no node can hold is not fetched, because the fetch would fail and
        // report the feature working as a fault
        if no_node_can_hold(repo) {
            standings.insert(repo.rid.clone(), Standing::NothingToCompare);
            continue;
        }
        // `None` is a repository the archive holds no signed refs of this identity for. It is
        // still fetched, because any row for it is work signed under this key missing here.
        let archived = repo.sigrefs.get(node_id);
        // The manifest is unvouched for, and `merge-base` takes no `--`, so an archived value
        // shaped like a flag or a revision expression is not compared. One bad oid marks its
        // own repository `CouldNotAsk` and leaves the rest to be compared.
        if archived.is_some_and(|archived| !git::names_an_oid(archived)) {
            standings.insert(repo.rid.clone(), Standing::CouldNotAsk);
            continue;
        }
        match rad.fetch(&repo.rid) {
            Ok(true) => fetched.push((repo, archived)),
            Ok(false) => {
                standings.insert(repo.rid.clone(), Standing::CouldNotAsk);
            }
            Err(e) => {
                ctx.term
                    .warn(&format!("{} could not be fetched: {e}", repo.rid));
                standings.insert(repo.rid.clone(), Standing::CouldNotAsk);
            }
        }
    }
    if fetched.is_empty() {
        return;
    }

    let held = what_others_hold(ctx, node_id);
    for (repo, archived) in fetched {
        let Some(held) = &held else {
            standings.insert(repo.rid.clone(), Standing::CouldNotAsk);
            continue;
        };
        let rid = prefixed_rid(&repo.rid);
        let recorded = held.get(&rid);
        let Some(archived) = archived else {
            standings.insert(repo.rid.clone(), without_a_head_of_ours(recorded));
            continue;
        };
        let path = ctx.home.repository_path(&repo.rid);
        let before = match baseline {
            Some(baseline) => Before::Held(baseline.get(&rid)),
            None => Before::Unknown,
        };
        let evidence = evidence_against(archived, recorded, before);
        // The control is the archived head, so it is asked at most once per repository, and
        // only when a `git` failure needs reading
        let mut control = None;
        // One warning per repository, however many of its rows cannot be read
        let mut said_already = false;
        let compared = classify(&evidence, |head| {
            let asked = git.is_ancestor(&path, head, archived)?;
            let answer = if matches!(asked, Answer::CouldNotAsk { .. }) {
                let store_holds_the_archived_head = match control {
                    Some(answered) => answered,
                    None => {
                        let answered = git.holds_object(&path, archived)? == Answer::Yes;
                        control = Some(answered);
                        answered
                    }
                };
                resolve_git_failure(&git, &path, head, store_holds_the_archived_head, asked)?
            } else {
                asked
            };
            if let Answer::CouldNotAsk { said } = &answer
                && !std::mem::replace(&mut said_already, true)
            {
                ctx.term.warn(&format!(
                    "git could not compare {} with what other nodes hold: {said}",
                    repo.rid
                ));
            }
            Ok(answer)
        });
        match compared {
            Ok(compared) => {
                if compared.someone_is_behind {
                    ahead_of_someone.insert(repo.rid.clone());
                }
                standings.insert(repo.rid.clone(), compared.standing);
            }
            // `git` itself could not run, from a vanished binary or exhausted file
            // descriptors. This repository becomes an unknown, and the report is still owed
            // for the rest.
            Err(e) => {
                ctx.term
                    .warn(&format!("{} could not be compared: {e}", repo.rid));
                standings.insert(repo.rid.clone(), Standing::CouldNotAsk);
            }
        }
    }
}

/// Re-applies seeding and following through `rad`, for a Radicle whose schema has moved on.
fn replay_policies(ctx: &Ctx, staging: &Path) -> Result<Vec<String>> {
    let path = staging.join("policies.json");
    if !path.is_file() {
        ctx.term
            .warn("this archive has no policies.json, so there was nothing to replay");
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(&path).map_err(|e| Error::io(&path, e))?;
    let policies: Policies = serde_json::from_str(&text)?;

    // `run` refused up front without `rad`, so a missing `rad` here vanished mid-restore.
    // Every row is reported missed and not raised, since exit 4 claims nothing was written.
    let rad = Rad::new(ctx.home.path());
    if !rad.is_available() {
        ctx.term.warn(&format!(
            "{}, so no policy was replayed",
            crate::exec::rad_missing(crate::exec::rad_override_from_env().as_deref())
        ));
        return Ok(policies.identifiers());
    }
    ctx.term.step("replaying policies through rad");

    // `policies.json` is unvouched for, and an id with a leading `-` would land in argv as a
    // flag. Such a row is skipped and named, because one lost decision is cheaper than
    // abandoning the rest of the replay.
    let mut skipped = Vec::new();
    let mut failed = Vec::new();
    for policy in policies.seeded() {
        replay(&policy.rid, &mut skipped, &mut failed, || {
            rad.seed(&policy.rid, &policy.scope)
        })?;
    }
    for policy in policies.blocked_repos() {
        replay(&policy.rid, &mut skipped, &mut failed, || {
            rad.block_repo(&policy.rid)
        })?;
    }
    for policy in policies.followed() {
        replay(&policy.nid, &mut skipped, &mut failed, || {
            rad.follow(&policy.nid, policy.alias.as_deref())
        })?;
    }
    for policy in policies.blocked_peers() {
        replay(&policy.nid, &mut skipped, &mut failed, || {
            rad.block_peer(&policy.nid)
        })?;
    }

    if !skipped.is_empty() {
        let (count, ids, them) = match skipped.len() {
            1 => (
                "1 policy was".to_string(),
                "Its id looks like a command-line flag",
                "it",
            ),
            n => (
                format!("{n} policies were"),
                "Their ids look like command-line flags",
                "them",
            ),
        };
        ctx.term.warn(&format!(
            "{count} skipped. {ids}: {}. Seed or follow {them} by hand",
            crate::term::shortlist(&skipped)
        ));
    }
    if !failed.is_empty() {
        // `rad` printed its reason on stderr. This warning keeps a restore that put back no
        // seeding policies from reading as a clean one.
        ctx.term.warn(&format!(
            "`rad` refused {}: {}. Those were not restored",
            crate::term::count(failed.len(), "policy", "policies"),
            crate::term::shortlist(&failed)
        ));
    }
    skipped.extend(failed);
    Ok(skipped)
}

/// Replays one policy row, unless its identifier is one `rad` would read as a flag.
///
/// A skipped row is this tool refusing a hostile archive, and a failed one is `rad` refusing
/// a decision, so the two are kept apart.
fn replay(
    id: &str,
    skipped: &mut Vec<String>,
    failed: &mut Vec<String>,
    put_back: impl FnOnce() -> Result<bool>,
) -> Result<()> {
    if !crate::rad::is_identifier(id) {
        skipped.push(id.to_string());
        return Ok(());
    }
    if !put_back()? {
        failed.push(id.to_string());
    }
    Ok(())
}

/// What the report is about to say, decided before a word of it is printed.
///
/// Held as a value so tests can check what a restore tells the user about their signed refs.
struct Verdict<'a> {
    /// Another node holds signed refs this copy does not. Do not write in these.
    at_risk: Vec<&'a str>,
    /// Work no reporting node has, whose only other copy is the archive. Push these.
    ahead: Vec<&'a str>,
    /// Nothing came back to compare against. Named, so a comparison that answered nothing does
    /// not read as a clean bill.
    not_checked: Vec<&'a str>,
    /// Repositories no node will ever hold. Named, so a home of only private repositories is
    /// still told why the network went unmentioned.
    nothing_to_compare: Vec<&'a str>,
    /// Work no node had when the archive was taken, with no node reporting since. Reported
    /// without `rad sync --announce`.
    ahead_of_a_stale_record: Vec<&'a str>,
    /// Whether every comparison ran, none found a fork, and at least one repository's record
    /// was read.
    nothing_was_reported_otherwise: bool,
}

impl<'a> Verdict<'a> {
    fn of(reconciled: &'a Reconciled) -> Self {
        let standings = &reconciled.standings;
        let of_standing = |wanted: Standing| -> Vec<&'a str> {
            standings
                .iter()
                .filter(|(_, standing)| **standing == wanted)
                .map(|(rid, _)| rid.as_str())
                .collect()
        };
        let at_risk = of_standing(Standing::PeerHoldsOther);
        let not_checked = of_standing(Standing::CouldNotAsk);
        let nothing_to_compare = of_standing(Standing::NothingToCompare);
        let ahead_of_a_stale_record = of_standing(Standing::ArchiveIsAheadOfAStaleRecord);
        // Taken from the second answer, because a repository one node is behind on and another
        // said nothing about reports as the unknown, and its unique work would go unnamed.
        // Repositories at risk are left out, because `rad sync --announce` publishes the fork.
        let ahead = reconciled
            .ahead_of_someone
            .iter()
            .map(String::as_str)
            .filter(|rid| !at_risk.contains(rid))
            .collect();
        // Said only when at least one repository's record was read and nothing went
        // unchecked, so the line never sits over private repositories or failed comparisons
        let nothing_was_reported_otherwise = at_risk.is_empty()
            && not_checked.is_empty()
            && standings.values().any(|standing| {
                matches!(
                    standing,
                    Standing::NothingSaysOtherwise
                        | Standing::ArchiveIsAhead
                        | Standing::ArchiveIsAheadOfAStaleRecord
                )
            });
        Self {
            at_risk,
            ahead,
            not_checked,
            nothing_to_compare,
            ahead_of_a_stale_record,
            nothing_was_reported_otherwise,
        }
    }
}

fn report(
    ctx: &Ctx,
    manifest: &Manifest,
    restored: &Restored,
    reconciled: &Reconciled,
    policies_missed: &[String],
) -> Result<std::process::ExitCode> {
    let dropped = &restored.dropped;
    let restored = &restored.repos;
    let standings = &reconciled.standings;
    let Verdict {
        at_risk,
        ahead,
        not_checked,
        nothing_to_compare,
        ahead_of_a_stale_record,
        nothing_was_reported_otherwise,
    } = Verdict::of(reconciled);

    if ctx.global.json {
        ctx.term.print_json(&serde_json::json!({
            "restored": manifest.identity.did,
            "home": ctx.home.path().display().to_string(),
            "repositories": restored.len(),
            "standings": standings.iter()
                .map(|(rid, standing)| serde_json::json!({
                    "rid": rid,
                    "standing": standing.as_str(),
                    "standingId": standing.id(),
                }))
                .collect::<Vec<_>>(),
            "atRisk": at_risk,
            "ahead": ahead,
            "notChecked": not_checked,
            "nothingToCompare": nothing_to_compare,
            "aheadOfAStaleRecord": ahead_of_a_stale_record,
            "notRestored": dropped,
        }))?;
    } else {
        let term = &ctx.term;
        term.blank();
        term.ok(&format!(
            "restored {} into {}",
            manifest.identity.alias.as_deref().unwrap_or("unnamed"),
            ctx.home.path().display()
        ));
        // Counted from the installed database, because the manifest's summary rides in every
        // tier and `policies.db` only above `identity`. Reported, never propagated, because
        // the fork warning, the dropped list and the exit code come after this line.
        match crate::db::read_policies(&ctx.home.policies_db()) {
            Ok(installed) => term.hint(&format!(
                "{}, {} seeded and {} followed policies",
                term::count(restored.len(), "repository", "repositories"),
                installed.seeded().count(),
                installed.followed().count()
            )),
            Err(e) => {
                term.hint(&term::count(restored.len(), "repository", "repositories"));
                term.warn(&format!("the restored policies could not be counted: {e}"));
            }
        }
        // Under `--no-reconcile` the line `run` printed is enough, and a second warning with a
        // remedy would read as a failure
        if reconciled.wanted == NetworkCheck::Wanted && !not_checked.is_empty() {
            term.warn(&format!(
                "{} of {} could not be compared with the network",
                not_checked.len(),
                term::count(restored.len(), "repository", "repositories")
            ));
            // Shortlisted, because a node that would not start makes this every repository
            term.detail(&term::shortlist(&not_checked));
            // The causes vary, and only a failed fetch is fixed by running it again, so the
            // remedy asserts none of them
            term.detail("the warnings above say why");
            term.detail(
                "before you write in them, clone each one into a new, empty RAD_HOME to check \
                 what the network holds",
            );
        }
        if !nothing_to_compare.is_empty() {
            term.hint(&format!(
                "{} private and shared with nobody, so there is nothing to compare: {}",
                term::count(
                    nothing_to_compare.len(),
                    "repository is",
                    "repositories are"
                ),
                term::shortlist(&nothing_to_compare)
            ));
        }
        if nothing_was_reported_otherwise {
            term.detail("no other node reported work of yours that is not in the archive");
        }
        if !ahead_of_a_stale_record.is_empty() {
            // The fact without the instruction. That row may be as stale as the archive, and
            // `rad sync --announce` on a copy the network has passed publishes the fork. The
            // backup's date is printed, because it bounds how stale the row can be.
            let taken = manifest
                .created
                .get(..10)
                .unwrap_or(manifest.created.as_str());
            term.warn(&format!(
                "{} work no other node had on {taken}: {}",
                term::count(
                    ahead_of_a_stale_record.len(),
                    "repository holds",
                    "repositories hold"
                ),
                term::shortlist(&ahead_of_a_stale_record)
            ));
            term.detail(&format!(
                "{taken} is when the archive was taken. No node has reported since, so the \
                 network may have moved on"
            ));
            term.detail(
                "before you announce, clone each one into a new, empty RAD_HOME to see what the \
                 network holds",
            );
        }
        if !ahead.is_empty() {
            term.warn(&format!(
                "{} work the nodes that answered do not have. Announce {} with the command below",
                term::count(ahead.len(), "repository holds", "repositories hold"),
                if ahead.len() == 1 { "it" } else { "each one" }
            ));
            for rid in &ahead {
                term.detail(&format!("rad sync {rid} --announce"));
            }
        }
        if !dropped.is_empty() {
            term.blank();
            term.fail(&format!(
                "{} from the archive could not be restored:",
                term::count(dropped.len(), "repository", "repositories")
            ));
            for rid in dropped {
                term.detail(rid);
            }
            term.detail("the archive still has them, and it was not changed");
        }
        if !at_risk.is_empty() {
            term.blank();
            term.fail("another node holds work of yours missing from these restored repositories:");
            for rid in &at_risk {
                term.detail(rid);
            }
            term.blank();
            term.fail("do not commit or push in these repositories yet");
            term.detail("committing or pushing in them would fork your own history");
            term.detail(
                "a fetch cannot fix this. It never updates your own work in a repository you \
                 already have",
            );
            term.detail("to see what the network holds, clone each one into a new, empty RAD_HOME");
        }
        term.blank();
        // The archive knows only that a node ran when it was taken, so the warning is
        // conditional. Two nodes on one key fork its history, so the stop comes first.
        match manifest.node.was_running {
            true => term.warn(
                "if the machine this archive came from still runs its node, stop it before you \
                 run `rad node start`",
            ),
            false => term.detail("start the node with `rad node start`"),
        }
    }

    // A repository this run meant to compare and could not fails the check, because a
    // scheduled restore exiting 0 over it is the last anyone hears. Under `--no-reconcile` the
    // same standings are what the user asked for.
    let unchecked = reconciled.wanted == NetworkCheck::Wanted && !not_checked.is_empty();
    // A repository or policy the archive carried and the home did not get also fails the check
    Ok(
        if at_risk.is_empty() && dropped.is_empty() && policies_missed.is_empty() && !unchecked {
            std::process::ExitCode::SUCCESS
        } else {
            std::process::ExitCode::from(EXIT_CHECKS_FAILED)
        },
    )
}

#[cfg(test)]
mod tests {
    /// Both spellings of the identity must be the archive's key, because the signed refs are
    /// looked up under the node id and a wrong one compares nothing at exit 0.
    #[test]
    fn a_manifest_whose_node_id_is_not_its_key_is_refused_like_a_wrong_did() {
        const DID: &str = "did:key:z6MkjDYUKMUeY58Vtr8dGJrHRvnTfjKWVGCBYJDVTHXsXzm5";
        const NODE_ID: &str = "z6MkjDYUKMUeY58Vtr8dGJrHRvnTfjKWVGCBYJDVTHXsXzm5";
        const SOMEBODY_ELSE: &str = "z6MktaNvN1tjt7bWaP9WNaKUnfLNqk7oYGjPGyMbcHDW2i8x";

        assert!(describes_this_key(DID, DID, NODE_ID).is_ok());
        assert!(describes_this_key(DID, DID, SOMEBODY_ELSE).is_err());
        assert!(describes_this_key(DID, &format!("did:key:{SOMEBODY_ELSE}"), NODE_ID).is_err());
        // A node id that is the DID over again, not the bare key
        assert!(describes_this_key(DID, DID, DID).is_err());
    }

    use super::*;

    /// Every standing id, as the exact string a script matches on. The second copy is on
    /// purpose, so an edit to `Standing::id` takes two edits to ship. A new variant needs a
    /// line here too, since nothing notices one left out.
    #[test]
    fn standing_ids_are_pinned_because_scripts_match_on_them() {
        let pinned = [
            (Standing::NothingSaysOtherwise, "nothing-reported-otherwise"),
            (Standing::ArchiveIsAhead, "ahead"),
            (
                Standing::ArchiveIsAheadOfAStaleRecord,
                "ahead-of-a-stale-record",
            ),
            (Standing::PeerHoldsOther, "at-risk"),
            (Standing::NothingToCompare, "nothing-to-compare"),
            (Standing::CouldNotAsk, "not-checked"),
        ];
        for (standing, spelled) in pinned {
            assert_eq!(standing.id(), spelled);
        }
        let distinct: std::collections::BTreeSet<_> =
            pinned.iter().map(|(standing, _)| standing.id()).collect();
        assert_eq!(distinct.len(), pinned.len(), "two standings share an id");
    }

    #[test]
    fn a_policy_row_naming_a_flag_is_skipped_without_rad_ever_being_asked() {
        let (mut skipped, mut failed) = (Vec::new(), Vec::new());
        let mut asked = false;
        replay("--help", &mut skipped, &mut failed, || {
            asked = true;
            Ok(true)
        })
        .expect("a skipped row is not an error");

        assert!(!asked, "`rad` was asked about an identifier that is a flag");
        assert_eq!(skipped, vec!["--help".to_string()]);
        assert!(failed.is_empty());
    }

    /// All three answers about the object check, on a machine that can only see one.
    ///
    /// A git that checks gets no word. "Did not check" is a fact about this git and names the
    /// fixing version, and "could not be read" is a fact about the reader and names none.
    #[test]
    fn only_the_git_that_checks_a_bundle_passes_without_a_word_about_it() {
        assert_eq!(bundle_check_notice(Some(true)), None);

        let (warning, detail) =
            bundle_check_notice(Some(false)).expect("a git that does not check says so");
        assert!(
            warning.contains("cannot check the archived repositories"),
            "{warning}"
        );
        let detail = detail.expect("the version that would fix it is named");
        assert!(
            detail.contains(&format!(
                "{}.{}",
                crate::git::FSCK_ON_A_BUNDLE_SINCE.0,
                crate::git::FSCK_ON_A_BUNDLE_SINCE.1
            )),
            "{detail}"
        );

        let (unknown, detail) =
            bundle_check_notice(None).expect("a version that could not be read says so");
        assert!(unknown.contains("could not be read"), "{unknown}");
        assert!(!unknown.contains("does not check"), "{unknown}");
        assert_eq!(
            detail, None,
            "nothing to advise: which git ran is not known"
        );
    }

    #[test]
    fn a_policy_row_rad_refuses_is_recorded_rather_than_dropped() {
        // The bool is `rad`'s exit status, and a discarded one lets a restore lose every
        // seeding policy at exit 0
        let (mut skipped, mut failed) = (Vec::new(), Vec::new());
        replay("rad:zAAA", &mut skipped, &mut failed, || Ok(false))
            .expect("a refused row is reported, not raised");

        assert_eq!(failed, vec!["rad:zAAA".to_string()]);
        assert!(skipped.is_empty());
    }

    #[test]
    fn a_policy_row_that_goes_back_is_recorded_nowhere() {
        let (mut skipped, mut failed) = (Vec::new(), Vec::new());
        replay("rad:zAAA", &mut skipped, &mut failed, || Ok(true)).expect("a good row replays");
        assert!(skipped.is_empty() && failed.is_empty());
    }

    /// The identity being restored, which is the one whose signed refs a fork would be under.
    const OWN_NODE: &str = "z6MkAAA";

    /// Forty hexadecimal characters, so the value passes the oid check and reaches `git`.
    fn oid(fill: char) -> String {
        std::iter::repeat_n(fill, 40).collect()
    }

    /// An `is_ancestor` answer that also records whether it was ever asked for.
    fn asked(
        answer: Answer,
        calls: &std::cell::Cell<usize>,
    ) -> impl FnMut(&str) -> Result<Answer> + '_ {
        move |_| {
            calls.set(calls.get() + 1);
            Ok(answer.clone())
        }
    }

    /// Rows some node wrote while this restore was running.
    fn announced(heads: &[String]) -> Evidence {
        Evidence {
            announced_since_restore: heads.iter().cloned().collect(),
            came_with_the_archive: BTreeSet::new(),
        }
    }

    /// Rows the home already held before this run began.
    fn carried(heads: &[String]) -> Evidence {
        Evidence {
            announced_since_restore: BTreeSet::new(),
            came_with_the_archive: heads.iter().cloned().collect(),
        }
    }

    /// The rows one repository has in the node's record of what other nodes hold.
    fn rows(heads: &[String]) -> BTreeSet<String> {
        heads.iter().cloned().collect()
    }

    /// The network side comes from the node's record, never local storage, because a fetch
    /// over an existing repository ignores the local peer's own key and would always read back
    /// the archive's refs as "in step".
    #[test]
    fn a_node_holding_signed_refs_this_copy_does_not_have_is_the_fork_hazard() {
        let calls = std::cell::Cell::new(0);
        let compared = classify(&announced(&[oid('b')]), asked(Answer::No, &calls))
            .expect("the ancestry answer is not an error");
        assert_eq!(compared.standing, Standing::PeerHoldsOther);
        assert!(!compared.someone_is_behind);
        assert_eq!(calls.get(), 1);
    }

    /// A killed `git`, an unreadable repository and an unresolvable archived oid all arrive as
    /// `CouldNotAsk`, and none of them is evidence that a peer forked the identity.
    #[test]
    fn a_git_that_could_not_answer_at_all_is_an_unknown_and_not_a_fork() {
        let calls = std::cell::Cell::new(0);
        let compared = classify(
            &announced(&[oid('b')]),
            asked(
                Answer::CouldNotAsk {
                    said: "fatal: not a git repository".to_string(),
                },
                &calls,
            ),
        )
        .expect("the ancestry answer is not an error");
        assert_eq!(compared.standing, Standing::CouldNotAsk);
    }

    #[test]
    fn a_node_still_back_at_an_ancestor_is_read_as_the_archive_being_ahead() {
        let calls = std::cell::Cell::new(0);
        let compared = classify(&announced(&[oid('b')]), asked(Answer::Yes, &calls))
            .expect("the ancestry answer is not an error");
        assert_eq!(compared.standing, Standing::ArchiveIsAhead);
        assert!(compared.someone_is_behind);
    }

    /// Unsafe next to any node is unsafe. Both orders are asserted, because one order passes
    /// against "first wins" or "last wins" with the fold doing nothing.
    #[test]
    fn the_node_that_most_needs_acting_on_is_the_one_reported() {
        for order in [[Answer::No, Answer::Yes], [Answer::Yes, Answer::No]] {
            let mut answers = order.clone().into_iter();
            let compared = classify(&announced(&[oid('a'), oid('b')]), |_| {
                Ok(answers.next().expect("one answer per head"))
            })
            .expect("the ancestry answer is not an error");
            assert_eq!(compared.standing, Standing::PeerHoldsOther, "{order:?}");
        }
    }

    /// A node behind and a node holding other refs are facts about different nodes. The
    /// standing carries the fork, and `someone_is_behind` keeps the work whose only other copy
    /// is the archive, which fetching later never recovers.
    #[test]
    fn work_a_node_is_behind_on_is_still_a_fact_beside_a_node_holding_other_refs() {
        let mut answers = [Answer::Yes, Answer::No].into_iter();
        let compared = classify(&announced(&[oid('a'), oid('b')]), |_| {
            Ok(answers.next().expect("one answer per head"))
        })
        .expect("the ancestry answer is not an error");

        assert_eq!(compared.standing, Standing::PeerHoldsOther);
        assert!(
            compared.someone_is_behind,
            "the node that is behind is still a node that is behind"
        );
    }

    /// `names_an_oid` accepts either case and git resolves either, so a byte-exact filter
    /// would report work already there as unpushed.
    #[test]
    fn one_commit_spelled_in_two_cases_is_not_two_commits() {
        let evidence = evidence_against(
            &oid('a').to_uppercase(),
            Some(&rows(&[oid('a')])),
            Before::Held(None),
        );

        assert_eq!(evidence.rows().count(), 0);
    }

    /// An agreeing row may be the archive's own, because heartwood rewrites a peer's row only
    /// when the peer announces a different head. Counting it compares the archive to itself.
    #[test]
    fn a_row_that_agrees_with_the_archive_is_not_evidence_about_the_network() {
        let evidence = evidence_against(&oid('a'), Some(&rows(&[oid('a')])), Before::Held(None));

        assert_eq!(evidence.rows().count(), 0);
    }

    /// A differing row is evidence however old it is. Filtered by timestamp, a seed holding
    /// work this archive lacks would read "could not be compared" at exit 0.
    #[test]
    fn a_row_that_differs_is_evidence_whenever_the_node_wrote_it() {
        let evidence = evidence_against(
            &oid('a'),
            Some(&rows(&[oid('b'), oid('c')])),
            Before::Held(None),
        );

        assert_eq!(
            evidence.announced_since_restore,
            BTreeSet::from([oid('b'), oid('c')])
        );
    }

    /// A manifest can carry either spelling, and the node writes only the prefixed one, so an
    /// exact match would compare a bare-rid archive against nothing.
    #[test]
    fn a_repository_id_without_its_prefix_still_finds_the_row_the_node_wrote() {
        let held = BTreeMap::from([("rad:z6MkAAA".to_string(), rows(&[oid('b')]))]);

        let evidence = evidence_against(
            &oid('a'),
            held.get(&prefixed_rid("z6MkAAA")),
            Before::Held(None),
        );

        assert_eq!(evidence.announced_since_restore, BTreeSet::from([oid('b')]));
    }

    #[test]
    fn identical_refs_leave_nothing_to_ask_git_about() {
        let calls = std::cell::Cell::new(0);
        let evidence = evidence_against(&oid('a'), Some(&rows(&[oid('a')])), Before::Held(None));
        let compared = classify(&evidence, asked(Answer::No, &calls)).expect("no head reaches git");

        assert_eq!(compared.standing, Standing::NothingSaysOtherwise);
        // Two identical oids are one commit, and asking `git` to walk between them spawns a
        // process per repository to learn nothing
        assert_eq!(calls.get(), 0, "git was asked about two identical oids");
    }

    /// `merge-base` takes no `--`, so a row shaped like a flag must never reach it. An
    /// unreadable database is no evidence of a fork either.
    #[test]
    fn a_recorded_head_that_is_not_an_oid_is_an_unknown_and_never_reaches_git() {
        let calls = std::cell::Cell::new(0);
        let compared = classify(
            &announced(&["--output=/etc/passwd".to_string()]),
            asked(Answer::No, &calls),
        )
        .expect("the ancestry answer is not an error");
        assert_eq!(compared.standing, Standing::CouldNotAsk);
        assert_eq!(calls.get(), 0, "git was handed a value out of a database");
    }

    /// A node recorded as behind on the backup's day has had every day since to pass this
    /// copy, and heartwood writes nothing while a peer agrees. `rad sync --announce` beside it
    /// could publish the fork.
    #[test]
    fn a_node_the_archive_recorded_as_behind_is_never_a_reason_to_push() {
        let calls = std::cell::Cell::new(0);
        let compared = classify(&carried(&[oid('b')]), asked(Answer::Yes, &calls))
            .expect("the ancestry answer is not an error");

        assert_eq!(compared.standing, Standing::ArchiveIsAheadOfAStaleRecord);
        assert!(!compared.someone_is_behind);
    }

    /// A node that once held refs signed under this key that this copy lacks still holds them,
    /// so the fork hazard is taken from a row of any age.
    #[test]
    fn a_node_the_archive_recorded_holding_other_refs_is_still_the_fork_hazard() {
        let calls = std::cell::Cell::new(0);
        let compared = classify(&carried(&[oid('b')]), asked(Answer::No, &calls))
            .expect("the ancestry answer is not an error");

        assert_eq!(compared.standing, Standing::PeerHoldsOther);
    }

    /// The home's copy of the table, read before this restore's node can write, decides the
    /// split. No clock is consulted, because heartwood replays old gossip under old stamps.
    #[test]
    fn a_row_the_archive_brought_is_told_from_one_that_arrived_during_the_restore() {
        let now = rows(&[oid('b'), oid('c')]);
        let already_there = rows(&[oid('b')]);

        let evidence = evidence_against(&oid('a'), Some(&now), Before::Held(Some(&already_there)));

        assert_eq!(evidence.announced_since_restore, BTreeSet::from([oid('c')]));
        assert_eq!(evidence.came_with_the_archive, BTreeSet::from([oid('b')]));
    }

    /// With no baseline, no row can be shown to have arrived during this run, so every row
    /// takes the reading that claims less and "push this first" stays withheld.
    #[test]
    fn an_unreadable_baseline_leaves_every_row_one_that_was_already_there() {
        let evidence = evidence_against(&oid('a'), Some(&rows(&[oid('b')])), Before::Unknown);

        assert!(evidence.announced_since_restore.is_empty());
        assert_eq!(evidence.came_with_the_archive, BTreeSet::from([oid('b')]));
    }

    /// A truncated pack makes `cat-file -e` answer "absent" for every object in it. The
    /// archived head is the control, so a damaged store is never read as a peer holding refs
    /// this copy lacks.
    #[test]
    fn a_store_that_cannot_produce_our_own_head_either_is_a_broken_store_and_not_a_fork() {
        let git = Git::new();
        assert!(git.is_available(), "this test drives the real git");
        let scratch = crate::key::tests::TestScratch::create("restore-truncated-pack");
        let (git_dir, peer, archived) = crate::git::tests::two_commits(&scratch);
        crate::git::tests::truncate_the_pack(&git_dir);

        let asked = git
            .is_ancestor(&git_dir, &peer, &archived)
            .expect("git ran");
        assert!(matches!(asked, Answer::CouldNotAsk { .. }), "{asked:?}");
        // The premise is a repository that opens while every object in it, the archived head
        // included, stops answering
        assert_eq!(
            git.holds_object(&git_dir, &peer).expect("git ran"),
            Answer::No
        );
        let control = git.holds_object(&git_dir, &archived).expect("git ran");
        assert_eq!(control, Answer::No, "the control object is unreadable too");

        let resolved =
            resolve_git_failure(&git, &git_dir, &peer, false, asked).expect("the probe runs");

        assert!(
            matches!(resolved, Answer::CouldNotAsk { .. }),
            "{resolved:?}"
        );
    }

    /// The pairs whose order decides a repository's one reported standing, spelled out because
    /// reordering `severity`'s arms is a one-character edit no other test notices.
    #[test]
    fn the_standing_that_most_needs_acting_on_wins_every_pair() {
        use Standing::*;

        for (worse, better) in [
            (PeerHoldsOther, CouldNotAsk),
            (PeerHoldsOther, ArchiveIsAhead),
            (PeerHoldsOther, ArchiveIsAheadOfAStaleRecord),
            (PeerHoldsOther, NothingSaysOtherwise),
            (CouldNotAsk, ArchiveIsAhead),
            (CouldNotAsk, ArchiveIsAheadOfAStaleRecord),
            (CouldNotAsk, NothingSaysOtherwise),
            (ArchiveIsAhead, ArchiveIsAheadOfAStaleRecord),
            (ArchiveIsAhead, NothingSaysOtherwise),
            (ArchiveIsAheadOfAStaleRecord, NothingSaysOtherwise),
            (NothingSaysOtherwise, NothingToCompare),
        ] {
            assert_eq!(worse.worse_of(better), worse, "{worse:?} vs {better:?}");
            assert_eq!(better.worse_of(worse), worse, "{better:?} vs {worse:?}");
        }
    }

    /// A record that was read and holds nothing against this copy earns
    /// `NothingSaysOtherwise`. Heartwood writes no row for a peer that agrees, so a
    /// `CouldNotAsk` here would send every healthy restore to rerun a pointless fetch.
    #[test]
    fn a_record_holding_nothing_against_this_copy_is_not_an_unknown() {
        let calls = std::cell::Cell::new(0);
        let compared = classify(&Evidence::default(), asked(Answer::No, &calls))
            .expect("the ancestry answer is not an error");
        assert_eq!(compared.standing, Standing::NothingSaysOtherwise);
        assert_eq!(calls.get(), 0);
    }

    /// A `git` failure over an object this copy holds is a fact about this machine.
    #[test]
    fn a_git_failure_over_an_object_this_copy_holds_says_nothing_about_a_peer() {
        let git = Git::new();
        assert!(git.is_available(), "this test drives the real git");
        let scratch = crate::key::tests::TestScratch::create("restore-git-failure-held");
        let (git_dir, _, head) = crate::git::tests::two_commits(&scratch);
        // An object that is here and is not a commit, which `merge-base` refuses with the
        // same exit 128 it gives for an object that is not here at all
        let tree = crate::git::tests::rev_parse(&git_dir, "HEAD^{tree}");

        let asked = git.is_ancestor(&git_dir, &tree, &head).expect("git ran");
        assert!(matches!(asked, Answer::CouldNotAsk { .. }), "{asked:?}");

        let resolved =
            resolve_git_failure(&git, &git_dir, &tree, true, asked).expect("the probe runs");

        assert!(
            matches!(resolved, Answer::CouldNotAsk { .. }),
            "{resolved:?}"
        );
    }

    /// A pull never brings back the local peer's own namespace, so a sigrefs commit a node
    /// announced and this disk lacks is work signed under this key that is missing here.
    #[test]
    fn a_head_this_copy_does_not_hold_at_all_is_a_peer_holding_refs_that_are_missing_here() {
        let git = Git::new();
        assert!(git.is_available(), "this test drives the real git");
        let scratch = crate::key::tests::TestScratch::create("restore-git-failure-absent");
        let (git_dir, _, head) = crate::git::tests::two_commits(&scratch);
        let nowhere = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

        let asked = git.is_ancestor(&git_dir, nowhere, &head).expect("git ran");
        let resolved =
            resolve_git_failure(&git, &git_dir, nowhere, true, asked).expect("the probe runs");

        assert_eq!(resolved, Answer::No);
    }

    /// The probe reads only failures. Over an answer `git` gave, it would turn "that node is
    /// behind us" into the fork verdict, since the head below is not on this disk.
    #[test]
    fn an_answer_git_gave_is_never_second_guessed() {
        let git = Git::new();
        assert!(git.is_available(), "this test drives the real git");
        let scratch = crate::key::tests::TestScratch::create("restore-answer-stands");
        let (git_dir, _, _) = crate::git::tests::two_commits(&scratch);
        let nowhere = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

        for answer in [Answer::Yes, Answer::No] {
            let left = resolve_git_failure(&git, &git_dir, nowhere, true, answer.clone())
                .expect("the probe runs");
            assert_eq!(left, answer);
        }
    }

    /// A repository record with only the fields the comparison reads set to anything.
    fn repo(rid: &str, visibility: &str, sigrefs: &[(&str, &str)]) -> RepoRecord {
        RepoRecord {
            rid: rid.to_string(),
            name: None,
            visibility: Some(visibility.to_string()),
            allowed: Vec::new(),
            is_delegate: true,
            delegates: vec![OWN_NODE.to_string()],
            scope: None,
            policy: None,
            head: None,
            refs: 1,
            sigrefs: sigrefs
                .iter()
                .map(|(node, head)| ((*node).to_string(), (*head).to_string()))
                .collect(),
            other_seeds: None,
            bundle: None,
        }
    }

    /// A run that gave up before asking still says which repositories no node could hold, so a
    /// home of private repositories is not told every comparison failed.
    #[test]
    fn a_repository_nobody_could_hold_is_not_reported_as_a_comparison_that_failed() {
        let restored = [
            repo("rad:zPriv", "private", &[(OWN_NODE, &oid('a'))]),
            repo("rad:zPub", "public", &[(OWN_NODE, &oid('a'))]),
        ];

        let given_up = nothing_compared(&restored, NetworkCheck::Wanted);

        assert_eq!(
            given_up.standings.get("rad:zPriv"),
            Some(&Standing::NothingToCompare)
        );
        assert_eq!(
            given_up.standings.get("rad:zPub"),
            Some(&Standing::CouldNotAsk)
        );
        assert!(given_up.ahead_of_someone.is_empty());
    }

    /// A repository first written after the backup has no signed refs of this identity in the
    /// archive and may have them on a seed, so any row for it is the fork hazard.
    #[test]
    fn a_node_holding_refs_for_a_repository_the_archive_signed_nothing_in_is_the_fork_hazard() {
        let recorded = BTreeSet::from([oid('b')]);

        assert_eq!(
            without_a_head_of_ours(Some(&recorded)),
            Standing::PeerHoldsOther
        );
        assert_eq!(without_a_head_of_ours(None), Standing::NothingSaysOtherwise);
        assert_eq!(
            without_a_head_of_ours(Some(&BTreeSet::new())),
            Standing::NothingSaysOtherwise
        );
    }

    /// Such a repository reaches the fetch, and reads as an unknown when the run gives up
    /// before asking. Asserted against `no_node_can_hold`, which decides the skip.
    #[test]
    fn a_repository_the_archive_signed_nothing_in_is_still_asked_about() {
        let theirs = repo("rad:zTheirs", "public", &[("z6MkOther", &oid('a'))]);
        assert!(!no_node_can_hold(&theirs), "written off before the fetch");

        let given_up = nothing_compared(&[theirs], NetworkCheck::Wanted);

        assert_eq!(
            given_up.standings.get("rad:zTheirs"),
            Some(&Standing::CouldNotAsk)
        );
    }

    /// A table this build cannot read comes back empty, and an empty record would reassure
    /// the user about every repository.
    #[test]
    fn a_sync_table_this_build_cannot_read_is_not_a_network_holding_nothing() {
        let scratch = crate::key::tests::TestScratch::create("restore-sync-schema");
        let node_db = scratch.path_of("node.db");
        rusqlite::Connection::open(&node_db)
            .expect("scratch database opens")
            .execute_batch("create table \"repo-sync-status-v2\" (repo text, node text, head text)")
            .expect("fixture schema applies");
        let term = term::Term::new(true, term::Verbosity::Quiet, true);

        let _reading_drift = crate::db::while_reading_drift();
        let _ = crate::db::drain_schema_drift();
        assert!(read_what_others_hold(&term, &node_db, OWN_NODE).is_none());

        // The same read on the schema this build follows, so the case above proves the drift
        // and not the fixture
        let readable = scratch.path_of("readable.db");
        rusqlite::Connection::open(&readable)
            .expect("scratch database opens")
            .execute_batch(
                "create table \"repo-sync-status\" (repo text, node text, head text, timestamp integer);
                 insert into \"repo-sync-status\" values ('rad:zAAA', 'z6MkOther', 'abc', 1);",
            )
            .expect("fixture schema applies");
        let _ = crate::db::drain_schema_drift();
        let held = read_what_others_hold(&term, &readable, OWN_NODE).expect("the table is read");
        assert_eq!(
            held.get("rad:zAAA"),
            Some(&BTreeSet::from(["abc".to_string()]))
        );
    }

    /// A table whose repository ids this build cannot match misses every lookup, and a miss
    /// would report the whole home clear.
    #[test]
    fn a_record_this_build_cannot_match_a_repository_in_is_not_a_network_holding_nothing() {
        let scratch = crate::key::tests::TestScratch::create("restore-sync-spelling");
        let node_db = scratch.path_of("node.db");
        rusqlite::Connection::open(&node_db)
            .expect("scratch database opens")
            .execute_batch(
                "create table \"repo-sync-status\" (repo text, node text, head text, timestamp integer);
                 insert into \"repo-sync-status\" values ('zAAA', 'z6MkOther', 'abc', 1);",
            )
            .expect("fixture schema applies");
        let term = term::Term::new(true, term::Verbosity::Quiet, true);

        let _reading_drift = crate::db::while_reading_drift();
        let _ = crate::db::drain_schema_drift();
        assert!(read_what_others_hold(&term, &node_db, OWN_NODE).is_none());
    }

    /// What `git config --list -z` prints for these settings, which is what the reader reads.
    fn listing(settings: &[(&str, &str)]) -> String {
        settings
            .iter()
            .map(|(name, value)| format!("{name}\n{value}\0"))
            .collect()
    }

    #[test]
    fn a_repository_config_out_of_an_archive_gives_up_everything_git_decides_here() {
        // The five settings `rad` leaves in `storage/<rid>/config`. The three under `[core]`
        // describe this disk, so the archive's values are dropped without a word.
        let real = listing(&[
            ("core.repositoryformatversion", "0"),
            ("core.filemode", "true"),
            ("core.bare", "true"),
            ("user.name", "maninak"),
            ("user.email", "maninak@z6MkvAFB"),
        ]);
        let allowed = allowed_config(&real);
        assert_eq!(
            allowed.kept,
            vec![
                ("user.name".to_string(), "maninak".to_string()),
                ("user.email".to_string(), "maninak@z6MkvAFB".to_string()),
            ]
        );
        // An honest archive carries exactly these, so a warning here would fire on every
        // repository of every recovery
        assert!(allowed.dropped.is_empty(), "{:?}", allowed.dropped);
    }

    #[test]
    fn a_repository_config_cannot_carry_a_setting_git_would_run() {
        // Each of these makes git run a command on an ordinary operation. They are spelled as
        // git lists them, lowercased and with subsections.
        let hostile = listing(&[
            ("core.fsmonitor", "/tmp/pwn"),
            ("core.pager", "/tmp/pwn"),
            ("core.sshcommand", "/tmp/pwn"),
            ("remote.rad.url", "ext::sh -c /tmp/pwn"),
            ("alias.st", "!/tmp/pwn"),
            ("include.path", "/tmp/pwn.config"),
            ("user.name", "kept"),
        ]);
        let allowed = allowed_config(&hostile);
        assert_eq!(
            allowed.kept,
            vec![("user.name".to_string(), "kept".to_string())]
        );
        // Named, so the warning says what was left out
        assert_eq!(
            allowed.dropped,
            vec![
                "alias.st",
                "core.fsmonitor",
                "core.pager",
                "core.sshcommand",
                "include.path",
                "remote.rad.url",
            ]
        );
    }

    #[test]
    fn a_setting_with_no_value_is_left_out_rather_than_read_as_an_empty_one() {
        // `[user] name` with no value, which git lists as a name alone and reads as true.
        // Written back as an empty string, it would name nobody and read as false.
        let odd = "user.name\0user.email\nkept\0";
        let allowed = allowed_config(odd);
        assert_eq!(
            allowed.kept,
            vec![("user.email".to_string(), "kept".to_string())]
        );
        assert_eq!(allowed.dropped, vec!["user.name"]);
    }

    #[test]
    fn a_second_displaced_key_does_not_take_the_note_describing_the_first() {
        // Both retirements sit in one directory, and the reader needs to tell them apart
        let first = "the key at keys/radicle is now radicle.retired.\n";
        let second = "the key at keys/radicle is now radicle.retired.2.\n";
        let both = appended(&appended("", first), second);
        assert!(both.contains("radicle.retired.\n"), "{both}");
        assert!(both.contains("radicle.retired.2.\n"), "{both}");
        assert!(
            both.starts_with(first),
            "the older note comes first: {both}"
        );
        assert_eq!(appended("", first), first);
    }

    fn reconciled(standings: &[(&str, Standing)], ahead_of_someone: &[&str]) -> Reconciled {
        Reconciled {
            standings: standings
                .iter()
                .map(|(rid, standing)| ((*rid).to_string(), *standing))
                .collect(),
            ahead_of_someone: ahead_of_someone
                .iter()
                .map(|rid| (*rid).to_string())
                .collect(),
            wanted: NetworkCheck::Wanted,
        }
    }

    /// The two lists give opposite instructions. A repository at risk handed `rad sync
    /// --announce` would publish the fork before the reader reached the warning.
    #[test]
    fn a_repository_at_risk_is_never_also_one_to_push_first() {
        let found = reconciled(&[("rad:zAAA", Standing::PeerHoldsOther)], &["rad:zAAA"]);
        let verdict = Verdict::of(&found);

        assert_eq!(verdict.at_risk, vec!["rad:zAAA"]);
        assert!(verdict.ahead.is_empty(), "{:?}", verdict.ahead);
    }

    /// A repository one node is behind on stays in the push-first list when another node's
    /// answer is unknown.
    #[test]
    fn work_no_node_reported_holding_is_still_pushed_first_when_the_standing_is_unknown() {
        let found = reconciled(&[("rad:zAAA", Standing::CouldNotAsk)], &["rad:zAAA"]);
        let verdict = Verdict::of(&found);

        assert_eq!(verdict.ahead, vec!["rad:zAAA"]);
    }

    /// The sentence covers the whole home, so one compared repository must not carry it over
    /// twenty that were not.
    #[test]
    fn nothing_reported_otherwise_is_said_only_once_everything_was_compared() {
        let some_unknown = reconciled(
            &[
                ("rad:zAAA", Standing::NothingSaysOtherwise),
                ("rad:zBBB", Standing::CouldNotAsk),
            ],
            &[],
        );
        assert!(!Verdict::of(&some_unknown).nothing_was_reported_otherwise);

        let every_one_compared = reconciled(&[("rad:zAAA", Standing::NothingSaysOtherwise)], &[]);
        assert!(Verdict::of(&every_one_compared).nothing_was_reported_otherwise);
    }

    /// A home of only private repositories names them, so the report still mentions the
    /// network and says why nothing was compared.
    #[test]
    fn repositories_no_node_can_ever_hold_are_named_rather_than_passed_over() {
        let found = reconciled(
            &[
                ("rad:zAAA", Standing::NothingToCompare),
                ("rad:zBBB", Standing::NothingToCompare),
            ],
            &[],
        );

        assert_eq!(
            Verdict::of(&found).nothing_to_compare,
            vec!["rad:zAAA", "rad:zBBB"]
        );
    }

    /// No node can hold these and none was asked, so the line must not imply a network check.
    #[test]
    fn nothing_reported_otherwise_is_not_said_when_nothing_was_ever_compared() {
        let found = reconciled(&[("rad:zAAA", Standing::NothingToCompare)], &[]);

        assert!(!Verdict::of(&found).nothing_was_reported_otherwise);
    }

    #[test]
    fn a_standing_says_what_it_means_in_words_a_person_can_act_on() {
        assert_eq!(
            Standing::NothingSaysOtherwise.as_str(),
            "no other node reported work of yours missing from the restored repository"
        );
        assert_eq!(
            Standing::PeerHoldsOther.as_str(),
            "another node holds work of yours missing from the restored repository"
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_private_copy_lands_with_owner_only_permissions() {
        use crate::container::MODE_SECRET;
        use std::os::unix::fs::PermissionsExt;

        let scratch = crate::key::tests::TestScratch::create("restore-owner-only");

        let source = scratch.path_of("source");
        std::fs::write(&source, b"key material").expect("source is writable");
        let target = scratch.path_of("target");
        copy_secret(&source, &target).expect("copy succeeds");

        assert_eq!(
            std::fs::read(&target).expect("target exists"),
            b"key material"
        );
        let mode = std::fs::metadata(&target)
            .expect("target exists")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, MODE_SECRET);
    }
}
