//! Putting a home back, and making sure it is safe to build on.
//!
//! Restoring is done in two moves. Everything is unpacked into a staging directory beside the
//! target home and checked there; only then is it installed. A half-restored identity is worse
//! than none, because it looks like one.

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
use crate::rad::Rad;
use crate::state;
use crate::term;

/// How long to wait for a node this command started to answer on its control socket, and how
/// often to look. The same shape as `backup`'s stop deadline, for the same reason: the command
/// that starts a daemon does not wait for it.
// Both only reach `wait_for_node`, which is the unix half of a platform pair.
#[cfg(unix)]
const NODE_START_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
#[cfg(unix)]
const NODE_START_POLL: std::time::Duration = std::time::Duration::from_millis(200);

/// How a restored repository stands next to what other nodes hold of its signed refs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// No node has said it holds anything other than what the archive holds.
    ///
    /// Deliberately not "in step with the network", which this tool cannot establish. The
    /// node's record of a peer is only rewritten when that peer announces a *different* head
    /// (`repo-sync-status` in heartwood's node database), so a peer that still agrees never
    /// refreshes its row and a row that agrees may be the one the archive itself carried.
    /// Disagreement announces itself; agreement is silent, and silence is not evidence. This
    /// is the standing a record with nothing in it against this copy earns, and all it earns.
    NothingSaysOtherwise,
    /// The archive holds work no node that answered has, said by a node during this restore.
    /// Push it before anything else.
    ///
    /// "No node that answered" and not "the network", for the reason `NothingSaysOtherwise`
    /// carries: a node that said nothing contributed nothing. A repository can also earn this
    /// alongside a row `git` could not read, so the sentence has to stay true of a comparison
    /// that only partly completed.
    ArchiveIsAhead,
    /// The archive holds work the only node that reported did not have, and that node
    /// reported before the archive was taken. The fact keeps; the instruction does not.
    ///
    /// A node behind you in January has had since January to catch up and pass you, and
    /// heartwood writes nothing when a peer still agrees, so no announcement ever corrects
    /// the row. Folded into `ArchiveIsAhead` this printed `rad sync --announce` over a copy
    /// the network could be months ahead of, which is the command that publishes the fork.
    /// Dropped altogether it lost a true and useful thing: this home holds work that, as far
    /// as anything on record goes, exists nowhere else.
    ArchiveIsAheadOfAStaleRecord,
    /// Another node holds signed refs under this identity that the restored copy does not
    /// have. Writing here signs a second history for one peer id, which is the fork.
    PeerHoldsOther,
    /// There was nothing on the other side to hold this against: it is announced to nobody,
    /// delegated to us alone, and allowed to nobody, so no fetch reaches anyone who could hold
    /// signed refs of ours for it.
    ///
    /// Read out of the archive's copy of the identity document, which is the document as of
    /// the backup. A delegate added since is not seen, and that is the one way this standing
    /// can be wrong; the report says which repositories earned it and why.
    NothingToCompare,
    /// Nothing came back to hold this against: the fetch failed, `git` could not answer, or
    /// the node's own record could not be read. A later fetch, with the node running, may.
    ///
    /// Not the standing for a record that was read and holds nothing against this copy. That
    /// is `NothingSaysOtherwise`, and calling it an unknown told every user of a healthy home
    /// to go and run the fetch that had just run: a peer that agrees writes no row, so there
    /// was never a row coming. Kept apart from `NothingToCompare` for the same reason in the
    /// other direction, a home of only private repositories being sent to fetch what nothing
    /// will ever announce.
    CouldNotAsk,
}

impl Standing {
    fn as_str(self) -> &'static str {
        match self {
            Self::NothingSaysOtherwise => "no other node has reported holding anything else",
            Self::ArchiveIsAhead => "holds work no node that answered has",
            Self::ArchiveIsAheadOfAStaleRecord => {
                "holds work no node had when the archive was taken"
            }
            Self::PeerHoldsOther => "another node holds signed refs this copy does not have",
            Self::NothingToCompare => "nothing to compare it with",
            Self::CouldNotAsk => "could not be compared",
        }
    }

    /// Ordered by what it costs to ignore, so that a repository several nodes disagree about
    /// is reported as the answer that most needs acting on. Safe next to one node and unsafe
    /// next to another is unsafe, and an unknown must not be hidden behind another node's
    /// agreement, so `CouldNotAsk` outranks both benign answers.
    ///
    /// `ArchiveIsAhead` losing to `CouldNotAsk` used to lose the advice with it, because the
    /// report read its "push this first" list off these standings and unpushed work whose only
    /// other copy is the archive does not come back by fetching later. `Comparison` carries
    /// that as a fact of its own now, so the ordering here decides only which words go beside
    /// the repository. `NothingToCompare` is at the bottom and never actually reaches the
    /// fold: `classify` cannot produce it, and the caller inserts it before any comparison.
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

/// Settle what a link at one of the home's own directories means before anything is written.
///
/// Every writer follows a link at a directory: `create_dir_all` walks through one, and the
/// copies and `git init` that follow land on the far side. So `keys` pointing at a directory
/// somebody else owns takes the private key, and `storage` pointing at one takes every
/// repository, private ones included.
///
/// Asked rather than refused outright, because pointing `storage` at a bigger disk is an
/// ordinary thing to have done on purpose, and a tool for recovery that cannot recover into
/// the layout somebody actually has is worse than the hazard: planting a link inside a home
/// needs write access to that home, which is already enough to read the key. The prompt names
/// where each one leads, `--yes` answers it the way an unattended restore needs, and a run
/// with nobody to ask refuses, so silence is never taken for consent.
///
/// Separate from `--force`, which says this restore may overwrite what is in the home and
/// never that it may write outside it. `--yes` does answer it, because that is the flag an
/// unattended restore into a second-disk layout has to be able to pass; `SECURITY.md` says so
/// rather than claiming a refusal this does not make.
///
/// What comes back is each name WITH the place it led to when the question was answered.
/// Consent is about the place: a `storage` re-aimed from the big disk to somebody's `.ssh`
/// during the minutes an archive takes to unpack is a different question, and one nobody has
/// been asked.
fn settle_directories_that_point_elsewhere(ctx: &Ctx) -> Result<Vec<Settled>> {
    let elsewhere = ctx.home.directories_that_point_elsewhere();
    if elsewhere.is_empty() {
        return Ok(Vec::new());
    }
    let mut settled = Vec::with_capacity(elsewhere.len());
    for name in &elsewhere {
        let here = ctx.home.path().join(name);
        // The target, so the question is about a place rather than about a word. A link this
        // process cannot resolve is one it cannot describe, and saying so is the answer.
        let there = std::fs::read_link(&here);
        let where_to = match &there {
            Ok(there) => there.display().to_string(),
            Err(e) => format!("somewhere this run could not read: {e}"),
        };
        ctx.term
            .warn(&format!("{} is a symlink to {where_to}", here.display()));
        settled.push(Settled {
            name,
            leads_to: there.ok(),
        });
    }
    ctx.term
        .detail("everything restored into it lands there, not in this home");
    if ctx.term.confirm("restore through them anyway?")? {
        return Ok(settled);
    }
    // Two different noes. Somebody who read the prompt and typed `n` is not a run with nobody
    // to ask, and telling them to pass --yes is advice for the opposite of what they answered.
    let (why, remedy) = match ctx.term.is_interactive() {
        true => (
            "and restoring through them was declined",
            "move them aside, or restore into a different --home",
        ),
        false => (
            "and this run has nobody to ask about it",
            "pass --yes if restoring through them is what you want, or move them aside",
        ),
    };
    Err(Error::refused(
        format!(
            "in {}, {} {} a symlink {why}",
            ctx.home.path().display(),
            term::shortlist(&elsewhere),
            term::is_or_are(elsewhere.len())
        ),
        remedy,
    ))
}

/// One of the home's own directories that leads elsewhere, and where it led when that was
/// settled. `leads_to` is `None` for a link this run could not resolve, which never matches a
/// later reading and so is refused rather than waved through.
struct Settled {
    name: &'static str,
    leads_to: Option<std::path::PathBuf>,
}

/// Refuse a link at one of those directories that is not the one the question was settled on.
///
/// The same three names, asked again after the archive is unpacked and again before the
/// repositories go in, because unpacking a large one takes minutes. Compared against where
/// each link led when it was consented to, not merely against the name: a link swapped to a
/// new target mid-run is a question nobody answered, so the layout somebody actually agreed to
/// passes and everything else is refused. Refused rather than asked about, and `--yes` does
/// not answer it, because a link that changed under a running restore is nobody's layout.
/// `ci/pins.sh` holds both calls, since no test can plant a link mid-run.
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
            "in {}, {} {} a symlink that is not the one this restore began with",
            home.path().display(),
            term::shortlist(&elsewhere),
            term::is_or_are(elsewhere.len())
        ),
        "nothing else should be writing to a home mid-restore: find out what did, then \
         restore again",
    ))
}

pub fn run(ctx: &Ctx, args: &Restore) -> Result<std::process::ExitCode> {
    // Before the `--words` branch below, which writes a key into `keys` of its own.
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

    // Two ways a home is occupied, and only the first used to be asked about. The second is
    // the one that bites quietly: a home whose key was retired by `move` holds no identity and
    // still holds every repository, and a restore rewinds all of their refs with a `--force`
    // fetch.
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
                    "{} holds no identity, and holds {}, which this restore would write over",
                    home.path().display(),
                    occupied.join(", ")
                ),
                "restore into a different --home, or pass --force to overwrite what is there",
            ));
        }
    }
    // Anything but a node proven stopped refuses. A socket that cannot be reached is not a
    // node that is down, and this guard exists precisely because being wrong about that costs
    // the home it was protecting.
    let state = home.probe_node_state();
    if !state.is_stopped() {
        return Err(match state.doubt() {
            Some(doubt) => Error::refused(
                format!("whether a node is running against this home cannot be told: {doubt}"),
                "make sure no node is running, then restore into this home again",
            ),
            None => match home.borrowed_socket() {
                Some(socket) => Error::refused(
                    format!(
                        "a node answered on {}, which RAD_SOCKET names rather than this home's \
                         own socket",
                        socket.display()
                    ),
                    "stop that node, or unset RAD_SOCKET if it belongs to another home, then \
                     restore again",
                ),
                None => Error::refused(
                    "the node is running against the home being restored into",
                    "run `rad node stop` first: a node writing to a home mid-restore corrupts \
                     both",
                ),
            },
        });
    }

    // Read while the archive is certainly still there, because `remember` below records it
    // and a second probe after a multi-gigabyte unpack can find the file moved or the medium
    // ejected. Guessing "unencrypted" there made `doctor` fail an archive that is encrypted.
    let encrypted = crypt::looks_encrypted(archive)?;
    let passphrase = crate::cmd::read_archive_passphrase(ctx, archive)?;

    // Staging sits beside the home by default, so the filesystem that has to hold the
    // restored data is the one proven to have room for it before anything is installed.
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
            "this archive does not match its own manifest, so nothing was installed",
            "check the file transferred completely, or restore an older archive",
        ));
    }
    let manifest = scan.manifest;
    prove_identity(&staging, &manifest)?;
    term.ok(&format!(
        "the archive restores {} ({})",
        manifest.identity.alias.as_deref().unwrap_or("unnamed"),
        manifest.identity.did
    ));

    // Before a byte is written, because exit 4 is documented as "everything is intact and
    // nothing was written". Asked for from inside `replay_policies`, which runs after the
    // identity, the databases and every repository are already on disk, it exited 4 over a
    // home it had just rewritten, and skipped `remember` on the way out so the home did not
    // even know where it came from.
    if args.replay_policies && !Rad::new(ctx.home.path()).is_available() {
        return Err(Error::refused(
            "--replay-policies needs rad on PATH",
            "install rad, or drop the flag and let the database be copied instead",
        ));
    }

    install(ctx, &staging, &settled)?;
    let restored = restore_repositories(ctx, &staging, &manifest, &settled)?;

    let policies_missed = if args.replay_policies {
        replay_policies(ctx, &staging)?
    } else {
        Vec::new()
    };

    // The comparison is the LAST thing, and its failure must not cost the record of what was
    // restored. Written before the `?`, because the identity, the repositories and the
    // policies are already on disk by now: a `rad node start` that fails here would otherwise
    // leave a home that has been fully restored and believes it has never seen an archive.
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

/// Record the archive this home came from.
///
/// Without this, a machine that has only ever restored believes it has no backup at all:
/// `doctor` fails a check that is not true and `diff` has nothing to compare against, on the
/// one day the user most wants to hear that they are covered.
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
    // The archive described repositories it deliberately did not carry, the public ones the
    // network still has. A record that claimed those are here would make the next `diff`
    // report them as newly missing.
    let present: BTreeSet<String> = restored.iter().map(|repo| repo.rid.clone()).collect();
    record.sigrefs.retain(|rid, _| present.contains(rid));
    record.carried.clone_from(&present);
    record.described = present;
    // What `doctor` needs to answer "may another machine still be running this identity". Only
    // a restore can record it: by the time doctor runs, the archive is gone and the machine it
    // came from is somewhere else.
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

/// Refuse to install a key that is not the key the manifest names.
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

/// Whether the manifest describes the key the archive carries. Both spellings of it.
///
/// The manifest names the identity twice, and only the did was ever checked. The node id is
/// the same key written another way, and it is not decoration: it picks the namespace the
/// signed-refs comparison reads and the key it looks the archived oid up under. One that
/// disagrees makes every repository come back "nothing to compare", so the restore exits 0
/// having compared nothing, which is the silent pass that comparison exists to prevent.
fn describes_this_key(did: &str, claimed_did: &str, claimed_node_id: &str) -> Result<()> {
    if did != claimed_did {
        return Err(Error::refused(
            format!("the archived key is {did} but the manifest says {claimed_did}"),
            "this archive is inconsistent; do not install it",
        ));
    }
    if did.strip_prefix("did:key:") != Some(claimed_node_id) {
        return Err(Error::refused(
            format!("the archived key is {did} but the manifest calls its node {claimed_node_id}"),
            "this archive is inconsistent; do not install it",
        ));
    }
    Ok(())
}

/// What the DID of the key at `path` is, when there is a readable one there.
fn read_did_at(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    crate::key::Identity::parse(&text).ok().map(|id| id.did())
}

/// Never destroy the key that is already here.
///
/// `--force` used to overwrite a live private key with no comparison and no way back, so
/// pointing it at the wrong archive ended an identity permanently and said `installed the
/// identity`. Now replacing an identity that is not the archive's own has to be confirmed by
/// name, the displaced key is renamed rather than replaced, and a note is left beside it
/// saying what it is, the way `migrate` does.
///
/// Fails CLOSED. A home whose public key is missing or unreadable cannot be shown to hold the
/// same identity as the archive, so it is treated as a different one and confirmed for. The
/// alternative reading, "cannot tell, so carry on", is the one that loses a key.
fn retire_any_displaced_key(ctx: &Ctx, staging: &Path) -> Result<()> {
    let existing = ctx.home.secret_key();
    if !existing.exists() {
        return Ok(());
    }

    let here = read_did_at(&ctx.home.public_key());
    let incoming = read_did_at(&staging.join("keys/radicle.pub"));
    // Same identity, provably: the DID is derived from the public key, so equal DIDs mean the
    // archive carries the key already here. Nothing is displaced, and retiring anyway filed a
    // fresh copy of the key on every restore, as radicle.retired, .retired.2, .retired.3.
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
            "{} holds a key whose identity could not be read, so whether this archive would \
             replace it cannot be told",
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
        // Appended, never `with_extension`, which REPLACES one: `radicle.retired` became
        // `radicle.pub`, so this renamed the file onto itself, reported success, and left
        // `install` to overwrite the displaced public half seconds later. `radicle.retired.2`
        // became `radicle.retired.pub`, colliding with the first retirement's.
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

/// Say, on disk, what the file beside this note is. Whoever finds it may be doing so years
/// later, on a machine they have forgotten restoring anything on.
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
    // Named only when it is really there. Whoever reads this is looking for files, and one
    // that does not exist sends them hunting; the public half is re-derivable from the
    // private one with `ssh-keygen -y` anyway, so saying nothing costs them nothing.
    let half = match public.and_then(Path::file_name) {
        Some(name) => format!(", and its public half as {}", name.to_string_lossy()),
        None => String::new(),
    };
    let note = format!(
        "A restore on {} put another identity into this home.\n\
         \n\
         The key that used to be at keys/radicle is now beside this note as {name}{half}.\n\
         It was {}.\n\
         \n\
         It still works. Put it back only into a home of its own, and never start a node with\n\
         it while another machine is running one under the same peer id.\n",
        crate::cmd::rfc3339_stamp(jiff::Timestamp::now()),
        former_did.unwrap_or("an identity this tool could not read"),
    );
    let path = ctx.home.keys_dir().join("DISPLACED.txt");
    // Read before it is written, because a second displaced restore is not a correction of the
    // first: `retired_path` never reuses a freed name, so the first key is still at
    // `radicle.retired` while this one goes to `radicle.retired.2`, and a note that truncates
    // leaves two keys in the directory and one paragraph naming only the newer of them.
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

/// One note after another, oldest first, with a blank line between them.
///
/// Separate from the writing so that the joining can be tested: the case worth pinning is the
/// second note, and reaching it through `restore` means two archives, two identities and a
/// home displaced twice.
fn appended(existing: &str, note: &str) -> String {
    if existing.is_empty() {
        return note.to_string();
    }
    // A trailing newline is what every note here ends with, so the separator is one more.
    format!("{existing}\n{note}")
}

/// Move the identity, the config and the databases into place.
fn install(ctx: &Ctx, staging: &Path, settled: &[Settled]) -> Result<()> {
    let home = &ctx.home;
    // Asked again here, not only at the top of `run`. Unpacking and verifying a multi-gigabyte
    // archive takes long enough for a login, a `rad node start` or a socket activation to land
    // in between, and a node writing to the home while this copies its databases over corrupts
    // both. The check up front is the courtesy that fails before the work; this is the one
    // that matters.
    refuse_a_link_that_appeared_mid_restore(home, settled)?;
    let state = home.probe_node_state();
    if !state.is_stopped() {
        return Err(match state.doubt() {
            Some(doubt) => Error::refused(
                format!(
                    "whether a node started against this home while the archive was being \
                     read cannot be told: {doubt}"
                ),
                "make sure no node is running, then restore again: nothing has been written yet",
            ),
            None => match home.borrowed_socket() {
                Some(socket) => Error::refused(
                    format!(
                        "a node answered on {} while the archive was being read, which \
                         RAD_SOCKET names rather than this home's own socket",
                        socket.display()
                    ),
                    "stop that node, or unset RAD_SOCKET if it belongs to another home, then \
                     restore again: nothing has been written yet",
                ),
                None => Error::refused(
                    "the node started against this home while the archive was being read",
                    "run `rad node stop` and restore again: nothing has been written yet",
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

/// The settings a restore takes out of an archive, and the reason there are only two.
///
/// A `config` in `storage/<rid>/` is where git looks for `core.fsmonitor`, `core.pager`,
/// `remote.<name>.url = ext::sh -c ...` and every other setting whose value git RUNS. An
/// archive is a file somebody handed you, so restoring one verbatim hands whoever wrote it a
/// command on the next git operation in that repository.
///
/// Everything else a real Radicle storage config holds is in `CONFIG_FROM_INIT` below, which
/// leaves the node's own name and DID: the two things nothing on this machine can supply.
const CONFIG_ALLOWED: &[&str] = &["user.email", "user.name"];

/// The settings `git init` works out for itself, which a restore therefore drops in silence.
///
/// Each of these describes the filesystem the repository is on NOW: the format version,
/// `filemode`, `ignorecase`, `precomposeunicode`, `symlinks`. The restoring machine's answer
/// is the true one and a year-old answer out of an archive can only be wrong, or aimed:
/// `bare = false` on a storage repository is one git will not use as storage, and
/// `repositoryformatversion = 99` is one every later git command refuses to open.
///
/// Kept apart from the rest so the warning stays worth reading. An honest archive carries
/// exactly these three under `[core]`, so warning about them would mean four lines per
/// repository on every recovery, which is how a reader learns to skip the line that says
/// `core.pager`.
///
/// `extensions.objectformat` is here rather than on the allowlist, and could not help there:
/// the bundle is unpacked into the repository `git init` just made, so a sha256 repository
/// fails at the unbundle, before any config is written. Revisit if Radicle storage ever moves
/// off sha1, which would mean choosing the format at `init` rather than restoring it after.
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

/// What a restore is willing to take out of a repository config, and what it left behind.
struct AllowedConfig {
    kept: Vec<(String, String)>,
    /// Named, not counted: whoever reads the warning is deciding whether the setting mattered.
    /// What `git init` writes for itself is not in here, so an honest archive names nothing.
    dropped: Vec<String>,
}

/// Keep the allowlisted settings out of a config an archive carried, and name the rest.
///
/// Reads what `git config --list -z` printed rather than the config text itself: a parser of
/// ours would have to model quoting, an inline `#`, `[core] key = value` on one line, a value
/// continued with a backslash, and the case folding git applies to a section and a key, and
/// every shape it modelled differently from git is either a setting git reads and this does
/// not, or one dropped without being named. The shipped script asks git the same question, so
/// both readers of an archive agree by construction rather than by two parsers matching.
///
/// The listing is `name\nvalue\0` per setting. A setting with no value at all prints its name
/// alone, and is dropped rather than read as an empty one.
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

/// What came back out of the bundles, and what did not.
struct Restored {
    repos: Vec<RepoRecord>,
    /// Repositories the archive carried that are not in the home now. Carried separately
    /// rather than inferred from the count, because a restore that quietly dropped one would
    /// otherwise report success over a home missing the work it was taken for.
    dropped: Vec<String>,
}

/// Rebuild each archived repository from its bundle.
///
/// One repository that will not open does not end the restore. `backup` already carries on
/// past a repository it cannot bundle, and the asymmetry was worse here: a bundle that fails
/// `fetch.fsckObjects` (old history with a malformed object bundles fine and refuses to
/// unbundle) abandoned every repository after it, and took the state record and the report
/// with it.
/// What a restore says about the object check before it opens the first bundle, if anything.
///
/// `unbundle` asks git to check the objects it is about to write, and a git older than the
/// one that started honouring that on a bundle accepts the setting and never looks at it: the
/// objects land unchecked and the run would otherwise report the same success as one that had
/// checked them. `None` from the reader is a third answer, not the bad one: not knowing which
/// git ran is not the same claim as knowing it did not check.
///
/// Pure, because the only machine that can watch the first arm is one whose git is new enough
/// and the only machine that can watch the second is one whose git is not.
fn bundle_check_notice(reaches: Option<bool>) -> Option<(String, Option<String>)> {
    match reaches {
        Some(true) => None,
        Some(false) => Some((
            "this git does not check the objects inside a bundle it fetches from, so the \
             repositories below are written without that check"
                .to_string(),
            Some(format!(
                "git {}.{} or newer runs it; until then, trust the archive's source",
                crate::git::FSCK_ON_A_BUNDLE_SINCE.0,
                crate::git::FSCK_ON_A_BUNDLE_SINCE.1
            )),
        )),
        None => Some((
            "the version of git could not be read, so it is not known whether the objects \
             inside each bundle were checked"
                .to_string(),
            None,
        )),
    }
}

/// Rebuild each archived repository from its bundle.
///
/// One repository that will not open does not end the restore. `backup` already carries on
/// past a repository it cannot bundle, and the asymmetry was worse here: a bundle that fails
/// `fetch.fsckObjects` (old history with a malformed object bundles fine and refuses to
/// unbundle) abandoned every repository after it, and took the state record and the report
/// with it.
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
        // Deliberately not offering the staging directory: it lives in the scratch this run
        // deletes on its way out, so the bundles named there are gone before the shell prompt
        // comes back. The archive still holds them, and the same restore run again with git
        // installed is the whole remedy.
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

    // Said once, before the first bundle is opened, and only now that there is at least one
    // to open: an archive carrying no repositories takes the early return above.
    if let Some((warning, detail)) = bundle_check_notice(git.fsck_reaches_a_bundle()) {
        ctx.term.warn(&warning);
        if let Some(detail) = detail {
            ctx.term.detail(&detail);
        }
    }

    // The third ask, and the last one before a repository is written. `install` asked before
    // the identity went in, and a link planted at `storage` after that answer is one this
    // `create_dir_all` would walk straight through.
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

/// Put one repository back, so that the caller can decide what a failure costs.
fn restore_one(ctx: &Ctx, git: &Git, staging: &Path, repo: &RepoRecord) -> Result<()> {
    let bundle = staging.join(git::bundle_entry(&repo.rid));
    let target = ctx.home.repository_path(&repo.rid);
    // Whether the repository was already there decides what a failure may clean up. Under
    // `--force` the home can hold a copy this run did not create, and deleting that on a
    // failed unbundle would destroy the thing the restore was meant to protect.
    // Ahead of `existed` and of everything the failure path may sweep, because both of those
    // resolve the link: `exists` follows it, and `remove_dir_all` over one answers with a
    // second error about the wrong thing. A link at the repository's own name is inside a
    // `storage` that is a real directory and so passed the check over the home's three, and
    // `git init --bare` initialises at whatever it points at. The archive names the
    // repository, so whoever wrote it knows which name to plant.
    if is_a_link(&target) {
        return Err(Error::refused(
            format!(
                "{} is a symlink, so this repository would be restored outside the home",
                target.display()
            ),
            "move it aside, or restore into a different --home",
        ));
    }
    let existed = target.exists();

    let put_back = || -> Result<()> {
        git.init_bare(&target)?;
        git.unbundle(&target, &bundle)?;
        if let Some(head) = &repo.head {
            // A skip rather than a failure, and the same one the shipped script makes: the
            // history is already unbundled at this point, and a pointer the manifest got
            // wrong must not cost the refs it was supposed to point at.
            if git::names_a_ref(head) {
                git.set_head(&target, head)?;
            } else {
                // Not a failed check, unlike a policy that did not go back: `HEAD` is a
                // pointer git rebuilds from the default branch, and no signed history rides
                // on it, so a run that lost one is still a complete restore.
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
                            "git runs commands out of a repository config, and an archive is",
                        );
                        ctx.term.detail(
                            "not vouched for by anybody: everything else here is what `git`",
                        );
                        ctx.term.detail("itself wrote when it made the repository");
                    }
                    for (name, value) in &allowed.kept {
                        if let Some(why) = git.set_config(&target, name, value)? {
                            ctx.term.warn(&format!(
                                "{}: `{name}` did not come back out of the archive's config: \
                                 {why}",
                                repo.display_name()
                            ));
                        }
                    }
                }
                // The repository keeps the config `git init` gave it, which is a working one:
                // a config the archive mangled is a line lost, not a repository lost.
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
            // An empty bare repository is not nothing: the next inventory counts it, the next
            // archive carries it, and `rad` reads it as a repository with no history at all.
            if !existed
                && let Err(swept) = std::fs::remove_dir_all(&target)
                // Nothing to sweep when the failure was `git init` itself, and saying so about
                // a directory that was never made only adds noise to an already bad moment.
                && swept.kind() != std::io::ErrorKind::NotFound
            {
                ctx.term.detail(&format!(
                    "the half-made {} could not be removed either: {swept}",
                    target.display()
                ));
            }
            Err(e)
        }
    }
}

/// What a whole run's comparison found.
///
/// The standings are one answer per repository; `ahead_of_someone` is a second, orthogonal one
/// that a single standing cannot carry. See `Comparison`.
#[derive(Default)]
struct Reconciled {
    standings: BTreeMap<String, Standing>,
    ahead_of_someone: BTreeSet<String>,
    wanted: NetworkCheck,
}

/// Whether this run meant to ask the network anything.
///
/// A repository nothing came back for is a check that did not run, not a check that passed,
/// and it costs the exit code for that reason. `--no-reconcile` is the one case where an
/// unasked question is what was asked for, so it is carried here rather than guessed at from
/// standings that look the same either way.
#[derive(Default, Debug, PartialEq, Eq)]
enum NetworkCheck {
    /// The run put the repositories to the network, or tried to.
    #[default]
    Wanted,
    /// `--no-reconcile`: nothing was compared and nothing was meant to be.
    Declined,
}

/// Compare each restored repository with what other nodes hold of its signed refs.
///
/// This is the check that separates a restore from a data-loss event. Signed refs are a chain:
/// if the archived copy is behind what the network has, and the user commits on top of it,
/// they sign a second history for their own namespace, and peers see a fork that does not
/// resolve itself.
///
/// The fetch is what makes the answer current; it is not itself the answer. See `classify` for
/// why the network's view of our own namespace has to come from the node's record of what
/// peers announced rather than from the refs sitting in local storage.
fn reconcile(ctx: &Ctx, manifest: &Manifest, restored: &[RepoRecord]) -> Result<Reconciled> {
    if restored.is_empty() {
        return Ok(Reconciled::default());
    }
    let node_id = &manifest.identity.node_id;

    let rad = Rad::new(ctx.home.path());
    if !rad.is_available() {
        ctx.term
            .warn("rad is not on PATH, so nothing was compared with the network");
        ctx.term
            .detail("run `rad sync <rid> --fetch` for each repository before you write to it");
        return Ok(nothing_compared(restored, NetworkCheck::Wanted));
    }
    let mut standings = Reconciled::default();

    // What the record held before this run could add to it, read while nothing can be writing
    // to it. Not from the archive's own copy in staging: `node/node.db` rides in an archive
    // only under `--with-node-db`, so for an ordinary archive there is no such file, the
    // baseline came back empty, and every row in the home's own months-old table read as one
    // that had just arrived. The home's copy at this instant is the archive's where the
    // archive carried one and the machine's own where it did not, and neither was written by
    // this run, which is the whole of what the split needs.
    // What makes a row that arrives during this run worth the stronger reading: a node
    // connecting for the first time subscribes to a fixed backlog of gossip, twenty-four hours
    // in heartwood 1.x (`INITIAL_SUBSCRIBE_BACKLOG_DELTA`), so what reaches a home with no
    // node database is a day old at most. A home that already had one asks for everything
    // since it was last online, which on an archive restored months later is months of replay;
    // those rows are the ones the baseline holds back, and this is why holding them back is
    // not merely conservative. Revisit if heartwood makes either window unbounded.
    let baseline = match crate::db::read_synced_heads(&ctx.home.node_db(), node_id) {
        Ok(baseline) => Some(baseline),
        Err(e) => {
            ctx.term.warn(&format!(
                "what the node already knew could not be read, so nothing here will be \
                 reported as work to push: {e}"
            ));
            None
        }
    };
    // The node is started here, and this is the only place it can be. Installing over a live
    // home corrupts both, so restore refuses to begin while the node runs; comparing with the
    // network needs a node to ask. Held together, those two rules made this check unreachable:
    // it warned and returned on every restore, while the README sold the comparison as the
    // thing that stops the user forking their own peer history. So the node is started once
    // the identity is safely in place, and put back the way it was found.
    //
    // Started only when the node is known to be down. A doubt here means `rad node start`
    // would be aimed at a home something else may already be serving, and a second node on one
    // key is the fork the whole comparison exists to prevent.
    let started_here = if !ctx.home.probe_node_state().is_stopped() {
        false
    } else {
        ctx.term
            .step("starting the node, to compare what was restored with the network");
        // Reported, never propagated. Everything from here on happens after the identity,
        // the repositories and the policies are on disk, and an error escaping would take the
        // report of what did not come back with it.
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
            ctx.term
                .detail("run `rad node start`, then `rad sync <rid> --fetch` before you write");
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
        // Reported, never propagated: the standings are the answer this function owes its
        // caller, and a stop that failed must not stand in front of them.
        if !matches!(rad.stop_node(), Ok(true)) {
            ctx.term
                .warn("the node was started to run this check and would not stop again");
            ctx.term
                .detail("stop it with `rad node stop` if you meant it to stay down");
        }
    }
    Ok(standings)
}

/// Whether the node answered on its control socket before `NODE_START_TIMEOUT` elapsed.
///
/// `rad node start` returns as soon as the daemon forks, so every query fired straight after
/// it fails on a machine where the node takes a moment: the comparison then filled with
/// `CouldNotAsk` for every repository and the restore reported success having compared
/// nothing. `backup`'s `quiesce` waits the same way for the same reason.
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

/// There is no control socket to poll here, so the unix `wait_for_node` would spend
/// `NODE_START_TIMEOUT`
/// reaching the one answer it can reach and then report that a node which may well be up would
/// not start. The fetches are asked instead: they fail per repository, saying so per
/// repository, which is a true sentence where "the node would not start" was not.
#[cfg(not(unix))]
fn wait_for_node(_ctx: &Ctx) -> bool {
    true
}

/// What one repository's comparison found.
///
/// Two answers rather than one, because they are facts about different nodes and folding them
/// loses the one with a permanent consequence. A repository can be ahead of the seed that has
/// answered and unknown to the seed that has not; reporting only the worse of those drops it
/// out of the "push this first" list, and unpushed work whose only other copy is the archive
/// does not come back by fetching later.
struct Comparison {
    standing: Standing,
    /// Some node's record is an ancestor of what the archive holds, so this repository carries
    /// work that node has never seen.
    someone_is_behind: bool,
}

/// Where a row in the node's record came from, which decides what may be read out of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    /// Some node wrote it while this restore was running.
    AnnouncedSinceRestore,
    /// The home already held it before this run began: the archive's row where the archive
    /// carried a node database, the machine's own where it did not.
    CameWithTheArchive,
}

/// Where the archive's signed refs stand against what other nodes hold of them.
///
/// `held` is what those nodes have said they carry of *our* `rad/sigrefs` that is not what the
/// archive carries. That record, and not the copy in local storage, is the only view of our
/// own namespace this machine can get: `rad sync <rid> --fetch` over a repository already in
/// storage is a pull, and a pull deliberately ignores the local peer's key, so our own refs
/// stay exactly as the archive wrote them however far the network has moved. Reading those
/// back and calling them the network is what reported every restore in step with a network
/// nobody had asked.
///
/// Kept apart from the fetching and the spawning of `git` because this is the decision the
/// whole tool exists for: writing on top of a restored copy another node has moved past forks
/// your own peer history, and there is no undo.
///
/// `is_ancestor` is a closure rather than a value, so the classification can be tested without
/// a repository on disk.
fn classify<F>(held: &Evidence, mut is_ancestor: F) -> Result<Comparison>
where
    F: FnMut(&str) -> Result<Answer>,
{
    // Nothing on record against the archive, which is what `NothingSaysOtherwise` claims and
    // the whole of what it claims. Not `CouldNotAsk`: the record was read, and it holds
    // nothing that contradicts this copy.
    let mut standing = Standing::NothingSaysOtherwise;
    let mut someone_is_behind = false;
    for (origin, head) in held.rows() {
        standing = standing.worse_of(if !git::names_an_oid(head) {
            // A row shaped like a flag would be one to `merge-base`, which takes no `--`. A
            // malformed row is a database this tool cannot read, not evidence of a fork.
            Standing::CouldNotAsk
        } else {
            match is_ancestor(head)? {
                // Their head is in our history, so they are behind and we hold the work. True
                // of a row that arrived just now; only ever true of one the archive carried at
                // the moment the backup was taken. A node that was behind in January is a node
                // that has had since January to catch up and pass us, and it announces nothing
                // when it does not, so acting on that row is how a copy the network is ahead
                // of gets told to run `rad sync --announce`.
                Answer::Yes => match origin {
                    Origin::AnnouncedSinceRestore => {
                        someone_is_behind = true;
                        Standing::ArchiveIsAhead
                    }
                    Origin::CameWithTheArchive => Standing::ArchiveIsAheadOfAStaleRecord,
                },
                // Their head is not in our history: work signed under this key that is not
                // here. Taken from either origin, because this reading cannot decay. A node
                // that once held refs under your key that you lack still holds them, so a row
                // the archive carried is as true today as the day it was written.
                //
                // `resolve_git_failure` turns a `git` that could not resolve their head at all
                // into this, having first established the object is genuinely absent.
                Answer::No => Standing::PeerHoldsOther,
                // `git` could not run, or could not open the repository. That says nothing
                // about any peer, and saying it does costs exit 3 and a warning that somebody
                // has forked their own identity.
                Answer::CouldNotAsk { .. } => Standing::CouldNotAsk,
            }
        });
    }
    Ok(Comparison {
        standing,
        someone_is_behind,
    })
}

/// What other nodes have said they hold of one repository's signed refs that is not what the
/// archive holds, split by whether the archive itself brought the row.
///
/// A row that agrees with the archive is in neither set. Nothing distinguishes the two things
/// it can be: heartwood rewrites a peer's row only when that peer announces a *different*
/// head, so an agreeing row is either a peer's first word or one that was in the table before
/// this run, which for a `--with-node-db` archive is the archive's own. Reading it as the
/// network agreeing is the archive being compared with itself.
///
/// A row that differs is kept, and where it came from decides what may be read out of it. Both
/// readings hold for a row that arrived during this run. Only the one that cannot decay, a
/// node holding refs signed under this key that are not here, may be taken from a row the
/// archive carried. See `classify`.
#[derive(Default)]
struct Evidence {
    announced_since_restore: BTreeSet<String>,
    came_with_the_archive: BTreeSet<String>,
}

impl Evidence {
    /// Every row worth asking `git` about, each beside where it came from.
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
    /// Not known. Every row then reads as one that was already there, which is the reading
    /// that claims less: it withholds "push this first" and keeps the fork verdict.
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

/// `recorded` is what the node's record holds for one repository now, and `before` what the
/// same record held for it when this restore started.
///
/// Split on the head alone, because `read_synced_heads` drops the node column: a second node
/// announcing a head the archive already had against a first node reads as a row that was
/// already there. That direction only ever withholds "push this first", which is the safe one.
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
        // Two spellings of one commit are not two commits, and treating them as two spends a
        // `git` to report unpushed work that does not exist.
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

/// The repository id in the form heartwood's own tables use, which carries the `rad:` prefix.
///
/// `rad::is_identifier` accepts both spellings and the archive is written by whoever wrote it,
/// so a manifest carrying bare `z...` rids restored, fetched, and then matched no row at all:
/// every repository quietly became "could not be compared" with nothing saying why.
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
/// `rad sync --fetch` returns when the fetches are done, and a peer's refs announcement is a
/// separate message that arrives over the same connection on its own schedule. Read
/// microseconds later, the table holds only what the archive itself carried, so a fork created
/// after the backup was taken goes unseen on a network that is about to say so.
///
/// A flat wait, with nothing to poll for: a peer that holds exactly what the archive holds
/// writes no row at all, so no observable state ever says the answers are in. The length was
/// inherited from what this command spends waiting for a node it started, and it is spent on
/// every restore that fetched anything rather than only when something is wrong, which is why
/// the line saying so names the number. Named from the constant, so the two cannot drift into
/// a run that says twenty and waits thirty.
fn what_others_hold(ctx: &Ctx, node_id: &str) -> Option<BTreeMap<String, BTreeSet<String>>> {
    ctx.term.step(&format!(
        "waiting {} seconds for other nodes to say what they hold of these refs",
        GOSSIP_WINDOW.as_secs()
    ));
    std::thread::sleep(GOSSIP_WINDOW);
    read_what_others_hold(&ctx.term, &ctx.home.node_db(), node_id)
}

/// The reading on its own, so that what it decides can be tested without the wait and without
/// a home around it.
///
/// `None` rather than an error when the record cannot be read, because propagating it would
/// cost the report of which repositories did not come back at all, which this run established
/// long before the comparison and which no later command can reconstruct.
fn read_what_others_hold(
    term: &term::Term,
    node_db: &Path,
    node_id: &str,
) -> Option<BTreeMap<String, BTreeSet<String>>> {
    match crate::db::read_synced_heads(node_db, node_id) {
        // A table that reads perfectly and whose repository ids are spelled some way this
        // build does not look up. Every lookup would miss, every repository would earn "no
        // other node has reported holding anything else", and the run would reassure its
        // reader on a table it had in its hands. `prefixed_rid` exists because the archive's
        // side of this went wrong once; nothing guarded heartwood's side.
        Ok(held) if !held.is_empty() && !held.keys().any(|repo| repo.starts_with(RID_PREFIX)) => {
            term.warn(
                "the node spells repository ids in a way this build does not recognise, so \
                 nothing was compared",
            );
            None
        }
        // A table this build cannot read comes back empty, and an empty record means "nobody
        // has reported anything else", which would reassure the reader on the strength of a
        // table nobody managed to open. Asked about this read rather than about the process,
        // because any other reader's drift would otherwise discard a record that was read
        // perfectly. `main` prints which table moved.
        Ok(_) if crate::db::saw_schema_drift_in(node_db, "sync status table") => {
            term.warn("this build cannot read part of the node's schema, so nothing was compared");
            None
        }
        Ok(held) => Some(held),
        Err(e) => {
            term.warn(&format!(
                "the node's record of what other nodes hold could not be read: {e}"
            ));
            None
        }
    }
}

/// Read a `git` that could not answer as a fact about the peer's head or one about this disk.
///
/// A peer's sigrefs commit that is not in local storage makes `merge-base` exit 128, and that
/// is the fork hazard rather than a broken machine: our own namespace is the one thing a pull
/// never brings back. But an unreadable repository exits 128 too, and blaming a peer for that
/// costs exit 3 and a warning that somebody's identity may have forked.
///
/// So the object is looked for, and the caller says whether the same repository could produce
/// the archived head. `cat-file -e` answers "absent" for an object sitting in a pack that was
/// truncated in transit, which a restore is exactly the moment for, and every object in that
/// pack answers the same way. The archived head is the control: a restore that worked put it
/// there, so a store that cannot produce it either is a store that cannot answer, not a
/// network holding something else.
///
/// Asking instead whether the archived head reaches itself proves nothing, because
/// `merge-base --is-ancestor A A` answers on equality without opening a single object.
///
/// One state is still read wrongly. The control proves that some lookup path works, not the
/// one the peer's head needed: a fetch that wrote a second, short pack holding only the peer's
/// head reports the fork over a repository nobody else has touched. Revisit if `git` grows a
/// cheap way to ask whether a lookup failed or came back empty.
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
/// The paths that give up before comparing anything used to hand back an empty record, which
/// `--json` rendered as empty `atRisk`, `ahead` and `notChecked` arrays: a run that never
/// asked the network anything was indistinguishable, to a script, from one that asked and
/// found nothing wrong.
fn nothing_compared(restored: &[RepoRecord], wanted: NetworkCheck) -> Reconciled {
    Reconciled {
        wanted,
        standings: restored
            .iter()
            .map(|repo| {
                // The two are still told apart. Collapsed into "could not be compared", a home
                // of three private repositories was told 3 of 3 had failed and sent to run a
                // fetch that fails for those by design, whatever the reason this run never
                // asked anybody anything.
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

/// The standing for a repository the archive holds no signed refs of ours for.
///
/// There is no head to run `merge-base` against, and none is needed: a row here says a node
/// announced that it holds signed refs under this key, and this copy holds none, which is the
/// fork hazard whatever the two heads would have been. A repository first written in after the
/// backup was taken is exactly this shape, and it used to be skipped as nothing to compare.
fn without_a_head_of_ours(recorded: Option<&BTreeSet<String>>) -> Standing {
    match recorded {
        Some(heads) if !heads.is_empty() => Standing::PeerHoldsOther,
        _ => Standing::NothingSaysOtherwise,
    }
}

/// Whether no node will ever hold signed refs of ours for this repository, whoever is asked.
///
/// Announced to nobody, delegated to us alone, allowed to nobody. One place, so the paths that
/// give up before asking say the same thing about a repository as the path that asks.
///
/// Deliberately NOT "the archive holds no signed refs of ours for it". That is a fact about
/// the archive and was read as one about the network: a repository first written in after the
/// backup was taken has no signed refs of ours in the archive and every reason to have them on
/// a seed, and skipping it reported the one case this command exists for as nothing to
/// compare, at exit 0. Such a repository is fetched like any other, and any row for it is a
/// node holding refs signed under this key that are not here.
///
/// Read out of the archive's copy of the identity document, so a delegate or an allowed peer
/// added after the backup is not seen. That direction can only leave a repository uncompared
/// that somebody does hold, which is why the report says who was not asked and why.
fn no_node_can_hold(repo: &RepoRecord) -> bool {
    // Private on its own is not enough, because `rad sync --fetch` reaches the delegates and
    // allowed peers of a private repository, and one shared with a collaborator is precisely
    // the one whose sigrefs can be behind theirs.
    repo.has_nowhere_to_fetch_from()
}

/// Never returns an error, because everything it can fail at happens after the identity, the
/// repositories and the policies are on disk. A `git` that vanished mid-run or a file
/// descriptor limit reached on the twelfth repository used to propagate past `report`, and the
/// user was never told which repositories the archive carried and the home did not get.
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
        // Nobody to ask: announced to nobody, delegated to us alone, allowed to nobody.
        // Asking anyway spends a fetch per repository to fail, and reports the feature working
        // as a fault. `no_node_can_hold` says what counts as nobody and why private alone
        // does not.
        if no_node_can_hold(repo) {
            standings.insert(repo.rid.clone(), Standing::NothingToCompare);
            continue;
        }
        // `None` is a repository the archive holds no signed refs of ours for, and it is
        // fetched like any other. There is no head to run `merge-base` against, and none is
        // needed: a row saying some node holds our sigrefs is, on its own, a node holding refs
        // signed under this key that this copy does not have.
        let archived = repo.sigrefs.get(node_id);
        // Nothing in this manifest was vouched for by anybody. `merge-base` takes no `--`, so
        // a value reading as a flag would be one, and a revision expression would have git
        // resolve something the archive chose. Not compared rather than refused outright: one
        // repository with a bad oid is not a reason to abandon the comparison of the rest, and
        // "could not ask" is the honest standing for it.
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
        // Asked once per repository rather than once per head: the control is the archived
        // head, which does not change between two peers' rows. Asked only when a `git` failure
        // needs reading, because a repository every row of which answered cleanly should not
        // spend a process on a question nothing is waiting for.
        let mut control = None;
        // One line per repository, not one per row. A repository several of whose rows cannot
        // be read said the same sentence several times, with nothing to tell the reader that
        // it was still the one repository.
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
            // `git` itself could not be run: the binary went away mid-restore, or this process
            // is out of file descriptors. One repository's worth of unknown, and the rest of
            // the report still owed to the user.
            Err(e) => {
                ctx.term
                    .warn(&format!("{} could not be compared: {e}", repo.rid));
                standings.insert(repo.rid.clone(), Standing::CouldNotAsk);
            }
        }
    }
}

/// Re-apply seeding and following through `rad`, for a Radicle whose schema has moved on.
fn replay_policies(ctx: &Ctx, staging: &Path) -> Result<Vec<String>> {
    let path = staging.join("policies.json");
    if !path.is_file() {
        ctx.term
            .warn("this archive has no policies.json, so there was nothing to replay");
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(&path).map_err(|e| Error::io(&path, e))?;
    let policies: Policies = serde_json::from_str(&text)?;

    // `run` refused before installing anything if `rad` was missing then, so reaching this
    // means it went away mid-restore. Reported as every row missed, not raised: every byte is
    // already on disk, and exit 4 here would say that nothing was written.
    let rad = Rad::new(ctx.home.path());
    if !rad.is_available() {
        ctx.term
            .warn("rad went away mid-restore, so no policy was replayed");
        return Ok(policies.identifiers());
    }
    ctx.term.step("replaying policies through rad");

    // `policies.json` comes out of the same unvouched-for archive as everything else, and a
    // rid or a nid lands in an argv position where a leading `-` is a flag rather than an id.
    // Skipped rather than fatal: one lost seeding decision the user can make again by hand is
    // a smaller loss than abandoning the rest of the replay, and neither is silent.
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
        ctx.term.warn(&format!(
            "{} skipped, because the archive spells an identifier in a way `rad` would read \
             as a flag: {}. Seed or follow those by hand",
            crate::term::count(skipped.len(), "policy row", "policy rows"),
            crate::term::shortlist(&skipped)
        ));
    }
    if !failed.is_empty() {
        // `rad` printed its own reason on stderr. Without this the run said nothing and exited
        // 0, so a restore that put back every repository and none of the seeding policies read
        // as a clean one.
        ctx.term.warn(&format!(
            "`rad` refused {}: {}. Those decisions are not in place",
            crate::term::count(failed.len(), "policy row", "policy rows"),
            crate::term::shortlist(&failed)
        ));
    }
    skipped.extend(failed);
    Ok(skipped)
}

/// Replay one policy row, unless its identifier is one `rad` would read as a flag.
///
/// The two outcomes are kept apart because they need different answers: a skipped row is this
/// tool refusing a hostile archive, and a failed one is `rad` refusing a decision it was asked
/// to put back.
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
/// A value rather than a handful of expressions inside `report`, because these are the whole
/// of what a restore tells somebody about their signed refs and until they were one the only
/// way to check them was to read a restore's output by eye.
struct Verdict<'a> {
    /// Another node holds signed refs this copy does not. Do not write in these.
    at_risk: Vec<&'a str>,
    /// Work no reporting node has, whose only other copy is the archive. Push these.
    ahead: Vec<&'a str>,
    /// Nothing came back to hold against. Named, so that a comparison which answered nothing
    /// does not read as a clean bill.
    not_checked: Vec<&'a str>,
    /// No node will ever hold these: announced to nobody, or with no signed refs of ours in
    /// the archive. Said out loud, because a home of only private repositories otherwise gets
    /// a restore that mentions the network nowhere at all.
    nothing_to_compare: Vec<&'a str>,
    /// Work no node had when the archive was taken, and no node has spoken since. The fact,
    /// without the `rad sync --announce` that belongs beside a fresh one.
    ahead_of_a_stale_record: Vec<&'a str>,
    /// Whether anything at all was held against what a node reported, which is what the line
    /// saying nobody has reported otherwise rests on.
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
        // Off the second answer rather than off the standings, because a repository some node
        // is behind on and another node has said nothing about reports as the unknown, and the
        // work it holds that nowhere else does would then never be named.
        //
        // Minus the ones at risk. The two lists give opposite instructions, and a repository
        // in both was handed `rad sync --announce` first, which is the command that publishes
        // the fork the second list exists to stop.
        let ahead = reconciled
            .ahead_of_someone
            .iter()
            .map(String::as_str)
            .filter(|rid| !at_risk.contains(rid))
            .collect();
        // Gated on a repository having genuinely been held against a row some node wrote.
        // Gated instead on the map being non-empty, it printed over a home of private
        // repositories nobody else can hold, and over runs where most comparisons failed:
        // right under the line saying so, which read as a partial pass.
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
                .map(|(rid, standing)| serde_json::json!({"rid": rid, "standing": standing.as_str()}))
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
        // Counted off the database now in the home, not off the manifest. `backup` fills the
        // manifest's policy summary at every tier, but only the tiers above `identity` carry
        // `policies.db`, so an identity-tier restore reported "45 seeding and 3 following
        // policies" over a home that seeds nothing, and `remember` then wrote those numbers
        // into the state record for the next `diff` to blame as drift.
        //
        // Reported, never propagated: this line sits in front of the fork warning, the list of
        // repositories that did not come back and the exit code, and a `policies.db` that
        // would not open used to take all three with it.
        match crate::db::read_policies(&ctx.home.policies_db()) {
            Ok(installed) => term.hint(&format!(
                "{}, {} seeding and {} following policies",
                term::count(restored.len(), "repository", "repositories"),
                installed.seeded().count(),
                installed.followed().count()
            )),
            Err(e) => {
                term.hint(&term::count(restored.len(), "repository", "repositories"));
                term.warn(&format!(
                    "the policies that came back could not be counted: {e}"
                ));
            }
        }
        if !not_checked.is_empty() {
            term.warn(&format!(
                "{} of {} repositories could not be compared with the network",
                not_checked.len(),
                restored.len()
            ));
            // Named rather than only counted, and shortlisted rather than listed: under
            // `--no-reconcile` on a seed this is every repository in the home.
            term.detail(&term::shortlist(&not_checked));
            // Several causes, and the remedy has to cover them without asserting any. A fetch
            // that failed is answered by running it again; a run that never asked, a head no
            // git would take, and a node database this build could not read are not, and
            // telling somebody to re-run the command that has just run is how the schema check
            // used to send people to start a node already up.
            term.detail("nothing came back to hold these against. Read any warning above for");
            term.detail("why, and if this run did ask, `rad sync <rid> --fetch` again with the");
            term.detail("node running");
        }
        if !nothing_to_compare.is_empty() {
            term.hint(&format!(
                "{} announced to nobody, delegated to you alone and allowed to nobody, so no \
                 node can hold anything to compare: {}",
                term::count(
                    nothing_to_compare.len(),
                    "repository is",
                    "repositories are"
                ),
                term::shortlist(&nothing_to_compare)
            ));
        }
        if nothing_was_reported_otherwise {
            term.detail("no other node has reported holding signed refs of yours missing here");
            term.detail("that is not proof there are none: a fetch never brings your own back");
        }
        if !ahead_of_a_stale_record.is_empty() {
            // The fact without the instruction. The only node on record was behind when the
            // archive was taken and has said nothing since, and heartwood writes nothing for
            // a peer that still agrees, so that row is as likely to be as stale as the
            // archive as it is to be current. `rad sync --announce` on a copy the network has
            // moved past is the command that publishes the fork.
            term.warn(&format!(
                "{} hold work no node had when the archive was taken: {}",
                term::count(
                    ahead_of_a_stale_record.len(),
                    "repository is thought to",
                    "repositories are thought to"
                ),
                term::shortlist(&ahead_of_a_stale_record)
            ));
            // The archive's own date rather than a figure standing in for it. How stale that
            // record might be is exactly the age of the backup, and somebody deciding whether
            // to announce is deciding on which month it was taken.
            let taken = manifest
                .created
                .get(..10)
                .unwrap_or(manifest.created.as_str());
            term.detail(&format!(
                "no node has spoken since, so that may be as old as the archive, {taken}:"
            ));
            term.detail("fetch, and look at what the network holds under your peer id, before");
            term.detail("you announce");
        }
        if !ahead.is_empty() {
            term.warn(&format!(
                "{} work no node that answered has; push them first",
                term::count(ahead.len(), "repository holds", "repositories hold")
            ));
            for rid in &ahead {
                term.hint(&format!("rad sync {rid} --announce"));
            }
        }
        if !dropped.is_empty() {
            term.blank();
            term.fail(&format!(
                "{} the archive carried could not be restored:",
                term::count(dropped.len(), "repository", "repositories")
            ));
            for rid in dropped {
                term.detail(rid);
            }
            term.detail("the archive still holds them; nothing about it was changed");
        }
        if !at_risk.is_empty() {
            term.blank();
            term.fail("another node holds signed refs of yours that these copies do not have:");
            for rid in &at_risk {
                term.detail(rid);
            }
            term.blank();
            term.fail("do not commit or push in them until this is resolved");
            term.detail("a fetch cannot bring your own signed refs back: to a node that already");
            term.detail("has the repository, `rad sync --fetch` is a pull, and a pull ignores");
            term.detail("your own key. Clone the repository into an empty home to see what the");
            term.detail("network has under your peer id before you write anything here");
        }
        term.blank();
        if manifest.node.was_running {
            match &manifest.node.why_running_is_unknown {
                // Said as a possibility, because that is what it is: the run that wrote this
                // archive could not reach the socket and wrote the cautious answer.
                Some(doubt) => term.warn(&format!(
                    "the machine this archive came from may have had a node running: \
                     the run that took it could not tell ({doubt})"
                )),
                None => term.warn(
                    "the machine this archive came from had a node running when it was taken",
                ),
            }
            term.detail("never run two nodes with one key: stop the other one first");
        }
        term.detail("start the node with `rad node start`");
    }

    // A repository this run meant to compare and could not is a failed check too. The fork
    // hazard is the reason this tool exists rather than a tarball, and a run that never got
    // to look at it has not established the thing its exit code would be claiming: `rad` off
    // PATH, a node that would not start and a fetch that failed all end here, and a scheduled
    // restore that exited 0 over any of them is the last anyone hears. Under `--no-reconcile`
    // the same standings mean the user asked for exactly this, which is why the two are told
    // apart rather than read off the standings.
    let unchecked = reconciled.wanted == NetworkCheck::Wanted && !not_checked.is_empty();
    // A repository the archive carried and the home did not get is a failed check, the same
    // as a fork hazard: the run did not deliver what it was asked for, and a scheduled restore
    // that exited 0 over it would be the last anyone heard about it. A seeding or following
    // decision that did not go back counts for the same reason.
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
    /// A manifest names its identity twice and both have to be the key in the archive. Only
    /// the did was checked, so an archive whose node id said something else installed happily
    /// and then compared nothing: every repository came back "nothing to compare", because the
    /// sigrefs are looked up under that node id, and the run exited 0 over it.
    #[test]
    fn a_manifest_whose_node_id_is_not_its_key_is_refused_like_a_wrong_did() {
        const DID: &str = "did:key:z6MkjDYUKMUeY58Vtr8dGJrHRvnTfjKWVGCBYJDVTHXsXzm5";
        const NODE_ID: &str = "z6MkjDYUKMUeY58Vtr8dGJrHRvnTfjKWVGCBYJDVTHXsXzm5";
        const SOMEBODY_ELSE: &str = "z6MktaNvN1tjt7bWaP9WNaKUnfLNqk7oYGjPGyMbcHDW2i8x";

        assert!(describes_this_key(DID, DID, NODE_ID).is_ok());
        assert!(describes_this_key(DID, DID, SOMEBODY_ELSE).is_err());
        assert!(describes_this_key(DID, &format!("did:key:{SOMEBODY_ELSE}"), NODE_ID).is_err());
        // A node id that is the did over again, rather than the key on its own.
        assert!(describes_this_key(DID, DID, DID).is_err());
    }

    use super::*;

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

    /// All three answers about the object check, on a machine that can only ever see one.
    ///
    /// A git new enough to run the check says nothing, because a restore that behaved as
    /// promised has nothing to report. The other two are different claims and must not be
    /// worded as one: "did not check" is a fact about this git, "could not be read" is a fact
    /// about this reader, and only the first names the version that would fix it.
    #[test]
    fn only_the_git_that_checks_a_bundle_passes_without_a_word_about_it() {
        assert_eq!(bundle_check_notice(Some(true)), None);

        let (warning, detail) =
            bundle_check_notice(Some(false)).expect("a git that does not check says so");
        assert!(
            warning.contains("does not check the objects inside a bundle"),
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
        // The bool is `rad`'s exit status. Discarding it was how a restore could put back
        // every repository, none of the seeding decisions, and still exit 0.
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

    /// Forty hexadecimal characters, so the value reaches `git` rather than being turned away
    /// as a row that is not an oid. Which oid it is never matters: the closure answers.
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

    /// The bug this whole function was rewritten for. The network side used to be read out of
    /// local storage, and `rad sync --fetch` over a repository already there is a pull,
    /// which ignores the local peer's own key: the refs read back were always the ones the
    /// archive had just written. Every restore reported every repository in step, on no
    /// evidence, and in step is the one answer that means "go ahead and write".
    #[test]
    fn a_node_holding_signed_refs_this_copy_does_not_have_is_the_fork_hazard() {
        let calls = std::cell::Cell::new(0);
        let compared = classify(&announced(&[oid('b')]), asked(Answer::No, &calls))
            .expect("the ancestry answer is not an error");
        assert_eq!(compared.standing, Standing::PeerHoldsOther);
        assert!(!compared.someone_is_behind);
        assert_eq!(calls.get(), 1);
    }

    /// A `git` killed by a signal, an unreadable repository and an unresolvable archived oid
    /// all arrive here identically. Reporting the loudest verdict this tool has, and exiting 3
    /// with it, on any of those is telling somebody their identity may be forked because a
    /// process died. `resolve_git_failure` establishes that the peer's head is genuinely not
    /// on this disk before it lets a failure mean anything about a peer.
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

    /// Safe next to one node and unsafe next to another is unsafe, and the report acts on one
    /// standing per repository. Asserted in both orders, because a single case passes just as
    /// well against "the last one wins" or "the first one wins" with the fold doing nothing.
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

    /// The fact that has no other home. A node behind us and a node holding refs we do not
    /// have are facts about different nodes, and the standing can only carry one of them:
    /// folded, the repository reports as the fork hazard alone and drops out of the "push this
    /// first" list, so work whose only other copy is the archive is never named. Fetching
    /// later recovers a missed fork; it does not recover work that exists nowhere.
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

    /// Two spellings of one commit are one commit. `names_an_oid` accepts either case and git
    /// resolves either, so a byte-exact filter kept an uppercase row as something to compare
    /// and came back with "push this first" about work that was already there.
    #[test]
    fn one_commit_spelled_in_two_cases_is_not_two_commits() {
        let evidence = evidence_against(
            &oid('a').to_uppercase(),
            Some(&rows(&[oid('a')])),
            Before::Held(None),
        );

        assert_eq!(evidence.rows().count(), 0);
    }

    /// The reading a row that agrees can never bear. A row agreeing with the archive is as
    /// likely to be one that was already in the table as a peer's first word, and nothing in
    /// the table tells them apart: heartwood rewrites a peer's row only when the peer
    /// announces a different head. Counted as the network agreeing, that is the archive
    /// compared with itself a second time.
    #[test]
    fn a_row_that_agrees_with_the_archive_is_not_evidence_about_the_network() {
        let evidence = evidence_against(&oid('a'), Some(&rows(&[oid('a')])), Before::Held(None));

        assert_eq!(evidence.rows().count(), 0);
    }

    /// And the reading a row that differs always bears, whenever it was written. Gated on a
    /// timestamp instead, a seed that already held work this archive was missing reported as
    /// "could not be compared" and the run exited 0 over a live fork hazard.
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

    /// `rad::is_identifier` takes both spellings, so a manifest can carry either, and the node
    /// writes only the prefixed one. Matched exactly, a bare-rid archive found no row for any
    /// repository and every one of them was compared against nothing at all.
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
        // Two oids that are the same string are the same commit, and asking `git` to walk
        // between them is a process spawned per repository to learn nothing.
        assert_eq!(calls.get(), 0, "git was asked about two identical oids");
    }

    /// A row shaped like a flag would be read as one by `merge-base`, which takes no `--`.
    /// Not the fork verdict either: a database this tool cannot read is not evidence of one.
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

    /// The instruction that must never come off a stale row. A node recorded as behind was
    /// behind on the day the backup was taken, and it has had every day since to catch up and
    /// pass this copy; heartwood writes nothing when a peer still agrees, so no announcement
    /// corrects the row. Acted on, it prints `rad sync --announce` beside a repository the
    /// network may be months ahead of, which is the command that publishes the fork.
    #[test]
    fn a_node_the_archive_recorded_as_behind_is_never_a_reason_to_push() {
        let calls = std::cell::Cell::new(0);
        let compared = classify(&carried(&[oid('b')]), asked(Answer::Yes, &calls))
            .expect("the ancestry answer is not an error");

        assert_eq!(compared.standing, Standing::ArchiveIsAheadOfAStaleRecord);
        assert!(!compared.someone_is_behind);
    }

    /// And the reading the same row still bears. A node that once held refs signed under this
    /// key that this copy lacks still holds them: nothing about a restore makes that untrue,
    /// so the fork hazard is taken from a row of any age.
    #[test]
    fn a_node_the_archive_recorded_holding_other_refs_is_still_the_fork_hazard() {
        let calls = std::cell::Cell::new(0);
        let compared = classify(&carried(&[oid('b')]), asked(Answer::No, &calls))
            .expect("the ancestry answer is not an error");

        assert_eq!(compared.standing, Standing::PeerHoldsOther);
    }

    /// Which side of the split a row lands on is decided by the archive's own copy of the
    /// table, read before the node this restore starts can write to it. No clock is consulted,
    /// because the column carries the announcing node's and heartwood replays old gossip under
    /// its old stamp.
    #[test]
    fn a_row_the_archive_brought_is_told_from_one_that_arrived_during_the_restore() {
        let now = rows(&[oid('b'), oid('c')]);
        let already_there = rows(&[oid('b')]);

        let evidence = evidence_against(&oid('a'), Some(&now), Before::Held(Some(&already_there)));

        assert_eq!(evidence.announced_since_restore, BTreeSet::from([oid('c')]));
        assert_eq!(evidence.came_with_the_archive, BTreeSet::from([oid('b')]));
    }

    /// With no baseline to read, nothing can be shown to have arrived during this run, and
    /// the reading that survives that is the one that claims less. Defaulted the other way,
    /// an unreadable record silently restored the advice this whole split exists to withhold.
    #[test]
    fn an_unreadable_baseline_leaves_every_row_one_that_was_already_there() {
        let evidence = evidence_against(&oid('a'), Some(&rows(&[oid('b')])), Before::Unknown);

        assert!(evidence.announced_since_restore.is_empty());
        assert_eq!(evidence.came_with_the_archive, BTreeSet::from([oid('b')]));
    }

    /// A pack that arrived truncated. `cat-file -e` answers "absent" for every object in it,
    /// so a probe that asked only about the peer's head read a damaged store as a node holding
    /// refs this copy does not have: exit 3, and a paragraph telling somebody their identity
    /// may have forked, over a repository nobody else had touched. The archived head is the
    /// control, because a restore that worked put it there.
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
        // The premise: the repository itself opens, and every object in it stops answering,
        // ours included. The control is what tells that from a node holding something else.
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

    /// A repository is reported as one standing, and these are the pairs whose order decides
    /// which. Written out rather than left to `severity`'s arms, because reordering those is a
    /// one-character edit that no other test would notice.
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

    /// A record that was read and holds nothing against this copy is exactly what the standing
    /// claims, and no more. Called `CouldNotAsk` instead, a healthy restore of a home whose
    /// peers all still agree reported every repository uncompared and sent the user to run a
    /// fetch that had just run: heartwood writes no row for a peer that agrees, so no fetch
    /// and no amount of waiting was ever going to produce one.
    #[test]
    fn a_record_holding_nothing_against_this_copy_is_not_an_unknown() {
        let calls = std::cell::Cell::new(0);
        let compared = classify(&Evidence::default(), asked(Answer::No, &calls))
            .expect("the ancestry answer is not an error");
        assert_eq!(compared.standing, Standing::NothingSaysOtherwise);
        assert_eq!(calls.get(), 0);
    }

    /// A repository this copy holds every object of, over which `git` still could not answer,
    /// is a fact about this machine. The probe this replaced asked whether the archived head
    /// reached itself, which `merge-base --is-ancestor A A` answers on equality without
    /// opening a single object, so it said yes over any repository at all and the run reported
    /// somebody's own identity as forked.
    #[test]
    fn a_git_failure_over_an_object_this_copy_holds_says_nothing_about_a_peer() {
        let git = Git::new();
        assert!(git.is_available(), "this test drives the real git");
        let scratch = crate::key::tests::TestScratch::create("restore-git-failure-held");
        let (git_dir, _, head) = crate::git::tests::two_commits(&scratch);
        // An object that is here and is not a commit, which `merge-base` refuses with the
        // same exit 128 it gives for an object that is not here at all.
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

    /// And the failure that is a fact about a peer. Our own namespace is the one thing a pull
    /// never brings back, so a sigrefs commit some node announced and this disk does not hold
    /// is work signed under this key that is not here.
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

    /// The probe reads a failure and nothing else. Run over an answer `git` gave, it would
    /// overturn it: the head below is one this copy does not hold, so a probe that reached it
    /// would turn "that node is behind us" into the fork verdict.
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

    /// The run that gave up before asking anybody still says which repositories nobody could
    /// ever have answered about. Collapsed into one standing, a home of three private
    /// repositories was told 3 of 3 comparisons had failed and sent to run a fetch that fails
    /// for those by design.
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

    /// The hazard that used to be reported as nothing to compare, at exit 0. A repository
    /// first written in after the backup was taken has no signed refs of ours in the archive
    /// and every reason to have them on a seed; skipping it on that basis read a fact about
    /// the archive as one about the network, over the exact case this command exists for.
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

    /// And such a repository reaches the fetch, and is an unknown rather than a nothing when
    /// the run gives up before asking. Asserted against `no_node_can_hold` itself, because
    /// that is the function the skip lived in.
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

    /// A table this build cannot read comes back empty, and an empty record is the sentence
    /// "no other node has reported holding anything else". Read as one, a schema that moved on
    /// would reassure every reader of it about every repository they have.
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

        // And the same read against the schema this build does follow, so that what the test
        // above proves is the drift and not the fixture.
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

    /// A table read perfectly whose repository ids are spelled some way this build does not
    /// look up. Every lookup misses, and a miss is the sentence that reassures, so the whole
    /// home would have been reported clear on the strength of a table nobody could match.
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
        // are what `git init` works out about this disk, so the restoring machine's answer is
        // the one that is true now and the archive's is dropped without a word about it.
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
        // Nothing named: an honest archive carries exactly these, and a warning that fires on
        // every repository of every recovery is one nobody reads by the fifth.
        assert!(allowed.dropped.is_empty(), "{:?}", allowed.dropped);
    }

    #[test]
    fn a_repository_config_cannot_carry_a_setting_git_would_run() {
        // Every one of these makes git run a command on an ordinary operation in the
        // repository, and all of them arrive in a file somebody else wrote. Spelled as git
        // reports them, which is how the reader sees them: lowercased, subsection and all.
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
        // Named, so the warning can say what was left out rather than that something was.
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
        // `[user] name` with nothing after it. Git prints the name alone and reads it as a
        // true boolean; written back as an empty string it would be a repository whose owner
        // has no name, and `git config --bool` would answer false to a caller asking.
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
        // `radicle.retired` from one restore and `radicle.retired.2` from the next both sit in
        // the same directory, and whoever finds them is looking for which is which.
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

    /// The two lists give opposite instructions, and this one was named in both. `rad sync
    /// --announce` came first in the output, so the reader was handed the command that
    /// publishes the fork before reaching the paragraph telling them not to write at all.
    #[test]
    fn a_repository_at_risk_is_never_also_one_to_push_first() {
        let found = reconciled(&[("rad:zAAA", Standing::PeerHoldsOther)], &["rad:zAAA"]);
        let verdict = Verdict::of(&found);

        assert_eq!(verdict.at_risk, vec!["rad:zAAA"]);
        assert!(verdict.ahead.is_empty(), "{:?}", verdict.ahead);
    }

    /// A repository some node is behind on reports as the unknown when another node said
    /// nothing usable, and the work it holds that nowhere else does would then never be named.
    #[test]
    fn work_no_node_reported_holding_is_still_pushed_first_when_the_standing_is_unknown() {
        let found = reconciled(&[("rad:zAAA", Standing::CouldNotAsk)], &["rad:zAAA"]);
        let verdict = Verdict::of(&found);

        assert_eq!(verdict.ahead, vec!["rad:zAAA"]);
    }

    /// The sentence is about the whole home, so one repository must not carry it for twenty.
    /// Printed right under the line saying most of them were never compared, it read as a
    /// partial pass over exactly the run that established least.
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

    /// A home of only private repositories used to get a restore that mentioned the network
    /// nowhere at all: nothing at risk, nothing ahead, nothing unchecked, and no line saying
    /// why. The standing exists; it was never read out.
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

    /// Nothing was held against anything: no node can hold these and none was asked. Gated on
    /// the standings merely being there, the line printed over a home of private repositories
    /// as though the network had been consulted about them.
    #[test]
    fn nothing_reported_otherwise_is_not_said_when_nothing_was_ever_compared() {
        let found = reconciled(&[("rad:zAAA", Standing::NothingToCompare)], &[]);

        assert!(!Verdict::of(&found).nothing_was_reported_otherwise);
    }

    #[test]
    fn a_standing_says_what_it_means_in_words_a_person_can_act_on() {
        assert_eq!(
            Standing::NothingSaysOtherwise.as_str(),
            "no other node has reported holding anything else"
        );
        assert_eq!(
            Standing::PeerHoldsOther.as_str(),
            "another node holds signed refs this copy does not have"
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
