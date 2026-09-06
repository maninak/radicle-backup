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
use crate::key::{Identity, SecretKey};
use crate::manifest::{Manifest, RepoRecord};
use crate::perms::{copy_doc, copy_secret, set_dir_owner_only};
use crate::rad::Rad;
use crate::state;
use crate::term;

/// How long to wait for a node this command started to answer on its control socket, and how
/// often to look. The same shape as `backup`'s stop deadline, for the same reason: the command
/// that starts a daemon does not wait for it.
const NODE_START_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);
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
    /// Disagreement announces itself; agreement is silent, and silence is not evidence.
    NothingSaysOtherwise,
    /// The archive holds work no reporting node has. Push it before anything else.
    ArchiveIsAhead,
    /// Another node holds signed refs under this identity that the restored copy does not
    /// have. Writing here signs a second history for one peer id, which is the fork.
    PeerHoldsOther,
    /// There was nothing on the other side to hold this against: the archive carries no signed
    /// refs of ours for it, or it is delegated to us alone and announced to nobody. No fetch
    /// changes either of those, so this is safe to write to.
    NothingToCompare,
    /// What other nodes hold is unknown: the fetch failed, or none of them has yet said what
    /// it has of ours. A later fetch may answer.
    ///
    /// Kept apart from `NothingToCompare` because the two owe the reader different advice.
    /// Folded together, a home of only private repositories was told every one "could not be
    /// compared" and sent to run `rad sync <rid> --fetch`, which fails for those by design.
    CouldNotAsk,
}

impl Standing {
    fn as_str(self) -> &'static str {
        match self {
            Self::NothingSaysOtherwise => "no other node has reported holding anything else",
            Self::ArchiveIsAhead => "holds work the network has not seen",
            Self::PeerHoldsOther => "another node holds signed refs this copy does not have",
            Self::NothingToCompare => "nothing to compare it with",
            Self::CouldNotAsk => "could not be compared",
        }
    }

    /// Ordered by what it costs to ignore, so that a repository several nodes disagree about
    /// is reported as the answer that most needs acting on. Safe next to one node and unsafe
    /// next to another is unsafe. `CouldNotAsk` outranks the two benign answers because an
    /// unknown must not be hidden behind some other node's agreement.
    fn severity(self) -> u8 {
        match self {
            Self::NothingToCompare => 0,
            Self::NothingSaysOtherwise => 1,
            Self::ArchiveIsAhead => 2,
            Self::CouldNotAsk => 3,
            Self::PeerHoldsOther => 4,
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

pub fn run(ctx: &Ctx, args: &Restore) -> Result<std::process::ExitCode> {
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

    install(ctx, &staging)?;
    let restored = restore_repositories(ctx, &staging, &manifest)?;

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
        Ok(BTreeMap::new())
    } else {
        reconcile(ctx, &manifest, &restored.repos)
    };
    remember(ctx, &manifest, &restored.repos, archive, encrypted);
    let standings = comparison?;

    report(ctx, &manifest, &restored, &standings, &policies_missed)
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
    std::fs::write(&path, note).map_err(|e| Error::io(&path, e))
}

/// Move the identity, the config and the databases into place.
fn install(ctx: &Ctx, staging: &Path) -> Result<()> {
    let home = &ctx.home;
    // Asked again here, not only at the top of `run`. Unpacking and verifying a multi-gigabyte
    // archive takes long enough for a login, a `rad node start` or a socket activation to land
    // in between, and a node writing to the home while this copies its databases over corrupts
    // both. The check up front is the courtesy that fails before the work; this is the one
    // that matters.
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
fn restore_repositories(ctx: &Ctx, staging: &Path, manifest: &Manifest) -> Result<Restored> {
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
            copy_doc(&config, &target.join("config"))?;
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
fn reconcile(
    ctx: &Ctx,
    manifest: &Manifest,
    restored: &[RepoRecord],
) -> Result<BTreeMap<String, Standing>> {
    let mut standings = BTreeMap::new();
    if restored.is_empty() {
        return Ok(standings);
    }

    let rad = Rad::new(ctx.home.path());
    if !rad.is_available() {
        ctx.term
            .warn("rad is not on PATH, so nothing was compared with the network");
        ctx.term
            .detail("run `rad sync <rid> --fetch` for each repository before you write to it");
        return Ok(standings);
    }
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
        if !rad.start_node()? || !wait_for_node(ctx) {
            ctx.term
                .warn("the node would not start, so nothing was compared with the network");
            ctx.term
                .detail("run `rad node start`, then `rad sync <rid> --fetch` before you write");
            return Ok(standings);
        }
        true
    };

    let outcome = compare_with_network(ctx, manifest, restored, &rad, &mut standings);

    // Put back before the outcome is propagated, so a comparison that fails halfway does not
    // also leave a node running that the user never started.
    if started_here {
        ctx.term.step("stopping the node again");
        // Reported, never propagated: the comparison's own outcome below is the answer this
        // function owes its caller, and a stop that failed must not stand in front of it.
        if !matches!(rad.stop_node(), Ok(true)) {
            ctx.term
                .warn("the node was started to run this check and would not stop again");
            ctx.term
                .detail("stop it with `rad node stop` if you meant it to stay down");
        }
    }
    outcome?;
    Ok(standings)
}

/// Whether the node answered on its control socket before `NODE_START_TIMEOUT` elapsed.
///
/// `rad node start` returns as soon as the daemon forks, so every query fired straight after
/// it fails on a machine where the node takes a moment: the comparison then filled with
/// `CouldNotAsk` for every repository and the restore reported success having compared nothing.
/// `backup`'s `quiesce` waits the same way for the same reason.
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

/// Where the archive's signed refs stand against what other nodes hold of them.
///
/// `held` is what those nodes last told this one they were carrying of *our* `rad/sigrefs`.
/// That, and not the copy in local storage, is the only view of our own namespace this machine
/// can get: `rad sync <rid> --fetch` over a repository already in storage is a pull, and a
/// pull deliberately ignores the local peer's key, so our own refs stay exactly as the archive
/// wrote them however far the network has moved. Reading those back and calling them the
/// network is what reported every restore in step with a network nobody had asked.
///
/// Kept apart from the fetching and the spawning of `git` because this is the decision the
/// whole tool exists for: writing on top of a restored copy another node has moved past forks
/// your own peer history, and there is no undo.
///
/// `is_ancestor` is a closure rather than a value, so a node holding exactly the archived head
/// costs no `git` at all.
fn classify<F>(archived: &str, held: &BTreeSet<String>, mut is_ancestor: F) -> Result<Standing>
where
    F: FnMut(&str) -> Result<Answer>,
{
    if held.is_empty() {
        return Ok(Standing::CouldNotAsk);
    }
    let mut standing = Standing::NothingSaysOtherwise;
    for head in held {
        standing = standing.worse_of(if head == archived {
            Standing::NothingSaysOtherwise
        } else if !git::names_an_oid(head) {
            // A row shaped like a flag would be one to `merge-base`, which takes no `--`. A
            // malformed row is a database this tool cannot read, not evidence of a fork.
            Standing::CouldNotAsk
        } else {
            match is_ancestor(head)? {
                // Their head is in our history: they are behind, and we hold the work.
                Answer::Yes => Standing::ArchiveIsAhead,
                Answer::No => Standing::PeerHoldsOther,
                // `git` could not resolve their head. For our own namespace that means the
                // object is not on this disk and no pull will bring it, so it is the evidence
                // rather than a hole in it: they signed something this copy does not have.
                Answer::CouldNotAsk { .. } => Standing::PeerHoldsOther,
            }
        });
    }
    Ok(standing)
}

fn compare_with_network(
    ctx: &Ctx,
    manifest: &Manifest,
    restored: &[RepoRecord],
    rad: &Rad,
    standings: &mut BTreeMap<String, Standing>,
) -> Result<()> {
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
        // as a fault. Private on its own is not enough, because `rad sync --fetch` reaches the
        // delegates and allowed peers of a private repository, and one shared with a
        // collaborator is precisely the one whose sigrefs can be behind theirs.
        if repo.has_nowhere_to_fetch_from() {
            standings.insert(repo.rid.clone(), Standing::NothingToCompare);
            continue;
        }
        let Some(archived) = repo.sigrefs.get(node_id) else {
            standings.insert(repo.rid.clone(), Standing::NothingToCompare);
            continue;
        };
        // Nothing in this manifest was vouched for by anybody. `merge-base` takes no `--`, so
        // a value reading as a flag would be one, and a revision expression would have git
        // resolve something the archive chose. Not compared rather than refused outright: one
        // repository with a bad oid is not a reason to abandon the comparison of the rest, and
        // "could not ask" is the honest standing for it.
        if !git::names_an_oid(archived) {
            standings.insert(repo.rid.clone(), Standing::CouldNotAsk);
            continue;
        }
        if !rad.fetch(&repo.rid)? {
            standings.insert(repo.rid.clone(), Standing::CouldNotAsk);
            continue;
        }
        fetched.push((repo, archived));
    }

    // Read once, after the last fetch rather than inside the loop. The rows are written by the
    // node's own thread as seeds announce over the connections a fetch opens, so every extra
    // repository fetched is more time for the earlier ones' announcements to land. A node that
    // has not heard from anybody yet leaves the map empty, which reads as "could not ask".
    let held = crate::db::read_synced_heads(&ctx.home.node_db(), node_id)?;
    let nothing = BTreeSet::new();
    for (repo, archived) in fetched {
        let path = ctx.home.repository_path(&repo.rid);
        let standing = classify(archived, held.get(&repo.rid).unwrap_or(&nothing), |head| {
            git.is_ancestor(&path, head, archived)
        })?;
        standings.insert(repo.rid.clone(), standing);
    }
    Ok(())
}

/// Re-apply seeding and following through `rad`, for a Radicle whose schema has moved on.
fn replay_policies(ctx: &Ctx, staging: &Path) -> Result<Vec<String>> {
    let path = staging.join("policies.json");
    if !path.is_file() {
        ctx.term
            .warn("this archive has no policies.json, so there was nothing to replay");
        return Ok(Vec::new());
    }
    let rad = Rad::new(ctx.home.path());
    if !rad.is_available() {
        return Err(Error::refused(
            "--replay-policies needs rad on PATH",
            "install rad, or drop the flag and let the database be copied instead",
        ));
    }

    let text = std::fs::read_to_string(&path).map_err(|e| Error::io(&path, e))?;
    let policies: Policies = serde_json::from_str(&text)?;
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

fn report(
    ctx: &Ctx,
    manifest: &Manifest,
    restored: &Restored,
    standings: &BTreeMap<String, Standing>,
    policies_missed: &[String],
) -> Result<std::process::ExitCode> {
    let dropped = &restored.dropped;
    let restored = &restored.repos;
    let at_risk: Vec<&String> = standings
        .iter()
        .filter(|(_, standing)| **standing == Standing::PeerHoldsOther)
        .map(|(rid, _)| rid)
        .collect();
    let ahead: Vec<&String> = standings
        .iter()
        .filter(|(_, standing)| **standing == Standing::ArchiveIsAhead)
        .map(|(rid, _)| rid)
        .collect();
    // Counted and said out loud. A repository the network could not be asked about is not one
    // nothing was said against, and the report used to mention only the fork and the unpushed
    // work, so a comparison that answered nothing at all read as a clean bill.
    let not_checked = standings
        .values()
        .filter(|standing| **standing == Standing::CouldNotAsk)
        .count();

    if ctx.global.json {
        ctx.term.print_json(&serde_json::json!({
            "restored": manifest.identity.did,
            "home": ctx.home.path().display().to_string(),
            "repositories": restored.len(),
            "standings": standings.iter()
                .map(|(rid, standing)| serde_json::json!({"rid": rid, "standing": standing.as_str()}))
                .collect::<Vec<_>>(),
            "atRisk": at_risk,
            "notChecked": not_checked,
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
        let installed = crate::db::read_policies(&ctx.home.policies_db())?;
        term.hint(&format!(
            "{}, {} seeding and {} following policies",
            term::count(restored.len(), "repository", "repositories"),
            installed.seeded().count(),
            installed.followed().count()
        ));
        if not_checked > 0 {
            term.warn(&format!(
                "{} of {} repositories could not be compared with the network",
                not_checked,
                restored.len()
            ));
            term.detail("run `rad sync <rid> --fetch` for those before you write to them");
        }
        // Said on every restore that compared anything, including the quiet ones, because the
        // absence of a warning here is not the same as a clean bill and the difference is the
        // whole reason somebody would write in these repositories tonight.
        if !standings.is_empty() && at_risk.is_empty() {
            term.detail("no other node has reported holding signed refs of yours missing here");
            term.detail("that is not proof there are none: a fetch never brings your own back");
        }
        if !ahead.is_empty() {
            term.warn(&format!(
                "{} repositor{} hold work the network has never seen; push them first",
                ahead.len(),
                if ahead.len() == 1 { "y" } else { "ies" }
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

    // A repository the archive carried and the home did not get is a failed check, the same
    // as a fork hazard: the run did not deliver what it was asked for, and a scheduled restore
    // that exited 0 over it would be the last anyone heard about it. A seeding or following
    // decision that did not go back counts for the same reason.
    Ok(
        if at_risk.is_empty() && dropped.is_empty() && policies_missed.is_empty() {
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

    fn holding(heads: &[String]) -> BTreeSet<String> {
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
        let standing = classify(&oid('a'), &holding(&[oid('b')]), asked(Answer::No, &calls))
            .expect("the ancestry answer is not an error");
        assert_eq!(standing, Standing::PeerHoldsOther);
        assert_eq!(calls.get(), 1);
    }

    /// A head `git` cannot resolve is not a gap in the evidence here, it is the evidence. Our
    /// own namespace is the one thing a pull will never fetch, so a sigrefs commit some node
    /// announced and this disk does not hold is work signed under this key that is not here.
    #[test]
    fn a_head_git_cannot_resolve_is_read_as_refs_this_copy_does_not_have() {
        let calls = std::cell::Cell::new(0);
        let standing = classify(
            &oid('a'),
            &holding(&[oid('b')]),
            asked(
                Answer::CouldNotAsk {
                    said: "fatal: Not a valid commit name".to_string(),
                },
                &calls,
            ),
        )
        .expect("the ancestry answer is not an error");
        assert_eq!(standing, Standing::PeerHoldsOther);
    }

    #[test]
    fn a_node_still_back_at_an_ancestor_is_read_as_the_archive_being_ahead() {
        let calls = std::cell::Cell::new(0);
        let standing = classify(&oid('a'), &holding(&[oid('b')]), asked(Answer::Yes, &calls))
            .expect("the ancestry answer is not an error");
        assert_eq!(standing, Standing::ArchiveIsAhead);
    }

    /// Safe next to one node and unsafe next to another is unsafe, and the report acts on one
    /// standing per repository. Taking the first, or the last, would have let a seed that
    /// happens to agree bury the one that does not.
    #[test]
    fn the_node_that_most_needs_acting_on_is_the_one_reported() {
        let calls = std::cell::Cell::new(0);
        let standing = classify(
            &oid('a'),
            &holding(&[oid('a'), oid('b')]),
            asked(Answer::No, &calls),
        )
        .expect("the ancestry answer is not an error");
        assert_eq!(standing, Standing::PeerHoldsOther);
    }

    #[test]
    fn identical_refs_are_in_step_without_asking_git_anything() {
        let calls = std::cell::Cell::new(0);
        let standing = classify(&oid('a'), &holding(&[oid('a')]), asked(Answer::No, &calls))
            .expect("the ancestry answer is not an error");
        assert_eq!(standing, Standing::NothingSaysOtherwise);
        // Two oids that are the same string are the same commit, and asking `git` to walk
        // between them is a process spawned per repository to learn nothing.
        assert_eq!(calls.get(), 0, "git was asked about two identical oids");
    }

    /// A row shaped like a flag would be read as one by `merge-base`, which takes no `--`.
    /// Not the fork verdict either: a database this tool cannot read is not evidence of one.
    #[test]
    fn a_recorded_head_that_is_not_an_oid_is_an_unknown_and_never_reaches_git() {
        let calls = std::cell::Cell::new(0);
        let standing = classify(
            &oid('a'),
            &holding(&["--output=/etc/passwd".to_string()]),
            asked(Answer::No, &calls),
        )
        .expect("the ancestry answer is not an error");
        assert_eq!(standing, Standing::CouldNotAsk);
        assert_eq!(calls.get(), 0, "git was handed a value out of a database");
    }

    /// Nobody has said what they hold, which is a different thing from everybody having
    /// agreed, and the report owes those two different advice.
    #[test]
    fn a_repository_no_other_node_has_reported_on_could_not_be_compared() {
        let calls = std::cell::Cell::new(0);
        let standing = classify(&oid('a'), &BTreeSet::new(), asked(Answer::No, &calls))
            .expect("the ancestry answer is not an error");
        assert_eq!(standing, Standing::CouldNotAsk);
        assert_eq!(calls.get(), 0);
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

        let dir = std::env::temp_dir().join(format!("rad-backup-restore-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch directory is creatable");

        let source = dir.join("source");
        std::fs::write(&source, b"key material").expect("source is writable");
        let target = dir.join("target");
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

        let _ = std::fs::remove_dir_all(dir);
    }
}
