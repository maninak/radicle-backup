//! Putting a home back, and making sure it is safe to build on.
//!
//! Restoring is done in two moves. Everything is unpacked into a staging directory beside the
//! target home and checked there; only then is it installed. A half-restored identity is worse
//! than none, because it looks like one.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::archive::Reader;
use crate::cli::Restore;
use crate::cmd::{Ctx, Scratch, copy_owner_only, copy_plain, set_owner_only, write_owner_only};
use crate::crypt;
use crate::db::Policies;
use crate::error::{EXIT_CHECKS_FAILED, Error, Result};
use crate::git::{self, Git};
use crate::home::NodeState;
use crate::key::{Identity, SecretKey};
use crate::manifest::{Manifest, RepoRecord};
use crate::rad::Rad;
use crate::term;

/// How a restored repository stands next to what the network holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// The archive and the network agree.
    Same,
    /// The network had newer signed refs, and now the restored copy does too.
    NetworkWasAhead,
    /// The archive holds work the network has not seen. Push it before anything else.
    ArchiveIsAhead,
    /// Two histories that are not ancestors of each other. Writing here forks the identity.
    Diverged,
    /// Nothing to compare: the repository has no signed refs of ours, or nothing answered.
    NotChecked,
}

impl Standing {
    fn as_str(self) -> &'static str {
        match self {
            Self::Same => "in step with the network",
            Self::NetworkWasAhead => "the network was ahead, and has been taken",
            Self::ArchiveIsAhead => "holds work the network has not seen",
            Self::Diverged => "diverged from the network",
            Self::NotChecked => "not checked",
        }
    }
}

pub fn run(ctx: &Ctx, args: &Restore) -> Result<std::process::ExitCode> {
    if args.words {
        return from_words(ctx).map(|()| std::process::ExitCode::SUCCESS);
    }

    let Some(archive) = &args.archive else {
        return Err(Error::refused(
            "no archive was named",
            "give a path to one, or pass --words to restore from a recovery sheet",
        ));
    };
    let home = &ctx.home;
    let term = &ctx.term;

    if home.exists() && !args.force {
        return Err(Error::refused(
            format!("{} already holds an identity", home.path().display()),
            "move it aside, restore into a different --home, or pass --force to overwrite it",
        ));
    }
    if home.node_state() == NodeState::Running {
        return Err(Error::refused(
            "the node is running against the home being restored into",
            "run `rad node stop` first: a node writing to a home mid-restore corrupts both",
        ));
    }

    let passphrase = if crypt::looks_encrypted(archive)? {
        Some(crypt::passphrase(
            crypt::PASSPHRASE_ENV,
            ctx.global.passphrase_file.as_deref(),
            "Passphrase for the archive: ",
            false,
            term.is_interactive(),
        )?)
    } else {
        None
    };

    let parent = home
        .path()
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&parent).map_err(|e| Error::io(&parent, e))?;
    let scratch = Scratch::create(&parent)?;
    let staging = scratch.file("home");

    term.step(&format!("unpacking {}", archive.display()));
    let scan = Reader::open(archive, passphrase.as_ref(), ctx.identity_files())?
        .unpack(archive, &staging)?;

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

    install(ctx, &staging, &manifest)?;
    let restored = restore_repositories(ctx, &staging, &manifest)?;

    if args.replay_policies {
        replay_policies(ctx, &staging)?;
    }

    let standings = if args.no_reconcile {
        term.warn("--no-reconcile: nothing was compared with the network");
        BTreeMap::new()
    } else {
        reconcile(ctx, &manifest, &restored)?
    };

    report(ctx, &manifest, &restored, &standings)
}

/// Refuse to install a key that is not the key the manifest names.
fn prove_identity(staging: &Path, manifest: &Manifest) -> Result<()> {
    let identity = Identity::read(staging.join("keys/radicle.pub"))?;
    if identity.did() != manifest.identity.did {
        return Err(Error::refused(
            format!(
                "the archived key is {} but the manifest says {}",
                identity.did(),
                manifest.identity.did
            ),
            "this archive is inconsistent; do not install it",
        ));
    }
    let secret = SecretKey::read(staging.join("keys/radicle"))?;
    if secret.identity()?.did() != manifest.identity.did {
        return Err(Error::refused(
            "the archived private and public keys are not a pair",
            "this archive is inconsistent; do not install it",
        ));
    }
    Ok(())
}

/// Move the identity, the config and the databases into place.
fn install(ctx: &Ctx, staging: &Path, manifest: &Manifest) -> Result<()> {
    let home = &ctx.home;
    for directory in [home.path().to_path_buf(), home.keys_dir(), home.node_dir()] {
        std::fs::create_dir_all(&directory).map_err(|e| Error::io(&directory, e))?;
    }
    set_owner_only(home.path())?;

    copy_owner_only(&staging.join("keys/radicle"), &home.secret_key())?;
    copy_plain(&staging.join("keys/radicle.pub"), &home.public_key())?;
    copy_plain(&staging.join("config.json"), &home.config())?;
    copy_owner_only(&staging.join("node/policies.db"), &home.policies_db())?;
    copy_owner_only(
        &staging.join("node/notifications.db"),
        &home.notifications_db(),
    )?;
    copy_owner_only(&staging.join("node/node.db"), &home.node_db())?;

    ctx.term.ok(&format!(
        "installed the identity into {}",
        home.path().display()
    ));
    let _ = manifest;
    Ok(())
}

/// Rebuild each archived repository from its bundle.
fn restore_repositories(ctx: &Ctx, staging: &Path, manifest: &Manifest) -> Result<Vec<RepoRecord>> {
    let carried: Vec<&RepoRecord> = manifest
        .repos
        .iter()
        .filter(|repo| repo.bundle.is_some())
        .collect();
    if carried.is_empty() {
        return Ok(Vec::new());
    }

    let git = Git::new();
    if !git.is_available() {
        ctx.term
            .warn("git is not on PATH, so the archived repositories were left unpacked");
        ctx.term.hint(&format!(
            "they are plain git bundles; see RESTORE.md in {}",
            staging.display()
        ));
        return Ok(Vec::new());
    }

    let storage = ctx.home.storage();
    std::fs::create_dir_all(&storage).map_err(|e| Error::io(&storage, e))?;
    ctx.term.step(&format!(
        "restoring {}",
        term::count(carried.len(), "repository", "repositories")
    ));

    let mut restored = Vec::new();
    for repo in carried {
        let bundle = staging.join(git::bundle_entry(&repo.rid));
        let target = ctx.home.repository_path(&repo.rid);

        git.init_bare(&target)?;
        git.unbundle(&target, &bundle)?;
        if let Some(head) = &repo.head {
            git.set_head(&target, head)?;
        }
        let config = staging.join(git::config_entry(&repo.rid));
        if config.is_file() {
            copy_plain(&config, &target.join("config"))?;
        }
        restored.push(repo.clone());
    }
    Ok(restored)
}

/// Compare each restored repository with what the network holds.
///
/// This is the check that separates a restore from a data-loss event. Signed refs are a chain:
/// if the archived copy is behind what the network has, and the user commits on top of it,
/// they sign a second history for their own namespace, and peers see a fork that does not
/// resolve itself.
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
            .hint("run `rad sync <rid> --fetch` for each repository before you write to it");
        return Ok(standings);
    }
    if ctx.home.node_state() != NodeState::Running {
        ctx.term
            .warn("the node is not running, so nothing was compared with the network");
        ctx.term
            .hint("run `rad node start`, then `rad sync <rid> --fetch` before you write");
        return Ok(standings);
    }

    let git = Git::new();
    let node_id = &manifest.identity.node_id;
    let sigrefs = git::sigrefs_ref(node_id);

    ctx.term.step(&format!(
        "comparing {} with the network",
        term::count(restored.len(), "repository", "repositories")
    ));
    for repo in restored {
        let Some(archived) = repo.sigrefs.get(node_id) else {
            standings.insert(repo.rid.clone(), Standing::NotChecked);
            continue;
        };
        if !rad.fetch(&repo.rid)? {
            standings.insert(repo.rid.clone(), Standing::NotChecked);
            continue;
        }

        let path = ctx.home.repository_path(&repo.rid);
        let current = git.ref_oid(&path, &sigrefs)?;
        let standing = match current {
            None => Standing::NotChecked,
            Some(current) if &current == archived => Standing::Same,
            Some(current) => {
                if git.is_ancestor(&path, archived, &current)? {
                    Standing::NetworkWasAhead
                } else if git.is_ancestor(&path, &current, archived)? {
                    Standing::ArchiveIsAhead
                } else {
                    Standing::Diverged
                }
            }
        };
        standings.insert(repo.rid.clone(), standing);
    }
    Ok(standings)
}

/// Re-apply seeding and following through `rad`, for a Radicle whose schema has moved on.
fn replay_policies(ctx: &Ctx, staging: &Path) -> Result<()> {
    let path = staging.join("policies.json");
    if !path.is_file() {
        ctx.term
            .warn("this archive has no policies.json, so there was nothing to replay");
        return Ok(());
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

    for policy in policies.seeded() {
        rad.seed(&policy.rid, &policy.scope)?;
    }
    for policy in policies.blocked_repos() {
        rad.block_repo(&policy.rid)?;
    }
    for policy in policies.followed() {
        rad.follow(&policy.nid, policy.alias.as_deref())?;
    }
    for policy in policies.blocked_peers() {
        rad.block_peer(&policy.nid)?;
    }
    Ok(())
}

/// Rebuild an identity from a mnemonic, for when the paper sheet is all that is left.
fn from_words(ctx: &Ctx) -> Result<()> {
    use std::io::BufRead;

    let home = &ctx.home;
    if home.exists() {
        return Err(Error::refused(
            format!("{} already holds an identity", home.path().display()),
            "restore into an empty --home",
        ));
    }
    // Read from stdin whether a person is typing or a script is piping. The words are secret,
    // but a pipe keeps them out of the process table and out of shell history, which is more
    // than a command-line argument would do.
    if ctx.term.is_interactive() {
        ctx.term
            .headline("Type the 24 words from your recovery sheet, separated by spaces:");
    }
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(Error::Bare)?;

    let mnemonic = bip39::Mnemonic::parse_normalized(line.trim()).map_err(|e| {
        Error::refused(
            format!("those words are not a valid mnemonic: {e}"),
            "check the sheet and try again",
        )
    })?;
    let entropy = Zeroizing::new(mnemonic.to_entropy());
    let seed: Zeroizing<[u8; 32]> =
        Zeroizing::new(<[u8; 32]>::try_from(entropy.as_slice()).map_err(|_| {
            Error::refused(
                "that mnemonic does not carry 32 bytes",
                "a Radicle key is 24 words; a 12-word phrase is something else",
            )
        })?);

    let identity = crate::key::identity_from_seed(&seed)?;
    ctx.term
        .ok(&format!("those words rebuild {}", identity.did()));
    if !ctx.term.confirm("Is that the identity you expected?")? {
        return Err(Error::refused(
            "stopped before writing anything",
            "check the words",
        ));
    }

    let passphrase = crypt::passphrase(
        crypt::KEY_PASSPHRASE_ENV,
        ctx.global.passphrase_file.as_deref(),
        "New passphrase for the restored key: ",
        true,
        ctx.term.is_interactive(),
    )?;
    let openssh = crate::key::openssh_from_seed(&seed, Some(&passphrase))?;

    std::fs::create_dir_all(home.keys_dir()).map_err(|e| Error::io(home.keys_dir(), e))?;
    set_owner_only(home.path())?;
    write_owner_only(&home.secret_key(), openssh.as_bytes())?;
    std::fs::write(home.public_key(), identity.to_openssh()?)
        .map_err(|e| Error::io(home.public_key(), e))?;

    ctx.term
        .ok(&format!("wrote the key into {}", home.keys_dir().display()));
    ctx.term
        .hint("`rad node start` will build the rest from the network");
    ctx.term
        .hint("your repositories come back with `rad clone <rid>` or `rad seed <rid>`");
    Ok(())
}

fn report(
    ctx: &Ctx,
    manifest: &Manifest,
    restored: &[RepoRecord],
    standings: &BTreeMap<String, Standing>,
) -> Result<std::process::ExitCode> {
    let diverged: Vec<&String> = standings
        .iter()
        .filter(|(_, standing)| **standing == Standing::Diverged)
        .map(|(rid, _)| rid)
        .collect();
    let ahead: Vec<&String> = standings
        .iter()
        .filter(|(_, standing)| **standing == Standing::ArchiveIsAhead)
        .map(|(rid, _)| rid)
        .collect();

    if ctx.global.json {
        ctx.term.print_json(&serde_json::json!({
            "restored": manifest.identity.did,
            "home": ctx.home.path().display().to_string(),
            "repositories": restored.len(),
            "standings": standings.iter()
                .map(|(rid, standing)| serde_json::json!({"rid": rid, "standing": standing.as_str()}))
                .collect::<Vec<_>>(),
            "diverged": diverged,
        }))?;
    } else {
        let term = &ctx.term;
        term.blank();
        term.ok(&format!(
            "restored {} into {}",
            manifest.identity.alias.as_deref().unwrap_or("unnamed"),
            ctx.home.path().display()
        ));
        term.hint(&format!(
            "{}, {} seeding and {} following policies",
            term::count(restored.len(), "repository", "repositories"),
            manifest.policies.seeded,
            manifest.policies.followed
        ));
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
        if !diverged.is_empty() {
            term.blank();
            term.fail("these repositories have diverged from the network:");
            for rid in &diverged {
                term.hint(rid);
            }
            term.blank();
            term.fail("do not commit or push in them until this is resolved");
            term.hint("your restored refs and the network's are not ancestors of each other,");
            term.hint("so writing on top of either one signs a second history for your peer id");
        }
        term.blank();
        if manifest.node.was_running {
            term.warn("the machine this archive came from had a node running when it was taken");
            term.hint("never run two nodes with one key: stop the other one first");
        }
        term.hint("start the node with `rad node start`");
    }

    Ok(if diverged.is_empty() {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::from(EXIT_CHECKS_FAILED)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::SECRET_MODE;

    #[test]
    fn every_standing_says_what_it_means_in_words_a_person_can_act_on() {
        assert_eq!(Standing::Same.as_str(), "in step with the network");
        assert_eq!(Standing::Diverged.as_str(), "diverged from the network");
    }

    #[test]
    fn a_private_copy_lands_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("rad-backup-restore-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch directory is creatable");

        let source = dir.join("source");
        std::fs::write(&source, b"key material").expect("source is writable");
        let target = dir.join("target");
        copy_owner_only(&source, &target).expect("copy succeeds");

        assert_eq!(
            std::fs::read(&target).expect("target exists"),
            b"key material"
        );
        let mode = std::fs::metadata(&target)
            .expect("target exists")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, SECRET_MODE);

        let _ = std::fs::remove_dir_all(dir);
    }
}
