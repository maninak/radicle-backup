//! Moving an identity to another machine.
//!
//! This is the common case, and it is the one with the footgun: two nodes running one key sign
//! conflicting histories for the same peer, and the network sees a fork that nothing resolves.
//! So the source key is retired as part of the move by default, not left behind as a courtesy
//! copy. `--keep-source` leaves it, and the archive says so, so the far end is warned.

use std::path::{Path, PathBuf};

use crate::cli::{Create, Migrate, TierArg, Verify};
use crate::cmd::{Ctx, backup, verify};
use crate::error::{Error, Result};

/// What the retired key is renamed to. It stays on disk rather than being deleted, because a
/// move that goes wrong halfway needs a way back.
pub(crate) const RETIRED_KEY: &str = "radicle.retired";
const RETIRED_NOTE: &str = "RETIRED.txt";

pub fn run(ctx: &Ctx, args: &Migrate) -> Result<()> {
    ctx.home.require_identity()?;

    // Not "is it running" but "is it proven stopped": this run is about to retire the key on
    // this machine, and a socket that could not be reached is not evidence of anything.
    let state = ctx.home.probe_node_state();
    if !state.is_stopped() {
        return Err(match state.doubt() {
            Some(doubt) => Error::refused(
                format!("whether the node is running cannot be told: {doubt}"),
                "make sure it is stopped and run the move again: two nodes sharing one key is \
                 what this refusal is for",
            ),
            None => match ctx.home.borrowed_socket() {
                Some(socket) => Error::refused(
                    format!(
                        "a node answered on {}, which RAD_SOCKET names rather than this home's \
                         own socket",
                        socket.display()
                    ),
                    "stop that node, or unset RAD_SOCKET if it belongs to another home, then \
                     run the move again",
                ),
                None => Error::refused(
                    "the node is running",
                    "run `rad node stop` first: a move that leaves it running is how two nodes \
                     end up sharing one key",
                ),
            },
        });
    }

    let create = Create {
        output: Some(args.output.clone()),
        tier: TierArg::Full,
        repos: None,
        stdout: false,
        plaintext: false,
        recipient: Vec::new(),
        stop_node: false,
        with_node_db: true,
        keep: None,
        dry_run: false,
    };
    // Decided here rather than inside `backup`, because it is what the archive claims about
    // this machine's future, and this is where that future is chosen.
    let purpose = match args.keep_source {
        true => backup::Purpose::MoveKeepingSource,
        false => backup::Purpose::Move,
    };
    let outcome = backup::run(ctx, &create, purpose)?;
    // A move retires the key on this machine, so an archive that is missing repositories must
    // not be the one it is retired against. `backup` carries on past a repository it cannot
    // bundle, which is right for a backup and wrong for the last copy before a machine is
    // left.
    if outcome.is_incomplete {
        return Err(Error::refused(
            "the archive this move would rely on is missing repositories that could not be bundled",
            "fix or remove the damaged repositories, then run the move again",
        ));
    }
    let archive = outcome.path.ok_or_else(|| {
        Error::refused(
            "a move needs an archive on disk",
            "give a path to write it to",
        )
    })?;

    ctx.term.blank();
    ctx.term
        .step("checking the archive before retiring anything");
    let report = verify::check(
        ctx,
        &Verify {
            target: crate::cli::ArchiveArg {
                archive: Some(archive.clone()),
            },
            deep: true,
        },
    )?;
    if !report.passed() {
        for problem in &report.problems {
            ctx.term.fail(problem);
        }
        return Err(Error::refused(
            "the archive did not verify, so this machine's key was left alone",
            "fix the problems above and run the move again",
        ));
    }
    ctx.term.ok("the archive restores this identity");

    if args.keep_source {
        ctx.term
            .warn("--keep-source: this machine keeps its key, and you now have two copies");
        ctx.term
            .detail("start only one of them, ever, or your peer id will fork");
    } else {
        retire(ctx, &archive)?;
    }

    ctx.term.blank();
    ctx.term.headline("on the other machine");
    ctx.term.hint(&format!(
        "copy {} across, then run:",
        archive.file_name().unwrap_or_default().to_string_lossy()
    ));
    ctx.term.hint("    rad-backup restore <archive>");
    ctx.term
        .hint("it will put the identity, the policies and the repositories back, then compare");
    ctx.term
        .hint("what came back with what other nodes report holding, and name any repository");
    ctx.term.hint("you must not write in");
    Ok(())
}

/// Rename the key so this node cannot start with it, and leave a note saying why.
fn retire(ctx: &Ctx, archive: &Path) -> Result<()> {
    let question = format!(
        "Retire the key on this machine? {} keeps the only usable copy.",
        archive.display()
    );
    if !ctx.term.confirm(&question)? {
        // The archive is already written, and it says this machine retires its key, because
        // that is what the command was asked to do. Saying so is the whole of the remedy: a
        // home restored from it will be told the source is safe, and it is not.
        return Err(Error::refused(
            format!(
                "nothing was retired, so this machine still holds the identity, and {} says \
                 otherwise to whoever restores it",
                archive.display()
            ),
            "delete that archive and run the move again with --keep-source, or answer yes",
        ));
    }

    let from = ctx.home.secret_key();
    let to = retired_path(&ctx.home.keys_dir());
    // Named for the source: a rename fails on either path, and the one a reader can act on
    // is the key that is still where it was.
    std::fs::rename(&from, &to).map_err(|e| Error::io(&from, e))?;

    // The name the rename actually used, not `RETIRED_KEY`: a second move puts its key at
    // `radicle.retired.2`, and a note pointing at `radicle.retired` sends the one person who
    // ever reads this file to the key from the move before. Read at 3am, that is the wrong key
    // put back on a machine whose node is about to sign under a peer id another node holds.
    let retired_as = to
        .file_name()
        .unwrap_or(RETIRED_KEY.as_ref())
        .to_string_lossy();
    let note_path = ctx.home.keys_dir().join(RETIRED_NOTE);
    let already = match std::fs::read_to_string(&note_path) {
        Ok(already) => Some(already),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(Error::io(&note_path, e)),
    };
    let note = retirement_note(
        already.as_deref(),
        &retired_as,
        &crate::cmd::rfc3339_stamp(jiff::Timestamp::now()),
        archive,
    );
    std::fs::write(&note_path, note).map_err(|e| Error::io(&note_path, e))?;

    ctx.term
        .ok(&format!("retired this machine's key to {}", to.display()));
    Ok(())
}

/// What `RETIRED.txt` says after this retirement, given whatever it said before.
///
/// Pure, so the two things that were wrong about it can be tested without a home: it named
/// `RETIRED_KEY` rather than the file the rename produced, so a second move sent its reader to
/// the key from the move before, and it was written rather than appended, so that second move
/// took the only record of which archive the first key had left with.
fn retirement_note(already: Option<&str>, retired_as: &str, when: &str, archive: &Path) -> String {
    let addition = format!(
        "This identity was moved to another machine on {when}.\n\
         \n\
         The key that used to be at keys/radicle is now beside this note as {retired_as}.\n\
         It still works, which is exactly the problem: if you put it back and start a node\n\
         here while the other machine is also running one, both will sign refs under the same\n\
         peer id and the network will see your identity fork.\n\
         \n\
         Put it back only if the move failed and the other machine never started its node.\n\
         \n\
         The archive it was moved with: {}\n",
        archive.display()
    );
    match already {
        Some(already) => format!("{already}\n{addition}"),
        None => addition,
    }
}

/// Where a first retirement puts the key it displaced.
///
/// Separate from `retired_path` below, which answers "where would the NEXT one go" and so
/// returns a name nothing is at. Asking that one whether a home holds a retired key can only
/// ever be answered no: the arm in `what_a_restore_would_overwrite` that did was unreachable.
pub(crate) fn first_retired_path(keys_dir: &Path) -> PathBuf {
    keys_dir.join(RETIRED_KEY)
}

/// Whether this home holds a key some earlier retirement displaced, under any of its names.
///
/// The directory rather than the first name, because `retired_path` never reuses a freed one:
/// a home whose `radicle.retired` was moved away by hand still holds `radicle.retired.2`, and
/// a probe that asked only for the first would read that home as empty and let a restore
/// write over the key in it. A directory that cannot be listed counts as holding one, for the
/// reason `what_a_restore_would_overwrite` gives: being wrong towards "present" costs one
/// `--force` and being wrong the other way costs somebody's only key.
pub(crate) fn holds_a_retired_key(keys_dir: &Path) -> bool {
    let entries = match std::fs::read_dir(keys_dir) {
        Ok(entries) => entries,
        Err(e) => return e.kind() != std::io::ErrorKind::NotFound,
    };
    entries.into_iter().any(|entry| match entry {
        Ok(entry) => entry.file_name().to_string_lossy().starts_with(RETIRED_KEY),
        // An entry that will not read is a name this cannot rule out, and `flatten` dropped
        // it silently: a directory listing that failed halfway through then read as one
        // holding nothing, which is the answer that lets a restore write over the key.
        Err(_) => true,
    })
}

/// Where the next retirement should put the key it displaces: the first name free.
///
/// A second move does not write over the first one's key: the same file name twice would mean
/// a key nobody meant to destroy is gone, which is the one outcome this whole tool exists to
/// prevent. The `unwrap_or` below cannot be reached, because the range it searches has no end;
/// it is there because the type says the search may fail and returning the occupied path is
/// the answer a caller can at least see going wrong.
pub(crate) fn retired_path(keys_dir: &Path) -> PathBuf {
    let first = first_retired_path(keys_dir);
    if !first.exists() {
        return first;
    }
    (2..)
        .map(|n| keys_dir.join(format!("{RETIRED_KEY}.{n}")))
        .find(|path| !path.exists())
        .unwrap_or(first)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bug, twice over: the note named `RETIRED_KEY` while the rename had produced
    /// `radicle.retired.2`, so it sent its reader to the key the move before had displaced,
    /// and it was written over the first note, taking the only record of which archive that
    /// key had left with. Both matter at the one moment this file is ever read, which is
    /// somebody deciding whether to put a key back on a machine whose peer id another node is
    /// signing under.
    #[test]
    fn a_second_move_names_its_own_key_and_keeps_the_first_note() {
        let first = retirement_note(
            None,
            RETIRED_KEY,
            "2026-01-02T03:04:05Z",
            Path::new("/backups/first.tar.zst"),
        );
        assert!(first.contains("as radicle.retired.\n"), "{first}");
        assert!(first.contains("/backups/first.tar.zst"), "{first}");

        let second = retirement_note(
            Some(&first),
            "radicle.retired.2",
            "2026-03-04T05:06:07Z",
            Path::new("/backups/second.tar.zst"),
        );
        assert!(second.contains("as radicle.retired.2.\n"), "{second}");
        // The first paragraph and its archive are still there to be read.
        assert!(second.contains("/backups/first.tar.zst"), "{second}");
        assert!(second.contains("/backups/second.tar.zst"), "{second}");
        assert!(second.starts_with(&first), "{second}");
    }

    #[test]
    fn a_retired_key_sits_beside_the_one_it_replaced() {
        let path = retired_path(Path::new("/home/me/.radicle/keys"));
        assert_eq!(
            path,
            PathBuf::from("/home/me/.radicle/keys/radicle.retired")
        );
        assert_ne!(path.file_name(), Some(std::ffi::OsStr::new("radicle")));
    }

    #[test]
    fn a_second_move_retires_beside_the_first_rather_than_over_it() {
        let dir = std::env::temp_dir().join(format!("rad-backup-retire-{}", std::process::id()));
        // Whatever a previous run left behind would change the answer this asks about.
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch directory is creatable");
        let first = retired_path(&dir);
        std::fs::write(&first, b"the first retired key").expect("the first key is writable");

        let second = retired_path(&dir);
        assert_ne!(second, first);
        assert_eq!(second, dir.join("radicle.retired.2"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
