//! Moving an identity to another machine.

use std::path::{Path, PathBuf};

use crate::cli::{Create, Migrate, TierArg, Verify};
use crate::cmd::{Ctx, backup, verify};
use crate::error::{Error, Result};
use crate::perms::MODE_DOC;

/// The file name the retired key is renamed to.
///
/// The key stays on disk, so a move that goes wrong halfway has a way back.
pub(crate) const RETIRED_KEY: &str = "radicle.retired";
const RETIRED_NOTE: &str = "RETIRED.txt";

pub fn run(ctx: &Ctx, args: &Migrate) -> Result<()> {
    ctx.home.require_identity()?;

    // The node must be proven stopped before its key is retired, because a socket that could
    // not be reached is no evidence the node is down
    let state = ctx.home.probe_node_state();
    if !state.is_stopped() {
        return Err(match state.doubt() {
            Some(doubt) => Error::refused(
                format!("could not tell whether your node is running\n{doubt}"),
                "make sure your node is stopped, then run the move again",
            ),
            None => match ctx.home.borrowed_socket() {
                Some(socket) => Error::refused(
                    format!(
                        "a node is running on {}, the socket RAD_SOCKET points to",
                        socket.display()
                    ),
                    "stop that node, or unset RAD_SOCKET if that node uses other Radicle data. \
                     Then run the move again",
                ),
                None => Error::refused(
                    "your node is running",
                    "run `rad node stop`, then run the move again",
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
    let purpose = match args.keep_source {
        true => backup::Purpose::MoveKeepingSource,
        false => backup::Purpose::Move,
    };
    let outcome = backup::run(ctx, &create, purpose)?;
    // `backup` carries on past a repository it cannot bundle. A move retires the key here, so
    // an archive missing repositories must not be the one the key is retired against.
    if outcome.is_incomplete {
        return Err(Error::refused(
            "the move stopped because the archive may be missing repositories",
            "fix what the backup reported above, then run the move again",
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
        .step("checking the archive before retiring the key on this machine");
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
            "the archive failed its check. The key on this machine was not changed",
            "fix the problems above, then run the move again",
        ));
    }
    ctx.term.ok("the archive can restore your identity");

    if args.keep_source {
        ctx.term
            .warn("--keep-source: this machine still has a usable key for your identity");
        ctx.term
            .detail("never run a node on both machines, or your identity will fork");
    } else {
        retire(ctx, &archive)?;
    }

    ctx.term.blank();
    ctx.term.headline("on the other machine");
    let file_name = archive.file_name().unwrap_or_default().to_string_lossy();
    ctx.term
        .hint(&format!("copy {file_name} to the other machine, then run:"));
    ctx.term
        .hint(&format!("    rad backup restore {file_name}"));
    ctx.term
        .hint("the restore brings back your identity, policies and repositories");
    ctx.term.hint(
        "it then compares them with the network and warns about any repository you should not \
         write to yet",
    );
    Ok(())
}

/// Renames the key so this node cannot start with it, and leaves a note saying why.
///
/// Two nodes running one key sign conflicting histories for the same peer, and the network
/// sees a fork that nothing resolves.
fn retire(ctx: &Ctx, archive: &Path) -> Result<()> {
    let question = format!(
        "Retire the key on this machine? The archive at {} will hold the only usable copy.",
        archive.display()
    );
    if !ctx.term.confirm(&question)? {
        // The written archive already says this machine retired its key, so a home restored
        // from it would be told the source is safe
        let remedy = match ctx.term.is_interactive() {
            true => {
                "delete that archive, then run the move again. Answer yes, or add \
                     --keep-source to keep the key on this machine"
            }
            false => {
                "delete that archive, then run the move again. Add --yes to retire the key, \
                      or --keep-source to keep it on this machine"
            }
        };
        return Err(Error::refused(
            format!(
                "the key on this machine was not retired. The archive at {} says it was",
                archive.display()
            ),
            remedy,
        ));
    }

    let from = ctx.home.secret_key();
    let to = retired_path(&ctx.home.keys_dir());
    // The error names the source, because the key still in place is the one a user can act on
    std::fs::rename(&from, &to).map_err(|e| Error::io(&from, e))?;

    // The note names the file the rename produced. A second move puts its key at
    // `radicle.retired.2`, and a note naming `radicle.retired` sends its reader to the key of
    // the move before.
    let retired_as = to
        .file_name()
        .unwrap_or(RETIRED_KEY.as_ref())
        .to_string_lossy();
    let note_path = ctx.home.keys_dir().join(RETIRED_NOTE);
    // Every failure from here on is reported and none propagates. The key is already renamed,
    // so an error here would report a failed move and withhold the line naming where it went.
    match read_former_note(&note_path) {
        // The note stays as it is, because writing over it drops the record of an earlier
        // retirement
        FormerNote::Unreadable(e) => {
            ctx.term.warn(&format!(
                "could not read {}: {e}. The note was left unchanged",
                note_path.display()
            ));
        }
        former => {
            let note = retirement_note(
                former.said(),
                &retired_as,
                &crate::cmd::rfc3339_stamp(jiff::Timestamp::now()),
                archive,
            );
            if let Err(e) = crate::perms::write_atomically(&note_path, note.as_bytes(), MODE_DOC) {
                ctx.term.warn(&format!(
                    "could not write the note {}: {e}",
                    note_path.display()
                ));
                ctx.term.detail(
                    "the key was still retired. No note in the keys directory explains why",
                );
            }
        }
    }

    ctx.term.ok(&format!(
        "retired the key on this machine. It is now at {}",
        to.display()
    ));
    Ok(())
}

/// What `RETIRED.txt` held before this retirement.
enum FormerNote {
    Absent,
    /// The text, carried into the note this move writes.
    Said(String),
    Unreadable(std::io::Error),
}

impl FormerNote {
    fn said(&self) -> Option<&str> {
        match self {
            Self::Said(said) => Some(said.as_str()),
            _ => None,
        }
    }
}

fn read_former_note(path: &Path) -> FormerNote {
    match std::fs::read_to_string(path) {
        Ok(said) => FormerNote::Said(said),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => FormerNote::Absent,
        Err(e) => FormerNote::Unreadable(e),
    }
}

/// The text of `RETIRED.txt` after this retirement, appended to what it `already` said.
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

/// The path a first retirement moves the key to.
///
/// `retired_path` always returns a name nothing is at, so asking it whether a home holds a
/// retired key always answers no.
pub(crate) fn first_retired_path(keys_dir: &Path) -> PathBuf {
    keys_dir.join(RETIRED_KEY)
}

/// Whether `keys_dir` holds a key some earlier retirement displaced, under any of its names.
///
/// Returns `true` when the directory cannot be listed, because a wrong yes costs one `--force`
/// and a wrong no lets a restore write over the user's only key.
pub(crate) fn holds_a_retired_key(keys_dir: &Path) -> bool {
    let entries = match std::fs::read_dir(keys_dir) {
        Ok(entries) => entries,
        Err(e) => return e.kind() != std::io::ErrorKind::NotFound,
    };
    // `retired_path` never reuses a freed name, so `radicle.retired.2` can stand alone
    entries.into_iter().any(|entry| match entry {
        Ok(entry) => entry.file_name().to_string_lossy().starts_with(RETIRED_KEY),
        // An entry that will not read may be a retired key, so it counts as one
        Err(_) => true,
    })
}

/// The first free path for the next retired key, so no retirement writes over an earlier one.
pub(crate) fn retired_path(keys_dir: &Path) -> PathBuf {
    let first = first_retired_path(keys_dir);
    if !first.exists() {
        return first;
    }
    (2..)
        .map(|n| keys_dir.join(format!("{RETIRED_KEY}.{n}")))
        .find(|path| !path.exists())
        // The search range has no end, so this fallback is unreachable
        .unwrap_or(first)
}

#[cfg(test)]
mod tests {
    use super::*;

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
        // Leftovers from a previous run would change the answer
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
