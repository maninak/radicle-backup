//! Deleting older archives, on purpose rather than as a side effect.
//!
//! `--keep` on a backup run prunes as it goes, which is what a timer wants. This is the same
//! rule with nothing else happening around it, for someone who has just noticed that a disk is
//! full and wants to see what would go before it goes.

use crate::archives::sidecar_path;
use crate::archives::{self, Archive};
use crate::cli::Prune;
use crate::cmd::{Ctx, archive_dir_from_env, refuse_keep_zero};
use crate::error::{Error, Result};
use crate::key::Identity;
use crate::state;
use crate::term;

/// The failure to remove the note beside an archive, if there is one to report.
///
/// The note describes an archive that is no longer there, so it goes with it. Missing is the
/// ordinary case, because most archives never had one. Anything else leaves a note standing
/// over a deletion, which is the one state a reader of that directory is misled by, so it is
/// said out loud rather than swallowed.
pub(crate) fn unremoved_sidecar(path: &std::path::Path) -> Option<std::io::Error> {
    match std::fs::remove_file(path) {
        Ok(()) => None,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => Some(e),
    }
}

pub fn run(ctx: &Ctx, args: &Prune) -> Result<()> {
    ctx.home.require_identity()?;
    refuse_keep_zero(args.keep)?;
    let identity = Identity::read(ctx.home.public_key())?;
    let stored = state::read(&identity.did())?;
    let directory = archive_dir_from_env(args.dir.as_deref(), stored.record());
    let present = archives::in_dir(&directory, &identity.node_id())?;

    let doomed: Vec<&Archive> = present.iter().skip(args.keep).collect();
    if doomed.is_empty() {
        ctx.term.ok(&format!(
            "nothing to prune: {} of this identity in {}, keeping {}",
            term::count(present.len(), "archive", "archives"),
            directory.display(),
            args.keep
        ));
        return Ok(());
    }

    ctx.term.headline(&format!(
        "{} to delete, keeping the newest {}",
        term::count(doomed.len(), "archive", "archives"),
        args.keep
    ));
    for archive in &doomed {
        ctx.term.print(&format!(
            "  {}  {}",
            archive.name(),
            term::human_bytes(archive.bytes)
        ))?;
    }
    let freed: u64 = doomed.iter().map(|archive| archive.bytes).sum();
    ctx.term.blank();

    if args.dry_run {
        ctx.term.hint(&format!(
            "{} would come back; nothing was deleted",
            term::human_bytes(freed)
        ));
        return Ok(());
    }
    if !ctx.term.confirm(&format!(
        "Delete them, freeing {}?",
        term::human_bytes(freed)
    ))? {
        return Err(Error::refused(
            "nothing was deleted",
            "run again without --dry-run when you have decided",
        ));
    }
    for archive in &doomed {
        std::fs::remove_file(&archive.path).map_err(|e| Error::io(&archive.path, e))?;
        let sidecar = sidecar_path(&archive.path);
        if let Some(e) = unremoved_sidecar(&sidecar) {
            ctx.term
                .warn(&format!("{} could not be removed: {e}", sidecar.display()));
        }
    }
    ctx.term.ok(&format!(
        "deleted {}, freeing {}",
        term::count(doomed.len(), "archive", "archives"),
        term::human_bytes(freed)
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::unremoved_sidecar;

    /// A note that is not there is the ordinary case and says nothing. A note that is
    /// there and would not go is a note left standing over a deleted archive, and `prune` used
    /// to drop that error on the floor, so the directory kept a description of something it no
    /// longer held and nobody was told why.
    #[test]
    fn a_note_that_would_not_go_is_reported_and_one_that_was_never_there_is_not() {
        let scratch = crate::key::tests::TestScratch::create("prune-sidecar");

        assert!(unremoved_sidecar(&scratch.path_of("absent.txt")).is_none());

        // A directory where the note should be: `remove_file` refuses it for a reason that is
        // not `NotFound`, which is the whole class this guards, without needing a mode change
        // that a root-run test would not feel.
        let occupied = scratch.path_of("occupied.txt");
        std::fs::create_dir(&occupied).expect("a directory in the scratch");
        let reported = unremoved_sidecar(&occupied).expect("it is reported");
        assert_ne!(reported.kind(), std::io::ErrorKind::NotFound);
    }
}
