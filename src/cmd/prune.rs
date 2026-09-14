//! Deleting older archives, on purpose rather than as a side effect.
//!
//! `--keep` on a backup run prunes as it goes, which is what a timer wants. This is the same
//! rule with nothing else happening around it, for someone who has just noticed that a disk is
//! full and wants to see what would go before it goes.

use crate::archives::sidecar_path;
use crate::archives::{self, Archive, Completeness, Fate};
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

    let (completeness, unreadable) = archives::completeness(&present);
    for e in &unreadable {
        ctx.term.warn(&format!(
            "could not read {e}. rad-backup cannot tell whether the archive beside that note \
             is missing repositories"
        ));
    }
    let fates = archives::fates(&completeness, args.keep);
    let with_fate = |wanted: Fate| -> Vec<(&Archive, &Completeness)> {
        present
            .iter()
            .zip(&completeness)
            .zip(&fates)
            .filter(|(_, fate)| **fate == wanted)
            .map(|(pair, _)| pair)
            .collect()
    };
    let doomed = with_fate(Fate::Deleted);
    let spared: Vec<&Archive> = with_fate(Fate::Spared)
        .into_iter()
        .map(|(archive, _)| archive)
        .collect();

    if doomed.is_empty() {
        ctx.term.ok(&format!(
            "nothing to delete. {} holds {} of your identity, and --keep is {}",
            directory.display(),
            term::count(present.len(), "archive", "archives"),
            args.keep
        ));
        say_spared(ctx, &spared);
        return Ok(());
    }

    ctx.term.headline(&format!(
        "{} to delete, keeping the newest {}",
        term::count(doomed.len(), "archive", "archives"),
        args.keep
    ));
    for (archive, note) in &doomed {
        ctx.term.print(&format!(
            "  {}  {}{}",
            archive.name(),
            term::human_bytes(archive.bytes),
            match note {
                Completeness::Incomplete(_) => "  may be missing repositories",
                Completeness::Complete(_) | Completeness::Unknown => "",
            }
        ))?;
    }
    let freed: u64 = doomed.iter().map(|(archive, _)| archive.bytes).sum();
    ctx.term.blank();
    say_spared(ctx, &spared);

    if args.dry_run {
        ctx.term.hint(&format!(
            "deleting them would free {}. Nothing was deleted",
            term::human_bytes(freed)
        ));
        return Ok(());
    }
    if !ctx.term.confirm(&format!(
        "Delete them and free {}?",
        term::human_bytes(freed)
    ))? {
        // Two different noes, as in `restore`: somebody who typed `n` has decided, and a run
        // with nobody to ask needs to be told how to say yes, not to decide.
        let remedy = match ctx.term.is_interactive() {
            true => "run the same command again when you want them deleted",
            false => "rad-backup could not ask for confirmation. Add --yes to delete them",
        };
        return Err(Error::refused("nothing was deleted", remedy));
    }
    for (archive, _) in &doomed {
        std::fs::remove_file(&archive.path).map_err(|e| Error::io(&archive.path, e))?;
        let sidecar = sidecar_path(&archive.path);
        if let Some(e) = unremoved_sidecar(&sidecar) {
            ctx.term.warn(&format!(
                "could not delete {}: {e}. Its archive is gone, so delete the note yourself",
                sidecar.display()
            ));
        }
    }
    ctx.term.ok(&format!(
        "deleted {}, freeing {}",
        term::count(doomed.len(), "archive", "archives"),
        term::human_bytes(freed)
    ));
    Ok(())
}

/// Name the older archives kept past `--keep`, so a count that does not add up says why.
fn say_spared(ctx: &Ctx, spared: &[&Archive]) {
    if spared.is_empty() {
        return;
    }
    ctx.term.detail(&format!(
        "also keeping {}. No newer archive is known to have everything they may have",
        term::count(spared.len(), "older archive", "older archives")
    ));
    // On stderr, never through `print`: stdout lists only what is deleted, and a script may
    // delete whatever it lists. Not dropped by `--quiet`, which every scheduled run passes.
    for archive in spared {
        ctx.term.detail(&format!(
            "  {}  {}",
            archive.name(),
            term::human_bytes(archive.bytes)
        ));
    }
    ctx.term.blank();
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
