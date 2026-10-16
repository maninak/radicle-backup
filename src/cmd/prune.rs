//! Deletes the archives past `--keep`, by the same rule a backup run with `--keep` applies.

use crate::archives::sidecar_path;
use crate::archives::{self, Archive, Completeness, Fate};
use crate::cli::Prune;
use crate::cmd::{Ctx, archive_dir_from_env, refuse_keep_zero};
use crate::error::{Error, Result};
use crate::key::Identity;
use crate::state;
use crate::term;

/// Deletes the note at `path` beside a deleted archive, and returns the error if it stays.
///
/// Returns `None` when the note is missing, the ordinary case. Any other failure leaves a note
/// describing an archive that is gone, which misleads a reader of the directory, so callers
/// report it.
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

    if present.is_empty() && crate::cmd::is_gone(&directory) {
        return Err(Error::refused(
            format!("{} does not exist", directory.display()),
            match args.dir {
                Some(_) => "check the path given to --dir or RAD_BACKUP_DIR",
                None => {
                    "pass --dir, or set RAD_BACKUP_DIR to the directory that holds your archives"
                }
            },
        ));
    }
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
        // A typed `n` is a decision, so its remedy says how to try again. A run with nobody to
        // ask is told how to say yes.
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

/// Names the older archives kept past `--keep`, so a count that does not add up says why.
fn say_spared(ctx: &Ctx, spared: &[&Archive]) {
    if spared.is_empty() {
        return;
    }
    ctx.term.detail(&format!(
        "also keeping {}. No newer archive is known to have everything they may have",
        term::count(spared.len(), "older archive", "older archives")
    ));
    // Spared archives never go through `print`, because a script may delete whatever stdout
    // lists. `detail` writes to stderr and survives `--quiet`, which scheduled runs pass.
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

    #[test]
    fn a_note_that_would_not_go_is_reported_and_one_that_was_never_there_is_not() {
        let scratch = crate::key::tests::TestScratch::create("prune-sidecar");

        assert!(unremoved_sidecar(&scratch.path_of("absent.txt")).is_none());

        // `remove_file` refuses a directory with an error other than `NotFound`, and needs no
        // mode change, which a test run as root would ignore
        let occupied = scratch.path_of("occupied.txt");
        std::fs::create_dir(&occupied).expect("a directory in the scratch");
        let reported = unremoved_sidecar(&occupied).expect("it is reported");
        assert_ne!(reported.kind(), std::io::ErrorKind::NotFound);
    }
}
