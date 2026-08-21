//! Deleting older archives, on purpose rather than as a side effect.
//!
//! `--keep` on a backup run prunes as it goes, which is what a timer wants. This is the same
//! rule with nothing else happening around it, for someone who has just noticed that a disk is
//! full and wants to see what would go before it goes.

use crate::archives::{self, Archive};
use crate::cli::Prune;
use crate::cmd::{Ctx, archive_dir, refuse_keep_zero, sidecar_path};
use crate::error::{Error, Result};
use crate::key::Identity;
use crate::state;
use crate::term;

pub fn run(ctx: &Ctx, args: &Prune) -> Result<()> {
    ctx.home.require()?;
    refuse_keep_zero(args.keep)?;
    let identity = Identity::read(ctx.home.public_key())?;
    let record = state::read(&identity.did())?;
    let directory = archive_dir(args.dir.as_deref(), record.record());
    let found = archives::in_dir(&directory, &identity.node_id())?;

    let doomed: Vec<&Archive> = found.iter().skip(args.keep).collect();
    if doomed.is_empty() {
        ctx.term.ok(&format!(
            "nothing to prune: {} of this identity in {}, keeping {}",
            term::count(found.len(), "archive", "archives"),
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
            term::bytes(archive.bytes)
        ));
    }
    let freed: u64 = doomed.iter().map(|archive| archive.bytes).sum();
    ctx.term.blank();

    if args.dry_run {
        ctx.term.hint(&format!(
            "{} would come back; nothing was deleted",
            term::bytes(freed)
        ));
        return Ok(());
    }
    if !ctx
        .term
        .confirm(&format!("Delete them, freeing {}?", term::bytes(freed)))?
    {
        return Err(Error::refused(
            "nothing was deleted",
            "run again without --dry-run when you have decided",
        ));
    }
    for archive in &doomed {
        std::fs::remove_file(&archive.path).map_err(|e| Error::io(&archive.path, e))?;
        // The note beside an archive describes an archive that is no longer there.
        let _ = std::fs::remove_file(sidecar_path(&archive.path));
    }
    ctx.term.ok(&format!(
        "deleted {}, freeing {}",
        term::count(doomed.len(), "archive", "archives"),
        term::bytes(freed)
    ));
    Ok(())
}
