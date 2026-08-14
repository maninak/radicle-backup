//! Which archives of this identity exist, and how old they are.
//!
//! Answered from file names and file sizes alone. No archive is opened and no passphrase is
//! asked for, so this stays usable on a machine where the passphrase lives in someone's head
//! and the archives live on a mounted disk.

use crate::archives::{self, Archive};
use crate::cli::Ls;
use crate::cmd::{Ctx, archive_dir};
use crate::error::Result;
use crate::key::Identity;
use crate::state;
use crate::term;

pub fn run(ctx: &Ctx, args: &Ls) -> Result<()> {
    if let Some(archive) = &args.mistaken {
        return Err(crate::error::Error::refused(
            "`ls` lists the archives of this identity; it does not open one",
            format!(
                "to see inside that one: rad backup show {}",
                archive.display()
            ),
        ));
    }
    ctx.home.require()?;
    let identity = Identity::read(ctx.home.public_key())?;
    let stored = state::read(&identity.did())?;
    if let Some(complaint) = stored.complaint() {
        ctx.term.warn(&complaint);
    }
    let record = stored.record();
    let directory = archive_dir(ctx, args.dir.as_deref(), record);
    let found = archives::in_dir(&directory, &identity.node_id())?;

    if ctx.global.json {
        let rows: Vec<serde_json::Value> = found
            .iter()
            .map(|archive| {
                serde_json::json!({
                    "path": archive.path.display().to_string(),
                    "bytes": archive.bytes,
                    "taken": archive.taken.map(crate::cmd::iso_stamp),
                    "encrypted": archive.encrypted,
                    "recorded": is_recorded(archive, record),
                })
            })
            .collect();
        ctx.term.print_json(&serde_json::json!({
            "directory": directory.display().to_string(),
            "archives": rows,
        }))?;
        return Ok(());
    }

    if found.is_empty() {
        ctx.term.headline(&format!(
            "no archive of {} in {}",
            identity.did(),
            directory.display()
        ));
        ctx.term.hint("take one with `rad backup`");
        return Ok(());
    }

    ctx.term.headline(&format!(
        "{} in {}",
        term::count(found.len(), "archive", "archives"),
        directory.display()
    ));
    ctx.term.blank();
    let now = jiff::Timestamp::now();
    for archive in &found {
        let when = archive
            .taken
            // Seconds, not `get_hours`: subtracting two timestamps gives a span whose largest
            // unit is seconds, so the hours COMPONENT of it is always 0 and every archive read
            // as "today" however old it was.
            .map(|taken| term::days_ago((now - taken).get_seconds().div_euclid(86_400)))
            .unwrap_or_else(|| "at an unreadable time".to_string());
        let mark = if is_recorded(archive, record) {
            "*"
        } else {
            " "
        };
        ctx.term.print(&format!(
            "{mark} {:<52} {:>9}  {when}{}",
            archive.name(),
            term::bytes(archive.bytes),
            if archive.encrypted {
                ""
            } else {
                "  (not encrypted)"
            }
        ));
    }
    if found.iter().any(|archive| is_recorded(archive, record)) {
        ctx.term.blank();
        ctx.term
            .hint("* the one this tool last wrote and checks against");
    }
    Ok(())
}

/// Whether this is the archive the state record points at. Compared by path, since two
/// archives taken in the same second would otherwise both look like the recorded one.
fn is_recorded(archive: &Archive, record: Option<&state::Record>) -> bool {
    record
        .and_then(|record| record.archive.as_deref())
        .is_some_and(|recorded| std::path::Path::new(recorded) == archive.path)
}
