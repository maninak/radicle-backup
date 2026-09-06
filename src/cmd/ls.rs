//! Which archives of this identity exist, and how old they are.
//!
//! Answered from file names, file sizes, and a read of the first bytes of each archive, which
//! is what says whether it is encrypted: a `--stdout` archive is encrypted under a name that
//! says otherwise. Nothing is decrypted and no passphrase is asked for, so this stays usable
//! on a machine where the passphrase lives in someone's head and the archives live on a
//! mounted disk.

use crate::archives::{self, Archive};
use crate::cli::Ls;
use crate::cmd::{Ctx, archive_dir_from_env};
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
    ctx.home.require_identity()?;
    let identity = Identity::read(ctx.home.public_key())?;
    let stored = state::read(&identity.did())?;
    if let Some(complaint) = stored.complaint() {
        ctx.term.warn(&complaint);
    }
    let record = stored.record();
    let directory = archive_dir_from_env(args.dir.as_deref(), record);
    let present = archives::in_dir(&directory, &identity.node_id())?;

    if ctx.global.json {
        let rows: Vec<serde_json::Value> = present
            .iter()
            .map(|archive| {
                serde_json::json!({
                    "path": archive.path.display().to_string(),
                    "bytes": archive.bytes,
                    "taken": archive.taken.map(crate::cmd::rfc3339_stamp),
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

    if present.is_empty() {
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
        term::count(present.len(), "archive", "archives"),
        directory.display()
    ));
    ctx.term.blank();
    let now = jiff::Timestamp::now();
    for archive in &present {
        let age = archive
            .taken
            .map(|taken| term::days_ago(term::days_between(taken, now)))
            .unwrap_or_else(|| "at an unreadable time".to_string());
        let mark = if is_recorded(archive, record) {
            "*"
        } else {
            " "
        };
        ctx.term.print(&format!(
            "{mark} {:<52} {:>9}  {age}{}",
            archive.name(),
            term::human_bytes(archive.bytes),
            match archive.encrypted {
                Some(true) => "",
                Some(false) => "  (not encrypted)",
                None => "  (could not be read)",
            }
        ))?;
    }
    if present.iter().any(|archive| is_recorded(archive, record)) {
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
