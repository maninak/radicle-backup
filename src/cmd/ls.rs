//! Lists this identity's archives and their ages.

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
            "`ls` lists your archives. It does not open one",
            format!(
                "to see what is inside that archive, run: rad backup show {}",
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
    // Encryption is read from each archive's first bytes, because a `--stdout` archive can be
    // encrypted under a plain name. `ls` never decrypts, so it needs no passphrase.
    let present = archives::in_dir(&directory, &identity.node_id())?;

    if ctx.global.json {
        let rows: Vec<serde_json::Value> = present
            .iter()
            .map(|archive| {
                serde_json::json!({
                    "path": archive.path.display().to_string(),
                    "bytes": archive.bytes,
                    "taken": crate::cmd::rfc3339_stamp(archive.taken),
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

    if present.is_empty() && crate::cmd::is_gone(&directory) {
        ctx.term
            .headline(&format!("{} does not exist", directory.display()));
        ctx.term.hint(match args.dir {
            Some(_) => "check the path given to --dir or RAD_BACKUP_DIR",
            None => "pass --dir, or set RAD_BACKUP_DIR to the directory that holds your archives",
        });
        return Ok(());
    }
    if present.is_empty() {
        ctx.term.headline(&format!(
            "no archive of {} in {}",
            identity.did(),
            directory.display()
        ));
        ctx.term.hint("create one with `rad backup`");
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
        let age = term::days_ago(term::days_between(archive.taken, now));
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
            .hint("* your last archive, which `rad backup diff` compares against");
    }
    Ok(())
}

/// Whether `archive` is the one the state record points at.
fn is_recorded(archive: &Archive, record: Option<&state::Record>) -> bool {
    // The match is by path, because two archives taken in the same second share a timestamp
    record
        .and_then(|record| record.archive.as_deref())
        .is_some_and(|recorded| std::path::Path::new(recorded) == archive.path)
}
