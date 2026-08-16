//! Showing what is inside an archive.

use crate::archive::Reader;
use crate::cli::Target;
use crate::cmd::Ctx;
use crate::crypt;
use crate::error::Result;
use crate::manifest::Manifest;
use crate::term;

pub fn run(ctx: &Ctx, args: &Target) -> Result<()> {
    let scan = open(ctx, args)?;
    if ctx.global.json {
        return ctx.term.print_json(&serde_json::to_value(&scan)?);
    }

    let term = &ctx.term;
    let manifest = &scan;
    term.headline(&format!(
        "{} ({})",
        manifest.identity.alias.as_deref().unwrap_or("unnamed"),
        manifest.identity.did
    ));
    term.hint(&format!(
        "taken {} from {} on {}",
        manifest.created,
        manifest.source.rad_home,
        manifest.source.host.as_deref().unwrap_or("an unnamed host")
    ));
    term.hint(&format!(
        "written by {} {}, on {} {}",
        manifest.tool.name,
        manifest.tool.version,
        manifest.source.os,
        manifest
            .source
            .rad_version
            .as_deref()
            .unwrap_or("an unrecorded rad")
    ));
    term.blank();

    term.headline(&format!(
        "{} entries, {}",
        manifest.entries.len(),
        term::bytes(manifest.total_bytes())
    ));
    for entry in &manifest.entries {
        term.print(&format!("{:>10}  {}", term::bytes(entry.bytes), entry.path));
    }

    if !manifest.repos.is_empty() {
        term.blank();
        let carried = manifest
            .repos
            .iter()
            .filter(|repo| repo.bundle.is_some())
            .count();
        term.headline(&format!(
            "{}, {carried} carried",
            term::count(manifest.repos.len(), "repository", "repositories")
        ));
        for repo in &manifest.repos {
            let marks = [
                repo.bundle.is_some().then_some("archived"),
                repo.is_private().then_some("private"),
                repo.delegate.then_some("delegate"),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(", ");
            // The name column stays empty when there is no name, rather than repeating the
            // identifier that is already in the next column.
            term.print(&format!(
                "{:<24} {:<40} {marks}",
                truncate(repo.name.as_deref().unwrap_or(""), 24),
                repo.rid
            ));
        }
    }

    term.blank();
    term.headline("policies");
    term.print(&format!(
        "{} seeded, {} blocked repositories, {} followed, {} blocked peers",
        manifest.policies.seeded,
        manifest.policies.blocked_repos,
        manifest.policies.followed,
        manifest.policies.blocked_peers
    ));

    if !manifest.warnings.is_empty() {
        term.blank();
        for warning in &manifest.warnings {
            term.warn(warning);
        }
    }
    Ok(())
}

/// Read an archive end to end and hand back what it says it holds.
///
/// The whole archive is read even for a listing, because the manifest is the last entry: it
/// carries the digest of every entry as written, which is a claim that can only be made once
/// the entries exist.
pub fn open(ctx: &Ctx, args: &Target) -> Result<Manifest> {
    let archive = crate::cmd::resolve_archive(ctx, args.archive.as_deref())?;
    let passphrase = if crypt::needs_passphrase(&archive)? {
        Some(crypt::read_passphrase(
            crypt::PASSPHRASE_ENV,
            ctx.global.passphrase_file.as_deref(),
            "Passphrase for the archive: ",
            crypt::Purpose::Opening,
            ctx.term.is_interactive(),
        )?)
    } else {
        None
    };
    let reader = Reader::open(&archive, passphrase.as_ref(), ctx.identity_files())?;
    Ok(reader.scan(&archive)?.manifest)
}

fn truncate(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_string();
    }
    let kept: String = text.chars().take(width.saturating_sub(1)).collect();
    format!("{kept}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_names_are_cut_with_a_mark_that_says_they_were() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("a-very-long-repository-name", 10), "a-very-lo…");
    }
}
