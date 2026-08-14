//! What has changed since the last archive.
//!
//! Answered from this tool's own record rather than by opening an archive, so it needs no
//! passphrase and no decryption. A scheduled job can use it to skip a run that would archive
//! nothing new: `rad-backup diff || rad-backup`.

use std::collections::BTreeSet;

use crate::cmd::Ctx;
use crate::db;
use crate::error::{EXIT_CHECKS_FAILED, Error, Result};
use crate::git::Git;
use crate::inventory;
use crate::key::Identity;
use crate::manifest::RepoSelection;
use crate::rad::Rad;
use crate::state;
use crate::term;

pub fn run(ctx: &Ctx) -> Result<std::process::ExitCode> {
    ctx.home.require()?;
    let identity = Identity::read(ctx.home.public_key())?;
    let node_id = identity.node_id();

    let stored = state::read(&identity.did())?;
    if let Some(complaint) = stored.complaint() {
        ctx.term.warn(&complaint);
    }
    let Some(record) = stored.record() else {
        let why = match stored {
            state::Stored::Unreadable { .. } => "the record of the last archive is unreadable",
            state::Stored::Absent | state::Stored::Record(_) => {
                "there is no archive of this identity to compare against"
            }
        };
        return Err(Error::refused(why, "take one with `rad backup`"));
    };

    let git = Git::new();
    let rad = Rad::new(ctx.home.path());
    let rad = rad.is_available().then_some(rad);
    let policies = db::read_policies(&ctx.home.policies_db())?;
    let routing = db::routing_counts(&ctx.home.node_db(), &node_id)?;
    let inventory = inventory::collect(
        &ctx.home,
        &git,
        rad.as_ref(),
        RepoSelection::None,
        &node_id,
        &policies,
        &routing,
    )?;

    let now: BTreeSet<String> = inventory
        .records
        .iter()
        .map(|repo| repo.rid.clone())
        .collect();
    let added: Vec<&String> = now.difference(&record.described).collect();
    let removed: Vec<&String> = record.described.difference(&now).collect();

    // A repository has moved on when the signed refs of this peer point somewhere else than
    // they did. That is the only change that can cost work, so it is the one worth naming.
    let changed: Vec<&str> = inventory
        .records
        .iter()
        .filter(|repo| {
            let current = repo.sigrefs.get(&node_id);
            match (current, record.sigrefs.get(&repo.rid)) {
                (Some(current), Some(archived)) => current != archived,
                (Some(_), None) => true,
                _ => false,
            }
        })
        .map(|repo| repo.display_name())
        .collect();

    let policy_drift = policies.seeded().count() != record.seeded
        || policies.followed().count() != record.followed;
    let drifted = !added.is_empty() || !removed.is_empty() || !changed.is_empty() || policy_drift;

    if ctx.global.json {
        ctx.term.print_json(&serde_json::json!({
            "since": record.created,
            "archive": record.archive,
            "changed": drifted,
            "repositoriesAdded": added,
            "repositoriesGone": removed,
            "repositoriesMoved": changed,
            "policiesChanged": policy_drift,
        }))?;
    } else {
        let term = &ctx.term;
        let age = record
            .age_in_days(jiff::Timestamp::now())
            .map(term::days_ago)
            .unwrap_or_else(|| record.created.clone());
        term.headline(&format!("since the {} archive, taken {age}", record.tier));
        term.blank();

        if !drifted {
            term.ok("nothing has changed");
        }
        if !added.is_empty() {
            term.warn(&format!(
                "{} new",
                term::count(added.len(), "repository", "repositories")
            ));
            for rid in &added {
                term.hint(rid);
            }
        }
        if !changed.is_empty() {
            term.warn(&format!(
                "{} with new signed refs of yours",
                term::count(changed.len(), "repository", "repositories")
            ));
            for name in &changed {
                term.hint(name);
            }
        }
        if !removed.is_empty() {
            term.step(&format!(
                "{} no longer here",
                term::count(removed.len(), "repository", "repositories")
            ));
        }
        if policy_drift {
            term.warn(&format!(
                "policies changed: {} seeded and {} followed now, {} and {} then",
                policies.seeded().count(),
                policies.followed().count(),
                record.seeded,
                record.followed
            ));
        }
        if drifted {
            term.blank();
            term.hint("take a fresh archive: rad backup");
        }
    }

    Ok(if drifted {
        std::process::ExitCode::from(EXIT_CHECKS_FAILED)
    } else {
        std::process::ExitCode::SUCCESS
    })
}
