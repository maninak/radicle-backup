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

/// Describe the same set of repositories the archive described, so the two are comparable.
///
/// A `--repos all` or `--repos seeded` archive describes repositories that are not this
/// peer's. Comparing that against a listing of only this peer's own reported every one of
/// them as gone, on every run, forever: a scheduled `diff` meant to say "nothing changed,
/// skip the backup" answered "repositories are missing" instead, and exited `3` doing it.
///
/// A selection this version does not know is read as `all`, because the two ways of being
/// wrong are not equal: describing too much makes a repository look newly added, and too
/// little makes one look lost.
fn comparison_selection(recorded: &str) -> RepoSelection {
    match RepoSelection::from_word(recorded) {
        RepoSelection::Unknown => RepoSelection::All,
        known => known,
    }
}

/// What one set of ids gained and lost since the last archive. Sorted, as the sets are.
#[derive(Debug, serde::Serialize)]
struct SetChange<'a> {
    added: Vec<&'a str>,
    removed: Vec<&'a str>,
}

impl<'a> SetChange<'a> {
    fn between(then: &'a BTreeSet<String>, now: &'a BTreeSet<String>) -> Self {
        Self {
            added: now.difference(then).map(String::as_str).collect(),
            removed: then.difference(now).map(String::as_str).collect(),
        }
    }

    fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty()
    }
}

/// Every policy set compared by id. Equal counts are not enough, because seeding one
/// repository and unseeding another leaves them equal while the archive no longer matches.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct PolicyChanges<'a> {
    seeded: SetChange<'a>,
    followed: SetChange<'a>,
    blocked_repos: SetChange<'a>,
    blocked_peers: SetChange<'a>,
}

impl<'a> PolicyChanges<'a> {
    fn between(then: &'a state::PolicySets, now: &'a state::PolicySets) -> Self {
        Self {
            seeded: SetChange::between(&then.seeded, &now.seeded),
            followed: SetChange::between(&then.followed, &now.followed),
            blocked_repos: SetChange::between(&then.blocked_repos, &now.blocked_repos),
            blocked_peers: SetChange::between(&then.blocked_peers, &now.blocked_peers),
        }
    }

    fn is_empty(&self) -> bool {
        self.seeded.is_empty()
            && self.followed.is_empty()
            && self.blocked_repos.is_empty()
            && self.blocked_peers.is_empty()
    }
}

/// "2 repositories newly seeded" and "1 repository no longer seeded", each over its names.
fn say_set_change(
    term: &term::Term,
    change: &SetChange,
    (singular, plural): (&str, &str),
    verb: &str,
    name: &dyn Fn(&str) -> String,
) {
    for (ids, how) in [(&change.added, "newly"), (&change.removed, "no longer")] {
        if ids.is_empty() {
            continue;
        }
        let count = term::count(ids.len(), singular, plural);
        term.warn(&format!("{count} {how} {verb}"));
        for id in ids {
            term.hint(&name(id));
        }
    }
}

pub fn run(ctx: &Ctx) -> Result<std::process::ExitCode> {
    ctx.home.require_identity()?;
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
    if rad.is_none() {
        ctx.term.warn(&format!(
            "{}. `diff` may report some of your repositories as changed or gone when they are not.",
            crate::exec::rad_missing(crate::exec::rad_override_from_env().as_deref())
        ));
    }
    let policies = db::read_policies(&ctx.home.policies_db())?;
    let routing = db::read_routing_counts(&ctx.home.node_db(), &node_id)?;
    let inventory = inventory::collect(
        &ctx.home,
        &git,
        rad.as_ref(),
        comparison_selection(&record.repo_selection),
        inventory::Purpose::Inspection,
        &node_id,
        &policies,
        &routing,
    )?;

    let rids_now: BTreeSet<String> = inventory
        .records
        .iter()
        .map(|repo| repo.rid.clone())
        .collect();
    let added: Vec<&String> = rids_now.difference(&record.described).collect();
    let removed: Vec<&String> = record.described.difference(&rids_now).collect();

    // A repository has moved on when the signed refs of this peer point somewhere else than
    // they did. That is the only change that can cost work, so it is the one worth naming.
    // A new repository is named once, as new: it has no archived signed refs either, so
    // without the first check it was listed a second time as moved.
    let moved: Vec<&crate::manifest::RepoRecord> = inventory
        .records
        .iter()
        .filter(|repo| record.described.contains(&repo.rid))
        .filter(|repo| {
            let current = repo.sigrefs.get(&node_id);
            match (current, record.sigrefs.get(&repo.rid)) {
                (Some(current), Some(archived)) => current != archived,
                (Some(_), None) => true,
                _ => false,
            }
        })
        .collect();
    // Two spellings of the same list: rids for the report a machine reads, names for the
    // lines a person reads.
    let moved_rids: Vec<&String> = moved.iter().map(|repo| &repo.rid).collect();
    let moved_names: Vec<&str> = moved.iter().map(|repo| repo.display_name()).collect();

    let policies_now = state::PolicySets::of(&policies);
    let policy_changes = record
        .policies
        .as_ref()
        .map(|then| PolicyChanges::between(then, &policies_now));
    let policy_drift = match &policy_changes {
        Some(changes) => !changes.is_empty(),
        // A record written before the sets were kept has only counts, and a swap of one
        // repository for another passes them.
        None => {
            policies_now.seeded.len() != record.seeded
                || policies_now.followed.len() != record.followed
        }
    };
    let drifted =
        !added.is_empty() || !removed.is_empty() || !moved_names.is_empty() || policy_drift;

    if ctx.global.json {
        // By rid, and by rid only. This report named the added and gone repositories by rid
        // and the moved ones by display name, so the one field a consumer would act on was
        // the one it could not look anything up with.
        ctx.term.print_json(&serde_json::json!({
            "since": record.created,
            "archive": record.archive,
            "changed": drifted,
            "repositoriesAdded": added,
            "repositoriesGone": removed,
            "repositoriesMoved": moved_rids,
            "policiesChanged": policy_drift,
            // `null` when the record predates the sets, and `policiesChanged` compared counts.
            "policies": policy_changes,
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
            match policy_changes {
                Some(_) => term.ok("nothing has changed"),
                None => term.ok("no repository has changed"),
            }
        }
        if !added.is_empty() {
            term.warn(&term::count(
                added.len(),
                "new repository",
                "new repositories",
            ));
            for rid in &added {
                // By name here and by rid in the JSON report, for the same reason each way
                // round: a person cannot recognise a rid, and a machine cannot look anything
                // up with a name. A repository that is new is in the inventory, so its name
                // is known; one that has gone is not, which is why gone ones are only counted.
                term.hint(&inventory.display_name(rid));
            }
        }
        if !moved_names.is_empty() {
            term.warn(&format!(
                "{} with new work of yours",
                term::count(moved_names.len(), "repository", "repositories")
            ));
            for name in &moved_names {
                term.hint(name);
            }
        }
        if !removed.is_empty() {
            term.step(&format!(
                "{} no longer on this machine",
                term::count(removed.len(), "repository", "repositories")
            ));
        }
        let repo_name = |rid: &str| inventory.display_name(rid);
        // The local alias beside the id when there is one, since an id alone is unrecognisable.
        let peer_name = |nid: &str| {
            let alias = policies
                .following
                .iter()
                .find(|policy| policy.nid == nid)
                .and_then(|policy| policy.alias.as_deref())
                .filter(|alias| !alias.is_empty());
            match alias {
                Some(alias) => format!("{alias} ({nid})"),
                None => nid.to_string(),
            }
        };
        const REPOS: (&str, &str) = ("repository", "repositories");
        const PEERS: (&str, &str) = ("peer", "peers");
        match &policy_changes {
            Some(changes) => {
                say_set_change(term, &changes.seeded, REPOS, "seeded", &repo_name);
                say_set_change(term, &changes.followed, PEERS, "followed", &peer_name);
                say_set_change(term, &changes.blocked_repos, REPOS, "blocked", &repo_name);
                say_set_change(term, &changes.blocked_peers, PEERS, "blocked", &peer_name);
            }
            None => {
                if policies_now.seeded.len() != record.seeded {
                    term.warn(&format!(
                        "{} seeded now, {} at the last archive",
                        term::count(policies_now.seeded.len(), REPOS.0, REPOS.1),
                        record.seeded
                    ));
                }
                if policies_now.followed.len() != record.followed {
                    term.warn(&format!(
                        "{} followed now, {} at the last archive",
                        term::count(policies_now.followed.len(), PEERS.0, PEERS.1),
                        record.followed
                    ));
                }
                if record.seeded + record.followed > 0 {
                    term.hint(
                        "the last archive only counted your policies. After your next backup, \
                         `rad backup diff` names each change.",
                    );
                }
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_comparison_describes_what_the_archive_it_compares_against_described() {
        // Not `None`. An archive taken with `--repos all` describes repositories this peer
        // does not own, and a comparison blind to them called every one of them gone.
        assert_eq!(comparison_selection("all"), RepoSelection::All);
        assert_eq!(comparison_selection("seeded"), RepoSelection::Seeded);
        assert_eq!(comparison_selection("mine"), RepoSelection::Mine);
        assert_eq!(comparison_selection("private"), RepoSelection::Private);
        assert_eq!(comparison_selection("none"), RepoSelection::None);
    }

    #[test]
    fn a_selection_this_version_cannot_read_describes_everything_rather_than_nothing() {
        // The safe direction: a repository that looks newly added is a curiosity, and one that
        // looks lost sends somebody hunting for a backup they already have.
        assert_eq!(comparison_selection("some-later-word"), RepoSelection::All);
        assert_eq!(comparison_selection(""), RepoSelection::All);
    }
}
