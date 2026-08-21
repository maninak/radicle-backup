//! Deciding which repositories an archive carries, and what it knows about them.
//!
//! Two costs are kept apart on purpose. Deciding what is yours reads files and spawns nothing,
//! so it stays cheap on a seed holding twelve thousand repositories. Gathering the paperwork
//! (name, delegates, visibility) asks `rad`, so it happens only for repositories that are
//! actually yours.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::db::{Policies, SeedingPolicy};
use crate::error::Result;
use crate::git::{self, Git};
use crate::home::Home;
use crate::manifest::{RepoRecord, RepoSelection};
use crate::rad::{Described, Listed, Listing, Rad};

/// What the inventory pass worked out, before anything is written.
pub struct Inventory {
    /// Every repository the archive will describe, whether or not it carries its data.
    pub records: Vec<RepoRecord>,
    /// Repositories whose data the archive will carry, by identifier.
    pub selected: BTreeSet<String>,
    pub warnings: Vec<String>,
}

impl Inventory {
    pub fn private(&self) -> impl Iterator<Item = &RepoRecord> {
        self.records.iter().filter(|record| record.is_private())
    }

    /// What to call a repository in a message: its name when the paperwork knows one, and its
    /// identifier when it does not.
    pub fn display_name(&self, rid: &str) -> String {
        self.records
            .iter()
            .find(|record| record.rid == rid)
            .map(|record| record.display_name().to_string())
            .unwrap_or_else(|| rid.to_string())
    }

    /// Repositories this identity is the only delegate of. Losing the key ends their
    /// governance, which is the one loss a backup cannot undo.
    pub fn sole_delegate(&self) -> impl Iterator<Item = &RepoRecord> {
        self.records
            .iter()
            .filter(|record| record.delegate && record.delegates.len() == 1)
    }
}

/// Work out what is in storage, what of it is yours, and what the selection asks for.
pub fn collect(
    home: &Home,
    git: &Git,
    rad: Option<&Rad>,
    selection: RepoSelection,
    node_id: &str,
    policies: &Policies,
    routing: &BTreeMap<String, u64>,
) -> Result<Inventory> {
    let mut warnings = Vec::new();
    let (stored, unreadable) = home.repository_ids()?;
    for name in &unreadable {
        warnings.push(format!(
            "storage/{name} was skipped: its directory name is not valid UTF-8, so it cannot \
             be a repository id and nothing in this archive carries it"
        ));
    }

    let mine = own_repository_ids(home, rad, node_id, &stored, &mut warnings)?;
    let stored_ids: BTreeSet<&str> = stored.iter().map(String::as_str).collect();
    let selected: BTreeSet<String> = match selection {
        RepoSelection::None => BTreeSet::new(),
        RepoSelection::Private | RepoSelection::Unknown => BTreeSet::new(),
        RepoSelection::Mine => mine.clone(),
        RepoSelection::Seeded => policies
            .seeded()
            .map(|policy| policy.rid.clone())
            .filter(|rid| stored_ids.contains(rid.as_str()))
            .collect(),
        RepoSelection::All => stored.iter().cloned().collect(),
    };

    // Paperwork is gathered for what is yours and for what is being carried, and for nothing
    // else: on a seed, the other twelve thousand repositories are somebody else's paperwork.
    let described: BTreeSet<&String> = mine.iter().chain(selected.iter()).collect();
    let seeding = policies.seeding_by_rid();
    let mut records = Vec::with_capacity(described.len());
    let mut undescribed = BTreeSet::new();
    let mut first_reason = None;
    for rid in described {
        let (record, unavailable) = describe(home, git, rad, rid, node_id, &seeding, routing)?;
        if let Some(why) = unavailable {
            first_reason.get_or_insert(why);
            undescribed.insert(record.rid.clone());
        }
        records.push(record);
    }
    records.sort_by(|a, b| a.rid.cmp(&b.rid));
    // One warning for all of them, not one each. A `rad` that has stopped answering fails for
    // every repository at once, and a seed holding thousands of them would otherwise put
    // thousands of lines into `manifest.warnings`, which is the same manifest that has an
    // 8 MiB ceiling the writer refuses its own archive against.
    if let Some(why) = first_reason {
        warnings.push(undescribed_warning(&undescribed, &why));
    }

    // The default selection is decided after the records exist, because "private" is a fact
    // about a repository that only the paperwork knows.
    let selected = match selection {
        RepoSelection::Private => {
            let private = private_selection(&records, &undescribed);
            // Visibility lives in the identity document, which only `rad` reads. Without it
            // every repository looks public, so this selection resolves to nothing, silently
            // and with no repository named. That is the STATE tier's default, which is what
            // the shipped systemd timer runs nightly: the failure mode was a year of green
            // runs over archives carrying none of the repositories they were taken for. Not
            // a refusal, because a home with no private repositories legitimately selects
            // nothing and restoring on a machine without `rad` is real, but this exact
            // combination is never what the person running it believes is happening.
            if rad.is_none() && private.is_empty() && !stored.is_empty() {
                warnings.push(format!(
                    "this archive carries NO repositories: {} are in storage, and without \
                     `rad` there is no way to tell which of them are private",
                    stored.len()
                ));
            }
            private
        }
        _ => selected,
    };

    Ok(Inventory {
        records,
        selected,
        warnings,
    })
}

/// The one warning that stands for every repository `rad` could not describe.
///
/// Names a few and counts the rest: the identifiers matter for a handful and stop being
/// readable well before they stop being numerous, while the count is what says how much of the
/// home this is about.
fn undescribed_warning(undescribed: &BTreeSet<String>, why: &str) -> String {
    const NAMED: usize = 5;
    let named: Vec<&str> = undescribed.iter().take(NAMED).map(String::as_str).collect();
    let rest = undescribed.len().saturating_sub(named.len());
    let listed = match rest {
        0 => named.join(", "),
        _ => format!("{}, and {rest} more", named.join(", ")),
    };
    format!(
        "`rad` could not describe {}: {listed} ({why}). They are carried as though they were \
         private, because a repository whose visibility cannot be read must not be left out of \
         an archive for looking public",
        crate::term::count(undescribed.len(), "repository", "repositories")
    )
}

/// What a private-only archive carries: what the paperwork calls private, plus anything the
/// paperwork could not be read for.
///
/// Pure, because it is the decision that empties an archive when it is wrong, and the only way
/// to hold it still is to be able to test it without a `rad` on PATH.
fn private_selection(records: &[RepoRecord], undescribed: &BTreeSet<String>) -> BTreeSet<String> {
    records
        .iter()
        .filter(|record| record.is_private() || undescribed.contains(&record.rid))
        .map(|record| record.rid.clone())
        .collect()
}

/// Repositories this identity has a stake in: ones it created or forked, ones marked private,
/// and any whose storage holds refs under its own namespace.
fn own_repository_ids(
    home: &Home,
    rad: Option<&Rad>,
    node_id: &str,
    stored: &[String],
    warnings: &mut Vec<String>,
) -> Result<BTreeSet<String>> {
    let mut mine = BTreeSet::new();

    match rad {
        Some(rad) => {
            for listing in [Listing::Own, Listing::Private] {
                match rad.list(listing)? {
                    Listed::Ids(ids) => mine.extend(ids),
                    // A listing that failed is not a listing that came back empty, and the
                    // difference decides whether a repository is in the archive at all.
                    Listed::Unavailable { why } => warnings.push(format!(
                        "`rad {}` failed, so repositories it would have named were judged by \
                         their refs alone: {why}",
                        listing.spelling()
                    )),
                }
            }
        }
        None => warnings.push(
            "`rad` is not on PATH, so repositories were judged by their refs alone".to_string(),
        ),
    }

    for rid in stored {
        if has_namespace_at(&home.repository_path(rid), node_id) {
            mine.insert(rid.clone());
        }
    }
    // A listing can name a repository that is no longer in storage; the archive can only carry
    // what is there. Through a set, because a seed reaches five figures of repositories and
    // this is a membership test per repository.
    let stored_ids: BTreeSet<&str> = stored.iter().map(String::as_str).collect();
    mine.retain(|rid| stored_ids.contains(rid.as_str()));
    Ok(mine)
}

fn describe(
    home: &Home,
    git: &Git,
    rad: Option<&Rad>,
    rid: &str,
    node_id: &str,
    seeding: &BTreeMap<&str, &SeedingPolicy>,
    routing: &BTreeMap<String, u64>,
) -> Result<(RepoRecord, Option<String>)> {
    let path = home.repository_path(rid);
    let refs = git.refs(&path)?;
    let sigrefs = sigrefs_by_peer(&refs);
    let head = git.head_target(&path)?;

    let policy = seeding.get(rid);
    let described = match rad {
        Some(rad) => Some(rad.describe_repo(rid)?),
        None => None,
    };
    // No `rad` at all is already said once, up front; only a `rad` that was asked and could
    // not answer is worth a line naming this repository.
    let (identity, unavailable) = match described {
        Some(Described::Identity(identity)) => (Some(identity), None),
        Some(Described::Unavailable { why }) => (None, Some(why)),
        None => (None, None),
    };
    let (name, delegates, visibility, allowed) = match identity {
        Some(identity) => (
            identity.name,
            identity.delegates,
            Some(identity.visibility),
            identity.allowed,
        ),
        None => (None, Vec::new(), None, Vec::new()),
    };

    let did = format!("did:key:{node_id}");
    Ok((
        RepoRecord {
            rid: rid.to_string(),
            name,
            visibility,
            allowed,
            delegate: delegates.contains(&did),
            delegates,
            scope: policy.map(|policy| policy.scope.clone()),
            policy: policy.map(|policy| policy.policy.clone()),
            head,
            refs: refs.len(),
            sigrefs,
            other_seeds: routing.get(rid).copied(),
            bundle: None,
        },
        unavailable,
    ))
}

/// The signed refs each peer published, read out of the ref list we already have rather than
/// asked of `rad` a second time.
fn sigrefs_by_peer(refs: &[git::Ref]) -> BTreeMap<String, String> {
    const PREFIX: &str = "refs/namespaces/";
    const SUFFIX: &str = "/refs/rad/sigrefs";

    refs.iter()
        .filter_map(|reference| {
            let rest = reference.name.strip_prefix(PREFIX)?;
            let peer = rest.strip_suffix(SUFFIX)?;
            Some((peer.to_string(), reference.oid.clone()))
        })
        .collect()
}

/// Whether a repository directory holds refs under a given namespace, without running git.
///
/// Loose refs are a directory; packed refs are one file. Checking both is what keeps this from
/// spawning a process per repository on a seed.
pub fn has_namespace_at(repo: &Path, node_id: &str) -> bool {
    let loose = repo.join("refs").join("namespaces").join(node_id);
    if loose.is_dir() {
        return true;
    }
    let packed = repo.join("packed-refs");
    match std::fs::read_to_string(packed) {
        Ok(text) => text.contains(&format!("refs/namespaces/{node_id}/")),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_refs_are_indexed_by_the_peer_that_signed_them() {
        let refs = vec![
            git::Ref {
                name: "refs/heads/master".to_string(),
                oid: "aaa".to_string(),
            },
            git::Ref {
                name: "refs/namespaces/z6MkAAA/refs/rad/sigrefs".to_string(),
                oid: "bbb".to_string(),
            },
            git::Ref {
                name: "refs/namespaces/z6MkBBB/refs/rad/sigrefs".to_string(),
                oid: "ccc".to_string(),
            },
            git::Ref {
                name: "refs/namespaces/z6MkAAA/refs/heads/master".to_string(),
                oid: "ddd".to_string(),
            },
        ];
        let sigrefs = sigrefs_by_peer(&refs);
        assert_eq!(sigrefs.len(), 2);
        assert_eq!(sigrefs.get("z6MkAAA"), Some(&"bbb".to_string()));
        assert_eq!(sigrefs.get("z6MkBBB"), Some(&"ccc".to_string()));
    }

    fn record(rid: &str, visibility: Option<&str>) -> RepoRecord {
        RepoRecord {
            rid: rid.to_string(),
            name: None,
            visibility: visibility.map(str::to_string),
            allowed: Vec::new(),
            delegate: false,
            delegates: Vec::new(),
            scope: None,
            policy: None,
            head: None,
            refs: 0,
            sigrefs: BTreeMap::new(),
            other_seeds: None,
            bundle: None,
        }
    }

    #[test]
    fn one_warning_stands_for_every_repository_rad_could_not_describe() {
        let many: BTreeSet<String> = (0..12).map(|n| format!("rad:z{n:02}")).collect();
        let warning = undescribed_warning(&many, "rad exited 1");

        // A `rad` that has stopped answering fails for every repository at once. One line per
        // repository would put thousands of them in `manifest.warnings`, and that manifest is
        // the one the writer refuses its own archive over at 8 MiB.
        assert_eq!(warning.lines().count(), 1);
        assert!(warning.contains("12 repositories"), "{warning}");
        assert!(warning.contains("and 7 more"), "{warning}");
        assert!(warning.contains("rad exited 1"), "{warning}");
    }

    #[test]
    fn a_handful_of_undescribable_repositories_are_all_named() {
        let few = BTreeSet::from(["rad:zA".to_string(), "rad:zB".to_string()]);
        let warning = undescribed_warning(&few, "rad exited 1");
        assert!(warning.contains("rad:zA, rad:zB"), "{warning}");
        assert!(!warning.contains("more"), "{warning}");
    }

    #[test]
    fn a_repository_rad_could_not_describe_is_carried_rather_than_taken_for_public() {
        let records = vec![
            record("rad:zPrivate", Some("private")),
            record("rad:zPublic", Some("public")),
            record("rad:zUnknown", None),
        ];
        let undescribed = BTreeSet::from(["rad:zUnknown".to_string()]);

        let selected = private_selection(&records, &undescribed);

        // The one `rad` could not answer for is in, because a repository with no visibility
        // reads as public, and reading it as public is how a private-only archive comes back
        // empty on the day it is needed.
        assert!(selected.contains("rad:zUnknown"));
        assert!(selected.contains("rad:zPrivate"));
        assert!(!selected.contains("rad:zPublic"));
    }

    #[test]
    fn nothing_is_carried_when_every_repository_is_public_and_all_of_them_were_described() {
        let records = vec![record("rad:zA", Some("public")), record("rad:zB", None)];
        // `rad` was not asked about B at all, which is not the same as being asked and
        // failing: with no `rad` on PATH the archive says so once, up front.
        assert!(private_selection(&records, &BTreeSet::new()).is_empty());
    }

    #[test]
    fn a_namespace_is_found_whether_its_refs_are_loose_or_packed() {
        let dir = std::env::temp_dir().join(format!("rad-backup-namespace-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("refs/namespaces/z6MkLoose"))
            .expect("loose ref directory is creatable");
        assert!(has_namespace_at(&dir, "z6MkLoose"));
        assert!(!has_namespace_at(&dir, "z6MkPacked"));

        std::fs::write(
            dir.join("packed-refs"),
            "# pack-refs with: peeled fully-peeled sorted\n\
             aaa refs/namespaces/z6MkPacked/refs/rad/sigrefs\n",
        )
        .expect("packed-refs is writable");
        assert!(has_namespace_at(&dir, "z6MkPacked"));
        assert!(!has_namespace_at(&dir, "z6MkAbsent"));

        let _ = std::fs::remove_dir_all(dir);
    }
}
