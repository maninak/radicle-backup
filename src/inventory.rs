//! Deciding which repositories an archive carries, and what it knows about them.
//!
//! Two costs are kept apart on purpose. Deciding what is yours reads files and spawns nothing,
//! so it stays cheap on a seed holding twelve thousand repositories. Gathering the paperwork
//! (name, delegates, visibility) asks `rad`, so it happens only for repositories that are
//! actually yours.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::db::Policies;
use crate::error::Result;
use crate::git::{self, Git};
use crate::home::Home;
use crate::manifest::{RepoRecord, RepoSelection};
use crate::rad::{Listing, Rad};

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
    let stored = home.repository_ids()?;

    let mine = own_repository_ids(home, rad, node_id, &stored, &mut warnings)?;
    let selected: BTreeSet<String> = match selection {
        RepoSelection::None => BTreeSet::new(),
        RepoSelection::Private | RepoSelection::Unknown => BTreeSet::new(),
        RepoSelection::Mine => mine.clone(),
        RepoSelection::Seeded => policies
            .seeded()
            .map(|policy| policy.rid.clone())
            .filter(|rid| stored.contains(rid))
            .collect(),
        RepoSelection::All => stored.iter().cloned().collect(),
    };

    // Paperwork is gathered for what is yours and for what is being carried, and for nothing
    // else: on a seed, the other twelve thousand repositories are somebody else's paperwork.
    let described: BTreeSet<&String> = mine.iter().chain(selected.iter()).collect();
    let mut records = Vec::with_capacity(described.len());
    for rid in described {
        records.push(describe(home, git, rad, rid, node_id, policies, routing)?);
    }
    records.sort_by(|a, b| a.rid.cmp(&b.rid));

    // The default selection is decided after the records exist, because "private" is a fact
    // about a repository that only the paperwork knows.
    let selected = match selection {
        RepoSelection::Private => records
            .iter()
            .filter(|record| record.is_private())
            .map(|record| record.rid.clone())
            .collect(),
        _ => selected,
    };

    Ok(Inventory {
        records,
        selected,
        warnings,
    })
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
                mine.extend(rad.list(listing)?);
            }
        }
        None => warnings.push(
            "`rad` is not on PATH, so repositories were judged by their refs alone".to_string(),
        ),
    }

    for rid in stored {
        if namespace_present_at(&home.repository_path(rid), node_id) {
            mine.insert(rid.clone());
        }
    }
    // A listing can name a repository that is no longer in storage; the archive can only carry
    // what is there.
    mine.retain(|rid| stored.contains(rid));
    Ok(mine)
}

fn describe(
    home: &Home,
    git: &Git,
    rad: Option<&Rad>,
    rid: &str,
    node_id: &str,
    policies: &Policies,
    routing: &BTreeMap<String, u64>,
) -> Result<RepoRecord> {
    let path = home.repository_path(rid);
    let refs = git.refs(&path)?;
    let sigrefs = sigrefs_by_peer(&refs);
    let head = git.head_target(&path)?;

    let policy = policies.seeding.iter().find(|policy| policy.rid == rid);
    let (name, delegates) = match rad.map(|rad| rad.identity_document(rid)).transpose()? {
        Some(Some(document)) => (
            document
                .get("payload")
                .and_then(|payload| payload.get("xyz.radicle.project"))
                .and_then(|project| project.get("name"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_string),
            document
                .get("delegates")
                .and_then(serde_json::Value::as_array)
                .map(|delegates| {
                    delegates
                        .iter()
                        .filter_map(serde_json::Value::as_str)
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default(),
        ),
        _ => (None, Vec::new()),
    };
    let visibility = match rad {
        Some(rad) => rad.visibility(rid)?,
        None => None,
    };

    let did = format!("did:key:{node_id}");
    Ok(RepoRecord {
        rid: rid.to_string(),
        name,
        visibility,
        delegate: delegates.contains(&did),
        delegates,
        scope: policy.map(|policy| policy.scope.clone()),
        policy: policy.map(|policy| policy.policy.clone()),
        head,
        refs: refs.len(),
        sigrefs,
        other_seeds: routing.get(rid).copied(),
        bundle: None,
    })
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
pub fn namespace_present_at(repo: &Path, node_id: &str) -> bool {
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

    #[test]
    fn a_namespace_is_found_whether_its_refs_are_loose_or_packed() {
        let dir = std::env::temp_dir().join(format!("rad-backup-namespace-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("refs/namespaces/z6MkLoose"))
            .expect("loose ref directory is creatable");
        assert!(namespace_present_at(&dir, "z6MkLoose"));
        assert!(!namespace_present_at(&dir, "z6MkPacked"));

        std::fs::write(
            dir.join("packed-refs"),
            "# pack-refs with: peeled fully-peeled sorted\n\
             aaa refs/namespaces/z6MkPacked/refs/rad/sigrefs\n",
        )
        .expect("packed-refs is writable");
        assert!(namespace_present_at(&dir, "z6MkPacked"));
        assert!(!namespace_present_at(&dir, "z6MkAbsent"));

        let _ = std::fs::remove_dir_all(dir);
    }
}
