//! What this tool remembers between runs.
//!
//! One small file per identity, holding no secrets: when the last archive was written, what
//! was in it, and where it went. It is what lets `doctor` say "your newest backup is 40 days
//! old and does not carry your two private repositories" without asking for a passphrase, and
//! what lets `diff` answer without opening an archive at all.
//!
//! It lives under the XDG state directory rather than in the Radicle home, because it is this
//! tool's memory and not part of anyone's identity.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    pub did: String,
    /// Absent when the archive went to stdout, where this tool cannot know where it landed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive: Option<String>,
    pub created: String,
    pub tier: String,
    pub repo_selection: String,
    pub entries: usize,
    pub bytes: u64,
    pub encrypted: bool,
    /// The repositories whose data that archive carried.
    ///
    /// Spelled `repos` on disk, because a state file written by an older version has to keep
    /// answering `carries`. Revisit if a state file ever gains a version field.
    #[serde(default, rename = "repos")]
    pub carried: BTreeSet<String>,
    /// Every repository the archive described, carried or not.
    #[serde(default)]
    pub described: BTreeSet<String>,
    /// This peer's signed refs per repository, as they were. What `diff` compares against.
    #[serde(default)]
    pub sigrefs: BTreeMap<String, String>,
    pub seeded: usize,
    pub followed: usize,
}

impl Record {
    /// The record a finished archive leaves behind. Everything here is already public: what
    /// went in, when, and where it went. Nothing that would help anyone read it.
    pub fn of(
        manifest: &crate::manifest::Manifest,
        archive: Option<&Path>,
        node_id: &str,
        encrypted: bool,
    ) -> Self {
        Self {
            did: manifest.identity.did.clone(),
            archive: archive.map(|path| path.display().to_string()),
            created: manifest.created.clone(),
            tier: manifest.tier.as_str().to_string(),
            repo_selection: manifest.repo_selection.as_str().to_string(),
            entries: manifest.entries.len(),
            bytes: manifest.total_bytes(),
            encrypted,
            carried: manifest
                .repos
                .iter()
                .filter(|repo| repo.bundle.is_some())
                .map(|repo| repo.rid.clone())
                .collect(),
            described: manifest.repos.iter().map(|repo| repo.rid.clone()).collect(),
            sigrefs: manifest
                .repos
                .iter()
                .filter_map(|repo| {
                    let oid = repo.sigrefs.get(node_id)?;
                    Some((repo.rid.clone(), oid.clone()))
                })
                .collect(),
            seeded: manifest.policies.seeded,
            followed: manifest.policies.followed,
        }
    }

    pub fn carries(&self, rid: &str) -> bool {
        self.carried.contains(rid)
    }

    /// Days between the archive and now, or `None` when the stamp does not parse.
    pub fn age_in_days(&self, now: jiff::Timestamp) -> Option<i64> {
        let created: jiff::Timestamp = self.created.parse().ok()?;
        Some(
            now.duration_since(created)
                .as_secs()
                .div_euclid(60 * 60 * 24),
        )
    }
}

/// Where the record for an identity lives, given a state directory. Pure.
pub fn path_in(base: &Path, did: &str) -> PathBuf {
    // The node id is the identity, and it is already filename-safe.
    let node_id = did.strip_prefix("did:key:").unwrap_or(did);
    base.join("rad-backup").join(format!("{node_id}.json"))
}

/// Where the record for an identity lives on this machine.
pub fn path_for(did: &str) -> Result<PathBuf> {
    let base = match std::env::var_os("XDG_STATE_HOME") {
        Some(dir) => PathBuf::from(dir),
        None => {
            let home = std::env::var_os("HOME").ok_or_else(|| {
                Error::refused(
                    "cannot tell where to keep this tool's state",
                    "set XDG_STATE_HOME or HOME",
                )
            })?;
            PathBuf::from(home).join(".local").join("state")
        }
    };
    Ok(path_in(&base, did))
}

/// What this tool remembers about an identity.
///
/// A state file that has gone bad is worth nothing and must not stop a run, but it is not the
/// same answer as never having taken a backup, and reporting it as one would tell somebody
/// their archive does not exist when it may be sitting right where they left it.
#[derive(Debug)]
pub enum Stored {
    Absent,
    Unreadable { path: PathBuf, reason: String },
    Record(Box<Record>),
}

impl Stored {
    /// The record, when there is one fit to answer with.
    pub fn record(&self) -> Option<&Record> {
        match self {
            Self::Record(record) => Some(record),
            Self::Absent | Self::Unreadable { .. } => None,
        }
    }

    /// What went wrong reading it, for a caller that should say so out loud.
    pub fn complaint(&self) -> Option<String> {
        match self {
            Self::Unreadable { path, reason } => Some(format!(
                "{} could not be read ({reason}), so this run cannot tell what the last \
                 archive held; the next backup rewrites it",
                path.display()
            )),
            Self::Absent | Self::Record(_) => None,
        }
    }
}

pub fn read(did: &str) -> Result<Stored> {
    let path = path_for(did)?;
    if !path.is_file() {
        return Ok(Stored::Absent);
    }
    let text = std::fs::read_to_string(&path).map_err(|e| Error::io(&path, e))?;
    match serde_json::from_str(&text) {
        Ok(record) => Ok(Stored::Record(Box::new(record))),
        Err(e) => Ok(Stored::Unreadable {
            path,
            reason: e.to_string(),
        }),
    }
}

pub fn write(record: &Record) -> Result<PathBuf> {
    let path = path_for(&record.did)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
    }
    let json = serde_json::to_vec_pretty(record)?;
    // Owner-only: no key material in here, but it does name every repository this identity
    // holds, private ones included, and where the archives of them are kept.
    crate::perms::write_owner_only(&path, &json)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> Record {
        Record {
            did: "did:key:z6MkvAFBkdph6yXSZDkkVqf9FfCcvkG29JD4KbwwnGphDRLV".to_string(),
            archive: Some("/backups/maninak.tar.zst.age".to_string()),
            created: "2026-08-01T12:00:00Z".to_string(),
            tier: "state".to_string(),
            repo_selection: "private".to_string(),
            entries: 9,
            bytes: 22_371,
            encrypted: true,
            carried: BTreeSet::from(["rad:zAAA".to_string()]),
            described: BTreeSet::from(["rad:zAAA".to_string(), "rad:zBBB".to_string()]),
            sigrefs: BTreeMap::new(),
            seeded: 45,
            followed: 3,
        }
    }

    #[test]
    fn the_state_file_is_named_after_the_identity_it_describes() {
        assert_eq!(
            path_in(Path::new("/var/state"), "did:key:z6MkAAA"),
            PathBuf::from("/var/state/rad-backup/z6MkAAA.json")
        );
        // A bare node id names the same file as the full DID, so a caller cannot split the
        // record in two by spelling the identity differently.
        assert_eq!(
            path_in(Path::new("/var/state"), "z6MkAAA"),
            path_in(Path::new("/var/state"), "did:key:z6MkAAA")
        );
    }

    #[test]
    fn an_archive_knows_which_repositories_it_carried_and_which_it_only_listed() {
        let record = record();
        assert!(record.carries("rad:zAAA"));
        assert!(!record.carries("rad:zBBB"));
        assert!(record.described.contains("rad:zBBB"));
    }

    #[test]
    fn a_state_file_written_before_the_field_was_renamed_still_says_what_it_carried() {
        // The field is `carried` in Rust and `repos` on disk. A state file already sitting in
        // `~/.local/state` spells it the old way, and `doctor` reads that file to say whether
        // the last archive covers a repository. Renaming the key would make every one of them
        // read as an archive that carried nothing.
        let written = serde_json::to_value(record()).expect("a record serialises");
        assert!(written.get("repos").is_some(), "{written}");
        assert!(written.get("carried").is_none(), "{written}");

        let read: Record = serde_json::from_value(written).expect("a record round-trips");
        assert!(read.carries("rad:zAAA"));
    }

    #[test]
    fn age_is_counted_in_whole_days_from_the_recorded_stamp() {
        let record = record();
        let now: jiff::Timestamp = "2026-08-14T12:00:00Z".parse().expect("a valid instant");
        assert_eq!(record.age_in_days(now), Some(13));
    }

    #[test]
    fn an_unparseable_stamp_is_no_age_rather_than_a_wrong_one() {
        let mut record = record();
        record.created = "last tuesday".to_string();
        let now: jiff::Timestamp = "2026-08-14T12:00:00Z".parse().expect("a valid instant");
        assert_eq!(record.age_in_days(now), None);
    }
}
