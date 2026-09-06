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
    #[serde(rename = "encrypted")]
    pub is_encrypted: bool,
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
    /// Set when a restore, rather than a backup, wrote this record.
    ///
    /// Cleared by the next backup taken here, deliberately: once this machine is taking its
    /// own archives it is the machine this identity lives on, and a warning that can never be
    /// answered is one people learn to scroll past.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restored: Option<Restored>,
}

/// What a restore knows about where this home came from.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Restored {
    /// Whether the archive said its source retires its own key, which only `move` does.
    /// `None` for an archive written before the manifest carried the answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_retires_key: Option<bool>,
    /// Whether a node was serving on the machine the archive was taken from.
    pub source_node_was_running: bool,
    /// Whether the field above is what the source run saw or what it assumed. A run that
    /// could not reach the control socket writes "running" as a precaution, and a report that
    /// repeats it as a fact tells somebody their key is being double-signed when it may not
    /// be. Absent in a record written before this was carried, which means it was seen.
    #[serde(default)]
    pub source_node_state_was_guessed: bool,
}

/// The path as the next reader will have to resolve it, which is from wherever they are.
///
/// `rad backup --output backups/nightly.tar.zst` is written down as given, and the record is
/// read back by a `doctor` or an `ls` run from somebody's home directory or by a timer with no
/// working directory to speak of: they went looking in the wrong place and reported the archive
/// missing. Falls back to the path as given when the current directory cannot be read, because
/// a relative path is still better than no record at all.
fn absolute_as_far_as_it_goes(path: &Path) -> String {
    std::path::absolute(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .display()
        .to_string()
}

impl Record {
    /// The record a finished archive leaves behind. Everything here is already public: what
    /// went in, when, and where it went. Nothing that would help anyone read it.
    pub fn from_manifest(
        manifest: &crate::manifest::Manifest,
        archive: Option<&Path>,
        node_id: &str,
        is_encrypted: bool,
    ) -> Self {
        Self {
            did: manifest.identity.did.clone(),
            archive: archive.map(absolute_as_far_as_it_goes),
            created: manifest.created.clone(),
            tier: manifest.tier.as_str().to_string(),
            repo_selection: manifest.repo_selection.as_str().to_string(),
            entries: manifest.entries.len(),
            bytes: manifest.total_bytes(),
            is_encrypted,
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
            // A backup records nothing here. Only a restore knows where a home came from, and
            // it sets this after building the record.
            restored: None,
        }
    }

    pub fn carries(&self, rid: &str) -> bool {
        self.carried.contains(rid)
    }

    /// Days between the archive and now, or `None` when the stamp does not parse.
    pub fn age_in_days(&self, now: jiff::Timestamp) -> Option<i64> {
        let created: jiff::Timestamp = self.created.parse().ok()?;
        Some(crate::term::days_between(created, now))
    }
}

/// Where the record for an identity lives, given a state directory. Pure.
pub fn path_in(base: &Path, did: &str) -> PathBuf {
    // The node id is the identity, and it is already filename-safe.
    let node_id = did.strip_prefix("did:key:").unwrap_or(did);
    base.join("rad-backup").join(format!("{node_id}.json"))
}

/// Where the record for an identity lives on this machine.
pub fn path_from_env(did: &str) -> Result<PathBuf> {
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
    Ok(read_at(path_from_env(did)?))
}

/// What the file at `path` says, or why it could not say it. Pure.
///
/// `metadata`, and not `is_file`, because `is_file` answers `false` for a file this process
/// may not stat and for a directory sitting where the file should be, and both then read as
/// `Absent`: `doctor` told the owner of a record it could not open that this tool had no
/// record of one anywhere. Only "not there" is absence, the way `Home::holds_identity` tells
/// the two apart; everything else that stops the file being read is `Unreadable`, which the
/// enum already means and which stops nothing. Revisit if a state file ever needs a run to
/// stop on it.
pub fn read_at(path: PathBuf) -> Stored {
    let unreadable = |reason: String| Stored::Unreadable {
        path: path.clone(),
        reason,
    };
    match std::fs::metadata(&path) {
        Ok(meta) if meta.is_file() => {}
        Ok(_) => return unreadable("there is a directory where the record should be".to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Stored::Absent,
        Err(e) => return unreadable(e.to_string()),
    }
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) => return unreadable(e.to_string()),
    };
    match serde_json::from_str(&text) {
        Ok(record) => Stored::Record(Box::new(record)),
        Err(e) => unreadable(e.to_string()),
    }
}

pub fn write(record: &Record) -> Result<PathBuf> {
    let path = path_from_env(&record.did)?;
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

    /// The one field of a manifest these tests need, spelled out because a `Manifest` has no
    /// `Default` and the rest of it says nothing about where the archive landed.
    fn manifest() -> crate::manifest::Manifest {
        crate::manifest::Manifest {
            format: crate::manifest::FORMAT_VERSION,
            tool: crate::manifest::ToolInfo::default(),
            created: "2026-08-14T00:00:00Z".to_string(),
            tier: crate::manifest::Tier::Identity,
            repo_selection: crate::manifest::RepoSelection::None,
            identity: crate::manifest::IdentityInfo {
                did: "did:key:z6MkTest".to_string(),
                node_id: "z6MkTest".to_string(),
                alias: None,
                public_key: "ssh-ed25519 AAAA".to_string(),
                fingerprint: "SHA256:test".to_string(),
                key_is_encrypted: true,
            },
            source: crate::manifest::SourceInfo {
                host: None,
                rad_home: "/home/tester/.radicle".to_string(),
                rad_version: None,
                git_version: None,
                os: "linux".to_string(),
                retires_key: None,
            },
            node: crate::manifest::NodeInfo::default(),
            entries: Vec::new(),
            repos: Vec::new(),
            policies: crate::manifest::PolicySummary::default(),
            warnings: Vec::new(),
        }
    }

    /// The bug: `--output backups/nightly.tar.zst` was written into the record exactly as
    /// typed, and `doctor` reading it back from another directory reported the archive gone.
    /// Asserted through `from_manifest` rather than on the helper, so that a call site that
    /// stops using the helper fails here rather than passing on the helper's own behaviour.
    #[test]
    fn a_relative_archive_path_is_recorded_the_way_the_next_reader_will_resolve_it() {
        let record = Record::from_manifest(
            &manifest(),
            Some(Path::new("backups/nightly.tar.zst")),
            "z6MkTest",
            true,
        );

        let written = record
            .archive
            .expect("an archive that went to a path is recorded");
        assert!(
            Path::new(&written).is_absolute(),
            "a record read from another directory has to be able to find this: {written}"
        );
        assert!(written.ends_with("backups/nightly.tar.zst"), "{written}");
    }

    #[test]
    fn an_archive_path_that_is_already_absolute_is_recorded_unchanged() {
        let given = "/backups/nightly.tar.zst";
        let record = Record::from_manifest(&manifest(), Some(Path::new(given)), "z6MkTest", true);

        assert_eq!(record.archive.as_deref(), Some(given));
    }

    fn record() -> Record {
        Record {
            did: "did:key:z6MkvAFBkdph6yXSZDkkVqf9FfCcvkG29JD4KbwwnGphDRLV".to_string(),
            archive: Some("/backups/maninak.tar.zst.age".to_string()),
            created: "2026-08-01T12:00:00Z".to_string(),
            tier: "state".to_string(),
            repo_selection: "private".to_string(),
            entries: 9,
            bytes: 22_371,
            is_encrypted: true,
            carried: BTreeSet::from(["rad:zAAA".to_string()]),
            described: BTreeSet::from(["rad:zAAA".to_string(), "rad:zBBB".to_string()]),
            sigrefs: BTreeMap::new(),
            seeded: 45,
            followed: 3,
            restored: None,
        }
    }

    /// The bug: `is_file` answered `false` for a directory sitting where the record should be
    /// and for a record this process may not stat, and both came back as `Absent`. `doctor`
    /// then said "this tool has no record of one anywhere" about a record it could not open.
    #[test]
    fn a_record_that_is_there_and_cannot_be_read_is_not_reported_as_never_written() {
        let dir = std::env::temp_dir().join(format!("rad-backup-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch directory is creatable");

        assert!(
            matches!(read_at(dir.join("never.json")), Stored::Absent),
            "nothing there is the one shape that is absence"
        );

        let squatted = dir.join("squatted.json");
        std::fs::create_dir_all(&squatted).expect("a directory in the file's place is creatable");
        let stored = read_at(squatted.clone());
        assert!(
            matches!(&stored, Stored::Unreadable { path, .. } if *path == squatted),
            "a directory in the file's place is not absence: {stored:?}"
        );
        assert!(
            stored.complaint().is_some(),
            "and it is something the run says out loud"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_record_this_process_may_not_open_is_unreadable_rather_than_absent_or_fatal() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir =
            std::env::temp_dir().join(format!("rad-backup-state-locked-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch directory is creatable");
        let locked = dir.join("locked.json");
        std::fs::write(
            &locked,
            serde_json::to_vec(&record()).expect("a record serialises"),
        )
        .expect("the fixture is writable");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000))
            .expect("mode is settable");
        // Root and anything holding CAP_DAC_OVERRIDE reads straight through mode 000, so there
        // is nothing it could fail to open. Probed here rather than guessed from a user name,
        // because the probe is the condition itself.
        let reads_through_any_mode = std::fs::read(&locked).is_ok();

        let stored = read_at(locked.clone());
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o600))
            .expect("mode is settable back");
        let _ = std::fs::remove_dir_all(&dir);

        if reads_through_any_mode {
            return;
        }
        let Stored::Unreadable { path, reason } = &stored else {
            panic!("a record that cannot be opened is not absence: {stored:?}");
        };
        assert_eq!(*path, locked);
        assert!(reason.contains("denied"), "{reason}");
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
