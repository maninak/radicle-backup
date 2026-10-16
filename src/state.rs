//! The per-identity record of the last archive, kept under the XDG state directory.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// What the last archive of an identity held and where it went, readable without a passphrase.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    pub did: String,
    /// `None` when the archive went to stdout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive: Option<String>,
    pub created: String,
    pub tier: String,
    pub repo_selection: String,
    pub entries: usize,
    pub bytes: u64,
    #[serde(rename = "encrypted")]
    pub is_encrypted: bool,
    /// The repositories whose data the archive carried.
    ///
    /// The field is `repos` on disk, so a state file written by an older version still
    /// answers `carries`. Revisit if a state file ever gains a version field.
    #[serde(default, rename = "repos")]
    pub carried: BTreeSet<String>,
    /// Every repository the archive described, carried or not.
    #[serde(default)]
    pub described: BTreeSet<String>,
    /// This peer's signed refs per repository at archive time, for `diff` to compare against.
    #[serde(default)]
    pub sigrefs: BTreeMap<String, String>,
    /// The policy counts. These stay beside `policies`, because an older version fails to
    /// read a file without them. Revisit if a state file ever gains a version field.
    pub seeded: usize,
    pub followed: usize,
    /// The ids the home seeded, followed and blocked, for `diff` to compare against.
    ///
    /// Equal counts hide a swap of one repository for another. A record from an older version
    /// holds `None` here and only the counts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policies: Option<PolicySets>,
    /// Where the home came from, set when a restore wrote this record.
    ///
    /// The next backup taken here clears it, because a machine taking its own archives is
    /// where the identity now lives, and a warning that never clears gets ignored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restored: Option<Restored>,
}

/// The policies of a home as sets of ids.
///
/// Blocks are included, because a block added after an archive is lost on restore, and the
/// node then fetches from that peer again.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicySets {
    #[serde(default)]
    pub seeded: BTreeSet<String>,
    #[serde(default)]
    pub followed: BTreeSet<String>,
    #[serde(default)]
    pub blocked_repos: BTreeSet<String>,
    #[serde(default)]
    pub blocked_peers: BTreeSet<String>,
}

impl PolicySets {
    pub fn of(policies: &crate::db::Policies) -> Self {
        Self {
            seeded: policies.seeded().map(|p| p.rid.clone()).collect(),
            followed: policies.followed().map(|p| p.nid.clone()).collect(),
            blocked_repos: policies.blocked_repos().map(|p| p.rid.clone()).collect(),
            blocked_peers: policies.blocked_peers().map(|p| p.nid.clone()).collect(),
        }
    }
}

/// What a restore knows about where this home came from.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Restored {
    /// Whether the archive's source retires its own key, as `move` does.
    ///
    /// `None` for an archive written before the manifest carried the answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_retires_key: Option<bool>,
    /// Whether a node was serving on the machine the archive was taken from.
    pub source_node_was_running: bool,
    /// Whether `source_node_was_running` was assumed, not seen.
    ///
    /// A source run that cannot reach the control socket writes "running" as a precaution,
    /// and a report must not repeat that as a fact. A missing field means it was seen.
    #[serde(default)]
    pub source_node_state_was_guessed: bool,
}

/// Makes `path` absolute, so a reader in another working directory finds the same file.
///
/// Falls back to `path` as given when the current directory cannot be read.
fn absolute_as_far_as_it_goes(path: &Path) -> String {
    std::path::absolute(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .display()
        .to_string()
}

impl Record {
    /// Builds the record a finished archive leaves behind, holding nothing that helps read it.
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
            // The manifest carries only counts, so each writer fills this from its own read
            policies: None,
            // A restore sets this after building the record
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

/// The path of the record for `did` under the state directory `base`.
pub fn path_in(base: &Path, did: &str) -> PathBuf {
    // The node id is filename-safe, and a bare one names the same file as the full DID
    let node_id = did.strip_prefix("did:key:").unwrap_or(did);
    base.join("rad-backup").join(format!("{node_id}.json"))
}

/// The path of the record for `did` under `XDG_STATE_HOME`, or `~/.local/state`.
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

/// The stored record of an identity, if any.
///
/// A broken state file must not stop a run. `Unreadable` keeps it apart from `Absent`, so a
/// report never says an archive does not exist when its record merely failed to read.
#[derive(Debug)]
pub enum Stored {
    Absent,
    Unreadable { path: PathBuf, reason: String },
    Record(Box<Record>),
}

impl Stored {
    /// The record, when one was read.
    pub fn record(&self) -> Option<&Record> {
        match self {
            Self::Record(record) => Some(record),
            Self::Absent | Self::Unreadable { .. } => None,
        }
    }

    /// The message to show the user when the record could not be read.
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

/// Reads the record at `path`.
///
/// Only a missing file is `Absent`. A directory in its place, a file this process may not
/// stat, and a file that fails to parse are all `Unreadable`.
pub fn read_at(path: PathBuf) -> Stored {
    let unreadable = |reason: String| Stored::Unreadable {
        path: path.clone(),
        reason,
    };
    // `metadata` and not `is_file`, because `is_file` answers `false` for an unreadable file
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
        // `create_dir_all` takes the umask, and this directory's file names are the DIDs of
        // every identity this machine keeps a record for
        crate::perms::set_dir_owner_only(parent)?;
    }
    let json = serde_json::to_vec_pretty(record)?;
    // The record names every repository the identity holds, private ones included
    crate::perms::write_owner_only(&path, &json)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal manifest, spelled out because `Manifest` has no `Default`.
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

    /// Asserted through `from_manifest`, so a call site that stops making the path absolute
    /// fails here.
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
        assert!(
            Path::new(&written).ends_with("backups/nightly.tar.zst"),
            "{written}"
        );
    }

    #[test]
    fn an_archive_path_that_is_already_absolute_is_recorded_unchanged() {
        // The path is built from `temp_dir`, because `/backups` is relative on Windows
        let given = std::env::temp_dir().join("backups").join("nightly.tar.zst");
        let record = Record::from_manifest(&manifest(), Some(&given), "z6MkTest", true);

        assert_eq!(record.archive, Some(given.display().to_string()));
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
            policies: None,
            restored: None,
        }
    }

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
        // Root and anything holding CAP_DAC_OVERRIDE reads through mode 000, so the test
        // probes for that and has nothing to check when it holds
        let reads_through_any_mode = std::fs::read(&locked).is_ok();

        let stored = read_at(locked.clone());
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o600))
            .expect("mode is settable back");
        let _ = std::fs::remove_dir_all(&dir);

        if reads_through_any_mode {
            crate::perms::tests::skip_as_privileged_from_env("an unreadable state record");
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
        // A bare node id and the full DID name the same file, so the record never splits
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
        // Renaming the `repos` key makes every existing state file read as an archive that
        // carried nothing
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
