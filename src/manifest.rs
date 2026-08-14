//! The archive manifest: what an archive says about itself.
//!
//! This is a wire format. It is read by builds of this tool that did not write it, so it
//! parses tolerantly: unknown fields are ignored, unknown enum values fall back to a variant
//! that says so instead of failing the whole read. Fields are camelCase to match the JSON
//! Radicle itself emits.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The archive layout this build writes. Bumped only when a reader that does not know the
/// change would misread an archive.
pub const FORMAT_VERSION: u32 = 1;

/// Entry name of the manifest inside the archive.
pub const MANIFEST_ENTRY: &str = "manifest.json";
/// Entry name of the plain-language restore instructions inside the archive.
pub const RESTORE_DOC_ENTRY: &str = "RESTORE.md";
/// Entry name of the standalone restore script inside the archive.
pub const RESTORE_SCRIPT_ENTRY: &str = "restore.sh";

/// How much of a home an archive holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// The 524 bytes nothing can give back, plus the config that names them.
    Identity,
    /// Identity, plus the policies, aliases and inventory a person cannot retype.
    State,
    /// Everything above, plus repositories.
    Full,
    /// Written by a newer build than this one.
    #[serde(other)]
    Unknown,
}

impl Tier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::State => "state",
            Self::Full => "full",
            Self::Unknown => "unknown",
        }
    }
}

/// Which repositories an archive was told to carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RepoSelection {
    /// No repositories at all.
    None,
    /// Only the repositories the open network does not carry: the private ones.
    Private,
    /// Private repositories, the ones you delegate, and any whose namespace holds your refs.
    Mine,
    /// Everything the seeding policy allows.
    Seeded,
    /// Every repository in storage.
    All,
    #[serde(other)]
    Unknown,
}

impl RepoSelection {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Private => "private",
            Self::Mine => "mine",
            Self::Seeded => "seeded",
            Self::All => "all",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub format: u32,
    pub tool: ToolInfo,
    /// RFC 3339, always UTC.
    pub created: String,
    pub tier: Tier,
    pub repo_selection: RepoSelection,
    pub identity: IdentityInfo,
    pub source: SourceInfo,
    pub node: NodeInfo,
    /// Sorted by path, so an unchanged home produces an identical manifest.
    pub entries: Vec<Entry>,
    #[serde(default)]
    pub repos: Vec<RepoRecord>,
    #[serde(default)]
    pub policies: PolicySummary,
    /// Things the user should know that did not stop the run: a skipped repository, a
    /// database that had to be opened writable, a node that was running.
    #[serde(default)]
    pub warnings: Vec<String>,
}

impl Manifest {
    pub fn total_bytes(&self) -> u64 {
        self.entries.iter().map(|entry| entry.bytes).sum()
    }

    pub fn entry(&self, path: &str) -> Option<&Entry> {
        self.entries.iter().find(|entry| entry.path == path)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
}

impl Default for ToolInfo {
    fn default() -> Self {
        Self {
            // The binary, not CARGO_PKG_NAME: this string is a documented field of the
            // archive format, and deriving it from the package would let a crate rename
            // silently rewrite what every future archive claims wrote it.
            name: env!("CARGO_BIN_NAME").to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentityInfo {
    pub did: String,
    pub node_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    /// The public key in OpenSSH form, so a restore can prove the secret key it wrote is the
    /// one this archive claims to hold.
    pub public_key: String,
    pub fingerprint: String,
    /// Whether the archived secret key carries its own passphrase.
    pub key_encrypted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    pub rad_home: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rad_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_version: Option<String>,
    pub os: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeInfo {
    /// Whether the node was serving its control socket when the archive was taken.
    pub was_running: bool,
    /// Whether this run stopped it, which is the only case where a restart is owed.
    pub stopped_by_backup: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub path: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicySummary {
    pub seeded: usize,
    pub blocked_repos: usize,
    pub followed: usize,
    pub blocked_peers: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RepoRecord {
    pub rid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// `public` or `private`. Absent when no `rad` was available to ask.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
    /// The peers a private repository is shared with, from its identity document. Empty for a
    /// public repository, and empty for a private one that was never allowed to anybody: a
    /// private repository is not automatically alone in the world, it is alone until its owner
    /// says otherwise.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed: Vec<String>,
    /// Whether the archived identity is one of this repository's delegates. A sole delegate
    /// who loses this key loses the repository's governance for good.
    pub delegate: bool,
    #[serde(default)]
    pub delegates: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    /// What `HEAD` pointed at, which a bundle does not carry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
    pub refs: usize,
    /// Signed refs per peer at the moment of the backup. Restore compares these with the
    /// network to decide whether building on the restored copy would fork the identity.
    #[serde(default)]
    pub sigrefs: BTreeMap<String, String>,
    /// How many other nodes the routing table said announce this repository.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub other_seeds: Option<u64>,
    /// Absent when the repository was recorded but not archived, which is how a state-tier
    /// archive keeps an inventory without the data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle: Option<Entry>,
}

impl RepoRecord {
    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or(&self.rid)
    }

    pub fn is_private(&self) -> bool {
        matches!(self.visibility.as_deref(), Some("private"))
    }

    /// Whether anything but this machine could hand this repository back: another node has
    /// announced it, or its owner allowed a peer to hold it.
    pub fn has_another_holder(&self) -> bool {
        self.other_seeds.is_some_and(|seeds| seeds > 0) || !self.allowed.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_manifest_names_the_command_that_wrote_it_and_not_the_crate_it_was_built_from() {
        // ARCHIVE-FORMAT.md publishes this exact string, and readers of an archive match on
        // it. Renaming the package to `radicle-backup` once changed it silently, which is why
        // it is spelled out here rather than derived: this assertion is the format, and it
        // must fail if the value ever moves again.
        assert_eq!(ToolInfo::default().name, "rad-backup");
    }

    #[test]
    fn an_unknown_tier_reads_as_unknown_instead_of_failing_the_whole_manifest() {
        let json = r#"{"tier":"quantum"}"#;
        #[derive(Deserialize)]
        struct Holder {
            tier: Tier,
        }
        let holder: Holder = serde_json::from_str(json).expect("unknown values are tolerated");
        assert_eq!(holder.tier, Tier::Unknown);
    }

    #[test]
    fn fields_a_newer_writer_added_do_not_break_an_older_reader() {
        let json = r#"{"rid":"rad:zAAA","delegate":false,"refs":3,"somethingNew":42}"#;
        let record: RepoRecord = serde_json::from_str(json).expect("unknown fields are ignored");
        assert_eq!(record.rid, "rad:zAAA");
        assert_eq!(record.refs, 3);
        assert!(record.bundle.is_none());
    }

    #[test]
    fn a_private_repository_allowed_to_a_peer_still_has_somewhere_else_to_come_from() {
        let mut record = RepoRecord {
            rid: "rad:zAAA".to_string(),
            name: None,
            visibility: Some("private".to_string()),
            allowed: Vec::new(),
            delegate: true,
            delegates: Vec::new(),
            scope: None,
            policy: None,
            head: None,
            refs: 0,
            sigrefs: BTreeMap::new(),
            other_seeds: None,
            bundle: None,
        };
        assert!(record.is_private());
        assert!(
            !record.has_another_holder(),
            "a private repository allowed to nobody is on this disk alone"
        );

        record.allowed = vec!["did:key:z6MkjDYUKMUeY58Vtr8dGJrHRvnTfjKWVGCBYJDVTHXsXzm5".into()];
        assert!(
            record.has_another_holder(),
            "a private repository allowed to a seed can be fetched back from it"
        );
    }
}
