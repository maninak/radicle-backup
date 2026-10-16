//! The archive manifest, a wire format read by builds of this tool that did not write it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The archive layout this build writes. Bump this number only when a reader that does not
/// know the change would misread an archive.
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
    /// The secret key and its public half, which nothing can give back, plus the config that
    /// names them.
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
    /// Only the private repositories, which the open network does not carry.
    Private,
    /// Private repositories, the ones the user delegates, and any whose namespace holds the
    /// user's refs.
    Mine,
    /// Everything the seeding policy allows.
    Seeded,
    /// Every repository in storage.
    All,
    /// Written by a newer build than this one.
    #[serde(other)]
    Unknown,
}

impl RepoSelection {
    /// Reads back what `as_str` wrote. An unrecognised word is `Unknown`, so a file written by
    /// a later version is read for what can be read.
    pub fn from_word(word: &str) -> Self {
        match word {
            "none" => Self::None,
            "private" => Self::Private,
            "mine" => Self::Mine,
            "seeded" => Self::Seeded,
            "all" => Self::All,
            _ => Self::Unknown,
        }
    }

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
    /// Things the user should know that did not stop the run, such as a skipped repository.
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
            // Never derive this from CARGO_PKG_NAME, because the string is a documented
            // archive field and a crate rename would silently rewrite it
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
    ///
    /// The wire name stays `keyEncrypted`, because every other build would read a renamed
    /// field as `false` for every key that has a passphrase.
    #[serde(rename = "keyEncrypted")]
    pub key_is_encrypted: bool,
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
    /// Whether the machine that wrote this archive retires its own key as part of the run,
    /// which `move` does. `None` in an archive older than this field.
    ///
    /// When false, the restored home may not be the only holder of the identity, and two
    /// nodes signing under one peer id fork that peer's history.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retires_key: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeInfo {
    /// Whether the node was serving its control socket when the archive was taken. A run that
    /// could not reach the socket writes `true`, because a node assumed up costs a warning and
    /// a node assumed down costs an identity.
    pub was_running: bool,
    /// The error the control socket gave when `was_running` is a precaution. Absent when the
    /// socket answered.
    ///
    /// `was_running` must stay a plain `bool`, because older builds cannot parse a manifest
    /// that omits it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why_running_is_unknown: Option<String>,
    /// Whether this run stopped the node, which means a restart is owed.
    #[serde(rename = "stoppedByBackup")]
    pub was_stopped_by_backup: bool,
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
    /// public repository and for a private one allowed to nobody.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed: Vec<String>,
    /// Whether the archived identity is one of this repository's delegates. A sole delegate
    /// who loses this key loses the repository's governance for good.
    #[serde(rename = "delegate")]
    pub is_delegate: bool,
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
    /// Signed refs per peer at the moment of the backup. Restore compares the archived
    /// identity's own entry with what other nodes announced, to tell whether building on the
    /// restored copy would fork the identity.
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

    /// Whether this repository is one Radicle announces.
    ///
    /// Never replace this with `!is_private()`, because a record whose identity document was
    /// never read would then count as public, and public counts end in `rad sync --announce`.
    pub fn is_public(&self) -> bool {
        matches!(self.visibility.as_deref(), Some("public"))
    }

    /// Whether this repository's identity document was read.
    ///
    /// `visibility`, `delegates` and `allowed` all come from that document, so an unread
    /// record's empty delegate list means nothing was asked. A report that misses this calls
    /// a home it never looked inside free of private repositories.
    pub fn identity_was_read(&self) -> bool {
        self.visibility.is_some()
    }

    /// Whether anything but this machine could hand this repository back, because another
    /// node announced it, its owner allowed a peer to hold it, or somebody else delegates it.
    ///
    /// A second delegate holds the repository by definition.
    pub fn has_another_holder(&self) -> bool {
        self.other_seeds.is_some_and(|seeds| seeds > 0)
            || !self.allowed.is_empty()
            || self.delegates.len() > 1
    }

    /// Whether a fetch has nobody to ask about this repository, which holds only for a private
    /// repository delegated to the archived identity alone and allowed to nobody.
    ///
    /// `rad sync --fetch` reaches a private repository through its delegates and allowed
    /// peers. An empty delegate list means nothing was read and answers false, because a
    /// needless fetch costs seconds and a skipped comparison costs a peer history.
    pub fn has_nowhere_to_fetch_from(&self) -> bool {
        self.is_private()
            && self.allowed.is_empty()
            && self.delegates.len() == 1
            && self.is_delegate
    }
}

#[cfg(test)]
mod tests {
    /// The sample in `ARCHIVE-FORMAT.md` is the spec a stranger reads to open an archive by
    /// hand, so it must keep parsing as a `Manifest`.
    #[test]
    fn the_sample_manifest_in_the_format_document_still_parses() {
        let document = include_str!("../ARCHIVE-FORMAT.md");
        let sample = document
            .split("```json")
            .nth(1)
            .and_then(|rest| rest.split("```").next())
            .expect("the format document shows a manifest");

        let manifest: super::Manifest =
            serde_json::from_str(sample).expect("the sample parses as a manifest");

        // Reading fields back stops a manifest that parsed into all-defaults from passing
        assert_eq!(manifest.tool.name, "rad-backup");
        assert_eq!(manifest.identity.alias.as_deref(), Some("alice"));
        assert_eq!(manifest.entries.len(), 1);
        assert_eq!(manifest.repos.len(), 1);
        assert_eq!(manifest.repos[0].name.as_deref(), Some("notes"));
    }

    use super::*;

    #[test]
    fn the_manifest_names_the_command_that_wrote_it_and_not_the_crate_it_was_built_from() {
        // ARCHIVE-FORMAT.md publishes this exact string and archive readers match on it. The
        // value is spelled out, so a crate rename fails here.
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
            is_delegate: true,
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

        record.allowed = vec![SOMEBODY_ELSE.to_string()];
        assert!(
            record.has_another_holder(),
            "a private repository allowed to a seed can be fetched back from it"
        );

        record.allowed = Vec::new();
        record.delegates = vec![ONLY_US.to_string(), SOMEBODY_ELSE.to_string()];
        assert!(
            record.has_another_holder(),
            "a second delegate holds the repository by definition, so it is not lost with this \
             disk"
        );

        record.delegates = vec![ONLY_US.to_string()];
        assert!(
            !record.has_another_holder(),
            "being the only delegate is what having nobody else looks like"
        );
    }

    /// The check `restore` uses to skip the sigrefs comparison. Skipping it for a repository
    /// somebody else holds forks the restored peer history, so each way a repository stays
    /// reachable is asserted on its own.
    #[test]
    fn only_a_private_repository_delegated_to_us_alone_has_nobody_to_ask() {
        let mut record = RepoRecord {
            rid: "rad:zAAA".to_string(),
            name: None,
            visibility: Some("private".to_string()),
            allowed: Vec::new(),
            is_delegate: true,
            delegates: vec![ONLY_US.to_string()],
            scope: None,
            policy: None,
            head: None,
            refs: 0,
            sigrefs: BTreeMap::new(),
            other_seeds: None,
            bundle: None,
        };
        assert!(record.has_nowhere_to_fetch_from());

        record.allowed = vec![SOMEBODY_ELSE.to_string()];
        assert!(
            !record.has_nowhere_to_fetch_from(),
            "a private repository allowed to a peer is fetched from that peer"
        );

        record.allowed = Vec::new();
        record.delegates.push(SOMEBODY_ELSE.to_string());
        assert!(
            !record.has_nowhere_to_fetch_from(),
            "a private repository with a second delegate is fetched from that delegate"
        );

        record.delegates = Vec::new();
        assert!(
            !record.has_nowhere_to_fetch_from(),
            "an archive too old to name the delegates says nothing about who holds it"
        );

        record.delegates = vec![ONLY_US.to_string()];
        record.visibility = Some("public".to_string());
        assert!(!record.has_nowhere_to_fetch_from());

        record.visibility = None;
        assert!(
            !record.has_nowhere_to_fetch_from(),
            "a repository nothing could ask about is not a repository nobody holds"
        );

        record.visibility = Some("private".to_string());
        record.delegates = vec![SOMEBODY_ELSE.to_string()];
        record.is_delegate = false;
        assert!(
            !record.has_nowhere_to_fetch_from(),
            "a repository whose one delegate is somebody else has that somebody to ask"
        );
    }

    /// Every check that counts public repositories ends its remedy in `rad sync --announce`,
    /// so a record whose identity document was never read counts as neither public nor
    /// private.
    #[test]
    fn a_repository_nothing_could_describe_is_neither_public_nor_private() {
        let mut record = RepoRecord {
            rid: "rad:zAAA".to_string(),
            name: None,
            visibility: None,
            allowed: Vec::new(),
            is_delegate: true,
            delegates: Vec::new(),
            scope: None,
            policy: None,
            head: None,
            refs: 0,
            sigrefs: BTreeMap::new(),
            other_seeds: None,
            bundle: None,
        };
        assert!(!record.is_private());
        assert!(!record.is_public());
        assert!(!record.identity_was_read());

        record.visibility = Some("public".to_string());
        assert!(record.is_public());
        record.visibility = Some("private".to_string());
        assert!(!record.is_public());
        // A visibility a later heartwood adds is not one this build may guess at either way
        record.visibility = Some("unlisted".to_string());
        assert!(!record.is_public());
        assert!(!record.is_private());
    }

    const ONLY_US: &str = "did:key:z6MkkfM3tPXNPrPevKr3uSiQtHPuwnNhu2yUVjgd2jXVsVz5";
    const SOMEBODY_ELSE: &str = "did:key:z6MkjDYUKMUeY58Vtr8dGJrHRvnTfjKWVGCBYJDVTHXsXzm5";
}
