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
    /// Only the repositories the open network does not carry: the private ones.
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
    /// Read back what `as_str` wrote, for the records and manifests that store the selection
    /// as a word. Anything unrecognised is `Unknown` rather than an error, on the same
    /// principle as the `#[serde(other)]` above: a file written by a later version is read for
    /// what can be read.
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
    /// Things the user should know that did not stop the run: a skipped repository, a
    /// database whose reading left an `-shm` index beside it, a node that was running.
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
    ///
    /// The wire name stays `keyEncrypted`: an archive is read by versions that were never
    /// built, and a field this one renamed would come back as `false` for every key that has
    /// a passphrase.
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
    /// which only `move` does.
    ///
    /// A home restored from an archive where this is false may not be the only one holding the
    /// identity, and two nodes signing under one peer id fork that peer's history. `None` in
    /// an archive written before this field existed, which is the case nothing here can
    /// resolve either way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retires_key: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeInfo {
    /// Whether the node was serving its control socket when the archive was taken. A run that
    /// could not reach the socket at all writes `true` here, because a node assumed up costs
    /// a warning and a node assumed down costs an identity; `why_running_is_unknown` beside it
    /// is how the far end tells the precaution from the observation.
    pub was_running: bool,
    /// Why the field above is a precaution rather than something this run saw: the error the
    /// control socket gave. Absent when the socket answered, which is the ordinary case.
    ///
    /// Added rather than making `was_running` an `Option`, because a manifest that omits a
    /// field an older build reads as a plain `bool` is a manifest that build cannot parse at
    /// all, and an archive has to stay readable by the versions already installed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub why_running_is_unknown: Option<String>,
    /// Whether this run stopped it, which is the only case where a restart is owed.
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
    /// public repository, and empty for a private one that was never allowed to anybody: a
    /// private repository is not automatically alone in the world, it is alone until its owner
    /// says otherwise.
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
    /// Signed refs per peer at the moment of the backup. Restore takes our own entry and
    /// holds it against the node's record of what other nodes announced, to decide whether
    /// building on the restored copy would fork the identity.
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
    /// Not `!is_private()`, because a record whose identity document was never read has no
    /// visibility at all and would pass that test. The checks that count public repositories
    /// end in `rad sync --announce`, and announcing one that turns out to be private is the
    /// single mistake they must never make, so an unread document is left out of the count and
    /// the caller says how many it could not describe.
    pub fn is_public(&self) -> bool {
        matches!(self.visibility.as_deref(), Some("public"))
    }

    /// Whether this repository's identity document was actually read.
    ///
    /// `visibility`, `delegates` and `allowed` all come out of that one document, so a record
    /// without a visibility has none of them: its delegate list is empty because nothing was
    /// asked, not because there is nobody. Anything reporting on those fields has to tell an
    /// unasked question from a negative answer, or it says "there are no private repositories"
    /// about a home it never looked inside.
    pub fn identity_was_read(&self) -> bool {
        self.visibility.is_some()
    }

    /// Whether anything but this machine could hand this repository back: another node has
    /// announced it, its owner allowed a peer to hold it, or somebody else delegates it.
    ///
    /// A second delegate holds the repository by definition, and leaving them out told the
    /// owner of a jointly delegated private repository that it was "in no archive and on no
    /// other node", which is a Fail over a copy that is sitting on the other delegate's disk.
    /// The same fact `has_nowhere_to_fetch_from` counts on, said about a different question.
    pub fn has_another_holder(&self) -> bool {
        self.other_seeds.is_some_and(|seeds| seeds > 0)
            || !self.allowed.is_empty()
            || self.delegates.len() > 1
    }

    /// Whether a fetch has anybody at all to ask about this repository.
    ///
    /// "Private" is about announcement, not about reachability: `rad sync --fetch` has a
    /// separate path for a private repository that goes to its delegates and its allowed
    /// peers. So only one delegated to us alone and allowed to nobody has no network side,
    /// and a private repository shared with a collaborator is exactly the one that can fork.
    ///
    /// A delegate list that is empty means nothing was read, not that there is nobody, so
    /// that case falls through to the fetch: an unnecessary fetch costs a few seconds, and a
    /// skipped comparison costs a peer history. The sole delegate has to be us for the same
    /// reason: a repository delegated to one person who is somebody else has that person to
    /// ask.
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
    /// hand. Nothing checked that it still parses as a `Manifest`, so a renamed field would
    /// have left the document describing a format this tool no longer writes.
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

        // Read back, so a manifest that parsed into all-defaults cannot pass for one that
        // matched.
        assert_eq!(manifest.tool.name, "rad-backup");
        assert_eq!(manifest.identity.alias.as_deref(), Some("alice"));
        assert_eq!(manifest.entries.len(), 1);
        assert_eq!(manifest.repos.len(), 1);
        assert_eq!(manifest.repos[0].name.as_deref(), Some("notes"));
    }

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

    /// The gate `restore` uses to skip the sigrefs comparison. Skipping it for a repository
    /// somebody else holds is how a restored copy forks its own peer history, so each way a
    /// repository stays reachable is spelled out here rather than left to the one boolean.
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
    /// and a record whose identity document was never read has no visibility at all. Told
    /// apart by `!is_private()`, such a record joined the public list, so a home with no `rad`
    /// on PATH was told to announce repositories that may well be private.
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
        // A visibility a later heartwood adds is not one this build may guess at either way.
        record.visibility = Some("unlisted".to_string());
        assert!(!record.is_public());
        assert!(!record.is_private());
    }

    const ONLY_US: &str = "did:key:z6MkkfM3tPXNPrPevKr3uSiQtHPuwnNhu2yUVjgd2jXVsVz5";
    const SOMEBODY_ELSE: &str = "did:key:z6MkjDYUKMUeY58Vtr8dGJrHRvnTfjKWVGCBYJDVTHXsXzm5";
}
