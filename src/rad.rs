//! The `rad` commands this tool runs, reading tables only for their `rad:z` identifiers.

use std::path::Path;

use crate::error::Result;
use crate::exec::Tool;

/// Whether a string may be handed to `rad` or `git` as an identifier, which is base58 with
/// an optional `rad:` prefix.
///
/// Ids arrive from an unvouched archive, and a value beginning with `-` in an argv position
/// reads as a flag.
pub fn is_identifier(value: &str) -> bool {
    let bare = value.strip_prefix("rad:").unwrap_or(value);
    !bare.is_empty() && bare.chars().all(|c| c.is_ascii_alphanumeric())
}

/// What `rad` was able to say about one repository.
///
/// A failed call keeps its reason, because a repository whose visibility could not be read
/// looks public and the private selection would silently leave it out of the archive.
pub enum Described {
    Identity(RepoIdentity),
    Unavailable { why: String },
}

/// What `rad ls` was able to answer, keeping a failed listing apart from an empty one
pub enum Listed {
    Ids(Vec<String>),
    Unavailable { why: String },
}

/// Which repositories to ask `rad ls` about.
#[derive(Debug, Clone, Copy)]
pub enum Listing {
    /// Repositories this identity initialised or forked
    Own,
    /// Repositories marked private, which only the peers their identity document allows can
    /// fetch
    Private,
}

impl Listing {
    /// The command as it would be typed, for a message about the one that failed.
    pub fn spelling(self) -> &'static str {
        match self {
            Self::Own => "ls",
            Self::Private => "ls --private",
        }
    }
}

pub struct Rad {
    tool: Tool,
}

impl Rad {
    pub fn new(home: &Path) -> Self {
        Self {
            tool: Tool::rad(home),
        }
    }

    pub fn is_available(&self) -> bool {
        self.tool.is_available()
    }

    /// The version string `rad --version` prints, recorded in the manifest so a later restore
    /// knows which Radicle wrote the storage.
    pub fn version(&self) -> Result<String> {
        Ok(self.tool.output(&["--version"])?.trim().to_string())
    }

    pub fn stop_node(&self) -> Result<bool> {
        self.tool.passthrough(&["node", "stop"])
    }

    pub fn start_node(&self) -> Result<bool> {
        self.tool.passthrough(&["node", "start"])
    }

    /// What a repository's identity document says about it.
    ///
    /// One `rad inspect` answers every question, because a seed asks this of every repository
    /// it holds and each extra subprocess is another fork and exec.
    pub fn describe_repo(&self, rid: &str) -> Result<Described> {
        let json = match self.tool.output(&["inspect", rid, "--identity"]) {
            Ok(json) => json,
            Err(e) => return Ok(Described::Unavailable { why: e.one_line() }),
        };
        match serde_json::from_str::<serde_json::Value>(&json) {
            Ok(document) => Ok(Described::Identity(RepoIdentity::from_document(&document))),
            Err(e) => Ok(Described::Unavailable {
                why: format!("`rad inspect --identity` did not print valid JSON: {e}"),
            }),
        }
    }

    pub fn list(&self, listing: Listing) -> Result<Listed> {
        let args: &[&str] = match listing {
            Listing::Own => &["ls"],
            Listing::Private => &["ls", "--private"],
        };
        match self.tool.output(args) {
            Ok(printed) => Ok(Listed::Ids(parse_repository_ids(&printed))),
            Err(e) => Ok(Listed::Unavailable { why: e.one_line() }),
        }
    }

    /// Fetches a repository from the network, so a restored copy can be compared with what
    /// other nodes hold.
    pub fn fetch(&self, rid: &str) -> Result<bool> {
        self.tool.passthrough(&["sync", rid, "--fetch"])
    }

    /// Re-applies one seeding policy, for restoring into a Radicle whose schema has moved on.
    pub fn seed(&self, rid: &str, scope: &str) -> Result<bool> {
        self.tool
            .passthrough(&["seed", rid, "--scope", scope, "--no-fetch"])
    }

    pub fn block_repo(&self, rid: &str) -> Result<bool> {
        self.tool.passthrough(&["block", rid])
    }

    pub fn follow(&self, nid: &str, alias: Option<&str>) -> Result<bool> {
        match alias {
            Some(alias) => self.tool.passthrough(&["follow", nid, "--alias", alias]),
            None => self.tool.passthrough(&["follow", nid]),
        }
    }

    pub fn block_peer(&self, nid: &str) -> Result<bool> {
        self.tool.passthrough(&["block", nid])
    }
}

/// The parts of an identity document this tool reads.
///
/// Parsed leniently, so a document that has grown or lost fields yields what could be read,
/// because nothing here is worth failing a backup over.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RepoIdentity {
    pub name: Option<String>,
    pub delegates: Vec<String>,
    /// `public` or `private`, defaulting to `public` as heartwood does when the document has
    /// no `visibility`
    pub visibility: String,
    /// The peers a private repository is shared with, always empty for a public one
    pub allowed: Vec<String>,
}

impl RepoIdentity {
    fn from_document(document: &serde_json::Value) -> Self {
        let name = document
            .get("payload")
            .and_then(|payload| payload.get("xyz.radicle.project"))
            .and_then(|project| project.get("name"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string);
        let delegates = strings_at(document.get("delegates"));
        let visibility = document
            .get("visibility")
            .and_then(|visibility| visibility.get("type"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("public")
            .to_string();
        let allowed = match visibility.as_str() {
            "public" => Vec::new(),
            _ => strings_at(document.get("visibility").and_then(|v| v.get("allow"))),
        };
        Self {
            name,
            delegates,
            visibility,
            allowed,
        }
    }
}

fn strings_at(value: Option<&serde_json::Value>) -> Vec<String> {
    value
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Pulls repository identifiers out of any `rad` output, sorted and deduplicated.
///
/// Table borders, column widths and colour change between releases, and a `rad:z...` token is
/// the identifier itself.
fn parse_repository_ids(printed: &str) -> Vec<String> {
    let mut ids: Vec<String> = printed
        .split(|c: char| c.is_whitespace() || c == '│' || c == '|')
        .filter(|token| token.starts_with("rad:z"))
        .map(|token| token.trim_end_matches(|c: char| !c.is_ascii_alphanumeric()))
        .map(str::to_string)
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Real `rad ls` output from rad 1.10.1, box drawing and all
    const LISTING: &str = "\
╭──────────────────────────────────────────────────────────────────╮
│ Name              RID                                Visibility  │
├──────────────────────────────────────────────────────────────────┤
│ awesome-radicle   rad:z3yQUb9HDAC7TQrUDGkQsXDsYFj9G   public     │
│ delete-me         rad:z3aBsetMhPLWMhqkaBJD9CZ4Lb1ZT   local      │
╰──────────────────────────────────────────────────────────────────╯";

    #[test]
    fn identifiers_survive_the_table_that_rad_ls_draws_around_them() {
        assert_eq!(
            parse_repository_ids(LISTING),
            vec![
                "rad:z3aBsetMhPLWMhqkaBJD9CZ4Lb1ZT".to_string(),
                "rad:z3yQUb9HDAC7TQrUDGkQsXDsYFj9G".to_string(),
            ]
        );
    }

    #[test]
    fn a_listing_with_no_repositories_yields_nothing_rather_than_a_blank_entry() {
        assert!(parse_repository_ids("").is_empty());
        assert!(parse_repository_ids("Nothing to show.").is_empty());
    }

    #[test]
    fn the_same_identifier_seen_twice_is_reported_once() {
        let text = "rad:zAAA rad:zAAA rad:zBBB";
        assert_eq!(parse_repository_ids(text), vec!["rad:zAAA", "rad:zBBB"]);
    }

    #[test]
    fn an_identifier_that_would_reach_rad_as_a_flag_is_not_an_identifier() {
        assert!(is_identifier("rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5"));
        assert!(is_identifier(
            "z6MkiTBz1ymuepK3Q7DwjNhrsFYVvfa4qGwrfKMdDwbrCVvV"
        ));

        // These reach `rad seed` or `rad follow` in an argv position from an unvouched
        // archive, and a leading `-` there is a flag
        assert!(!is_identifier("--help"));
        assert!(!is_identifier("-v"));
        assert!(!is_identifier("rad:-v"));
        assert!(!is_identifier(""));
        assert!(!is_identifier("rad:"));
        assert!(!is_identifier("../../.ssh"));
    }
}
