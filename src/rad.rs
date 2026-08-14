//! The `rad` commands this tool asks questions of.
//!
//! Only two kinds of call live here. Queries that return JSON (`rad inspect --identity`) are
//! parsed as JSON. Queries that return a table are never parsed by column: repository
//! identifiers are picked out of the text by their `rad:z` prefix, which is a shape no table
//! layout can change. Anything more fragile than that belongs in `git` or in SQLite instead.

use std::path::Path;

use crate::error::Result;
use crate::exec::Tool;

/// Which repositories to ask `rad ls` about.
#[derive(Debug, Clone, Copy)]
pub enum Listing {
    /// Repositories this identity initialised or forked.
    Own,
    /// Repositories the network has never seen and never will.
    Private,
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

    /// The version string `rad --version` prints, recorded in the manifest so that a restore
    /// years later knows which Radicle wrote the storage it is holding.
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
    /// One `rad inspect` per repository rather than one per question: on a seed being asked
    /// about every repository it holds, each extra subprocess is another fork and exec.
    pub fn describe_repo(&self, rid: &str) -> Result<Option<RepoIdentity>> {
        let Some(json) = self.tool.raw_output(&["inspect", rid, "--identity"])? else {
            return Ok(None);
        };
        let Ok(document) = serde_json::from_str::<serde_json::Value>(&json) else {
            return Ok(None);
        };
        Ok(Some(RepoIdentity::from_document(&document)))
    }

    /// Repository identifiers from a `rad ls` listing.
    pub fn list(&self, listing: Listing) -> Result<Vec<String>> {
        let args: &[&str] = match listing {
            Listing::Own => &["ls"],
            Listing::Private => &["ls", "--private"],
        };
        let Some(out) = self.tool.raw_output(args)? else {
            return Ok(Vec::new());
        };
        Ok(repository_ids(&out))
    }

    /// Fetch a repository from the network, which is what makes a restored copy comparable
    /// with what other nodes hold.
    pub fn fetch(&self, rid: &str) -> Result<bool> {
        self.tool.passthrough(&["sync", rid, "--fetch"])
    }

    /// Re-apply one seeding policy, for restoring into a Radicle whose schema has moved on.
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

/// The parts of an identity document this tool has an opinion about.
///
/// Parsed leniently: a document that has grown fields, or lost the ones we look for, yields
/// what could be read rather than an error. Nothing here is worth failing a backup over.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RepoIdentity {
    pub name: Option<String>,
    pub delegates: Vec<String>,
    /// `public` or `private`. A document with no `visibility` is public, which is heartwood's
    /// own default.
    pub visibility: String,
    /// The peers a private repository is shared with. Always empty for a public one.
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

/// Pull repository identifiers out of any `rad` output.
///
/// Table borders, column widths and colour all change between releases; a `rad:z...` token
/// does not, because it is the identifier itself.
fn repository_ids(text: &str) -> Vec<String> {
    let mut ids: Vec<String> = text
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

    /// Real `rad ls` output from rad 1.10.1, box drawing and all.
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
            repository_ids(LISTING),
            vec![
                "rad:z3aBsetMhPLWMhqkaBJD9CZ4Lb1ZT".to_string(),
                "rad:z3yQUb9HDAC7TQrUDGkQsXDsYFj9G".to_string(),
            ]
        );
    }

    #[test]
    fn a_listing_with_no_repositories_yields_nothing_rather_than_a_blank_entry() {
        assert!(repository_ids("").is_empty());
        assert!(repository_ids("Nothing to show.").is_empty());
    }

    #[test]
    fn the_same_identifier_seen_twice_is_reported_once() {
        let text = "rad:zAAA rad:zAAA rad:zBBB";
        assert_eq!(repository_ids(text), vec!["rad:zAAA", "rad:zBBB"]);
    }
}
