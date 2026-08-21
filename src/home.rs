//! The layout of a Radicle home, and which parts of it are worth an archive.
//!
//! Paths are named after what `rad self` calls them, so that a reader can hold this file and
//! `rad self` output side by side.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Whether the node is listening on its control socket right now.
///
/// The socket file survives a stopped node, so its presence proves nothing and connecting is
/// the only honest test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    Running,
    Stopped,
}

pub struct Home {
    path: PathBuf,
}

impl Home {
    /// The home a path names, whether or not anything is there yet. Pure.
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The home this machine is configured to use: an explicit `--home`, else `RAD_HOME`,
    /// else `~/.radicle`, which is the same order `rad` itself resolves in.
    pub fn from_env(explicit: Option<PathBuf>) -> Result<Self> {
        if let Some(path) = explicit {
            return Ok(Self::at(path));
        }
        if let Some(home) = std::env::var_os("RAD_HOME") {
            return Ok(Self::at(PathBuf::from(home)));
        }
        let user = std::env::var_os("HOME").ok_or_else(|| {
            Error::refused(
                "cannot tell where your Radicle home is",
                "set RAD_HOME, or pass --home <path>",
            )
        })?;
        Ok(Self::at(PathBuf::from(user).join(".radicle")))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn keys_dir(&self) -> PathBuf {
        self.path.join("keys")
    }

    /// The 444 bytes that are the identity. Losing this file is the only unrecoverable loss.
    pub fn secret_key(&self) -> PathBuf {
        self.keys_dir().join("radicle")
    }

    pub fn public_key(&self) -> PathBuf {
        self.keys_dir().join("radicle.pub")
    }

    pub fn config(&self) -> PathBuf {
        self.path.join("config.json")
    }

    pub fn storage(&self) -> PathBuf {
        self.path.join("storage")
    }

    pub fn node_dir(&self) -> PathBuf {
        self.path.join("node")
    }

    /// Seeding scopes, follows and blocks. Small, and impossible to reconstruct from memory.
    pub fn policies_db(&self) -> PathBuf {
        self.node_dir().join("policies.db")
    }

    /// Inbox read state. Losing it is an annoyance, not a loss.
    pub fn notifications_db(&self) -> PathBuf {
        self.node_dir().join("notifications.db")
    }

    /// Routing table, address book and gossip. Regenerates from the network within minutes of
    /// a node starting, so it is excluded unless asked for.
    pub fn node_db(&self) -> PathBuf {
        self.node_dir().join("node.db")
    }

    /// The socket a running node listens on. The file survives a stopped node, so
    /// `node_state` below connects to it rather than trusting that it is there. Only a unix
    /// node has one, and only `node_state` asks for it.
    #[cfg(unix)]
    pub fn control_socket(&self) -> PathBuf {
        self.node_dir().join("control.sock")
    }

    /// A home is real once it holds a secret key. Everything else `rad` recreates.
    pub fn holds_identity(&self) -> bool {
        self.secret_key().is_file()
    }

    pub fn require(&self) -> Result<()> {
        if self.holds_identity() {
            return Ok(());
        }
        Err(Error::NotAHome {
            path: self.path.clone(),
        })
    }

    #[cfg(unix)]
    pub fn node_state(&self) -> NodeState {
        match std::os::unix::net::UnixStream::connect(self.control_socket()) {
            Ok(_) => NodeState::Running,
            Err(_) => NodeState::Stopped,
        }
    }

    /// A Radicle node is a unix program: there is no control socket to connect to here, and so
    /// nothing that could be writing to storage while an archive is read.
    #[cfg(not(unix))]
    pub fn node_state(&self) -> NodeState {
        NodeState::Stopped
    }

    /// The alias the node announces, read from `config.json` rather than from `rad self`, so
    /// that reading an archived home works without a `rad` on PATH.
    pub fn alias(&self) -> Result<Option<String>> {
        let path = self.config();
        if !path.is_file() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(&path).map_err(|e| Error::io(&path, e))?;
        // The path, because serde says only "expected value at line 1 column 1", and a home
        // with a malformed `config.json` is otherwise a run that fails naming nothing.
        let config: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| Error::Malformed {
                path: path.clone(),
                reason: format!("this is not valid JSON: {e}"),
            })?;
        Ok(config
            .get("node")
            .and_then(|node| node.get("alias"))
            .and_then(|alias| alias.as_str())
            .map(str::to_string))
    }

    /// Storage directory names are repository identifiers without the `rad:` prefix, so the
    /// inventory of a home is a directory listing and needs neither `rad` nor a running node.
    ///
    /// The second half of the answer is the directories it could not read as identifiers. A
    /// caller has to say so: skipping one quietly writes an archive missing a repository and
    /// still reports success.
    pub fn repository_ids(&self) -> Result<(Vec<String>, Vec<String>)> {
        let storage = self.storage();
        if !storage.is_dir() {
            return Ok((Vec::new(), Vec::new()));
        }
        let mut rids = Vec::new();
        let mut skipped = Vec::new();
        for entry in std::fs::read_dir(&storage).map_err(|e| Error::io(&storage, e))? {
            let entry = entry.map_err(|e| Error::io(&storage, e))?;
            if !entry.path().is_dir() {
                continue;
            }
            // `to_str`, not `to_string_lossy`: a lossy name would become replacement
            // characters and then be handed on as a repository id, and ids address paths.
            let name = entry.file_name();
            match name.to_str() {
                Some(name) if name.starts_with('z') => rids.push(format!("rad:{name}")),
                Some(_) => {}
                // Skipped, and said so. Dropping it silently would write an archive missing a
                // repository and call the run a success, which is the failure this whole tool
                // exists to make impossible.
                None => skipped.push(entry.file_name().to_string_lossy().into_owned()),
            }
        }
        // Sorted, so the inventory of one home is the same list whatever order the filesystem
        // hands its entries back in.
        rids.sort();
        skipped.sort();
        Ok((rids, skipped))
    }

    /// The storage directory for a repository, by `rad:`-prefixed or bare identifier.
    pub fn repository_path(&self, rid: &str) -> PathBuf {
        self.storage().join(rid.strip_prefix("rad:").unwrap_or(rid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_archived_path_hangs_off_the_home_it_was_built_from() {
        let home = Home::at("/var/lib/radicle");
        assert_eq!(
            home.secret_key(),
            PathBuf::from("/var/lib/radicle/keys/radicle")
        );
        assert_eq!(
            home.policies_db(),
            PathBuf::from("/var/lib/radicle/node/policies.db")
        );
        assert_eq!(
            home.notifications_db(),
            PathBuf::from("/var/lib/radicle/node/notifications.db")
        );
    }

    #[test]
    fn repository_paths_accept_an_identifier_with_or_without_its_prefix() {
        let home = Home::at("/home/me/.radicle");
        let with = home.repository_path("rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5");
        let without = home.repository_path("z3gqcJUoA1n9HaHKufZs5FCSGazv5");
        assert_eq!(with, without);
        assert!(with.ends_with("storage/z3gqcJUoA1n9HaHKufZs5FCSGazv5"));
    }
}
