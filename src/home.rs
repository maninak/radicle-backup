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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeState {
    Running,
    Stopped,
    /// The socket answered neither way: it is there and cannot be connected to, or the answer
    /// came back as something other than "nothing is listening".
    ///
    /// Never folded into `Stopped`, which is what a bare `is_ok()` did. Everything that writes
    /// to a home asks this first, and the whole point of asking is that two writers in one
    /// home fork the identity: a permission error read as "the node is stopped" is a restore
    /// that overwrites storage a live node is holding open.
    Unknown {
        socket: PathBuf,
        why: String,
    },
}

impl NodeState {
    /// Whether a node is known to be running. False for `Unknown`, so a caller that only wants
    /// to warn does not warn on a doubt.
    pub fn is_running(&self) -> bool {
        matches!(self, Self::Running)
    }

    /// Whether it is safe to write into this home. Only a node proven stopped is: `Unknown`
    /// means nobody established that nothing else is writing.
    pub fn is_stopped(&self) -> bool {
        matches!(self, Self::Stopped)
    }

    /// What could not be established, for a caller that must refuse rather than guess.
    pub fn doubt(&self) -> Option<String> {
        match self {
            Self::Unknown { socket, why } => {
                Some(format!("{} could not be reached: {why}", socket.display()))
            }
            Self::Running | Self::Stopped => None,
        }
    }
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
        let user_home = std::env::var_os("HOME").ok_or_else(|| {
            Error::refused(
                "cannot tell where your Radicle home is",
                "set RAD_HOME, or pass --home <path>",
            )
        })?;
        Ok(Self::at(PathBuf::from(user_home).join(".radicle")))
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

    /// The socket a running node listens on, as this home would place it. Pure.
    #[cfg(unix)]
    pub fn control_socket_at(&self) -> PathBuf {
        self.node_dir().join("control.sock")
    }

    /// The socket a running node listens on, given whatever `RAD_SOCKET` was set to. Pure.
    ///
    /// The override wins, because that is what heartwood's own `socket_from_env` does, and a
    /// node started under it is listening somewhere this home's own path does not name. Asking
    /// the wrong path answers "nothing is listening" about a node that is: a backup then
    /// records `--stop-node` as having stopped a node it never touched, and the restore on the
    /// far end skips the warning that two nodes must never share one key.
    #[cfg(unix)]
    pub fn control_socket_given(&self, override_path: Option<PathBuf>) -> PathBuf {
        override_path.unwrap_or_else(|| self.control_socket_at())
    }

    /// The socket a running node listens on, as `rad` would find it here.
    #[cfg(unix)]
    pub fn control_socket_from_env(&self) -> PathBuf {
        self.control_socket_given(std::env::var_os("RAD_SOCKET").map(PathBuf::from))
    }

    /// Whether a home is real, which it is once it holds a secret key. Everything else `rad`
    /// recreates.
    ///
    /// An error, not a `false`, when the key is there and cannot be looked at. Every caller is
    /// asking the same question, "would going on here overwrite somebody's identity", and
    /// `is_file()` answered no to it for an unsearchable directory or a mount that had gone
    /// away. `restore --force` is not the only way to lose a key.
    pub fn holds_identity(&self) -> Result<bool> {
        let key = self.secret_key();
        match std::fs::metadata(&key) {
            Ok(meta) => Ok(meta.is_file()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(Error::io(&key, e)),
        }
    }

    pub fn require_identity(&self) -> Result<()> {
        match self.holds_identity()? {
            true => Ok(()),
            false => Err(Error::NotAHome {
                path: self.path.clone(),
            }),
        }
    }

    #[cfg(unix)]
    pub fn probe_node_state(&self) -> NodeState {
        use std::io::ErrorKind;

        let socket = self.control_socket_from_env();
        match std::os::unix::net::UnixStream::connect(&socket) {
            Ok(_) => NodeState::Running,
            // The two answers that mean nothing is listening: no socket file at all, and a
            // socket file left behind by a node that is gone. Everything else, permission
            // denied above all, says only that this process could not ask.
            Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::ConnectionRefused) => {
                NodeState::Stopped
            }
            Err(e) => NodeState::Unknown {
                socket,
                why: e.to_string(),
            },
        }
    }

    /// A Radicle node is a unix program: there is no control socket to connect to here, and so
    /// nothing that could be writing to storage while an archive is read.
    #[cfg(not(unix))]
    pub fn probe_node_state(&self) -> NodeState {
        NodeState::Stopped
    }

    /// The socket `RAD_SOCKET` names, when it names one other than this home's own.
    ///
    /// A node answering there is not necessarily this home's node: heartwood resolves the
    /// variable before the home-relative default, so somebody with one exported for their main
    /// node was told "the node is running against the home being restored into" about a node
    /// serving a different home entirely. The refusal stands either way, because a node for
    /// this home could not have bound that socket, but the sentence has to name what answered.
    #[cfg(unix)]
    pub fn borrowed_socket(&self) -> Option<PathBuf> {
        let socket = self.control_socket_from_env();
        (socket != self.control_socket_at()).then_some(socket)
    }

    #[cfg(not(unix))]
    pub fn borrowed_socket(&self) -> Option<PathBuf> {
        None
    }

    /// The alias the node announces, read from `config.json` rather than from `rad self`, so
    /// that reading an archived home works without a `rad` on PATH.
    pub fn read_alias(&self) -> Result<Option<String>> {
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
    pub fn read_inventory(&self) -> Result<(Vec<String>, Vec<String>)> {
        let storage = self.storage();
        if !storage.is_dir() {
            return Ok((Vec::new(), Vec::new()));
        }
        let mut rids = Vec::new();
        let mut unreadable = Vec::new();
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
                None => unreadable.push(entry.file_name().to_string_lossy().into_owned()),
            }
        }
        // Sorted, so the inventory of one home is the same list whatever order the filesystem
        // hands its entries back in.
        rids.sort();
        unreadable.sort();
        Ok((rids, unreadable))
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

    /// The bug this guards: `UnixStream::connect(..).is_ok()` read every error as "the node is
    /// stopped". A control socket is created `srwxrwxr-x` inside a directory, so a home
    /// reached over a mount another user owns answers "stopped" about a node that is up.
    /// `restore --force` then wrote over storage a live node was holding, and `--stop-node`
    /// recorded a stop it never performed. The three answers it can give are walked in turn:
    /// nothing listening, somebody listening, and a question this process cannot put.
    #[cfg(unix)]
    #[test]
    fn a_socket_that_could_not_be_asked_is_not_reported_as_a_stopped_node() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = std::env::temp_dir().join(format!("rad-backup-socket-{}", std::process::id()));
        let home = Home::at(&root);
        std::fs::create_dir_all(home.node_dir()).expect("scratch home is creatable");

        // Nothing there at all, which is the ordinary shape of a machine with no node.
        assert_eq!(home.probe_node_state(), NodeState::Stopped);

        // Somebody listening, which is what the probe is for.
        let listening = std::os::unix::net::UnixListener::bind(home.control_socket_at())
            .expect("a scratch socket is bindable");
        assert_eq!(home.probe_node_state(), NodeState::Running);

        // The socket file a node that died leaves behind. Nothing accepts on it, and that is
        // a real answer rather than a doubt.
        drop(listening);
        assert!(
            home.control_socket_at().exists(),
            "the socket file outlives its listener"
        );
        assert_eq!(home.probe_node_state(), NodeState::Stopped);

        // The directory holding the socket cannot be entered, so this process cannot ask.
        let unreadable = std::fs::Permissions::from_mode(0o000);
        std::fs::set_permissions(home.node_dir(), unreadable).expect("mode is settable");
        let state = home.probe_node_state();
        // Root and anything holding CAP_DAC_OVERRIDE walks straight through mode 000, so there
        // is nothing it could fail to ask. Probed here rather than guessed from a user name,
        // because the probe is the condition itself; an outcome-shaped guard would also skip
        // whenever the bug this test exists for came back.
        let walks_through_any_mode = std::fs::read_dir(home.node_dir()).is_ok();
        std::fs::set_permissions(home.node_dir(), std::fs::Permissions::from_mode(0o700))
            .expect("mode is settable back");

        if !walks_through_any_mode {
            assert_ne!(
                state,
                NodeState::Stopped,
                "a socket nobody could reach is not an answer"
            );
            assert!(!state.is_running(), "{state:?}");
            assert!(
                state
                    .doubt()
                    .is_some_and(|doubt| doubt.contains("control.sock")),
                "{state:?}"
            );
        }

        let _ = std::fs::remove_dir_all(root);
    }

    /// heartwood resolves `RAD_SOCKET` before the home-relative default, so a node started
    /// under it listens somewhere this home's own path does not name. This tool asked the
    /// home-relative path unconditionally, and got "nothing is listening" about a node that
    /// was, which is the answer that lets a second writer into a home.
    #[cfg(unix)]
    #[test]
    fn the_socket_asked_about_is_the_one_rad_itself_would_use() {
        let home = Home::at("/var/lib/radicle");
        let default = PathBuf::from("/var/lib/radicle/node/control.sock");
        assert_eq!(home.control_socket_at(), default);
        assert_eq!(home.control_socket_given(None), default);
        assert_eq!(
            home.control_socket_given(Some(PathBuf::from("/run/user/1000/radicle.sock"))),
            PathBuf::from("/run/user/1000/radicle.sock")
        );
    }
}
