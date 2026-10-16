//! The layout of a Radicle home, and which parts of it are worth an archive.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Whether a link stands at `path`, whatever it points at.
pub fn is_a_link(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|entry| entry.is_symlink())
}

// Path bytes a socket address holds, 103 on macOS and 107 on Linux. A path is blamed on its
// length only past the shorter one, where that explanation is true.
#[cfg(unix)]
const SHORTEST_SUN_PATH: usize = 103;
#[cfg(unix)]
const LONGEST_SUN_PATH: usize = 107;

/// Whether the node is listening on its control socket right now.
///
/// The socket file survives a stopped node, so connecting is the test.
// Off unix nothing constructs `Running` or `Unknown`. The `expect` fails the build once a
// non-unix node can answer, so the attribute never sits on live code.
#[cfg_attr(
    not(unix),
    expect(dead_code, reason = "no control socket to answer on")
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeState {
    Running,
    Stopped,
    /// The socket answered neither way. It exists and cannot be connected to, or the error was
    /// something other than "nothing is listening".
    ///
    /// Never fold this into `Stopped`. Two writers in one home fork the identity, so a
    /// permission error read as stopped lets a restore overwrite a live node's storage.
    Unknown {
        socket: PathBuf,
        why: String,
    },
}

impl NodeState {
    /// Whether a node is known to be running. False for `Unknown`, so a caller that only wants
    /// to warn does not warn on a doubt.
    #[cfg_attr(not(unix), expect(dead_code, reason = "nothing here can answer yes"))]
    pub fn is_running(&self) -> bool {
        matches!(self, Self::Running)
    }

    /// Whether it is safe to write into this home, which needs a node proven stopped.
    /// `Unknown` answers false.
    pub fn is_stopped(&self) -> bool {
        matches!(self, Self::Stopped)
    }

    /// What could not be established about the node, for a refusal to quote.
    pub fn doubt(&self) -> Option<String> {
        match self {
            Self::Unknown { socket, why } => {
                Some(format!("could not connect to {}: {why}", socket.display()))
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

    /// The home this machine is configured to use, in `rad`'s own order (an explicit `--home`,
    /// then `RAD_HOME`, then `~/.radicle`).
    pub fn from_env(explicit: Option<PathBuf>) -> Result<Self> {
        if let Some(path) = explicit {
            return Ok(Self::at(path));
        }
        if let Some(home) = std::env::var_os("RAD_HOME") {
            return Ok(Self::at(PathBuf::from(home)));
        }
        let user_home = std::env::var_os("HOME").ok_or_else(|| {
            Error::refused(
                "HOME is not set, so rad-backup cannot find your Radicle home",
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

    /// The secret key, which is the identity. Nothing recovers this file once it is lost.
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

    /// Inbox read state, cheap to lose.
    pub fn notifications_db(&self) -> PathBuf {
        self.node_dir().join("notifications.db")
    }

    /// Routing table, address book and gossip. This database regenerates from the network
    /// within minutes of a node starting, so it is excluded unless asked for.
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
    /// The override wins, as in heartwood's `socket_from_env`. Asking the home's own path
    /// would miss a node started under the override and let a second writer into the home.
    #[cfg(unix)]
    pub fn control_socket_given(&self, override_path: Option<PathBuf>) -> PathBuf {
        override_path.unwrap_or_else(|| self.control_socket_at())
    }

    /// The socket a running node listens on, as `rad` would find it here.
    #[cfg(unix)]
    pub fn control_socket_from_env(&self) -> PathBuf {
        self.control_socket_given(std::env::var_os("RAD_SOCKET").map(PathBuf::from))
    }

    /// Whether a home is real, which it is once it holds a secret key. `rad` recreates the
    /// rest.
    ///
    /// Errs when the key cannot be looked at, because the question is whether going on would
    /// overwrite somebody's identity, and an unreadable key may still be there.
    pub fn holds_identity(&self) -> Result<bool> {
        let key = self.secret_key();
        match std::fs::metadata(&key) {
            Ok(meta) => Ok(meta.is_file()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(Error::io(&key, e)),
        }
    }

    /// What a restore into this home would write over, besides the secret key.
    ///
    /// A restore replaces `config.json` and the node databases, and its forced bundle fetch
    /// rewinds every stored ref, other peers' signed refs included. A home with a retired or
    /// deleted key still holds all of that, and for a private repository nobody else does.
    ///
    /// Anything the filesystem will not answer about counts as present, because a wrong
    /// "present" costs one `--force` and a wrong "absent" costs the refs.
    pub fn what_a_restore_would_overwrite(&self) -> Vec<&'static str> {
        let mut found = Vec::new();
        if !self.is_absent(&self.storage()) && !self.is_empty_dir(&self.storage()) {
            found.push("stored repositories");
        }
        if !self.is_absent(&self.node_dir()) && !self.is_empty_dir(&self.node_dir()) {
            found.push("node databases");
        }
        if !self.is_absent(&self.config()) {
            found.push("config.json");
        }
        // Every retired name counts. `retired_path` answers with a free name by construction,
        // so asking it would always find nothing.
        if crate::cmd::migrate::holds_a_retired_key(&self.keys_dir()) {
            found.push("a retired key");
        }
        found
    }

    /// Which of the directories a restore fills point somewhere else.
    ///
    /// Every write into `keys`, `node` and `storage` follows a link at the directory, so a
    /// linked `keys` puts the private key wherever the link points.
    ///
    /// `--force` must not answer this, because it permits overwriting what is here, never
    /// writing somewhere else. The home's own path is not checked, because the user named it.
    /// Revisit if a home ever comes from a path the user did not name.
    pub fn directories_that_point_elsewhere(&self) -> Vec<&'static str> {
        [
            ("keys", self.keys_dir()),
            ("node", self.node_dir()),
            ("storage", self.storage()),
        ]
        .into_iter()
        .filter(|(_, path)| is_a_link(path))
        .map(|(name, _)| name)
        .collect()
    }

    /// Whether nothing is at `path`. A path the filesystem will not answer about counts as
    /// present, because a wrong "absent" lets a write through.
    fn is_absent(&self, path: &Path) -> bool {
        matches!(std::fs::symlink_metadata(path), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
    }

    /// Whether `path` is a directory with nothing in it. A directory that cannot be listed is
    /// not empty.
    ///
    /// `rad auth` leaves an empty `storage` and `node`, which must not block a restore into a
    /// freshly created home.
    fn is_empty_dir(&self, path: &Path) -> bool {
        match std::fs::read_dir(path) {
            Ok(mut entries) => entries.next().is_none(),
            Err(_) => false,
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
            // Nothing is listening when the socket file is missing or left by a dead node. Any
            // other error, permission denied above all, says only that this process could not
            // ask.
            Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::ConnectionRefused) => {
                NodeState::Stopped
            }
            // A path too long for `sun_path` fails with an `InvalidInput` naming neither path
            // nor limit, so this arm rewords it and keeps the refusal. The length check stops
            // an interior NUL, also `InvalidInput`, from getting this sentence.
            Err(e)
                if e.kind() == ErrorKind::InvalidInput
                    && socket.as_os_str().len() > SHORTEST_SUN_PATH =>
            {
                NodeState::Unknown {
                    why: format!(
                        "{e}. The path is {} bytes long, but a node socket path can be at most \
                         {SHORTEST_SUN_PATH} bytes on macos and {LONGEST_SUN_PATH} on linux. \
                         Set RAD_SOCKET to a shorter path, or use a Radicle home with a shorter \
                         path",
                        socket.as_os_str().len()
                    ),
                    socket,
                }
            }
            Err(e) => NodeState::Unknown {
                socket,
                why: e.to_string(),
            },
        }
    }

    /// Answers `Stopped`, because a Radicle node runs only on unix, so nothing here can be
    /// writing to storage.
    #[cfg(not(unix))]
    pub fn probe_node_state(&self) -> NodeState {
        NodeState::Stopped
    }

    /// The socket `RAD_SOCKET` names, when it names one other than this home's own.
    ///
    /// heartwood resolves the variable before the home-relative default, so a node answering
    /// there may serve another home. A refusal still stands, but it must name what answered.
    #[cfg(unix)]
    pub fn borrowed_socket(&self) -> Option<PathBuf> {
        let socket = self.control_socket_from_env();
        (socket != self.control_socket_at()).then_some(socket)
    }

    #[cfg(not(unix))]
    pub fn borrowed_socket(&self) -> Option<PathBuf> {
        None
    }

    /// The alias the node announces, read from `config.json` so that reading an archived home
    /// needs no `rad` on PATH.
    pub fn read_alias(&self) -> Result<Option<String>> {
        let path = self.config();
        if !path.is_file() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(&path).map_err(|e| Error::io(&path, e))?;
        // The error carries the path, because serde names only a line and a column
        let config: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| Error::Malformed {
                path: path.clone(),
                reason: format!("not valid JSON ({e})"),
            })?;
        Ok(config
            .get("node")
            .and_then(|node| node.get("alias"))
            .and_then(|alias| alias.as_str())
            .map(str::to_string))
    }

    /// Lists the repository ids in storage, and the directory names that are not UTF-8.
    ///
    /// Storage directory names are ids without `rad:`, so this needs neither `rad` nor a
    /// running node. A caller must report the second list, because skipping one quietly
    /// writes an archive missing a repository and still reports success.
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
            // Ids come from `to_str`, because a lossy name would pass on as a repository id,
            // and ids address paths
            let name = entry.file_name();
            match name.to_str() {
                Some(name) if name.starts_with('z') => rids.push(format!("rad:{name}")),
                Some(_) => {}
                None => unreadable.push(entry.file_name().to_string_lossy().into_owned()),
            }
        }
        // The sort keeps one home's list identical whatever order the filesystem returns
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

    /// A home too deep for a socket path says which path and what to do about it.
    ///
    /// The probe still refuses, because reading this as stopped costs the home. A home under a
    /// macOS temp directory (`/var/folders/<x>/<y>/T/`) is the ordinary way to hit the limit.
    // Unix only, like the socket. The path is refused before the filesystem is touched, so
    // nothing here has to exist.
    #[cfg(unix)]
    #[test]
    fn a_socket_path_too_long_to_bind_says_which_path_and_how_long_it_may_be() {
        let home = Home::at(std::env::temp_dir().join("d".repeat(120)));

        let state = home.probe_node_state();
        let NodeState::Unknown { why, .. } = &state else {
            panic!("a path nothing can bind is not an answer about a node: {state:?}");
        };
        assert!(
            why.contains(&SHORTEST_SUN_PATH.to_string())
                && why.contains(&LONGEST_SUN_PATH.to_string()),
            "{why}"
        );
        assert!(why.contains("macos") && why.contains("linux"), "{why}");
        assert!(why.contains("RAD_SOCKET"), "{why}");
        assert!(
            why.contains(&home.control_socket_at().as_os_str().len().to_string()),
            "the length of the path that was refused is what says how much to cut: {why}"
        );
    }

    /// Walks the probe's three answers (nothing listening, somebody listening, and a question
    /// this process cannot put). Reading the last as stopped lets `restore --force`
    /// write over a live node's storage.
    #[cfg(unix)]
    #[test]
    fn a_socket_that_could_not_be_asked_is_not_reported_as_a_stopped_node() {
        use std::os::unix::fs::PermissionsExt as _;

        // The short scratch keeps under the socket path limit, which the ordinary scratch
        // exceeds on macOS
        let scratch = crate::key::tests::TestScratch::create_short("sock");
        let home = Home::at(scratch.path_of("home"));
        std::fs::create_dir_all(home.node_dir()).expect("scratch home is creatable");

        // A missing socket file is the ordinary shape of a machine with no node
        assert_eq!(home.probe_node_state(), NodeState::Stopped);

        // A listener is what the probe looks for
        let listening = std::os::unix::net::UnixListener::bind(home.control_socket_at())
            .expect("a scratch socket is bindable");
        assert_eq!(home.probe_node_state(), NodeState::Running);

        // A dead node leaves its socket file behind, and a refused connect there means stopped
        drop(listening);
        assert!(
            home.control_socket_at().exists(),
            "the socket file outlives its listener"
        );
        // A socket stays bound while any copy of its fd is open, and every subprocess another
        // test spawns holds one between `fork` and `exec`. A measured 646 connects in 2000
        // were accepted with eight spawning threads, so the state is waited out.
        assert_eq!(settled_state(&home), NodeState::Stopped);

        // The directory holding the socket cannot be entered, so this process cannot ask
        let unreadable = std::fs::Permissions::from_mode(0o000);
        std::fs::set_permissions(home.node_dir(), unreadable).expect("mode is settable");
        let state = home.probe_node_state();
        // Root and anything holding CAP_DAC_OVERRIDE walks through mode 000, so this reads the
        // directory to find out. A guard shaped by the outcome would skip the bug it tests.
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
    }

    /// A link at a directory a restore fills sends the restore out of the home, and a linked
    /// `keys` takes the private key with it. A plain directory at the same name stays allowed,
    /// because `rad auth` leaves exactly that.
    // Unix only, because the test makes a symlink
    #[cfg(unix)]
    #[test]
    fn a_directory_a_restore_fills_that_points_out_of_the_home_is_refused() {
        let scratch = crate::key::tests::TestScratch::create("home-linked-dirs");
        let home = Home::at(scratch.path_of("home"));
        let there = scratch.path_of("elsewhere");
        std::fs::create_dir_all(&there).expect("the directory pointed at is creatable");
        std::fs::create_dir_all(home.node_dir()).expect("the node directory is creatable");
        assert!(
            home.directories_that_point_elsewhere().is_empty(),
            "a home whose directories are directories points nowhere else"
        );

        // One link at a time, so each of the three names is shown to be checked
        for (name, linked) in [
            ("keys", home.keys_dir()),
            ("node", home.node_dir()),
            ("storage", home.storage()),
        ] {
            let _ = std::fs::remove_dir(&linked);
            std::os::unix::fs::symlink(&there, &linked).expect("a symlink is creatable");
            assert_eq!(
                home.directories_that_point_elsewhere(),
                vec![name],
                "the link at {name} is the only one there"
            );
            std::fs::remove_file(&linked).expect("the link is removable");
        }
    }

    /// A home holding somebody's displaced key is occupied, and a restore has to say so.
    ///
    /// Both names are checked, because a second retirement takes a numbered name and the first
    /// can then be gone.
    #[test]
    fn a_home_holding_a_key_a_migration_displaced_is_not_an_empty_one() {
        let scratch = crate::key::tests::TestScratch::create("home-retired-key");
        let home = Home::at(scratch.path_of("home"));
        let keys = home.keys_dir();
        std::fs::create_dir_all(&keys).expect("the keys directory is creatable");
        assert!(
            home.what_a_restore_would_overwrite().is_empty(),
            "an empty home has nothing to write over"
        );

        std::fs::write(
            crate::cmd::migrate::first_retired_path(&keys),
            b"a displaced key",
        )
        .expect("the retired key is writable");
        assert!(
            home.what_a_restore_would_overwrite()
                .contains(&"a retired key"),
            "{:?}",
            home.what_a_restore_would_overwrite()
        );

        // The first retired key can be moved away by hand, and `retired_path` never reuses a
        // freed name, so no single-name probe finds the numbered key
        let numbered = crate::cmd::migrate::retired_path(&keys);
        std::fs::write(&numbered, b"another displaced key").expect("the second key is writable");
        std::fs::remove_file(crate::cmd::migrate::first_retired_path(&keys))
            .expect("the first retired key is removable");
        assert_ne!(numbered, crate::cmd::migrate::first_retired_path(&keys));
        assert!(
            home.what_a_restore_would_overwrite()
                .contains(&"a retired key"),
            "{:?}",
            home.what_a_restore_would_overwrite()
        );
    }

    /// What the probe answers once no file descriptor for the socket is left open anywhere.
    ///
    /// Only `Running` is waited out, because other tests' subprocesses carry the descriptor.
    /// `Unknown` is about this process and never settles, so waiting only slows a failure.
    #[cfg(unix)]
    fn settled_state(home: &Home) -> NodeState {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let state = home.probe_node_state();
            if !state.is_running() || std::time::Instant::now() >= deadline {
                return state;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    /// heartwood resolves `RAD_SOCKET` before the home-relative default. Asking the home's
    /// own path answers "nothing is listening" about a live node and lets a second writer in.
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
