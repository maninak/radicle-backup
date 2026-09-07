//! The layout of a Radicle home, and which parts of it are worth an archive.
//!
//! Paths are named after what `rad self` calls them, so that a reader can hold this file and
//! `rad self` output side by side.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Whether a link stands at `path`, whatever it points at. Asked of a directory a restore
/// fills and of a repository's own directory inside `storage`, so it lives here rather than
/// in either caller.
pub fn is_a_link(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|entry| entry.is_symlink())
}

/// What a `sun_path` holds, less the terminator it takes: macOS gives 104 bytes and Linux 108.
/// Both are named because the message quotes both, and a path is only refused for its length
/// past the smaller one, which is where the explanation starts being able to be true.
#[cfg(unix)]
const SHORTEST_SUN_PATH: usize = 103;
#[cfg(unix)]
const LONGEST_SUN_PATH: usize = 107;

/// Whether the node is listening on its control socket right now.
///
/// The socket file survives a stopped node, so its presence proves nothing and connecting is
/// the only honest test.
// Off unix there is no control socket, so `probe_node_state` has one answer and nothing
// constructs the other two. The type stays one type on every platform, because a per-platform
// enum would put a `cfg` on every match in the tree. `expect` rather than `allow`, so the day
// a Windows node does answer, the attribute fails the build instead of sitting on live code.
#[cfg_attr(
    not(unix),
    expect(dead_code, reason = "no control socket to answer on")
)]
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
    #[cfg_attr(not(unix), expect(dead_code, reason = "nothing here can answer yes"))]
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

    /// The secret key, which is the identity. Losing this file is the only unrecoverable loss.
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

    /// What a restore into this home would write over, besides the secret key.
    ///
    /// Occupancy is a wider question than "is there an identity". A restore replaces
    /// `config.json` and the node databases, and fetches every bundle with `--force`, which
    /// rewinds every ref in every stored repository, other peers' namespaces and their signed
    /// refs included. A home whose key `move` retired, or whose key was deleted by hand, still
    /// holds all of that, and asking only about the key walked a restore past both the refusal
    /// and the confirmation: a stale archive then took its refs over newer ones that, for a
    /// private repository, nobody else holds.
    ///
    /// Named rather than counted, because a refusal that says what is there is one somebody
    /// can act on. Anything the filesystem will not answer about counts as present, because
    /// being wrong towards "present" costs one `--force` and being wrong the other way costs
    /// the refs.
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
        // Every name a retirement hands out, not the one the next would take: `retired_path`
        // answers with a name nothing is at by construction, so asking it this could only be
        // answered "nothing here", and a home holding somebody's displaced key read as empty.
        if crate::cmd::migrate::holds_a_retired_key(&self.keys_dir()) {
            found.push("a retired key");
        }
        found
    }

    /// Which of the directories a restore fills point somewhere else.
    ///
    /// A restore writes the key, the databases and every repository into `keys`, `node` and
    /// `storage` by name, and a link at a directory is resolved by everything that writes:
    /// `create_dir_all` walks through one, and the copies and `git init` that follow land on
    /// the far side of it. So a home seeded with one sends an archive's contents out of
    /// itself, and `keys` pointing at a directory somebody else owns puts the private key in
    /// it. This only answers the question; what the caller does about it differs by caller.
    /// `restore` names where each one leads and asks, because pointing `storage` at a bigger
    /// disk is an ordinary thing to have done, and refuses any link that changed after that
    /// was settled. The shipped `restore.sh` refuses outright, having nobody to ask.
    ///
    /// Separate from `what_a_restore_would_overwrite` because `--force` answers that one and
    /// must not answer this: force is permission to overwrite what is here, never permission
    /// to write somewhere else. The home's own path is deliberately not checked, because
    /// pointing `~/.radicle` at another disk is something people do on purpose and it is the
    /// path the user named. Revisit if a home ever comes from somewhere the user did not
    /// name, which would make that link somebody else's choice rather than theirs.
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

    /// Whether nothing is at `path`. Anything the filesystem refuses to answer about counts as
    /// something being there, because every caller is deciding whether it is safe to write.
    fn is_absent(&self, path: &Path) -> bool {
        matches!(std::fs::symlink_metadata(path), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
    }

    /// Whether `path` is a directory with nothing in it. `rad auth` leaves an empty `storage`
    /// and an empty `node`, and refusing over those would refuse the ordinary case of
    /// restoring into a home somebody has just created. A directory that cannot be listed is
    /// not empty.
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
            // The two answers that mean nothing is listening: no socket file at all, and a
            // socket file left behind by a node that is gone. Everything else, permission
            // denied above all, says only that this process could not ask.
            Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::ConnectionRefused) => {
                NodeState::Stopped
            }
            // A path too long for `sun_path` comes back as `InvalidInput` and the words
            // "path must be shorter than SUN_LEN", which name neither the path, nor the
            // limit, nor a way out. The refusal itself stands, because a node reached some
            // other way is still a node and reading this as "stopped" is what costs the home:
            // only the sentence changes. The length is checked as well as the kind, because
            // an interior NUL is `InvalidInput` too, and about a short path this sentence
            // would be a lie. It is still the wrong sentence about a long path with a NUL in
            // it, which nothing here can produce: neither an environment variable nor an
            // argument can carry one.
            Err(e)
                if e.kind() == ErrorKind::InvalidInput
                    && socket.as_os_str().len() > SHORTEST_SUN_PATH =>
            {
                NodeState::Unknown {
                    why: format!(
                        "{e}, and that path is {} bytes: a control socket path can be at most \
                         {SHORTEST_SUN_PATH} bytes on macos and {LONGEST_SUN_PATH} on linux. \
                         Point RAD_SOCKET at a shorter one, or use a home whose own path is \
                         shorter",
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

    /// A home too deep for a socket path says which path and what to do about it.
    ///
    /// The refusal is right: nothing here can tell whether a node is running, and reading that
    /// as "stopped" is what costs the home. What was wrong was the sentence. The system says
    /// "path must be shorter than SUN_LEN" and stops, which names neither the path nor the
    /// limit nor a way out. A home under `~` is nowhere near the limit; a home under a macOS
    /// temp directory, which is `/var/folders/<x>/<y>/T/` and half the budget before anything
    /// is named, is how this gets reached, and it is where the suite kept meeting it.
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

    /// The bug this guards: `UnixStream::connect(..).is_ok()` read every error as "the node is
    /// stopped". A control socket is created `srwxrwxr-x` inside a directory, so a home
    /// reached over a mount another user owns answers "stopped" about a node that is up.
    /// `restore --force` then wrote over storage a live node was holding, and `--stop-node`
    /// recorded a stop it never performed. Every answer it can give is walked in turn: nothing
    /// listening, somebody listening, and a question this process cannot put.
    #[cfg(unix)]
    #[test]
    fn a_socket_that_could_not_be_asked_is_not_reported_as_a_stopped_node() {
        use std::os::unix::fs::PermissionsExt as _;

        // Short on purpose: a unix socket path has a hard length limit, and the ordinary
        // scratch spends more than macOS allows before this test has named anything.
        let scratch = crate::key::tests::TestScratch::create_short("sock");
        let home = Home::at(scratch.path_of("home"));
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
        // Dropping the listener does not always unbind on the instant. Every subprocess
        // another test spawns holds a copy of this fd for the moment between `fork` and
        // `exec`, and a socket stays bound while any copy is open, so a connect made in that
        // window is accepted by a listener nobody owns any more. Measured at 646 connects in
        // 2000 with eight spawning threads, which is a run failing at random under load.
        // Waited out rather than probed once, because the state being asked about is "the
        // last copy of the fd is gone", and it arrives in microseconds.
        assert_eq!(settled_state(&home), NodeState::Stopped);

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
    }

    /// A link at a directory sends the whole restore out of the home, and an empty one hides
    /// it: the guard the shipped script had, and this one did not, checked the names files go
    /// to and never the directories holding them, so `keys` aimed elsewhere passed every check
    /// and the key went with it. An empty directory at the same name has to stay allowed,
    /// because `rad auth` leaves exactly that.
    // Unix only: it is about following a symlink, which is what `symlink` here needs to make.
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

        // One at a time, because a list that names two of the three says nothing about
        // whether the third is asked about at all.
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
    /// The arm asked `retired_path`, which answers with the first name that is FREE, so it
    /// was answered "nothing there" whatever the home held: the one thing this list exists to
    /// notice about a migrated home was unreachable. Both names are checked, because a second
    /// retirement takes a numbered one and only the first proves any is there.
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

        // A second retirement takes a numbered name, and the first can then be moved away by
        // hand: `retired_path` never reuses a freed name, so what is left is a home holding a
        // displaced key under a name no single-name probe would think to ask about.
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
    /// A test that wants the answer for an unowned socket file has to outlast the descriptors
    /// other tests' subprocesses are carrying, so `Running` is waited out. Any other answer is
    /// returned as it stands: `Unknown` is a verdict about this process, not a state that
    /// settles, and waiting on it would only turn a real regression into a slow one.
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
