//! End-to-end tests against the shipped binary, with `rad` and the network stubbed out.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The BIP-39 mnemonic for all-zero entropy, which rebuilds the same key on every run.
const WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon abandon abandon art";

/// The identity `WORDS` rebuilds.
///
/// A change in key derivation would orphan every printed recovery sheet, so this DID is
/// spelled out by hand.
const DID: &str = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp";

const KEY_PASSPHRASE: &str = "the key passphrase";
const ARCHIVE_PASSPHRASE: &str = "the archive passphrase";

const RID: &str = "z3gqcJUoA1n9HaHKufZs5FCSGazv5";

/// A fixture root short enough that a control socket still fits under it.
///
/// A restore probes `<home>/node/control.sock`, which must fit in `sun_path` (104 bytes on
/// macOS, 108 on Linux). The macOS temp directory is long, so `/tmp` is used when it would
/// not fit.
#[cfg(unix)]
fn scratch_root(name: &str) -> PathBuf {
    // The longest home a fixture names, plus the socket under it
    const DEEPEST: usize = "/identity-passphrase/node/control.sock".len();
    const SUN_LEN: usize = 104;

    let under_temp = std::env::temp_dir().join(name);
    match under_temp.as_os_str().len() + DEEPEST < SUN_LEN {
        true => under_temp,
        false => PathBuf::from("/tmp").join(name),
    }
}

#[cfg(not(unix))]
fn scratch_root(name: &str) -> PathBuf {
    std::env::temp_dir().join(name)
}

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    /// Builds a Radicle home with an identity, policies and one repository.
    fn create(name: &str) -> Self {
        let root = scratch_root(&format!("rad-backup-it-{name}-{}", std::process::id()));
        // The root holds a real secret key under a name guessable from the pid, so it must be
        // new and owner-only. The guard is armed before the first write, so a panic partway
        // through still cleans up.
        create_private_dir(&root).expect("the fixture root is creatable and was not already there");
        let fixture = Self { root };

        fixture.restore_from_words();
        fixture.write_config();
        fixture.write_policies();
        fixture.write_repository();
        fixture
    }

    fn home(&self) -> PathBuf {
        self.root.join("home")
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }

    fn restore_from_words(&self) {
        let ran = self.run_with_stdin(&["restore", "--words", "--yes"], &self.home(), WORDS);
        assert_success(&ran, "restoring the fixture identity from words");
        assert!(
            stderr(&ran).contains(DID),
            "the fixed mnemonic no longer rebuilds {DID}: {}",
            stderr(&ran)
        );
    }

    fn write_config(&self) {
        let config = r#"{"node":{"alias":"fixture","network":"main"},"cli":{"hints":true}}"#;
        std::fs::write(self.home().join("config.json"), config).expect("config is writable");
    }

    fn write_policies(&self) {
        let path = self.home().join("node/policies.db");
        std::fs::create_dir_all(path.parent().expect("it has a parent"))
            .expect("the node directory is creatable");
        let db = rusqlite::Connection::open(&path).expect("the policy database opens");
        db.execute_batch(
            r#"
            create table if not exists "following" (
              "id" text primary key not null,
              "alias" text default '',
              "policy" text default 'allow'
            ) strict;
            create table if not exists "seeding" (
              "id" text primary key not null,
              "scope" text default 'followed',
              "policy" text default 'allow'
            ) strict;
            insert into seeding values ('rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5', 'all', 'allow');
            insert into seeding values ('rad:z4Vg1Kh4RcCf7RyfhpUsAeMLuRuMS', 'followed', 'block');
            insert into following values ('z6MkFriend', 'friend', 'allow');
            "#,
        )
        .expect("the fixture policies are writable");
    }

    /// Writes a bare repository holding this peer's namespace.
    fn write_repository(&self) {
        let work = self.path("work");
        let storage = self.home().join("storage").join(RID);
        std::fs::create_dir_all(&work).expect("the working copy is creatable");

        git(&["init", "--quiet", "--initial-branch=master", "."], &work);
        std::fs::write(work.join("a.txt"), b"hello\n").expect("a file is writable");
        git(&["add", "."], &work);
        git(
            &[
                "-c",
                "user.email=fixture@example.com",
                "-c",
                "user.name=fixture",
                "commit",
                "--quiet",
                "-m",
                "first",
            ],
            &work,
        );
        git(
            &["init", "--quiet", "--bare", &storage.to_string_lossy()],
            &work,
        );
        // `rad` adds the node's alias and DID to a storage config, and a restore carries these
        // settings over, so tests about that carrying need them here
        for (name, value) in [
            ("user.name", "fixture".to_string()),
            ("user.email", format!("fixture@{DID}")),
        ] {
            git(
                &[
                    "--git-dir",
                    &storage.to_string_lossy(),
                    "config",
                    name,
                    &value,
                ],
                &work,
            );
        }
        self.publish(&work);
    }

    /// Pushes the working copy into this peer's namespace and signs it, as a node would.
    fn publish(&self, work: &Path) {
        let storage = self.home().join("storage").join(RID);
        let node_id = DID.trim_start_matches("did:key:");
        let namespace = format!("refs/namespaces/{node_id}");
        git(
            &[
                "push",
                "--quiet",
                "--force",
                &storage.to_string_lossy(),
                &format!("master:{namespace}/refs/heads/master"),
            ],
            work,
        );
        let head = git(&["rev-parse", "master"], work);
        git(
            &[
                "--git-dir",
                &storage.to_string_lossy(),
                "update-ref",
                &format!("{namespace}/refs/rad/sigrefs"),
                head.trim(),
            ],
            work,
        );
        git(
            &[
                "--git-dir",
                &storage.to_string_lossy(),
                "symbolic-ref",
                "HEAD",
                &format!("{namespace}/refs/heads/master"),
            ],
            work,
        );
    }

    /// Adds a commit and re-signs, so an archive taken earlier is behind this home.
    fn advance(&self) {
        let work = self.path("work");
        std::fs::write(work.join("a.txt"), b"hello again\n").expect("a file is writable");
        git(&["add", "."], &work);
        git(
            &[
                "-c",
                "user.email=fixture@example.com",
                "-c",
                "user.name=fixture",
                "commit",
                "--quiet",
                "-m",
                "second",
            ],
            &work,
        );
        self.publish(&work);
    }

    fn run(&self, args: &[&str], home: &Path) -> Output {
        self.command(args, home).output().expect("rad-backup runs")
    }

    fn run_with_stdin(&self, args: &[&str], home: &Path, input: &str) -> Output {
        use std::io::Write as _;

        let mut child = self
            .command(args, home)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("rad-backup starts");
        child
            .stdin
            .as_mut()
            .expect("stdin is piped")
            .write_all(format!("{input}\n").as_bytes())
            .expect("stdin is writable");
        child.wait_with_output().expect("rad-backup finishes")
    }

    /// Puts a stub `rad` where this fixture's runs find it, answering for a repository of
    /// the given `visibility`.
    ///
    /// The stub prints `STUB-RAD-UNSTUBBED` on stderr and fails on any call it was not taught.
    #[cfg(unix)]
    fn stub_rad(&self, visibility: &str) {
        use std::os::unix::fs::PermissionsExt as _;

        let bin = self.path("bin");
        std::fs::create_dir_all(&bin).expect("the stub directory is creatable");
        let private_listing = match visibility {
            "private" => format!("echo 'rad:{RID}  stub  a stub repository'"),
            _ => "true".to_string(),
        };
        let script = format!(
            r#"#!/bin/sh
case "$1" in
--version) echo "rad 1.0.0-stub" ;;
ls)
	case "$2" in
	--private) {private_listing} ;;
	*) echo 'rad:{RID}  stub  a stub repository' ;;
	esac
	;;
inspect)
	[ "$3" = "--identity" ] || exit 1
	printf '%s
' '{{"payload":{{"xyz.radicle.project":{{"name":"stub"}}}},"delegates":["did:key:{DID}"],"visibility":{{"type":"{visibility}"}}}}'
	;;
*)
	echo "STUB-RAD-UNSTUBBED: $*" >&2
	exit 1
	;;
esac
"#
        );
        let path = bin.join("rad");
        std::fs::write(&path, script).expect("the stub is writable");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("the stub is executable");
    }

    fn command(&self, args: &[&str], home: &Path) -> Command {
        let stub = self.path("bin/rad");
        let mut command = Command::new(env!("CARGO_BIN_EXE_rad-backup"));
        command
            .args(args)
            .arg("--home")
            .arg(home)
            // A test run must never rewrite the real state that `doctor` reads
            .env("XDG_STATE_HOME", self.path("state"))
            .env("RAD_PASSPHRASE", KEY_PASSPHRASE)
            .env("RAD_BACKUP_PASSPHRASE", ARCHIVE_PASSPHRASE)
            .env("NO_COLOR", "1")
            // A real `rad` on PATH would reach for a node this fixture does not have
            .env(
                "RAD",
                match stub.is_file() {
                    true => stub,
                    false => PathBuf::from("/nonexistent/rad"),
                },
            );
        command
    }
}

/// Creates an owner-only directory, failing when the path exists, as `crate::perms` does.
#[cfg(unix)]
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;

    std::fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir(path)
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn git(args: &[&str], cwd: &Path) -> String {
    let ran = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("git runs");
    assert!(
        ran.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&ran.stderr)
    );
    String::from_utf8_lossy(&ran.stdout).into_owned()
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::metadata(path)
        .expect("the file is there")
        .permissions()
        .mode()
}

fn stderr(ran: &Output) -> String {
    String::from_utf8_lossy(&ran.stderr).into_owned()
}

fn stdout(ran: &Output) -> String {
    String::from_utf8_lossy(&ran.stdout).into_owned()
}

fn assert_success(ran: &Output, what: &str) {
    assert!(
        ran.status.success(),
        "{what} exited {:?}: {}",
        ran.status.code(),
        stderr(ran)
    );
}

/// Asserts exit `3`, a run that did what it was asked and could not finish a check.
///
/// A restore in this suite exits `3` whenever it reaches the network comparison, because the
/// fixtures carry no `rad`.
fn assert_checks_failed(ran: &Output, what: &str) {
    assert_eq!(
        ran.status.code(),
        Some(3),
        "{what} should have reported an unfinished check: {}",
        stderr(ran)
    );
}

/// A restore with `--no-reconcile` exits `0`, and the same restore without it exits `3`.
#[test]
fn a_comparison_that_was_declined_is_not_a_comparison_that_failed() {
    let fixture = Fixture::create("declined-comparison");
    let backups = fixture.path("backups");

    let ran = fixture.run(
        &[
            "--tier",
            "full",
            "--output",
            &backups.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    assert_success(&ran, "taking a full backup");
    let archive = only_archive(&backups);

    let asked = fixture.path("asked");
    let ran = fixture.run(&["restore", "--yes", &archive.to_string_lossy()], &asked);
    assert_checks_failed(&ran, "a restore whose comparison could not run");

    let declined = fixture.path("declined");
    let ran = fixture.run(
        &[
            "restore",
            "--yes",
            "--no-reconcile",
            &archive.to_string_lossy(),
        ],
        &declined,
    );
    assert_success(&ran, "a restore whose comparison was declined");
    assert!(
        declined.join("keys/radicle").is_file(),
        "the identity came back whichever way the comparison went: {}",
        stderr(&ran)
    );
}

/// The installed shells the shipped script must behave the same under.
///
/// Fails on Linux CI when any is missing, because the workflow installs all four. Elsewhere
/// the list is only printed. On Debian and Ubuntu `sh` is `dash`, so one shell runs twice.
#[cfg(unix)]
fn probe_shells() -> Vec<&'static str> {
    const WANTED: [&str; 4] = ["sh", "dash", "bash", "busybox"];

    // A shell that fails to spawn is not installed. `--version` itself is not portable.
    let shells: Vec<&str> = WANTED
        .into_iter()
        .filter(|shell| Command::new(shell).arg("--version").output().is_ok())
        .collect();
    assert!(
        shells.contains(&"sh"),
        "no POSIX shell to run the archive's own reader with"
    );
    eprintln!(
        "the shipped script was checked under: {}",
        shells.join(", ")
    );
    if std::env::var_os("CI").is_some() && cfg!(target_os = "linux") {
        for wanted in WANTED {
            assert!(
                shells.contains(&wanted),
                "CI is meant to run this under {wanted}, which is not installed"
            );
        }
    }
    shells
}

/// Runs a fragment of the shipped script under `shell` and `set -eu`, with `variables`
/// exported.
///
/// The shipped script opens with `set -eu`, so a fragment run without it misses an unset
/// variable or an unchecked status that aborts the real restore.
#[cfg(unix)]
fn under_shell(shell: &str, fragment: &str, variables: &[(&str, &str)]) -> Output {
    let mut command = Command::new(shell);
    if shell == "busybox" {
        command.arg("ash");
    }
    command.arg("-c").arg(format!("set -eu\n{fragment}"));
    for (name, value) in variables {
        command.env(name, value);
    }
    command
        .output()
        .unwrap_or_else(|e| panic!("{shell} runs: {e}"))
}

/// Whether this machine has `jq`, failing on Linux CI where the workflow installs it.
///
/// The shipped script reads `head` with `jq`, so without it every repository comes back with
/// no HEAD. Elsewhere a missing `jq` prints what `what` skipped.
#[cfg(unix)]
fn probe_jq(what: &str) -> bool {
    if Command::new("jq").arg("--version").output().is_ok() {
        return true;
    }
    assert!(
        !(std::env::var_os("CI").is_some() && cfg!(target_os = "linux")),
        "CI installs jq, and without it this checks nothing: {what}"
    );
    eprintln!("skipping {what}: no jq here, which is what reads `head` in the shipped script");
    false
}

fn only_archive(directory: &Path) -> PathBuf {
    let mut archives: Vec<PathBuf> = std::fs::read_dir(directory)
        .expect("the backup directory is readable")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "age" || extension == "zst")
        })
        .collect();
    archives.sort();
    assert_eq!(archives.len(), 1, "expected one archive in {directory:?}");
    archives.remove(0)
}

/// `--replay-policies` needs `rad`, so without one the restore exits `4` before writing.
#[test]
fn a_restore_refused_for_want_of_rad_leaves_the_home_untouched() {
    let fixture = Fixture::create("restore-replay-without-rad");
    let backups = fixture.path("backups");

    let ran = fixture.run(
        &[
            "--tier",
            "full",
            "--output",
            &backups.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    assert_success(&ran, "taking a full backup");
    let archive = only_archive(&backups);

    let restored = fixture.path("restored");
    let ran = fixture.run(
        &[
            "restore",
            "--replay-policies",
            "--yes",
            &archive.to_string_lossy(),
        ],
        &restored,
    );
    let said = stderr(&ran);

    assert_eq!(
        ran.status.code(),
        Some(4),
        "a flag that cannot be honoured is a refusal: {said}"
    );
    assert!(
        !restored.join("keys/radicle").exists(),
        "exit 4 promises an untouched home: {said}"
    );
}

#[test]
fn without_git_a_restore_says_no_repositories_came_back_instead_of_reporting_success() {
    let fixture = Fixture::create("restore-without-git");
    let backups = fixture.path("backups");

    let ran = fixture.run(
        &[
            "--tier",
            "full",
            "--output",
            &backups.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    assert_success(&ran, "taking a full backup");
    let archive = only_archive(&backups);

    let restored = fixture.path("restored");
    let ran = fixture
        .command(&["restore", "--yes", &archive.to_string_lossy()], &restored)
        .env("GIT", "/nonexistent/git")
        .output()
        .expect("rad-backup runs");
    let said = stderr(&ran);

    assert!(
        restored.join("keys/radicle").is_file(),
        "the identity should still be restored: {said}"
    );
    // A scheduled restore that exits 0 with every repository missing goes unnoticed
    assert_eq!(
        ran.status.code(),
        Some(3),
        "a restore that dropped every repository must not exit 0: {said}"
    );
    assert!(
        said.contains("no repositories were restored"),
        "it has to say so plainly: {said}"
    );
    assert!(
        said.contains(RID),
        "the repositories it could not restore must be named: {said}"
    );
    // The run deletes its scratch directory on the way out, so no hint may point there. The
    // Windows permissions warning names it too, without sending the reader there.
    let scratch_hint = said
        .lines()
        .filter(|line| !line.contains("cannot restrict a file to one user"))
        .find(|line| line.contains(".rad-backup") || line.contains("staging"));
    assert_eq!(
        scratch_hint, None,
        "it must not offer a path this run is about to delete: {said}"
    );
}

#[test]
fn a_full_archive_restores_an_identity_its_policies_and_its_repositories_byte_for_byte() {
    let fixture = Fixture::create("roundtrip");
    let backups = fixture.path("backups");

    let ran = fixture.run(
        &[
            "--tier",
            "full",
            "--output",
            &backups.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    assert_success(&ran, "taking a full backup");
    let archive = only_archive(&backups);

    let ran = fixture.run(
        &["verify", "--deep", &archive.to_string_lossy()],
        &fixture.home(),
    );
    assert_success(&ran, "verifying the archive");
    assert!(stderr(&ran).contains(DID), "{}", stderr(&ran));

    let restored = fixture.path("restored");
    let ran = fixture.run(&["restore", "--yes", &archive.to_string_lossy()], &restored);
    assert_checks_failed(&ran, "restoring the archive");

    let before = std::fs::read(fixture.home().join("keys/radicle")).expect("the key is readable");
    let after = std::fs::read(restored.join("keys/radicle")).expect("the restored key is readable");
    assert_eq!(before, after, "the restored key is not the archived one");

    let storage = restored.join("storage").join(RID);
    let refs = git(
        &["--git-dir", &storage.to_string_lossy(), "for-each-ref"],
        &restored,
    );
    assert!(refs.contains("/refs/rad/sigrefs"), "{refs}");
    assert!(refs.contains("/refs/heads/master"), "{refs}");
    let head = git(
        &[
            "--git-dir",
            &storage.to_string_lossy(),
            "symbolic-ref",
            "HEAD",
        ],
        &restored,
    );
    assert!(head.contains("refs/namespaces/"), "{head}");

    let db = rusqlite::Connection::open(restored.join("node/policies.db"))
        .expect("the restored policy database opens");
    let seeded: i64 = db
        .query_row("select count(*) from seeding", [], |row| row.get(0))
        .expect("the seeding table survives");
    assert_eq!(seeded, 2);
}

#[test]
fn an_archive_that_lost_a_byte_fails_verification_instead_of_restoring_quietly() {
    let fixture = Fixture::create("damaged");
    let backups = fixture.path("backups");

    let ran = fixture.run(
        &[
            "--plaintext",
            "--repos",
            "none",
            "--output",
            &backups.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    assert_success(&ran, "taking a plaintext backup");
    let archive = only_archive(&backups);

    // The archive is plaintext, so the manifest's digests catch the damage. About one
    // single-byte flip in five thousand still decodes to an intact tar, so a run is flipped.
    let mut bytes = std::fs::read(&archive).expect("the archive is readable");
    let middle = bytes.len() / 2;
    for byte in &mut bytes[middle..middle + 64] {
        *byte ^= 0xff;
    }
    std::fs::write(&archive, &bytes).expect("the archive is writable");

    let ran = fixture.run(&["verify", &archive.to_string_lossy()], &fixture.home());
    assert!(
        !ran.status.success(),
        "a damaged archive verified clean: {}",
        stderr(&ran)
    );
}

#[test]
fn verify_deep_without_git_says_in_one_readable_sentence_what_it_could_not_open() {
    let fixture = Fixture::create("verify-deep-without-git");
    let backups = fixture.path("backups");

    let ran = fixture.run(
        &[
            "--tier",
            "full",
            "--output",
            &backups.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    assert_success(&ran, "taking a full backup");
    let archive = only_archive(&backups);

    let ran = fixture
        .command(
            &["verify", "--deep", &archive.to_string_lossy()],
            &fixture.home(),
        )
        .env("GIT", "/nonexistent/git")
        .output()
        .expect("rad-backup runs");
    let said = stderr(&ran);

    // Neither `cargo fmt` nor clippy sees continuation indentation left inside a literal
    assert!(
        said.contains("1 repository in this archive could not be checked"),
        "the sentence has to read as one: {said}"
    );
    assert!(
        !said.contains("  not checked"),
        "no run of spaces inside the sentence: {said}"
    );

    // An unopened repository shows as an absent check, so a script cannot mistake it for a
    // broken archive
    let ran = fixture
        .command(
            &["verify", "--deep", "--json", &archive.to_string_lossy()],
            &fixture.home(),
        )
        .env("GIT", "/nonexistent/git")
        .output()
        .expect("rad-backup runs");
    let report: serde_json::Value =
        serde_json::from_str(&stdout(&ran)).expect("the verify report is json");
    assert_eq!(report["passed"], false, "{report}");
    let checks = report["checks"]
        .as_array()
        .expect("the report lists checks");
    assert!(
        !checks
            .iter()
            .any(|check| check["checkId"] == "repositories"),
        "{report}"
    );
    assert!(
        checks.iter().any(|check| check["checkId"] == "public-key"),
        "the other deep checks still ran: {report}"
    );
}

#[test]
fn diff_is_quiet_until_the_home_moves_on_and_then_says_which_repository_did() {
    let fixture = Fixture::create("diff");
    let backups = fixture.path("backups");

    let ran = fixture.run(
        &[
            "--tier",
            "full",
            "--output",
            &backups.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    assert_success(&ran, "taking a full backup");

    let ran = fixture.run(&["diff"], &fixture.home());
    assert_success(&ran, "diffing an unchanged home");

    // One followed peer swapped for another leaves every count equal. A scheduled
    // `diff || backup` must still take the archive, because a restore would bring back the
    // old peer.
    let db = rusqlite::Connection::open(fixture.home().join("node/policies.db"))
        .expect("the policy database opens");
    db.execute_batch(
        "delete from following where id = 'z6MkFriend';
         insert into following values ('z6MkStranger', '', 'allow');",
    )
    .expect("the followed peer is swappable");
    let ran = fixture.run(&["diff", "--json"], &fixture.home());
    assert_eq!(
        ran.status.code(),
        Some(3),
        "a swapped peer is drift: {}",
        stderr(&ran)
    );
    let report: serde_json::Value =
        serde_json::from_str(&stdout(&ran)).expect("--json prints json");
    assert_eq!(
        report["policies"]["followed"],
        serde_json::json!({"added": ["z6MkStranger"], "removed": ["z6MkFriend"]})
    );

    fixture.advance();

    let ran = fixture.run(&["diff", "--json"], &fixture.home());
    assert_eq!(
        ran.status.code(),
        Some(3),
        "a changed home should exit 3: {}",
        stderr(&ran)
    );
    let report: serde_json::Value =
        serde_json::from_str(&stdout(&ran)).expect("--json prints json");
    assert_eq!(report["changed"], serde_json::Value::Bool(true));
    assert_eq!(
        report["repositoriesMoved"],
        serde_json::json!([format!("rad:{RID}")])
    );
}

/// Takes a `--repos private` archive with a stub `rad`, returning its manifest and stderr.
#[cfg(unix)]
fn private_run(name: &str, visibility: &str) -> (serde_json::Value, String) {
    let fixture = Fixture::create(name);
    fixture.stub_rad(visibility);
    let backups = fixture.path("backups");

    let ran = fixture.run(
        &[
            "--tier",
            "full",
            "--repos",
            "private",
            "--plaintext",
            "--output",
            &backups.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    assert_success(&ran, "taking a private-selection archive");
    let said = stderr(&ran).to_string();

    // Without this check the test passes against a `rad` that fails every call
    assert!(!said.contains("STUB-RAD-UNSTUBBED"), "{said}");

    let archive = only_archive(&backups);
    let shown = fixture.run(
        &["show", "--json", &archive.to_string_lossy()],
        &fixture.home(),
    );
    assert_success(&shown, "showing the archive");
    let manifest: serde_json::Value =
        serde_json::from_slice(&shown.stdout).expect("the report is json");
    assert_eq!(
        manifest["source"]["radVersion"], "rad 1.0.0-stub",
        "the run did not go through the stub at all"
    );
    (manifest, said)
}

#[test]
#[cfg(unix)]
fn a_private_selection_carries_the_repository_rad_calls_private() {
    let (manifest, _said) = private_run("private-yes", "private");

    let repo = &manifest["repos"][0];
    assert_eq!(repo["visibility"], "private", "{manifest}");
    assert_eq!(repo["name"], "stub", "{manifest}");
    assert!(
        !repo["bundle"].is_null(),
        "a private repository was left out of a --repos private archive: {manifest}"
    );
}

#[test]
#[cfg(unix)]
fn a_private_selection_leaves_out_the_repository_rad_calls_public() {
    let (manifest, said) = private_run("private-no", "public");

    let repo = &manifest["repos"][0];
    assert_eq!(repo["visibility"], "public", "{manifest}");
    assert!(
        repo["bundle"].is_null(),
        "a public repository was carried by a --repos private archive: {manifest}"
    );

    // An archive that carries none of the repositories it was taken for says so in the summary
    assert!(
        said.contains("saved: your key, 0 private repositories,"),
        "{said}"
    );
}

#[test]
fn a_state_archive_carries_the_paperwork_but_not_the_repositories() {
    let fixture = Fixture::create("state-tier");
    let backups = fixture.path("backups");

    let ran = fixture.run(
        &["--output", &backups.to_string_lossy(), "--yes"],
        &fixture.home(),
    );
    // Without `rad` the default private selection cannot see which repository is private and
    // carries none. The run still writes the archive, and exits 3 so a timer hears.
    assert_checks_failed(
        &ran,
        "a state backup that could not tell private repositories apart",
    );
    let archive = only_archive(&backups);

    let ran = fixture.run(
        &["show", "--json", &archive.to_string_lossy()],
        &fixture.home(),
    );
    assert_success(&ran, "showing the archive");
    let manifest: serde_json::Value =
        serde_json::from_str(&stdout(&ran)).expect("--json prints json");

    assert_eq!(manifest["tier"], "state");
    let entries: Vec<String> = manifest["entries"]
        .as_array()
        .expect("entries is an array")
        .iter()
        .map(|entry| entry["path"].as_str().unwrap_or_default().to_string())
        .collect();
    assert!(entries.contains(&"keys/radicle".to_string()), "{entries:?}");
    assert!(
        entries.contains(&"node/policies.db".to_string()),
        "{entries:?}"
    );
    assert!(
        !entries.iter().any(|path| path.ends_with(".bundle")),
        "a state archive carried repository data: {entries:?}"
    );

    // The manifest still describes the repository it carries no bundle for
    let repos = manifest["repos"].as_array().expect("repos is an array");
    assert_eq!(repos.len(), 1);
    assert_eq!(repos[0]["rid"], format!("rad:{RID}"));
    assert!(repos[0]["bundle"].is_null());
}

#[cfg(unix)]
#[test]
fn the_note_beside_an_archive_replaces_a_symlink_at_its_name_and_not_its_target() {
    let fixture = Fixture::create("note-symlink");
    let backups = fixture.path("backups");
    create_private_dir(&backups).expect("the backup directory is creatable");
    let archive = backups.join("named.tar.zst");
    let victim = fixture.path("victim");
    std::fs::write(&victim, b"not the note").expect("the victim is writable");
    std::os::unix::fs::symlink(&victim, backups.join("named.tar.zst.README.txt"))
        .expect("a symlink is creatable");

    let ran = fixture.run(
        &[
            "--tier",
            "identity",
            "--plaintext",
            "--output",
            &archive.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    assert_success(&ran, "a backup beside a planted symlink");

    assert_eq!(
        std::fs::read_to_string(&victim).expect("the victim is readable"),
        "not the note"
    );
    let note = backups.join("named.tar.zst.README.txt");
    assert!(
        !std::fs::symlink_metadata(&note)
            .expect("the note is there")
            .is_symlink()
    );
    let written = std::fs::read_to_string(&note).expect("the note is readable");
    assert!(written.contains("named.tar.zst"), "{written}");
}

#[test]
fn restoring_into_an_occupied_home_is_refused_before_anything_is_overwritten() {
    let fixture = Fixture::create("occupied");
    let backups = fixture.path("backups");

    let ran = fixture.run(
        &[
            "--repos",
            "none",
            "--output",
            &backups.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    assert_success(&ran, "taking a backup");
    let archive = only_archive(&backups);

    let before = std::fs::read(fixture.home().join("keys/radicle")).expect("the key is readable");
    let ran = fixture.run(
        &["restore", "--yes", &archive.to_string_lossy()],
        &fixture.home(),
    );
    assert_eq!(ran.status.code(), Some(4), "{}", stderr(&ran));
    let after = std::fs::read(fixture.home().join("keys/radicle")).expect("the key is readable");
    assert_eq!(before, after, "a refused restore still touched the key");
}

/// A link at `keys`, `node` or `storage` needs consent before a restore writes through it.
///
/// `--yes` gives that consent, `--force` does not, and a run with nobody to ask refuses.
#[cfg(unix)]
#[test]
fn a_home_whose_directories_point_elsewhere_is_asked_about_and_never_assumed() {
    let fixture = Fixture::create("linked-dirs");
    let backups = fixture.path("backups");

    // The full tier gives an accepted restore a repository to write through the link
    let ran = fixture.run(
        &[
            "--tier",
            "full",
            "--output",
            &backups.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    assert_success(&ran, "taking a backup");
    let archive = only_archive(&backups);
    let named = archive.to_string_lossy().to_string();

    // One link at a time, so a check firing for `keys` proves nothing about the other two
    for name in ["keys", "node", "storage"] {
        let home = fixture.path(&format!("one-{name}"));
        let elsewhere = fixture.path(&format!("one-elsewhere-{name}"));
        std::fs::create_dir_all(&home).expect("the home is creatable");
        std::fs::create_dir_all(&elsewhere).expect("the directory pointed at is creatable");
        std::os::unix::fs::symlink(&elsewhere, home.join(name)).expect("a symlink is creatable");

        // The suite's runs are not interactive, so without `--yes` there is nobody to ask
        let ran = fixture.run(&["restore", &named], &home);
        let said = stderr(&ran);
        assert_eq!(ran.status.code(), Some(4), "{said}");
        assert!(said.contains(&format!("{name} is a symlink")), "{said}");
        assert!(
            said.contains(&elsewhere.display().to_string()),
            "the question has to name where the link leads: {said}"
        );
        assert_eq!(
            std::fs::read_dir(&elsewhere)
                .expect("the directory pointed at is listable")
                .count(),
            0,
            "a restore nobody consented to wrote through the link: {said}"
        );
    }

    // `--force` lets a restore overwrite what is in the home, never write outside it
    let home = fixture.path("forced");
    let elsewhere = fixture.path("forced-elsewhere");
    std::fs::create_dir_all(&home).expect("the home is creatable");
    std::fs::create_dir_all(&elsewhere).expect("the directory pointed at is creatable");
    std::os::unix::fs::symlink(&elsewhere, home.join("storage")).expect("a symlink is creatable");
    let ran = fixture.run(&["restore", "--force", &named], &home);
    assert_eq!(ran.status.code(), Some(4), "{}", stderr(&ran));

    // `--yes` lets a user who made the link on purpose restore through it
    let ran = fixture.run(&["restore", "--yes", &named], &home);
    assert_checks_failed(&ran, "restoring through a link the run was told to accept");
    assert!(
        std::fs::read_dir(&elsewhere)
            .expect("the directory pointed at is listable")
            .count()
            > 0,
        "an accepted restore should have written through the link"
    );
}

/// `--words` writes into `keys` without an archive, so it skips the archive restore's checks.
#[cfg(unix)]
#[test]
fn rebuilding_from_words_asks_about_a_linked_keys_directory_before_writing_a_key() {
    let fixture = Fixture::create("words-linked-dir");
    let home = fixture.path("linked");
    let elsewhere = fixture.path("keys-elsewhere");
    std::fs::create_dir_all(&home).expect("the home is creatable");
    std::fs::create_dir_all(&elsewhere).expect("the directory pointed at is creatable");
    std::os::unix::fs::symlink(&elsewhere, home.join("keys")).expect("a symlink is creatable");

    let ran = fixture.run_with_stdin(&["restore", "--words"], &home, WORDS);
    let said = stderr(&ran);
    assert_eq!(ran.status.code(), Some(4), "{said}");
    assert_eq!(
        std::fs::read_dir(&elsewhere)
            .expect("the directory pointed at is listable")
            .count(),
        0,
        "a key was written through the link: {said}"
    );
}

/// A link at the repository's own name inside a real `storage`, which the check over the
/// home's three directories cannot see.
#[cfg(unix)]
#[test]
fn a_repository_whose_directory_points_out_of_storage_is_dropped_and_not_restored() {
    let fixture = Fixture::create("linked-repo");
    let backups = fixture.path("backups");

    // The default tier carries no repositories
    let ran = fixture.run(
        &[
            "--tier",
            "full",
            "--output",
            &backups.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    assert_success(&ran, "taking a backup");
    let archive = only_archive(&backups);

    let home = fixture.path("linked-storage");
    let elsewhere = fixture.path("repo-elsewhere");
    std::fs::create_dir_all(home.join("storage")).expect("storage is creatable");
    std::fs::create_dir_all(&elsewhere).expect("the directory pointed at is creatable");
    std::os::unix::fs::symlink(&elsewhere, home.join("storage").join(RID))
        .expect("a symlink is creatable");

    // The link makes `storage` occupied, so `--force` is needed to reach the repository
    let ran = fixture.run(
        &["restore", "--force", "--yes", &archive.to_string_lossy()],
        &home,
    );
    let said = stderr(&ran);
    assert!(said.contains("is a symlink"), "{said}");
    assert_eq!(ran.status.code(), Some(3), "{said}");
    assert_eq!(
        std::fs::read_dir(&elsewhere)
            .expect("the directory pointed at is listable")
            .count(),
        0,
        "the repository was restored through the link: {said}"
    );
}

/// A restore fetches every bundle with `--force`, rewinding every stored ref, so stored
/// repositories make a home occupied even with no key.
#[test]
fn a_home_with_repositories_and_no_key_is_still_occupied() {
    let fixture = Fixture::create("keyless-occupied");
    let backups = fixture.path("backups");

    let ran = fixture.run(
        &[
            "--repos",
            "none",
            "--output",
            &backups.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    assert_success(&ran, "taking a backup");
    let archive = only_archive(&backups);

    // `move` leaves no key and every repository still there
    std::fs::remove_file(fixture.home().join("keys/radicle")).expect("the key is removable");
    let repositories = files_under(&fixture.home().join("storage"));
    assert!(!repositories.is_empty(), "the fixture has repositories");

    let ran = fixture.run(
        &["restore", "--yes", &archive.to_string_lossy()],
        &fixture.home(),
    );
    let said = stderr(&ran);
    assert_eq!(ran.status.code(), Some(4), "{said}");
    assert!(said.contains("stored repositories"), "{said}");
    assert_eq!(
        files_under(&fixture.home().join("storage")),
        repositories,
        "a refused restore still touched storage"
    );
}

/// The file names leak, such as every DID this machine keeps a record for.
#[cfg(unix)]
#[test]
fn a_directory_this_tool_makes_is_owner_only_and_not_only_the_files_in_it() {
    let fixture = Fixture::create("owner-only-dirs");
    assert_eq!(mode(&fixture.home()) & 0o777, 0o700, "the home itself");
    assert_eq!(
        mode(&fixture.home().join("keys")) & 0o777,
        0o700,
        "the keys directory a recovery sheet rebuilt"
    );

    let backups = fixture.path("backups");
    let ran = fixture.run(
        &[
            "--tier",
            "identity",
            "--output",
            &backups.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    assert_success(&ran, "taking an archive, which writes the state record");
    assert_eq!(
        mode(&fixture.path("state/rad-backup")) & 0o777,
        0o700,
        "the state directory: {}",
        stderr(&ran)
    );
}

/// The homes this tool and the shipped script restored from one archive, with their stderr.
#[cfg(unix)]
struct BothWays {
    by_tool: PathBuf,
    tool_said: String,
    by_script: PathBuf,
    script_said: String,
}

#[cfg(unix)]
impl BothWays {
    /// The settings git reads from the restored repository's config.
    ///
    /// Fails on a config git refuses to read, which a text assertion would pass over.
    fn settings(&self, home: &Path) -> String {
        let repo = home.join(format!("storage/{RID}"));
        // `--local` keeps the global git config of whoever runs the suite out of the answer
        let ran = Command::new("git")
            .args([
                "--git-dir",
                &repo.to_string_lossy(),
                "config",
                "--local",
                "--list",
            ])
            .output()
            .expect("git runs");
        assert_success(&ran, "reading the restored repository's config");
        stdout(&ran)
    }

    fn is_bare(&self, home: &Path) -> bool {
        let repo = home.join(format!("storage/{RID}"));
        let ran = Command::new("git")
            .args([
                "--git-dir",
                &repo.to_string_lossy(),
                "rev-parse",
                "--is-bare-repository",
            ])
            .output()
            .expect("git runs");
        assert_success(&ran, "opening the restored repository");
        stdout(&ran).trim() == "true"
    }
}

#[cfg(unix)]
fn restore_with_planted_config(fixture: &Fixture, planted: &str) -> BothWays {
    let backups = fixture.path("backups");
    let ran = fixture.run(
        &[
            "--tier",
            "full",
            "--plaintext",
            "--output",
            &backups.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    assert_success(&ran, "taking a full archive");

    // A hostile archive carries a matching size and digest, so the manifest is rewritten too
    let archive = repack_with(fixture, &only_archive(&backups), |extracted| {
        let entry = format!("repos/{RID}.config");
        std::fs::write(extracted.join(&entry), planted).expect("the planted config is writable");
        rewrite_manifest_entry(extracted, &entry, planted.as_bytes());
    });

    let by_tool = fixture.path("by-tool");
    let ran = fixture.run(&["restore", "--yes", &archive.to_string_lossy()], &by_tool);
    let tool_said = stderr(&ran);

    let extracted = fixture.path("by-hand");
    std::fs::create_dir_all(&extracted).expect("the extraction directory is creatable");
    let bytes = std::fs::read(&archive).expect("the archive is readable");
    let mut tarball = Vec::new();
    zstd::stream::copy_decode(bytes.as_slice(), &mut tarball).expect("the archive decompresses");
    std::fs::write(extracted.join("archive.tar"), &tarball).expect("the tarball is writable");
    let ran = Command::new("tar")
        .args(["-xf", "archive.tar"])
        .current_dir(&extracted)
        .output()
        .expect("tar runs");
    assert_success(&ran, "extracting the archive");

    let by_script = fixture.path("by-script");
    let ran = Command::new("sh")
        .args(["restore.sh", &by_script.to_string_lossy()])
        .current_dir(&extracted)
        .env("HOME", fixture.path("fake-home"))
        .output()
        .expect("the restore script runs");
    assert_success(&ran, "restoring with the shipped script");
    let script_said = stderr(&ran);

    BothWays {
        by_tool,
        tool_said,
        by_script,
        script_said,
    }
}

/// git runs the value of `core.pager`, `core.fsmonitor` and an `ext::` remote URL on ordinary
/// operations, so neither reader may restore them.
#[cfg(unix)]
#[test]
fn a_repository_config_from_an_archive_cannot_carry_a_command_into_storage() {
    let fixture = Fixture::create("hostile-config");
    // `[user] name` is allowed and only the archive can supply it, so its arrival proves the
    // reader read the config
    let both = restore_with_planted_config(
        &fixture,
        "[core]\n\tbare = true\n\tpager = /tmp/rad-backup-pwn\n\
         \tfsmonitor = /tmp/rad-backup-pwn\n\
         [remote \"rad\"]\n\turl = ext::sh -c /tmp/rad-backup-pwn\n\
         [user]\n\tname = carried-from-the-archive\n",
    );

    for home in [&both.by_tool, &both.by_script] {
        let settings = both.settings(home);
        for gone in ["pager", "fsmonitor", "ext::", "rad-backup-pwn"] {
            assert!(
                !settings.contains(gone),
                "{gone} reached {}: {settings}",
                home.display()
            );
        }
        assert!(
            settings.contains("carried-from-the-archive"),
            "nothing was carried out of the config, so this proves nothing: {settings}"
        );
        assert!(both.is_bare(home), "{} is not bare", home.display());
    }
    // Both readers name each dropped setting
    for said in [&both.tool_said, &both.script_said] {
        assert!(said.contains("core.pager"), "{said}");
        assert!(said.contains("remote.rad.url"), "{said}");
    }
}

/// Every archive carries these settings, and a warning per repository would bury the one
/// about `core.pager`.
#[cfg(unix)]
#[test]
fn what_git_decides_for_itself_is_left_out_of_an_archive_without_a_warning() {
    let fixture = Fixture::create("quiet-config");
    let both = restore_with_planted_config(
        &fixture,
        "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = true\n\
         [user]\n\tname = carried-from-the-archive\n",
    );
    for said in [&both.tool_said, &both.script_said] {
        assert!(
            !said.contains("left out"),
            "an ordinary archive warned about the settings every archive carries: {said}"
        );
    }
    assert!(
        both.settings(&both.by_tool)
            .contains("carried-from-the-archive"),
        "the quiet path did not carry the name either, so this proves nothing"
    );
}

/// One unbalanced quote makes git refuse a whole config file, which would break every later
/// git command in that repository.
#[cfg(unix)]
#[test]
fn a_repository_config_the_archive_mangled_still_leaves_a_repository_that_opens() {
    let fixture = Fixture::create("mangled-config");
    let both =
        restore_with_planted_config(&fixture, "[core]\n\tbare = true\n[user]\n\tname = \"oops\n");
    for said in [&both.tool_said, &both.script_said] {
        assert!(
            said.contains("could not be read"),
            "a config git would not parse has to be said out loud: {said}"
        );
    }
    for home in [&both.by_tool, &both.by_script] {
        assert!(
            both.is_bare(home),
            "{} did not come back as a bare repository",
            home.display()
        );
    }
}

/// A key with no value reads as true in git, and written back it would become a name set to
/// the empty string.
#[cfg(unix)]
#[test]
fn a_config_value_that_reads_as_a_flag_is_a_value_and_a_valueless_key_is_neither() {
    let fixture = Fixture::create("aimed-config");
    let both = restore_with_planted_config(
        &fixture,
        "[core]\n\tbare = true\n[user]\n\temail = --unset\n\tname\n",
    );
    for home in [&both.by_tool, &both.by_script] {
        let settings = both.settings(home);
        assert!(
            settings.contains("user.email=--unset"),
            "a value that reads as a flag was not taken as a value: {settings}"
        );
        assert!(
            !settings.contains("user.name="),
            "a key with no value came back as a name set to nothing: {settings}"
        );
        assert!(both.is_bare(home), "{} is not bare", home.display());
    }
}

/// A directory at the note's name makes reading and writing the note fail after the rename.
#[test]
fn a_move_whose_note_cannot_be_written_still_says_where_the_key_went() {
    let fixture = Fixture::create("move-note");
    std::fs::create_dir(fixture.home().join("keys/RETIRED.txt"))
        .expect("the note's name is occupiable");

    let archive = fixture.path("moved.tar.zst");
    let ran = fixture.run(
        &["move", "--yes", &archive.to_string_lossy()],
        &fixture.home(),
    );
    assert_success(&ran, "moving the identity");

    let said = stderr(&ran);
    let retired = fixture.home().join("keys/radicle.retired");
    assert!(
        retired.is_file(),
        "the key must be retired whatever the note did: {said}"
    );
    assert!(
        said.contains("radicle.retired"),
        "the run must say where the key went: {said}"
    );
    // Windows prints `keys/RETIRED.txt` with its slash unconverted, so this joins per part
    let note = fixture.home().join("keys").join("RETIRED.txt");
    assert!(
        said.contains(&format!("could not read {}", note.display())),
        "a note that could not be read must be said out loud: {said}"
    );
}

#[test]
fn restoring_over_another_identity_keeps_the_key_it_displaces() {
    let fixture = Fixture::create("displaced");
    let backups = fixture.path("backups");

    let ran = fixture.run(
        &[
            "--tier",
            "identity",
            "--plaintext",
            "--output",
            &backups.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    assert_success(&ran, "taking an identity archive");
    let archive = only_archive(&backups);

    let occupied = fixture.path("occupied");
    std::fs::create_dir_all(occupied.join("keys")).expect("the home is creatable");
    let stranger = b"a key belonging to another identity";
    std::fs::write(occupied.join("keys/radicle"), stranger).expect("the key is writable");
    std::fs::write(
        occupied.join("keys/radicle.pub"),
        b"ssh-ed25519 AAAA stranger",
    )
    .expect("the public half is writable");

    let ran = fixture.run(
        &["restore", "--force", "--yes", &archive.to_string_lossy()],
        &occupied,
    );
    assert_success(&ran, "restoring over another identity");

    let retired = occupied.join("keys/radicle.retired");
    assert!(
        retired.is_file(),
        "the displaced key must be kept: {}",
        stderr(&ran)
    );
    assert_eq!(
        std::fs::read(&retired).expect("the retired key is readable"),
        stranger,
        "the retired file is not the key that was displaced"
    );
    // `with_extension` on `radicle.retired` gives `radicle.pub`, which renames the public
    // half onto itself and lets the restore overwrite it
    let retired_public = occupied.join("keys/radicle.retired.pub");
    assert_eq!(
        std::fs::read(&retired_public).expect("the retired public half is readable"),
        b"ssh-ed25519 AAAA stranger",
        "the retired public half is not the one that was displaced"
    );
    let note =
        std::fs::read_to_string(occupied.join("keys/DISPLACED.txt")).expect("the note is readable");
    assert!(note.contains("radicle.retired.pub"), "{note}");

    // The restore landed, so the exit above is no refusal reported as success
    assert_eq!(
        std::fs::read(occupied.join("keys/radicle")).expect("the restored key is readable"),
        std::fs::read(fixture.home().join("keys/radicle")).expect("the archived key is readable")
    );
    assert_eq!(
        std::fs::read(occupied.join("keys/radicle.pub")).expect("the restored half is readable"),
        std::fs::read(fixture.home().join("keys/radicle.pub")).expect("the archived half reads")
    );
}

/// Every tier's manifest summarises the policies, and only tiers above `identity` carry them.
#[test]
fn a_home_restored_without_policies_reports_no_drift_over_the_ones_it_never_got() {
    let fixture = Fixture::create("identity-tier-drift");
    let backups = fixture.path("backups");

    let ran = fixture.run(
        &[
            "--tier",
            "identity",
            "--output",
            &backups.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    assert_success(&ran, "taking an identity-tier backup");
    let archive = only_archive(&backups);

    // The fixture seeds and follows, so a record that took the summary would show as drift
    let restored = fixture.path("restored");
    let ran = fixture.run(&["restore", "--yes", &archive.to_string_lossy()], &restored);
    assert_success(&ran, "restoring an identity-tier archive");

    let ran = fixture.run(&["diff"], &restored);
    assert_success(
        &ran,
        "diffing a home restored from an identity-tier archive",
    );
}

#[test]
fn a_restored_home_knows_which_archive_it_came_from_and_reports_no_drift() {
    let fixture = Fixture::create("restored-state");
    let backups = fixture.path("backups");

    // A `state` archive describes the repository without carrying it
    let ran = fixture.run(
        &[
            "--repos",
            "none",
            "--output",
            &backups.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    assert_success(&ran, "taking a state backup");
    let archive = only_archive(&backups);

    let restored = fixture.path("restored");
    let ran = fixture.run(&["restore", "--yes", &archive.to_string_lossy()], &restored);
    assert_success(&ran, "restoring the archive");

    let ran = fixture.run(&["diff", "--json"], &restored);
    assert_success(&ran, "diffing a freshly restored home");
    let report: serde_json::Value =
        serde_json::from_str(&stdout(&ran)).expect("--json prints json");
    // A restore records which policies it put back, so the next diff compares them by id
    assert!(report["policies"].is_object(), "{report}");

    // The topic prints whatever the verdict is, so the detail and the archive's file name
    // carry the assertion
    let ran = fixture.run(&["doctor"], &restored);
    let said = stderr(&ran);
    let name = archive
        .file_name()
        .expect("the archive has a name")
        .to_string_lossy();
    assert!(
        said.contains("was taken") && said.contains(name.as_ref()),
        "a restored home should name the archive it came from: {said}"
    );
}

#[test]
fn with_no_archive_named_a_command_acts_on_the_newest_one_and_says_which() {
    let fixture = Fixture::create("newest");
    let backups = fixture.path("backups");
    let dir = backups.to_string_lossy().into_owned();

    let ran = fixture.run(
        &["--repos", "none", "--output", &dir, "--yes"],
        &fixture.home(),
    );
    assert_success(&ran, "taking the first archive");
    // The name carries a whole-second stamp, so two archives need a second between them
    std::thread::sleep(std::time::Duration::from_millis(1100));
    fixture.advance();
    let ran = fixture.run(
        &["--repos", "none", "--output", &dir, "--yes"],
        &fixture.home(),
    );
    assert_success(&ran, "taking the second archive");

    let mut archives: Vec<PathBuf> = std::fs::read_dir(&backups)
        .expect("the backup directory is readable")
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.to_string_lossy().ends_with(".age"))
        .collect();
    archives.sort();
    assert_eq!(archives.len(), 2, "two archives should exist");
    let newest = archives[1].to_string_lossy().into_owned();

    // RAD_BACKUP_DIR tells a command with no argument where to look
    let ran = fixture
        .command(&["show", "--json"], &fixture.home())
        .env("RAD_BACKUP_DIR", &dir)
        .output()
        .expect("rad-backup runs");
    assert_success(&ran, "showing the newest archive");
    assert!(
        stderr(&ran).contains(&newest),
        "the archive it chose must be named on stderr: {}",
        stderr(&ran)
    );
    let manifest: serde_json::Value =
        serde_json::from_str(&stdout(&ran)).expect("--json prints json");
    let shown = manifest["created"].as_str().expect("a created stamp");

    let ran = fixture
        .command(
            &["show", "--json", &archives[0].to_string_lossy()],
            &fixture.home(),
        )
        .output()
        .expect("rad-backup runs");
    let older: serde_json::Value = serde_json::from_str(&stdout(&ran)).expect("--json prints json");
    assert!(
        shown > older["created"].as_str().expect("a created stamp"),
        "the newest archive is the one that should have been chosen"
    );
}

#[test]
fn prune_deletes_older_archives_of_this_identity_and_nothing_else() {
    let fixture = Fixture::create("prune");
    let backups = fixture.path("backups");
    let dir = backups.to_string_lossy().into_owned();

    for _ in 0..2 {
        let ran = fixture.run(
            &["--repos", "none", "--output", &dir, "--yes"],
            &fixture.home(),
        );
        assert_success(&ran, "taking an archive");
        std::thread::sleep(std::time::Duration::from_millis(1100));
    }
    let bystander = backups.join("holiday-photos.tar.zst");
    let other = backups.join("someone-z6MkvAFBkdph-20200101T000000Z.tar.zst.age");
    std::fs::write(&bystander, b"not an archive").expect("the fixture file is writable");
    std::fs::write(&other, b"another identity").expect("the fixture file is writable");

    let ran = fixture.run(
        &["prune", "--keep", "1", "--dir", &dir, "--yes"],
        &fixture.home(),
    );
    assert_success(&ran, "pruning");

    let left: Vec<String> = std::fs::read_dir(&backups)
        .expect("the backup directory is readable")
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| !name.ends_with(".README.txt"))
        .collect();
    assert!(
        bystander.exists(),
        "a file this tool never wrote must survive"
    );
    assert!(other.exists(), "another identity's archive must survive");
    assert_eq!(
        left.iter()
            .filter(|name| name.starts_with("fixture-"))
            .count(),
        1,
        "exactly one archive of this identity should be left: {left:?}"
    );
}

#[test]
#[cfg(unix)]
fn keep_deletes_archives_missing_repositories_but_never_the_newest_complete_one() {
    let fixture = Fixture::create("keep-incomplete");
    let backups = fixture.path("backups");
    let dir = backups.to_string_lossy().into_owned();
    let archives = || -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&backups)
            .expect("the backup directory is readable")
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".age"))
            .collect();
        names.sort();
        names
    };

    // With `rad`, the default private selection carries the private repository
    fixture.stub_rad("private");
    let ran = fixture.run(&["--output", &dir, "--yes"], &fixture.home());
    assert_success(&ran, "taking the complete archive");
    let complete = archives();
    std::fs::remove_file(fixture.path("bin/rad")).expect("the stub is removable");

    // Without `rad` the selection carries no repositories. The first run proves the complete
    // archive outlives `--keep 1`, and the second that an incomplete one does not.
    let mut newest = Vec::new();
    for _ in 0..2 {
        std::thread::sleep(std::time::Duration::from_millis(1100));
        let before = archives();
        let ran = fixture.run(&["--keep", "1", "--output", &dir, "--yes"], &fixture.home());
        assert_eq!(ran.status.code(), Some(3), "{}", stderr(&ran));
        newest = archives()
            .into_iter()
            .filter(|name| !before.contains(name))
            .collect();
    }

    let mut expected = [complete, newest].concat();
    expected.sort();
    assert_eq!(archives(), expected);

    // A script may feed `prune`'s stdout to `rm`, so it must name nothing `prune` keeps
    let ran = fixture.run(
        &["prune", "--keep", "1", "--dir", &dir, "--dry-run"],
        &fixture.home(),
    );
    assert_success(&ran, "a dry-run prune");
    assert_eq!(stdout(&ran), "", "{}", stderr(&ran));
}

#[test]
fn a_dry_run_reports_what_it_would_carry_and_writes_nothing() {
    let fixture = Fixture::create("dry-run");
    let backups = fixture.path("backups");
    let dir = backups.to_string_lossy().into_owned();

    let ran = fixture.run(
        &["--dry-run", "--tier", "full", "--output", &dir],
        &fixture.home(),
    );
    assert_success(&ran, "a dry run");
    assert!(
        stderr(&ran).contains("nothing was written"),
        "a dry run must say that it wrote nothing: {}",
        stderr(&ran)
    );
    assert!(
        !backups.exists() || std::fs::read_dir(&backups).into_iter().flatten().count() == 0,
        "a dry run must leave the output directory empty"
    );
}

#[test]
fn a_dry_run_asked_for_json_answers_with_json() {
    let fixture = Fixture::create("dry-run-json");
    let dir = fixture.path("backups").to_string_lossy().into_owned();

    let ran = fixture.run(
        &["--dry-run", "--json", "--tier", "full", "--output", &dir],
        &fixture.home(),
    );
    assert_success(&ran, "a dry run asked for json");

    let report: serde_json::Value =
        serde_json::from_str(&stdout(&ran)).expect("--dry-run --json prints json");
    assert_eq!(report["dryRun"], serde_json::Value::Bool(true));
    assert_eq!(report["tier"], serde_json::Value::String("full".into()));
    assert_eq!(
        report["repos"][0]["rid"],
        serde_json::Value::String(format!("rad:{RID}"))
    );
}

/// A timer that reads only the exit status tells an incomplete backup apart by exit `3`.
#[test]
fn a_backup_that_lost_a_repository_writes_the_archive_and_still_exits_three() {
    let fixture = Fixture::create("incomplete");
    let backups = fixture.path("backups");

    // A file at `objects` breaks the repository for `git bundle`. A deleted repository would
    // read as one that was never there, which is not an error.
    let objects = fixture.home().join("storage").join(RID).join("objects");
    std::fs::remove_dir_all(&objects).expect("the object directory is removable");
    std::fs::write(&objects, b"not a directory").expect("something else goes in its place");

    let ran = fixture.run(
        &[
            "--tier",
            "full",
            "--plaintext",
            "--output",
            &backups.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    let said = stderr(&ran);

    assert_eq!(
        ran.status.code(),
        Some(3),
        "a backup missing a repository must not exit 0: {said}"
    );
    let archive = only_archive(&backups);
    assert!(archive.is_file(), "the archive should still exist: {said}");
    assert!(said.contains(RID), "it has to name what it lost: {said}");
}

// Windows has no shell for the shipped POSIX script
#[cfg(unix)]
#[test]
fn the_shipped_script_skips_a_bundle_whose_name_is_not_a_repository_id() {
    let fixture = Fixture::create("script-rid");
    let backups = fixture.path("backups");

    let ran = fixture.run(
        &[
            "--tier",
            "full",
            "--plaintext",
            "--output",
            &backups.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    assert_success(&ran, "taking a plaintext archive");

    let extracted = fixture.path("extracted");
    std::fs::create_dir_all(&extracted).expect("the extraction directory is creatable");
    let archive = std::fs::read(only_archive(&backups)).expect("the archive is readable");
    let mut tarball = Vec::new();
    zstd::stream::copy_decode(archive.as_slice(), &mut tarball).expect("the archive decompresses");
    std::fs::write(extracted.join("archive.tar"), &tarball).expect("the tarball is writable");
    let ran = Command::new("tar")
        .args(["-xf", "archive.tar"])
        .current_dir(&extracted)
        .output()
        .expect("tar runs");
    assert_success(&ran, "extracting the archive");

    // A name no `rad` would mint. The script skips that one bundle and restores the rest.
    std::fs::write(extracted.join("repos/a..b.bundle"), b"not a bundle")
        .expect("the planted bundle is writable");

    let target = fixture.path("by-script");
    let ran = Command::new("sh")
        .args(["restore.sh", &target.to_string_lossy()])
        .current_dir(&extracted)
        .env("HOME", fixture.path("fake-home"))
        .env("RAD_HOME", fixture.path("decoy-home"))
        .output()
        .expect("the restore script runs");
    assert_success(&ran, "restoring with a planted bundle present");
    assert!(
        stderr(&ran).contains("is not a repository id"),
        "{}",
        stderr(&ran)
    );
    assert!(
        !target.join("storage/a..b").exists(),
        "the script made a repository out of a name that is not an id"
    );

    assert!(target.join("storage").join(RID).is_dir());
}

// Windows has neither a shell for the shipped script nor the mode bits it sets
#[cfg(unix)]
#[test]
fn the_shipped_script_and_this_tool_rebuild_the_same_home() {
    if !probe_jq("what the shipped script restores against what this tool restores") {
        return;
    }
    let fixture = Fixture::create("parity");
    let backups = fixture.path("backups");

    let ran = fixture.run(
        &[
            "--tier",
            "full",
            "--plaintext",
            "--output",
            &backups.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    assert_success(&ran, "taking a plaintext archive");
    let archive = only_archive(&backups);

    let by_tool = fixture.path("by-tool");
    let ran = fixture.run(&["restore", "--yes", &archive.to_string_lossy()], &by_tool);
    assert_checks_failed(&ran, "restoring with this tool");

    let extracted = fixture.path("extracted");
    std::fs::create_dir_all(&extracted).expect("the extraction directory is creatable");
    let bytes = std::fs::read(&archive).expect("the archive is readable");
    let mut tarball = Vec::new();
    zstd::stream::copy_decode(bytes.as_slice(), &mut tarball).expect("the archive decompresses");
    std::fs::write(extracted.join("archive.tar"), &tarball).expect("the tarball is writable");
    let ran = Command::new("tar")
        .args(["-xf", "archive.tar"])
        .current_dir(&extracted)
        .output()
        .expect("tar runs");
    assert_success(&ran, "extracting the archive");

    let by_script = fixture.path("by-script");
    let ran = Command::new("sh")
        .args(["restore.sh", &by_script.to_string_lossy()])
        .current_dir(&extracted)
        .env("HOME", fixture.path("fake-home"))
        .env("RAD_HOME", fixture.path("decoy-home"))
        .output()
        .expect("the restore script runs");
    assert_success(&ran, "restoring with the shipped script");

    // SQLite makes its `-wal` and `-shm` files on whichever side opens a database first
    let names = |home: &Path| -> Vec<String> {
        let mut found: Vec<String> = files_under(home)
            .iter()
            .filter_map(|path| path.strip_prefix(home).ok())
            .map(|path| path.to_string_lossy().into_owned())
            .filter(|name| !name.ends_with("-wal") && !name.ends_with("-shm"))
            .collect();
        found.sort();
        found
    };
    assert_eq!(
        names(&by_tool),
        names(&by_script),
        "the two restores put back different sets of files"
    );

    for name in ["keys/radicle", "keys/radicle.pub", "config.json"] {
        assert_eq!(
            std::fs::read(by_tool.join(name)).expect("this tool restored it"),
            std::fs::read(by_script.join(name)).expect("the script restored it"),
            "{name} differs between the two restores"
        );
    }
    assert_eq!(
        mode(&by_tool.join("keys/radicle")) & 0o777,
        mode(&by_script.join("keys/radicle")) & 0o777,
        "the private key lands at different modes"
    );

    let storage = |home: &Path| {
        home.join("storage")
            .join(RID)
            .to_string_lossy()
            .into_owned()
    };
    let refs_of = |home: &Path| {
        let mut lines: Vec<String> = git(&["--git-dir", &storage(home), "for-each-ref"], home)
            .lines()
            .map(str::to_string)
            .collect();
        lines.sort();
        lines
    };
    assert_eq!(
        refs_of(&by_tool),
        refs_of(&by_script),
        "the two restores rebuilt different refs"
    );
    assert_eq!(
        git(
            &["--git-dir", &storage(&by_tool), "symbolic-ref", "HEAD"],
            &by_tool
        ),
        git(
            &["--git-dir", &storage(&by_script), "symbolic-ref", "HEAD"],
            &by_script
        ),
        "the two restores left HEAD pointing at different places"
    );

    // The two readers write settings in different orders, so the comparison is of what git
    // reads back
    let settings = |home: &Path| -> Vec<String> {
        let mut lines: Vec<String> = git(
            &["--git-dir", &storage(home), "config", "--local", "--list"],
            home,
        )
        .lines()
        .map(str::to_string)
        .collect();
        lines.sort();
        lines
    };
    assert_eq!(
        settings(&by_tool),
        settings(&by_script),
        "the two restores left different settings in the repository config"
    );

    let seeded = |home: &Path| -> i64 {
        rusqlite::Connection::open(home.join("node/policies.db"))
            .expect("the policy database opens")
            .query_row("select count(*) from seeding", [], |row| row.get(0))
            .expect("the seeding table survives")
    };
    assert_eq!(seeded(&by_tool), seeded(&by_script));
}

/// Every file under `directory`, recursively.
fn files_under(directory: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(directory) else {
        return found;
    };
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            found.extend(files_under(&path));
        } else {
            found.push(path);
        }
    }
    found
}

#[test]
fn a_run_leaves_nothing_readable_behind_and_what_it_writes_cannot_be_opened_without_the_passphrase()
{
    // The armour line marks any openssh private key, whichever key it is
    const ARMOUR: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----";
    const AGE_MAGIC: &[u8] = b"age-encryption.org/";

    let fixture = Fixture::create("hygiene");
    let backups = fixture.path("backups");
    let scratch = fixture.path("scratch");
    std::fs::create_dir_all(&scratch).expect("the scratch parent is creatable");

    let ran = fixture.run(
        &[
            "--tier",
            "full",
            "--output",
            &backups.to_string_lossy(),
            "--scratch-dir",
            &scratch.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    assert_success(&ran, "taking a full backup");

    assert_eq!(
        files_under(&scratch),
        Vec::<PathBuf>::new(),
        "the working directory outlived the run that made it"
    );
    for path in files_under(&backups) {
        let bytes = std::fs::read(&path).expect("what was written is readable");
        assert!(
            !contains(&bytes, ARMOUR),
            "{} holds a private key in the clear",
            path.display()
        );
    }

    // A merely compressed archive would also pass the search above, so this checks for age
    let archive = std::fs::read(only_archive(&backups)).expect("the archive is readable");
    assert!(archive.starts_with(AGE_MAGIC), "the archive is not age");
    let mut opened = Vec::new();
    assert!(
        zstd::stream::copy_decode(archive.as_slice(), &mut opened).is_err(),
        "the archive decompressed without a passphrase"
    );

    // The search must find the key in an archive that carries it, or it proves nothing
    let plain = fixture.path("plaintext");
    let ran = fixture.run(
        &[
            "--tier",
            "identity",
            "--plaintext",
            "--output",
            &plain.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    assert_success(&ran, "taking a plaintext archive");
    let archive = std::fs::read(only_archive(&plain)).expect("the archive is readable");
    let mut tar = Vec::new();
    zstd::stream::copy_decode(archive.as_slice(), &mut tar).expect("the archive decompresses");
    assert!(
        contains(&tar, ARMOUR),
        "the search cannot find a key that is definitely there, so it proves nothing"
    );
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

// Windows has neither a shell for the shipped script nor the mode bits it sets
#[test]
#[cfg(unix)]
fn the_shipped_restore_script_rebuilds_a_home_without_this_tool() {
    let fixture = Fixture::create("script");
    let backups = fixture.path("backups");

    let ran = fixture.run(
        &[
            "--tier",
            "full",
            "--plaintext",
            "--output",
            &backups.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    assert_success(&ran, "taking a plaintext archive");

    let extracted = fixture.path("extracted");
    std::fs::create_dir_all(&extracted).expect("the extraction directory is creatable");
    let archive = std::fs::read(only_archive(&backups)).expect("the archive is readable");
    let mut tarball = Vec::new();
    zstd::stream::copy_decode(archive.as_slice(), &mut tarball).expect("the archive decompresses");
    let tar_path = extracted.join("archive.tar");
    std::fs::write(&tar_path, &tarball).expect("the tarball is writable");
    let ran = Command::new("tar")
        .args(["-xf", "archive.tar"])
        .current_dir(&extracted)
        .output()
        .expect("tar runs");
    assert_success(&ran, "extracting the archive");

    // HOME is redirected so a script bug cannot reach the real home. RAD_HOME is a decoy, so a
    // script that ignored its argument fails.
    let target = fixture.path("by-script");
    let decoy = fixture.path("decoy-home");
    let ran = Command::new("sh")
        .args(["restore.sh", &target.to_string_lossy()])
        .current_dir(&extracted)
        .env("HOME", fixture.path("fake-home"))
        .env("RAD_HOME", &decoy)
        .output()
        .expect("the restore script runs");
    assert_success(&ran, "restoring with the shipped script");
    // The closing line counts as `term::count` does, over the fixture's one repository
    let said = String::from_utf8_lossy(&ran.stdout);
    assert!(said.contains("and 1 repository\n"), "{said}");
    assert!(
        !decoy.exists(),
        "the script ignored its argument and restored into RAD_HOME instead"
    );

    let before = std::fs::read(fixture.home().join("keys/radicle")).expect("the key is readable");
    let after = std::fs::read(target.join("keys/radicle")).expect("the restored key is readable");
    assert_eq!(before, after, "the script did not restore the archived key");
    assert_eq!(
        mode(&target.join("keys/radicle")) & 0o777,
        0o600,
        "the script left the private key readable by others"
    );

    let storage = target.join("storage").join(RID);
    let refs = git(
        &["--git-dir", &storage.to_string_lossy(), "for-each-ref"],
        &target,
    );
    assert!(refs.contains("/refs/rad/sigrefs"), "{refs}");
    assert!(refs.contains("/refs/heads/master"), "{refs}");
    if probe_jq("the HEAD the shipped script sets from the manifest") {
        let head = git(
            &[
                "--git-dir",
                &storage.to_string_lossy(),
                "symbolic-ref",
                "HEAD",
            ],
            &target,
        );
        assert!(head.contains("refs/namespaces/"), "{head}");
    }

    let db = rusqlite::Connection::open(target.join("node/policies.db"))
        .expect("the restored policy database opens");
    let seeded: i64 = db
        .query_row("select count(*) from seeding", [], |row| row.get(0))
        .expect("the seeding table survives");
    assert_eq!(seeded, 2);

    // The whole script runs under every installed shell, so a bashism anywhere in it fails.
    // The run above already checked what it produces.
    for shell in probe_shells() {
        if shell == "sh" {
            continue;
        }
        let elsewhere = fixture.path(&format!("by-{shell}"));
        let mut command = Command::new(shell);
        if shell == "busybox" {
            command.arg("ash");
        }
        let ran = command
            .args(["restore.sh", &elsewhere.to_string_lossy()])
            .current_dir(&extracted)
            .env("HOME", fixture.path("fake-home"))
            .env("RAD_HOME", &decoy)
            .output()
            .unwrap_or_else(|e| panic!("{shell} runs the restore script: {e}"));
        assert_success(
            &ran,
            &format!("restoring with the shipped script under {shell}"),
        );
        let said = String::from_utf8_lossy(&ran.stdout);
        assert!(said.contains("and 1 repository\n"), "under {shell}: {said}");
    }

    // A second run into the home it built, named through RAD_HOME, must refuse
    let ran = Command::new("sh")
        .arg("restore.sh")
        .current_dir(&extracted)
        .env("HOME", fixture.path("fake-home"))
        .env("RAD_HOME", &target)
        .output()
        .expect("the restore script runs");
    assert!(
        !ran.status.success(),
        "the script overwrote an occupied home: {}",
        stderr(&ran)
    );
    assert!(
        stderr(&ran).contains("already holds an identity"),
        "{}",
        stderr(&ran)
    );
}

// The copy-paste block from `RESTORE.md` needs a POSIX shell
#[cfg(unix)]
#[test]
fn the_hand_restore_sheet_refuses_to_paste_a_key_over_one_already_there() {
    let fixture = Fixture::create("restore-md-guard");
    let stage = fixture.path("stage");
    let home = fixture.path("occupied");
    std::fs::create_dir_all(stage.join("keys")).expect("the staging directory is made");
    std::fs::create_dir_all(home.join("keys")).expect("the occupied home is made");
    std::fs::write(stage.join("keys/radicle"), b"the archived key").expect("a key to copy");
    std::fs::write(stage.join("keys/radicle.pub"), b"the archived public key").expect("a pub");
    std::fs::write(home.join("keys/radicle"), b"the key already here").expect("a key to guard");

    // A reader pastes this block whole, so its guard must stop the `cp` that follows it
    let sheet = include_str!("../assets/RESTORE.md");
    let block = sheet
        .split("```sh")
        .nth(1)
        .and_then(|rest| rest.split("```").next())
        .expect("the sheet opens with a shell block");

    let ran = std::process::Command::new("sh")
        .arg("-c")
        .arg(block)
        .current_dir(&stage)
        .env("RAD_HOME", &home)
        .env("HOME", fixture.path("elsewhere"))
        .output()
        .expect("sh runs");

    assert_eq!(
        std::fs::read(home.join("keys/radicle")).expect("the key is still readable"),
        b"the key already here",
        "pasting the block must not overwrite an identity: {}",
        String::from_utf8_lossy(&ran.stderr)
    );

    // `mkdir -p` and `cp` walk through a linked directory. One link at a time, so a check
    // firing for `keys` proves nothing about the other two.
    for name in ["keys", "node", "storage"] {
        let linked = fixture.path(&format!("linked-home-{name}"));
        let elsewhere = fixture.path(&format!("linked-elsewhere-{name}"));
        std::fs::create_dir_all(&linked).expect("the home is made");
        std::fs::create_dir_all(&elsewhere).expect("the directory pointed at is made");
        std::os::unix::fs::symlink(&elsewhere, linked.join(name)).expect("a symlink is creatable");

        let ran = std::process::Command::new("sh")
            .arg("-c")
            .arg(block)
            .current_dir(&stage)
            .env("RAD_HOME", &linked)
            .env("HOME", fixture.path("elsewhere"))
            .output()
            .expect("sh runs");

        let said = String::from_utf8_lossy(&ran.stderr);
        assert!(
            said.contains("symlink"),
            "the block wrote through the link at {name} without saying anything: {said}"
        );
        assert_eq!(
            std::fs::read_dir(&elsewhere)
                .expect("the directory pointed at is listable")
                .count(),
            0,
            "pasting the block wrote through the link at {name}: {said}"
        );
    }
}

/// `Command::output()` gives the child a pipe, which `paper` must accept while it refuses a
/// terminal.
#[test]
fn a_recovery_sheet_still_pipes_even_though_it_refuses_a_terminal() {
    let fixture = Fixture::create("paper-pipe");

    let ran = fixture.run(&["paper"], &fixture.home());
    assert_success(&ran, "rendering a paper sheet to a pipe");

    let sheet = stdout(&ran);
    assert!(
        sheet.contains("<html") && sheet.contains("</html>"),
        "a piped sheet should be the whole HTML document, got {} bytes",
        sheet.len()
    );
}

// Windows has no shell for the shipped POSIX script
#[cfg(unix)]
/// `git symbolic-ref` accepts no `--`, so a manifest `head` of `-d` would reach it as a flag.
#[test]
fn the_shipped_script_refuses_a_head_that_does_not_name_a_ref() {
    if !probe_jq("the shipped script's refusal of a head that names no ref") {
        return;
    }
    let fixture = Fixture::create("script-head");
    let backups = fixture.path("backups");

    let ran = fixture.run(
        &[
            "--tier",
            "full",
            "--plaintext",
            "--output",
            &backups.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    assert_success(&ran, "taking a plaintext archive");

    let extracted = fixture.path("extracted");
    std::fs::create_dir_all(&extracted).expect("the extraction directory is creatable");
    let archive = std::fs::read(only_archive(&backups)).expect("the archive is readable");
    let mut tarball = Vec::new();
    zstd::stream::copy_decode(archive.as_slice(), &mut tarball).expect("the archive decompresses");
    std::fs::write(extracted.join("archive.tar"), &tarball).expect("the tarball is writable");
    let ran = Command::new("tar")
        .args(["-xf", "archive.tar"])
        .current_dir(&extracted)
        .output()
        .expect("tar runs");
    assert_success(&ran, "extracting the archive");

    let manifest_path = extracted.join("manifest.json");
    let text = std::fs::read_to_string(&manifest_path).expect("the manifest is readable");
    let mut manifest: serde_json::Value = serde_json::from_str(&text).expect("the manifest parses");
    let repos = manifest["repos"]
        .as_array_mut()
        .expect("the manifest names repositories");
    assert!(
        !repos.is_empty(),
        "this check needs a repository to plant on"
    );
    for repo in repos.iter_mut() {
        repo["head"] = serde_json::Value::String("-d".to_string());
    }
    std::fs::write(
        &manifest_path,
        serde_json::to_string(&manifest).expect("the manifest serialises"),
    )
    .expect("the manifest is writable");

    let target = fixture.path("by-script");
    let ran = Command::new("sh")
        .args(["restore.sh", &target.to_string_lossy()])
        .current_dir(&extracted)
        .env("HOME", fixture.path("fake-home"))
        .env("RAD_HOME", fixture.path("decoy-home"))
        .output()
        .expect("the restore script runs");
    assert_success(&ran, "restoring with a hostile head planted");
    assert!(
        stderr(&ran).contains("does not name a ref"),
        "{}",
        stderr(&ran)
    );
    // Refusing HEAD, a pointer into the refs, must not cost the history it points at
    assert!(stdout(&ran).contains("1 repository"), "{}", stdout(&ran));
    assert!(
        target
            .join("storage/z3gqcJUoA1n9HaHKufZs5FCSGazv5/refs")
            .exists(),
        "the repository was dropped rather than restored without its HEAD"
    );
}

// The repack shells out to `tar` and needs `/`-separated entry names
#[cfg(unix)]
/// The same skip the shipped script makes over a planted `HEAD` of `-d`.
#[test]
fn a_head_that_does_not_name_a_ref_costs_the_pointer_and_not_the_repository() {
    let fixture = Fixture::create("tool-head");
    let backups = fixture.path("backups");

    let ran = fixture.run(
        &[
            "--tier",
            "full",
            "--plaintext",
            "--output",
            &backups.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    assert_success(&ran, "taking a plaintext archive");
    let hostile = repack_with_a_planted_head(&fixture, &only_archive(&backups));

    let restored = fixture.path("restored");
    let ran = fixture.run(&["restore", "--yes", &hostile.to_string_lossy()], &restored);
    assert_checks_failed(&ran, "restoring an archive whose manifest names a bad head");
    assert!(
        stderr(&ran).contains("does not name a ref"),
        "{}",
        stderr(&ran)
    );
    assert!(
        restored.join("storage").join(RID).join("refs").exists(),
        "the repository was dropped rather than restored without its HEAD"
    );
}

/// `cp`, `mkdir -p` and `git init` follow a symlink, so the shipped script refuses to write
/// through one.
#[cfg(unix)]
#[test]
fn the_shipped_script_refuses_a_home_whose_names_are_symlinks() {
    let fixture = Fixture::create("script-symlinks");
    let backups = fixture.path("backups");
    let ran = fixture.run(
        &[
            "--tier",
            "full",
            "--plaintext",
            "--output",
            &backups.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    assert_success(&ran, "taking a plaintext archive");

    let extracted = fixture.path("extracted");
    std::fs::create_dir_all(&extracted).expect("the extraction directory is creatable");
    let archive = std::fs::read(only_archive(&backups)).expect("the archive is readable");
    let mut tarball = Vec::new();
    zstd::stream::copy_decode(archive.as_slice(), &mut tarball).expect("the archive decompresses");
    std::fs::write(extracted.join("archive.tar"), &tarball).expect("the tarball is writable");
    let ran = Command::new("tar")
        .args(["-xf", "archive.tar"])
        .current_dir(&extracted)
        .output()
        .expect("tar runs");
    assert_success(&ran, "extracting the archive");

    // `cp` writes through a link at a file, and `mkdir -p` and `git init` walk through a link
    // at a directory. Each case names its shape, so a new file is never tested as a directory.
    enum PointsAt {
        AFile,
        ADirectory,
    }

    let refuses = |name: &str, shape: PointsAt| {
        let home = fixture.path(&format!("home-{}", name.replace('/', "-")));
        let elsewhere = fixture.path(&format!("elsewhere-{}", name.replace('/', "-")));
        std::fs::create_dir_all(&home).expect("the home is creatable");
        match shape {
            PointsAt::AFile => {
                std::fs::create_dir_all(home.join("keys")).expect("keys is creatable");
                std::fs::create_dir_all(home.join("node")).expect("node is creatable");
                // Every `cp` follows a link to an existing file. GNU coreutils declines a
                // dangling one, which would pass here and fail on other platforms.
                std::fs::write(&elsewhere, b"the file the link points at")
                    .expect("the file a link is about to point at is writable");
            }
            PointsAt::ADirectory => {
                std::fs::create_dir_all(&elsewhere).expect("the directory is creatable");
            }
        }
        std::os::unix::fs::symlink(&elsewhere, home.join(name)).expect("a symlink is creatable");

        let ran = Command::new("sh")
            .args(["restore.sh", &home.to_string_lossy()])
            .current_dir(&extracted)
            .env("HOME", fixture.path("fake-home"))
            .output()
            .expect("the restore script runs");
        let said = stderr(&ran);
        assert_eq!(ran.status.code(), Some(1), "a symlink at {name}: {said}");
        assert!(said.contains("symlink"), "a symlink at {name}: {said}");
        match shape {
            PointsAt::AFile => assert_eq!(
                std::fs::read(&elsewhere).expect("the file the link points at is readable"),
                b"the file the link points at",
                "the script wrote through the symlink at {name}: {said}"
            ),
            PointsAt::ADirectory => assert_eq!(
                std::fs::read_dir(&elsewhere)
                    .expect("the directory the link points at is listable")
                    .count(),
                0,
                "the script wrote into the directory the symlink at {name} points at: {said}"
            ),
        }
    };

    refuses("keys/radicle", PointsAt::AFile);
    refuses("keys/radicle.pub", PointsAt::AFile);
    refuses("config.json", PointsAt::AFile);
    refuses("node/policies.db", PointsAt::AFile);
    refuses("keys", PointsAt::ADirectory);
    refuses("node", PointsAt::ADirectory);
    refuses("storage", PointsAt::ADirectory);

    // A link at the repository's own name inside a real `storage` is skipped, not fatal,
    // because earlier repositories are already back. The exit code says nothing here.
    let home = fixture.path("home-linked-repo");
    let elsewhere = fixture.path("elsewhere-linked-repo");
    std::fs::create_dir_all(home.join("storage")).expect("storage is creatable");
    std::fs::create_dir_all(&elsewhere).expect("the directory pointed at is creatable");
    std::os::unix::fs::symlink(&elsewhere, home.join("storage").join(RID))
        .expect("a symlink is creatable");

    let ran = Command::new("sh")
        .args(["restore.sh", &home.to_string_lossy()])
        .current_dir(&extracted)
        .env("HOME", fixture.path("fake-home"))
        .output()
        .expect("the restore script runs");
    let said = stderr(&ran);
    assert!(said.contains("is a symlink"), "{said}");
    assert_eq!(
        std::fs::read_dir(&elsewhere)
            .expect("the directory pointed at is listable")
            .count(),
        0,
        "the script restored a repository through the link: {said}"
    );
}

/// Runs the `case` lifted from `assets/restore.sh`, so a change to one reader alone fails.
///
/// The table repeats a unit test in `git::tests` and adds the cases only a shell gets wrong,
/// because a bin-only crate has no library to call into.
#[cfg(unix)]
#[test]
fn the_shipped_script_refuses_every_head_this_tool_refuses() {
    let script = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/restore.sh"))
        .expect("the shipped script is readable");
    let start = script
        .find("case \"$head\" in")
        .expect("the shipped script still decides about HEAD with a case");
    let tail = &script[start..];
    let end = start
        + tail
            .find("\n\t\tesac")
            .expect("the case about HEAD is still closed by an esac")
        + "\n\t\tesac".len();
    let lifted = script[start..end]
        .replace(
            "git --git-dir \"$target\" symbolic-ref HEAD \"$head\"",
            "echo ACCEPT",
        )
        .replace(
            "echo \"skipping HEAD for $rid: '$head' does not name a ref\" >&2",
            "echo SKIP",
        );
    assert!(
        lifted.contains("echo ACCEPT") && lifted.contains("echo SKIP"),
        "the case no longer has the branches this substitutes, so it is not being tested: \
         {lifted}"
    );

    let refused = [
        "refs/../../evil",
        "refs/heads/../../../etc/x",
        "refs/",
        "refs/heads/",
        "refs//heads/x",
        "refs/heads/.hidden",
        "refs/heads/x.lock",
        "refs/heads/a b",
        "refs/heads/a^b",
        "-d",
        "--version",
        "master",
        "refs/heads/a\nb",
        "refs/heads/a\tb",
    ];
    let accepted = [
        "refs/heads/master",
        "refs/heads/feature/nested",
        "refs/heads/v1.0",
        "refs/namespaces/z6Mk/refs/heads/master",
        // A shell whose character classes work per byte must still accept an accented branch
        "refs/heads/caf\u{e9}",
    ];

    let shells = probe_shells();

    let verdict = |shell: &str, head: &str| -> String {
        let ran = under_shell(shell, &lifted, &[("head", head)]);
        String::from_utf8_lossy(&ran.stdout).trim().to_string()
    };
    for shell in &shells {
        for head in refused {
            assert_eq!(
                verdict(shell, head),
                "SKIP",
                "under {shell}, the shipped script accepts a head this tool refuses: {head:?}"
            );
        }
        for head in accepted {
            assert_eq!(
                verdict(shell, head),
                "ACCEPT",
                "under {shell}, the shipped script refuses a head this tool accepts: {head:?}"
            );
        }
    }
}

/// `fetch.fsckObjects` reaches a bundle only from git 2.46, so both readers warn below it.
///
/// Runs the block lifted from `assets/restore.sh`, so a change to one reader alone fails.
#[cfg(unix)]
#[test]
fn the_shipped_script_warns_about_the_same_gits_this_tool_warns_about() {
    let script = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/restore.sh"))
        .expect("the shipped script is readable");
    let start = script
        .find("git_said=")
        .expect("the shipped script still reads the version of git");
    let tail = &script[start..];
    let end = start
        + tail
            .find("\nesac\n")
            .expect("the version case is still closed")
        + "\nesac".len();
    // `$SAID` lets the table ask about versions this machine does not have installed
    let lifted = script[start..end].replace("$(git --version 2>/dev/null || true)", "$SAID");
    assert!(
        lifted.contains("$SAID") && lifted.contains("2.46"),
        "the block no longer has what this substitutes, so it is not being tested: {lifted}"
    );

    // Each version with whether the script warns. The tails are ones distributions ship.
    let table = [
        ("git version 1.9.1", true),
        ("git version 2.9.5", true),
        ("git version 2.34.1", true),
        ("git version 2.39.5 (Apple Git-154)", true),
        ("git version 2.45.2", true),
        ("git version 2.46.0", false),
        ("git version 2.51.0.windows.1", false),
        ("git version 3.0.0", false),
    ];
    for shell in probe_shells() {
        for (said, warns) in table {
            let ran = under_shell(shell, &lifted, &[("SAID", said), ("bundles", "yes")]);
            let printed = stderr(&ran);
            assert_eq!(
                printed.contains("does not check the objects inside a bundle"),
                warns,
                "under {shell}, {said:?} was answered with {printed:?}"
            );
            // An identity-only archive has nothing to unbundle, so it gets no warning
            let ran = under_shell(shell, &lifted, &[("SAID", said), ("bundles", "")]);
            assert_eq!(
                stderr(&ran),
                "",
                "under {shell}, {said:?} spoke about bundles on an archive carrying none"
            );
        }
        // An unreadable version must be reported, because silence claims the objects were
        // checked. A bare `2` is the shape a dot-stripping reader gets wrong.
        for said in [
            "git version next",
            "git version 2",
            "git version 2.x",
            "git version",
            // A leading-digit pattern takes `46-rc0` for a number, and `[` then fails on it
            "git version 2.46-rc0",
            "git version 2.45-rc1",
        ] {
            let ran = under_shell(shell, &lifted, &[("SAID", said), ("bundles", "yes")]);
            assert!(
                stderr(&ran).contains("could not be read"),
                "under {shell}, {said:?}: {}",
                stderr(&ran)
            );
        }
        // Without git this block stays quiet. The script's first git call fails later and
        // names the missing tool.
        let ran = under_shell(shell, &lifted, &[("SAID", ""), ("bundles", "yes")]);
        assert_eq!(stderr(&ran), "", "under {shell}, git being absent");
    }
}

/// Repacks an archive with `-d` planted as every repository's `HEAD`.
#[cfg(unix)]
fn repack_with_a_planted_head(fixture: &Fixture, archive: &Path) -> PathBuf {
    repack_with(fixture, archive, |extracted| {
        let manifest_path = extracted.join("manifest.json");
        let text = std::fs::read_to_string(&manifest_path).expect("the manifest is readable");
        let mut manifest: serde_json::Value =
            serde_json::from_str(&text).expect("the manifest parses");
        let repos = manifest["repos"]
            .as_array_mut()
            .expect("the manifest names repositories");
        assert!(
            !repos.is_empty(),
            "this check needs a repository to plant on"
        );
        for repo in repos.iter_mut() {
            repo["head"] = serde_json::Value::String("-d".to_string());
        }
        std::fs::write(
            &manifest_path,
            serde_json::to_string(&manifest).expect("the manifest serialises"),
        )
        .expect("the manifest is writable");
    })
}

/// Rewrites the manifest's size and sha256 for `entry` to match `bytes`, as the author of a
/// hostile archive would.
#[cfg(unix)]
fn rewrite_manifest_entry(extracted: &Path, entry: &str, bytes: &[u8]) {
    use sha2::Digest as _;

    let digest = hex::encode(sha2::Sha256::digest(bytes));
    let path = extracted.join("manifest.json");
    let text = std::fs::read_to_string(&path).expect("the manifest is readable");
    let mut manifest: serde_json::Value = serde_json::from_str(&text).expect("the manifest parses");
    let entries = manifest["entries"]
        .as_array_mut()
        .expect("the manifest lists its entries");
    let listed = entries
        .iter_mut()
        .find(|listed| listed["path"] == entry)
        .unwrap_or_else(|| panic!("the manifest lists {entry}"));
    listed["bytes"] = serde_json::Value::from(bytes.len() as u64);
    listed["sha256"] = serde_json::Value::String(digest);
    std::fs::write(
        &path,
        serde_json::to_string(&manifest).expect("the manifest serialises"),
    )
    .expect("the manifest is writable");
}

/// Extracts an archive, lets `plant` rewrite what it holds, and packs it again under the same
/// name.
#[cfg(unix)]
fn repack_with(fixture: &Fixture, archive: &Path, plant: impl FnOnce(&Path)) -> PathBuf {
    let extracted = fixture.path("planted-extract");
    std::fs::create_dir_all(&extracted).expect("the extraction directory is creatable");
    let bytes = std::fs::read(archive).expect("the archive is readable");
    let mut tarball = Vec::new();
    zstd::stream::copy_decode(bytes.as_slice(), &mut tarball).expect("the archive decompresses");
    let opened = fixture.path("planted.tar");
    std::fs::write(&opened, &tarball).expect("the tarball is writable");
    let ran = Command::new("tar")
        .args(["-xf", &opened.to_string_lossy()])
        .current_dir(&extracted)
        .output()
        .expect("tar runs");
    assert_success(&ran, "extracting the archive");

    plant(&extracted);

    // The reader matches `manifest.json` by its exact entry name, so each file is named to
    // `tar` one by one. A directory argument would add entries the original never had.
    let mut entries = Vec::new();
    collect_files(&extracted, &extracted, &mut entries);
    entries.sort();
    let rebuilt = fixture.path("planted-backups");
    std::fs::create_dir_all(&rebuilt).expect("the archive directory is creatable");
    let repacked = fixture.path("repacked.tar");
    let mut args = vec!["-cf".to_string(), repacked.to_string_lossy().into_owned()];
    args.extend(entries);
    let ran = Command::new("tar")
        .args(&args)
        .current_dir(&extracted)
        .output()
        .expect("tar runs");
    assert_success(&ran, "repacking the archive");

    let name = archive.file_name().expect("the archive has a name");
    let target = rebuilt.join(name);
    let tar_bytes = std::fs::read(&repacked).expect("the repacked tar is readable");
    let file = std::fs::File::create(&target).expect("the archive is creatable");
    zstd::stream::copy_encode(tar_bytes.as_slice(), file, 3).expect("the archive compresses");
    target
}

#[cfg(unix)]
/// Every regular file under `dir`, named relative to `root`.
fn collect_files(root: &Path, dir: &Path, ran: &mut Vec<String>) {
    for entry in std::fs::read_dir(dir).expect("the directory is readable") {
        let path = entry.expect("the entry is readable").path();
        if path.is_dir() {
            collect_files(root, &path, ran);
        } else {
            let relative = path
                .strip_prefix(root)
                .expect("the entry is under the root");
            ran.push(relative.to_string_lossy().into_owned());
        }
    }
}

#[test]
fn a_diff_against_an_archive_of_everything_does_not_report_a_foreign_repository_gone() {
    let fixture = Fixture::create("diff-foreign");
    let backups = fixture.path("backups");

    // A repository held for another peer, which `--repos all` carries and `mine` never names
    const FOREIGN: &str = "z2rGGGeuiMJUpZTUBUdyKzsBQU3xz";
    let foreign = fixture.home().join("storage").join(FOREIGN);
    git(
        &["init", "--quiet", "--bare", &foreign.to_string_lossy()],
        &fixture.path("."),
    );
    // `git bundle` fails on a repository with no history
    const FOREIGN_PEER: &str = "z6MkwLM8ubPRsUFMkgBjxhr2VqfoLYRhpXCTBBpJ7BjgWZgt";
    let namespace = format!("refs/namespaces/{FOREIGN_PEER}");
    let work = fixture.path("work");
    git(
        &[
            "push",
            "--quiet",
            "--force",
            &foreign.to_string_lossy(),
            &format!("master:{namespace}/refs/heads/master"),
        ],
        &work,
    );
    git(
        &[
            "--git-dir",
            &foreign.to_string_lossy(),
            "symbolic-ref",
            "HEAD",
            &format!("{namespace}/refs/heads/master"),
        ],
        &work,
    );

    let ran = fixture.run(
        &[
            "--repos",
            "all",
            "--plaintext",
            "--output",
            &backups.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    assert_success(&ran, "taking an archive of everything");

    let ran = fixture.run(&["diff", "--json"], &fixture.home());
    let report: serde_json::Value =
        serde_json::from_str(&stdout(&ran)).expect("the diff report is json");
    assert_eq!(
        report["repositoriesGone"],
        serde_json::json!([]),
        "{}",
        stdout(&ran)
    );
    assert!(
        ran.status.success(),
        "diff exited {:?} over a repository that never left storage: {}",
        ran.status.code(),
        stdout(&ran)
    );
}

/// `backup` stamps whether the run retires the key, `restore` copies that into the state
/// file, and `doctor` reads it back. Losing it at any step silently passes the check.
#[test]
fn a_home_restored_from_an_ordinary_backup_is_told_the_source_machine_still_holds_the_key() {
    let fixture = Fixture::create("sole-holder");
    let backups = fixture.path("backups");

    let ran = fixture.run(
        &[
            "--repos",
            "none",
            "--output",
            &backups.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    assert_success(&ran, "taking a backup");
    let archive = only_archive(&backups);

    // Nothing was restored into the source home, so it has no second machine to warn about
    let ran = fixture.run(&["doctor", "--json"], &fixture.home());
    assert_eq!(verdict_of(&ran, "key-copies"), "pass");

    // This count pairs with the hand-written check list in `doctor.rs`. A new check in
    // `examine` raises both, and joins `every_topic` too.
    let report: serde_json::Value =
        serde_json::from_str(&stdout(&ran)).expect("the doctor report is json");
    assert_eq!(report["total"], 9, "{report}");

    let restored = fixture.path("restored");
    let ran = fixture.run(&["restore", "--yes", &archive.to_string_lossy()], &restored);
    assert_success(&ran, "restoring the archive");

    // The restored home holds a key another machine also holds
    let ran = fixture.run(&["doctor", "--json"], &restored);
    assert_eq!(verdict_of(&ran, "key-copies"), "warn");
    let report: serde_json::Value =
        serde_json::from_str(&stdout(&ran)).expect("the doctor report is json");
    let check = report["checks"]
        .as_array()
        .expect("the report lists checks")
        .iter()
        .find(|check| check["checkId"] == "key-copies")
        .expect("the check is in the report");
    assert!(
        check["remedy"].is_string(),
        "a warning with no way out is a nag: {check}"
    );
}

#[test]
fn a_node_database_that_will_not_open_costs_the_checks_that_read_it_and_not_the_report() {
    let fixture = Fixture::create("unreadable-node-db");
    let home = fixture.home();

    // An absent file means a node that never ran, so this one exists and is not SQLite
    std::fs::write(home.join("node/node.db"), b"this is not a database")
        .expect("the fixture home is writable");

    let ran = fixture.run(&["doctor", "--json"], &home);
    let report: serde_json::Value =
        serde_json::from_str(&stdout(&ran)).expect("the doctor report is json");
    // A check that reads nothing from the file still answers
    assert_eq!(verdict_of(&ran, "key-passphrase"), "pass", "{report}");

    for id in ["public-repositories", "unshared-work"] {
        assert_eq!(verdict_of(&ran, id), "unknown", "{report}");
        let check = report["checks"]
            .as_array()
            .expect("the report lists checks")
            .iter()
            .find(|check| check["checkId"] == id)
            .expect("the check is in the report");
        let remedy = check["remedy"].as_str().unwrap_or_default();
        assert!(
            remedy.contains("could not be read"),
            "{id} blamed something other than the file it could not open: {check}"
        );
        assert!(
            !remedy.contains("rad node start"),
            "{id} sent the reader to start a node over a database that will not open: {check}"
        );
    }

    // This fixture cannot build a routing table, so a unit test in `doctor` checks this
    // reader's answer. Here it only has to answer.
    assert_ne!(verdict_of(&ran, "private-repositories"), "", "{report}");
}

/// The verdict of the doctor check with `checkId` `id`, out of a `--json` run.
fn verdict_of(ran: &Output, id: &str) -> String {
    let report: serde_json::Value =
        serde_json::from_str(&stdout(ran)).expect("the doctor report is json");
    report["checks"]
        .as_array()
        .expect("the report lists checks")
        .iter()
        .find(|check| check["checkId"] == id)
        .and_then(|check| check["verdict"].as_str())
        .unwrap_or_else(|| panic!("no check with the id {id} in {}", stdout(ran)))
        .to_string()
}

/// The flow the README recommends for an unattended timer, with a passphrase-protected key as
/// `rad auth` writes it.
///
/// age reports a key it could not unlock exactly as it reports a key that is not a recipient.
#[test]
fn an_archive_encrypted_to_an_ssh_key_opens_again_with_that_key_and_its_passphrase() {
    let fixture = Fixture::create("recipient-round-trip");
    let backups = fixture.path("backups");
    let secret_key = fixture.home().join("keys/radicle");
    let recipient = std::fs::read_to_string(fixture.home().join("keys/radicle.pub"))
        .expect("the fixture public key is readable");

    let ran = fixture.run(
        &[
            "create",
            "--tier",
            "identity",
            "--recipient",
            recipient.trim(),
            "--output",
            &backups.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    assert_success(&ran, "taking a backup encrypted to an ssh recipient");
    let archive = only_archive(&backups);

    // The run names the key while the user setting up the timer can still check they hold
    // the private half
    let said = stderr(&ran);
    assert!(said.contains("opens only with the private half"), "{said}");
    assert!(said.contains(recipient.trim()), "{said}");

    // A bare `age -d` on a recipient archive asks for a passphrase that does not exist, so the
    // note names the key for both paths
    let sidecar_path = archive.with_file_name(format!(
        "{}.README.txt",
        archive
            .file_name()
            .expect("it has a name")
            .to_string_lossy()
    ));
    let sidecar = std::fs::read_to_string(&sidecar_path).expect("the sidecar note is readable");
    assert!(sidecar.contains("--identity"), "{sidecar}");
    assert!(sidecar.contains("age -d -i"), "{sidecar}");
    assert!(sidecar.contains(recipient.trim()), "{sidecar}");

    // A timer has nothing to unlock the key with, so the run must name the locked key
    let locked = fixture.run(
        &[
            "verify",
            "--identity",
            &secret_key.to_string_lossy(),
            &archive.to_string_lossy(),
        ],
        &fixture.home(),
    );
    let said = stderr(&locked);
    assert!(!locked.status.success(), "{said}");
    assert!(said.contains("stayed locked"), "{said}");
    assert!(
        said.contains(&secret_key.to_string_lossy().to_string()),
        "{said}"
    );

    let passphrase_file = fixture.path("identity-passphrase");
    std::fs::write(&passphrase_file, KEY_PASSPHRASE).expect("the passphrase file is writable");
    let opened = fixture.run(
        &[
            "verify",
            "--deep",
            "--identity",
            &secret_key.to_string_lossy(),
            "--identity-passphrase-file",
            &passphrase_file.to_string_lossy(),
            &archive.to_string_lossy(),
        ],
        &fixture.home(),
    );
    assert_success(
        &opened,
        "verifying an archive encrypted to an ssh recipient",
    );
    assert!(stderr(&opened).contains(DID), "{}", stderr(&opened));

    // clap and `read_passphrase` read these variables, which no unit test reaches
    for (variable, value) in [
        ("RAD_BACKUP_IDENTITY_PASSPHRASE", KEY_PASSPHRASE.to_string()),
        (
            "RAD_BACKUP_IDENTITY_PASSPHRASE_FILE",
            passphrase_file.to_string_lossy().into_owned(),
        ),
    ] {
        let ran = fixture
            .command(
                &[
                    "verify",
                    "--identity",
                    &secret_key.to_string_lossy(),
                    &archive.to_string_lossy(),
                ],
                &fixture.home(),
            )
            .env(variable, value)
            .output()
            .expect("rad-backup runs");
        assert_success(&ran, &format!("verifying with {variable}"));
    }
}

/// A package build runs `rad-backup man > rad-backup.1`, so a pipe gets the page itself.
#[test]
fn the_man_page_written_to_a_pipe_is_roff_a_package_can_install() {
    let ran = Command::new(env!("CARGO_BIN_EXE_rad-backup"))
        .arg("man")
        .output()
        .expect("rad-backup runs");
    assert_success(&ran, "writing the man page");
    let page = stdout(&ran);
    assert!(page.contains("\n.TH rad-backup 1 "), "{page}");
    assert!(page.contains("\n.SH COMMANDS\n"), "{page}");
}
