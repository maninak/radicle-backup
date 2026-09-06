//! What the tool promises, proven end to end against the binary that ships.
//!
//! Every fixture here is built by running `rad-backup` itself, so the tests need nothing on
//! the machine that the tool does not already need: `git`, and nothing else. The identity
//! comes from a fixed mnemonic, which makes every run produce the same DID and makes a
//! failure reproducible from the test name alone.
//!
//! Two things are stood in for, because a test cannot have them: `rad`, by a shell script the
//! fixture writes (see `stub_rad`), and the network it would talk to. Everything else is the
//! real thing, down to the shipped `restore.sh` being run by `sh`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// BIP-39's all-zero entropy vector. A real key, deterministically.
const WORDS: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon abandon abandon art";

/// The identity those words rebuild. Hard-coded so that a change in key derivation, which
/// would silently orphan every recovery sheet ever printed, fails a test instead.
const DID: &str = "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp";

const KEY_PASSPHRASE: &str = "the key passphrase";
const ARCHIVE_PASSPHRASE: &str = "the archive passphrase";

const RID: &str = "z3gqcJUoA1n9HaHKufZs5FCSGazv5";

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    /// A Radicle home with an identity, policies and one repository, built from nothing.
    fn create(name: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("rad-backup-it-{name}-{}", std::process::id()));
        // Owner-only, and never a directory that was already there, because the root holds a
        // real Radicle home with a real secret key under a name guessable from the pid. A
        // `create_dir_all` over a root somebody else planted first would have built that home
        // under their permissions, and a leftover from a crashed run fails here on purpose.
        // The guard is armed before the first file is written so that a panic partway through
        // still removes what was written.
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

    /// A bare repository holding this peer's namespace, which is what makes it "mine".
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
        self.publish(&work);
    }

    /// Push the working copy into this peer's namespace and sign it, the way a node would.
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

    /// Add a commit and re-sign, so that the archive on disk is now behind this home.
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

    /// Put a stand-in `rad` where this fixture's runs will find it.
    ///
    /// Without one every test drives the no-`rad` path, which is the path that cannot see a
    /// repository's visibility: the private selection, the delegate list and the name in the
    /// manifest all come from `rad inspect`, and none of them was reachable from a test. The
    /// stub answers only what these tests ask and shouts on stderr about anything else, so a
    /// question nobody stubbed fails the test rather than quietly degrading to "no rad".
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
            // Kept out of the real one, so a test run never rewrites what `doctor` reads.
            .env("XDG_STATE_HOME", self.path("state"))
            .env("RAD_PASSPHRASE", KEY_PASSPHRASE)
            .env("RAD_BACKUP_PASSPHRASE", ARCHIVE_PASSPHRASE)
            .env("NO_COLOR", "1")
            // A real `rad` on PATH would reach for a node this fixture does not have, so the
            // default is a path that cannot exist and the stub is opted into per test.
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

/// What `rad-backup` itself does for a working directory, spelled out here because an
/// integration test cannot reach `crate::perms`. `create_dir` fails when the path exists,
/// which is the property that matters on every platform; the mode is the part only unix has.
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

/// Every shell on the machine the shipped script has to decide the same way under.
///
/// Not just `/bin/sh`: its patterns lean on bracket expressions and character classes, and
/// this is the archive's reader of last resort, so it has to agree wherever somebody runs it.
/// Spawning is the test for whether one is installed, because `--version` is not portable
/// across them (dash has none) and a missing shell fails to spawn at all.
///
/// A shell that is not installed drops out of the list, and a check that quietly covers less
/// than it claims is the thing these tests exist to prevent. So on Linux CI, whose workflow
/// installs all four, a short list is a failure rather than a fact about the machine. Off CI
/// the list is only printed, and only `--nocapture` or a failing assertion shows it: nothing
/// there can insist on a shell the developer has not got.
///
/// Four names, not four implementations. On Debian and Ubuntu `/bin/sh` is `dash`, so the
/// same shell is exercised twice; the run is worth what the distinct ones in it are worth.
// Unix only, like its callers: they run a POSIX script Windows has no shell for.
#[cfg(unix)]
fn probe_shells() -> Vec<&'static str> {
    const WANTED: [&str; 4] = ["sh", "dash", "bash", "busybox"];

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

/// One shell running a fragment lifted out of the shipped script, with `variables` exported.
///
/// Under `set -eu`, because that is the line the shipped script opens with and a fragment run
/// without it cannot fail the way the real one would. An unset variable, or a command whose
/// status nobody reads, aborts the restore there and passes here otherwise, which is the
/// failure `restore.sh` has already been bitten by once.
// Unix only, like its callers.
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

/// Whether this machine has `jq`, refusing on the CI leg whose workflow installs it.
///
/// The shipped script reads `head` out of the manifest with `jq`, so a machine without one
/// restores every repository with no HEAD. That difference surfaces far from its cause, as a
/// HEAD comparison the two readers appear to disagree on: nix hit exactly this, its check
/// environment having no jq. Off CI it is a fact about the machine and the caller says what
/// it skipped; on Linux CI the workflow installs jq, so an absence is a broken workflow and
/// a silent skip there would report coverage nobody has.
///
/// One helper rather than three: the three callers had three different policies, and two of
/// them skipped without a word.
///
/// Unix only, like every caller: each runs the shipped POSIX script, which Windows has no
/// shell for.
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

/// Exit 4 is documented as "everything is intact and nothing was written", and
/// `--replay-policies` broke it. The flag asked for `rad` from inside the replay, which runs
/// after the identity, the databases and every repository are already on disk, so the refusal
/// arrived over a home the run had just rewritten, and it skipped the state record on the way
/// out.
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

    // The identity is genuinely back, so this is not a failed restore.
    assert!(
        restored.join("keys/radicle").is_file(),
        "the identity should still be restored: {said}"
    );
    // But every repository the archive carried is missing, and a run that exits 0 over that
    // is a scheduled restore nobody ever hears about again.
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
    // It used to point at the staging directory inside the scratch this run deletes on its
    // way out, so the bundles it named were gone before the shell prompt came back.
    // The Windows-only warning about permissions names the scratch directory too, and it is
    // not sending anybody there: it says what the platform could not promise about a file it
    // just wrote. Only the lines that offer the reader somewhere to look are under test.
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
    assert_success(&ran, "restoring the archive");

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
            "--output",
            &backups.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    assert_success(&ran, "taking a plaintext backup");
    let archive = only_archive(&backups);

    // Plaintext, so the damage is caught by the manifest's digests rather than by age.
    let mut bytes = std::fs::read(&archive).expect("the archive is readable");
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0xff;
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

    // A re-wrap once left the continuation indentation inside the string literal, so the line
    // arrived with a run of eighteen spaces in the middle of a sentence. Neither `cargo fmt`
    // nor clippy reads inside a literal, so nothing but a reader would ever have caught it.
    assert!(
        said.contains("1 repository bundle in this archive could not be opened"),
        "the sentence has to read as one: {said}"
    );
    assert!(
        !said.contains("  not opened"),
        "no run of spaces inside the sentence: {said}"
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
    assert!(
        stderr(&ran).contains("nothing has changed"),
        "{}",
        stderr(&ran)
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

/// What a `--repos private` run put in the archive, and what the run said while doing it.
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

    // The stub shouts about anything it was not taught. Without this the test would pass just
    // as happily against a `rad` that failed every call, which is the state it replaced.
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

    // And the summary says so in the line somebody actually reads, because an archive that
    // quietly carries none of the repositories it was taken for is the failure this selection
    // exists to avoid.
    assert!(said.contains("repositories private (0 carried)"), "{said}");
}

#[test]
fn a_state_archive_carries_the_paperwork_but_not_the_repositories() {
    let fixture = Fixture::create("state-tier");
    let backups = fixture.path("backups");

    let ran = fixture.run(
        &["--output", &backups.to_string_lossy(), "--yes"],
        &fixture.home(),
    );
    assert_success(&ran, "taking a state backup");
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

    // The repository is still described, because knowing what you had is most of a restore.
    let repos = manifest["repos"].as_array().expect("repos is an array");
    assert_eq!(repos.len(), 1);
    assert_eq!(repos[0]["rid"], format!("rad:{RID}"));
    assert!(repos[0]["bundle"].is_null());
}

#[test]
fn restoring_into_an_occupied_home_is_refused_before_anything_is_overwritten() {
    let fixture = Fixture::create("occupied");
    let backups = fixture.path("backups");

    let ran = fixture.run(
        &["--output", &backups.to_string_lossy(), "--yes"],
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

/// A home with no key still holds everything a restore rewrites.
///
/// Occupancy was decided on `keys/radicle` alone, so a home whose key `move` retired, or whose
/// key was deleted, answered "empty" and a restore went through with neither `--force` nor a
/// confirmation. It fetches every bundle with `--force`, which rewinds every ref in every
/// stored repository, other peers' namespaces included, to whatever the archive holds. For a
/// private repository nobody else has, there is nothing to bring the newer refs back from.
#[test]
fn a_home_with_repositories_and_no_key_is_still_occupied() {
    let fixture = Fixture::create("keyless-occupied");
    let backups = fixture.path("backups");

    let ran = fixture.run(
        &["--output", &backups.to_string_lossy(), "--yes"],
        &fixture.home(),
    );
    assert_success(&ran, "taking a backup");
    let archive = only_archive(&backups);

    // Exactly what `move` leaves behind: no key, and every repository still there.
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

/// Restoring over a home that holds a DIFFERENT identity must file the old key, not delete
/// it: the key is the identity, and there is no way back from overwriting one.
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

    // A home holding somebody else's key, which `--force` is about to restore over.
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
    // The public half too, and under the name the note beside it gives. `with_extension`
    // turned `radicle.retired` into `radicle.pub`, so the rename that was meant to keep it
    // renamed the file onto itself, succeeded, and left the restore to overwrite it seconds
    // later. Nothing failed, and the note pointed at a file that was never written.
    let retired_public = occupied.join("keys/radicle.retired.pub");
    assert_eq!(
        std::fs::read(&retired_public).expect("the retired public half is readable"),
        b"ssh-ed25519 AAAA stranger",
        "the retired public half is not the one that was displaced"
    );
    let note =
        std::fs::read_to_string(occupied.join("keys/DISPLACED.txt")).expect("the note is readable");
    assert!(note.contains("radicle.retired.pub"), "{note}");

    // And the restore really did land, so this is not a refusal dressed up as a success.
    assert_eq!(
        std::fs::read(occupied.join("keys/radicle")).expect("the restored key is readable"),
        std::fs::read(fixture.home().join("keys/radicle")).expect("the archived key is readable")
    );
    assert_eq!(
        std::fs::read(occupied.join("keys/radicle.pub")).expect("the restored half is readable"),
        std::fs::read(fixture.home().join("keys/radicle.pub")).expect("the archived half reads")
    );
}

#[test]
fn a_restored_home_knows_which_archive_it_came_from_and_reports_no_drift() {
    let fixture = Fixture::create("restored-state");
    let backups = fixture.path("backups");

    // A `state` archive describes the repository without carrying it, which is the case that
    // made a freshly restored home report the repositories it never asked for as missing.
    let ran = fixture.run(
        &["--output", &backups.to_string_lossy(), "--yes"],
        &fixture.home(),
    );
    assert_success(&ran, "taking a state backup");
    let archive = only_archive(&backups);

    let restored = fixture.path("restored");
    let ran = fixture.run(&["restore", "--yes", &archive.to_string_lossy()], &restored);
    assert_success(&ran, "restoring the archive");

    let ran = fixture.run(&["diff"], &restored);
    assert_success(&ran, "diffing a freshly restored home");
    assert!(
        stderr(&ran).contains("nothing has changed"),
        "a restore should leave nothing to report: {}",
        stderr(&ran)
    );

    // Asserted on the detail rather than the topic, because the topic prints whatever the
    // verdict is: matching it would pass just as happily on "no archive has ever been taken".
    // The file name too, since the check now reads the directory instead of trusting the
    // state record, and naming the archive it actually found is the difference.
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

    let ran = fixture.run(&["--output", &dir, "--yes"], &fixture.home());
    assert_success(&ran, "taking the first archive");
    // The name carries a whole-second stamp, so two archives need a second between them.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    fixture.advance();
    let ran = fixture.run(&["--output", &dir, "--yes"], &fixture.home());
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

    // RAD_BACKUP_DIR is how a command with no argument knows where to look.
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
        let ran = fixture.run(&["--output", &dir, "--yes"], &fixture.home());
        assert_success(&ran, "taking an archive");
        std::thread::sleep(std::time::Duration::from_millis(1100));
    }
    // A file this tool did not write, and one belonging to another identity.
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

    // `--json` was honoured by every reporting path except this one, which printed the human
    // table on stdout. A consumer got something that parses as far as the first line.
    let report: serde_json::Value =
        serde_json::from_str(&stdout(&ran)).expect("--dry-run --json prints json");
    assert_eq!(report["dryRun"], serde_json::Value::Bool(true));
    assert_eq!(report["tier"], serde_json::Value::String("full".into()));
    assert_eq!(
        report["repos"][0]["rid"],
        serde_json::Value::String(format!("rad:{RID}"))
    );
}

/// Exit `3` is the whole scheduling contract: a timer that only reads the status has no
/// other way to tell a complete backup from one that lost a repository on the way.
#[test]
fn a_backup_that_lost_a_repository_writes_the_archive_and_still_exits_three() {
    let fixture = Fixture::create("incomplete");
    let backups = fixture.path("backups");

    // Break the only repository in a way `git bundle` cannot work around: an `objects` that
    // is a file rather than a directory. Deleting it would look like a repository that was
    // never there, which is a different thing and is not an error.
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
    // And the archive is still written, because everything else in the home is worth having.
    let archive = only_archive(&backups);
    assert!(archive.is_file(), "the archive should still exist: {said}");
    assert!(said.contains(RID), "it has to name what it lost: {said}");
}

// Unix only: it runs the shipped POSIX script, which Windows has no shell for.
#[cfg(unix)]
/// The shipped script and this tool are two implementations of one restore, kept in step by
/// policy (guardrail: an archive never depends on this tool to be read). Nothing enforced that
/// they stayed in step, so anything added to one side only, the way `repos/*.config` or the
/// HEAD restore could have been, would have gone unnoticed until somebody needed the other.
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

    // A name no `rad` would mint, planted the way a hostile archive would carry it. The tool
    // refuses such an archive outright; the script has to refuse the one bundle and go on,
    // because it is the path that runs when the tool is not there to refuse anything.
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

    // And the real repository still came back, so this is a skip and not a bail-out.
    assert!(target.join("storage").join(RID).is_dir());
}

// Unix only: it runs the shipped POSIX script and compares the mode bits it sets,
// neither of which Windows has.
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
    assert_success(&ran, "restoring with this tool");

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

    // Sqlite's own scratch files are not part of either restore: whichever side opens a
    // database first makes them, and they say nothing about what was put back.
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

    let seeded = |home: &Path| -> i64 {
        rusqlite::Connection::open(home.join("node/policies.db"))
            .expect("the policy database opens")
            .query_row("select count(*) from seeding", [], |row| row.get(0))
            .expect("the seeding table survives")
    };
    assert_eq!(seeded(&by_tool), seeded(&by_script));
}

/// Every file under a directory, so a test can look at what a run left behind rather than at
/// what it meant to leave behind.
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
    // What a copy of an openssh private key looks like from the outside. Searching for this
    // rather than for the key bytes keeps the test honest about what it is looking for.
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

    // Nothing found above would also be true of a merely compressed archive, so this is the
    // half that says why: the payload is age, and age does not open without the passphrase.
    let archive = std::fs::read(only_archive(&backups)).expect("the archive is readable");
    assert!(archive.starts_with(AGE_MAGIC), "the archive is not age");
    let mut opened = Vec::new();
    assert!(
        zstd::stream::copy_decode(archive.as_slice(), &mut opened).is_err(),
        "the archive decompressed without a passphrase"
    );

    // And the search itself, against an archive that really does carry the key. Without this
    // the assertions above would pass just as happily if they were looking for nothing.
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

// Unix only: it runs the shipped POSIX script and checks the mode bits it sets, neither
// of which Windows has.
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

    // Run it the way someone in trouble would: a shell, the extracted directory, and no
    // rad-backup anywhere. The target is given as the argument the README documents, with
    // HOME and RAD_HOME both pointed elsewhere: HOME so a bug in the script cannot reach
    // the real home of whoever is running the tests, RAD_HOME so that the argument being
    // ignored, which is what it used to be, shows up as a failure rather than as a pass.
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
    // The fixture home holds exactly one repository, and the closing line the script prints is
    // the last thing somebody reads before deciding the restore worked. `term::count` is the
    // rule this tool holds its own output to; the shipped script has to keep it too.
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

    // And a second run over the home it just built, addressed the other way, refuses
    // instead of overwriting the key.
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

// Unix only: it runs the copy-paste block from `RESTORE.md` through a POSIX shell.
#[cfg(unix)]
// `Command::output()` gives the child a pipe, which is the case this guards: the sheet is
// the key in the clear, so `paper` refuses a terminal but must keep working when piped.
// Written as "refuse whenever --output is absent" the guard would take piping away, and
// this test is what goes red if anyone writes it that way.
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

    // The block a reader in a recovery panic pastes whole. Its guard used to only echo, and
    // the `cp` that ends whatever identity is already there was the very next line.
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
}

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

// Unix only: it runs the shipped POSIX script, which Windows has no shell for.
#[cfg(unix)]
/// A hostile manifest must not steer `git symbolic-ref` by way of the shipped script.
///
/// `symbolic-ref` accepts no `--`, so a `head` of `-d` is read as a flag rather than as the
/// branch the repository is supposed to point at. `rad-backup` refuses such a manifest; this
/// is the same refusal in the script that runs when `rad-backup` is not there.
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

    // Planted the way a hostile archive would carry it, on every repository the manifest
    // names.
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
    // A skip, not a bail-out: the refs are the repository, and HEAD is only a pointer into
    // them, so refusing the pointer must not cost the history it points at.
    assert!(stdout(&ran).contains("1 repository"), "{}", stdout(&ran));
    assert!(
        target
            .join("storage/z3gqcJUoA1n9HaHKufZs5FCSGazv5/refs")
            .exists(),
        "the repository was dropped rather than restored without its HEAD"
    );
}

// Unix only: it rebuilds the archive by shelling out to `tar`, and the entry names have to
// stay `/`-separated for the reader to match them, which a Windows path does not give.
#[cfg(unix)]
/// This tool must make the same skip the shipped script makes, over the same planted `HEAD`.
///
/// It did not. `set_head` returned an error from inside the closure that puts a repository
/// back, so a `head` of `-d` failed the whole `restore_one`, the freshly unbundled history was
/// swept, and the repository landed in the dropped list. The refusal that was there to keep a
/// hostile value away from `git symbolic-ref` was costing the repository it protected.
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
    assert_success(&ran, "restoring an archive whose manifest names a bad head");
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

/// The two readers of an archive must refuse the same `HEAD` values.
///
/// The real `case` is lifted out of `assets/restore.sh` rather than restated, so a change to
/// one reader that is not made to the other fails here. The table repeats
/// `git::tests::a_head_under_refs_that_climbs_out_of_the_repository_is_refused` and adds the
/// cases only a shell can get wrong, because a bin-only crate has no library to call into.
// Unix only: it runs the shipped script's own `case` through a POSIX shell.
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
        // A branch named in a language with accents is a ref like any other, and a shell
        // whose character classes work per byte must not quietly drop its HEAD.
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

/// The shipped script must say what this tool says about a git that checks nothing.
///
/// `fetch.fsckObjects` reaches a bundle only from git 2.46, and both readers pass it. A reader
/// that stayed quiet on an older git would hand back a home that looks exactly like one whose
/// objects were checked, so both say so, and this pins the version boundary the script draws.
///
/// The real block is lifted out of `assets/restore.sh` rather than restated, for the same
/// reason the `HEAD` case above is: a change made to one reader and not the other fails here.
// Unix only: it runs the shipped script's own shell.
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
    // The version comes from the environment rather than from the git that is installed, so
    // the table below can ask about versions this machine does not have.
    let lifted = script[start..end].replace("$(git --version 2>/dev/null || true)", "$SAID");
    assert!(
        lifted.contains("$SAID") && lifted.contains("2.46"),
        "the block no longer has what this substitutes, so it is not being tested: {lifted}"
    );

    // A version and whether the script must warn about it. The tails are the ones
    // distributions actually ship, and the last row is what an unreadable answer must do.
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
            // The same version with nothing to unbundle. That is every identity-only
            // archive, and a warning about the repositories below is describing a risk
            // this restore is not taking.
            let ran = under_shell(shell, &lifted, &[("SAID", said), ("bundles", "")]);
            assert_eq!(
                stderr(&ran),
                "",
                "under {shell}, {said:?} spoke about bundles on an archive carrying none"
            );
        }
        // Nothing that reads as a version at all: neither claim can be made, and saying
        // nothing would be the claim that it checked. `2` is here because the two readers
        // once disagreed about it, the shell warning where `rad-backup` said it could not
        // tell, and a bare number is the only shape a dot-stripping reader gets wrong.
        for said in [
            "git version next",
            "git version 2",
            "git version 2.x",
            "git version",
        ] {
            let ran = under_shell(shell, &lifted, &[("SAID", said), ("bundles", "yes")]);
            assert!(
                stderr(&ran).contains("could not be read"),
                "under {shell}, {said:?}: {}",
                stderr(&ran)
            );
        }
        // Git absent altogether says nothing here. The script dies a few lines later on the
        // first git it runs, and that failure names the missing tool; a sentence about what
        // a bundle was checked for would only be read first and answer a different question.
        let ran = under_shell(shell, &lifted, &[("SAID", ""), ("bundles", "yes")]);
        assert_eq!(stderr(&ran), "", "under {shell}, git being absent");
    }
}

/// Rebuild an archive with `-d` planted as every repository's `HEAD`, the way a hostile or a
/// corrupt manifest would carry it.
///
/// Every file is named to `tar` one by one rather than by its directory, because the reader
/// matches `manifest.json` by its exact entry name and a directory argument would add entries
/// the original archive never had.
// Unix only: its one caller is, and it reaches `collect_files`, which is too.
#[cfg(unix)]
fn repack_with_a_planted_head(fixture: &Fixture, archive: &Path) -> PathBuf {
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

/// A `diff` against a `--repos all` archive must not report somebody else's repositories gone.
///
/// The archive describes every repository in storage; a comparison that only ever looked at
/// this peer's own found the rest missing, said so, and exited `3`, every run, forever. A
/// scheduled `diff` whose whole job is to answer "did anything change, or can the backup be
/// skipped" therefore never answered "nothing changed" again.
#[test]
fn a_diff_against_an_archive_of_everything_does_not_report_a_foreign_repository_gone() {
    let fixture = Fixture::create("diff-foreign");
    let backups = fixture.path("backups");

    // A bare repository in storage under a namespace that is not this peer's: what a seed
    // holds for other people, and what `--repos all` carries while `mine` never names.
    const FOREIGN: &str = "z2rGGGeuiMJUpZTUBUdyKzsBQU3xz";
    let foreign = fixture.home().join("storage").join(FOREIGN);
    git(
        &["init", "--quiet", "--bare", &foreign.to_string_lossy()],
        &fixture.path("."),
    );
    // Given history, because an archive of everything bundles it, and a bundle of nothing is
    // an error rather than an empty bundle.
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

/// The whole wiring of the two-nodes-one-key warning, end to end.
///
/// `backup` stamps the manifest with whether the run retires this machine's key, `restore`
/// copies that into the state file, and `doctor` reads it back. Every one of those is a place
/// the answer can be lost, and losing it means the check quietly passes on the hazard it was
/// added for.
#[test]
fn a_home_restored_from_an_ordinary_backup_is_told_the_source_machine_still_holds_the_key() {
    let fixture = Fixture::create("sole-holder");
    let backups = fixture.path("backups");

    let ran = fixture.run(
        &["--output", &backups.to_string_lossy(), "--yes"],
        &fixture.home(),
    );
    assert_success(&ran, "taking a backup");
    let archive = only_archive(&backups);

    // The home the archive was taken from: nothing was restored here, so there is no second
    // machine to warn about.
    let ran = fixture.run(&["doctor", "--json"], &fixture.home());
    assert_eq!(verdict_of(&ran, "key copies"), "pass");

    // How many checks the command runs, asked of the command itself. `doctor.rs` keeps a
    // hand-written list of every check for the rules that sweep their topics, and a tenth
    // check added to `examine` alone would be swept by none of them: this is the half of the
    // pair that notices. Raise both when a check is added, and put it in `every_topic` too.
    let report: serde_json::Value =
        serde_json::from_str(&stdout(&ran)).expect("the doctor report is json");
    assert_eq!(report["total"], 9, "{report}");

    let restored = fixture.path("restored");
    let ran = fixture.run(&["restore", "--yes", &archive.to_string_lossy()], &restored);
    assert_success(&ran, "restoring the archive");

    // And the home it was restored into, which now holds a key another machine also holds.
    let ran = fixture.run(&["doctor", "--json"], &restored);
    assert_eq!(verdict_of(&ran, "key copies"), "warn");
    let report: serde_json::Value =
        serde_json::from_str(&stdout(&ran)).expect("the doctor report is json");
    let check = report["checks"]
        .as_array()
        .expect("the report lists checks")
        .iter()
        .find(|check| check["topic"] == "key copies")
        .expect("the check is in the report");
    assert!(
        check["remedy"].is_string(),
        "a warning with no way out is a nag: {check}"
    );
}

/// The verdict of one doctor check, by topic, out of a `--json` run.
fn verdict_of(ran: &Output, topic: &str) -> String {
    let report: serde_json::Value =
        serde_json::from_str(&stdout(ran)).expect("the doctor report is json");
    report["checks"]
        .as_array()
        .expect("the report lists checks")
        .iter()
        .find(|check| check["topic"] == topic)
        .and_then(|check| check["verdict"].as_str())
        .unwrap_or_else(|| panic!("no check named {topic} in {}", stdout(ran)))
        .to_string()
}

/// The flow the README recommends for an unattended timer, proven end to end: an archive
/// encrypted to a machine's own ssh public key, opened again with the private half. That half
/// is passphrase-protected, because that is the normal state of an ssh key and what `rad auth`
/// writes.
///
/// It did not work. age reports a key it could not unlock exactly as it reports a key that is
/// not a recipient at all, so someone holding the correct key, in a real recovery, was told
/// the key was wrong and no prompt ever appeared.
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

    // The run itself names the key, not only the note beside the archive: the note is read in
    // the middle of a recovery, and this is read while whoever set the timer up is still
    // watching and could still go and check they have the private half.
    let said = stderr(&ran);
    assert!(said.contains("opens only with the private half"), "{said}");
    assert!(said.contains(recipient.trim()), "{said}");

    // The note beside the archive is what a person who no longer has this tool reads. For a
    // recipient archive a bare `age -d` asks for a passphrase that does not exist, so the note
    // has to name the key instead, on both the with-tool and the without-tool path.
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

    // Nothing to unlock the key with, which is where a timer lands. The run must name the key
    // it could not open rather than call it the wrong one.
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

    // The other two ways in. RAD_BACKUP_IDENTITY_PASSPHRASE is what the CHANGELOG offers a
    // timer, and RAD_BACKUP_IDENTITY_PASSPHRASE_FILE is the flag's own variable: both are
    // read by clap and by `read_passphrase` rather than by anything a unit test can see, so
    // if they are wrong nothing else here would notice.
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
