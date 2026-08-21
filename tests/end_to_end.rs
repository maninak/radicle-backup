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
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("the fixture root is creatable");
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
        let out = self.run_with_stdin(&["restore", "--words", "--yes"], &self.home(), WORDS);
        assert_success(&out, "restoring the fixture identity from words");
        assert!(
            stderr(&out).contains(DID),
            "the fixed mnemonic no longer rebuilds {DID}: {}",
            stderr(&out)
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

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn git(args: &[&str], cwd: &Path) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::metadata(path)
        .expect("the file is there")
        .permissions()
        .mode()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn assert_success(out: &Output, what: &str) {
    assert!(
        out.status.success(),
        "{what} exited {:?}: {}",
        out.status.code(),
        stderr(out)
    );
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

#[test]
fn without_git_a_restore_says_no_repositories_came_back_instead_of_reporting_success() {
    let fixture = Fixture::create("restore-without-git");
    let backups = fixture.path("backups");

    let out = fixture.run(
        &[
            "--tier",
            "full",
            "--output",
            &backups.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    assert_success(&out, "taking a full backup");
    let archive = only_archive(&backups);

    let restored = fixture.path("restored");
    let out = fixture
        .command(&["restore", "--yes", &archive.to_string_lossy()], &restored)
        .env("GIT", "/nonexistent/git")
        .output()
        .expect("rad-backup runs");
    let said = stderr(&out);

    // The identity is genuinely back, so this is not a failed restore.
    assert!(
        restored.join("keys/radicle").is_file(),
        "the identity should still be restored: {said}"
    );
    // But every repository the archive carried is missing, and a run that exits 0 over that
    // is a scheduled restore nobody ever hears about again.
    assert_eq!(
        out.status.code(),
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
    let scratch_hint = said
        .lines()
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

    let out = fixture.run(
        &[
            "--tier",
            "full",
            "--output",
            &backups.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    assert_success(&out, "taking a full backup");
    let archive = only_archive(&backups);

    let out = fixture.run(
        &["verify", "--deep", &archive.to_string_lossy()],
        &fixture.home(),
    );
    assert_success(&out, "verifying the archive");
    assert!(stderr(&out).contains(DID), "{}", stderr(&out));

    let restored = fixture.path("restored");
    let out = fixture.run(&["restore", "--yes", &archive.to_string_lossy()], &restored);
    assert_success(&out, "restoring the archive");

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

    let out = fixture.run(
        &[
            "--plaintext",
            "--output",
            &backups.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    assert_success(&out, "taking a plaintext backup");
    let archive = only_archive(&backups);

    // Plaintext, so the damage is caught by the manifest's digests rather than by age.
    let mut bytes = std::fs::read(&archive).expect("the archive is readable");
    let middle = bytes.len() / 2;
    bytes[middle] ^= 0xff;
    std::fs::write(&archive, &bytes).expect("the archive is writable");

    let out = fixture.run(&["verify", &archive.to_string_lossy()], &fixture.home());
    assert!(
        !out.status.success(),
        "a damaged archive verified clean: {}",
        stderr(&out)
    );
}

#[test]
fn verify_deep_without_git_says_in_one_readable_sentence_what_it_could_not_open() {
    let fixture = Fixture::create("verify-deep-without-git");
    let backups = fixture.path("backups");

    let out = fixture.run(
        &[
            "--tier",
            "full",
            "--output",
            &backups.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    assert_success(&out, "taking a full backup");
    let archive = only_archive(&backups);

    let out = fixture
        .command(
            &["verify", "--deep", &archive.to_string_lossy()],
            &fixture.home(),
        )
        .env("GIT", "/nonexistent/git")
        .output()
        .expect("rad-backup runs");
    let said = stderr(&out);

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

    let out = fixture.run(
        &[
            "--tier",
            "full",
            "--output",
            &backups.to_string_lossy(),
            "--yes",
        ],
        &fixture.home(),
    );
    assert_success(&out, "taking a full backup");

    let out = fixture.run(&["diff"], &fixture.home());
    assert_success(&out, "diffing an unchanged home");
    assert!(
        stderr(&out).contains("nothing has changed"),
        "{}",
        stderr(&out)
    );

    fixture.advance();

    let out = fixture.run(&["diff", "--json"], &fixture.home());
    assert_eq!(
        out.status.code(),
        Some(3),
        "a changed home should exit 3: {}",
        stderr(&out)
    );
    let report: serde_json::Value =
        serde_json::from_str(&stdout(&out)).expect("--json prints json");
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

    let out = fixture.run(
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
    assert_success(&out, "taking a private-selection archive");
    let said = stderr(&out).to_string();

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

    let out = fixture.run(
        &["--output", &backups.to_string_lossy(), "--yes"],
        &fixture.home(),
    );
    assert_success(&out, "taking a state backup");
    let archive = only_archive(&backups);

    let out = fixture.run(
        &["show", "--json", &archive.to_string_lossy()],
        &fixture.home(),
    );
    assert_success(&out, "showing the archive");
    let manifest: serde_json::Value =
        serde_json::from_str(&stdout(&out)).expect("--json prints json");

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

    let out = fixture.run(
        &["--output", &backups.to_string_lossy(), "--yes"],
        &fixture.home(),
    );
    assert_success(&out, "taking a backup");
    let archive = only_archive(&backups);

    let before = std::fs::read(fixture.home().join("keys/radicle")).expect("the key is readable");
    let out = fixture.run(
        &["restore", "--yes", &archive.to_string_lossy()],
        &fixture.home(),
    );
    assert_eq!(out.status.code(), Some(4), "{}", stderr(&out));
    let after = std::fs::read(fixture.home().join("keys/radicle")).expect("the key is readable");
    assert_eq!(before, after, "a refused restore still touched the key");
}

/// Restoring over a home that holds a DIFFERENT identity must file the old key, not delete
/// it: the key is the identity, and there is no way back from overwriting one.
#[test]
fn restoring_over_another_identity_keeps_the_key_it_displaces() {
    let fixture = Fixture::create("displaced");
    let backups = fixture.path("backups");

    let out = fixture.run(
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
    assert_success(&out, "taking an identity archive");
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

    let out = fixture.run(
        &["restore", "--force", "--yes", &archive.to_string_lossy()],
        &occupied,
    );
    assert_success(&out, "restoring over another identity");

    let retired = occupied.join("keys/radicle.retired");
    assert!(
        retired.is_file(),
        "the displaced key must be kept: {}",
        stderr(&out)
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
    let out = fixture.run(
        &["--output", &backups.to_string_lossy(), "--yes"],
        &fixture.home(),
    );
    assert_success(&out, "taking a state backup");
    let archive = only_archive(&backups);

    let restored = fixture.path("restored");
    let out = fixture.run(&["restore", "--yes", &archive.to_string_lossy()], &restored);
    assert_success(&out, "restoring the archive");

    let out = fixture.run(&["diff"], &restored);
    assert_success(&out, "diffing a freshly restored home");
    assert!(
        stderr(&out).contains("nothing has changed"),
        "a restore should leave nothing to report: {}",
        stderr(&out)
    );

    // Asserted on the detail rather than the topic, because the topic prints whatever the
    // verdict is: matching it would pass just as happily on "no archive has ever been taken".
    let out = fixture.run(&["doctor"], &restored);
    assert!(
        stderr(&out).contains("archive was taken"),
        "a restored home should know its archive: {}",
        stderr(&out)
    );
}

#[test]
fn with_no_archive_named_a_command_acts_on_the_newest_one_and_says_which() {
    let fixture = Fixture::create("newest");
    let backups = fixture.path("backups");
    let dir = backups.to_string_lossy().into_owned();

    let out = fixture.run(&["--output", &dir, "--yes"], &fixture.home());
    assert_success(&out, "taking the first archive");
    // The name carries a whole-second stamp, so two archives need a second between them.
    std::thread::sleep(std::time::Duration::from_millis(1100));
    fixture.advance();
    let out = fixture.run(&["--output", &dir, "--yes"], &fixture.home());
    assert_success(&out, "taking the second archive");

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
    let out = fixture
        .command(&["show", "--json"], &fixture.home())
        .env("RAD_BACKUP_DIR", &dir)
        .output()
        .expect("rad-backup runs");
    assert_success(&out, "showing the newest archive");
    assert!(
        stderr(&out).contains(&newest),
        "the archive it chose must be named on stderr: {}",
        stderr(&out)
    );
    let manifest: serde_json::Value =
        serde_json::from_str(&stdout(&out)).expect("--json prints json");
    let shown = manifest["created"].as_str().expect("a created stamp");

    let out = fixture
        .command(
            &["show", "--json", &archives[0].to_string_lossy()],
            &fixture.home(),
        )
        .output()
        .expect("rad-backup runs");
    let older: serde_json::Value = serde_json::from_str(&stdout(&out)).expect("--json prints json");
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
        let out = fixture.run(&["--output", &dir, "--yes"], &fixture.home());
        assert_success(&out, "taking an archive");
        std::thread::sleep(std::time::Duration::from_millis(1100));
    }
    // A file this tool did not write, and one belonging to another identity.
    let bystander = backups.join("holiday-photos.tar.zst");
    let other = backups.join("someone-z6MkvAFBkdph-20200101T000000Z.tar.zst.age");
    std::fs::write(&bystander, b"not an archive").expect("the fixture file is writable");
    std::fs::write(&other, b"another identity").expect("the fixture file is writable");

    let out = fixture.run(
        &["prune", "--keep", "1", "--dir", &dir, "--yes"],
        &fixture.home(),
    );
    assert_success(&out, "pruning");

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
    let fixture = Fixture::create("rehearsal");
    let backups = fixture.path("backups");
    let dir = backups.to_string_lossy().into_owned();

    let out = fixture.run(
        &["--dry-run", "--tier", "full", "--output", &dir],
        &fixture.home(),
    );
    assert_success(&out, "rehearsing a backup");
    assert!(
        stderr(&out).contains("nothing was written"),
        "a dry run must say that it wrote nothing: {}",
        stderr(&out)
    );
    assert!(
        !backups.exists() || std::fs::read_dir(&backups).into_iter().flatten().count() == 0,
        "a dry run must leave the output directory empty"
    );
}

#[test]
fn a_dry_run_asked_for_json_answers_with_json() {
    let fixture = Fixture::create("rehearsal-json");
    let dir = fixture.path("backups").to_string_lossy().into_owned();

    let out = fixture.run(
        &["--dry-run", "--json", "--tier", "full", "--output", &dir],
        &fixture.home(),
    );
    assert_success(&out, "rehearsing a backup as json");

    // `--json` was honoured by every reporting path except this one, which printed the human
    // table on stdout. A consumer got something that parses as far as the first line.
    let report: serde_json::Value =
        serde_json::from_str(&stdout(&out)).expect("--dry-run --json prints json");
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

    let out = fixture.run(
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
    let said = stderr(&out);

    assert_eq!(
        out.status.code(),
        Some(3),
        "a backup missing a repository must not exit 0: {said}"
    );
    // And the archive is still written, because everything else in the home is worth having.
    let archive = only_archive(&backups);
    assert!(archive.is_file(), "the archive should still exist: {said}");
    assert!(said.contains(RID), "it has to name what it lost: {said}");
}

/// The shipped script and this tool are two implementations of one restore, kept in step by
/// policy (guardrail: an archive never depends on this tool to be read). Nothing enforced that
/// they stayed in step, so anything added to one side only, the way `repos/*.config` or the
/// HEAD restore could have been, would have gone unnoticed until somebody needed the other.
#[test]
fn the_shipped_script_skips_a_bundle_whose_name_is_not_a_repository_id() {
    let fixture = Fixture::create("script-rid");
    let backups = fixture.path("backups");

    let out = fixture.run(
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
    assert_success(&out, "taking a plaintext archive");

    let extracted = fixture.path("extracted");
    std::fs::create_dir_all(&extracted).expect("the extraction directory is creatable");
    let archive = std::fs::read(only_archive(&backups)).expect("the archive is readable");
    let mut tarball = Vec::new();
    zstd::stream::copy_decode(archive.as_slice(), &mut tarball).expect("the archive decompresses");
    std::fs::write(extracted.join("archive.tar"), &tarball).expect("the tarball is writable");
    let out = Command::new("tar")
        .args(["-xf", "archive.tar"])
        .current_dir(&extracted)
        .output()
        .expect("tar runs");
    assert_success(&out, "extracting the archive");

    // A name no `rad` would mint, planted the way a hostile archive would carry it. The tool
    // refuses such an archive outright; the script has to refuse the one bundle and go on,
    // because it is the path that runs when the tool is not there to refuse anything.
    std::fs::write(extracted.join("repos/a..b.bundle"), b"not a bundle")
        .expect("the planted bundle is writable");

    let target = fixture.path("by-script");
    let out = Command::new("sh")
        .args(["restore.sh", &target.to_string_lossy()])
        .current_dir(&extracted)
        .env("HOME", fixture.path("fake-home"))
        .env("RAD_HOME", fixture.path("decoy-home"))
        .output()
        .expect("the restore script runs");
    assert_success(&out, "restoring with a planted bundle present");
    assert!(
        stderr(&out).contains("is not a repository id"),
        "{}",
        stderr(&out)
    );
    assert!(
        !target.join("storage/a..b").exists(),
        "the script made a repository out of a name that is not an id"
    );

    // And the real repository still came back, so this is a skip and not a bail-out.
    assert!(target.join("storage").join(RID).is_dir());
}

#[test]
fn the_shipped_script_and_this_tool_rebuild_the_same_home() {
    let fixture = Fixture::create("parity");
    let backups = fixture.path("backups");

    let out = fixture.run(
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
    assert_success(&out, "taking a plaintext archive");
    let archive = only_archive(&backups);

    let by_tool = fixture.path("by-tool");
    let out = fixture.run(&["restore", "--yes", &archive.to_string_lossy()], &by_tool);
    assert_success(&out, "restoring with this tool");

    let extracted = fixture.path("extracted");
    std::fs::create_dir_all(&extracted).expect("the extraction directory is creatable");
    let bytes = std::fs::read(&archive).expect("the archive is readable");
    let mut tarball = Vec::new();
    zstd::stream::copy_decode(bytes.as_slice(), &mut tarball).expect("the archive decompresses");
    std::fs::write(extracted.join("archive.tar"), &tarball).expect("the tarball is writable");
    let out = Command::new("tar")
        .args(["-xf", "archive.tar"])
        .current_dir(&extracted)
        .output()
        .expect("tar runs");
    assert_success(&out, "extracting the archive");

    let by_script = fixture.path("by-script");
    let out = Command::new("sh")
        .args(["restore.sh", &by_script.to_string_lossy()])
        .current_dir(&extracted)
        .env("HOME", fixture.path("fake-home"))
        .env("RAD_HOME", fixture.path("decoy-home"))
        .output()
        .expect("the restore script runs");
    assert_success(&out, "restoring with the shipped script");

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

    let out = fixture.run(
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
    assert_success(&out, "taking a full backup");

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
    let out = fixture.run(
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
    assert_success(&out, "taking a plaintext archive");
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

    let out = fixture.run(
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
    assert_success(&out, "taking a plaintext archive");

    let extracted = fixture.path("extracted");
    std::fs::create_dir_all(&extracted).expect("the extraction directory is creatable");
    let archive = std::fs::read(only_archive(&backups)).expect("the archive is readable");
    let mut tarball = Vec::new();
    zstd::stream::copy_decode(archive.as_slice(), &mut tarball).expect("the archive decompresses");
    let tar_path = extracted.join("archive.tar");
    std::fs::write(&tar_path, &tarball).expect("the tarball is writable");
    let out = Command::new("tar")
        .args(["-xf", "archive.tar"])
        .current_dir(&extracted)
        .output()
        .expect("tar runs");
    assert_success(&out, "extracting the archive");

    // Run it the way someone in trouble would: a shell, the extracted directory, and no
    // rad-backup anywhere. The target is given as the argument the README documents, with
    // HOME and RAD_HOME both pointed elsewhere: HOME so a bug in the script cannot reach
    // the real home of whoever is running the tests, RAD_HOME so that the argument being
    // ignored, which is what it used to be, shows up as a failure rather than as a pass.
    let target = fixture.path("by-script");
    let decoy = fixture.path("decoy-home");
    let out = Command::new("sh")
        .args(["restore.sh", &target.to_string_lossy()])
        .current_dir(&extracted)
        .env("HOME", fixture.path("fake-home"))
        .env("RAD_HOME", &decoy)
        .output()
        .expect("the restore script runs");
    assert_success(&out, "restoring with the shipped script");
    // The fixture home holds exactly one repository, and the closing line the script prints is
    // the last thing somebody reads before deciding the restore worked. `term::count` is the
    // rule this tool holds its own output to; the shipped script has to keep it too.
    let said = String::from_utf8_lossy(&out.stdout);
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
    if Command::new("sh")
        .args(["-c", "command -v jq"])
        .output()
        .is_ok_and(|out| out.status.success())
    {
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
    let out = Command::new("sh")
        .arg("restore.sh")
        .current_dir(&extracted)
        .env("HOME", fixture.path("fake-home"))
        .env("RAD_HOME", &target)
        .output()
        .expect("the restore script runs");
    assert!(
        !out.status.success(),
        "the script overwrote an occupied home: {}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("already holds an identity"),
        "{}",
        stderr(&out)
    );
}

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

    let out = std::process::Command::new("sh")
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
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_recovery_sheet_still_pipes_even_though_it_refuses_a_terminal() {
    let fixture = Fixture::create("paper-pipe");

    let out = fixture.run(&["paper"], &fixture.home());
    assert_success(&out, "rendering a paper sheet to a pipe");

    let sheet = stdout(&out);
    assert!(
        sheet.contains("<html") && sheet.contains("</html>"),
        "a piped sheet should be the whole HTML document, got {} bytes",
        sheet.len()
    );
}
