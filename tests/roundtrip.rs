//! What the tool promises, proven end to end against the binary that ships.
//!
//! Every fixture here is built by running `rad-backup` itself, so the tests need nothing on
//! the machine that the tool does not already need: `git`, and nothing else. The identity
//! comes from a fixed mnemonic, which makes every run produce the same DID and makes a
//! failure reproducible from the test name alone.

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

    fn command(&self, args: &[&str], home: &Path) -> Command {
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
            // A `rad` on PATH would reach for a node this fixture does not have.
            .env("RAD", "/nonexistent/rad");
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

#[test]
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
