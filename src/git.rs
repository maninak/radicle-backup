//! The git operations a backup needs, and nothing more.

use std::path::Path;

use crate::error::{Error, Result};
use crate::exec::Tool;

/// A ref name and the object it points at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ref {
    pub name: String,
    pub oid: String,
}

pub struct Git {
    tool: Tool,
}

impl Default for Git {
    fn default() -> Self {
        Self::new()
    }
}

impl Git {
    pub fn new() -> Self {
        Self { tool: Tool::git() }
    }

    pub fn is_available(&self) -> bool {
        self.tool.is_available()
    }

    pub fn version(&self) -> Result<String> {
        Ok(self.tool.output(&["--version"])?.trim().to_string())
    }

    /// Whether this git checks the objects in a bundle it fetches from, which `unbundle` asks
    /// for and older gits accept and ignore. `None` when the version could not be read.
    pub fn fsck_reaches_a_bundle(&self) -> Option<bool> {
        version_checks_a_bundle(&self.version().ok()?)
    }

    /// Every ref in the repository, sorted by name so that two runs over an unchanged
    /// repository produce identical output.
    pub fn refs(&self, git_dir: &Path) -> Result<Vec<Ref>> {
        let printed = self.tool.output(&[
            "--git-dir".as_ref(),
            git_dir.as_os_str(),
            "for-each-ref".as_ref(),
            "--sort=refname".as_ref(),
            "--format=%(objectname) %(refname)".as_ref(),
        ])?;
        Ok(printed
            .lines()
            .filter_map(|line| line.split_once(' '))
            .map(|(oid, name)| Ref {
                name: name.to_string(),
                oid: oid.to_string(),
            })
            .collect())
    }

    /// What `HEAD` is a symbolic ref to, which a bundle does not carry and a restore must set
    /// back by hand.
    pub fn head_target(&self, git_dir: &Path) -> Result<Option<String>> {
        let printed = self.tool.answer(&[
            "--git-dir".as_ref(),
            git_dir.as_os_str(),
            "symbolic-ref".as_ref(),
            "HEAD".as_ref(),
        ])?;
        Ok(printed.map(|target| target.trim().to_string()))
    }

    /// Whether `ancestor` is reachable from `descendant`, or that git could not say.
    ///
    /// `git merge-base` exits 128 over an oid it cannot resolve or an object it cannot read.
    /// Never fold that into "no", because a no here reports the user's own history as forked.
    pub fn is_ancestor(
        &self,
        git_dir: &Path,
        ancestor: &str,
        descendant: &str,
    ) -> Result<crate::exec::Answer> {
        self.tool.answers(&[
            "--git-dir".as_ref(),
            git_dir.as_os_str(),
            "merge-base".as_ref(),
            "--is-ancestor".as_ref(),
            ancestor.as_ref(),
            descendant.as_ref(),
        ])
    }

    /// Whether this copy holds the object `oid` names.
    ///
    /// Never peel the oid with `^{commit}`, because a peel turns a missing object into the
    /// exit 128 an unreadable repository gives. Bare, `cat-file -e` exits 1 for absent.
    pub fn holds_object(&self, git_dir: &Path, oid: &str) -> Result<crate::exec::Answer> {
        self.tool.answers(&[
            "--git-dir".as_ref(),
            git_dir.as_os_str(),
            "cat-file".as_ref(),
            "-e".as_ref(),
            oid.as_ref(),
        ])
    }

    /// Writes every ref in the repository, namespaces included, into one bundle file.
    ///
    /// `--all` covers `refs/*` and `HEAD`, which on a Radicle repository means every peer's
    /// namespace and its `rad/sigrefs`.
    pub fn bundle(&self, git_dir: &Path, bundle: &Path) -> Result<()> {
        self.tool.output(&[
            "--git-dir".as_ref(),
            git_dir.as_os_str(),
            "bundle".as_ref(),
            "create".as_ref(),
            "--quiet".as_ref(),
            bundle.as_os_str(),
            "--all".as_ref(),
        ])?;
        Ok(())
    }

    /// The refs a bundle carries. Reading them also checks that the bundle is well formed,
    /// with no repository needed.
    pub fn bundle_refs(&self, bundle: &Path) -> Result<Vec<Ref>> {
        let printed =
            self.tool
                .output(&["bundle".as_ref(), "list-heads".as_ref(), bundle.as_os_str()])?;
        Ok(printed
            .lines()
            .filter_map(|line| line.split_once(' '))
            .map(|(oid, name)| Ref {
                name: name.to_string(),
                oid: oid.to_string(),
            })
            .collect())
    }

    pub fn init_bare(&self, git_dir: &Path) -> Result<()> {
        self.tool.output(&[
            "init".as_ref(),
            "--bare".as_ref(),
            "--quiet".as_ref(),
            git_dir.as_os_str(),
        ])?;
        Ok(())
    }

    /// Everything a config file says, through git's own parser, as `name\nvalue\0` per
    /// setting. `None` for a file git will not read, which is any malformed one.
    pub fn config_listing(&self, file: &Path) -> Result<Option<String>> {
        // `--no-includes` is git's default for `--file` and is spelled out anyway, because an
        // `include.path` in an unvouched archive would read a config from a path it chose
        self.tool.answer(&[
            "config".as_ref(),
            "--no-includes".as_ref(),
            "--file".as_ref(),
            file.as_os_str(),
            "--list".as_ref(),
            "-z".as_ref(),
        ])
    }

    /// Writes one setting into a repository's own config, returning git's words if it refused.
    ///
    /// git quotes and escapes the value for its own reader. A hand-written value git cannot
    /// parse breaks every later git command in that repository.
    pub fn set_config(&self, git_dir: &Path, name: &str, value: &str) -> Result<Option<String>> {
        self.tool.refused(&[
            "--git-dir".as_ref(),
            git_dir.as_os_str(),
            "config".as_ref(),
            name.as_ref(),
            value.as_ref(),
        ])
    }

    /// Pulls every ref out of a bundle into a repository, keeping ref names as they were.
    ///
    /// `fetch.fsckObjects` is on, because the archive's digests only prove which bundle was
    /// shipped, and a `.git` or `..` tree entry would reach storage unchecked. Gits older
    /// than `FSCK_ON_A_BUNDLE_SINCE` skip it silently, which `fsck_reaches_a_bundle` detects.
    pub fn unbundle(&self, git_dir: &Path, bundle: &Path) -> Result<()> {
        self.tool.output(&unbundle_args(git_dir, bundle))?;
        Ok(())
    }

    /// Points `HEAD` at a ref, refusing a target that does not name one.
    ///
    /// `symbolic-ref` takes no `--`, so an unvouched manifest's `head: "-d"` would otherwise
    /// reach git as a flag.
    pub fn set_head(&self, git_dir: &Path, target: &str) -> Result<()> {
        if !names_a_ref(target) {
            return Err(Error::refused(
                format!("`{target}` does not name a ref, so HEAD was left alone"),
                "the archive records a wrong HEAD for this repository. Its history is not affected",
            ));
        }
        self.tool.output(&[
            "--git-dir".as_ref(),
            git_dir.as_os_str(),
            "symbolic-ref".as_ref(),
            "HEAD".as_ref(),
            target.as_ref(),
        ])?;
        Ok(())
    }
}

/// Whether a `HEAD` out of a manifest names a ref, by roughly git's own refname rules.
///
/// `git symbolic-ref` writes whatever it is given, so `refs/../../evil` is accepted and the
/// next update of that ref writes a file outside the repository, straight into `storage`.
pub fn names_a_ref(target: &str) -> bool {
    let Some(rest) = target.strip_prefix("refs/") else {
        return false;
    };
    !rest.is_empty()
        && rest.split('/').all(|part| {
            !part.is_empty()
                // A leading dot covers `.` and `..`, so no component leaves the repository
                && !part.starts_with('.')
                && !part.ends_with(".lock")
                && part
                    .chars()
                    .all(|c| !c.is_ascii_control() && !" ~^:?*[\\".contains(c))
        })
}

/// The arguments `unbundle` passes to git.
///
/// These live in a function of their own so a test can assert the object check on any
/// machine, including one whose git ignores it.
fn unbundle_args<'a>(git_dir: &'a Path, bundle: &'a Path) -> [&'a std::ffi::OsStr; 9] {
    [
        "-c".as_ref(),
        FSCK_ON_FETCH.as_ref(),
        "--git-dir".as_ref(),
        git_dir.as_os_str(),
        "fetch".as_ref(),
        "--quiet".as_ref(),
        "--force".as_ref(),
        bundle.as_os_str(),
        "refs/*:refs/*".as_ref(),
    ]
}

/// The setting that asks git to check the objects a fetch is about to write.
///
/// `fetch.` is narrower than `transfer.` and wins, so a user's own `transfer.fsckObjects`
/// setting cannot turn this check off.
pub(crate) const FSCK_ON_FETCH: &str = "fetch.fsckObjects=true";

/// The first git that runs `fsck` over a bundle it fetches from.
///
/// Older gits accept `-c fetch.fsckObjects=true` and ignore it on this path. Measured against
/// git 2.34.1, where a bundle carrying a `.git` tree entry unbundles without a word.
pub(crate) const FSCK_ON_A_BUNDLE_SINCE: (u32, u32) = (2, 46);

/// Whether the git that printed `said` checks a bundle it fetches from, or `None` when the
/// version cannot be read.
fn version_checks_a_bundle(said: &str) -> Option<bool> {
    Some(parse_version(said)? >= FSCK_ON_A_BUNDLE_SINCE)
}

/// The major and minor out of whatever `git --version` printed.
///
/// Tolerates distribution tails such as `2.51.0.windows.1` and `2.39.5 (Apple Git-154)`.
/// `None` for anything unreadable, because a guess would turn "could not tell" into "no".
fn parse_version(said: &str) -> Option<(u32, u32)> {
    let numbered = said
        .split_whitespace()
        .find(|word| word.starts_with(|c: char| c.is_ascii_digit()))?;
    let mut parts = numbered.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// Whether a value out of a manifest is a full sha1 or sha256 oid in hexadecimal.
///
/// Signed-ref oids reach `git merge-base --is-ancestor`, which takes no `--` and reads a
/// leading `-` as a flag. A revision expression is refused, because a real archive never
/// carries one. Revisit if Radicle ever writes a sigref as anything but a full oid.
pub fn names_an_oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.chars().all(|c| c.is_ascii_hexdigit())
}

/// Whether two oids out of the node's own records name one commit, in either letter case.
///
/// Every comparison of these oids goes through here, because two readers that disagree about
/// case report work the network holds as stranded.
pub fn same_oid(one: &str, other: &str) -> bool {
    one.eq_ignore_ascii_case(other)
}

/// The bundle file name for a repository inside an archive, shared by writer and reader.
///
/// Never build this as a `PathBuf`, because tar separates with `/` on every platform and a
/// Windows path would spell it `repos\x.bundle`, which matches no tar entry.
pub fn bundle_entry(rid: &str) -> String {
    format!("repos/{}.bundle", rid.strip_prefix("rad:").unwrap_or(rid))
}

/// The config file name for a repository inside an archive.
pub fn config_entry(rid: &str) -> String {
    format!("repos/{}.config", rid.strip_prefix("rad:").unwrap_or(rid))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn archive_entry_names_drop_the_rad_prefix_but_keep_the_identifier() {
        assert_eq!(
            bundle_entry("rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5"),
            "repos/z3gqcJUoA1n9HaHKufZs5FCSGazv5.bundle"
        );
        assert_eq!(
            config_entry("z3gqcJUoA1n9HaHKufZs5FCSGazv5"),
            "repos/z3gqcJUoA1n9HaHKufZs5FCSGazv5.config"
        );
    }

    /// Builds a repository with two commits through the real `git`, returning its `--git-dir`
    /// and the two oids, oldest first.
    pub(crate) fn two_commits(
        scratch: &crate::key::tests::TestScratch,
    ) -> (std::path::PathBuf, String, String) {
        let work = scratch.path_of("repo");
        std::fs::create_dir(&work).expect("the scratch directory is writable");
        let run = |args: &[&str]| {
            let finished = std::process::Command::new("git")
                .args(args)
                .current_dir(&work)
                .output()
                .expect("git runs");
            assert!(finished.status.success(), "git {args:?}");
            String::from_utf8_lossy(&finished.stdout).trim().to_string()
        };
        run(&["init", "-q", "-b", "master"]);
        run(&["config", "user.email", "nobody@example.invalid"]);
        run(&["config", "user.name", "Nobody"]);
        run(&["commit", "-q", "--allow-empty", "-m", "first"]);
        let first = run(&["rev-parse", "HEAD"]);
        run(&["commit", "-q", "--allow-empty", "-m", "second"]);
        let second = run(&["rev-parse", "HEAD"]);
        (work.join(".git"), first, second)
    }

    #[test]
    fn a_version_git_printed_reads_as_a_number_or_as_nothing_at_all() {
        assert_eq!(parse_version("git version 2.34.1"), Some((2, 34)));
        assert_eq!(parse_version("git version 2.46.0"), Some((2, 46)));
        // Distribution tails are why the parser reads one word of the line
        assert_eq!(parse_version("git version 2.51.0.windows.1"), Some((2, 51)));
        assert_eq!(
            parse_version("git version 2.39.5 (Apple Git-154)"),
            Some((2, 39))
        );
        // An unreadable version is `None`, which reads as "could not tell"
        assert_eq!(parse_version("git version next"), None);
        assert_eq!(parse_version(""), None);
    }

    /// The check `unbundle` asks for, asked of the git that is actually here.
    ///
    /// A `.git` tree entry (fsck's `hasDotgit`) in storage hands the next checkout a path that
    /// overwrites the repository's metadata. Both outcomes are asserted, and an old git is
    /// never skipped, because "the check did not fire" is what this test pins down.
    #[test]
    fn a_bundle_carrying_a_dotgit_tree_is_refused_by_exactly_the_gits_that_check_one() {
        let git = Git::new();
        assert!(git.is_available(), "these tests drive the real git");
        let scratch = crate::key::tests::TestScratch::create("git-hostile-bundle");
        let (git_dir, _, _) = two_commits(&scratch);

        let run = |args: &[&str]| {
            let finished = std::process::Command::new("git")
                .arg("--git-dir")
                .arg(&git_dir)
                .args(args)
                .output()
                .expect("git runs");
            assert!(finished.status.success(), "git {args:?}");
            String::from_utf8_lossy(&finished.stdout).trim().to_string()
        };
        // `mktree` writes what it is handed, so it builds the `.git` entry a hostile archive
        // would carry
        let blob = run(&["hash-object", "-w", "--stdin"]);
        let tree = {
            let mut child = std::process::Command::new("git")
                .arg("--git-dir")
                .arg(&git_dir)
                .arg("mktree")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("git mktree runs");
            {
                use std::io::Write as _;
                let mut stdin = child.stdin.take().expect("mktree reads its input");
                writeln!(stdin, "100644 blob {blob}\t.git").expect("the entry is writable");
            }
            let finished = child.wait_with_output().expect("git mktree finishes");
            assert!(finished.status.success(), "git mktree");
            String::from_utf8_lossy(&finished.stdout).trim().to_string()
        };
        let commit = run(&["commit-tree", "-m", "hostile", &tree]);
        run(&["update-ref", "refs/heads/hostile", &commit]);
        let bundle = scratch.path_of("hostile.bundle");
        let bundled = std::process::Command::new("git")
            .arg("--git-dir")
            .arg(&git_dir)
            .arg("bundle")
            .arg("create")
            .arg("-q")
            .arg(&bundle)
            .arg("refs/heads/hostile")
            .output()
            .expect("git bundle runs");
        assert!(bundled.status.success(), "the hostile bundle is buildable");

        let target = scratch.path_of("target.git");
        git.init_bare(&target)
            .expect("a bare repository is creatable");
        let unbundled = git.unbundle(&target, &bundle);

        match git.fsck_reaches_a_bundle() {
            Some(true) => {
                let refusal = unbundled.expect_err(
                    "this git checks a bundle, so a `.git` tree entry must not reach storage",
                );
                // The error is matched by name, because a refusal for an unrelated reason
                // would also satisfy a bare `is_err`
                assert!(
                    refusal.to_string().contains("hasDotgit"),
                    "the refusal is meant to be fsck naming the entry: {refusal}"
                );
            }
            Some(false) => assert!(
                unbundled.is_ok(),
                "this git does not check a bundle, so the refusal came from somewhere else \
                 and the warning the restore prints is describing the wrong thing"
            ),
            None => panic!("the version of the git running this test could not be read"),
        }
    }

    /// The fetch that opens a bundle asks for the object check, whatever git is installed.
    ///
    /// The test above sees the check fire only on a git that runs it, so this test guards the
    /// flag on every machine.
    #[test]
    fn the_fetch_that_opens_a_bundle_asks_git_to_check_what_it_writes() {
        let args = unbundle_args(
            Path::new("/storage/repo.git"),
            Path::new("/archive/a.bundle"),
        );
        let spelled: Vec<&str> = args
            .iter()
            .map(|arg| arg.to_str().expect("the fixed arguments are utf-8"))
            .collect();
        assert!(
            spelled.windows(2).any(|pair| pair == ["-c", FSCK_ON_FETCH]),
            "the object check is no longer asked for: {spelled:?}"
        );
    }

    /// The version the warning turns on, pinned whatever git runs the suite.
    ///
    /// On a git older than the boundary, `(2, 40)` or a `>` for the `>=` passes every other
    /// test. `ci/pins.sh` holds the shipped script to the same number.
    #[test]
    fn the_boundary_is_the_first_git_that_checks_a_bundle_and_not_the_one_before_it() {
        for (said, expected) in [
            ("git version 1.9.1", Some(false)),
            ("git version 2.34.1", Some(false)),
            ("git version 2.39.5 (Apple Git-154)", Some(false)),
            ("git version 2.45.2", Some(false)),
            ("git version 2.46.0", Some(true)),
            ("git version 2.46", Some(true)),
            ("git version 2.51.0.windows.1", Some(true)),
            ("git version 3.0.0", Some(true)),
            ("git version 2", None),
            ("git version next", None),
        ] {
            assert_eq!(version_checks_a_bundle(said), expected, "{said}");
        }
    }

    /// One revision resolved in an existing repository, for a test that needs an oid the
    /// helper above does not hand back.
    pub(crate) fn rev_parse(git_dir: &std::path::Path, revision: &str) -> String {
        let finished = std::process::Command::new("git")
            .arg("--git-dir")
            .arg(git_dir)
            .args(["rev-parse", revision])
            .output()
            .expect("git runs");
        assert!(finished.status.success(), "git rev-parse {revision}");
        String::from_utf8_lossy(&finished.stdout).trim().to_string()
    }

    /// Packs everything and cuts the pack short, which is damage a restore can produce. The
    /// repository still opens, and `cat-file -e` reports every object in it as absent.
    pub(crate) fn truncate_the_pack(git_dir: &std::path::Path) {
        let run = |args: &[&str]| {
            let finished = std::process::Command::new("git")
                .arg("--git-dir")
                .arg(git_dir)
                .args(args)
                .output()
                .expect("git runs");
            assert!(finished.status.success(), "git {args:?}");
        };
        run(&["repack", "-a", "-d", "-q"]);
        let packs = git_dir.join("objects/pack");
        let pack = std::fs::read_dir(&packs)
            .expect("the pack directory is readable")
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .find(|path| path.extension().is_some_and(|kind| kind == "pack"))
            .expect("repack wrote a pack");
        // `repack` leaves the pack read only, which blocks the write on Windows, so the pack
        // is made writable first. Unix gets owner-only, because `set_readonly(false)` there
        // hands the file to everybody.
        #[cfg(unix)]
        crate::perms::set_mode(&pack, crate::perms::MODE_SECRET)
            .expect("the pack's mode is settable");
        #[cfg(not(unix))]
        {
            let mut permissions = std::fs::metadata(&pack)
                .expect("the pack is readable")
                .permissions();
            // Clippy's lint is about unix, where clearing the flag means `0o777`. Off unix the
            // flag is one attribute bit and no mode exists.
            #[expect(
                clippy::permissions_set_readonly_false,
                reason = "off unix this is an attribute, not a mode"
            )]
            permissions.set_readonly(false);
            std::fs::set_permissions(&pack, permissions).expect("the pack's mode is settable");
        }
        // The cut clamps to the pack's length, because a panicking slice index would report a
        // broken fixture as a broken assertion
        let whole = std::fs::read(&pack).expect("the pack is readable");
        let short = whole[..whole.len().min(60)].to_vec();
        std::fs::write(&pack, short).expect("the pack is writable");
    }

    /// `merge-base` exits 128 both for an absent object and for an unopenable repository.
    /// Bare `cat-file -e` separates them, with 1 for absent and 128 for the repository.
    #[test]
    fn an_object_that_is_absent_answers_differently_from_a_repository_that_cannot_be_opened() {
        let git = Git::new();
        assert!(git.is_available(), "these tests drive the real git");
        let scratch = crate::key::tests::TestScratch::create("git-holds-object");
        let (git_dir, _, second) = two_commits(&scratch);

        assert_eq!(
            git.holds_object(&git_dir, &second).expect("git ran"),
            crate::exec::Answer::Yes
        );
        assert_eq!(
            git.holds_object(&git_dir, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
                .expect("git ran"),
            crate::exec::Answer::No
        );
        let unopenable = git
            .holds_object(std::path::Path::new("/nonexistent-git-dir"), &second)
            .expect("git ran");
        assert!(
            matches!(unopenable, crate::exec::Answer::CouldNotAsk { .. }),
            "{unopenable:?}"
        );

        // A store that cannot produce an object it has answers as one that never had it, so
        // "absent" is a fact about a lookup and not yet about the network
        truncate_the_pack(&git_dir);
        assert_eq!(
            git.holds_object(&git_dir, &second).expect("git ran"),
            crate::exec::Answer::No
        );
    }

    /// `git merge-base --is-ancestor` exits 128 when it cannot resolve an oid. Read as "not an
    /// ancestor", that exit reports the user's own peer history as forked.
    #[test]
    fn an_oid_git_cannot_resolve_is_not_an_answer_about_ancestry() {
        let git = Git::new();
        assert!(git.is_available(), "these tests drive the real git");
        let scratch = crate::key::tests::TestScratch::create("git-ancestry");
        let (git_dir, first, second) = two_commits(&scratch);

        assert_eq!(
            git.is_ancestor(&git_dir, &first, &second).expect("git ran"),
            crate::exec::Answer::Yes
        );
        assert_eq!(
            git.is_ancestor(&git_dir, &second, &first).expect("git ran"),
            crate::exec::Answer::No
        );

        let nowhere = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let unanswered = git
            .is_ancestor(&git_dir, nowhere, &second)
            .expect("git ran");
        assert!(
            matches!(unanswered, crate::exec::Answer::CouldNotAsk { .. }),
            "{unanswered:?}"
        );
    }

    /// The signed-ref oids in a manifest reach a command line. `merge-base` takes no `--`, so
    /// a leading `-` would read as a flag, and a revision expression would resolve something
    /// nobody vouched for.
    #[test]
    fn only_a_plain_hexadecimal_oid_out_of_a_manifest_reaches_git() {
        assert!(names_an_oid("da39a3ee5e6b4b0d3255bfef95601890afd80709"));
        assert!(names_an_oid(&"a".repeat(64)));

        assert!(!names_an_oid("--output=/etc/passwd"));
        assert!(!names_an_oid("-h"));
        assert!(!names_an_oid("HEAD"));
        assert!(!names_an_oid("master^"));
        assert!(!names_an_oid("da39a3ee"));
        assert!(!names_an_oid(""));
        assert!(!names_an_oid(&"g".repeat(40)));
    }

    #[test]
    fn a_head_that_does_not_name_a_ref_is_refused_before_git_is_asked() {
        // `symbolic-ref` takes no `--`, so this check keeps a hostile manifest's value from
        // reaching git as a flag. The refusal comes before the spawn, so no git is needed.
        let git = Git::new();
        let dir = Path::new("/nonexistent/repo.git");
        assert!(git.set_head(dir, "-d").is_err());
        assert!(git.set_head(dir, "--version").is_err());
        assert!(git.set_head(dir, "master").is_err());
        assert!(git.set_head(dir, "").is_err());
    }

    #[test]
    fn a_head_under_refs_that_climbs_out_of_the_repository_is_refused() {
        // `git symbolic-ref` stores this, and the next update of the ref writes beside the
        // repository, which in a Radicle home is `storage`. Reproduced against git 2.34.
        assert!(!names_a_ref("refs/../../evil"));
        assert!(!names_a_ref("refs/heads/../../../etc/x"));
        assert!(!names_a_ref("refs/"));
        assert!(!names_a_ref("refs/heads/"));
        assert!(!names_a_ref("refs//heads/x"));
        assert!(!names_a_ref("refs/heads/.hidden"));
        assert!(!names_a_ref("refs/heads/x.lock"));
        assert!(!names_a_ref("refs/heads/a b"));
        assert!(!names_a_ref("refs/heads/a^b"));
        // Real archive names still pass, or the guard would cost every restore its pointer
        assert!(names_a_ref("refs/heads/master"));
        assert!(names_a_ref("refs/heads/feature/nested"));
        assert!(names_a_ref("refs/heads/v1.0"));
        assert!(names_a_ref("refs/namespaces/z6Mk/refs/heads/master"));
        // Only ASCII control characters are refused, so a branch name with accents keeps its
        // HEAD
        assert!(names_a_ref("refs/heads/caf\u{e9}"));
    }
}
