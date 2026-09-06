//! The git operations a backup needs, and nothing more.
//!
//! Repositories are archived as bundles rather than as directory copies, because a bundle is
//! a single file whose object graph git itself checks on the way in and on the way out. A
//! directory copy would also carry unreachable objects and could be silently truncated.

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

    /// Whether this git checks the objects in a bundle it is fetching from, which is what the
    /// `fetch.fsckObjects` in `unbundle` below asks for and what older gits accept and ignore.
    /// `None` when the version could not be read, which is a different sentence from "no".
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

    /// Whether `ancestor` is reachable from `descendant`.
    ///
    /// This is the fork test. `restore` asks it with a head some other node announced it holds
    /// of our signed refs as the `ancestor` and the archived head as the `descendant`: a yes
    /// means that node is simply behind us, a no means it is holding work signed under this
    /// key that the restored copy does not have, and the third answer means `git` could not
    /// say, which is a fact about this machine and not about that node.
    ///
    /// Three answers, not two. `git merge-base` exits 128 over an oid it cannot resolve or an
    /// object it cannot read, and folded into "not an ancestor" that became the loudest thing
    /// this tool says, told to somebody on the strength of an error nobody read.
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

    /// Whether this copy actually holds the object `oid` names.
    ///
    /// `restore` asks this only after `merge-base` has failed, to read that failure. A peer's
    /// sigrefs commit that is genuinely not on this disk is the fork hazard, because our own
    /// namespace is the one thing a pull never brings back; a `merge-base` that failed for any
    /// other reason is a fact about this machine and must not be reported as one about a peer.
    ///
    /// `cat-file -e` without a `^{commit}` peel, which turns a missing object into the same
    /// exit 128 an unreadable repository gives and so answers nothing. Bare, it exits 1 for
    /// absent and keeps 128 for a repository it could not open.
    pub fn holds_object(&self, git_dir: &Path, oid: &str) -> Result<crate::exec::Answer> {
        self.tool.answers(&[
            "--git-dir".as_ref(),
            git_dir.as_os_str(),
            "cat-file".as_ref(),
            "-e".as_ref(),
            oid.as_ref(),
        ])
    }

    /// Write every ref in the repository, namespaces included, into one bundle file.
    ///
    /// `--all` covers `refs/*` and `HEAD`, which on a Radicle repository means every peer's
    /// namespace and their `rad/sigrefs`.
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

    /// The refs a bundle carries. Reading them is also how a bundle is checked for being
    /// well formed without a repository to check its prerequisites against.
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

    /// Pull every ref out of a bundle and into a repository, keeping ref names as they were.
    ///
    /// With `fetch.fsckObjects`, because the bundle is the one part of an archive nothing else
    /// validates: the digests only prove it is the bundle the archive author shipped. Git's
    /// default is off, which would write a tree entry named `.git`, or a `..` component,
    /// straight into storage for the next checkout to materialise.
    ///
    /// It reaches a bundle only from git `FSCK_ON_A_BUNDLE_SINCE`. Older gits read the setting
    /// and never consult it on this path, so the objects land unchecked and nothing says so:
    /// `fsck_reaches_a_bundle` is what the restore asks in order to say it out loud.
    pub fn unbundle(&self, git_dir: &Path, bundle: &Path) -> Result<()> {
        self.tool.output(&unbundle_args(git_dir, bundle))?;
        Ok(())
    }

    /// Point `HEAD` at a ref.
    ///
    /// The target is refused unless it names a ref, because it comes out of a manifest nobody
    /// has vouched for and `symbolic-ref` accepts no `--` to fence a value off from its own
    /// flags. A manifest saying `head: "-d"` would otherwise reach git as a flag rather than
    /// as the branch this repository is supposed to point at.
    ///
    /// Kept as an error for a caller that has nothing better to do with it, but a caller
    /// restoring a repository is expected to ask `names_a_ref` first and carry on without the
    /// pointer, which is what the shipped script does.
    pub fn set_head(&self, git_dir: &Path, target: &str) -> Result<()> {
        if !names_a_ref(target) {
            return Err(Error::refused(
                format!("`{target}` does not name a ref, so HEAD was left alone"),
                "the archive's manifest is wrong about this repository; report it",
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

/// Whether a `HEAD` out of a manifest names a ref.
///
/// Separate from `set_head` so that refusing the value and losing the repository are separate
/// decisions. The refs are the repository and `HEAD` is only a pointer into them, so a caller
/// that has already unbundled the history should keep it and drop the pointer.
///
/// The `refs/` prefix alone is not enough. `git symbolic-ref` writes whatever it is given
/// without validating it, so `refs/../../evil` is accepted and the next update of that ref
/// writes a file outside the repository, in a Radicle home directly into `storage`. What is
/// left is roughly git's own refname rules, which is what a real archive carries anyway.
pub fn names_a_ref(target: &str) -> bool {
    let Some(rest) = target.strip_prefix("refs/") else {
        return false;
    };
    !rest.is_empty()
        && rest.split('/').all(|part| {
            !part.is_empty()
                // Covers `.` and `..`, so no component can climb out of the repository.
                && !part.starts_with('.')
                && !part.ends_with(".lock")
                && part
                    .chars()
                    .all(|c| !c.is_ascii_control() && !" ~^:?*[\\".contains(c))
        })
}

/// What `unbundle` runs, apart from the name of git itself.
///
/// A function of its own so that the object check can be asserted on any machine. Read off a
/// real fetch it can only be seen where git honours it, which is to say on nobody's Ubuntu
/// 22.04, and a test that passes whether or not the flag is there is the shape of test this
/// one exists to not be.
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
/// `fetch.` and not `transfer.`, because the two are read in that order and the narrower one
/// wins: a user who turned `transfer.fsckObjects` off for their own remotes would otherwise
/// turn this off with it.
pub(crate) const FSCK_ON_FETCH: &str = "fetch.fsckObjects=true";

/// The first git that runs `fsck` over a bundle it fetches from. Before it,
/// `fetch_refs_from_bundle` never asked, so `-c fetch.fsckObjects=true` was accepted and had
/// no effect on this one code path. Measured against git 2.34.1, where a bundle carrying a
/// tree entry named `.git` unbundles without a word.
pub(crate) const FSCK_ON_A_BUNDLE_SINCE: (u32, u32) = (2, 46);

/// The same question as `fsck_reaches_a_bundle`, asked of a version string rather than of the
/// git that is installed, so that both sides of the boundary can be put to it on one machine.
fn version_checks_a_bundle(said: &str) -> Option<bool> {
    Some(parse_version(said)? >= FSCK_ON_A_BUNDLE_SINCE)
}

/// The major and minor out of whatever `git --version` printed.
///
/// Tolerant of the tails distributions add, `2.51.0.windows.1` and `2.39.5 (Apple Git-154)`
/// among them, and `None` for anything it cannot read rather than a guess: the caller turns
/// `None` into "could not tell", which is not the same claim as "does not check".
fn parse_version(said: &str) -> Option<(u32, u32)> {
    let numbered = said
        .split_whitespace()
        .find(|word| word.starts_with(|c: char| c.is_ascii_digit()))?;
    let mut parts = numbered.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

/// Whether a value out of a manifest names an object git could be asked about.
///
/// The signed-ref oids in a manifest reach `git merge-base --is-ancestor <a> <b>`, which takes
/// no `--` and reads a leading `-` as one of its own flags. The rid and the `HEAD` in the same
/// manifest are already gated (`reject_hostile_rid`, `names_a_ref`) and these were not, so this
/// closes the last argv position an unvouched-for archive reaches.
///
/// Hexadecimal and nothing else, at sha1 or sha256 length, because that is what a sigref oid
/// is. Not a revision expression: `HEAD@{1}`, `master^`, and every other thing git resolves are
/// values a real archive never carries, and accepting them would put a parser between an
/// archive and a command line for no gain. Revisit if Radicle ever writes a sigref as anything
/// but a full oid.
pub fn names_an_oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.chars().all(|c| c.is_ascii_hexdigit())
}

/// Whether two oids out of the node's own records name one commit.
///
/// `names_an_oid` lets either case through and git resolves either, so two spellings of one
/// commit reach these readers as two strings. One place for the comparison, because `restore`
/// and `doctor` read the same `repo-sync-status` column and disagreeing about equality made
/// `doctor` report work as stranded on a disk the network had held for months.
pub fn same_oid(one: &str, other: &str) -> bool {
    one.eq_ignore_ascii_case(other)
}

/// The bundle file name for a repository inside an archive. One place, so the writer and the
/// reader cannot disagree about it.
///
/// A `String` holding a literal `/`, not a `PathBuf`: this names a place inside a tar, and tar
/// separates with `/` on every platform. Built as a path it came back `repos\x.bundle` on
/// Windows while tar stored `repos/x.bundle`, so the manifest accused the archive of both
/// losing an entry and carrying an unlisted one. Joining it onto a directory still works, so
/// only the naming side changes.
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

    /// A helper that drives the real `git` to build a repository with two commits in it,
    /// returning its `--git-dir` and the two oids, oldest first.
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
        // The tails distributions add, which is the reason this takes a word and not a line.
        assert_eq!(parse_version("git version 2.51.0.windows.1"), Some((2, 51)));
        assert_eq!(
            parse_version("git version 2.39.5 (Apple Git-154)"),
            Some((2, 39))
        );
        // No guess out of something unreadable: the caller says "could not tell" instead.
        assert_eq!(parse_version("git version next"), None);
        assert_eq!(parse_version(""), None);
    }

    /// The check `unbundle` asks for, asked of the git that is actually here.
    ///
    /// A tree entry named `.git` is what `fsck` calls `hasDotgit`, and writing one into
    /// storage hands the next checkout a path that overwrites the repository's own metadata.
    /// The bundle is the one part of an archive nothing else validates, so this is the whole
    /// of that promise, and it holds only from git 2.46: before it the setting was accepted
    /// and never consulted on the bundle path. Asserted both ways rather than skipped on an
    /// old git, because "the check did not fire" is the answer this test exists to pin down.
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
        // A tree holding one entry called `.git`, committed and bundled. `mktree` writes what
        // it is handed, which is how a hostile archive would carry one.
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
                // Named, because any error at all would satisfy a bare `is_err`, and a
                // refusal for an unrelated reason would then read as this check firing.
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
    /// The test above can only watch the check fire on a git that runs it on this path, which
    /// leaves every developer on an older one with a green suite and no guard at all. This is
    /// the half that holds on any machine: the flag is either in the command or it is not.
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

    /// The version the warning turns on, pinned away from the one machine running the suite.
    ///
    /// Without this the constant is asserted by nothing: on a git older than the boundary
    /// every wrong boundary older than that one answers identically, so `(2, 40)` and a `>`
    /// in place of the `>=` both pass. `ci/pins.sh` holds the same number in the shipped
    /// script to this one, so the two readers of an archive cannot drift apart either.
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

    /// Damage of the kind a restore can produce: everything packed, and the pack short. The
    /// repository still opens and every object in it stops answering, which is a state
    /// `cat-file -e` reports as "absent" rather than as a failure.
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
        // `repack` leaves the pack read only, and on Windows that is a file attribute a write
        // will not clear for itself, so the mode goes back first. Owner-only rather than
        // `set_readonly(false)`, which on unix hands the file to everybody.
        crate::perms::set_mode(&pack, crate::perms::MODE_SECRET)
            .expect("the pack's mode is settable");
        // Truncated to whatever is there when the pack is shorter than the cut, because a
        // slice index that panicked would report a broken test as a broken assertion.
        let whole = std::fs::read(&pack).expect("the pack is readable");
        let short = whole[..whole.len().min(60)].to_vec();
        std::fs::write(&pack, short).expect("the pack is writable");
    }

    /// Three answers again, and the point is that they are not the same three. `merge-base`
    /// gives 128 both for an object that is not here and for a repository it cannot open, so
    /// reading its failure needs a question that separates those, and `cat-file -e` bare is
    /// it: 1 for absent, 128 kept for the repository itself.
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

        // And the state this question cannot separate, which is why `restore` asks it twice.
        // A store that cannot produce an object it has answers exactly as one that never had
        // it, so "absent" is a fact about a lookup and not yet a fact about the network.
        truncate_the_pack(&git_dir);
        assert_eq!(
            git.holds_object(&git_dir, &second).expect("git ran"),
            crate::exec::Answer::No
        );
    }

    /// Three answers, and the third is the one that matters. `git merge-base --is-ancestor`
    /// exits 0 for yes, 1 for no, and 128 when it cannot resolve an oid at all, and that last
    /// one used to fold into "not an ancestor". Asked both ways round, two of those became
    /// `Unrelated`, which a restore reports as the user's own peer history having forked: the
    /// loudest thing this tool says, on the strength of an error nobody read.
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

    /// The signed-ref oids in a manifest are the last values from an archive that reach a
    /// command line. `merge-base` takes no `--`, so a leading `-` would be read as a flag, and
    /// a revision expression would have git resolve something nobody vouched for.
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
        // `symbolic-ref` takes no `--`, so this is the only thing standing between a hostile
        // manifest and git reading the value as one of its own flags. No git needed: the
        // refusal happens before the spawn, which is the property under test.
        let git = Git::new();
        let dir = Path::new("/nonexistent/repo.git");
        assert!(git.set_head(dir, "-d").is_err());
        assert!(git.set_head(dir, "--version").is_err());
        assert!(git.set_head(dir, "master").is_err());
        assert!(git.set_head(dir, "").is_err());
    }

    #[test]
    fn a_head_under_refs_that_climbs_out_of_the_repository_is_refused() {
        // `git symbolic-ref` stores this without complaint, and the next update of the ref
        // writes the file it names: `refs/../../evil` lands beside the repository, which in
        // a Radicle home is `storage` itself. Reproduced against git 2.34.
        assert!(!names_a_ref("refs/../../evil"));
        assert!(!names_a_ref("refs/heads/../../../etc/x"));
        assert!(!names_a_ref("refs/"));
        assert!(!names_a_ref("refs/heads/"));
        assert!(!names_a_ref("refs//heads/x"));
        assert!(!names_a_ref("refs/heads/.hidden"));
        assert!(!names_a_ref("refs/heads/x.lock"));
        assert!(!names_a_ref("refs/heads/a b"));
        assert!(!names_a_ref("refs/heads/a^b"));
        // The names a real archive carries still pass, or the guard would cost every restore
        // the pointer it was written to protect.
        assert!(names_a_ref("refs/heads/master"));
        assert!(names_a_ref("refs/heads/feature/nested"));
        assert!(names_a_ref("refs/heads/v1.0"));
        assert!(names_a_ref("refs/namespaces/z6Mk/refs/heads/master"));
        // Only ASCII control characters are refused, so a branch named in a language with
        // accents keeps its HEAD.
        assert!(names_a_ref("refs/heads/caf\u{e9}"));
    }
}
