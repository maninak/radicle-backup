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
    /// means that node is simply behind us, and anything else means it is holding work signed
    /// under this key that the restored copy does not have.
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
    pub fn unbundle(&self, git_dir: &Path, bundle: &Path) -> Result<()> {
        self.tool.output(&[
            "-c".as_ref(),
            "fetch.fsckObjects=true".as_ref(),
            "--git-dir".as_ref(),
            git_dir.as_os_str(),
            "fetch".as_ref(),
            "--quiet".as_ref(),
            "--force".as_ref(),
            bundle.as_os_str(),
            "refs/*:refs/*".as_ref(),
        ])?;
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
mod tests {
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
    fn two_commits(scratch: &crate::cmd::Scratch) -> (std::path::PathBuf, String, String) {
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

    /// Three answers, and the third is the one that matters. `git merge-base --is-ancestor`
    /// exits 0 for yes, 1 for no, and 128 when it cannot resolve an oid at all, and that last
    /// one used to fold into "not an ancestor". Asked both ways round, two of those became
    /// `Unrelated`, which a restore reports as the user's own peer history having forked: the
    /// loudest thing this tool says, on the strength of an error nobody read.
    #[test]
    fn an_oid_git_cannot_resolve_is_not_an_answer_about_ancestry() {
        let git = Git::new();
        assert!(git.is_available(), "these tests drive the real git");
        let scratch = crate::cmd::Scratch::create(std::env::temp_dir().as_path())
            .expect("a working directory is creatable");
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
