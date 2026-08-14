//! The git operations a backup needs, and nothing more.
//!
//! Repositories are archived as bundles rather than as directory copies, because a bundle is
//! a single file whose object graph git itself checks on the way in and on the way out. A
//! directory copy would also carry unreachable objects and could be silently truncated.

use std::path::{Path, PathBuf};

use crate::error::Result;
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
        let out = self.tool.output(&[
            "--git-dir".as_ref(),
            git_dir.as_os_str(),
            "for-each-ref".as_ref(),
            "--sort=refname".as_ref(),
            "--format=%(objectname) %(refname)".as_ref(),
        ])?;
        Ok(out
            .lines()
            .filter_map(|line| line.split_once(' '))
            .map(|(oid, name)| Ref {
                name: name.to_string(),
                oid: oid.to_string(),
            })
            .collect())
    }

    /// The object a ref points at, or `None` when the ref does not exist.
    pub fn ref_oid(&self, git_dir: &Path, name: &str) -> Result<Option<String>> {
        let out = self.tool.raw_output(&[
            "--git-dir".as_ref(),
            git_dir.as_os_str(),
            "rev-parse".as_ref(),
            "--verify".as_ref(),
            "--quiet".as_ref(),
            format!("{name}^{{commit}}").as_ref(),
        ])?;
        Ok(out
            .map(|oid| oid.trim().to_string())
            .filter(|o| !o.is_empty()))
    }

    /// What `HEAD` is a symbolic ref to, which a bundle does not carry and a restore must set
    /// back by hand.
    pub fn head_target(&self, git_dir: &Path) -> Result<Option<String>> {
        let out = self.tool.raw_output(&[
            "--git-dir".as_ref(),
            git_dir.as_os_str(),
            "symbolic-ref".as_ref(),
            "HEAD".as_ref(),
        ])?;
        Ok(out.map(|target| target.trim().to_string()))
    }

    /// Whether `ancestor` is reachable from `descendant`. This is the fork test: a restored
    /// namespace is safe to build on only when its signed refs are an ancestor of what the
    /// network holds.
    pub fn is_ancestor(&self, git_dir: &Path, ancestor: &str, descendant: &str) -> Result<bool> {
        self.tool.succeeds(&[
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
    /// namespace and their `rad/sigrefs`. Verified against real storage rather than assumed.
    pub fn bundle(&self, git_dir: &Path, out: &Path) -> Result<()> {
        self.tool.output(&[
            "--git-dir".as_ref(),
            git_dir.as_os_str(),
            "bundle".as_ref(),
            "create".as_ref(),
            "--quiet".as_ref(),
            out.as_os_str(),
            "--all".as_ref(),
        ])?;
        Ok(())
    }

    /// The refs a bundle carries. Reading them is also how a bundle is checked for being
    /// well formed without a repository to check its prerequisites against.
    pub fn bundle_refs(&self, bundle: &Path) -> Result<Vec<Ref>> {
        let out =
            self.tool
                .output(&["bundle".as_ref(), "list-heads".as_ref(), bundle.as_os_str()])?;
        Ok(out
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

    pub fn set_head(&self, git_dir: &Path, target: &str) -> Result<()> {
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

/// The bundle file name for a repository inside an archive. One place, so the writer and the
/// reader cannot disagree about it.
pub fn bundle_entry(rid: &str) -> PathBuf {
    PathBuf::from("repos").join(format!(
        "{}.bundle",
        rid.strip_prefix("rad:").unwrap_or(rid)
    ))
}

/// The config file name for a repository inside an archive.
pub fn config_entry(rid: &str) -> PathBuf {
    PathBuf::from("repos").join(format!(
        "{}.config",
        rid.strip_prefix("rad:").unwrap_or(rid)
    ))
}

/// The ref that holds a peer's signed refs, which is what divergence is measured on.
pub fn sigrefs_ref(node_id: &str) -> String {
    format!("refs/namespaces/{node_id}/refs/rad/sigrefs")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_entry_names_drop_the_rad_prefix_but_keep_the_identifier() {
        assert_eq!(
            bundle_entry("rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5"),
            PathBuf::from("repos/z3gqcJUoA1n9HaHKufZs5FCSGazv5.bundle")
        );
        assert_eq!(
            config_entry("z3gqcJUoA1n9HaHKufZs5FCSGazv5"),
            PathBuf::from("repos/z3gqcJUoA1n9HaHKufZs5FCSGazv5.config")
        );
    }

    #[test]
    fn the_sigrefs_ref_is_namespaced_under_the_peer_it_belongs_to() {
        assert_eq!(
            sigrefs_ref("z6MkvAFBkdph6yXSZDkkVqf9FfCcvkG29JD4KbwwnGphDRLV"),
            "refs/namespaces/z6MkvAFBkdph6yXSZDkkVqf9FfCcvkG29JD4KbwwnGphDRLV/refs/rad/sigrefs"
        );
    }
}
