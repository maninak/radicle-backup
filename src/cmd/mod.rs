//! The verbs, one module each, and the pieces they share.

pub mod backup;
pub mod diff;
pub mod doctor;
pub mod ls;
pub mod migrate;
pub mod paper;
pub mod prune;
pub mod restore;
pub mod schedule;
pub mod show;
pub mod verify;

use std::path::{Path, PathBuf};

use crate::cli::Global;
use crate::error::{Error, Result};
use crate::home::Home;
use crate::term::Term;

/// What every verb needs: somewhere to print, a home to work on, and the flags that outlive
/// the choice of verb.
pub struct Ctx {
    pub term: Term,
    pub home: Home,
    pub global: Global,
}

impl Ctx {
    pub fn identity_files(&self) -> &[PathBuf] {
        &self.global.identity
    }

    /// The node id of the identity being worked on, for finding its archives.
    pub fn node_id(&self) -> Result<String> {
        self.home.require()?;
        Ok(crate::key::Identity::read(self.home.public_key())?.node_id())
    }
}

/// Where this identity's archives are expected to live.
///
/// In order: what the caller said, then RAD_BACKUP_DIR, then wherever the last archive
/// actually went, then the working directory. The remembered directory matters most: someone
/// who has taken a backup once has already answered this question, and asking again by way of
/// an empty listing is a worse answer than using what they said.
pub fn archive_dir(
    ctx: &Ctx,
    given: Option<&Path>,
    record: Option<&crate::state::Record>,
) -> PathBuf {
    if let Some(dir) = given {
        return dir.to_path_buf();
    }
    if let Some(dir) = std::env::var_os("RAD_BACKUP_DIR") {
        return PathBuf::from(dir);
    }
    if let Some(parent) = record
        .and_then(|record| record.archive.as_ref())
        .map(PathBuf::from)
        .and_then(|path| path.parent().map(Path::to_path_buf))
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        return parent;
    }
    let _ = ctx;
    PathBuf::from(".")
}

/// The archive a command was pointed at, or the newest one of this identity that can be
/// found. Says which it chose, because a command that reads a file the user did not name has
/// to be obvious about which file that was.
pub fn resolve_archive(ctx: &Ctx, given: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = given {
        return Ok(path.to_path_buf());
    }
    let node_id = ctx.node_id()?;
    let record = crate::state::read(&crate::key::Identity::read(ctx.home.public_key())?.did())?;
    let directory = archive_dir(ctx, None, record.record());
    let found = crate::archives::newest(&directory, &node_id)?;
    let Some(archive) = found else {
        return Err(Error::refused(
            format!(
                "no archive was named, and none of this identity is in {}",
                directory.display()
            ),
            "name one, or set RAD_BACKUP_DIR to where you keep them",
        ));
    };
    ctx.term.step(&format!(
        "using the newest archive: {}",
        archive.path.display()
    ));
    Ok(archive.path)
}

/// A directory for working files, removed when it goes out of scope.
///
/// Snapshots of databases and freshly built git bundles have to exist as files before they can
/// be added to a tar, because tar needs a size before it takes content. They are put next to
/// the archive being written, on the filesystem the user already chose for it, rather than in
/// a shared temporary directory where a private repository's contents would be a surprise.
pub struct Scratch {
    path: PathBuf,
}

impl Scratch {
    pub fn create(parent: &Path) -> Result<Self> {
        let path = parent.join(format!(".rad-backup-{}", std::process::id()));
        // Owner-only from the moment it exists, and never a directory that was already
        // there: the name has a process id in it, which is guessable, and a working directory
        // somebody else made first would hold a private repository's contents under their
        // permissions. A leftover from a crashed run with this pid lands here too, which is
        // why the error names the path to remove.
        crate::perms::create_private_dir(&path).map_err(|e| match e {
            Error::Io { .. } if path.exists() => Error::refused(
                format!("{} is already there", path.display()),
                "remove it if it is left over from a run that crashed, then try again",
            ),
            other => other,
        })?;
        Ok(Self { path })
    }

    pub fn file(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_dir_all(&self.path) {
            // Leaving working files behind can mean leaving repository data behind, so it is
            // said out loud even though there is nothing left to do about it here.
            eprintln!(
                "! could not remove the working directory {}: {e}",
                self.path.display()
            );
        }
    }
}

/// Make a directory readable only by its owner, before anything is written into it.
pub fn set_owner_only(path: &Path) -> Result<()> {
    crate::perms::set_mode(path, crate::perms::DIR_MODE)
}

pub use crate::perms::write_owner_only;

/// Copy a file that may hold key material, landing it owner-only. Missing sources are not an
/// error: an archive of one tier simply does not carry what another tier would.
pub fn copy_owner_only(from: &Path, to: &Path) -> Result<()> {
    if !from.is_file() {
        return Ok(());
    }
    let bytes = zeroize::Zeroizing::new(std::fs::read(from).map_err(|e| Error::io(from, e))?);
    write_owner_only(to, &bytes)
}

/// Copy a file that holds nothing secret, landing it at the mode a home `rad` built itself
/// would have. The staging copy is owner-only because it sat beside a private key, and
/// carrying that mode through would leave a restored home subtly unlike a native one.
pub fn copy_plain(from: &Path, to: &Path) -> Result<()> {
    if !from.is_file() {
        return Ok(());
    }
    std::fs::copy(from, to).map_err(|e| Error::io(to, e))?;
    crate::perms::set_mode(to, crate::perms::DOC_MODE)
}

/// Fill `{{PLACEHOLDER}}` markers in one of the shipped documents.
pub fn fill(template: &str, values: &[(&str, &str)]) -> String {
    let mut text = template.to_string();
    for (key, value) in values {
        text = text.replace(&format!("{{{{{key}}}}}"), value);
    }
    text
}

/// The name an archive gets: identity first, then when it was taken, so that a directory of
/// them sorts by identity and then chronologically.
pub fn archive_name(alias: Option<&str>, node_id: &str, stamp: &str, encrypted: bool) -> String {
    let alias = alias
        .map(sanitise)
        .filter(|alias| !alias.is_empty())
        .unwrap_or_else(|| "radicle".to_string());
    let short: String = node_id.chars().take(12).collect();
    let extension = if encrypted { "tar.zst.age" } else { "tar.zst" };
    format!("{alias}-{short}-{stamp}.{extension}")
}

/// The note written beside an archive, in plain text, whatever the archive itself is.
pub fn sidecar_path(archive: &Path) -> PathBuf {
    let mut name = archive
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "archive".to_string());
    name.push_str(".README.txt");
    archive.with_file_name(name)
}

/// A UTC timestamp for a file name: sortable, no punctuation a shell would mind.
pub fn file_stamp(now: jiff::Timestamp) -> String {
    now.strftime("%Y%m%dT%H%M%SZ").to_string()
}

/// A UTC timestamp for the manifest: RFC 3339, to the second.
pub fn iso_stamp(now: jiff::Timestamp) -> String {
    now.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Keep the characters a file name can hold everywhere, and drop the rest.
fn sanitise(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_archive_is_named_after_the_identity_and_the_moment_it_was_taken() {
        let name = archive_name(
            Some("maninak"),
            "z6MkvAFBkdph6yXSZDkkVqf9FfCcvkG29JD4KbwwnGphDRLV",
            "20260814T173500Z",
            true,
        );
        assert_eq!(name, "maninak-z6MkvAFBkdph-20260814T173500Z.tar.zst.age");
    }

    #[test]
    fn an_alias_with_spaces_or_slashes_cannot_reach_out_of_its_directory() {
        let name = archive_name(
            Some("../../etc/pa sswd"),
            "z6MkAAA",
            "20260814T173500Z",
            false,
        );
        assert!(!name.contains('/'));
        assert!(name.starts_with(".."), "{name}");
        assert!(name.ends_with(".tar.zst"));
    }

    #[test]
    fn a_home_with_no_alias_still_gets_a_usable_name() {
        let name = archive_name(None, "z6MkAAA", "20260814T173500Z", true);
        assert_eq!(name, "radicle-z6MkAAA-20260814T173500Z.tar.zst.age");
    }

    #[test]
    fn the_note_sits_beside_the_archive_and_keeps_its_name() {
        assert_eq!(
            sidecar_path(Path::new("/backups/maninak-z6Mk-2026.tar.zst.age")),
            PathBuf::from("/backups/maninak-z6Mk-2026.tar.zst.age.README.txt")
        );
    }

    #[test]
    fn placeholders_are_replaced_and_unknown_ones_are_left_alone() {
        let filled = fill("hello {{NAME}}, {{MISSING}}", &[("NAME", "world")]);
        assert_eq!(filled, "hello world, {{MISSING}}");
    }

    #[test]
    fn a_working_directory_is_owner_only_from_the_moment_it_exists() {
        use std::os::unix::fs::PermissionsExt;

        let parent =
            std::env::temp_dir().join(format!("rad-backup-scratch-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&parent);
        std::fs::create_dir_all(&parent).expect("the parent is creatable");

        let scratch = Scratch::create(&parent).expect("a working directory is creatable");
        let mode = std::fs::metadata(&scratch.path)
            .expect("it is there")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, crate::perms::DIR_MODE);

        let _ = std::fs::remove_dir_all(&parent);
    }

    #[test]
    fn a_working_directory_somebody_else_made_first_is_refused_and_not_reused() {
        let parent = std::env::temp_dir().join(format!("rad-backup-squat-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&parent);
        std::fs::create_dir_all(&parent).expect("the parent is creatable");

        // What an attacker who guessed the pid would leave behind: the directory already
        // there, with permissions of their choosing.
        let squatted = parent.join(format!(".rad-backup-{}", std::process::id()));
        std::fs::create_dir_all(&squatted).expect("the squatted directory is creatable");
        crate::perms::set_mode(&squatted, 0o777).expect("its mode is settable");

        let refused = Scratch::create(&parent);
        assert!(
            matches!(refused, Err(Error::Refused { .. })),
            "a directory that was already there was reused"
        );

        let _ = std::fs::remove_dir_all(&parent);
    }
}
