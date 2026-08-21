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
pub mod words;

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

/// The passphrase for opening an archive, if that archive wants one.
///
/// One place, because `restore`, `show` and `verify` each carried a verbatim copy of it, and
/// a change to the wording or to where a passphrase may come from had to land in all three or
/// two verbs would start asking differently from the third.
pub fn archive_passphrase(ctx: &Ctx, archive: &Path) -> Result<Option<zeroize::Zeroizing<String>>> {
    if !crate::crypt::needs_passphrase(archive)? {
        return Ok(None);
    }
    Ok(Some(crate::crypt::read_passphrase(
        crate::crypt::PASSPHRASE_ENV,
        ctx.global.passphrase_file.as_deref(),
        "Passphrase for the archive: ",
        crate::crypt::Purpose::Opening,
        ctx.term.is_interactive(),
    )?))
}

/// Where this identity's archives are expected to live.
///
/// In order: what the caller said, then RAD_BACKUP_DIR, then wherever the last archive
/// actually went, then the working directory. The remembered directory matters most: someone
/// who has taken a backup once has already answered this question, and asking again by way of
/// an empty listing is a worse answer than using what they said.
pub fn archive_dir(given: Option<&Path>, record: Option<&crate::state::Record>) -> PathBuf {
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
    let directory = archive_dir(None, record.record());
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

/// Substitute `{{KEY}}` markers in one of the shipped documents, in ONE pass over it.
///
/// Sequential `replace` calls read their own output, so a value containing a marker was
/// expanded by a later key. An alias of `{{SECRET}}`, which arrives in a `config.json` copied
/// verbatim out of somebody else's archive, put the 24-word mnemonic in the title of the
/// recovery sheet. Scanning once means an inserted value is never looked at again, so no
/// value can name another key, whatever it holds.
pub fn fill(template: &str, values: &[(&str, &str)]) -> String {
    let mut text = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            break;
        };
        let key = &after[..end];
        match values.iter().find(|(name, _)| *name == key) {
            Some((_, value)) => {
                text.push_str(&rest[..start]);
                text.push_str(value);
            }
            // An unknown marker is left as it was written. A template carrying `{{` for its
            // own reasons is not this function's business to mangle.
            None => text.push_str(&rest[..start + 2 + end + 2]),
        }
        rest = &after[end + 2..];
    }
    text.push_str(rest);
    text
}

/// Refuse a retention of zero, wherever it was spelled.
///
/// `prune` refused it and `--keep` did not, so one number meant "refuse" on one verb and
/// "delete every archive but the one just written" on the other. Both read `RAD_BACKUP_KEEP`
/// and `schedule` writes that file, so the divergence reached an unattended timer.
pub fn refuse_keep_zero(keep: usize) -> Result<()> {
    if keep == 0 {
        return Err(Error::refused(
            "--keep 0 would delete every archive of this identity",
            "keep at least one, or delete the files yourself if that is really what you mean",
        ));
    }
    Ok(())
}

/// A UTC timestamp for the manifest: RFC 3339, to the second.
pub fn iso_stamp(now: jiff::Timestamp) -> String {
    now.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn placeholders_are_replaced_and_unknown_ones_are_left_alone() {
        let filled = fill("hello {{NAME}}, {{MISSING}}", &[("NAME", "world")]);
        assert_eq!(filled, "hello world, {{MISSING}}");
    }

    #[test]
    fn a_value_cannot_name_another_key() {
        // The alias arrives in a `config.json` that a restore copies verbatim out of somebody
        // else's archive, and `paper` puts it in the title of a sheet printed next to the key.
        let filled = fill(
            "{{ALIAS}} holds {{SECRET}}",
            &[("ALIAS", "{{SECRET}}"), ("SECRET", "the 24 words")],
        );
        assert_eq!(filled, "{{SECRET}} holds the 24 words");
    }

    #[test]
    #[cfg(unix)]
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
