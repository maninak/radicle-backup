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

/// The terminal, the home and the global flags every verb works with.
pub struct Ctx {
    pub term: Term,
    pub home: Home,
    pub global: Global,
}

impl Ctx {
    /// The private keys offered for an archive encrypted to a recipient, and what unlocks one
    /// that is itself passphrase-protected.
    pub fn identities(&self) -> crate::crypt::Identities {
        crate::crypt::Identities {
            files: self.global.age_identity_files.clone(),
            passphrase_file: self.global.age_identity_passphrase_file.clone(),
            is_interactive: self.term.is_interactive(),
        }
    }

    /// The node id of the identity being worked on, for finding its archives.
    pub fn read_node_id(&self) -> Result<String> {
        self.home.require_identity()?;
        Ok(crate::key::Identity::read(self.home.public_key())?.node_id())
    }
}

/// Reads the passphrase for opening `archive`, if that archive wants one.
pub fn read_archive_passphrase(
    ctx: &Ctx,
    archive: &Path,
) -> Result<Option<zeroize::Zeroizing<String>>> {
    if !crate::crypt::needs_passphrase(archive)? {
        return Ok(None);
    }
    Ok(Some(crate::crypt::read_passphrase(
        crate::crypt::Protects::Archive,
        ctx.global.passphrase_file.as_deref(),
        "Passphrase for the archive: ",
        crate::crypt::Purpose::Opening,
        ctx.term.is_interactive(),
    )?))
}

/// Where this identity's archives are expected to live, from every source but the environment.
///
/// The order is the flag, then `RAD_BACKUP_DIR`, then the directory the last archive went to,
/// then the working directory.
///
/// Takes `RAD_BACKUP_DIR` as an argument, so a test need not set a variable every other test
/// in the process sees. [`archive_dir_from_env`] reads it.
pub fn archive_dir_given(
    flag: Option<&Path>,
    variable: Option<PathBuf>,
    record: Option<&crate::state::Record>,
) -> PathBuf {
    if let Some(dir) = flag {
        return dir.to_path_buf();
    }
    if let Some(dir) = variable {
        return dir;
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

/// Resolves [`archive_dir_given`] with `RAD_BACKUP_DIR` read from the environment.
pub fn archive_dir_from_env(flag: Option<&Path>, record: Option<&crate::state::Record>) -> PathBuf {
    archive_dir_given(
        flag,
        std::env::var_os("RAD_BACKUP_DIR").map(PathBuf::from),
        record,
    )
}

/// The archive a command was pointed at, or else this identity's newest one.
///
/// Prints the newest archive's path, because a command reading a file the user did not name
/// has to say which file it read.
pub fn resolve_archive(ctx: &Ctx, given: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = given {
        return Ok(path.to_path_buf());
    }
    let node_id = ctx.read_node_id()?;
    let record = crate::state::read(&crate::key::Identity::read(ctx.home.public_key())?.did())?;
    let directory = archive_dir_from_env(None, record.record());
    let found = crate::archives::newest(&directory, &node_id)?;
    let Some(archive) = found else {
        return Err(Error::refused(
            format!(
                "no archive was given, and no archive of your identity is in {}",
                directory.display()
            ),
            "pass the path to an archive, or set RAD_BACKUP_DIR to the directory that holds them",
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
/// Database snapshots and git bundles become files here first, because tar needs a size before
/// it takes content. Callers create it beside their output, on a filesystem the user chose, so
/// a private repository stays out of a shared temporary directory. `backup --stdout` has no
/// output directory, so it uses the system's temporary one unless `--scratch-dir` is given.
pub struct Scratch {
    path: PathBuf,
}

impl Scratch {
    pub fn create(parent: &Path) -> Result<Self> {
        let path = parent.join(format!(".rad-backup-{}", std::process::id()));
        // The directory is owner-only from creation and never reused, because its name holds
        // a guessable pid and a directory someone else made first would expose its contents.
        // A leftover from a crashed run with this pid is refused too, so the error names it.
        crate::perms::create_private_dir(&path).map_err(|e| match e {
            Error::Io { .. } if path.exists() => Error::refused(
                format!("the working directory {} already exists", path.display()),
                "if an earlier run crashed and left it behind, delete it and run again",
            ),
            other => other,
        })?;
        Ok(Self { path })
    }

    pub fn path_of(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_dir_all(&self.path) {
            // Working files can hold repository data, so a failed removal is reported though
            // nothing can be done about it here
            eprintln!(
                "! could not remove the working directory {}: {e}. It may hold copies of your \
                 data. Delete it yourself",
                self.path.display()
            );
        }
    }
}

/// Substitutes `{{KEY}}` markers in `template` in one pass, leaving unknown ones as written.
///
/// An inserted value is never scanned again, so a value such as an alias of `{{SECRET}}`
/// cannot expand to another key.
pub fn fill(template: &str, values: &[(&str, &str)]) -> String {
    // The buffer is sized up front, because growing it frees the old one with a partial copy
    // of the key in it, out of reach of the `Zeroizing` around the result. The estimate runs
    // high, which is harmless.
    let mut filled = String::with_capacity(room_for(template, values));
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            break;
        };
        let key = &after[..end];
        match values.iter().find(|(name, _)| *name == key) {
            Some((_, value)) => {
                filled.push_str(&rest[..start]);
                filled.push_str(value);
            }
            None => filled.push_str(&rest[..start + 2 + end + 2]),
        }
        rest = &after[end + 2..];
    }
    filled.push_str(rest);
    filled
}

/// How much room [`fill`] needs before it writes anything.
///
/// Each value counts once per marker that asks for it, because `{{ALIAS}}` appears twice in
/// the recovery sheet, and a buffer that grows midway frees a block holding the key.
fn room_for(template: &str, values: &[(&str, &str)]) -> usize {
    template.len()
        + values
            .iter()
            .map(|(name, value)| {
                let marker = format!("{{{{{name}}}}}");
                template.matches(marker.as_str()).count() * value.len()
            })
            .sum::<usize>()
}

/// Refuses a retention of zero, wherever it was spelled.
///
/// A zero on a backup run would delete every archive but the one just written.
pub fn refuse_keep_zero(keep: usize) -> Result<()> {
    if keep == 0 {
        return Err(Error::refused(
            "--keep 0 would delete every archive of your identity",
            "use --keep 1 or more. To delete every archive, delete the files yourself",
        ));
    }
    Ok(())
}

/// Formats `at` as an RFC 3339 UTC timestamp, to the second.
pub fn rfc3339_stamp(at: jiff::Timestamp) -> String {
    at.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn where_archives_live_prefers_the_flag_then_the_variable_then_where_the_last_one_went() {
        let mut record = crate::state::Record {
            did: "did:key:z6MkAAA".to_string(),
            archive: Some("/mnt/backups/radicle-z6MkAAA-20260901T000000Z.tar.zst".to_string()),
            created: "2026-09-01T00:00:00Z".to_string(),
            tier: "full".to_string(),
            repo_selection: "mine".to_string(),
            entries: 0,
            bytes: 0,
            is_encrypted: true,
            carried: Default::default(),
            described: Default::default(),
            sigrefs: Default::default(),
            seeded: 0,
            followed: 0,
            policies: None,
            restored: None,
        };
        let flag = PathBuf::from("/flag");
        let variable = PathBuf::from("/variable");

        assert_eq!(
            archive_dir_given(Some(&flag), Some(variable.clone()), Some(&record)),
            flag
        );
        assert_eq!(
            archive_dir_given(None, Some(variable.clone()), Some(&record)),
            variable
        );
        assert_eq!(
            archive_dir_given(None, None, Some(&record)),
            PathBuf::from("/mnt/backups")
        );

        // Neither an archive that went to stdout nor one recorded without a directory names a
        // directory, so neither stands in for one
        record.archive = None;
        assert_eq!(
            archive_dir_given(None, None, Some(&record)),
            PathBuf::from(".")
        );
        record.archive = Some("radicle.tar.zst".to_string());
        assert_eq!(
            archive_dir_given(None, None, Some(&record)),
            PathBuf::from(".")
        );
        assert_eq!(archive_dir_given(None, None, None), PathBuf::from("."));
    }

    #[test]
    fn placeholders_are_replaced_and_unknown_ones_are_left_alone() {
        let filled = fill("hello {{NAME}}, {{MISSING}}", &[("NAME", "world")]);
        assert_eq!(filled, "hello world, {{MISSING}}");
    }

    #[test]
    fn a_value_cannot_name_another_key() {
        // The alias arrives in a `config.json` that a restore copies verbatim out of somebody
        // else's archive, and `paper` puts it in the title of a sheet printed next to the key
        let filled = fill(
            "{{ALIAS}} holds {{SECRET}}",
            &[("ALIAS", "{{SECRET}}"), ("SECRET", "the 24 words")],
        );
        assert_eq!(filled, "{{SECRET}} holds the 24 words");
    }

    #[test]
    fn a_document_is_sized_for_every_marker_that_asks_for_the_same_value() {
        let template = "{{ALIAS}} .. {{ALIAS}}";
        let values = [("ALIAS", "a name long enough to matter")];
        assert!(room_for(template, &values) >= fill(template, &values).len());
    }

    #[test]
    fn a_document_is_sized_without_counting_a_value_no_marker_asks_for() {
        // A value no marker asks for adds nothing, so the sheet is not sized for a mnemonic it
        // never prints
        assert_eq!(room_for("nothing here", &[("SECRET", "the 24 words")]), 12);
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
        assert_eq!(mode & 0o777, crate::perms::MODE_DIR);

        let _ = std::fs::remove_dir_all(&parent);
    }

    #[test]
    fn a_working_directory_somebody_else_made_first_is_refused_and_not_reused() {
        let parent = std::env::temp_dir().join(format!("rad-backup-squat-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&parent);
        std::fs::create_dir_all(&parent).expect("the parent is creatable");

        // An attacker who guessed the pid leaves the directory already there, with permissions
        // of their choosing
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
