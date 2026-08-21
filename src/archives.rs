//! Finding the archives of one identity on disk.
//!
//! Every command that takes an archive can be given none, and mean the newest one. That is
//! only safe if "the newest one" is decided the same way everywhere, and if the set it is
//! chosen from can never include a file this tool did not write: a retention rule or a
//! default argument that could reach anything else is a deletion bug waiting for a bad path.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// The suffixes this tool writes. A file that ends in neither was not written here.
const SUFFIXES: [&str; 2] = [".tar.zst.age", ".tar.zst"];

/// How much of a node id an archive name carries. Long enough that two identities on one
/// machine cannot collide, short enough to leave a file name readable.
pub const SHORT_ID: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Archive {
    pub path: PathBuf,
    pub bytes: u64,
    /// When the name says it was taken. `None` when the stamp does not parse, which is not an
    /// error: the file is still an archive, it just cannot be sorted by its own claim.
    pub taken: Option<jiff::Timestamp>,
    pub encrypted: bool,
}

impl Archive {
    pub fn name(&self) -> String {
        self.path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default()
    }
}

/// Every archive of this identity in `directory`, newest first.
///
/// The alias is deliberately not part of the match. An identity that renames itself keeps the
/// same node id, and archives taken under the old name are still that identity's archives.
pub fn in_dir(directory: &Path, node_id: &str) -> Result<Vec<Archive>> {
    let short: String = node_id.chars().take(SHORT_ID).collect();
    let marker = format!("-{short}-");
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        // A directory that is not there holds no archives, which is an answer, not a failure.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::io(directory, e)),
    };

    let mut archives: Vec<Archive> = entries
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
        .filter_map(|entry| {
            let path = entry.path();
            let name = path.file_name()?.to_string_lossy().into_owned();
            let suffix = SUFFIXES.iter().find(|suffix| name.ends_with(**suffix))?;
            let stamp = name
                .split_once(&marker)?
                .1
                .strip_suffix(*suffix)?
                .to_string();
            Some(Archive {
                bytes: entry.metadata().map(|meta| meta.len()).unwrap_or_default(),
                taken: parse_stamp(&stamp),
                encrypted: *suffix == SUFFIXES[0],
                path,
            })
        })
        .collect();

    // By the stamp, never by the file name: the name begins with the alias, so sorting by it
    // would order archives by what the identity was called rather than by when they were
    // taken. One whose stamp did not parse sorts last, and ties break by name so the order is
    // total and the same on every run.
    archives.sort_by(|a, b| b.taken.cmp(&a.taken).then_with(|| b.name().cmp(&a.name())));
    Ok(archives)
}

/// The newest archive of this identity in `directory`, if there is one.
pub fn newest(directory: &Path, node_id: &str) -> Result<Option<Archive>> {
    Ok(in_dir(directory, node_id)?.into_iter().next())
}

/// The stamp `archive_name` writes, read back.
fn parse_stamp(stamp: &str) -> Option<jiff::Timestamp> {
    jiff::civil::DateTime::strptime("%Y%m%dT%H%M%SZ", stamp)
        .ok()?
        .to_zoned(jiff::tz::TimeZone::UTC)
        .ok()
        .map(|zoned| zoned.timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;

    const NODE: &str = "z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp";
    const OTHER: &str = "z6MkvAFBkdph6yXSZDkkVqf9FfCcvkG29JD4KbwwnGphDRLV";

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("rad-backup-archives-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch directory is creatable");
        dir
    }

    fn touch(dir: &Path, name: &str) {
        std::fs::write(dir.join(name), b"x").expect("the fixture file is writable");
    }

    #[test]
    fn archives_of_one_identity_come_back_newest_first_and_nothing_else_comes_back() {
        let dir = scratch("listing");
        touch(&dir, "maninak-z6MkiTBz1ymu-20260101T000000Z.tar.zst.age");
        touch(&dir, "maninak-z6MkiTBz1ymu-20260814T120000Z.tar.zst.age");
        // The same identity after a rename: same node id, so still its archive.
        touch(&dir, "kostis-z6MkiTBz1ymu-20260301T000000Z.tar.zst");
        // Somebody else's identity, and a file this tool never wrote.
        touch(&dir, "other-z6MkvAFBkdph-20260814T130000Z.tar.zst.age");
        touch(&dir, "holiday-photos.tar.zst");
        touch(
            &dir,
            "maninak-z6MkiTBz1ymu-20260814T120000Z.tar.zst.age.README.txt",
        );

        let found = in_dir(&dir, NODE).expect("the directory is readable");
        let names: Vec<String> = found.iter().map(Archive::name).collect();
        assert_eq!(
            names,
            vec![
                "maninak-z6MkiTBz1ymu-20260814T120000Z.tar.zst.age",
                "kostis-z6MkiTBz1ymu-20260301T000000Z.tar.zst",
                "maninak-z6MkiTBz1ymu-20260101T000000Z.tar.zst.age",
            ]
        );
        assert!(found[0].encrypted);
        assert!(!found[1].encrypted, "a .tar.zst is not encrypted");
        assert_eq!(
            in_dir(&dir, OTHER)
                .expect("the directory is readable")
                .len(),
            1,
            "one identity's listing must never include another's"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_name_stamp_comes_back_as_the_instant_it_was_written_for() {
        let dir = scratch("stamp");
        touch(&dir, "maninak-z6MkiTBz1ymu-20260814T165609Z.tar.zst.age");

        let found = in_dir(&dir, NODE).expect("the directory is readable");
        let taken = found[0].taken.expect("the stamp parses");
        assert_eq!(
            taken.strftime("%Y-%m-%dT%H:%M:%SZ").to_string(),
            "2026-08-14T16:56:09Z"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_archive_named_by_the_writer_is_found_again_by_the_reader() {
        let dir = scratch("writer-and-reader");
        let name = crate::cmd::archive_name(Some("fixture"), NODE, "20260101T000000Z", true);
        touch(&dir, &name);

        // The writer used to spell the length of the short node id by hand while this reader
        // matched on SHORT_ID. They agreed only by coincidence, and moving the constant would
        // have made every new archive invisible to `ls`, `prune` and `--keep` at once.
        let found = in_dir(&dir, NODE).expect("the directory is readable");
        assert_eq!(found.iter().map(Archive::name).collect::<Vec<_>>(), [name]);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_directory_that_is_not_there_holds_no_archives_rather_than_failing() {
        let missing =
            std::env::temp_dir().join(format!("rad-backup-absent-{}", std::process::id()));
        assert!(
            in_dir(&missing, NODE)
                .expect("a missing directory is not an error")
                .is_empty()
        );
        assert!(
            newest(&missing, NODE)
                .expect("a missing directory is not an error")
                .is_none()
        );
    }
}
