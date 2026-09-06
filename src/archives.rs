//! Naming the archives of one identity, and finding them again on disk.
//!
//! Every command that reads an archive, except `restore`, can be given none and mean the
//! newest one. (`restore` asks for the path, because putting the wrong archive back is not
//! something a default should be able to do.) Defaulting is only safe if "the newest one" is
//! decided the same way everywhere, and if the set it is chosen from can never include a file
//! this tool did not write: a retention rule or a default argument that could reach anything
//! else is a deletion bug waiting for a bad path.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// The suffixes this tool writes. A file that ends in neither was not written here.
const SUFFIXES: [&str; 2] = [".tar.zst.age", ".tar.zst"];

/// How much of a node id an archive name carries. Long enough that two identities on one
/// machine cannot collide, short enough to leave a file name readable.
pub const SHORT_NODE_ID_LEN: usize = 12;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Archive {
    pub path: PathBuf,
    pub bytes: u64,
    /// When the name says it was taken. `None` when the stamp does not parse, which is not an
    /// error: the file is still an archive, it just cannot be sorted by its own claim.
    pub taken: Option<jiff::Timestamp>,
    /// Whether the file begins with an age header. `None` when it could not be read to look,
    /// which `ls` prints as unknown.
    ///
    /// Read off the bytes, never off the `.age` suffix. `rad backup --stdout > name.tar.zst`
    /// writes an encrypted archive under a name that says otherwise, and `ls` printed "(not
    /// encrypted)" beside it: a claim about who can read a file, made from its name.
    pub encrypted: Option<bool>,
}

impl Archive {
    pub fn name(&self) -> String {
        self.path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default()
    }
}

/// Every archive of this identity in `directory`, newest first, and those that could not be
/// examined.
///
/// The alias is deliberately not part of the match. An identity that renames itself keeps the
/// same node id, and archives taken under the old name are still that identity's archives.
///
/// The second list is every file named like one of this identity's archives that could not be
/// examined, each with why, in the shape `Home::read_inventory` hands back what it could not
/// read. Left out of the first list instead, one used to vanish: `prune` reported "freeing
/// 0 B", never deleted it and never counted it against `--keep`, and `newest` could name the
/// file beside it. A caller that can say so and carry on prints these; one that acts on the
/// count or picks by it goes through `in_dir`, which refuses an incomplete listing.
pub fn listing(directory: &Path, node_id: &str) -> Result<(Vec<Archive>, Vec<Error>)> {
    let short: String = node_id.chars().take(SHORT_NODE_ID_LEN).collect();
    let marker = format!("-{short}-");
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        // A directory that is not there holds no archives, which is an answer, not a failure.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((Vec::new(), Vec::new())),
        Err(e) => return Err(Error::io(directory, e)),
    };

    let mut archives = Vec::new();
    let mut unexamined = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|e| Error::io(directory, e))?;
        let path = entry.path();
        let Some(stamp) = stamp_of(&path, &marker) else {
            continue;
        };
        // `metadata`, which follows a symlink, and not `file_type`, which does not: an archive
        // kept elsewhere and linked into the directory is still an archive of this identity,
        // and it used to be dropped as "not a file".
        let bytes = match std::fs::metadata(&path) {
            Ok(meta) if meta.is_file() => meta.len(),
            // A directory named like an archive is not one.
            Ok(_) => continue,
            // Gone between the listing and the look, which is an answer.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                unexamined.push(Error::io(&path, e));
                continue;
            }
        };
        archives.push(Archive {
            bytes,
            taken: parse_stamp(&stamp),
            // One short read per archive in a directory listing, which is cheaper than being
            // wrong about whether somebody's key is readable.
            encrypted: crate::crypt::looks_encrypted(&path).ok(),
            path,
        });
    }

    // By the stamp, never by the file name: the name begins with the alias, so sorting by it
    // would order archives by what the identity was called rather than by when they were
    // taken. One whose stamp did not parse sorts last, and ties break by name so the order is
    // total and the same on every run.
    archives.sort_by(|a, b| b.taken.cmp(&a.taken).then_with(|| b.name().cmp(&a.name())));
    unexamined.sort_by_key(|e| e.to_string());
    Ok((archives, unexamined))
}

/// The stamp in a file name that this tool wrote for this identity, or `None` for any other
/// file.
fn stamp_of(path: &Path, marker: &str) -> Option<String> {
    let name = path.file_name()?.to_string_lossy().into_owned();
    let suffix = SUFFIXES.iter().find(|suffix| name.ends_with(**suffix))?;
    Some(
        name.split_once(marker)?
            .1
            .strip_suffix(*suffix)?
            .to_string(),
    )
}

/// Every archive of this identity in `directory`, newest first, or a failure when one of them
/// could not be examined.
///
/// Fails closed rather than listing what it could see, because every caller of this acts on
/// the list as if it were the whole of it: `prune` deletes by count, `--keep` keeps by count,
/// and `newest` names a file to read. An archive that is there and could not be examined is
/// news, not absence. Revisit when every caller goes through `listing` and says so itself.
pub fn in_dir(directory: &Path, node_id: &str) -> Result<Vec<Archive>> {
    let (archives, unexamined) = listing(directory, node_id)?;
    match unexamined.into_iter().next() {
        None => Ok(archives),
        Some(first) => Err(first),
    }
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

/// The name an archive gets: identity first, then when it was taken, so that a directory of
/// them sorts by identity and then chronologically.
pub fn archive_name(alias: Option<&str>, node_id: &str, stamp: &str, encrypted: bool) -> String {
    let alias = alias
        .map(sanitise)
        .filter(|alias| !alias.is_empty())
        .unwrap_or_else(|| "radicle".to_string());
    let short: String = node_id.chars().take(SHORT_NODE_ID_LEN).collect();
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

    const NODE: &str = "z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp";
    const OTHER: &str = "z6MkvAFBkdph6yXSZDkkVqf9FfCcvkG29JD4KbwwnGphDRLV";

    fn scratch_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("rad-backup-archives-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch directory is creatable");
        dir
    }

    /// A file with an age header in it, so `in_dir` reads it as encrypted the way it reads a
    /// real archive: from the bytes rather than from the name.
    fn touch_encrypted(dir: &Path, name: &str) {
        std::fs::write(dir.join(name), b"age-encryption.org/v1\n").expect("fixture is writable");
    }

    fn touch(dir: &Path, name: &str) {
        std::fs::write(dir.join(name), b"x").expect("the fixture file is writable");
    }

    /// The bug: `encrypted` was set from the `.age` suffix, and `ls` printed "(not encrypted)"
    /// from it. `rad backup --stdout > name.tar.zst` writes an encrypted archive under a name
    /// that says otherwise, and the listing told its owner it could be read by anyone.
    #[test]
    fn whether_an_archive_is_encrypted_is_read_from_it_and_not_from_its_name() {
        let dir = scratch_dir("header");
        touch_encrypted(&dir, "maninak-z6MkiTBz1ymu-20260814T120000Z.tar.zst");
        touch(&dir, "maninak-z6MkiTBz1ymu-20260101T000000Z.tar.zst.age");

        let found = in_dir(&dir, NODE).expect("the directory is readable");
        assert_eq!(found[0].encrypted, Some(true), "the header says so");
        assert_eq!(found[1].encrypted, Some(false), "the suffix does not");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn archives_of_one_identity_come_back_newest_first_and_nothing_else_comes_back() {
        let dir = scratch_dir("listing");
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
        assert_eq!(found[1].encrypted, Some(false), "no age header in it");
        // The name says `.age` and the bytes do not, and the bytes win. A name is not
        // evidence about who can read a file.
        assert_eq!(found[0].encrypted, Some(false), "a name is not a header");
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
        let dir = scratch_dir("stamp");
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
    fn an_archive_named_by_the_writer_is_found_again_by_the_reader() {
        let dir = scratch_dir("writer-and-reader");
        let name = crate::archives::archive_name(Some("fixture"), NODE, "20260101T000000Z", true);
        touch(&dir, &name);

        // The writer used to spell the length of the short node id by hand while this reader
        // matched on SHORT_NODE_ID_LEN. They agreed only by coincidence, and moving the
        // constant would have made every new archive invisible to `ls`, `prune` and `--keep`
        // at once.
        let found = in_dir(&dir, NODE).expect("the directory is readable");
        assert_eq!(found.iter().map(Archive::name).collect::<Vec<_>>(), [name]);

        let _ = std::fs::remove_dir_all(dir);
    }

    /// The bug: the listing kept only what `file_type` called a file, and `file_type` does not
    /// follow a symlink. An archive kept on another disk and linked into the directory was
    /// invisible to `ls`, `prune` and `--keep`, and its size was never read.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_archive_is_listed_with_the_size_of_what_it_points_at() {
        let dir = scratch_dir("symlink");
        let elsewhere = scratch_dir("symlink-target");
        let name = "maninak-z6MkiTBz1ymu-20260814T120000Z.tar.zst";
        std::fs::write(elsewhere.join(name), b"twelve bytes").expect("fixture is writable");
        std::os::unix::fs::symlink(elsewhere.join(name), dir.join(name))
            .expect("a symlink is creatable");

        let found = in_dir(&dir, NODE).expect("the directory is readable");
        assert_eq!(found.iter().map(Archive::name).collect::<Vec<_>>(), [name]);
        assert_eq!(
            found[0].bytes, 12,
            "the size is the target's, not the link's"
        );

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&elsewhere);
    }

    /// The bug: an archive whose metadata could not be read was listed with `bytes: 0`, and
    /// one whose kind could not be read was not listed at all. `prune` then reported "freeing
    /// 0 B", never deleted it and never counted it against `--keep`, and `newest` could name
    /// the file beside it.
    #[cfg(unix)]
    #[test]
    fn an_archive_that_cannot_be_examined_is_reported_rather_than_dropped() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = scratch_dir("unexamined");
        let locked = scratch_dir("unexamined-target");
        let hidden = "maninak-z6MkiTBz1ymu-20260814T120000Z.tar.zst";
        let seen = "maninak-z6MkiTBz1ymu-20260101T000000Z.tar.zst";
        touch(&locked, hidden);
        touch(&dir, seen);
        // A link into a directory this process may not enter, so the archive is there and
        // cannot be examined.
        std::os::unix::fs::symlink(locked.join(hidden), dir.join(hidden))
            .expect("a symlink is creatable");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000))
            .expect("mode is settable");
        // Root and anything holding CAP_DAC_OVERRIDE walks straight through mode 000, so
        // there is nothing it could fail to examine. Probed here rather than guessed from a
        // user name, because the probe is the condition itself.
        let walks_through_any_mode = std::fs::metadata(dir.join(hidden)).is_ok();

        let listed = listing(&dir, NODE);
        let refused = in_dir(&dir, NODE);
        let newest_one = newest(&dir, NODE);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700))
            .expect("mode is settable back");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&locked);

        if walks_through_any_mode {
            return;
        }
        let (archives, unexamined) = listed.expect("the directory itself is readable");
        assert_eq!(
            archives.iter().map(Archive::name).collect::<Vec<_>>(),
            [seen],
            "what could be examined is still listed"
        );
        let complaints: Vec<String> = unexamined.iter().map(ToString::to_string).collect();
        assert_eq!(complaints.len(), 1, "{complaints:?}");
        assert!(
            complaints[0].contains(hidden),
            "the complaint names the archive: {complaints:?}"
        );
        // The callers that delete by count or pick by name must not act on a listing with a
        // hole in it.
        assert!(
            matches!(refused, Err(Error::Io { ref path, .. }) if path.ends_with(hidden)),
            "an incomplete listing is not a listing: {refused:?}"
        );
        assert!(
            newest_one.is_err(),
            "the newest of an incomplete listing may be the one that could not be seen"
        );
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
