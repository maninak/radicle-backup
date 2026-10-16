//! The archive container, a tar of plain files compressed with zstd and encrypted with age.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::path::{Component, Path};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypt::{self, Encryption, Sink};
use crate::error::{Error, Result};
use crate::manifest::{Entry, MANIFEST_ENTRY, Manifest};

/// The zstd level, a little slower than the default 3 and meaningfully smaller on the text in
/// a Radicle home. Levels above about 15 stop paying.
const COMPRESSION_LEVEL: i32 = 10;

/// The largest manifest a reader accepts, checked from the tar header before allocating.
///
/// `read_to_string` grows to the declared size, so a header claiming 8 GiB would cost 8 GiB.
/// A real manifest takes about a kilobyte per repository, so thousands fit.
const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;

/// The largest entry a reader accepts, checked from the tar header before copying.
///
/// The ceiling sits far above any repository bundle and only refuses the absurd before it
/// fills a disk.
const MAX_ENTRY_BYTES: u64 = 64 * 1024 * 1024 * 1024;

pub use crate::perms::{MODE_DOC, MODE_SECRET};

pub struct Writer<'a> {
    tar: tar::Builder<zstd::Encoder<'static, Sink<'a>>>,
    entries: Vec<Entry>,
}

impl<'a> Writer<'a> {
    pub fn create(output: Box<dyn Write + 'a>, encryption: &Encryption) -> Result<Self> {
        let sink = Sink::new(output, encryption)?;
        let encoder = zstd::Encoder::new(sink, COMPRESSION_LEVEL).map_err(Error::PathlessIo)?;
        Ok(Self {
            tar: tar::Builder::new(encoder),
            entries: Vec::new(),
        })
    }

    /// Adds an in-memory entry, such as a JSON export or the restore instructions.
    pub fn add_bytes(&mut self, path: &str, bytes: &[u8], mode: u32) -> Result<()> {
        reject_unwritable_name(path)?;
        let mut header = entry_header(bytes.len() as u64, mode);
        self.tar
            .append_data(&mut header, path, bytes)
            .map_err(Error::PathlessIo)?;
        self.entries.push(Entry {
            path: path.to_string(),
            bytes: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(bytes)),
        });
        Ok(())
    }

    /// Adds a file from disk, hashing it in the same pass that copies it.
    ///
    /// The tar header carries the size before the content, and some files are read live from
    /// the home. A file whose length changes mid-copy fails the run.
    pub fn add_file(&mut self, path: &str, source: &Path, mode: u32) -> Result<Entry> {
        reject_unwritable_name(path)?;
        let file = std::fs::File::open(source).map_err(|e| Error::io(source, e))?;
        let size = file.metadata().map_err(|e| Error::io(source, e))?.len();

        let mut reader = HashingReader::new(file);
        let mut header = entry_header(size, mode);
        self.tar
            .append_data(&mut header, path, &mut reader)
            .map_err(Error::PathlessIo)?;

        let written = reader.bytes_read();
        if written != size {
            return Err(Error::Refused {
                what: format!(
                    "{} changed while it was being added to the archive. It was {size} bytes, \
                     but {written} bytes were read",
                    source.display()
                ),
                remedy: "run the backup again. If this keeps happening, stop whatever writes to \
                     your Radicle home during the backup. `--stop-node` stops your node for it"
                    .to_string(),
            });
        }

        let entry = Entry {
            path: path.to_string(),
            bytes: size,
            sha256: reader.digest(),
        };
        self.entries.push(entry.clone());
        Ok(entry)
    }

    /// Writes the manifest and closes every layer.
    ///
    /// The manifest comes last, because it carries each entry's digest as written. The archive
    /// is readable only once this returns, because the encryption layer writes its last chunk.
    pub fn finish(mut self, manifest: &mut Manifest) -> Result<()> {
        manifest.entries = std::mem::take(&mut self.entries);
        manifest.entries.sort_by(|a, b| a.path.cmp(&b.path));

        let json = serde_json::to_vec_pretty(manifest)?;
        // The writer enforces the reader's ceiling, so this tool never writes an archive it
        // would refuse to open
        if json.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(Error::Refused {
                what: format!(
                    "the archive's record of its files would be {} bytes. The limit is \
                     {MAX_MANIFEST_BYTES} bytes",
                    json.len()
                ),
                remedy: format!(
                    "include fewer repositories with `--repos private` or `--repos mine`. \
                     Report this with `rad issue open --repo {}`",
                    crate::credits::RID
                ),
            });
        }
        let mut header = entry_header(json.len() as u64, MODE_DOC);
        self.tar
            .append_data(&mut header, MANIFEST_ENTRY, json.as_slice())
            .map_err(Error::PathlessIo)?;

        let encoder = self.tar.into_inner().map_err(Error::PathlessIo)?;
        let sink = encoder.finish().map_err(Error::PathlessIo)?;
        sink.finish()
    }
}

/// What a pass over an archive observed, for checking against the manifest's claims.
pub struct Scan {
    pub manifest: Manifest,
    /// Each entry's byte count and sha256 as read out of the archive.
    pub observed: BTreeMap<String, (u64, String)>,
}

impl Scan {
    /// Describes each entry that differs from the manifest's record, is missing, or is
    /// unlisted.
    pub fn mismatches(&self) -> Vec<String> {
        let mut problems = Vec::new();
        for entry in &self.manifest.entries {
            match self.observed.get(&entry.path) {
                None => problems.push(format!(
                    "{}: listed in the archive's record but missing",
                    entry.path
                )),
                Some((bytes, sha256)) => {
                    if *bytes != entry.bytes {
                        problems.push(format!(
                            "{}: {} bytes in the archive, but the archive's record says {}",
                            entry.path, bytes, entry.bytes
                        ));
                    } else if *sha256 != entry.sha256 {
                        problems.push(format!(
                            "{}: its contents are damaged or were changed",
                            entry.path
                        ));
                    }
                }
            }
        }
        for path in self.observed.keys() {
            if self.manifest.entry(path).is_none() {
                problems.push(format!(
                    "{path}: in the archive but not in the archive's record"
                ));
            }
        }
        problems
    }
}

pub struct Reader<'a> {
    archive: tar::Archive<Box<dyn Read + 'a>>,
}

impl<'a> Reader<'a> {
    /// Opens an archive, decrypting it when it begins with an age header, so a renamed archive
    /// still opens.
    pub fn open(
        path: &Path,
        passphrase: Option<&Zeroizing<String>>,
        identities: &crypt::Identities,
    ) -> Result<Self> {
        let file = std::fs::File::open(path).map_err(|e| Error::io(path, e))?;
        let stream: Box<dyn Read> = if crypt::looks_encrypted(path)? {
            crypt::decrypting_reader(file, passphrase, identities)?
        } else {
            Box::new(file)
        };
        let decoder = zstd::Decoder::new(stream).map_err(|e| Error::NotAnArchive {
            path: path.to_path_buf(),
            reason: format!("it is not zstd-compressed ({e})"),
        })?;
        Ok(Self {
            archive: tar::Archive::new(Box::new(decoder)),
        })
    }

    /// Reads the whole archive without writing anything, hashing as it goes.
    pub fn scan(self, archive_path: &Path) -> Result<Scan> {
        self.walk(archive_path, |_, reader| {
            io::copy(reader, &mut io::sink()).map_err(Error::PathlessIo)?;
            Ok(())
        })
    }

    /// Reads the whole archive, writing each entry under `into`.
    ///
    /// `into` must be a staging directory and never the home, so a truncated or corrupt
    /// archive cannot leave a half-built identity behind.
    pub fn unpack(self, archive_path: &Path, into: &Path) -> Result<Scan> {
        std::fs::create_dir_all(into).map_err(|e| Error::io(into, e))?;
        self.walk(archive_path, |entry_path, reader| {
            let destination = into.join(entry_path);
            if let Some(parent) = destination.parent() {
                std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
            }
            let mut file = crate::perms::create_private_file(&destination)?;
            io::copy(reader, &mut file).map_err(Error::PathlessIo)?;
            file.flush().map_err(Error::PathlessIo)?;
            Ok(())
        })
    }

    fn walk(
        mut self,
        archive_path: &Path,
        mut visit: impl FnMut(&str, &mut dyn Read) -> Result<()>,
    ) -> Result<Scan> {
        let mut manifest = None;
        let mut observed = BTreeMap::new();

        for entry in self.archive.entries().map_err(Error::PathlessIo)? {
            let mut entry = entry.map_err(Error::PathlessIo)?;
            let entry_name_os = entry.path().map_err(Error::PathlessIo)?.into_owned();
            // A lossy conversion maps two non-UTF-8 names to one string, and one file then
            // silently overwrites the other. Entry names this tool writes are ASCII.
            let entry_path = entry_name_os
                .to_str()
                .ok_or_else(|| Error::NotAnArchive {
                    path: archive_path.to_path_buf(),
                    reason: format!(
                        "it holds a file name that is not valid UTF-8: {}",
                        entry_name_os.display()
                    ),
                })?
                .to_string();
            reject_traversal(&entry_path, archive_path)?;

            // `entry.size()` honours a PAX size override, which is what bounds the reader. The
            // ustar field can declare 1 while the entry hands out gigabytes.
            let declared = entry.size();

            if entry_path == MANIFEST_ENTRY {
                if declared > MAX_MANIFEST_BYTES {
                    return Err(Error::NotAnArchive {
                        path: archive_path.to_path_buf(),
                        reason: format!(
                            "its {MANIFEST_ENTRY} file claims {declared} bytes. The limit is \
                             {MAX_MANIFEST_BYTES}"
                        ),
                    });
                }
                let mut json = String::new();
                entry.read_to_string(&mut json).map_err(Error::PathlessIo)?;
                // The error names the archive, because serde alone names no file
                manifest = Some(serde_json::from_str::<Manifest>(&json).map_err(|e| {
                    Error::NotAnArchive {
                        path: archive_path.to_path_buf(),
                        reason: format!("its {MANIFEST_ENTRY} file could not be read: {e}"),
                    }
                })?);
                continue;
            }

            if declared > MAX_ENTRY_BYTES {
                return Err(Error::NotAnArchive {
                    path: archive_path.to_path_buf(),
                    reason: format!(
                        "its file {entry_path} claims {declared} bytes. The limit is \
                         {MAX_ENTRY_BYTES}"
                    ),
                });
            }

            let mut reader = HashingReader::new(entry);
            visit(&entry_path, &mut reader)?;
            observed.insert(entry_path, (reader.bytes_read(), reader.digest()));
        }

        let manifest = manifest.ok_or_else(|| Error::NotAnArchive {
            path: archive_path.to_path_buf(),
            reason: format!("it has no {MANIFEST_ENTRY} file"),
        })?;
        if manifest.format > crate::manifest::FORMAT_VERSION {
            return Err(Error::ArchiveTooNew {
                found: manifest.format,
                supported: crate::manifest::FORMAT_VERSION,
            });
        }
        for repo in &manifest.repos {
            reject_hostile_rid(&repo.rid, archive_path)?;
        }
        Ok(Scan { manifest, observed })
    }
}

fn entry_header(size: u64, mode: u32) -> tar::Header {
    let mut header = tar::Header::new_gnu();
    header.set_size(size);
    header.set_mode(mode);
    header.set_entry_type(tar::EntryType::Regular);
    // Fixed ownership and timestamp make an unchanged repository's entry identical across
    // archives, so restic and borg can deduplicate it. The manifest's clock and age's salt
    // still make each whole archive differ.
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    header
}

/// Refuses to write an entry under a name the tar cannot carry unchanged.
///
/// Verify compares the name the manifest recorded with the name tar stored. A name with a
/// Windows separator makes those disagree, and the archive fails its own verification.
fn reject_unwritable_name(path: &str) -> Result<()> {
    if !is_portable_entry_name(path) {
        return Err(Error::Refused {
            what: format!("`{path}` cannot be used as a file name inside an archive"),
            remedy: format!(
                "this is a bug in rad-backup. Report it with `rad issue open --repo {}`",
                crate::credits::RID
            ),
        });
    }
    Ok(())
}

/// Refuses an entry that would be written outside the directory it is unpacked into.
///
/// A restore runs with the user's full rights, and an entry named
/// `../../.ssh/authorized_keys` would use them.
fn reject_traversal(entry_path: &str, archive: &Path) -> Result<()> {
    if !is_portable_entry_name(entry_path) {
        return Err(Error::NotAnArchive {
            path: archive.to_path_buf(),
            reason: format!(
                "its file `{entry_path}` would be written outside the target directory"
            ),
        });
    }
    Ok(())
}

/// Whether `entry_path` is a relative, `/`-separated name that stays under its root.
///
/// The name is judged as written, the same on every platform. A backslash or a `C:` is never a
/// name this tool writes, and on Windows `/etc/passwd` is not `is_absolute()` yet lands at the
/// drive root.
fn is_portable_entry_name(entry_path: &str) -> bool {
    let bytes = entry_path.as_bytes();
    let drive_qualified = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    !drive_qualified
        && !entry_path.contains('\\')
        && !Path::new(entry_path).components().any(|c| {
            matches!(
                c,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
}

/// Refuses a repository id that would not stay a single directory under `storage/`.
///
/// `Home::repository_path` joins each manifest id onto the home, and `Path::join` drops the
/// base for an absolute component. A real id is `rad:` followed by base58.
fn reject_hostile_rid(rid: &str, archive: &Path) -> Result<()> {
    if !crate::rad::is_identifier(rid) {
        return Err(Error::NotAnArchive {
            path: archive.to_path_buf(),
            reason: format!("`{rid}` is not a repository id"),
        });
    }
    Ok(())
}

/// A reader that digests what passes through it, so hashing costs no extra pass.
struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
    bytes: u64,
}

impl<R: Read> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            bytes: 0,
        }
    }

    fn digest(self) -> String {
        hex::encode(self.hasher.finalize())
    }

    fn bytes_read(&self) -> u64 {
        self.bytes
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.hasher.update(&buf[..read]);
        self.bytes += read as u64;
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::manifest::{IdentityInfo, NodeInfo, RepoSelection, SourceInfo, Tier, ToolInfo};

    fn manifest() -> Manifest {
        Manifest {
            format: crate::manifest::FORMAT_VERSION,
            tool: ToolInfo::default(),
            created: "2026-08-14T00:00:00Z".to_string(),
            tier: Tier::Identity,
            repo_selection: RepoSelection::None,
            identity: IdentityInfo {
                did: "did:key:z6MkTest".to_string(),
                node_id: "z6MkTest".to_string(),
                alias: Some("tester".to_string()),
                public_key: "ssh-ed25519 AAAA".to_string(),
                fingerprint: "SHA256:test".to_string(),
                key_is_encrypted: true,
            },
            source: SourceInfo {
                host: None,
                rad_home: "/home/tester/.radicle".to_string(),
                rad_version: None,
                git_version: None,
                os: "linux".to_string(),
                retires_key: None,
            },
            node: NodeInfo::default(),
            entries: Vec::new(),
            repos: Vec::new(),
            policies: crate::manifest::PolicySummary::default(),
            warnings: Vec::new(),
        }
    }

    fn scratch_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("rad-backup-archive-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch directory is creatable");
        dir
    }

    fn write_archive(path: &Path, encryption: &Encryption) {
        let file = std::fs::File::create(path).expect("archive is creatable");
        let mut writer = Writer::create(Box::new(file), encryption).expect("writer opens");
        writer
            .add_bytes("keys/radicle", b"pretend key material", MODE_SECRET)
            .expect("entry is writable");
        writer
            .add_bytes("config.json", b"{\"node\":{}}", MODE_DOC)
            .expect("entry is writable");
        writer.finish(&mut manifest()).expect("archive closes");
    }

    #[test]
    fn an_archive_round_trips_and_reports_no_mismatches() {
        let dir = scratch_dir("round-trip");
        let path = dir.join("archive.tar.zst");
        write_archive(&path, &Encryption::Plaintext);

        let scan = Reader::open(&path, None, &crypt::Identities::default())
            .expect("archive opens")
            .scan(&path)
            .expect("archive scans");
        assert_eq!(scan.manifest.entries.len(), 2);
        assert!(scan.mismatches().is_empty(), "{:?}", scan.mismatches());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    #[cfg(unix)]
    fn unpacking_writes_every_entry_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch_dir("unpack");
        let path = dir.join("archive.tar.zst");
        write_archive(&path, &Encryption::Plaintext);

        let into = dir.join("staging");
        let scan = Reader::open(&path, None, &crypt::Identities::default())
            .expect("archive opens")
            .unpack(&path, &into)
            .expect("archive unpacks");
        assert!(scan.mismatches().is_empty());

        let key = into.join("keys/radicle");
        assert_eq!(
            std::fs::read(&key).expect("key was written"),
            b"pretend key material"
        );
        let mode = std::fs::metadata(&key)
            .expect("key is there")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, MODE_SECRET);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_tampered_entry_is_reported_as_a_digest_mismatch() {
        let dir = scratch_dir("tamper");
        let path = dir.join("archive.tar.zst");
        write_archive(&path, &Encryption::Plaintext);

        // A manifest with one entry's claim rewritten is what a corrupted archive looks like
        let scan = Reader::open(&path, None, &crypt::Identities::default())
            .expect("archive opens")
            .scan(&path)
            .expect("archive scans");
        let mut manifest = scan.manifest;
        if let Some(entry) = manifest
            .entries
            .iter_mut()
            .find(|e| e.path == "config.json")
        {
            entry.sha256 = "0".repeat(64);
        }
        let tampered = Scan {
            manifest,
            observed: scan.observed,
        };
        let problems = tampered.mismatches();
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("config.json"), "{problems:?}");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn an_encrypted_archive_needs_its_passphrase_and_then_reads_normally() {
        let dir = scratch_dir("encrypted");
        let path = dir.join("archive.tar.zst.age");
        let passphrase = Zeroizing::new("open sesame".to_string());
        write_archive(&path, &Encryption::Passphrase(passphrase.clone()));

        assert!(crypt::looks_encrypted(&path).expect("header is readable"));
        assert!(Reader::open(&path, None, &crypt::Identities::default()).is_err());

        let scan = Reader::open(&path, Some(&passphrase), &crypt::Identities::default())
            .expect("archive opens with the passphrase")
            .scan(&path)
            .expect("archive scans");
        assert!(scan.mismatches().is_empty());

        let _ = std::fs::remove_dir_all(dir);
    }

    /// Builds an archive by hand, to test entry types the writer never emits.
    fn write_hostile_archive(path: &Path, entry: impl FnOnce(&mut tar::Builder<Vec<u8>>)) {
        let mut builder = tar::Builder::new(Vec::new());
        entry(&mut builder);

        let mut header = entry_header(0, MODE_DOC);
        let json = serde_json::to_vec(&manifest()).expect("a manifest serialises");
        header.set_size(json.len() as u64);
        header.set_cksum();
        builder
            .append_data(&mut header, MANIFEST_ENTRY, json.as_slice())
            .expect("the manifest appends");
        let tar = builder.into_inner().expect("the tar closes");

        let file = std::fs::File::create(path).expect("archive is creatable");
        let mut encoder = zstd::Encoder::new(file, 1).expect("encoder opens");
        encoder.write_all(&tar).expect("the tar compresses");
        encoder.finish().expect("the encoder closes");
    }

    #[test]
    fn an_archive_whose_manifest_will_not_parse_says_which_archive() {
        let dir = scratch_dir("bad-manifest");
        let path = dir.join("archive.tar.zst");

        let junk = b"this is not a manifest";
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = entry_header(junk.len() as u64, MODE_DOC);
        builder
            .append_data(&mut header, MANIFEST_ENTRY, junk.as_slice())
            .expect("the entry appends");
        let tar = builder.into_inner().expect("the tar closes");
        let file = std::fs::File::create(&path).expect("archive is creatable");
        let mut encoder = zstd::Encoder::new(file, 1).expect("encoder opens");
        encoder.write_all(&tar).expect("the tar compresses");
        encoder.finish().expect("the encoder closes");

        let failed = Reader::open(&path, None, &crypt::Identities::default())
            .expect("the outer layers still open")
            .scan(&path);
        let failed = match failed {
            Ok(_) => panic!("a manifest that is not json must not scan"),
            Err(e) => e,
        };

        // The error must name the archive, because serde's own message names no file
        let said = failed.to_string();
        assert!(said.contains("archive.tar.zst"), "{said}");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_repository_id_that_would_not_stay_under_storage_is_refused() {
        let archive = Path::new("/tmp/whatever.tar.zst");
        assert!(reject_hostile_rid("rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5", archive).is_ok());
        assert!(reject_hostile_rid("z3gqcJUoA1n9HaHKufZs5FCSGazv5", archive).is_ok());

        // `Path::join` drops the base for an absolute component, so each of these would
        // write outside the home
        assert!(reject_hostile_rid("rad:../../../.ssh", archive).is_err());
        assert!(reject_hostile_rid("..", archive).is_err());
        assert!(reject_hostile_rid("/etc/cron.d", archive).is_err());
        assert!(reject_hostile_rid("rad:a/b", archive).is_err());
        assert!(reject_hostile_rid("rad:a\\b", archive).is_err());
        assert!(reject_hostile_rid("", archive).is_err());
        assert!(reject_hostile_rid("rad:", archive).is_err());
    }

    #[test]
    fn an_archive_naming_a_repository_outside_the_home_is_refused_before_it_is_opened() {
        let dir = scratch_dir("hostile-rid");
        let path = dir.join("archive.tar.zst");

        // The archive is built by hand, because this tool never writes such an id, so the
        // refusal must happen on read
        let mut json = serde_json::to_value(manifest()).expect("a manifest serialises");
        json["repos"] = serde_json::json!([{
            "rid": "rad:../../../../tmp/pwned",
            "delegate": false,
            "refs": 0,
        }]);
        let json = serde_json::to_vec(&json).expect("the manifest serialises");

        let mut builder = tar::Builder::new(Vec::new());
        let mut header = entry_header(json.len() as u64, MODE_DOC);
        builder
            .append_data(&mut header, MANIFEST_ENTRY, json.as_slice())
            .expect("the entry appends");
        let tar = builder.into_inner().expect("the tar closes");
        let file = std::fs::File::create(&path).expect("archive is creatable");
        let mut encoder = zstd::Encoder::new(file, 1).expect("encoder opens");
        encoder.write_all(&tar).expect("the tar compresses");
        encoder.finish().expect("the encoder closes");

        // `scan` runs before any verb writes, and the manifest is a second place, besides
        // entry names, where an archive states a path
        let refused = Reader::open(&path, None, &crypt::Identities::default())
            .expect("the outer layers still open")
            .scan(&path);
        let refused = match refused {
            Ok(_) => panic!("an archive naming a repository outside the home must not scan"),
            Err(e) => e,
        };
        let said = refused.to_string();
        assert!(said.contains("is not a repository id"), "{said}");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_symlink_entry_becomes_a_plain_file_and_never_a_link_out_of_the_staging_directory() {
        let dir = scratch_dir("symlink");
        let path = dir.join("archive.tar.zst");
        let outside = dir.join("outside.txt");
        std::fs::write(&outside, b"not yours").expect("the target is writable");

        write_hostile_archive(&path, |builder| {
            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_mode(MODE_SECRET);
            header.set_entry_type(tar::EntryType::Symlink);
            header
                .set_link_name("../outside.txt")
                .expect("the link name fits");
            header.set_cksum();
            builder
                .append_data(&mut header, "keys/radicle", std::io::empty())
                .expect("the symlink appends");
        });

        let into = dir.join("staging");
        Reader::open(&path, None, &crypt::Identities::default())
            .expect("archive opens")
            .unpack(&path, &into)
            .expect("archive unpacks");

        let landed = into.join("keys/radicle");
        let kind = std::fs::symlink_metadata(&landed).expect("something landed");
        assert!(
            !kind.is_symlink(),
            "a symlink was created out of an archive"
        );
        assert_eq!(
            std::fs::read(&outside).expect("the target survives"),
            b"not yours",
            "the entry was written through the link"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn an_archive_whose_entry_climbs_out_is_refused_before_anything_is_written() {
        let dir = scratch_dir("climb");
        let path = dir.join("archive.tar.zst");
        write_hostile_archive(&path, |builder| {
            // The tar crate's path API refuses `..`, so the name goes straight into the
            // header field, as a handwritten tar would have it
            let mut header = entry_header(6, MODE_SECRET);
            let name = b"../escaped";
            header.as_old_mut().name[..name.len()].copy_from_slice(name);
            header.set_cksum();
            builder
                .append(&header, b"gotcha".as_slice())
                .expect("the entry appends");
        });

        let into = dir.join("staging");
        let refused = Reader::open(&path, None, &crypt::Identities::default())
            .expect("archive opens")
            .unpack(&path, &into);
        assert!(matches!(refused, Err(Error::NotAnArchive { .. })));
        assert!(!dir.join("escaped").exists());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn an_entry_that_climbs_out_of_the_archive_is_refused() {
        let archive = Path::new("/tmp/whatever.tar.zst");
        assert!(reject_traversal("keys/radicle", archive).is_ok());
        assert!(reject_traversal("../../.ssh/authorized_keys", archive).is_err());
        assert!(reject_traversal("/etc/passwd", archive).is_err());
        // Windows shapes are refused on every platform, because the archive is the same file
        // wherever it is opened. The first two are not `is_absolute()` on Windows.
        assert!(reject_traversal("C:/Windows/System32/drivers/etc/hosts", archive).is_err());
        assert!(reject_traversal("C:evil", archive).is_err());
        assert!(reject_traversal("\\\\server\\share\\evil", archive).is_err());
        assert!(reject_traversal("keys\\radicle", archive).is_err());
    }

    #[test]
    fn an_entry_name_the_tar_would_rewrite_is_refused_at_write_time() {
        assert!(reject_unwritable_name("repos/z3gq.bundle").is_ok());
        // `PathBuf::join` builds this on Windows, and tar stores it with `/` while the
        // manifest keeps the backslash, so the archive fails its own verification
        assert!(reject_unwritable_name("repos\\z3gq.bundle").is_err());
        assert!(reject_unwritable_name("/etc/passwd").is_err());
        assert!(reject_unwritable_name("../escape").is_err());
    }

    #[test]
    fn repository_entry_names_are_the_same_on_every_platform() {
        for name in [
            crate::git::bundle_entry("rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5"),
            crate::git::config_entry("rad:z3gqcJUoA1n9HaHKufZs5FCSGazv5"),
        ] {
            assert!(
                reject_unwritable_name(&name).is_ok(),
                "`{name}` is not a name an archive can carry"
            );
        }
    }
}
