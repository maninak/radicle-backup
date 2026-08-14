//! The archive container: a tar of plain files, compressed with zstd, then encrypted with age.
//!
//! Layers are ordinary formats in an ordinary order on purpose. Somebody with no copy of this
//! tool, five years from now, can recover an identity with `age`, `tar` and `git` alone, and
//! the instructions for doing that ride inside the archive.
//!
//! The manifest is written last, because it carries the digest of every entry as that entry
//! was written. A manifest written first could only carry digests of what was on disk before
//! the copy, which is a claim about the wrong bytes.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::crypt::{self, Encryption, Sink};
use crate::error::{Error, Result};
use crate::manifest::{Entry, MANIFEST_ENTRY, Manifest};

/// zstd level 10 costs a little more time than the default 3 and gives a meaningfully smaller
/// archive on the text-heavy contents of a Radicle home. Levels above ~15 stop paying.
const COMPRESSION_LEVEL: i32 = 10;

/// Permissions for anything that could hold key material: owner read and write, nothing else.
pub const SECRET_MODE: u32 = 0o600;
/// Permissions for documentation entries a user is meant to read after extracting.
pub const DOC_MODE: u32 = 0o644;

pub struct Writer<'a> {
    tar: tar::Builder<zstd::Encoder<'static, Sink<'a>>>,
    entries: Vec<Entry>,
}

impl<'a> Writer<'a> {
    pub fn create(output: Box<dyn Write + 'a>, encryption: &Encryption) -> Result<Self> {
        let sink = Sink::new(output, encryption)?;
        let encoder = zstd::Encoder::new(sink, COMPRESSION_LEVEL).map_err(Error::Bare)?;
        Ok(Self {
            tar: tar::Builder::new(encoder),
            entries: Vec::new(),
        })
    }

    /// Add bytes already in memory: manifests, JSON exports, the restore instructions.
    pub fn add_bytes(&mut self, path: &str, bytes: &[u8], mode: u32) -> Result<()> {
        let mut header = header(bytes.len() as u64, mode);
        self.tar
            .append_data(&mut header, path, bytes)
            .map_err(Error::Bare)?;
        self.entries.push(Entry {
            path: path.to_string(),
            bytes: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(bytes)),
        });
        Ok(())
    }

    /// Add a file from disk, hashing it in the same pass that copies it.
    ///
    /// The tar header needs the size before the content, so a file that changes length while
    /// it is being read would produce a corrupt entry. Everything this tool archives is either
    /// static (keys, config) or a snapshot it just took, so that cannot happen here.
    pub fn add_file(&mut self, path: &str, source: &Path, mode: u32) -> Result<Entry> {
        let file = std::fs::File::open(source).map_err(|e| Error::io(source, e))?;
        let size = file.metadata().map_err(|e| Error::io(source, e))?.len();

        let mut reader = HashingReader::new(file);
        let mut header = header(size, mode);
        self.tar
            .append_data(&mut header, path, &mut reader)
            .map_err(Error::Bare)?;

        let entry = Entry {
            path: path.to_string(),
            bytes: size,
            sha256: reader.digest(),
        };
        self.entries.push(entry.clone());
        Ok(entry)
    }

    /// Write the manifest and close every layer. The archive is only readable once this
    /// returns, because the encryption layer writes its final chunk here.
    pub fn finish(mut self, manifest: &mut Manifest) -> Result<()> {
        manifest.entries = std::mem::take(&mut self.entries);
        manifest.entries.sort_by(|a, b| a.path.cmp(&b.path));

        let json = serde_json::to_vec_pretty(manifest)?;
        let mut header = header(json.len() as u64, DOC_MODE);
        self.tar
            .append_data(&mut header, MANIFEST_ENTRY, json.as_slice())
            .map_err(Error::Bare)?;

        let encoder = self.tar.into_inner().map_err(Error::Bare)?;
        let sink = encoder.finish().map_err(Error::Bare)?;
        sink.finish()
    }
}

/// What a pass over an archive observed, for checking against what the manifest claims.
pub struct Scan {
    pub manifest: Manifest,
    /// Path to (bytes, sha256) as actually read out of the archive.
    pub observed: BTreeMap<String, (u64, String)>,
}

impl Scan {
    /// Entries whose bytes do not match the manifest, plus entries the manifest lists that the
    /// archive does not contain. Both are corruption; naming which is which saves a bisect.
    pub fn mismatches(&self) -> Vec<String> {
        let mut problems = Vec::new();
        for entry in &self.manifest.entries {
            match self.observed.get(&entry.path) {
                None => problems.push(format!(
                    "{}: listed in the manifest but missing",
                    entry.path
                )),
                Some((bytes, sha256)) => {
                    if *bytes != entry.bytes {
                        problems.push(format!(
                            "{}: {} bytes in the archive, {} in the manifest",
                            entry.path, bytes, entry.bytes
                        ));
                    } else if *sha256 != entry.sha256 {
                        problems.push(format!(
                            "{}: contents do not match their digest",
                            entry.path
                        ));
                    }
                }
            }
        }
        for path in self.observed.keys() {
            if self.manifest.entry(path).is_none() {
                problems.push(format!("{path}: in the archive but not in the manifest"));
            }
        }
        problems
    }
}

pub struct Reader<'a> {
    archive: tar::Archive<Box<dyn Read + 'a>>,
}

impl<'a> Reader<'a> {
    /// Open an archive, decrypting it when it is encrypted. Detection reads the age header
    /// rather than trusting the file name, so a renamed archive still opens.
    pub fn open(
        path: &Path,
        passphrase: Option<&Zeroizing<String>>,
        identities: &[PathBuf],
    ) -> Result<Self> {
        let file = std::fs::File::open(path).map_err(|e| Error::io(path, e))?;
        let stream: Box<dyn Read> = if crypt::looks_encrypted(path)? {
            crypt::decrypting_reader(file, passphrase, identities)?
        } else {
            Box::new(file)
        };
        let decoder = zstd::Decoder::new(stream).map_err(|e| Error::NotAnArchive {
            path: path.to_path_buf(),
            reason: format!("not zstd-compressed ({e})"),
        })?;
        Ok(Self {
            archive: tar::Archive::new(Box::new(decoder)),
        })
    }

    /// Read the whole archive without writing anything, hashing as it goes.
    pub fn scan(self, path: &Path) -> Result<Scan> {
        self.walk(path, |_, reader| {
            io::copy(reader, &mut io::sink()).map_err(Error::Bare)?;
            Ok(())
        })
    }

    /// Read the whole archive, writing each entry under `into`.
    ///
    /// Entries land in a staging directory rather than in the home being restored, so that a
    /// truncated or corrupt archive cannot leave a half-built identity behind.
    pub fn unpack(self, path: &Path, into: &Path) -> Result<Scan> {
        std::fs::create_dir_all(into).map_err(|e| Error::io(into, e))?;
        self.walk(path, |entry_path, reader| {
            let destination = into.join(entry_path);
            if let Some(parent) = destination.parent() {
                std::fs::create_dir_all(parent).map_err(|e| Error::io(parent, e))?;
            }
            let mut file = create_private(&destination)?;
            io::copy(reader, &mut file).map_err(Error::Bare)?;
            file.flush().map_err(Error::Bare)?;
            Ok(())
        })
    }

    fn walk(
        mut self,
        path: &Path,
        mut sink: impl FnMut(&str, &mut dyn Read) -> Result<()>,
    ) -> Result<Scan> {
        let mut manifest = None;
        let mut observed = BTreeMap::new();

        for entry in self.archive.entries().map_err(Error::Bare)? {
            let mut entry = entry.map_err(Error::Bare)?;
            let entry_path = entry
                .path()
                .map_err(Error::Bare)?
                .to_string_lossy()
                .into_owned();
            reject_traversal(&entry_path, path)?;

            if entry_path == MANIFEST_ENTRY {
                let mut json = String::new();
                entry.read_to_string(&mut json).map_err(Error::Bare)?;
                manifest = Some(serde_json::from_str::<Manifest>(&json)?);
                continue;
            }

            let mut reader = HashingReader::new(entry);
            sink(&entry_path, &mut reader)?;
            observed.insert(entry_path, (reader.bytes_read(), reader.digest()));
        }

        let manifest = manifest.ok_or_else(|| Error::NotAnArchive {
            path: path.to_path_buf(),
            reason: format!("no {MANIFEST_ENTRY} inside"),
        })?;
        if manifest.format > crate::manifest::FORMAT_VERSION {
            return Err(Error::ArchiveTooNew {
                found: manifest.format,
                supported: crate::manifest::FORMAT_VERSION,
            });
        }
        Ok(Scan { manifest, observed })
    }
}

/// Create a file only the owner can read, before any bytes go into it.
///
/// Setting the mode after writing would leave a window in which a private key is
/// world-readable, and on a shared machine that window is all an attacker needs.
pub fn create_private(path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(SECRET_MODE)
        .open(path)
        .map_err(|e| Error::io(path, e))
}

fn header(size: u64, mode: u32) -> tar::Header {
    let mut header = tar::Header::new_gnu();
    header.set_size(size);
    header.set_mode(mode);
    header.set_entry_type(tar::EntryType::Regular);
    // Fixed ownership and timestamp keep two archives of an unchanged home byte-identical,
    // which is what lets restic and borg deduplicate successive backups.
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    header
}

/// Refuse an entry that would write outside the directory it is being unpacked into.
///
/// Archives are usually one's own, but "usually" is not a security property: a restore runs
/// with the user's full rights, and an entry called `../../.ssh/authorized_keys` would use
/// them.
fn reject_traversal(entry_path: &str, archive: &Path) -> Result<()> {
    let path = Path::new(entry_path);
    let escapes = path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir));
    if escapes {
        return Err(Error::NotAnArchive {
            path: archive.to_path_buf(),
            reason: format!("entry `{entry_path}` points outside the archive"),
        });
    }
    Ok(())
}

/// A reader that digests what passes through it, so hashing costs no extra pass over the data.
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
                key_encrypted: true,
            },
            source: SourceInfo {
                host: None,
                rad_home: "/home/tester/.radicle".to_string(),
                rad_version: None,
                git_version: None,
                os: "linux".to_string(),
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
            .add_bytes("keys/radicle", b"pretend key material", SECRET_MODE)
            .expect("entry is writable");
        writer
            .add_bytes("config.json", b"{\"node\":{}}", DOC_MODE)
            .expect("entry is writable");
        writer.finish(&mut manifest()).expect("archive closes");
    }

    #[test]
    fn an_archive_round_trips_and_reports_no_mismatches() {
        let dir = scratch_dir("round-trip");
        let path = dir.join("archive.tar.zst");
        write_archive(&path, &Encryption::None);

        let scan = Reader::open(&path, None, &[])
            .expect("archive opens")
            .scan(&path)
            .expect("archive scans");
        assert_eq!(scan.manifest.entries.len(), 2);
        assert!(scan.mismatches().is_empty(), "{:?}", scan.mismatches());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn unpacking_writes_every_entry_with_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch_dir("unpack");
        let path = dir.join("archive.tar.zst");
        write_archive(&path, &Encryption::None);

        let into = dir.join("staging");
        let scan = Reader::open(&path, None, &[])
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
        assert_eq!(mode & 0o777, SECRET_MODE);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_tampered_entry_is_reported_as_a_digest_mismatch() {
        let dir = scratch_dir("tamper");
        let path = dir.join("archive.tar.zst");
        write_archive(&path, &Encryption::None);

        // Rewrite the manifest's claim about one entry, which is what a corrupted archive
        // looks like from the reader's side.
        let scan = Reader::open(&path, None, &[])
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
        assert!(Reader::open(&path, None, &[]).is_err());

        let scan = Reader::open(&path, Some(&passphrase), &[])
            .expect("archive opens with the passphrase")
            .scan(&path)
            .expect("archive scans");
        assert!(scan.mismatches().is_empty());

        let _ = std::fs::remove_dir_all(dir);
    }

    /// Build an archive by hand, so that entry types our own writer never emits can be tested.
    fn write_hostile_archive(path: &Path, entry: impl FnOnce(&mut tar::Builder<Vec<u8>>)) {
        let mut builder = tar::Builder::new(Vec::new());
        entry(&mut builder);

        let mut header = header(0, DOC_MODE);
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
    fn a_symlink_entry_becomes_a_plain_file_and_never_a_link_out_of_the_staging_directory() {
        let dir = scratch_dir("symlink");
        let path = dir.join("archive.tar.zst");
        let outside = dir.join("outside.txt");
        std::fs::write(&outside, b"not yours").expect("the target is writable");

        write_hostile_archive(&path, |builder| {
            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_mode(SECRET_MODE);
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
        Reader::open(&path, None, &[])
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
            // The tar crate refuses to write `..` through its own path API, which is exactly
            // the archive a hostile writer would not use. The name goes into the header field
            // directly, the way a handwritten tar would have it.
            let mut header = header(6, SECRET_MODE);
            let name = b"../escaped";
            header.as_old_mut().name[..name.len()].copy_from_slice(name);
            header.set_cksum();
            builder
                .append(&header, b"gotcha".as_slice())
                .expect("the entry appends");
        });

        let into = dir.join("staging");
        let refused = Reader::open(&path, None, &[])
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
    }
}
