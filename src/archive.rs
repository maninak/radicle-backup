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

/// A ceiling on the manifest, checked before a byte of it is allocated.
///
/// `read_to_string` grows to whatever the tar header declares, so an archive whose manifest
/// header claims 8 GiB costs 8 GiB of memory to reject. The real thing is a few kilobytes of
/// JSON per entry; a home with a hundred thousand entries would not reach a tenth of this.
const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;

/// A ceiling on any single entry, likewise checked from the header before copying.
///
/// Generous on purpose: the largest thing this tool writes is one repository bundle, and the
/// point is not to guess a real size but to refuse the absurd before it fills a disk.
const MAX_ENTRY_BYTES: u64 = 64 * 1024 * 1024 * 1024;

pub use crate::perms::{DOC_MODE, SECRET_MODE};

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
    /// it is being read produces a corrupt entry. Most of what this tool archives is a
    /// snapshot it just took, but some of it is read live out of the home, so the two are
    /// compared afterwards rather than assumed equal: a `config.json` rewritten mid-run would
    /// otherwise be padded or truncated to fit a header that no longer describes it, and the
    /// archive would be reported as written.
    pub fn add_file(&mut self, path: &str, source: &Path, mode: u32) -> Result<Entry> {
        let file = std::fs::File::open(source).map_err(|e| Error::io(source, e))?;
        let size = file.metadata().map_err(|e| Error::io(source, e))?.len();

        let mut reader = HashingReader::new(file);
        let mut header = header(size, mode);
        self.tar
            .append_data(&mut header, path, &mut reader)
            .map_err(Error::Bare)?;

        let written = reader.bytes_read();
        if written != size {
            return Err(Error::Refused {
                what: format!(
                    "{} changed while it was being archived: the entry says {size} bytes and \
                     {written} were read",
                    source.display()
                ),
                remedy: "take the backup again, and if it keeps happening, stop whatever is \
                     writing to the home while it runs (`--stop-node` covers the node itself)"
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

    /// Write the manifest and close every layer. The archive is only readable once this
    /// returns, because the encryption layer writes its final chunk here.
    pub fn finish(mut self, manifest: &mut Manifest) -> Result<()> {
        manifest.entries = std::mem::take(&mut self.entries);
        manifest.entries.sort_by(|a, b| a.path.cmp(&b.path));

        let json = serde_json::to_vec_pretty(manifest)?;
        // The same ceiling the reader enforces, checked here so the tool cannot write an
        // archive it would then refuse to open. A home would need on the order of a hundred
        // thousand repositories to reach it; if one ever does, this says so at the moment the
        // archive is written rather than at the moment somebody needs it back.
        if json.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(Error::Refused {
                what: format!(
                    "the manifest for this home is {} bytes, more than the {MAX_MANIFEST_BYTES} \
                     an archive can carry",
                    json.len()
                ),
                remedy: "take several archives with `--repos`, each covering part of the home"
                    .to_string(),
            });
        }
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
            let mut file = crate::perms::create_private(&destination)?;
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
            let raw = entry.path().map_err(Error::Bare)?.into_owned();
            // Refused rather than lossily converted: two names differing only outside UTF-8
            // both become the same string of replacement characters, so one file would
            // silently overwrite the other and the digest check would still pass. The format
            // says entry names are ASCII paths this tool wrote, so there is nothing to lose.
            let entry_path = raw
                .to_str()
                .ok_or_else(|| Error::NotAnArchive {
                    path: path.to_path_buf(),
                    reason: format!("entry name is not valid UTF-8: {}", raw.display()),
                })?
                .to_string();
            reject_traversal(&entry_path, path)?;

            // `entry.size()`, not `header().size()`: a PAX header can override the ustar
            // size field, and the override is what bounds the reader. Read from the header,
            // both ceilings below saw a declared 1 while the entry handed out gigabytes.
            let declared = entry.size();

            if entry_path == MANIFEST_ENTRY {
                if declared > MAX_MANIFEST_BYTES {
                    return Err(Error::NotAnArchive {
                        path: path.to_path_buf(),
                        reason: format!(
                            "{MANIFEST_ENTRY} declares {declared} bytes, more than the \
                             {MAX_MANIFEST_BYTES} this reads"
                        ),
                    });
                }
                let mut json = String::new();
                entry.read_to_string(&mut json).map_err(Error::Bare)?;
                manifest = Some(serde_json::from_str::<Manifest>(&json)?);
                continue;
            }

            if declared > MAX_ENTRY_BYTES {
                return Err(Error::NotAnArchive {
                    path: path.to_path_buf(),
                    reason: format!(
                        "entry {entry_path} declares {declared} bytes, more than the \
                         {MAX_ENTRY_BYTES} this reads"
                    ),
                });
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
        for repo in &manifest.repos {
            reject_hostile_rid(&repo.rid, path)?;
        }
        Ok(Scan { manifest, observed })
    }
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

/// Refuse a repository id that would not stay a single directory under `storage/`.
///
/// Entry names are checked above, but the ids in the manifest are a second, separate source of
/// paths: `Home::repository_path` joins one onto the home, and `Path::join` with an absolute
/// component throws the base away. An id of `rad:../../x` got `git init --bare` run on it
/// outside the home. A real id is `rad:` and base58, so anything else is refused here, once,
/// rather than at each of restore, verify and sync.
fn reject_hostile_rid(rid: &str, archive: &Path) -> Result<()> {
    let bare = rid.strip_prefix("rad:").unwrap_or(rid);
    if bare.is_empty() || !bare.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(Error::NotAnArchive {
            path: archive.to_path_buf(),
            reason: format!("`{rid}` is not a repository id"),
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
    #[cfg(unix)]
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
