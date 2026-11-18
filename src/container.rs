//! The archive container, a tar of plain files compressed with zstd and encrypted with age.

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
#[cfg(feature = "cli")]
use zeroize::Zeroizing;

#[cfg(feature = "cli")]
use crate::crypt;
use crate::crypt::{Encryption, Sink};
use crate::error::{Error, Result};
use crate::manifest::{Entry, MANIFEST_ENTRY, Manifest};

/// The zstd level `rad-backup` writes, a little slower than the default 3 and meaningfully
/// smaller on the text in a Radicle home. Levels above about 15 stop paying. A reader does not
/// depend on it.
pub const COMPRESSION_LEVEL: i32 = 10;

/// The largest manifest a reader accepts, checked from the tar header before allocating.
///
/// `read_to_string` grows to the declared size, so a header claiming 8 GiB would cost 8 GiB.
/// A real manifest takes about a kilobyte per repository, so thousands fit.
pub const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;

/// The largest entry a reader accepts, checked from the tar header before copying.
///
/// The ceiling sits far above any repository bundle and only refuses the absurd before it
/// fills a disk.
pub const MAX_ENTRY_BYTES: u64 = 64 * 1024 * 1024 * 1024;

/// The longest entry name, the GNU header's name field, which is all the writer uses.
pub const MAX_NAME_BYTES: usize = 100;

/// The mode of a private key, and of the archives that carry one.
pub const MODE_SECRET: u32 = 0o600;
/// The mode of what a Radicle home keeps world-readable, such as a public key or a config.
pub const MODE_DOC: u32 = 0o644;

/// The tar block, which every header and every padded entry fills.
const BLOCK: u64 = 512;

/// Writes an archive into any byte sink.
///
/// After any error the archive is incomplete, so the writer is dropped and not written to
/// again.
pub struct Writer<'a> {
    tar: tar::Builder<zstd::Encoder<'static, Sink<'a>>>,
    entries: Vec<Entry>,
    names: Spellings,
    open: Option<OpenEntry>,
}

/// The entry [`Writer::begin_entry`] started, whose bytes are still arriving.
struct OpenEntry {
    path: String,
    size: u64,
    hasher: Sha256,
    written: u64,
}

impl<'a> Writer<'a> {
    /// Opens an archive over `output`.
    ///
    /// `level` is the zstd level, which no reader depends on. `rad-backup` passes
    /// [`COMPRESSION_LEVEL`]. `work_factor` pins a passphrase archive's scrypt work factor, as
    /// [`Sink::new`] takes it.
    pub fn create(
        output: Box<dyn Write + 'a>,
        encryption: &Encryption,
        level: i32,
        work_factor: Option<u8>,
    ) -> Result<Self> {
        let sink = Sink::new(output, encryption, work_factor)?;
        let encoder = zstd::Encoder::new(sink, level).map_err(Error::PathlessIo)?;
        Ok(Self {
            tar: tar::Builder::new(encoder),
            entries: Vec::new(),
            names: Spellings::default(),
            open: None,
        })
    }

    /// Adds an in-memory entry, such as a JSON export or the restore instructions.
    pub fn add_bytes(&mut self, path: &str, bytes: &[u8], mode: u32) -> Result<()> {
        self.begin_entry(path, bytes.len() as u64, mode)?;
        self.write_entry(bytes)?;
        self.end_entry()?;
        Ok(())
    }

    /// Adds an entry of `size` bytes read from `source`, hashing it in the same pass that
    /// copies it.
    ///
    /// The tar header carries the size before the content, so a source that yields more or
    /// fewer bytes is refused as [`Error::EntryLength`]. The entry then stays open, so nothing
    /// else can be added or finished. Drop the writer and start again, because the source did
    /// not match the size its header promised.
    pub fn add_stream(
        &mut self,
        path: &str,
        size: u64,
        source: &mut dyn Read,
        mode: u32,
    ) -> Result<Entry> {
        self.begin_entry(path, size, mode)?;
        let mut buffer = vec![0u8; 64 * 1024];
        loop {
            let read = match source.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => read,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(Error::PathlessIo(e)),
            };
            self.write_entry(&buffer[..read])?;
        }
        self.end_entry()
    }

    /// Adds a file from disk, hashing it in the same pass that copies it.
    ///
    /// Some files are read live from the home. A file whose length changes mid-copy fails the
    /// run.
    #[cfg(feature = "cli")]
    pub fn add_file(&mut self, path: &str, source: &Path, mode: u32) -> Result<Entry> {
        let mut file = std::fs::File::open(source).map_err(|e| Error::io(source, e))?;
        let size = file.metadata().map_err(|e| Error::io(source, e))?.len();
        self.add_stream(path, size, &mut file, mode)
            .map_err(|failure| match failure {
                Error::EntryLength {
                    declared, given, ..
                } => Error::Refused {
                    what: format!(
                        "{} changed while it was being added to the archive. It was {declared} \
                         bytes, but {}{given} bytes were read",
                        source.display(),
                        // reading stops at the first byte past the declared size
                        if given > declared { "at least " } else { "" }
                    ),
                    remedy: "run the backup again. If this keeps happening, stop whatever \
                             writes to your Radicle home during the backup. `--stop-node` stops \
                             your node for it"
                        .to_string(),
                },
                other => other,
            })
    }

    /// Starts an entry of `size` bytes, whose content follows through
    /// [`write_entry`](Self::write_entry) and which [`end_entry`](Self::end_entry) closes.
    ///
    /// The header is the one `add_bytes` writes. A name too long for it is refused, because
    /// `tar` would carry it in an extra GNU long-name record, a header shape no archive of this
    /// format holds.
    pub fn begin_entry(&mut self, path: &str, size: u64, mode: u32) -> Result<()> {
        if path.eq_ignore_ascii_case(MANIFEST_ENTRY) {
            return Err(misuse(&format!(
                "`{path}` is the name `finish` gives the manifest, so no other entry can take it"
            )));
        }
        self.start_entry(path, size, mode)
    }

    fn start_entry(&mut self, path: &str, size: u64, mode: u32) -> Result<()> {
        self.refuse_while_open()?;
        reject_unwritable_name(path)?;
        if size > MAX_ENTRY_BYTES {
            return Err(Error::Refused {
                what: format!(
                    "`{path}` is {size} bytes, over the {MAX_ENTRY_BYTES} bytes an archive entry can hold"
                ),
                remedy: "leave this repository out of the archive".to_string(),
            });
        }
        if let Some(first) = self.names.first_spelling(path) {
            return Err(misuse(&if first == path {
                format!("`{path}` was already added to this archive")
            } else {
                format!(
                    "`{path}` was already added to this archive as `{first}`, which is the same file where case is ignored"
                )
            }));
        }
        let mut header = entry_header(size, mode);
        header.set_path(path).map_err(|e| Error::Refused {
            what: format!("`{path}` cannot be used as a file name inside an archive ({e})"),
            remedy: "use a name of at most 100 bytes, made of relative `/`-separated parts"
                .to_string(),
        })?;
        header.set_cksum();
        self.names.insert(path);
        self.tar
            .get_mut()
            .write_all(header.as_bytes())
            .map_err(Error::PathlessIo)?;
        self.open = Some(OpenEntry {
            path: path.to_string(),
            size,
            hasher: Sha256::new(),
            written: 0,
        });
        Ok(())
    }

    /// Writes the next bytes of the entry [`begin_entry`](Self::begin_entry) started.
    ///
    /// Bytes past its declared size are refused, and none of them is written.
    pub fn write_entry(&mut self, bytes: &[u8]) -> Result<()> {
        let Some(open) = self.open.as_mut() else {
            return Err(misuse("bytes were written with no entry begun"));
        };
        let given = open.written + bytes.len() as u64;
        if given > open.size {
            return Err(Error::EntryLength {
                entry: open.path.clone(),
                declared: open.size,
                given,
            });
        }
        self.tar
            .get_mut()
            .write_all(bytes)
            .map_err(Error::PathlessIo)?;
        open.hasher.update(bytes);
        open.written = given;
        Ok(())
    }

    /// Closes the entry [`begin_entry`](Self::begin_entry) started, padding it to a whole tar
    /// block, and returns its record.
    ///
    /// An entry shorter than its declared size is refused, because its header already promised
    /// that size. The entry stays open after that error. Write its missing bytes and end it
    /// again, or drop the writer, because nothing else can be added or finished while it is open.
    pub fn end_entry(&mut self) -> Result<Entry> {
        let Some(open) = self.open.as_ref() else {
            return Err(misuse("an entry was ended with none begun"));
        };
        // A short entry stays open, so the archive cannot be finished around a header that
        // promised more bytes than follow it.
        if open.written != open.size {
            return Err(Error::EntryLength {
                entry: open.path.clone(),
                declared: open.size,
                given: open.written,
            });
        }
        let open = self
            .open
            .take()
            .expect("the entry checked just above is still open");
        let short_of_block = (BLOCK - open.size % BLOCK) % BLOCK;
        self.tar
            .get_mut()
            .write_all(&[0u8; BLOCK as usize][..short_of_block as usize])
            .map_err(Error::PathlessIo)?;
        let entry = Entry {
            path: open.path,
            bytes: open.size,
            sha256: hex::encode(open.hasher.finalize()),
        };
        self.entries.push(entry.clone());
        Ok(entry)
    }

    fn refuse_while_open(&self) -> Result<()> {
        match &self.open {
            Some(open) => Err(misuse(&format!(
                "`{}` is still being written, so nothing else can be added",
                open.path
            ))),
            None => Ok(()),
        }
    }

    /// Writes the manifest and closes every layer.
    ///
    /// The manifest comes last, because it carries each entry's digest as written. The archive
    /// is readable only once this returns, because the encryption layer writes its last chunk.
    pub fn finish(mut self, manifest: &mut Manifest) -> Result<()> {
        self.refuse_while_open()?;
        manifest.entries = std::mem::take(&mut self.entries);
        manifest.entries.sort_by(|a, b| a.path.cmp(&b.path));

        // The writer holds the manifest to the reader's checks, so this library never writes an
        // archive it would refuse to open
        if manifest.format > crate::manifest::FORMAT_VERSION {
            return Err(misuse(&format!(
                "the archive's record says format {}, and this library reads up to format {}",
                manifest.format,
                crate::manifest::FORMAT_VERSION
            )));
        }
        if let Some(repo) = manifest
            .repos
            .iter()
            .find(|repo| !crate::manifest::is_identifier(&repo.rid))
        {
            return Err(misuse(&format!("`{}` is not a repository id", repo.rid)));
        }
        let json = serde_json::to_vec_pretty(manifest)?;
        if json.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(Error::Refused {
                what: format!(
                    "the archive's record of its files would be {} bytes. The limit is \
                     {MAX_MANIFEST_BYTES} bytes",
                    json.len()
                ),
                remedy: manifest_too_big_remedy(),
            });
        }
        self.start_entry(MANIFEST_ENTRY, json.len() as u64, MODE_DOC)?;
        self.write_entry(&json)?;
        self.end_entry()?;

        let encoder = self.tar.into_inner().map_err(Error::PathlessIo)?;
        let sink = encoder.finish().map_err(Error::PathlessIo)?;
        sink.finish()
    }
}

// The CLI chooses the repositories that fill the manifest. Another writer chooses its own entries
#[cfg(feature = "cli")]
fn manifest_too_big_remedy() -> String {
    format!(
        "include fewer repositories with `--repos private` or `--repos mine`. Report this with \
         `rad issue open --repo {}`",
        crate::credits::RID
    )
}
#[cfg(not(feature = "cli"))]
fn manifest_too_big_remedy() -> String {
    "put fewer entries and repositories in the archive".to_string()
}

/// A refusal for a caller that used the library out of order, which is a bug in that caller.
fn misuse(what: &str) -> Error {
    Error::Refused {
        what: what.to_string(),
        remedy: format!(
            "this is a bug in the program writing or reading the archive. If that is \
             rad-backup, report it with `rad issue open --repo {}`",
            crate::credits::RID
        ),
    }
}

/// What a pass over an archive observed, for checking against the manifest's claims.
pub struct Scan {
    pub manifest: Manifest,
    /// The sha256 of the manifest's own bytes, so a second pass can hold the archive to the
    /// manifest the first pass read.
    pub manifest_sha256: String,
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
                None => problems.push(missing(&entry.path)),
                Some((bytes, sha256)) => {
                    if *bytes != entry.bytes {
                        problems.push(wrong_size(&entry.path, *bytes, entry.bytes));
                    } else if *sha256 != entry.sha256 {
                        problems.push(changed(&entry.path));
                    }
                }
            }
        }
        for path in self.observed.keys() {
            if self.manifest.entry(path).is_none() {
                problems.push(unlisted(path));
            }
        }
        problems
    }
}

fn missing(path: &str) -> String {
    format!("{path}: listed in the archive's record but missing")
}

fn wrong_size(path: &str, bytes: u64, listed: u64) -> String {
    format!("{path}: {bytes} bytes in the archive, but the archive's record says {listed}")
}

fn changed(path: &str) -> String {
    format!("{path}: its contents are damaged or were changed")
}

fn unlisted(path: &str) -> String {
    format!("{path}: in the archive but not in the archive's record")
}

/// What a tar entry is, as [`Walker::begin`] names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    /// The manifest, whose bytes go to [`Walker::manifest_bytes`].
    Manifest,
    /// A file, whose bytes are hashed and reported to [`Walker::end`].
    File(String),
}

/// Every check a reader makes on an archive's entries, apart from reading them.
///
/// The driver walks the tar, which this crate does with the `tar` crate and a browser may do
/// another way. For each header it calls [`begin`](Self::begin) with the raw name, the type
/// byte and the declared size, then hands over the manifest's bytes or each file's count and
/// digest. Errors name the archive by the label given.
///
/// The driver hands over every header as it stands, with the `tar` crate in raw mode. A GNU
/// long-name or PAX record is otherwise read whole into memory before `begin` sees the entry
/// it describes, so a few kilobytes of archive could claim gigabytes. `begin` refuses each such
/// record, since the format holds none.
///
/// A first pass made with [`new`](Self::new) learns the manifest, which comes last. A second
/// pass made with [`expecting`](Self::expecting) holds every entry to that manifest as it
/// arrives, so a reader that writes entries out can refuse an archive that changed between
/// the two passes before keeping anything from it.
///
/// A first pass compares nothing as it goes. Call [`Scan::mismatches`] on what
/// [`finish`](Self::finish) returns before trusting any entry.
pub struct Walker {
    label: PathBuf,
    is_expecting: bool,
    record: Option<(Manifest, String)>,
    was_record_read: bool,
    observed: BTreeMap<String, (u64, String)>,
    names: Spellings,
    open: Option<EntryKind>,
}

impl Walker {
    pub fn new(label: &Path) -> Self {
        Self {
            label: label.to_path_buf(),
            is_expecting: false,
            record: None,
            was_record_read: false,
            observed: BTreeMap::new(),
            names: Spellings::default(),
            open: None,
        }
    }

    /// A pass that holds the archive to `manifest`, whose own bytes hash to `manifest_sha256`,
    /// as [`Scan`] reports both.
    pub fn expecting(manifest: Manifest, manifest_sha256: String, label: &Path) -> Self {
        Self {
            is_expecting: true,
            record: Some((manifest, manifest_sha256)),
            ..Self::new(label)
        }
    }

    /// Checks an entry's name, type and declared size before any of its bytes are read.
    ///
    /// `type_flag` is the header's type byte. `declared_size` is the size the driver will read
    /// at most, which in raw mode is the header's own size field.
    pub fn begin(
        &mut self,
        raw_name: &[u8],
        type_flag: u8,
        declared_size: u64,
    ) -> Result<EntryKind> {
        if self.open.is_some() {
            return Err(misuse("an entry was begun before the last one ended"));
        }
        // A link, a directory or a device escapes or reaches past the staging directory, and a
        // long-name or PAX record is a header shape the writer never makes
        if !matches!(type_flag, b'0' | b'\0') {
            return Err(self.not_an_archive(format!(
                "it holds `{}` with tar type `{}`, and the format holds only regular files",
                String::from_utf8_lossy(raw_name),
                type_flag.escape_ascii()
            )));
        }
        if raw_name.len() > MAX_NAME_BYTES {
            return Err(self.not_an_archive(format!(
                "it holds a file name of {} bytes. The limit is {MAX_NAME_BYTES}",
                raw_name.len()
            )));
        }
        // A lossy conversion maps two non-UTF-8 names to one string, and one file then
        // silently overwrites the other. Entry names this tool writes are ASCII.
        let name = std::str::from_utf8(raw_name).map_err(|_| {
            self.not_an_archive(format!(
                "it holds a file name that is not valid UTF-8: {}",
                String::from_utf8_lossy(raw_name)
            ))
        })?;
        reject_traversal(name, &self.label)?;
        // Two entries that land on one file would let a first pass vouch for bytes it never
        // compared with the record
        if let Some(first) = self.names.first_spelling(name) {
            return Err(self.not_an_archive(repeated(first, name)));
        }
        self.names.insert(name);

        let kind = if name == MANIFEST_ENTRY {
            if declared_size > MAX_MANIFEST_BYTES {
                return Err(self.not_an_archive(format!(
                    "its {MANIFEST_ENTRY} file claims {declared_size} bytes. The limit is \
                     {MAX_MANIFEST_BYTES}"
                )));
            }
            EntryKind::Manifest
        } else {
            if declared_size > MAX_ENTRY_BYTES {
                return Err(self.not_an_archive(format!(
                    "its file {name} claims {declared_size} bytes. The limit is \
                     {MAX_ENTRY_BYTES}"
                )));
            }
            if let Some(manifest) = self.expected() {
                match manifest.entry(name) {
                    None => return Err(self.damaged(unlisted(name))),
                    Some(listed) if listed.bytes != declared_size => {
                        return Err(self.damaged(wrong_size(name, declared_size, listed.bytes)));
                    }
                    Some(_) => {}
                }
            }
            EntryKind::File(name.to_string())
        };
        self.open = Some(kind.clone());
        Ok(kind)
    }

    /// Takes the manifest's bytes, after [`begin`](Self::begin) named the entry
    /// [`EntryKind::Manifest`].
    pub fn manifest_bytes(&mut self, json: &[u8]) -> Result<()> {
        if self.open.take() != Some(EntryKind::Manifest) {
            return Err(misuse(
                "manifest bytes arrived for an entry that is not the manifest",
            ));
        }
        if json.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(self.not_an_archive(format!(
                "its {MANIFEST_ENTRY} file holds {} bytes. The limit is {MAX_MANIFEST_BYTES}",
                json.len()
            )));
        }
        let sha256 = hex::encode(Sha256::digest(json));
        if self.is_expecting {
            if self
                .record
                .as_ref()
                .is_some_and(|(_, known)| *known != sha256)
            {
                return Err(self.damaged(changed(MANIFEST_ENTRY)));
            }
            self.was_record_read = true;
            return Ok(());
        }

        // The error names the archive, because serde alone names no file
        let manifest = serde_json::from_slice::<Manifest>(json).map_err(|e| {
            self.not_an_archive(format!("its {MANIFEST_ENTRY} file could not be read: {e}"))
        })?;
        if manifest.format > crate::manifest::FORMAT_VERSION {
            return Err(Error::ArchiveTooNew {
                found: manifest.format,
                supported: crate::manifest::FORMAT_VERSION,
            });
        }
        for repo in &manifest.repos {
            reject_hostile_rid(&repo.rid, &self.label)?;
        }
        self.record = Some((manifest, sha256));
        self.was_record_read = true;
        Ok(())
    }

    /// Records a file's byte count and digest as read, after [`begin`](Self::begin) named it.
    pub fn end(&mut self, path: String, bytes: u64, sha256: String) -> Result<()> {
        match self.open.take() {
            Some(EntryKind::File(begun)) if begun == path => {}
            _ => return Err(misuse("an entry was ended that was not the one begun")),
        }
        if let Some(listed) = self.expected().and_then(|manifest| manifest.entry(&path)) {
            if listed.bytes != bytes {
                return Err(self.damaged(wrong_size(&path, bytes, listed.bytes)));
            }
            if listed.sha256 != sha256 {
                return Err(self.damaged(changed(&path)));
            }
        }
        self.observed.insert(path, (bytes, sha256));
        Ok(())
    }

    /// Ends the pass, once the tar has no more entries.
    ///
    /// After a first pass, an `Ok` says only that the archive was walkable. Its
    /// [`Scan::mismatches`] say whether the entries match the manifest.
    pub fn finish(self) -> Result<Scan> {
        if self.open.is_some() {
            return Err(misuse("the walk ended inside an entry"));
        }
        let (manifest, manifest_sha256) = match self.record {
            Some(record) if self.was_record_read => record,
            _ => {
                return Err(Error::NotAnArchive {
                    path: self.label,
                    reason: format!("it has no {MANIFEST_ENTRY} file"),
                });
            }
        };
        if self.is_expecting
            && let Some(absent) = manifest
                .entries
                .iter()
                .find(|entry| !self.observed.contains_key(&entry.path))
        {
            return Err(Error::Damaged {
                path: self.label,
                problem: missing(&absent.path),
            });
        }
        Ok(Scan {
            manifest,
            manifest_sha256,
            observed: self.observed,
        })
    }

    fn expected(&self) -> Option<&Manifest> {
        match (&self.record, self.is_expecting) {
            (Some((manifest, _)), true) => Some(manifest),
            _ => None,
        }
    }

    fn not_an_archive(&self, reason: String) -> Error {
        Error::NotAnArchive {
            path: self.label.clone(),
            reason,
        }
    }

    fn damaged(&self, problem: String) -> Error {
        Error::Damaged {
            path: self.label.clone(),
            problem,
        }
    }
}

#[cfg(feature = "cli")]
pub struct Reader<'a> {
    archive: tar::Archive<Box<dyn Read + 'a>>,
}

#[cfg(feature = "cli")]
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
            // The library's read errors carry no path, and the user needs to know which file
            crypt::decrypting_reader(file, passphrase, identities, None).map_err(|e| match e {
                Error::PathlessIo(e) => Error::io(path, e),
                other => other,
            })?
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
            copy_entry(reader, archive_path, &mut io::sink(), archive_path)
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
            copy_entry(reader, archive_path, &mut file, &destination)?;
            file.flush().map_err(|e| Error::io(&destination, e))
        })
    }

    fn walk(
        mut self,
        archive_path: &Path,
        mut visit: impl FnMut(&str, &mut dyn Read) -> Result<()>,
    ) -> Result<Scan> {
        let mut walker = Walker::new(archive_path);

        // A damaged archive fails here with zstd's or age's bare message, so each error names
        // the archive
        let damaged = |e| Error::io(archive_path, e);
        for entry in self.archive.entries().map_err(damaged)?.raw(true) {
            let mut entry = entry.map_err(damaged)?;
            let raw_name = entry.path_bytes().into_owned();
            let type_flag = entry.header().entry_type().as_byte();
            match walker.begin(&raw_name, type_flag, entry.size())? {
                EntryKind::Manifest => {
                    let mut json = Vec::new();
                    entry.read_to_end(&mut json).map_err(damaged)?;
                    walker.manifest_bytes(&json)?;
                }
                EntryKind::File(entry_path) => {
                    let mut reader = HashingReader::new(entry);
                    visit(&entry_path, &mut reader)?;
                    let bytes = reader.bytes_read();
                    walker.end(entry_path, bytes, reader.digest())?;
                }
            }
        }
        walker.finish()
    }
}

/// Copies one entry out, naming the archive for a read error and `destination` for a write one.
#[cfg(feature = "cli")]
fn copy_entry(
    reader: &mut dyn Read,
    archive_path: &Path,
    writer: &mut impl Write,
    destination: &Path,
) -> Result<()> {
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(read) => read,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::io(archive_path, e)),
        };
        writer
            .write_all(&buffer[..read])
            .map_err(|e| Error::io(destination, e))?;
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
                "this is a bug in the program writing the archive. If that is rad-backup, report \
                 it with `rad issue open --repo {}`",
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
                "it holds a file named `{entry_path}`, which is not a name the format allows: \
                 `/`-separated parts of printable ASCII other than space, `\\`, `:` and `~`, \
                 none of them empty or ending in `.`"
            ),
        });
    }
    Ok(())
}

/// Whether `entry_path` is the one spelling of a file under the target directory, judged the
/// same on every platform: `/`-separated parts of printable ASCII other than space, `\`, `:`
/// and `~`, none of them empty or ending in `.`.
///
/// Windows drops a part's trailing `.`, reads `~` in 8.3 short names and `:` as a drive or a
/// stream, and lands `/etc/passwd` at the drive root, so each would be a second spelling there.
fn is_portable_entry_name(entry_path: &str) -> bool {
    entry_path
        .bytes()
        .all(|b| b.is_ascii_graphic() && !matches!(b, b'\\' | b':' | b'~'))
        && entry_path
            .split('/')
            .all(|part| !part.is_empty() && !part.ends_with('.'))
}

/// The entry names seen so far, keyed without case, because a file system that ignores case
/// puts `A` and `a` in one file.
#[derive(Default)]
struct Spellings(BTreeMap<String, String>);

impl Spellings {
    fn first_spelling(&self, name: &str) -> Option<&str> {
        self.0.get(&name.to_ascii_lowercase()).map(String::as_str)
    }

    fn insert(&mut self, name: &str) {
        self.0.insert(name.to_ascii_lowercase(), name.to_string());
    }
}

fn repeated(first: &str, name: &str) -> String {
    if first == name {
        format!("it holds two files named {name}")
    } else {
        format!("it holds files named {first} and {name}, which are one file where case is ignored")
    }
}

/// Refuses a repository id that would not stay a single directory under `storage/`.
///
/// `Home::repository_path` joins each manifest id onto the home, and `Path::join` drops the
/// base for an absolute component. A real id is `rad:` followed by base58.
fn reject_hostile_rid(rid: &str, archive: &Path) -> Result<()> {
    if !crate::manifest::is_identifier(rid) {
        return Err(Error::NotAnArchive {
            path: archive.to_path_buf(),
            reason: format!("`{rid}` is not a repository id"),
        });
    }
    Ok(())
}

/// A reader that digests what passes through it, so hashing costs no extra pass.
pub struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
    bytes: u64,
}

impl<R: Read> HashingReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            bytes: 0,
        }
    }

    /// The sha256 of every byte read, in hex.
    pub fn digest(self) -> String {
        hex::encode(self.hasher.finalize())
    }

    pub fn bytes_read(&self) -> u64 {
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
        let mut writer = Writer::create(Box::new(file), encryption, COMPRESSION_LEVEL, None)
            .expect("writer opens");
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
            manifest_sha256: scan.manifest_sha256,
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
    fn a_symlink_entry_is_refused_and_nothing_is_written_through_it() {
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
        let refused = Reader::open(&path, None, &crypt::Identities::default())
            .expect("archive opens")
            .unpack(&path, &into);
        assert!(
            matches!(&refused, Err(Error::NotAnArchive { reason, .. }) if reason.contains("keys/radicle")),
            "{:?}",
            refused.err()
        );
        assert!(
            std::fs::symlink_metadata(into.join("keys/radicle")).is_err(),
            "an entry landed from a symlink header"
        );
        assert_eq!(
            std::fs::read(&outside).expect("the target survives"),
            b"not yours",
            "the entry was written through the link"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_long_name_record_is_refused_before_its_body_is_read() {
        let dir = scratch_dir("long-name");
        let path = dir.join("archive.tar.zst");

        // A processing tar reader buffers a GNU long-name record's body whole, as large as its
        // header claims. This one claims a gigabyte and the stream ends long before, so a reader
        // that buffers it reports damage or runs out of memory instead of this refusal
        write_hostile_archive(&path, |builder| {
            let mut header = tar::Header::new_gnu();
            header.set_size(1 << 30);
            header.set_entry_type(tar::EntryType::GNULongName);
            header.set_path("././@LongLink").expect("the name fits");
            header.set_cksum();
            builder.get_mut().extend_from_slice(header.as_bytes());
        });

        let refused = Reader::open(&path, None, &crypt::Identities::default())
            .expect("archive opens")
            .scan(&path);
        assert!(
            matches!(&refused, Err(Error::NotAnArchive { reason, .. }) if reason.contains("tar type `L`")),
            "{:?}",
            refused.err()
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
        // tar stores the first as `keys/radicle`, and Windows writes the rest to that file or
        // to `keys/radicle.pub`, so each is a second spelling
        assert!(reject_unwritable_name("./keys/radicle").is_err());
        assert!(reject_unwritable_name("keys/radicle:x").is_err());
        assert!(reject_unwritable_name("keys//radicle").is_err());
        assert!(reject_unwritable_name("keys/./radicle").is_err());
        assert!(reject_unwritable_name("keys/radicle.").is_err());
        assert!(reject_unwritable_name("keys/RADICL~1.PUB").is_err());
    }

    #[test]
    fn an_entry_that_is_not_the_size_its_header_promised_is_refused() {
        let mut writer = Writer::create(
            Box::new(Vec::new()),
            &Encryption::Plaintext,
            COMPRESSION_LEVEL,
            None,
        )
        .expect("writer opens");

        writer
            .begin_entry("long", 3, MODE_DOC)
            .expect("the entry begins");
        assert!(matches!(
            writer.write_entry(b"four"),
            Err(Error::EntryLength {
                declared: 3,
                given: 4,
                ..
            })
        ));
        // Nothing else may start while the entry is open, or its bytes would land inside it
        assert!(matches!(
            writer.add_bytes("other", b"x", MODE_DOC),
            Err(Error::Refused { what, .. }) if what.contains("is still being written")
        ));
        writer
            .write_entry(b"ab")
            .expect("bytes within the size are taken");
        assert!(matches!(
            writer.end_entry(),
            Err(Error::EntryLength {
                declared: 3,
                given: 2,
                ..
            })
        ));
        // The short entry is still open, so the archive cannot be closed around it
        assert!(matches!(
            writer.finish(&mut manifest()),
            Err(Error::Refused { what, .. }) if what.contains("is still being written")
        ));
    }

    #[test]
    fn a_name_that_needs_a_gnu_long_name_record_is_refused() {
        let mut writer = Writer::create(
            Box::new(Vec::new()),
            &Encryption::Plaintext,
            COMPRESSION_LEVEL,
            None,
        )
        .expect("writer opens");
        let long = format!("repos/{}.bundle", "z".repeat(100));
        assert!(matches!(
            writer.begin_entry(&long, 0, MODE_DOC),
            Err(Error::Refused { .. })
        ));
    }

    #[test]
    fn a_second_pass_refuses_an_entry_whose_digest_differs_from_the_record() {
        let mut record = manifest();
        record.entries = vec![Entry {
            path: "config.json".to_string(),
            bytes: 3,
            sha256: hex::encode(Sha256::digest(b"abc")),
        }];
        let label = Path::new("archive.tar.zst");
        let mut walker = Walker::expecting(record, "0".repeat(64), label);

        assert_eq!(
            walker
                .begin(b"config.json", b'0', 3)
                .expect("a listed entry of its size begins"),
            EntryKind::File("config.json".to_string())
        );
        let refused = walker.end(
            "config.json".to_string(),
            3,
            hex::encode(Sha256::digest(b"abd")),
        );
        assert!(
            matches!(&refused, Err(Error::Damaged { path, problem }) if path == label && problem.starts_with("config.json:")),
            "{:?}",
            refused.err()
        );
    }

    #[test]
    fn a_first_pass_refuses_a_second_entry_with_the_same_name() {
        for second in ["repos/a.bundle", "REPOS/A.bundle"] {
            let mut walker = Walker::new(Path::new("archive.tar.zst"));
            let digest = hex::encode(Sha256::digest(b"abc"));
            walker
                .begin(b"repos/a.bundle", b'0', 3)
                .expect("the first copy begins");
            walker
                .end("repos/a.bundle".to_string(), 3, digest)
                .expect("the first copy ends");

            let refused = walker.begin(second.as_bytes(), b'0', 3);
            assert!(
                matches!(&refused, Err(Error::NotAnArchive { reason, .. }) if reason.contains(second)),
                "{second}: {:?}",
                refused.err()
            );
        }
    }

    #[test]
    fn the_writer_refuses_an_entry_its_reader_would_refuse() {
        for (first, second) in [
            ("repos/a.bundle", "repos/a.bundle"),
            ("repos/a.bundle", "Repos/a.bundle"),
            ("config.json", MANIFEST_ENTRY),
        ] {
            let mut archive = Vec::new();
            let mut writer =
                Writer::create(Box::new(&mut archive), &Encryption::Plaintext, 1, None)
                    .expect("the writer opens");
            writer
                .add_bytes(first, b"abc", MODE_DOC)
                .expect("the first entry is added");
            let refused = writer.add_bytes(second, b"abc", MODE_DOC);
            assert!(
                matches!(&refused, Err(Error::Refused { what, .. }) if what.contains(second)),
                "{second}: {:?}",
                refused.err()
            );
        }
    }

    #[test]
    fn the_writer_refuses_a_record_its_reader_would_refuse() {
        let too_new = Manifest {
            format: crate::manifest::FORMAT_VERSION + 1,
            ..manifest()
        };
        let hostile_repo = serde_json::from_value(serde_json::json!({
            "rid": "rad:../../.ssh", "delegate": false, "refs": 0
        }))
        .expect("the record parses");
        let hostile = Manifest {
            repos: vec![hostile_repo],
            ..manifest()
        };
        for mut record in [too_new, hostile] {
            let mut archive = Vec::new();
            let writer = Writer::create(Box::new(&mut archive), &Encryption::Plaintext, 1, None)
                .expect("the writer opens");
            let refused = writer.finish(&mut record);
            assert!(
                matches!(refused, Err(Error::Refused { .. })),
                "{:?}",
                refused.err()
            );
        }
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
