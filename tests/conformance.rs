//! The conformance archives in `tests/fixtures`, which another implementation of the format
//! reads and writes against. `tests/fixtures/README.md` says what each one is.

// Only (a) is rewritten here. `examples/write_fixtures.rs` writes the other two
#[allow(dead_code)]
#[path = "support/fixtures.rs"]
mod fixtures;

use std::io::Read;
use std::path::{Path, PathBuf};

use radicle_backup::container::{EntryKind, HashingReader, Scan, Walker};
use radicle_backup::crypt::{self, Identities};
use radicle_backup::error::Error;
use zeroize::Zeroizing;

fn fixture(name: &str) -> (PathBuf, Vec<u8>) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let bytes = std::fs::read(&path).expect("the fixture is in the checkout");
    (path, bytes)
}

/// Walks a decrypted stream the way any reader of the format would, with the library's checks.
fn walk(plaintext: impl Read, label: &Path) -> Scan {
    let decoder = zstd::Decoder::new(plaintext).expect("the stream is zstd");
    let mut archive = tar::Archive::new(decoder);
    let mut walker = Walker::new(label);
    for entry in archive.entries().expect("the tar reads").raw(true) {
        let mut entry = entry.expect("the entry reads");
        let name = entry.path_bytes().into_owned();
        let type_flag = entry.header().entry_type().as_byte();
        match walker
            .begin(&name, type_flag, entry.size())
            .expect("the entry passes")
        {
            EntryKind::Manifest => {
                let mut json = Vec::new();
                entry.read_to_end(&mut json).expect("the manifest reads");
                walker.manifest_bytes(&json).expect("the manifest passes");
            }
            EntryKind::File(path) => {
                let mut reader = HashingReader::new(entry);
                std::io::copy(&mut reader, &mut std::io::sink()).expect("the entry reads");
                let bytes = reader.bytes_read();
                walker
                    .end(path, bytes, reader.digest())
                    .expect("the entry passes");
            }
        }
    }
    walker.finish().expect("the archive is whole")
}

#[test]
fn the_writer_reproduces_the_plaintext_fixture_byte_for_byte() {
    let (path, committed) = fixture(fixtures::PLAINTEXT);
    let written = fixtures::plaintext().expect("the fixture is writable");
    let tar = |zstd: &[u8]| zstd::decode_all(zstd).expect("the fixture is zstd");
    assert!(
        tar(&written) == tar(&committed),
        "the writer no longer writes the tar inside {} byte for byte, which is a change to the \
         archive format. If it is meant, run `cargo run --example write_fixtures` and say so in \
         the changelog",
        path.display()
    );
    // The same tar compressed differently is a zstd upgrade, which every reader still opens
    assert!(
        written == committed,
        "zstd now compresses {} differently, though the tar inside is unchanged. After a zstd \
         upgrade that is expected: run `cargo run --example write_fixtures` and commit only the new \
         plaintext fixture, since the other two still open",
        path.display()
    );
    assert!(walk(committed.as_slice(), &path).mismatches().is_empty());
}

#[test]
fn the_passphrase_fixture_opens_the_same_through_the_passphrase_and_through_its_file_key() {
    let (plain_path, plain) = fixture(fixtures::PLAINTEXT);
    let expected = walk(plain.as_slice(), &plain_path);
    let (path, archive) = fixture(fixtures::PASSPHRASE_ARCHIVE);
    let passphrase = Zeroizing::new(fixtures::PASSPHRASE.to_string());

    let through_passphrase = crypt::decrypting_reader(
        std::io::Cursor::new(&archive),
        Some(&passphrase),
        &Identities::default(),
        Some(fixtures::WORK_FACTOR),
    )
    .expect("the passphrase opens it");
    let key = crypt::unwrap_file_key(archive.as_slice(), &passphrase, fixtures::WORK_FACTOR)
        .expect("the passphrase unwraps its file key");
    let through_key =
        crypt::reader_with_file_key(archive.as_slice(), &key).expect("the file key opens it");

    for scan in [walk(through_passphrase, &path), walk(through_key, &path)] {
        assert!(scan.mismatches().is_empty(), "{:?}", scan.mismatches());
        // The same manifest bytes as the plaintext fixture's, so the same files and digests
        assert_eq!(scan.manifest_sha256, expected.manifest_sha256);
        assert_eq!(scan.observed, expected.observed);
    }
}

#[test]
fn a_file_key_opens_only_the_archive_it_came_from() {
    let passphrase = Zeroizing::new(fixtures::PASSPHRASE.to_string());
    let (_, own) = fixture(fixtures::PASSPHRASE_ARCHIVE);
    let (_, other) = fixture(fixtures::GROVE);
    let key = crypt::unwrap_file_key(own.as_slice(), &passphrase, fixtures::WORK_FACTOR)
        .expect("the passphrase unwraps its file key");

    let opened = crypt::reader_with_file_key(other.as_slice(), &key);
    assert!(
        matches!(opened, Err(Error::StaleFileKey)),
        "a foreign key is refused as the wrong key, not as damage"
    );
}
