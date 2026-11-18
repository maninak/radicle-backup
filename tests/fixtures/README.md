# Conformance archives

Three small archives of the format `ARCHIVE-FORMAT.md` specifies, for another implementation (such as Grove's in the browser) to test against. `tests/conformance.rs` and `verify_and_restore_read_an_archive_written_the_way_grove_writes_one` in `tests/end_to_end.rs` check them on every `cargo test`. They ship in the published crate, because its tests read them, so a project testing against them can take them from the crate or from this repository.

| File | What it is |
|---|---|
| `plaintext.tar.zst` | (a) A `--plaintext` archive at zstd level 10. It holds no key and no salt, so the writer reproduces it byte for byte, and a test fails when the writer's bytes change. |
| `passphrase.tar.zst.age` | (b) The same entries and the same `manifest.json` bytes as (a), encrypted to a passphrase at scrypt work factor 10. A test opens it with the passphrase and with its unwrapped file key. |
| `grove-level-3.tar.zst.age` | (c) An identity archive written the way Grove writes one: zstd level 3, a pinned work factor (10 here, 18 in Grove), and every entry pushed through `begin_entry`, `write_entry` and `end_entry` in small chunks. `rad-backup verify --deep` must pass on it, and `rad-backup restore` must bring its key back at mode 0600. |

- Archive passphrase: `the fixture passphrase`
- Passphrase on the private key inside (c): `the fixture key passphrase`
- Identity in (c): the all-zero seed, `did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp`. (a) and (b) name the same DID but carry no key.

(a) and (b) test the container and its encryption only. They are not restorable identities: their identity fields are placeholders, their bundle is not a git bundle, and `rad-backup verify` reports the missing key. (c) is the one whole identity.

The expected manifest of (a) and (b) is (a)'s own `manifest.json` (`zstd -dc plaintext.tar.zst | tar -xO manifest.json`), and `tests/conformance.rs` holds (b)'s manifest bytes to it.

Every manifest field is fixed (`tool.version` is `0.0.0-fixture`, `created` is `2026-11-18T00:00:00Z`), so a release changes none of them.

## Regenerating

`cargo run --example write_fixtures` rewrites all three from `tests/support/fixtures.rs`. (b) and (c) come out different on every run, because age draws a fresh salt and file key and the key's own encryption draws a fresh salt. Their contents stay the same. (a) changes when the tar inside it changes, which is a change to the archive format, so regenerate it then only on purpose and say so in the changelog. It also changes when a zstd upgrade compresses the same tar differently, which every reader still opens. The test names which of the two happened. After a zstd upgrade alone, commit only the new (a), because (b) and (c) still open and regenerating them only churns their salts.
