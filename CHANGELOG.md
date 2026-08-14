# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses [semantic versioning](https://semver.org/spec/v2.0.0.html). The archive format has its own version, tracked in `ARCHIVE-FORMAT.md`.

## [Unreleased]

### Added

- `rad backup`: encrypted archives of a Radicle identity, node state and repositories, in three tiers (`identity`, `state`, `full`) with `--repos` to override what each carries.
- `restore`: staged, digest-checked restores that compare every restored repository with the network before handing back control, so a stale archive cannot fork your peer history.
- `verify` and `verify --deep`: digests, and a proof that the archive really does rebuild the identity it names.
- `doctor`: seven checks on how recoverable an identity currently is, each naming the command that fixes it.
- `diff`: what has changed since the last archive, with no passphrase and no decryption. Exits `3` on drift, so `rad backup diff || rad backup` is a complete scheduling policy.
- `list`: what is inside an archive, as prose or as JSON.
- `move`: a machine-to-machine migration that retires the source key only after the archive verifies deeply.
- `paper`: a printable recovery sheet with a QR code, and `--words` for a 24-word mnemonic that `restore --words` reads back.
- Encryption to a passphrase or to age and ssh recipients, with `--plaintext` for archives going straight into a store that encrypts them.
- A recovery path that needs nothing but `tar`, `git`, `sqlite3` and `jq`: `RESTORE.md` and `restore.sh` ride inside every archive.
- Shell completions (`completions`) and a man page (`man`).
