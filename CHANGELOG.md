# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses [semantic versioning](https://semver.org/spec/v2.0.0.html). The archive format has its own version, tracked in `ARCHIVE-FORMAT.md`.

## [Unreleased]

### Fixed

- `--dry-run --json` answers with the report every other command's `--json` gives, instead of printing the human table on stdout and no object at all.
- Output a machine consumes (JSON reports, listings, recovery sheets) now fails the run when it cannot be written, instead of exiting `0` over a truncated report. A pipe closed on purpose, as `... | head` does, still counts as success.
- A `rad` that fails to answer is no longer read as a `rad` with nothing to say. A repository whose visibility could not be read is carried as though it were private and named in a warning, rather than taken for public and left out of `--repos private`.
- `restore` no longer abandons the whole restore over one repository that will not come back: the rest are restored, the ones that did not are named, and the run exits `3`. The JSON report gains `notRestored`.
- A repository that fails partway through being restored no longer leaves an empty bare repository in storage for the next inventory to count as a repository.
- `restore` without `git` on PATH now says how many repositories it could not put back, instead of reporting success.
- `create --stdout --json` is refused rather than writing the archive and the report into the same stream.
- `rad backup --tier full create` is refused with the flag's place, not with `--tier` shapes an archive, and `create` does not create one.
- - `rad backup --output ... schedule` is told that the flag belongs after the verb, instead of that `schedule` does not create an archive, which reads as a denial of a flag it plainly has.

### Security

- `paper --output` no longer takes its path from `RAD_BACKUP_DIR`. A recovery sheet carrying the secret key was being written into the directory backups go to, which is usually the directory that gets synced off the machine.

## [0.1.0] - 2026-08-16

### Added

- `rad backup`: encrypted archives of a Radicle identity, node state and repositories, in three tiers (`identity`, `state`, `full`) with `--repos` to override what each carries.
- `restore`: staged, digest-checked restores that compare every restored repository with the network before handing back control, so a stale archive cannot fork your peer history.
- `verify` and `verify --deep`: digests, and a proof that the archive really does rebuild the identity it names.
- `doctor`: seven checks on how recoverable an identity currently is, each naming the command that fixes it. Exits `3` when any check fails, so it works as a monitoring probe.
- `diff`: what has changed since the last archive, with no passphrase and no decryption. Exits `3` on drift, so `rad backup diff || rad backup` is a complete scheduling policy.
- `show`: what is inside an archive, as prose or as JSON.
- `ls`: every archive of this identity on disk, newest first, without opening any of them.
- `prune`: the same retention rule as `--keep`, on its own, with `--dry-run`.
- `schedule`: installs and turns on a systemd user timer, and refuses to enable one that has no way to get a passphrase.
- `--dry-run`: what a backup would carry, and roughly how large, writing nothing.
- Every command that takes an archive now defaults to the newest one of this identity it can find, and says which it chose.
- `move`: a machine-to-machine move that retires the source key only after the archive verifies deeply.
- `paper`: a printable recovery sheet with a QR code, and `--words` for a 24-word mnemonic that `restore --words` reads back.
- Encryption to a passphrase or to age and ssh recipients, with `--plaintext` for archives going straight into a store that encrypts them.
- A recovery path that needs nothing but `tar`, `git` and a POSIX shell: `RESTORE.md` and `restore.sh` ride inside every archive.
- Shell completions (`completions`) and a man page (`man`).
- Reproducible builds: a pinned toolchain, one codegen unit, `SOURCE_DATE_EPOCH` taken from the commit and remapped paths, checked twice over by CI and by the Nix flake.
- Signed releases: `sha256sums.txt` carries an ssh signature that `packaging/release/verify.sh` checks against `packaging/release/allowed_signers`.
- Packages: `.deb` for amd64 and arm64 from a signed apt repository at <https://apt.radicle.tools>, tarballs for Linux, macOS and FreeBSD, a `.zip` for Windows, a crate, and a Nix flake.
- An audit map in `SECURITY.md`: every file that touches a secret and what each has to convince a reviewer of.
- A `rad-restore` symlink to the same binary, so `rad restore <archive>` also works.
