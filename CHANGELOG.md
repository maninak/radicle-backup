# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses [semantic versioning](https://semver.org/spec/v2.0.0.html). The archive format has its own version, tracked in `ARCHIVE-FORMAT.md`.

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
