# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses [semantic versioning](https://semver.org/spec/v2.0.0.html). The archive format has its own version, tracked in `ARCHIVE-FORMAT.md`.

## [Unreleased]

### Added

- `schedule --recipient` and `schedule --plaintext`: a scheduled backup can now encrypt to an age or ssh key, or skip encryption for a store that encrypts it, with no passphrase file needed.

### Fixed

- `--dry-run --json` now prints a JSON report, like every other command's `--json`, instead of the human-readable table.
- Output a machine consumes (JSON reports, listings, recovery sheets) now fails the run when it cannot be written, instead of exiting `0` over a truncated report. A pipe closed on purpose, as `... | head` does, still counts as success.
- A repository whose visibility `rad` could not report is now treated as private and named in a warning, instead of being taken for public and left out of `--repos private`.
- `restore` no longer abandons the whole restore over one repository that fails: the rest are restored, the failed ones are named, and the run exits `3` with a `notRestored` list in its JSON report.
- A repository whose restore fails partway no longer leaves an empty repository behind in storage, which later backups would have counted as real.
- `restore` without `git` on PATH now says how many repositories it could not put back, instead of reporting success.
- `create --stdout --json` is refused rather than writing the archive and the report into the same stream.
- A flag typed before its verb, as in `rad backup --tier full create` or `rad backup --output ... schedule`, is now answered with where the flag belongs, instead of a message that reads as a denial of a flag the verb plainly has.
- The marker lines in a generated systemd unit now say what is true: a unit that keeps them is rewritten by the next `schedule` run, and deleting them is what preserves a hand edit. The environment file, which every run rewrites in full, no longer carries the marker.
- `schedule` no longer accepts a `RAD_BACKUP_PASSPHRASE` exported in your shell as proof that the timer can get a passphrase: systemd starts the service from its own environment. One that systemd itself holds still counts, so a working timer is not refused.
- A binary or output path containing a space now produces a unit systemd can run and a crontab line a shell can run.
- A recipient holding a character systemd or a shell treats specially (a `$` or `%`, a quote, a backslash) now reaches the scheduled run exactly as it was given, in both the systemd unit and the printed crontab line.
- `schedule --status` now says when systemd could not be asked at all (as over ssh to a headless machine), instead of reporting a running timer as `disabled`.
- A backup no longer fails after the archive is already written: a `.README.txt` note that could not be placed beside it, or older archives that could not be pruned, are warnings now rather than an exit `1` over a good archive.
- `--stop-node` now reports when `rad node stop` itself failed, and gives up at once instead of waiting out the whole timeout on a node that was never going to stop.
- `verify --deep` without `git` on PATH now names the bundles it could not open, instead of passing.
- A followed peer with no alias no longer fails the backup's read of the policies database.
- Write and parse errors name the file they are about.
- Failing to open a recipient-encrypted archive now points at `--identity` and the kind of key it was encrypted to, instead of blaming a passphrase that was never involved.
- The copy-paste block in `RESTORE.md` that puts the identity back now refuses to run over a home that already holds a key, instead of printing a warning and overwriting the key on the next line.
- `restore.sh` inside an archive no longer claims to have restored policies that a tier without them never carried.
- The refusal over a home too large for one archive now suggests `--repos private` or `--repos mine`, which narrow what is carried; it used to suggest splitting the home across several `--repos` runs, which the flag cannot do.
- A crash or a full disk partway through a restore can no longer leave a home holding neither the old identity nor the new one: the key files and `config.json` are now written beside their targets and renamed into place.
- `restore --force` over another identity now keeps the public half of the displaced key beside the retired private half. Before, only the private half survived; a public key derives back from it, so nothing was ever beyond recovery.
- `restore` checks again that the node is not running immediately before it writes, not only before it reads the archive: unpacking a large archive leaves time for a node to start in between.
- Reading a node database that has a write-ahead log beside it creates a `-shm` index file in the home, and the run now names that file instead of staying silent.
- A node database that cannot be read is now named in the error, instead of a bare `unable to open database file` with no path.
- An archive whose manifest will not parse is now named in the error, instead of a bare `expected value at line 1 column 1` with no file attached.
- `--stop-node` asks for the archive passphrase before it stops the node, not while the node is down waiting for somebody to find it.
- `diff --json` now names moved repositories by rid, like every other list in the report, instead of by display name.
- The manifest records the hostname on macOS and the BSDs, which have neither `/etc/hostname` nor `HOSTNAME` and so recorded nothing at all.
- A repository `git` cannot read no longer stops the whole backup: it is named, carried into the manifest with no refs, and the archive is written and marked incomplete (exit `3`) instead of not written at all.
- The warnings about a repository `rad` could not describe or `git` could not read no longer promise it a place in the archive when the run's tier or `--repos` choice never selects it.
- Counts agree with their nouns in the shipped `restore.sh` and in `verify --deep` without git, so no line reads "1 repositories".

### Security

- `paper` without `--output` no longer writes the sheet to a path taken from `RAD_BACKUP_DIR`. A recovery sheet carrying the secret key could land unasked where backups go, which is often a directory synced off the machine.
- The shipped `restore.sh` skips a bundle whose name is not a repository id, rather than trusting the name it was handed. `rad backup` already refuses such an archive; the script is what runs when `rad backup` is not there.

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
- Every command that reads an archive, except `restore`, can be given none and mean the newest one of this identity it can find, and says which it chose. `restore` asks for the path, because putting the wrong archive back is not something a default should be able to do.
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
