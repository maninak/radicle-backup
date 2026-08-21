# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses [semantic versioning](https://semver.org/spec/v2.0.0.html). The archive format has its own version, tracked in `ARCHIVE-FORMAT.md`.

## [Unreleased]

### Added

- `schedule --recipient` and `schedule --plaintext`. A timer could only ever write passphrase-encrypted archives, so an identity backed up to an age or ssh key could not be scheduled at all. Neither needs a passphrase file, and both go into the unit's command line rather than the environment file.

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
- A `create` flag written before the verb is now told where it belongs.
- The marker in a generated systemd unit said edits would not be replaced, which is the opposite of what the next `schedule` run does to a file carrying it. The environment file, which every run rewrites in full, no longer carries that marker at all.
- `schedule` no longer accepts a `RAD_BACKUP_PASSPHRASE` exported in your shell as proof that the timer can get a passphrase: systemd starts the service from its own environment. One that systemd itself holds still counts, so a working timer is not refused.
- A binary or output path containing a space now produces a unit systemd can run and a crontab line a shell can run.
- `schedule --status` tells a timer that was never installed from a systemd that could not be asked, instead of reporting `disabled` on a headless machine whose timer runs every night.
- A backup no longer fails after the archive is already complete: a sidecar that could not be written, or older archives that could not be swept, are warnings now rather than an exit `1` over a good archive.
- `--stop-node` says so when `rad node stop` itself failed, and refuses at once rather than spending the whole timeout waiting for a stop that was never asked for.
- `--stop-node` says so when `rad node stop` itself failed, and refuses at once rather than spending the whole timeout watching a socket that was never going to close.
- `verify --deep` without `git` on PATH now names the bundles it could not open, instead of passing.
- A `following` row with no alias no longer fails the whole read of `policies.db`.
- Write and parse errors name the file they are about.
- An archive encrypted to recipients now says which key to pass when none of the given identities open it, instead of blaming a passphrase it never asked for.
- Pasting section 1 of `RESTORE.md` over a home that already holds a key now refuses instead of warning and then overwriting the identity on the next line.
- `restore.sh` inside an archive no longer claims to have restored policies that a tier without them never carried.
- The refusal over an oversized manifest names a remedy that can be followed. It asked for several archives with `--repos`, each covering part of the home, and `--repos` picks a category rather than a slice of one.
- `restore.sh` inside an archive no longer tells the reader to check policies that a tier without them never carried.
- A restore writes the secret key, the public key and `config.json` beside their targets and renames them into place. A crash or a full disk part way through used to leave a home holding neither the old identity nor the new one, because the old file was unlinked before the first byte of the new one was written.
- `restore` checks again that the node is not running immediately before it writes, not only before it reads the archive: unpacking a large archive leaves time for a node to start in between.
- Reading a node database that has a write-ahead log beside it creates a `-shm` file in the home, and the run now says so. It was reported as nothing at all, because the recording sat behind a writable-connection fallback that a write-ahead log never reaches. That fallback is gone: it could not run, and could not have helped.
- A node database that cannot be read names itself, instead of surfacing as a bare `unable to open database file` from whichever query happened to run first.
- An archive whose manifest will not parse names the archive, instead of surfacing as serde's own `expected value at line 1 column 1` with no file attached.
- `--stop-node` asks for the archive passphrase before it stops the node, not while the node is down waiting for somebody to find it.
- The `diff --json` report names moved repositories by rid, like every other field in it. It named them by display name, so the one list a consumer would act on was the one it could not look anything up with.
- The manifest records the hostname on macOS and the BSDs, which have neither `/etc/hostname` nor `HOSTNAME` and so recorded nothing at all.
- A repository `git` cannot read no longer stops the whole backup. It is named, carried into the manifest with no refs, and the archive is written and marked incomplete (exit `3`) instead of not written at all. The bundling stage already worked this way; the inventory that runs before it did not, so it never got the chance.
- - A `restore --force` over another identity keeps the public half of the key it displaces. That rename put the file back onto itself, reported success, and left the restore to overwrite it seconds later, while the note filed beside the retired key named a file that was never written. The private half was always kept and a public key derives back from it, so nothing was beyond recovery.
- - The warnings about a repository `rad` could not describe or `git` could not read say what this run actually carries. Both promised a place in the archive to repositories that a `--tier identity` or `--repos seeded` run never selects.
- - A recipient holding a `$` or a `%` reaches the scheduled run as it was given. systemd substitutes both inside `ExecStart=`, quotes or no quotes, and an ssh recipient ends in a free-text comment.
- - The crontab line printed where there is no systemd is quoted for a shell rather than for systemd. A recipient holding a quote produced a line `sh` refused outright, and one holding a backslash was changed without saying so.
- - `rad backup --output ... schedule` is told that the flag belongs after the verb, instead of that `schedule` does not create an archive, which reads as a denial of a flag it plainly has.
- - Counts agree with their nouns in the shipped `restore.sh` and in `verify --deep` without git, so no line reads "1 repositories".
- A `following` row with no alias no longer fails the whole read of the node database.
- Write and parse errors name the file they are about.
- An archive encrypted to recipients now says which key to pass when none of the given identities open it, instead of blaming a passphrase it never asked for.
- Pasting section 1 of `RESTORE.md` over a home that already holds a key now refuses instead of warning and then overwriting the identity on the next line.
- `restore.sh` inside an archive no longer tells the reader to check policies that a tier without them never carried.
- The refusal over an oversized manifest names a remedy that exists: `--repos` selects a category, and never could cover "part of the home".
- A restore writes the secret key, the public key and `config.json` beside their targets and renames them into place. A crash or a full disk part way through used to leave a home holding neither the old identity nor the new one, because the old file was unlinked before the first byte of the new one was written.
- `restore` checks again that the node is not running immediately before it writes, not only before it reads the archive: unpacking a large archive leaves time for a node to start in between.
- Reading a node database that has a write-ahead log beside it creates a `-shm` file in the home, and the run now says so. It was reported as nothing at all, because the recording sat behind a writable-connection fallback that a write-ahead log never reaches. That fallback is gone: it could not run, and could not have helped.
- A node database that cannot be read names itself, instead of surfacing as a bare `unable to open database file` from whichever query happened to run first.
- An archive whose manifest will not parse names the archive, instead of surfacing as serde's own `expected value at line 1 column 1` with no file attached.
- `--stop-node` asks for the archive passphrase before it stops the node, not while the node is down waiting for somebody to find it.
- The `diff --json` report names moved repositories by rid, like every other field in it. It named them by display name, so the one list a consumer would act on was the one it could not look anything up with.
- The manifest records the hostname on macOS and the BSDs, which have neither `/etc/hostname` nor `HOSTNAME` and so recorded nothing at all.

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
