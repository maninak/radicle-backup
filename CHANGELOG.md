# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses [semantic versioning](https://semver.org/spec/v2.0.0.html). The archive format has its own version, tracked in `ARCHIVE-FORMAT.md`.

## [0.2.0] - 2026-08-21

### Added

- `doctor` now warns when another machine may still be holding your key. Restoring an ordinary backup leaves the key on the machine the backup came from, and two machines running one key fork your own history. `rad backup move` retires the old key, so a home moved here is fine. The check is called `key copies`, and it can only answer for a home restored by this version or later.
- `doctor` now names the public repositories with changes no other node has yet, so you can see what a dead disk would take with it. The check is called `signed refs propagation`.
- `schedule --recipient` and `schedule --plaintext`: a scheduled backup can encrypt to an age or ssh key, or skip encryption when the destination already encrypts. Neither needs a passphrase file.

### Changed

- `doctor`'s `seeding elsewhere` check is now called `other seeds`, so the name reads the same whether the check passes or fails. If you match on topic names in `--json`, this one changed.

### Fixed

- A crash or a full disk partway through a restore can no longer leave a home holding neither the old identity nor the new one. The key files and `config.json` are written beside their targets and renamed into place.
- `restore` no longer gives up on the whole home because one repository failed. The rest are restored, the failures are named, and the run exits `3`.
- A repository whose restore fails partway no longer leaves an empty repository behind, which later backups would have counted as real.
- `restore` without `git` on PATH now says how many repositories it could not put back, instead of reporting success.
- `restore` checks that the node is still stopped immediately before it writes, not only before it reads the archive. Unpacking a large archive leaves plenty of time for a node to start.
- `restore --force` over another identity now keeps the public half of the displaced key beside the private half it files away. Only the private half survived before; the public half can be recomputed from it, so nothing was ever lost.
- `restore --replay-policies` no longer throws away what `rad` said about each policy. A seeding or following decision that did not go back is named, and the run exits `3`. A restore that put back every repository and not one policy used to exit `0` in silence.
- The copy-paste block in `RESTORE.md` that puts your identity back now refuses to run over a home that already holds a key. It used to print a warning and overwrite the key on the next line.
- `restore.sh` inside an archive no longer claims to have restored policies that its tier never carried.
- A backup no longer fails after the archive is already written. A `.README.txt` that could not be placed beside it, or old archives that could not be pruned, are warnings now instead of an exit `1` over a good archive.
- A repository `git` cannot read no longer stops the whole backup. It is named, carried into the manifest with no refs, and the archive is written and marked incomplete (exit `3`).
- A repository whose visibility `rad` could not report is now treated as private and named in a warning. It used to be taken for public, which left it out of `--repos private`.
- A followed peer with no alias no longer fails the backup's read of the policies database.
- `--stop-node` asks for the archive passphrase before it stops the node, not while the node is down waiting for somebody to find it.
- `--stop-node` now reports when `rad node stop` itself failed, and gives up at once instead of waiting out the whole timeout on a node that was never going to stop.
- The refusal over a home too large for one archive now suggests `--repos private` or `--repos mine`, which do narrow what is carried. It used to suggest splitting the home across several `--repos` runs, which the flag cannot do.
- `diff` against an archive taken with `--repos all` or `--repos seeded` no longer reports every repository that is not your own as gone, on every run. It exits `0` when nothing has changed, so a scheduled `diff` can decide whether tonight's backup is needed.
- `doctor` no longer says an unencrypted archive holds your private key in the clear when the key inside carries its own passphrase. It now says the archive can be read by anyone who holds it, which is true either way.
- `doctor`'s remedy for an unprotected key names the key's real path, instead of `$RAD_HOME/keys/radicle`, which was not a runnable command for anyone who never set `RAD_HOME`.
- `verify --deep` without `git` on PATH says how many bundles it could not open, instead of passing.
- The warnings about a repository `rad` could not describe or `git` could not read no longer promise it a place in the archive when the run was never going to carry it.
- Output a machine consumes (JSON reports, listings, recovery sheets) now fails the run when it cannot be written, instead of exiting `0` over a truncated report. A pipe closed on purpose, as `... | head` does, still counts as success.
- `--dry-run --json` prints a JSON report, like every other `--json`, instead of the human-readable table.
- `create --stdout --json` is refused, instead of writing the archive and the report into the same stream.
- `diff --json` names moved repositories by rid, like every other list in the report, instead of by display name.
- `schedule` no longer accepts a `RAD_BACKUP_PASSPHRASE` exported in your shell as proof that the timer can get a passphrase, because systemd starts the service from its own environment. One that systemd itself holds still counts, so a working timer is not refused.
- A binary or output path containing a space now produces a unit systemd can run and a crontab line a shell can run.
- A recipient holding a character systemd or a shell treats specially (a `$` or `%`, a quote, a backslash) now reaches the scheduled run exactly as you typed it, in both the systemd unit and the printed crontab line.
- `schedule --status` says when systemd could not be asked at all, as over ssh to a headless machine, instead of reporting a running timer as `disabled`.
- The marker lines in a generated systemd unit now say what is true: a unit that keeps them is rewritten by the next `schedule` run, and deleting them is what preserves a hand edit. The environment file, which every run rewrites in full, no longer carries the marker.
- A flag typed before its verb, as in `rad backup --tier full create`, now gets a message saying where the flag belongs, instead of an error that reads as if the flag does not exist.
- Failing to open a recipient-encrypted archive points at `--identity` and the kind of key it was encrypted to, instead of blaming a passphrase that was never involved.
- Write and parse errors name the file they are about.
- A node database that cannot be read is named in the error, instead of a bare `unable to open database file` with no path.
- An archive whose manifest will not parse is named in the error, instead of a bare `expected value at line 1 column 1` with no file attached.
- Reading a node database that has a write-ahead log beside it leaves a `-shm` file in the home, and the run now says so instead of staying silent.
- The manifest records the hostname on macOS and the BSDs, which have neither `/etc/hostname` nor `HOSTNAME` and so recorded nothing at all.
- Counts agree with their nouns, so no line reads "1 repositories".

### Security

- `paper` without `--output` no longer writes the sheet to a path taken from `RAD_BACKUP_DIR`. A recovery sheet carries the secret key, and could land unasked where backups go, which is often a directory synced off the machine.
- A `head` in the manifest is refused unless it really names a ref, rather than being handed to `git symbolic-ref`. A value like `-d` would otherwise reach git as one of its own flags, and `git symbolic-ref` stores whatever it is given without checking, so a value like `refs/../../evil` would write a file next to the repository the next time anything updated that ref. Both `restore` and the shipped `restore.sh` check it now, and the repository still comes back, without its `HEAD`.
- `restore --replay-policies` skips a seeding or following row whose identifier `rad` would read as a flag, and names what it skipped. Those values come out of the archive, and nothing had vouched for them before they reached a command line.
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
