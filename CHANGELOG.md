# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses [semantic versioning](https://semver.org/spec/v2.0.0.html). The archive format has its own version, tracked in `ARCHIVE-FORMAT.md`.

## [Unreleased]

### Added

- `--identity-passphrase-file` and `RAD_BACKUP_IDENTITY_PASSPHRASE`, for the passphrase on a `--identity` key. It is a different secret from the archive's, so it has its own flag and its own variable, and `--help` says which is which.

### Fixed

- A passphrase-protected ssh key now opens an archive encrypted to it. It never had: no prompt appeared, and the run said the key did not open the archive, which was false and is the worst thing to tell someone in the middle of a recovery. `--recipient <ssh pubkey>` is what the README recommends for an unattended timer, and a passphrase on that key is the normal state of an ssh key, so the flow the tool recommends could not be completed with the tool. A key that stayed locked, a key with the wrong passphrase, a key age cannot use, and a key the archive was simply not encrypted to are now four different messages.
- The note written beside a recipient-encrypted archive gave a command that cannot open it. It printed `age -d <file>`, which asks for a passphrase that such an archive does not have, and the `rad-backup` lines beside it left out `--identity`. It now names the keys the archive was encrypted to, and how to give one.
- That same note offered a command that would have destroyed the archive it sits beside. `age -d -i <key file> archive.tar.zst.age` is not a template to a shell: `<key` redirects input, and `>archive.tar.zst.age` truncates the archive to nothing. It now says `KEYFILE`, and no command the note offers carries a redirect.
- A key age cannot read no longer ends a run that has a usable key beside it. Passing every key in `~/.ssh` is ordinary, and one `id_ecdsa` next to the right `id_ed25519` refused the whole restore. Unusable keys are now named as a footnote on the failure that follows, and only a run with no usable key at all stops.
- A key that failed to unlock is now named on its own. The message used to list every key a passphrase had been supplied for, so a key that unlocked perfectly well appeared as part of the fault, and it blamed the passphrase for a failure that is equally a key type age cannot use. It now names the one key, says both possibilities, and says which keys were never reached.
- `doctor` now reads the archive rather than its own record of the last run. It reported "no archive has ever been taken for this identity" at machines with working nightly backups, because the timer runs as another user or the home came back through `restore.sh`, and it called an archive encrypted when the newest one on disk was written with `--plaintext`.
- `doctor` now says whether the newest archive can still be opened, trying the key given with `--identity` against it. An archive whose key is gone was reported as a working backup.
- `doctor`'s `key copies` check no longer passes a home it knows nothing about. `sudo rad-backup restore` writes its record into root's state directory and `restore.sh` writes none at all, so the two people most likely to be holding a second copy of their key were the ones told they were not.
- `rad backup move --keep-source` no longer writes an archive claiming the source machine retires its key. The home restored from it was told the machine it came from was safe, which is the exact fork this tool exists to prevent, announced as a pass.

- Whether a node is running is now answered from the socket `rad` itself would use, and a socket that could not be asked is no longer read as a stopped node. `RAD_SOCKET` was ignored, so a node started under it was invisible, and a permission error on the socket answered "stopped" about a node that was up. `restore` and `move` refuse rather than guess, and a backup that cannot tell says so in the archive instead of recording that the node was down.
- A restore no longer reports seeding and following policies an identity-tier archive never carried. The numbers came from the manifest, which is filled at every tier, rather than from the database that was installed, and the next `diff` then blamed the difference as drift.
- A repository the network could not be asked about is now told apart from one there is nothing to compare with. Three private repositories, which are announced to nobody by design, were reported as "3 of 3 could not be compared" and the reader was sent to run a command that fails every time.
- `schedule` no longer overwrites a unit file it cannot read. A hand-written unit saved unreadable, or holding bytes that are not UTF-8, was the one file the "not written by this tool" check could not see, and it was overwritten with a note saying it had been written.
- `ls` now reads whether an archive is encrypted from the file rather than from its name. `rad backup --stdout > name.tar.zst` writes an encrypted archive under a name that says otherwise, and the listing told its owner it could be read by anyone.
- A repository whose `packed-refs` cannot be read is now named rather than treated as somebody else's. With `rad` also unavailable, `--repos mine` wrote an archive missing it and exited 0.
- A home whose key is there and cannot be looked at is no longer treated as an empty home. `restore --force` and `words --restore` both decided on `is_file()`, which is false for an unreadable directory as well as for an absent key.
- `doctor` no longer reports "the node has no record of what any other node holds" when the node database is there and will not open.
- A dry run now says when part of storage could not be measured. The estimate is meant to run high, and an unreadable directory silently counted as zero was the one thing making it run low.

### Changed

- `restore --json` renames one standing. `not checked` is now `nothing to compare it with` or `could not be compared`, which are different answers with different fixes.
- `doctor --backup-dir` is now `doctor --dir`, matching `ls` and `prune`, and it is now where the checks actually look rather than a path printed in a remedy. `--backup-dir` still works.

## [0.2.1] - 2026-08-22

### Fixed

- `nix build` works again. The flake runs the test suite as part of the build, and one test needs `jq` to read a manifest the way the shipped script does, which the build environment did not have, so v0.2.0 would not build from the flake at all.
- The `restore.sh` inside an archive refuses the same `HEAD` values `rad backup` refuses. It used to let through a few that git itself rejects, such as a name whose component starts with a dot or ends in `.lock`, so the two readers of one archive could put back different things.
- The `restore.sh` inside an archive says when `jq` is missing, instead of putting every repository back without its `HEAD` and saying nothing about it.

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
