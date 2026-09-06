# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses [semantic versioning](https://semver.org/spec/v2.0.0.html). The archive format has its own version, tracked in `ARCHIVE-FORMAT.md`.

## [Unreleased]

### Added

- `--identity-passphrase-file` and `RAD_BACKUP_IDENTITY_PASSPHRASE`, for the passphrase on a `--identity` key. It is a different secret from the archive's, so it has its own flag and its own variable, and `--help` says which is which.
- A `--recipient` run now names, in its own output, the key the archive will need to be opened. Until now only the note beside the archive said so, and that note is read in the middle of a recovery: the run is the last moment somebody is still in a position to go and check they have the private half.

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
- `restore` compares a private repository with the network again when anybody else can hold it. Private means announced to nobody, not unreachable: `rad sync --fetch` goes to a private repository's delegates and allowed peers, so one shared with a collaborator was exactly the case the sigrefs check was skipped for, and skipping it is how a restored copy forks its own peer history. Only a private repository delegated to you alone and allowed to nobody is left uncompared now.
- `doctor` no longer fails an archive whose key is sitting right there with a passphrase on it. A passphrase-protected ssh key is the state this tool recommends, and "the key never came unlocked" was reported as "the key does not open this archive": a red line every night, and an exit 3 with it. It is now an unknown that says how to unlock the key, and the check never prompts, whatever the run around it is doing.
- `doctor` no longer stops outright when heartwood renames a column in the node database. A renamed table was already tolerated; a renamed column aborted the whole report.
- `doctor`'s `signed refs propagation` check now says when it could not describe every repository. Without a `rad` on PATH no repository looks private, so private ones were counted as public and the remedy told you to announce them.
- An archive taken while the control socket could not be reached now says so, rather than recording that a node was running as though it had been seen. The far end says "could not tell" instead of telling somebody their identity is being double-signed, and `--stop-node` names the socket it could not ask instead of blaming the node for not stopping.
- An archive that could not be read is no longer reported as unencrypted. Only a file too short to hold an age header answers that question; an unreadable one now says so.
- A refusal about a running node names the socket when `RAD_SOCKET` chose it. Restoring into `--home /tmp/other` with one exported for your main node said "the node is running against the home being restored into", about a node serving a different home entirely.
- The warning a restore prints about a node it could not ask no longer has a hole punched through the middle of it. A line continuation was missing from the message, so twenty-two spaces were printed inside the sentence.
- `prune` now says when the note beside an archive would not go. The archive was deleted and the note describing it stayed, and the error saying why was dropped, so the directory kept a description of something it no longer held and nobody was told.
- `prune --dir` and `doctor --dir` now say in `--help` and in `man rad-backup` that they read `RAD_BACKUP_DIR`. They always did, but only `ls --dir` was documented as doing so, so a reader of the other two entries concluded the variable was ignored there.
- A restore no longer reports that your peer history has forked because `git` could not answer. `git merge-base --is-ancestor` exits 128 over an oid it cannot resolve or an object it cannot read, and that was folded into "not an ancestor"; asked both ways round, two of those made the divergence verdict, which is the most alarming thing this tool says and it was said on the strength of an error nobody read. Such a repository now reports that it could not be compared.
- A restore into a home with no key no longer goes ahead without asking. Occupancy was decided on `keys/radicle` alone, so a home whose key `move` retired, or whose key was deleted, counted as empty while still holding every repository, and the restore rewound all of their refs with a `--force` fetch, other peers' namespaces included. It now names what is there and refuses without `--force`.
- The signed-ref oids in a manifest are checked before they reach `git`, and a manifest whose node id is not the key it carries is refused. `merge-base` takes no `--`, so a value out of an archive nobody vouched for could be read as one of its own flags; and a node id that disagreed with the key made every repository come back "nothing to compare", so a restore exited 0 having compared nothing.
- `doctor` no longer says an archive "is not there now" without looking. `rad backup --output /backups/mine.tar.zst.age` writes a name the listing does not recognise, so one report called an archive gone while its own `archive location` line said it was there.
- `doctor`'s private repository coverage says whose word it is taking. It reads the state record, which is hearsay about a file this run may never have seen, and it was printing "all N of them are in the newest archive" as a pass in the same report whose freshness line said that archive was missing.
- `doctor` no longer counts a repository it could not describe as public. Both the `other seeds` and the `signed refs propagation` checks tested `!is_private()`, which is true for a record whose identity document was never read, so a home with no `rad` on PATH was told to `rad sync --announce` repositories that may well be private.
- A private repository somebody else delegates is no longer reported as being in no archive and on no other node. A second delegate holds it by definition, which the restore's own fetch gate already counted on and this check did not.
- `rad backup` no longer fails outright when heartwood renames a table in the node database. Only one of the three readers tolerated that; the other two aborted the whole run with an sqlite error. Every reader now answers "not known" and says which table has moved on, in the run's output and in the archive's own warnings.
- `ls`, `prune`, `--keep` and the default archive now see an archive that is a symlink, and refuse to act on a directory holding an archive of this identity they could not examine, instead of listing it as 0 B or leaving it out.
- A state file that is there and cannot be read is no longer reported as one that was never written. `doctor` said "this tool has no record of one anywhere" about a record sitting right there, and a permission error on it aborted the whole report.
- `--stop-node` no longer leaves the node down after a stop it could not confirm. When the control socket cannot be reached, no poll can see the node go down, and the run recorded that it had stopped nothing, so it put nothing back and told the user to go and stop a node that may already have been stopped.
- `schedule --status` recognises a timer that systemd reports as `enabled-runtime`. It was compared against the exact word `enabled`, so the owner of a live timer was told no backup was scheduled on the machine.
- A key that stayed locked, or one age could not use, exits 1 rather than 4. Exit 4 means the run stopped because going on would have been unsafe, so a script reading it as "refused, safe to retry" looped on a typo. It is the same code a wrong archive passphrase already used.
- `doctor` no longer answers an empty node table with "start the node" when the node is running and the table is one this build cannot read. Both causes arrive as the same empty map, the warning naming the file was already printed below, and the remedy above it was sending people to start a node that was already up.
- A relative `--output` is written into the state record as the path it resolves to, not as it was typed. `rad backup --output backups/nightly.tar.zst` left `doctor`, `ls` and `diff` looking for `backups/nightly.tar.zst` under whatever directory they were run from, and reporting the archive missing.
- `paper` no longer leaves plaintext copies of the key on the heap while escaping it and rendering its QR code. The sheet it prints is byte for byte the same.

### Changed

- `restore` compares a repository against what other nodes have announced they hold of your signed refs, instead of against your own storage. It was reading back what it had just written: `rad sync <rid> --fetch` over a repository already in storage is a pull, and heartwood's pull deliberately ignores the local peer's key, so the refs read back were always the archive's own. Every restore reported every repository "in step with the network", which is the one answer that means "safe to write", on a comparison of a value with itself. The standings `the network was ahead` and `diverged` are gone, because neither can be established this way: a node holding refs signed with your key that this copy does not have is now reported as `another node holds signed refs this copy does not have`, and it still exits `3`. `in step with the network` is gone for the same reason and is now `no other node has reported holding anything else`: heartwood rewrites its record of a peer only when that peer announces a different head, so disagreement announces itself and agreement is silent, and the report now says so out loud instead of reading silence as a pass. Only a row some node wrote more than an hour after the archive was taken counts as evidence (the hour is heartwood's own tolerance for a peer's clock running ahead, and the row carries that peer's clock, not ours), because a restored home's node database is the archive's own and every row in it agrees with the archive by construction: read as evidence, that is the archive compared with itself a second time. The run now waits up to twenty seconds after the fetches for other nodes to say what they hold, ending the moment every repository has an answer: a refs announcement is a separate message from the fetch, and reading the table microseconds later found nothing on a network that was working fine. `restore --json` renames the `diverged` array to `atRisk` and gains `ahead`, the repositories holding work some node has never seen, which used to be visible only by parsing the standing strings.
- `restore --json` renames one standing. `not checked` is now `nothing to compare it with` or `could not be compared`, which are different answers with different fixes.
- `ls --json` can now report `"encrypted": null`, for an archive whose first bytes could not be read. It was always `true` or `false`, and one of them was a guess.
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
