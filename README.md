# radicle-backup

[![Sponsor maninak on Liberapay](https://img.shields.io/badge/Liberapay-Donate-F6C915?logo=liberapay&logoColor=black)](https://liberapay.com/maninak/donate)

[![version](https://img.shields.io/github/v/release/maninak/radicle-backup?sort=semver&label=version&color=44CC11)](https://github.com/maninak/radicle-backup/releases/latest)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Rust](https://img.shields.io/badge/rust-000000.svg?logo=rust&logoColor=white)](./Cargo.toml)
[![radicle.tools artifact](https://img.shields.io/badge/radicle.tools-artifact-ff1aff?labelColor=15161c)](https://radicle.tools)

**Back up, restore and move a [Radicle](https://radicle.xyz) identity, node state and repositories. `rad backup`.**

A Radicle key cannot be reissued: lose it and nothing on the network can give back the ability to sign as yourself, push to your own repositories, or govern a repository you are the only delegate of. This tool writes that key, and everything around it that the network cannot restore, into one encrypted file.

```sh
rad backup                      # one encrypted archive of everything the network cannot replace
rad backup doctor               # what would you lose right now, and what fixes it
rad backup restore <archive>    # put it all back, on this machine or another one
```

Beyond copying files:

- The default archive carries what the network will not hand back and skips what it will: a public repository is on other nodes, a private one is by default nowhere else at all.
- `restore` compares every restored repository with the network before handing control back, because pushing on top of stale signed refs forks your own peer history.
- An archive is `tar` inside `zstd` inside optional `age`, with recovery instructions and a shell script inside it, so `tar`, `git` and a POSIX shell can restore it without this tool.
- `doctor` reports what would be lost right now and names the command that fixes each failing line.

## Install

### Debian, Ubuntu and derivatives

```sh
curl -fsSL https://apt.radicle.tools/pubkey.asc | sudo tee /etc/apt/keyrings/radicle-tools.asc > /dev/null
echo "deb [signed-by=/etc/apt/keyrings/radicle-tools.asc] https://apt.radicle.tools stable main" | sudo tee /etc/apt/sources.list.d/radicle-tools.list
sudo apt update && sudo apt install radicle-backup
```

Updates arrive through `apt upgrade` like anything else, and through `unattended-upgrades` if you enable this origin for it (see [Automatic updates](#automatic-updates)).

### Prebuilt binary

```sh
curl -fsSL https://github.com/maninak/radicle-backup/releases/latest/download/rad-backup-x86_64-unknown-linux-musl.tar.gz | tar -xz
sudo install -m 755 rad-backup-x86_64-unknown-linux-musl/rad-backup /usr/local/bin/
```

The Linux builds are statically linked against musl, so they run on any distribution and inside `scratch` containers. There are aarch64 builds for Linux and macOS as well as x86_64, a Windows `.zip`, and an x86_64 FreeBSD build that is cross-compiled and **untested**, because there is no FreeBSD runner to test it on; a report either way is welcome. Every release ships `sha256sums.txt` and a signature beside it, and `verify.sh` in the same release checks both.

### From source

```sh
cargo install radicle-backup
```

Needs Rust 1.88 or newer. `git` on `PATH` is required at runtime; `rad` is optional and only makes the archive better informed.

### As a `rad` subcommand

Any executable called `rad-<name>` on `PATH` becomes `rad <name>`. Installing this as `rad-backup` is what makes `rad backup` work, and every example below can be written either way. The package also installs a `rad-restore` symlink to the same binary, so `rad restore <archive>` works too.

### Tab completion

The Debian package and the Nix flake install completions for bash, fish and zsh already. Everywhere else, ask the binary for them:

```sh
rad-backup completions bash | sudo tee /etc/bash_completion.d/rad-backup > /dev/null
rad-backup completions zsh  > ~/.zfunc/_rad-backup        # with ~/.zfunc on $fpath
rad-backup completions fish > ~/.config/fish/completions/rad-backup.fish
```

Completion fires on `rad-backup <TAB>`, not on `rad backup <TAB>`: `rad` ships no completions of its own, so a shell has nothing to hand the subcommand off to.

## Usage

```sh
rad backup                              # the default: a state-tier archive in the working directory
rad backup --output ~/backups           # into a directory, named for the identity and the moment
rad backup --tier full                  # ...and every repository that is yours
rad backup --repos all --stop-node      # everything in storage, with the node stopped for it
rad backup --stdout | ssh backup-host 'cat > radicle.tar.zst.age'   # straight to somewhere else
rad backup --keep 7                     # delete this identity's older archives, keep the newest 7

rad backup --dry-run                    # what it would carry, and roughly how big, writing nothing
rad backup schedule --output ~/backups  # take one automatically on a systemd user timer

rad backup doctor                       # what you would lose right now
rad backup diff                         # has anything changed since the last archive?
rad backup ls                           # which archives exist, newest first
rad backup show                         # what is inside the newest one, without unpacking it
rad backup verify                       # do its bytes still match what it says they are
rad backup verify --deep <archive>      # ...and does it actually restore the identity it claims
rad backup restore <archive>            # put it back
rad backup move <output-path>           # move this identity to another machine, safely
rad backup paper                        # a printable recovery sheet, for the drawer
rad backup prune --keep 7               # delete the older ones, keeping the newest 7
```

**Every command that takes an archive can be given none**, and then acts on the newest archive of this identity it can find, saying on stderr which one that was. It looks in `RAD_BACKUP_DIR`, then wherever the last archive actually went, then the working directory. Naming a path is always allowed and always wins.

`doctor`, `diff`, `ls`, `show`, `verify` and `--dry-run` are the read-only verbs: none of them writes to your home, and none of them needs the node stopped. The one exception announces itself: a database that cannot be opened read-only is opened writable to recover its write-ahead log, and the run says so.

Every knob that is not a one-off is an environment variable, so a run is configured the way `rad` itself is. They are listed under [Configuration](#configuration).

### Example output

Taking the default archive of a home with four repositories, two of them private:

```
· reading policies and inventory
· archiving the identity
· archiving policies, aliases and inbox state
· bundling 2 repositories

✓ wrote ~/backups/alice-z6Mk<nid>-20260814T165609Z.tar.zst.age
  alice (did:key:z6Mk<nid>), 12 entries, 30.7 KiB of content
  tier state, repositories private (2 carried), policies 16 seeded / 3 followed

  check it: rad-backup verify ~/backups/alice-z6Mk<nid>-20260814T165609Z.tar.zst.age
```

The two private repositories were carried; the two public ones are on other nodes and were not. A plain-text note lands beside every archive as `<name>.README.txt`, saying what the file is and how to open it, for whoever finds it without this tool.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | It worked, and nothing needs your attention. |
| `1` | It failed: a file could not be read, a passphrase was wrong, an archive did not decrypt. |
| `2` | The arguments were wrong. Clap's own code. |
| `3` | Checks failed: `verify` found the archive incomplete, `doctor` has a failing line, `diff` found drift. |
| `4` | Refused. Everything is intact and nothing was written, because doing it would have been unsafe. |

Codes `3` and `4` are the ones worth scripting against: `rad backup diff || rad backup` takes an archive only when something changed.

## What gets backed up

Three tiers, each a superset of the one above it. The default is `state`.

| Tier | Carries | Size | For |
|---|---|---|---|
| `identity` | Keys and `config.json` | ~1 KiB | The absolute minimum. Everything else can be rebuilt from the network, slowly. |
| `state` *(default)* | ...plus seeding and following policies, aliases, inbox state, an inventory of every repository, and the data of any repository the network does not have | KiBs to MiBs | Daily use. |
| `full` | ...plus every repository that is yours | MiBs to GiBs | Leaving a machine, or being the only copy. |

`--repos` overrides what the tier implies: `none`, `private`, `mine`, `seeded`, `all`.

The archive itself is `tar` inside `zstd` inside optional `age`, and holds:

```
manifest.json                 what is in here, with a sha256 of every entry
keys/radicle                  the private key, byte for byte as it was on disk
keys/radicle.pub              the public key
config.json                   the node config
policies.json                 seeding and following policies, as readable JSON
aliases.json                  the peer aliases this node had learned
node/policies.db              the policy database itself, snapshotted consistently
node/notifications.db         inbox read state
repos/<rid>.bundle            a git bundle holding every ref of a repository
repos/<rid>.config            that repository's git config
RESTORE.md                    how to get all of this back without this tool
restore.sh                    a script that does it, needing only git and a POSIX shell
```

The manifest is written last, after every entry. `verify` reads it both directions: an entry that is listed but missing, and an entry that is present but unlisted, are both reported.

`node.db` (the routing table and address book) is excluded by default because a node rebuilds it from gossip within minutes; `--with-node-db` includes it. The COB cache is never archived, because it is rebuilt from the repositories that are.

## Encryption

An archive holds your private key, so by default it is encrypted with a passphrase you are asked for:

```sh
rad backup                                   # asks, twice, and never echoes
RAD_BACKUP_PASSPHRASE=... rad backup         # for cron
rad backup --passphrase-file ~/.secret       # the file's contents, minus any trailing newline
```

Or to a key rather than a passphrase, which is what you want when a machine takes its own backups and must not hold anything that can read them:

```sh
rad backup --recipient age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
rad backup --recipient ~/.ssh/id_ed25519.pub     # ssh keys work too
rad backup restore --identity ~/.ssh/id_ed25519 <archive>
```

`--plaintext` writes an unencrypted archive. It says so loudly, `doctor` fails a check while one is the newest archive, and it exists for the case where the archive is going straight into a store that encrypts it for you (restic, borg, an encrypted disk).

The private key inside keeps whatever protection it already had. If it had no passphrase of its own, the archive's encryption is the only thing standing between a copied file and your identity, and every command that notices says so.

## Restoring

```sh
rad backup restore ~/backups/alice-z6Mk<nid>-20260814T165609Z.tar.zst.age
```

```
· unpacking ~/backups/alice-z6Mk<nid>-20260814T165609Z.tar.zst.age
✓ the archive restores alice (did:key:z6Mk<nid>)
✓ installed the identity into ~/.radicle
· restoring 2 repositories
· comparing 2 repositories with the network

✓ restored alice into ~/.radicle
  2 repositories, 16 seeding and 3 following policies

  start the node with `rad node start`
```

Everything is unpacked into a staging directory first and every digest is checked before a single byte lands in the home, so a truncated or tampered archive cannot leave you with half an identity. Restoring into a home that already holds one is refused (exit `4`) unless you pass `--force`.

### The fork hazard, and what this does about it

Radicle signs a set of refs per peer. If you restore an archive taken before your last push, your storage now holds signed refs that are *behind* what the network already accepted. Push on top of them and you sign a second, conflicting history for your own peer id. Other nodes do not resolve that: they see your identity fork.

So after restoring, and before handing control back, every restored repository is fetched and compared:

| Standing | What it means | What happens |
|---|---|---|
| in step | Your signed refs match the network's | Nothing to do |
| the network was ahead | The network had newer refs, which are now yours | Fetched and taken; you are current |
| holds work the network has not seen | The archive is ahead, as after a crash | Kept; push when ready |
| diverged | Neither is an ancestor of the other | **Named, and the restore exits `3`** |

`--no-reconcile` skips all of this, for restoring on a machine with no network; fetch before you push.

### Restoring without this tool

If this program is gone, or does not run where you are:

```sh
age -d alice-....tar.zst.age | zstd -dc | tar -x     # or: zstd -dc ... | tar -x, if plaintext
cat RESTORE.md                                       # the whole procedure, in prose
sh restore.sh ~/.radicle                             # or just run it
```

`restore.sh` needs `git` and a POSIX shell. It uses `jq` when it is installed, to set each restored repository's `HEAD`, and skips that step when it is not. It takes the target home as its argument, falling back to `$RAD_HOME` and then to `$HOME/.radicle`, and refuses to run against a home that already holds an identity.

## `doctor`

```
recovery posture of /home/alice/.radicle

✓ key passphrase: the key is encrypted with aes256-ctr (bcrypt)
✗ backup: no archive has ever been taken for this identity
  --> rad backup
? archive encryption: there is no archive to judge
? archive location: no archive path was recorded, so this could not be judged
! private repositories: 3 of 3 are in no archive, though every one of those is allowed to a peer that could hold a copy
  --> rad backup --repos private
! delegate quorum: 6 repositories have you as their only delegate: example-app, example-tool, example-config, example-docs, example-site, example-lib
  --> a backup covers loss but not theft. Three delegates survive one lost key; two are worse than one, because both are still needed and there is twice the chance of losing one. Add one with `rad id edit`
✓ seeding elsewhere: every public repository is announced by at least one other node

2 pass, 2 worth improving, 1 failing, 2 could not be checked
  every ✗ is a way to lose this identity; the line under it is the fix
```

Seven checks. The left of each line names what was looked at and the right says what was found, so a line never argues with its own marker: `✓` passed, `!` is worth improving, `✗` is a way to lose the identity, `?` could not be looked at at all. A `-->` line is the command that fixes the one above it.

The line between a `!` and a `✗` is whether anything else holds a copy: a private repository in no archive fails when no other node has it and warns when its identity allows a peer that could, and an archive older than 30 days warns rather than fails.

`doctor --json` prints the same as structured data. It exits `3` when any check fails, which makes it a monitoring probe.

## `diff`

Answers "is the newest archive still current?" without a passphrase and without opening it, by comparing this tool's own record of what it wrote with what is in the home now.

```sh
rad backup diff || rad backup      # take a new archive only when something changed
```

It exits `0` when nothing has moved and `3` when something has: a new repository, one that is gone, one whose signed refs have moved on, or a policy change.

## Keeping the pile tidy

```sh
rad backup ls                       # every archive of this identity, newest first
rad backup prune --keep 7           # delete the rest, after showing you what goes
rad backup prune --keep 7 --dry-run # ...or just show it
```

Only files this tool named, for this identity, in that one directory are ever considered. Another identity's archives and anything else in the folder are not candidates for deletion, whatever `--keep` says. `--keep` on a backup run applies the same rule at the same moment the new archive lands.

## Moving to another machine

```sh
rad node stop
rad backup move ~/radicle-move.tar.zst.age
# ...copy the file across...
rad backup restore radicle-move.tar.zst.age      # on the new machine
```

`move` takes a `full` archive, verifies it deeply, and only then retires the key on this machine, renaming it to `keys/radicle.retired` and leaving a note beside it saying why. It is not deleted: a move that goes wrong halfway needs a way back.

The reason it retires anything at all: two nodes running the same key sign conflicting refs for the same peer, and the network sees your identity fork. `--keep-source` skips the retirement and warns you, in those words.

## Paper backups

```sh
rad backup paper --output sheet.html      # then open it in a browser and print it
rad backup paper --words --output sheet.html
```

A one-page sheet with your DID, your key's fingerprint, a QR code, and either the key file itself or the 24 words that rebuild it.

`--words` renders the key as a BIP-39 mnemonic, which survives a bad photocopy and can be typed back by a person who has nothing but the sheet:

```sh
rad backup restore --words
```

The sheet with `--words` on it *is* the key: it is not protected by anything, and anyone holding it is you. Store it the way you store cash. Without `--words` the sheet holds the key file as it is on disk, which is useless to a thief who does not also have your key passphrase, and useless to *you* if you forget it.

## Running it on a schedule

One command sets up a systemd user timer, writes the environment it needs, and turns it on:

```sh
rad backup schedule --output /mnt/backups/radicle --keep 14 \
                    --passphrase-file ~/.config/rad-backup/passphrase

rad backup schedule --status        # is it on, when does it next run, did the last one fail
rad backup schedule --off           # stop, leaving the unit files in place
rad backup schedule --every 'Mon,Thu 04:00'   # any systemd calendar expression
```

It refuses to enable a timer that cannot work: an unattended run has nobody to type a passphrase at, so a passphrase file (or `RAD_BACKUP_PASSPHRASE` in the timer's environment) is not optional. The timer is `Persistent=true`, so a laptop that was asleep at the appointed hour takes its backup when it wakes.

It writes `~/.config/systemd/user/rad-backup.{service,timer}` and the settings they read in `~/.config/rad-backup/env`. Edit either unit by hand and it stays yours: a unit file without this tool's marker line at the top is never replaced, and the run says so instead. The `env` file is rewritten by every `rad backup schedule` run, so a lasting settings change belongs on the command line that writes it. The package ships the same units under `/usr/lib/systemd/user`, disabled, for anyone who would rather wire it up with `systemctl --user` themselves.

Or with cron, if you prefer:

```sh
# every day at 03:17, keep the newest fortnight
17 3 * * * RAD_BACKUP_PASSPHRASE_FILE=$HOME/.config/rad-backup/passphrase rad-backup --output /mnt/backups/radicle --keep 14 --yes --quiet
```

Point either at a destination that does not die with this disk. A second disk or another machine is the obvious answer, but a directory that a sync client already carries off the machine (MEGA, Dropbox, Drive, Syncthing) counts too, even though it shares a filesystem with your home. `doctor` cannot tell those apart, so it warns when the archive is on the same filesystem and leaves the call to you.

### Automatic updates

The apt repository is signed and carries an `Origin` of `radicle-tools`, so `unattended-upgrades` can be pointed at it:

```
// /etc/apt/apt.conf.d/51unattended-upgrades-radicle
Unattended-Upgrade::Allowed-Origins {
    "radicle-tools:stable";
};
```

## Configuration

| Variable | Does |
|---|---|
| `RAD_HOME` | The Radicle home to work on. Same meaning as everywhere else in Radicle. `--home` overrides it. |
| `RAD_BACKUP_DIR` | Where archives go when `--output` is not given. |
| `RAD_BACKUP_PASSPHRASE` | The archive passphrase, so cron is not asked for one. |
| `RAD_BACKUP_PASSPHRASE_FILE` | The same, read from a file, which keeps it out of the process table. |
| `RAD_BACKUP_TIER` | The default tier: `identity`, `state` or `full`. |
| `RAD_BACKUP_KEEP` | Keep this many of this identity's archives in the output directory, deleting older ones. |
| `RAD_PASSPHRASE` | The *key's* passphrase. `paper --words` reads it to decrypt the key; `restore --words` reads it as the restored key's new passphrase. |
| `RAD` | The `rad` binary to call. |
| `GIT` | The `git` binary to call. |
| `NO_COLOR` | A non-empty value turns off colour, as does `--no-color` and a pipe. |
| `RAD_BACKUP_SCRATCH_DIR` | Where working files go: database snapshots, fresh bundles, and the staging copy a restore is checked in. Defaults to beside whatever the command is producing. |
| `XDG_STATE_HOME` | Where this tool remembers what it last wrote. Holds no secrets. |

## What this tool doesn't do

- **It is not a node backup for a public seed.** `--repos all` will happily archive twelve thousand repositories, and you will be happier with `btrfs send`, ZFS snapshots, or [radicle-seed-prune](https://app.radicle.at/nodes/seed.radicle.at/rad:zxvTkxzouwrYFwycnsctrMT3iM2E) and a filesystem-level tool.
- **It does not rotate keys.** Radicle has no key rotation to drive. A compromised key needs a new identity and a delegate change.
- **It does not talk to any service.** No telemetry, no upload, no phone home. Where the archive goes is entirely your business.
- **It does not make Windows a Radicle machine.** There is a Windows build, and it reads, checks and lists archives properly. What it cannot do is promise that a file it writes is readable only by you, because Windows has no mode bits and this tool carries no Windows API dependency to set an ACL; it says so the first time it writes such a file. Radicle itself is a unix program, so the home a backup describes lives on the Linux or macOS side, WSL included.

## Development

```sh
just check    # cargo fmt --check, then the lints, then the tests: what CI runs, in that order
```

The integration suite in `tests/` builds a Radicle home from a fixed mnemonic, takes real archives of it, restores them into a second home and compares the two byte for byte. It needs `git` and nothing else, so it runs anywhere the tool does.

Contributions are welcome as pull requests or as Radicle patches. `CONTRIBUTING.md` has the details, `ARCHIVE-FORMAT.md` specifies the format if you want to write another reader, and `SECURITY.md` says what to do about a vulnerability.

[How to audit this](SECURITY.md#how-to-audit-this) names the five files that touch a secret and what each one has to convince a reviewer of.

## Support

This repository on Radicle is [`rad:zwuwC3UnuVYy2tvG9dd11QCUbA7J`](https://app.radicle.at/nodes/seed.radicle.at/rad:zwuwC3UnuVYy2tvG9dd11QCUbA7J). Clone it with `rad clone rad:zwuwC3UnuVYy2tvG9dd11QCUbA7J`.

Issues live there: `rad issue open` in that clone, or the `#support` channel on the [Radicle Zulip](https://radicle.zulipchat.com).

If this tool is useful to you:

- 💛 Chip in on [Liberapay](https://liberapay.com/maninak/donate).
- 🌱 `rad seed rad:zwuwC3UnuVYy2tvG9dd11QCUbA7J` to keep a copy on the network, and ⭐ star it on [GitHub](https://github.com/maninak/radicle-backup).
- 🗣️ Tell someone who keeps only one copy of their Radicle home, or backs it up by hand. Or open an issue with any edge case you hit.

## License

MIT OR Apache-2.0, at your option. Bundle it, fork it, repackage it, vendor it into a distribution.

---

[![A radicle.tools artifact - homegrown apps and tools for Radicle](https://radicle.tools/badge/artifact.svg)](https://radicle.tools)
