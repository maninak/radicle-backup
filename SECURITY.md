# Security

## Reporting a vulnerability

Email **security@radicle.tools**, or open a [private security advisory](https://github.com/maninak/radicle-backup/security/advisories/new) on GitHub. Please do not open a public issue for anything that would let someone else read a key.

Expect an acknowledgement within 72 hours and an assessment within a week. If a fix is warranted it ships as a patch release with an advisory naming you, unless you would rather not be named.

## How to audit this

This program holds an ed25519 key that cannot be rotated, revoked or reissued. Everything that touches a secret is either in the table below or named in this paragraph. The first five rows are the core. The next three are where a verb decides whether a secret is asked for at all, and hand the asking itself to `src/crypt.rs`. The two after those are the recovery paths that also hold raw key material and must keep the same `Zeroizing` discipline, the two after those are where a value out of an archive nobody has vouched for is checked before it reaches a command line, and the last is about the home being written into rather than about what is written. Three verbs are left off on purpose: `src/cmd/restore.rs`, `src/cmd/verify.rs` and `src/cmd/show.rs` hold an archive passphrase only for the call that carries it from `read_archive_passphrase` in `src/cmd/mod.rs` to `Reader::open` in `src/container.rs`, and decide nothing about it. One function in the first of those is the exception and is worth reading anyway: `retire_any_displaced_key` is the only place outside this table that moves a live private key, and it renames rather than deletes, confirms by name, and leaves a note saying what it did.

| Read this | To satisfy yourself that |
|---|---|
| `src/key.rs` | The key is parsed, decrypted and re-encrypted in memory only, and every buffer holding seed or passphrase bytes is a `Zeroizing` one. |
| `src/crypt.rs` | Archives are age, each passphrase comes from three places only and knows which of the three secrets it protects, an empty one is refused, and a wrong one is told apart from a damaged file and from a key that stayed locked. |
| `src/perms.rs` | "Owner only" is defined once, applied at creation rather than after it, and admits out loud when a platform cannot promise it. |
| `src/exec.rs` | Nothing is run through a shell, and no child process inherits a passphrase it has no use for. The list of secrets to scrub is walked through a `match`, so a new one cannot be added without the compiler asking where it goes. |
| `src/container.rs` | An archive from anywhere is hostile input: no absolute paths, no `..`, regular files only, no repository id that would not stay a single directory under `storage/`, and every entry digested against the manifest in both directions. |
| `src/cmd/mod.rs` | Every verb that opens an archive asks for its passphrase through `read_archive_passphrase`, which asks only when the archive header says one sealed it, and `Ctx::identities` is the one place the `--identity` key files and whether there is a terminal to prompt on are gathered before `src/crypt.rs` tries them. |
| `src/cmd/backup/mod.rs` | `ask_encryption` writes a plaintext archive only when `--plaintext` was given, and warns when it does; a passphrase that seals a new archive is read for `Sealing`, so it is typed twice. |
| `src/cmd/doctor.rs` | `check_archive_encryption` never prompts: a passphrase archive is judged from its header without being opened, and the `--identity` keys are tried with `is_interactive` forced off, so a key that stays locked is reported as a question the check could not put rather than as a failure or a prompt on a timer. `check_key_protection` reads the key file to say whether it is encrypted and never decrypts it. |
| `src/cmd/paper.rs` | The recovery sheet is the key in the clear: the mnemonic, the key file, the escaped HTML and the QR SVG are each built once, at their exact final size, in a `Zeroizing` buffer that is never regrown, and the one untrusted field (the alias) is HTML-escaped. The exception is inside the `qrcode` crate, which is not reachable from here without `unsafe` or a fork: its module matrix, encoder buffers and the renderer's growing `String` hold copies of the drawing that decode back to the key, and none of them is wiped. |
| `src/cmd/words.rs` | The 24 words typed to rebuild an identity arrive on a `Zeroizing` line and stay in `Zeroizing` buffers through to the key file, written at `0600`. |
| `src/rad.rs` | An identifier taken from an archive is base58 and nothing else before it reaches `rad`, so a repository or node id out of a manifest cannot arrive in an argv position reading as a flag. |
| `src/git.rs` | A `HEAD` taken from an archive names a ref before it reaches `git symbolic-ref`, which accepts no `--` and stores what it is handed without checking it, so neither a value read as a flag nor one that climbs out of the repository gets through. |
| `src/home.rs` | `directories_that_point_elsewhere` answers whether a symlink stands at `keys`, `node` or `storage`, the three directories a restore fills. Everything that writes follows a link at a directory, so a `keys` aimed at a directory somebody else owns is how a private key leaves the home it was restored into. |

Five invariants those files exist to hold:

- Anything that could hold key material is **created** at `0600`, and working directories at `0700`, rather than chmodded afterwards: a key that is briefly world-readable has already been read. Windows has no mode bits, and the program says so the first time it writes such a file.
- A restore writes nothing through a link at a **directory**. `keys`, `node` and `storage` are asked before the first write, again once the archive is unpacked, and again before the repositories go in; a repository's own directory inside `storage` is asked for as well, and each is refused rather than followed, because a directory this program did not make is not one it may replace. At a **file** it writes, the link is replaced instead: `write_atomically` unlinks the name and creates it afresh at `0600` or `0644`, so nothing is written through it either. The `assets/restore.sh` that rides inside every archive asks a wider question, refusing the leaf names outright, because a shell script's `cp` has no unlink to fall back on.
- A passphrase is never in `argv`, never in a log, and never in a child process's environment. `RAD_PASSPHRASE` reaches `rad` alone, because `rad` is the only thing that signs with the key.
- The one socket this program opens itself is the node's local control socket, which it uses to ask whether the node is running. Everything else goes through `rad`: the `rad sync` a restore runs to compare what it restored with the network, and the `rad node stop` and `rad node start` a restore or a `--stop-node` backup needs. A move stops no node: it refuses to run while one is up, and says so. No telemetry, no update check, no upload.
- `unsafe` is forbidden crate-wide, `unwrap` is a denied lint, and CI fails on either.

Two checks to run:

```sh
just repro                              # build it twice, get one binary
./packaging/release/verify.sh <dir>     # what you downloaded is what was signed
```

Run the second one from a `rad clone`, not from the copy beside the download: it trusts the `allowed_signers` next to itself.

Then read `ARCHIVE-FORMAT.md` and open an archive with nothing but `age`, `zstd` and `tar`.

## What it does not protect against

- **A machine that is already compromised.** If something can read `~/.radicle/keys/radicle`, it does not need this tool.
- **A passphrase you lose.** No recovery, no escrow, no backdoor. Print a sheet with `rad backup paper`.
- **A paper sheet with `--words` on it.** Those 24 words are the key, in the clear. Anyone holding that sheet is you.
- **Where you put the archive.** An encrypted archive on a hostile server is fine; a `--plaintext` one is not, and `doctor` keeps saying so.

## Supported versions

The newest release. Older ones get fixes only if a report explains why the newest cannot be adopted.
