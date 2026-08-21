# Security

## Reporting a vulnerability

Email **security@radicle.tools**, or open a [private security advisory](https://github.com/maninak/radicle-backup/security/advisories/new) on GitHub. Please do not open a public issue for anything that would let someone else read a key.

Expect an acknowledgement within 72 hours and an assessment within a week. If a fix is warranted it ships as a patch release with an advisory naming you, unless you would rather not be named.

## How to audit this

This program holds an ed25519 key that cannot be rotated, revoked or reissued. Everything that touches a secret lives in the files below: the first five are the core, the next two are the recovery paths that also hold raw key material and must keep the same `Zeroizing` discipline, and the last two are where a value out of an archive nobody has vouched for is checked before it reaches a command line.

| Read this | To satisfy yourself that |
|---|---|
| `src/key.rs` | The key is parsed, decrypted and re-encrypted in memory only, and every buffer holding seed or passphrase bytes is a `Zeroizing` one. |
| `src/crypt.rs` | Archives are age, the passphrase comes from three places only, an empty one is refused, and a wrong one is told apart from a damaged file. |
| `src/perms.rs` | "Owner only" is defined once, applied at creation rather than after it, and admits out loud when a platform cannot promise it. |
| `src/exec.rs` | Nothing is run through a shell, and no child process inherits a passphrase it has no use for. |
| `src/container.rs` | An archive from anywhere is hostile input: no absolute paths, no `..`, regular files only, no repository id that would not stay a single directory under `storage/`, and every entry digested against the manifest in both directions. |
| `src/cmd/paper.rs` | The recovery sheet is the key in the clear: the mnemonic, the key file, and the HTML that carries them are all `Zeroizing`, and the one untrusted field (the alias) is HTML-escaped. |
| `src/cmd/words.rs` | The 24 words typed to rebuild an identity arrive on a `Zeroizing` line and stay in `Zeroizing` buffers through to the key file, written at `0600`. |
| `src/rad.rs` | An identifier taken from an archive is base58 and nothing else before it reaches `rad`, so a repository or node id out of a manifest cannot arrive in an argv position reading as a flag. |
| `src/git.rs` | A `HEAD` taken from an archive names a ref before it reaches `git symbolic-ref`, which accepts no `--` and stores what it is handed without checking it, so neither a value read as a flag nor one that climbs out of the repository gets through. |

Four invariants those files exist to hold:

- Anything that could hold key material is **created** at `0600`, and working directories at `0700`, rather than chmodded afterwards: a key that is briefly world-readable has already been read. Windows has no mode bits, and the program says so the first time it writes such a file.
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
