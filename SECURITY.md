# Security

## Reporting a vulnerability

Email **security@radicle.tools**, or open a [private security advisory](https://github.com/maninak/radicle-backup/security/advisories/new) on GitHub. Please do not open a public issue for anything that would let someone else read a key.

Expect an acknowledgement within 72 hours and an assessment within a week. If a fix is warranted it ships as a patch release with an advisory naming you, unless you would rather not be named.

## How to audit this

This program holds an ed25519 key that cannot be rotated, revoked or reissued. Everything that touches a secret lives in the files below: the first five are the core, and the last two are the recovery paths that also hold raw key material and must keep the same `Zeroizing` discipline.

| Read this | To satisfy yourself that |
|---|---|
| `src/key.rs` | The key is parsed, decrypted and re-encrypted in memory only, and every buffer holding seed or passphrase bytes is a `Zeroizing` one. |
| `src/crypt.rs` | Archives are age, the passphrase comes from three places only, an empty one is refused, and a wrong one is told apart from a damaged file. |
| `src/perms.rs` | "Owner only" is defined once, applied at creation rather than after it, and admits out loud when a platform cannot promise it. |
| `src/exec.rs` | Nothing is run through a shell, and no child process inherits a passphrase it has no use for. |
| `src/archive.rs` | An archive from anywhere is hostile input: no absolute paths, no `..`, regular files only, every entry digested against the manifest in both directions. |
| `src/cmd/paper.rs` | The recovery sheet is the key in the clear: the mnemonic, the key file, and the HTML that carries them are all `Zeroizing`, and the one untrusted field (the alias) is HTML-escaped. |
| `src/cmd/restore.rs` (`from_words`) | The 24 words typed to rebuild an identity arrive on a `Zeroizing` line and stay in `Zeroizing` buffers through to the key file, written at `0600`. |

Four invariants those files exist to hold:

- Anything that could hold key material is **created** at `0600`, and working directories at `0700`, rather than chmodded afterwards: a key that is briefly world-readable has already been read. Windows has no mode bits, and the program says so the first time it writes such a file.
- A passphrase is never in `argv`, never in a log, and never in a child process's environment. `RAD_PASSPHRASE` reaches `rad` alone, because `rad` is the only thing that signs with the key.
- The one socket this program opens itself is the node's local control socket, which it uses to ask whether the node is running. Everything else goes through `rad`: the `rad sync` a restore runs to compare what it restored with the network, and the `rad node stop` and `rad node start` a restore or a move needs. No telemetry, no update check, no upload.
- `unsafe` is forbidden crate-wide, `unwrap` is a denied lint, and CI fails on either.

Two checks to run:

```sh
just repro                              # build it twice, get one binary
./packaging/release/verify.sh <dir>     # what you downloaded is what was signed
```

Then read `ARCHIVE-FORMAT.md` and open an archive with nothing but `age`, `zstd` and `tar`.

## What it does not protect against

- **A machine that is already compromised.** If something can read `~/.radicle/keys/radicle`, it does not need this tool.
- **A passphrase you lose.** No recovery, no escrow, no backdoor. Print a sheet with `rad backup paper`.
- **A paper sheet with `--words` on it.** Those 24 words are the key, in the clear. Anyone holding that sheet is you.
- **Where you put the archive.** An encrypted archive on a hostile server is fine; a `--plaintext` one is not, and `doctor` keeps saying so.

## Supported versions

The newest release. Older ones get fixes only if a report explains why the newest cannot be adopted.
