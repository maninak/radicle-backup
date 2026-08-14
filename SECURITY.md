# Security

## Reporting a vulnerability

Email **info@radicle.tools**, or open a [private security advisory](https://github.com/maninak/radicle-backup/security/advisories/new) on GitHub. Please do not open a public issue for anything that would let someone else read a key.

Expect an acknowledgement within 72 hours and an assessment within a week. If a fix is warranted it ships as a patch release with an advisory naming you, unless you would rather not be named.

## What this program handles

Everything here exists because this tool touches an ed25519 private key that cannot be rotated, revoked or reissued. Losing it ends an identity; leaking it hands that identity to somebody else, permanently.

**Files it writes.** Anything that has held or could hold key material is created with mode `0600` at the moment of creation, never chmodded afterwards, because a private key that is briefly world-readable has already been read. On a platform with no mode bits, Windows above all, that promise cannot be kept: the file inherits the permissions of the folder it lands in, and the program says so out loud the first time it writes one rather than letting you assume otherwise. Working directories are `0700`. An archive being written lands under a `.partial` name and is renamed only when it is complete, so an interrupted run cannot leave something that looks like a usable backup. Scratch directories are removed when the command ends, including on failure, and say so loudly if removal fails.

**Encryption.** Archives are encrypted by default with [age](https://age-encryption.org): scrypt for a passphrase, X25519 or ssh recipients for `--recipient`. `--plaintext` is available, announces itself, and fails a `doctor` check for as long as such an archive is the newest one. The private key inside keeps whatever protection it already had; nothing here weakens it.

**Passphrases** are read from a file, an environment variable or a hidden prompt, in that order, and are held in `Zeroizing`/`secrecy` wrappers so they are wiped when dropped. They are never passed as command-line arguments, which would put them in the process table, and never written to a log.

**Untrusted archives.** An archive is data from wherever it was stored, which may not be where it was written. Reading one never trusts it: entry paths that are absolute or contain `..` are refused before anything is written; entries are unpacked as regular files only, so a symlink or hardlink entry cannot be created and cannot be written through; every entry is digested and compared with the manifest, in both directions, before a restore installs anything; and an archive claiming a newer format version is refused rather than read partially. Restores stage into a temporary directory and are checked there, so a bad archive cannot leave a half-built home.

**Subprocesses.** `rad` and `git` are invoked with argument vectors, never through a shell, with `GIT_CONFIG_NOSYSTEM=1`, `GIT_TERMINAL_PROMPT=0` and `GIT_PAGER=cat`, so a repository or a system config cannot change what a run does.

**Network.** This program opens no sockets of its own. The only thing that touches the network is `rad sync`, invoked during a restore to compare restored repositories with what the network holds. There is no telemetry, no update check, and no upload of anything, ever.

**Unsafe code** is forbidden at the crate level (`unsafe_code = "forbid"`), and `unwrap` is a denied lint.

## What it deliberately does not protect against

- **A machine that is already compromised.** If something can read `~/.radicle/keys/radicle`, it does not need this tool, and no archive setting changes that.
- **A passphrase you lose.** There is no recovery, no escrow and no backdoor. The paper sheet (`rad backup paper`) exists precisely because this is unrecoverable.
- **A paper sheet with `--words` on it.** Those 24 words are the key, in the clear, by design. Anyone holding that sheet is you.
- **Where you put the archive.** An encrypted archive on a hostile server is fine; a `--plaintext` one is not, and the tool will keep saying so.

## Supported versions

The newest release. Older ones get fixes only if the newest release cannot be adopted for a reason a report explains.
