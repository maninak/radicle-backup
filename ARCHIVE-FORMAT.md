# The archive format, version 1

This document is the specification: enough for another program, or a person with a shell, to read an archive without this one.

## Layers

```
<file> = age( zstd( tar( entries ) ) )     when encrypted
<file> =      zstd( tar( entries ) )       when written with --plaintext
```

- **age**: [age](https://age-encryption.org) v1, either an `scrypt` recipient (a passphrase) or one or more `X25519`/`ssh` recipients (`--recipient`). The file begins with the ASCII bytes `age-encryption.org/`, which is how a reader decides whether to decrypt rather than trusting the file name.
- **zstd**: a standard zstd stream, level 10.
- **tar**: a GNU tar stream. Entries are regular files only; no directories, symlinks, hardlinks or device nodes are ever written, and a reader must not create any, because a symlink or a device node in a hostile archive is how extraction escapes the directory it was pointed at or reaches into the system. Every header carries `uid=0`, `gid=0` and `mtime=0`, so an entry's bytes do not depend on who wrote it or when. The archive as a whole still differs between runs: `manifest.json` carries the creation time, and encryption adds a fresh salt.

Nothing in the format depends on a `rad` version. An archive written next to Radicle 1.10 restores next to Radicle 2.x, because it carries the files and the git objects rather than a serialisation of anyone's internal types.

## Entries

| Path | Mode | Present when |
|---|---|---|
| `keys/radicle` | `0600` | Always. The private key, byte for byte as it was on disk, keeping whatever passphrase it had. |
| `keys/radicle.pub` | `0644` | Always. |
| `config.json` | `0644` | The home had one. |
| `policies.json` | `0644` | Tier `state` or `full`. Seeding and following policies as readable JSON, so a future Radicle whose schema has moved on can still be told what to seed. |
| `aliases.json` | `0644` | Tier `state` or `full`. Peer aliases this node had learned. |
| `node/policies.db` | `0600` | Tier `state` or `full`, and the file exists. A consistent snapshot, taken through SQLite's online backup API rather than copied. |
| `node/notifications.db` | `0600` | Tier `state` or `full`, and the file exists. |
| `node/node.db` | `0600` | `--with-node-db`. The routing table and address book, which a node otherwise rebuilds from gossip. |
| `repos/<rid>.bundle` | `0600` | The repository was selected. A `git bundle` of every ref, including `refs/namespaces/*`, and HEAD. |
| `repos/<rid>.config` | `0644` | That repository had a git config. |
| `RESTORE.md` | `0644` | Always. |
| `restore.sh` | `0755` | Always. |
| `manifest.json` | `0644` | Always, and always **last**. |

`<rid>` is the repository identifier without its `rad:` prefix.

The manifest is written after every other entry, so the digests in it describe what was actually written rather than what was intended. A streaming reader learns the expected digests only at the end: hash as you go, compare at the close.

## `manifest.json`

Keys are camelCase. Unknown keys must be ignored, and unknown values of `tier` and `repoSelection` must parse as "unknown" rather than failing the whole file: a version 1 reader must survive a version 1 writer that learned a new word.

```json
{
  "format": 1,
  "tool": { "name": "rad-backup", "version": "0.1.0" },
  "created": "2026-08-14T16:56:09Z",
  "tier": "state",
  "repoSelection": "private",
  "identity": {
    "did": "did:key:z6Mk<nid>",
    "nodeId": "z6Mk<nid>",
    "alias": "alice",
    "publicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... radicle",
    "fingerprint": "SHA256:<fingerprint>",
    "keyEncrypted": true
  },
  "source": {
    "host": "workstation",
    "radHome": "/home/alice/.radicle",
    "radVersion": "rad 1.10.1 (71f39fb195068d598d75f7cd606d41a4f8ad4b10)",
    "gitVersion": "git version 2.43.0",
    "os": "linux"
  },
  "node": { "wasRunning": false, "stoppedByBackup": false },
  "entries": [
    { "path": "keys/radicle", "bytes": 444, "sha256": "f6709082cff5a587..." }
  ],
  "repos": [
    {
      "rid": "rad:z<rid>",
      "name": "notes",
      "visibility": "private",
      "allowed": ["did:key:z6Mk<peer>"],
      "delegate": true,
      "delegates": ["did:key:z6Mk<nid>"],
      "scope": "all",
      "policy": "allow",
      "head": "refs/namespaces/z6Mk<nid>/refs/heads/master",
      "refs": 2,
      "sigrefs": { "z6Mk<nid>": "e1ad198b..." },
      "otherSeeds": 4,
      "bundle": { "path": "repos/z<rid>.bundle", "bytes": 726, "sha256": "ba4048a8..." }
    }
  ],
  "policies": { "seeded": 16, "blockedRepos": 0, "followed": 3, "blockedPeers": 0 },
  "warnings": []
}
```

Fields that carry weight:

- **`entries[].sha256`** is over the entry's bytes as stored, uncompressed and unencrypted. It is the whole of verification: an entry listed but absent, an entry present but unlisted, a length that disagrees or a digest that disagrees are all errors.
- **`repos[].sigrefs`** maps a peer's node id to the object its `refs/rad/sigrefs` pointed at when the archive was taken. Comparing it with what the network holds is how a restore detects divergence before anyone pushes on top of it.
- **`repos[].bundle`** is absent when the repository was described but not carried, which is how a `state` archive keeps an inventory without the data.
- **`repos[].visibility`** is `public` or `private`, from the repository's identity document; a document with no `visibility` is public, as heartwood reads it. `private` means the open network does not carry it, and `repos[].allowed` lists the peers its owner allowed to hold a copy. That list being empty is what makes a repository unrecoverable without this archive.
- **`identity.keyEncrypted`** says whether the archived key has a passphrase of its own. When it is `false`, the archive's own encryption is the only thing protecting the identity.
- **`node.wasRunning`** records that storage was read while a node could write to it. The databases are still consistent (they are snapshotted, not copied), but a repository fetched during the run may be missing its newest refs.

## Reading one by hand

```sh
age -d archive.tar.zst.age | zstd -dc | tar -tv        # what is in it
age -d archive.tar.zst.age | zstd -dc | tar -xO manifest.json | jq .

age -d archive.tar.zst.age | zstd -dc | tar -x         # all of it
install -m 600 keys/radicle ~/.radicle/keys/radicle
install -m 644 keys/radicle.pub ~/.radicle/keys/radicle.pub
install -m 644 config.json ~/.radicle/config.json
install -m 600 node/policies.db ~/.radicle/node/policies.db

rid=z<rid>
git init --bare ~/.radicle/storage/$rid
git --git-dir ~/.radicle/storage/$rid -c fetch.fsckObjects=true fetch --force repos/$rid.bundle 'refs/*:refs/*'
git --git-dir ~/.radicle/storage/$rid symbolic-ref HEAD "$(jq -r '.repos[]|select(.rid|endswith("'$rid'")).head' manifest.json)"
```

`fetch.fsckObjects` because a bundle is the one part of an archive that nothing else validates, and one can carry a tree entry named `.git` or `..`. `restore.sh` inside the archive runs this loop for every repository. It does not check digests: compare `sha256sum` output against the manifest by hand, or use `rad-backup verify`. Drop `age -d` for a plaintext archive.

## Compatibility rules

- **`format` is a single integer.** A reader must refuse an archive whose `format` is greater than the one it knows, and say so in those words, because a newer format may change what an entry means, and a half-understood restore is worse than a refused one.
- **New entries may be added** in a future version 1 archive. A reader must ignore an entry it does not recognise rather than treating it as corruption; the manifest is what decides whether the archive is complete.
- **Entry paths never change meaning.** If what belongs at `node/policies.db` ever stops being a policy database, it gets a new path and the format version goes up.
- **The plaintext recovery path never goes away.** Any change that would make an archive unreadable without this tool is out of scope.

## Version history

| Version | Released | Changes |
|---|---|---|
| 1 | 0.1.0 | The format described here. |
