# The archive format, version 1

This document is the specification. It exists so that another program, or a person with a shell, can read an archive without this one. That is a promise the project makes rather than a side effect: an archive readable only by the program that wrote it is a bet on that program still existing when you need it.

## Layers

```
<file> = age( zstd( tar( entries ) ) )     when encrypted
<file> =      zstd( tar( entries ) )       when written with --plaintext
```

- **age**: [age](https://age-encryption.org) v1, either an `scrypt` recipient (a passphrase) or one or more `X25519`/`ssh` recipients (`--recipient`). The file begins with the ASCII bytes `age-encryption.org/`, which is how a reader decides whether to decrypt rather than trusting the file name.
- **zstd**: a standard zstd stream, level 10.
- **tar**: a GNU tar stream. Entries are regular files only; no directories, symlinks, hardlinks or device nodes are ever written, and a reader must not create any. Every header carries `uid=0`, `gid=0` and `mtime=0` so that two archives of an unchanged home are byte-identical, which is what lets restic and borg deduplicate them.

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

The manifest is written after every other entry, so the digests in it describe what was actually written rather than what was intended. A reader that streams the archive therefore learns what it should have seen only at the end, which is the correct order for verification: read everything, hash as you go, compare at the close.

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
    "did": "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
    "nodeId": "z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
    "alias": "maninak",
    "publicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... radicle",
    "fingerprint": "SHA256:tAXFyTXI8xtDaujAEcwJslAYc9/6FKcUkd2Lw0xDhPo",
    "keyEncrypted": true
  },
  "source": {
    "host": "hades",
    "radHome": "/home/maninak/.radicle",
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
      "rid": "rad:z2NrpBPWc7T9yStKMbCfEr4Wt5PYN",
      "name": "notes",
      "visibility": "private",
      "delegate": true,
      "delegates": ["did:key:z6MkiTBz1ymu..."],
      "scope": "all",
      "policy": "allow",
      "head": "refs/namespaces/z6MkiTBz1ymu.../refs/heads/master",
      "refs": 2,
      "sigrefs": { "z6MkiTBz1ymu...": "e1ad198be4cede66d76015a0291e13288871464d" },
      "otherSeeds": 4,
      "bundle": { "path": "repos/z2Nrp....bundle", "bytes": 726, "sha256": "ba4048a8..." }
    }
  ],
  "policies": { "seeded": 16, "blockedRepos": 0, "followed": 3, "blockedPeers": 0 },
  "warnings": []
}
```

Fields that carry weight:

- **`entries[].sha256`** is over the entry's bytes as stored, uncompressed and unencrypted. It is the whole of verification: an entry listed but absent, an entry present but unlisted, a length that disagrees or a digest that disagrees are all errors.
- **`repos[].sigrefs`** maps a peer's node id to the object its `refs/rad/sigrefs` pointed at when the archive was taken. This is what makes a restore safe rather than merely complete: comparing it with what the network holds is how divergence is detected before anyone pushes on top of it.
- **`repos[].bundle`** is absent when the repository was described but not carried, which is how a `state` archive keeps an inventory without the data.
- **`repos[].visibility`** of `private` or `local` means the repository exists nowhere but the machine that wrote the archive.
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

rid=z2NrpBPWc7T9yStKMbCfEr4Wt5PYN
git init --bare ~/.radicle/storage/$rid
git --git-dir ~/.radicle/storage/$rid fetch --force repos/$rid.bundle 'refs/*:refs/*'
git --git-dir ~/.radicle/storage/$rid symbolic-ref HEAD "$(jq -r '.repos[]|select(.rid|endswith("'$rid'")).head' manifest.json)"
```

`restore.sh` inside the archive does exactly this, for every repository, and checks the digests first. Drop `age -d` for a plaintext archive.

## Compatibility rules

- **`format` is a single integer.** A reader must refuse an archive whose `format` is greater than the one it knows, and say so in those words rather than failing obscurely halfway through.
- **New entries may be added** in a future version 1 archive. A reader must ignore an entry it does not recognise rather than treating it as corruption; the manifest is what decides whether the archive is complete.
- **Entry paths never change meaning.** If what belongs at `node/policies.db` ever stops being a policy database, it gets a new path and the format version goes up.
- **The plaintext recovery path never goes away.** Any change that would make an archive unreadable without this tool is out of scope for the project, not merely a breaking change.

## Version history

| Version | Released | Changes |
|---|---|---|
| 1 | unreleased | The format described here. |
