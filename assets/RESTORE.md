# Restoring this Radicle home by hand

This archive was written by `rad-backup` on {{CREATED}}, from `{{RAD_HOME}}` on `{{HOST}}`.
It holds the identity `{{ALIAS}}` (`{{DID}}`).

You do not need `rad-backup` to restore it. The archive is a plain tar of plain files, and everything below uses `git` and a POSIX shell. `jq` is used to read `manifest.json` and `policies.json`; where it appears, you can read those files by eye instead.

## 1. Put the identity back

```sh
export RAD_HOME="${RAD_HOME:-$HOME/.radicle}"

# Stop if a key is already there. Overwriting one ends whatever identity it belongs to.
[ -e "$RAD_HOME/keys/radicle" ] && echo "a key is already there; move it aside first"

mkdir -p "$RAD_HOME/keys" "$RAD_HOME/node"

# The umask so the key is never briefly world-readable, and the chmod because a umask
# applies only when cp creates the file: over an existing 0644 file it does nothing.
(umask 077 && cp keys/radicle "$RAD_HOME/keys/radicle")
chmod 600 "$RAD_HOME/keys/radicle"
cp keys/radicle.pub "$RAD_HOME/keys/radicle.pub"
chmod 644 "$RAD_HOME/keys/radicle.pub"

# config.json is absent from an identity-tier archive, and from a home that never had one.
[ -f config.json ] && cp config.json "$RAD_HOME/config.json"
```

That is the whole identity. The key file is still protected by whatever passphrase it had when the archive was made.

Check that it is the right one:

```sh
ssh-keygen -l -f "$RAD_HOME/keys/radicle.pub"
# expect: {{FINGERPRINT}}
```

## 2. Put the policies back

`policies.db` holds every repository you seed, every peer you follow, and everything you blocked.

```sh
# Both are absent from an identity-tier archive, hence the guards.
[ -f node/policies.db ] && cp node/policies.db "$RAD_HOME/node/policies.db"
[ -f node/notifications.db ] && cp node/notifications.db "$RAD_HOME/node/notifications.db"
```

If that database refuses to open because Radicle has moved on to a newer schema, use `policies.json` instead, which is the same content as text. Every line of it maps to one command:

```sh
# seeded repositories
jq -r '.seeding[] | select(.policy=="allow") | "rad seed \(.rid) --scope \(.scope)"' policies.json
# blocked repositories
jq -r '.seeding[] | select(.policy=="block") | "rad block \(.rid)"' policies.json
# followed peers
jq -r '.following[] | select(.policy=="allow") | "rad follow \(.nid)"' policies.json
# blocked peers
jq -r '.following[] | select(.policy=="block") | "rad block \(.nid)"' policies.json
```

Read that output, then run it.

## 3. Put the repositories back

Each repository is one git bundle holding every ref, every peer's namespace and their signed refs.

```sh
for bundle in repos/*.bundle; do
  rid=$(basename "$bundle" .bundle)
  git init --bare --quiet "$RAD_HOME/storage/$rid"
  # --force because the refs come from the bundle, not from a merge; fsckObjects because
  # nothing else validates a bundle's objects, and one can name a path like `.git` or `..`.
  git --git-dir "$RAD_HOME/storage/$rid" -c fetch.fsckObjects=true \
    fetch --quiet --force "$PWD/$bundle" 'refs/*:refs/*'
  cp "repos/$rid.config" "$RAD_HOME/storage/$rid/config" 2>/dev/null || true
  head=$(jq -r --arg rid "rad:$rid" '.repos[] | select(.rid==$rid) | .head // empty' manifest.json)
  [ -n "$head" ] && git --git-dir "$RAD_HOME/storage/$rid" symbolic-ref HEAD "$head"
done
```

`restore.sh`, next to this file, is the same procedure with error handling. It takes the target home as its argument (`sh restore.sh ~/.radicle`), falling back to `$RAD_HOME` and then `$HOME/.radicle`, and refuses to run against a home that already holds a key.

## 4. Before you write anything to a restored repository

Read this part. It is the one way a restore can cost you something.

Your own refs in each repository are signed as a chain. If this archive is older than what the network has, and you commit or push on top of it, you sign a second, conflicting history for yourself. Other nodes see that as a fork of your identity, and it does not resolve itself.

So, for every repository you restored and intend to write to:

```sh
rad sync <rid> --fetch     # get what the network has
```

If the fetch brings in newer refs of your own, keep those and not the archived ones. `rad-backup restore` does this comparison for you and refuses to continue when the two histories have diverged.

## 5. One node, one key

Never run two nodes with this key at the same time. They will both sign refs, and they will disagree. If the machine this archive came from is still running its node, stop it before you start the restored one.

## What is in here

| Path | What it is |
|---|---|
| `manifest.json` | What this archive holds, and the SHA-256 of every entry |
| `keys/radicle` | The private key. The only irreplaceable thing here |
| `keys/radicle.pub` | The public key |
| `config.json` | Alias, preferred seeds, connect list, limits |
| `policies.json` | Seeds, follows and blocks as text |
| `node/policies.db` | The same, as the database Radicle reads |
| `node/notifications.db` | Inbox read state |
| `aliases.json` | The names peers announced for themselves |
| `repos/*.bundle` | One git bundle per repository, all refs included |
| `repos/*.config` | Each repository's git config |
| `node/node.db` | Routing table and address book, only if it was asked for |

Verify any entry against the manifest:

```sh
sha256sum keys/radicle
jq -r '.entries[] | select(.path=="keys/radicle") | .sha256' manifest.json
```
