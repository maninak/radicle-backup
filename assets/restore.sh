#!/bin/sh
#
# Restore a Radicle home from the extracted contents of a rad-backup archive.
#
# Run it from the directory this file is in, after extracting the archive. It needs only
# `git`, `cp` and a POSIX shell; `jq` is used when present and skipped when not.
#
# This script exists so that an archive can be restored by someone who does not have
# rad-backup, or cannot run it. `rad-backup restore` does the same and additionally checks
# your restored repositories against the network, which this script cannot do.

set -eu

RAD_HOME="${RAD_HOME:-$HOME/.radicle}"

if [ ! -f manifest.json ]; then
	echo "run this from the directory the archive was extracted into" >&2
	exit 1
fi

if [ -f "$RAD_HOME/keys/radicle" ]; then
	echo "$RAD_HOME already holds an identity; move it aside first" >&2
	exit 1
fi

echo "restoring into $RAD_HOME"
mkdir -p "$RAD_HOME/keys" "$RAD_HOME/node" "$RAD_HOME/storage"

# The identity. Permissions are set before the bytes land, not after, so the key is never
# briefly readable by anyone else.
(umask 077 && cp keys/radicle "$RAD_HOME/keys/radicle")
cp keys/radicle.pub "$RAD_HOME/keys/radicle.pub"
chmod 644 "$RAD_HOME/keys/radicle.pub"
cp config.json "$RAD_HOME/config.json"

[ -f node/policies.db ] && cp node/policies.db "$RAD_HOME/node/policies.db"
[ -f node/notifications.db ] && cp node/notifications.db "$RAD_HOME/node/notifications.db"
[ -f node/node.db ] && cp node/node.db "$RAD_HOME/node/node.db"

restored=0
for bundle in repos/*.bundle; do
	[ -e "$bundle" ] || break
	rid=$(basename "$bundle" .bundle)
	target="$RAD_HOME/storage/$rid"

	git init --bare --quiet "$target"
	git --git-dir "$target" fetch --quiet --force "$(pwd)/$bundle" 'refs/*:refs/*'
	[ -f "repos/$rid.config" ] && cp "repos/$rid.config" "$target/config"

	if command -v jq >/dev/null 2>&1; then
		head=$(jq -r --arg rid "rad:$rid" \
			'.repos[] | select(.rid==$rid) | .head // empty' manifest.json)
		[ -n "$head" ] && git --git-dir "$target" symbolic-ref HEAD "$head"
	fi

	restored=$((restored + 1))
done

echo "restored the identity, its policies and $restored repositories"
echo
echo "before writing to any restored repository, fetch what the network has:"
echo "    rad sync <rid> --fetch"
echo "building on refs that are behind the network's forks your own history."
echo
echo "and never run two nodes with this key at once."
