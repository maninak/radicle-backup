#!/bin/sh
#
# Restore a Radicle home from the extracted contents of a rad-backup archive.
#
# Run it from the directory this file is in, after extracting the archive:
#
#     sh restore.sh [target-home]
#
# The target home defaults to $RAD_HOME, then to $HOME/.radicle. It needs `git` and a POSIX
# shell; `jq` is used when present and skipped when not.
#
# This script exists so that an archive can be restored by someone who does not have
# rad-backup, or cannot run it. `rad-backup restore` does the same and additionally checks
# your restored repositories against the network, which this script cannot do.

set -eu

RAD_HOME="${1:-${RAD_HOME:-$HOME/.radicle}}"

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
# Guarded like the databases below: an identity-tier archive, or a home that never had a
# config, legitimately has no config.json, and under `set -e` a bare cp aborted the restore
# after the key had landed and before any repository did.
[ -f config.json ] && cp config.json "$RAD_HOME/config.json"

[ -f node/policies.db ] && cp node/policies.db "$RAD_HOME/node/policies.db"
[ -f node/notifications.db ] && cp node/notifications.db "$RAD_HOME/node/notifications.db"
[ -f node/node.db ] && cp node/node.db "$RAD_HOME/node/node.db"

restored=0
for bundle in repos/*.bundle; do
	[ -e "$bundle" ] || break
	rid=$(basename "$bundle" .bundle)
	# A real id is base58 and nothing else. `rad-backup` refuses an archive whose manifest
	# says otherwise, and this script is what runs when `rad-backup` is not there. Today the
	# glob above already keeps `..` out, because a leading dot does not match `*`; this says
	# so on purpose, so that reading ids from manifest.json instead, the way HEAD is read
	# below, cannot quietly drop it.
	case "$rid" in
	'' | *[!A-Za-z0-9]*)
		echo "skipping $bundle: '$rid' is not a repository id" >&2
		continue
		;;
	esac
	target="$RAD_HOME/storage/$rid"

	git init --bare --quiet "$target"
	# fsckObjects, matching what `rad-backup restore` does: a bundle is the one part of
	# an archive nothing else validates, and one can carry a tree entry named `.git`.
	git --git-dir "$target" -c fetch.fsckObjects=true \
		fetch --quiet --force "$(pwd)/$bundle" 'refs/*:refs/*'
	[ -f "repos/$rid.config" ] && cp "repos/$rid.config" "$target/config"

	if command -v jq >/dev/null 2>&1; then
		head=$(jq -r --arg rid "rad:$rid" \
			'.repos[] | select(.rid==$rid) | .head // empty' manifest.json)
		# `symbolic-ref` takes no `--`, so a manifest saying `head: "-d"` would reach git
		# as a flag rather than as a branch, and it stores whatever it is handed without
		# checking, so `refs/../../evil` would later write a file outside the repository.
		# The same check `rad-backup` makes, here for the same reason the id above is
		# checked: this script runs when it is not there.
		case "$head" in
		'') ;;
		*..*|*//*|*/|*' '*|*'~'*|*'^'*|*':'*|*'?'*|*'*'*|*'['*|*'\'*)
			echo "skipping HEAD for $rid: '$head' does not name a ref" >&2 ;;
		refs/?*) git --git-dir "$target" symbolic-ref HEAD "$head" ;;
		*) echo "skipping HEAD for $rid: '$head' does not name a ref" >&2 ;;
		esac
	fi

	restored=$((restored + 1))
done

case "$restored" in
1) counted="1 repository" ;;
*) counted="$restored repositories" ;;
esac
if [ -f node/policies.db ]; then
	echo "restored the identity, its policies and $counted"
else
	echo "restored the identity and $counted; this archive carried no policies"
fi
echo
echo "before writing to any restored repository, fetch what the network has:"
echo "    rad sync <rid> --fetch"
echo "writing on top of refs the network has already moved past forks your own history."
echo
echo "and never run two nodes with this key at once."
