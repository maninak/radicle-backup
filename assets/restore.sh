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

# `-e` and `-L`, not `-f`: a dangling symlink at the key's name is not a file, so `-f` alone
# walked straight past one and the `cp` below then followed it and wrote the private key to
# whatever it pointed at, outside the home and at whatever permissions that path had.
if [ -e "$RAD_HOME/keys/radicle" ] || [ -L "$RAD_HOME/keys/radicle" ]; then
	echo "$RAD_HOME already holds an identity; move it aside first" >&2
	exit 1
fi

# The same hazard at every other name this writes. `cp` follows a symlink at its destination,
# so a home seeded with one is a home that redirects an archive's contents somewhere else, and
# a `config.json` pointing at a file this user can write is enough. Refused rather than
# unlinked: this script never destroys anything in a home it did not put there.
for name in keys/radicle.pub config.json node/policies.db node/notifications.db node/node.db; do
	if [ -L "$RAD_HOME/$name" ]; then
		echo "$RAD_HOME/$name is a symlink, so restoring would write through it;" \
			"move it aside first" >&2
		exit 1
	fi
done

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

# Whether there is anything for the next block to be about. An identity-only archive carries
# no bundles, and a warning about "the repositories below" followed by none of them describes
# a risk this run is not taking.
bundles=""
for bundle in repos/*.bundle; do
	[ -e "$bundle" ] || break
	bundles=yes
	break
done

# Said once, before the first bundle is opened, and for the same reason `rad-backup restore`
# says it: the `fetch.fsckObjects` below reaches a bundle only from git 2.46. An older git
# accepts the setting and never consults it on this path, so the objects go into storage
# unchecked and a run that says nothing looks exactly like one that checked them.
#
# The first word that starts with a digit, rather than a pattern over the whole line, because
# what follows the number is the distribution's to choose: `2.51.0.windows.1` and
# `2.39.5 (Apple Git-154)` are both out there.
git_said=$(git --version 2>/dev/null || true)
git_version=""
for word in $git_said; do
	case "$word" in
	[0-9]*)
		git_version=$word
		break
		;;
	esac
done
# A number with no dot in it is not a version this can read: `${v#*.}` hands back the whole
# value when there is nothing to strip, so a bare `2` would otherwise read as major 2 minor 2
# and be warned about, where `rad-backup` says it could not tell.
git_major=""
git_minor=""
if [ "$git_version" != "${git_version#*.}" ]; then
	git_major=${git_version%%.*}
	git_minor=${git_version#*.}
	git_minor=${git_minor%%.*}
fi
case "$git_major:$git_minor" in
[0-9]*:[0-9]*)
	if [ -n "$bundles" ] && { [ "$git_major" -lt 2 ] ||
		{ [ "$git_major" -eq 2 ] && [ "$git_minor" -lt 46 ]; }; }; then
		echo "this git does not check the objects inside a bundle it fetches from, so the" >&2
		echo "repositories below are written without that check; git 2.46 or newer runs it" >&2
	fi
	;;
*)
	# Git printing nothing at all is git not being installed, and the failure this script
	# then dies of says that far better than a sentence about what a bundle was checked for.
	if [ -n "$bundles" ] && [ -n "$git_said" ]; then
		echo "the version of git could not be read, so it is not known whether the objects" >&2
		echo "inside each bundle were checked on the way in" >&2
	fi
	;;
esac

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

	if ! command -v jq >/dev/null 2>&1; then
		echo "jq is not installed, so $rid came back without its HEAD" >&2
	else
		head=$(jq -r --arg rid "rad:$rid" \
			'.repos[] | select(.rid==$rid) | .head // empty' manifest.json)
		# `symbolic-ref` takes no `--`, so a manifest saying `head: "-d"` would reach git
		# as a flag rather than as a branch, and it stores whatever it is handed without
		# checking, so `refs/../../evil` would later write a file outside the repository.
		# The same set `rad-backup` refuses, checked again here for the same reason the
		# id above is: this script runs when `rad-backup` is not there, and both readers
		# of an archive have to put the same thing back. A `refs/` prefix, and no
		# component that is empty, starts with a dot, ends in `.lock`, or holds a
		# character git forbids in a refname.
		case "$head" in
		'') ;;
		*[[:cntrl:]]* | *..* | */.* | *//* | */ | *.lock | *.lock/* \
		| *' '* | *'~'* | *'^'* | *':'* | *'?'* | *'*'* | *'['* | *\\*)
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
