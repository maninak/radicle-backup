#!/bin/sh
#
# Restore a Radicle home from the extracted contents of a rad-backup archive.
#
# Run it from the directory this file is in, after extracting the archive:
#
#     sh restore.sh [target-home]
#
# The target home defaults to $RAD_HOME, then to $HOME/.radicle. It needs `git` and a POSIX
# shell, and uses `jq` when present to restore each repository's HEAD.
#
# `rad-backup restore` does the same and also checks your restored repositories against the
# network, which this script cannot do.

set -eu

RAD_HOME="${1:-${RAD_HOME:-$HOME/.radicle}}"

if [ ! -f manifest.json ]; then
	echo "run this from the directory the archive was extracted into" >&2
	exit 1
fi

# `-L` as well, because a dangling symlink at the key's name fails `-e`, and the `cp` below
# would follow it and write the private key outside the home
if [ -e "$RAD_HOME/keys/radicle" ] || [ -L "$RAD_HOME/keys/radicle" ]; then
	echo "$RAD_HOME already holds an identity; move it aside first" >&2
	exit 1
fi

# `cp` and `mkdir -p` follow a symlink, so a link at any name this writes would redirect the
# archive, private key included, outside the home. A link is refused and never removed.
# `$RAD_HOME` itself may be a link, because pointing it at another disk is deliberate.
for name in keys node storage keys/radicle.pub config.json \
	node/policies.db node/notifications.db node/node.db; do
	if [ -L "$RAD_HOME/$name" ]; then
		echo "$RAD_HOME/$name is a symlink, so restoring would write through it;" \
			"move it aside first" >&2
		exit 1
	fi
done

echo "restoring into $RAD_HOME"
mkdir -p "$RAD_HOME/keys" "$RAD_HOME/node" "$RAD_HOME/storage"

# The identity. The umask applies before the bytes land, so the key is never readable by
# anyone else.
(umask 077 && cp keys/radicle "$RAD_HOME/keys/radicle")
cp keys/radicle.pub "$RAD_HOME/keys/radicle.pub"
chmod 644 "$RAD_HOME/keys/radicle.pub"
# An archive may carry no config.json, and under `set -e` a bare `cp` would abort the
# restore after the key had landed
[ -f config.json ] && cp config.json "$RAD_HOME/config.json"

[ -f node/policies.db ] && cp node/policies.db "$RAD_HOME/node/policies.db"
[ -f node/notifications.db ] && cp node/notifications.db "$RAD_HOME/node/notifications.db"
[ -f node/node.db ] && cp node/node.db "$RAD_HOME/node/node.db"

# Whether the archive carries any repositories, so an identity-only restore skips the git
# warning below
bundles=""
for bundle in repos/*.bundle; do
	[ -e "$bundle" ] || break
	bundles=yes
	break
done

# The `fetch.fsckObjects` below reaches a bundle only from git 2.46. An older git ignores it
# and stores the objects unchecked, so this warns once, as `rad-backup restore` does.
#
# The version is the first word starting with a digit, because distributions append their own
# tails (`2.51.0.windows.1`, `2.39.5 (Apple Git-154)`).
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
# A number with no dot is unreadable, because `${v#*.}` returns the whole value when there is
# nothing to strip and a bare `2` would read as 2.2
git_major=""
git_minor=""
if [ "$git_version" != "${git_version#*.}" ]; then
	git_major=${git_version%%.*}
	git_minor=${git_version#*.}
	git_minor=${git_minor%%.*}
fi
# The unreadable arm matches any character a number may not hold, because a release
# candidate's `46-rc0` would make `-lt` fail with "Illegal number". Neither half holds a
# colon, so the separator is exempt.
case "$git_major:$git_minor" in
*[!0-9:]* | :* | *:)
	# Git printing nothing means git is missing, and the next git call reports that clearly
	if [ -n "$bundles" ] && [ -n "$git_said" ]; then
		echo "the version of git could not be read, so it is not known whether the objects" >&2
		echo "inside each bundle were checked on the way in" >&2
	fi
	;;
*)
	if [ -n "$bundles" ] && { [ "$git_major" -lt 2 ] ||
		{ [ "$git_major" -eq 2 ] && [ "$git_minor" -lt 46 ]; }; }; then
		echo "this git does not check the objects inside a bundle it fetches from, so the" >&2
		echo "repositories below are written without that check; git 2.46 or newer runs it" >&2
	fi
	;;
esac

restored=0
for bundle in repos/*.bundle; do
	[ -e "$bundle" ] || break
	rid=$(basename "$bundle" .bundle)
	# A real id is base58 and nothing else, as `rad-backup` also enforces. The glob already
	# keeps `..` out, and this check keeps it out if ids are ever read from manifest.json.
	case "$rid" in
	'' | *[!A-Za-z0-9]*)
		echo "skipping $bundle: '$rid' is not a repository id" >&2
		continue
		;;
	esac
	target="$RAD_HOME/storage/$rid"
	# Initialising follows a link at the repository's own name, and the archive's author knows
	# which name to plant. It is skipped, because earlier repositories are already back.
	if [ -L "$target" ]; then
		echo "skipping $rid: $target is a symlink, so it would be restored outside the home" >&2
		continue
	fi

	git init --bare --quiet "$target"
	# fsckObjects, as `rad-backup restore` does, because nothing else validates a bundle and
	# one can carry a tree entry named `.git`
	git --git-dir "$target" -c fetch.fsckObjects=true \
		fetch --quiet --force "$(pwd)/$bundle" 'refs/*:refs/*'
	# Only the node's name and DID come back, the allowlist `rad-backup restore` applies. Git
	# RUNS some config values (`core.pager`, `core.fsmonitor`, `ext::` urls), and an archive
	# is a file somebody handed you. `--no-includes` stops `include.path` reaching elsewhere.
	if [ -f "repos/$rid.config" ]; then
		if git config --no-includes --file "repos/$rid.config" --list >/dev/null 2>&1; then
			for key in user.email user.name; do
				value=$(git config --no-includes --file "repos/$rid.config" \
					--get "$key" 2>/dev/null) || continue
				# A key with no value prints nothing, and would come back as an empty name
				[ -n "$value" ] || continue
				git --git-dir "$target" config "$key" "$value" 2>/dev/null ||
					echo "skipping $key for $rid: git would not take that value" >&2
			done
			# Names every key left out, except those a fresh repository writes about this
			# disk. `--name-only` needs git 2.19, and an older git reports nothing here.
			init_writes='core\.(bare|filemode|ignorecase|logallrefupdates'
			init_writes="$init_writes|precomposeunicode|repositoryformatversion|symlinks)"
			left_out=$(git config --no-includes --file "repos/$rid.config" \
				--list --name-only 2>/dev/null |
				grep -vxE "user\.(name|email)|$init_writes|extensions\.(compat)?objectformat" ||
				[ $? -eq 1 ])
			if [ -n "$left_out" ]; then
				echo "$rid: git runs what a repository config tells it to, and this" \
					"archive is vouched for by nobody, so these were left out:" >&2
				echo "$left_out" | sed 's/^/  /' >&2
			fi
		else
			echo "the config in the archive for $rid could not be read, so it came back" \
				"without its name and DID" >&2
		fi
	fi

	if ! command -v jq >/dev/null 2>&1; then
		echo "jq is not installed, so $rid came back without its HEAD" >&2
	else
		head=$(jq -r --arg rid "rad:$rid" \
			'.repos[] | select(.rid==$rid) | .head // empty' manifest.json)
		# `symbolic-ref` takes no `--` and stores what it is handed, so `-d` reaches git as
		# a flag and `refs/../../evil` writes outside the repository. A HEAD needs `refs/`
		# and a valid refname, the same set `rad-backup` refuses.
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
if [ "$restored" -gt 0 ]; then
	echo
	echo "to see your issues and patches again, run this once:"
	echo "    RAD_HOME='$RAD_HOME' rad cob migrate"
	echo "and then this for each repository:"
	echo "    RAD_HOME='$RAD_HOME' rad issue cache --repo <rid>"
	echo "    RAD_HOME='$RAD_HOME' rad patch cache --repo <rid>"
fi
echo
echo "before writing to any restored repository, fetch what the network has:"
echo "    RAD_HOME='$RAD_HOME' rad sync <rid> --fetch"
echo "writing on top of refs the network has already moved past forks your own history."
echo
echo "and never run two nodes with this key at once."
