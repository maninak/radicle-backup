#!/usr/bin/env bash

# Compile every tracked `.rs` file the way a target that is not unix sees it

set -euo pipefail

# shellcheck source=ci/lib.sh
. "$(dirname "$0")/lib.sh"

files=$(rust_sources "nothing was compiled")
saved=target/nonunix-originals
echo "originals are copied to $saved while this runs"

# Zero gates means the pattern stopped matching. `/dev/null` makes `grep -c` print a name with
# every count, because a lone file gets a bare number and `awk -F:` would sum it as zero.
# shellcheck disable=SC2086 # the file list is split on purpose, here and below
gates=$(grep -c '^[[:space:]]*#\[cfg(unix)\]$' /dev/null $files | awk -F: '{total += $2} END {print total+0}')
if [ "$gates" -eq 0 ]; then
	echo "no '#[cfg(unix)]' gates matched, so nothing was checked" | complain
	exit 1
fi

# Originals are copied under their real paths to `target/nonunix-originals`, where a `kill -9`
# leaves them. An existing copy is a killed run's originals and is never cleared, because
# saving the rewritten tree over it would make the trap restore the mangled files for good.
if [ -e "$saved" ]; then
	echo "$saved is already there, which means a run of this gate was killed before it could" \
		"put the tree back. Those are your originals and this tree is the rewritten one:" \
		"compare them, copy back what you want, and remove that directory before running" \
		"this again. For tracked files 'git checkout -- src tests' is the same thing." |
		complain
	exit 1
fi
for file in $files; do
	mkdir -p "$saved/$(dirname "$file")"
	cp "$file" "$saved/$file"
done
trap 'for file in $files; do cp "$saved/$file" "$file"; done; rm -rf "$saved"' EXIT

# The expressions switch every `#[cfg(unix)]` off, drop `#[cfg(not(unix))]` so its item
# compiles, and make each remaining `not(unix)` true so a wrapped `cfg_attr` applies. Each file
# is written from its saved copy, because `sed -i` spells its suffix differently on BSD.
for file in $files; do
	sed -e 's/^\([[:space:]]*\)#\[cfg(unix)\]$/\1#[cfg(all(unix, any()))]/' \
		-e '/^[[:space:]]*#\[cfg(not(unix))\]$/d' \
		-e 's/not(unix)/all()/g' \
		"$saved/$file" > "$file"
done

# Any other spelling of unix (`any(unix, windows)`, `cfg!(unix)`, `target_family`) survives the
# rewrite and stays true here, so the gate refuses to report a platform it did not simulate
# shellcheck disable=SC2086
missed=$(grep -nE '(#\[cfg|cfg!|cfg_attr)[^]]*[^a-z_]unix' $files |
	grep -v 'cfg(all(unix, any()))' || [ $? -eq 1 ])
if [ -n "$missed" ]; then
	printf '%s\n' "$missed" |
		sed 's/$/: this spelling of unix survives the rewrite, so it was compiled as unix/' |
		complain
	exit 1
fi

RUSTFLAGS="-D warnings" cargo clippy --all-targets --locked
