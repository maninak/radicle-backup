#!/usr/bin/env bash

# Compile the suite the way a target that is not unix sees it.
#
# A helper without `#[cfg(unix)]` that calls one which has it builds here and fails on
# Windows, and that has now reached CI three times. There is no local windows build to catch
# it with, because zstd's C code wants `lib.exe`, so this turns the gates off and compiles
# that instead.
#
# Every tracked `.rs` file, not just the integration suite. Reading one file left `src/` out,
# which is where eight of the gates in `src/home.rs` alone live: a change that made two
# `NodeState` variants unreachable off unix passed this recipe and would have failed the
# Windows job, and only a hand-run of the same two `sed` expressions over `src/` found it.
#
# What this does NOT see: an ungated `use std::os::unix::...`, of which this tree has twenty.
# The simulation compiles for a linux target, so those paths resolve here however they are
# gated, and only the real windows job finds one. This gate is about the shape of the `cfg`
# tree, not about what the standard library offers.
#
# Files are rewritten in place and put back by the trap, so a failing compile, a Ctrl-C or any
# signal bash can trap leaves the working tree as it found it. A `kill -9` cannot be trapped,
# so the copies go to a named directory under `target/` rather than to an anonymous `mktemp`
# one: after a kill the tree is still rewritten, and `NONUNIX_ORIGINALS` below is where the
# originals are. Recovering them is a `cp` per file, or `git checkout --` for what is tracked.

set -euo pipefail

# shellcheck source=ci/lib.sh
. "$(dirname "$0")/lib.sh"

files=$(rust_sources "nothing was compiled")
saved=target/nonunix-originals
echo "originals are copied to $saved while this runs"

# Zero gates means the pattern stopped matching, not that there is nothing to check.
# `/dev/null` in the file list so `grep -c` prints a name with every count: given one file
# and no second operand it prints the bare number, `awk -F:` sums the empty second field,
# and a one-file tree reads as zero gates.
gates=$(grep -c '^[[:space:]]*#\[cfg(unix)\]$' /dev/null $files | awk -F: '{total += $2} END {print total+0}')
if [ "$gates" -eq 0 ]; then
	echo "no '#[cfg(unix)]' gates matched, so nothing was checked" | complain
	exit 1
fi

# Copied under their real paths, not with the separators squeezed to `_`: two tracked files
# whose flattened names collide shared one copy, the second overwrote the first, and the trap
# then restored both from the survivor. That is uncommitted work destroyed by a gate, reported
# as a pass. The copies are made before the trap is installed, so a failure here cannot fire a
# restore over files that were never rewritten.
rm -rf "$saved"
for file in $files; do
	mkdir -p "$saved/$(dirname "$file")"
	cp "$file" "$saved/$file"
done
trap 'for file in $files; do cp "$saved/$file" "$file"; done; rm -rf "$saved"' EXIT

# Indented gates count: a method inside an `impl` carries one, and leaving it while its
# caller goes reports the caller's absence as dead code, which is this check inventing a
# failure windows would never see.
#
# The second expression drops `#[cfg(not(unix))]` so its item compiles unconditionally.
# A platform pair has two arms, and switching only the unix one off would take both away,
# reporting an absence windows would never see.
#
# The third makes every `not(unix)` still standing come out true, which is what applies a
# `#[cfg_attr(not(unix), ...)]`. `unix` holds here, so without it the simulation switches
# an item off and then declines to apply the very attribute that says why the item is
# gone, reporting a failure windows would never see. It runs after the deletion above, so
# the only `not(unix)` left to rewrite is one inside a `cfg_attr`. Substituting the token
# rather than matching the line, because `rustfmt` wraps a long attribute over four lines
# on a width it does not document, and a line-shaped pattern quietly stops matching the
# day a reason gets longer.
#
# Reading a saved copy and writing the file, rather than `sed -i`, which spells its backup
# suffix differently on GNU and BSD and so breaks on the macOS checkouts.
for file in $files; do
	sed -e 's/^\([[:space:]]*\)#\[cfg(unix)\]$/\1#[cfg(all(unix, any()))]/' \
		-e '/^[[:space:]]*#\[cfg(not(unix))\]$/d' \
		-e 's/not(unix)/all()/g' \
		"$saved/$file" > "$file"
done

# What the three expressions above did not reach. They know `#[cfg(unix)]` alone on its line
# and the `not(unix)` token, and nothing else: `#[cfg(any(unix, windows))]`, `cfg!(unix)` in
# expression position and `#[cfg(target_family = "unix")]` all survive them, stay true here,
# and leave this compiling something the windows job does not. Refusing is the honest answer,
# because the alternative is a gate that reports a platform it did not simulate.
missed=$(grep -nE '(#\[cfg|cfg!|cfg_attr)[^]]*[^a-z_]unix' $files |
	grep -v 'cfg(all(unix, any()))' || [ $? -eq 1 ])
if [ -n "$missed" ]; then
	printf '%s\n' "$missed" |
		sed 's/$/: this spelling of unix survives the rewrite, so it was compiled as unix/' |
		complain
	exit 1
fi

RUSTFLAGS="-D warnings" cargo clippy --all-targets --locked
