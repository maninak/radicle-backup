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
# Files are rewritten in place and put back by the trap, so a failing compile or a Ctrl-C
# leaves the working tree as it found it.

set -euo pipefail

# shellcheck source=ci/lib.sh
. "$(dirname "$0")/lib.sh"

files=$(rust_sources "nothing was compiled")
saved=$(mktemp -d)
trap 'for file in $files; do cp "$saved/$(echo "$file" | tr / _)" "$file"; done; rm -rf "$saved"' EXIT
# Zero gates means the pattern stopped matching, not that there is nothing to check.
gates=$(grep -c '^[[:space:]]*#\[cfg(unix)\]$' $files | awk -F: '{total += $2} END {print total+0}')
if [ "$gates" -eq 0 ]; then
	echo "no '#[cfg(unix)]' gates matched, so nothing was checked" | complain
	exit 1
fi
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
	cp "$file" "$saved/$(echo "$file" | tr / _)"
	sed -e 's/^\([[:space:]]*\)#\[cfg(unix)\]$/\1#[cfg(all(unix, any()))]/' \
		-e '/^[[:space:]]*#\[cfg(not(unix))\]$/d' \
		-e 's/not(unix)/all()/g' \
		"$saved/$(echo "$file" | tr / _)" > "$file"
done
RUSTFLAGS="-D warnings" cargo clippy --all-targets --locked
