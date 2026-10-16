#!/usr/bin/env sh

# Every tracked shell script through shellcheck, including notes and style

set -eu

# shellcheck source=ci/lib.sh
. "$(dirname "$0")/lib.sh"

if ! command -v shellcheck > /dev/null; then
	echo "shellcheck is not installed, so the shell scripts went unchecked. This recipe is" \
		"what CI runs and CI has it, so it refuses rather than skipping: a gate that passes" \
		"by not running is the one thing worse than no gate. 'apt install shellcheck', or" \
		"'brew install shellcheck'." | complain
	exit 1
fi

scripts=$(git -c core.quotePath=false ls-files | grep '\.sh$' || [ $? -eq 1 ])
if [ -z "$scripts" ]; then
	echo "no shell scripts were listed, so none was checked" | complain
	exit 1
fi

# A shellcheck that stopped running reports a clean tree, so it is first put to a bad script
control=$(mktemp -d)
trap 'rm -rf "$control"' EXIT
# shellcheck disable=SC2016 # `$1` and `$UNSET_ON_PURPOSE` must reach the control script
# unexpanded, or shellcheck has nothing to complain about
printf '#!/bin/sh\nif [ $1 = x ]; then echo "$UNSET_ON_PURPOSE"; fi\n' > "$control/bad.sh"
if shellcheck "$control/bad.sh" > /dev/null 2>&1; then
	echo "shellcheck passed a script written to fail it, so what it says about this repository" \
		"means nothing" | complain
	exit 1
fi

# SC2317 and SC2329 (unreachable code, uninvoked function) are off for every script, because
# `names.sh` calls each rule through a variable and neither check follows that. Revisit when
# an indirect call becomes visible to shellcheck.
#
# shellcheck disable=SC2086 # the list is split on purpose, and a path with whitespace in it
# fails loudly here
shellcheck --exclude=SC2317,SC2329 $scripts
