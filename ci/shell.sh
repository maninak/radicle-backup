#!/usr/bin/env sh

# Every tracked shell script, through shellcheck.
#
# `assets/restore.sh` is the reason. A guardrail of this project is that an archive can be put
# back with a POSIX shell, `git` and `jq` and nothing else, so that script is the reader of
# last resort and it runs on somebody else's machine in the middle of a recovery. The gates in
# `ci/` are the second reason: they are what says the Rust is right, and nothing was saying
# they were.
#
# Notes and style are as much of it as errors and warnings. Everything shellcheck says about
# these files today is deliberate and carries a `disable` with the reason beside it, which is
# worth more than the finding: the next reader sees that the word splitting is on purpose.

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

# Put to a script written to be complained about, before its answer about ours is worth
# anything. A shellcheck that stopped running, or one invoked with the wrong arguments, says
# the same nothing about a clean tree as about a broken one.
control=$(mktemp -d)
trap 'rm -rf "$control"' EXIT
# shellcheck disable=SC2016 # the single quotes are the point: `$1` and `$UNSET_ON_PURPOSE`
# have to reach the control script as themselves, and expanding them here would write a
# control that shellcheck is happy with.
printf '#!/bin/sh\nif [ $1 = x ]; then echo "$UNSET_ON_PURPOSE"; fi\n' > "$control/bad.sh"
if shellcheck "$control/bad.sh" > /dev/null 2>&1; then
	echo "shellcheck passed a script written to fail it, so what it says about this repository" \
		"means nothing" | complain
	exit 1
fi

# Two findings about reachability are off for the whole directory rather than silenced line by
# line: SC2317, "command appears to be unreachable", and SC2329, "this function is never
# invoked". Every rule in `names.sh` is called through a variable holding its name, which is
# what lets each one be run over the tree and over a line written to be caught, and neither
# pass can follow a call through a variable: between them they report every rule and the body
# of every rule. Both are raised only by shellchecks newer than 0.8, which is why they reached
# CI rather than this machine. Revisit if shellcheck learns to see an indirect call.
#
# shellcheck disable=SC2086 # the list is split on purpose; `ls-files` above is read the same
# way `rust_sources` is, and a path with whitespace in it would fail loudly here.
shellcheck --exclude=SC2317,SC2329 $scripts
