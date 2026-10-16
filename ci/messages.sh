#!/usr/bin/env sh

# No user-facing message carries a run of spaces where a line continuation should be

set -eu

# shellcheck source=ci/lib.sh
. "$(dirname "$0")/lib.sh"

# `cargo fmt` leaves the inside of a literal alone, so a hand-joined message reaches the user
# with a hole in it. A literal continued with its `\` dropped spans lines and slips past this.
# The run is three spaces, because a fake `rad` output in the tests aligns columns with two.
gap='"[^"]*[[:alnum:],.:;)!?%'"'"'"-]   +[[:alnum:]]'
# A pattern that has stopped matching reports a clean tree, so it is tried on a bad line first
if ! printf '%s\n' 'x("a node running: the run                      that took it")' \
	| grep -Eq "$gap"; then
	echo "the message check no longer catches a gap it was written for" | complain
	exit 1
fi
# The files are listed explicitly, because a `--include` that stops matching reads nothing and
# reports a clean tree
sources=$(rust_sources "no message was checked")
# `|| [ $? -eq 1 ]` accepts grep's "no match" and fails on its 2 for "could not read that
# file", which a half-applied patch causes. Never `|| true`, which passes both.
# shellcheck disable=SC2086 # the file list is split on purpose, and `rust_sources` refuses a
# tracked path with whitespace in it
gaps=$(grep -En "$gap" $sources || [ $? -eq 1 ])
if [ -n "$gaps" ]; then
	echo "$gaps" | sed 's/$/: a run of spaces in a message, so a line continuation was dropped/' | complain
	exit 1
fi
