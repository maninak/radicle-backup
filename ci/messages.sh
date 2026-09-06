#!/usr/bin/env sh

# No user-facing message carries a run of spaces where a line continuation should be.
#
# `cargo fmt` will not touch the inside of a literal, so a message hand-joined from two lines
# keeps whatever whitespace the join left and reaches the user as a hole in the middle of a
# sentence. One had been printing that way in `restore` for as long as the warning existed.
#
# Line-based, so it catches the run of spaces WITHIN one source line, which is the shape the
# real defect had. A literal continued to the next line with the trailing `\` dropped is a
# different shape and this does not see it: telling a literal that spans lines from a comment,
# a char literal or a raw string needs a Rust parser, and a gate that guesses would fire on
# the templates this tool ships. Revisit if that shape ever occurs.
#
# The pattern deliberately wants a word character on both sides of the run, so the indentation
# inside the multi-line templates this tool ships (`RESTORE.md`, `restore.sh`, the systemd
# units, the recovery sheet) is not a hit.

set -eu

# shellcheck source=ci/lib.sh
. "$(dirname "$0")/lib.sh"

gap='"[^"]*[[:alnum:],.:;)]   +[[:alnum:]]'
# The pattern is tried against a line known to be bad first. A gate nobody has watched
# fail reports a safety it may not be providing, and this one is a single regex.
if ! printf '%s\n' 'x("a node running: the run                      that took it")' \
	| grep -Eq "$gap"; then
	echo "the message check no longer catches a gap it was written for" | complain
	exit 1
fi
# The files are listed rather than described to `grep`, because a `--include` that stops
# matching (`*.rust`, a directory renamed) reads nothing and reports a clean tree.
sources=$(rust_sources "no message was checked")
gaps=$(grep -En "$gap" $sources || true)
if [ -n "$gaps" ]; then
	echo "$gaps" | sed 's/$/: a run of spaces in a message, so a line continuation was dropped/' | complain
	exit 1
fi
