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
# The pattern deliberately wants a character on both sides of the run that ends or begins a
# word, so the indentation inside the multi-line templates this tool ships (`RESTORE.md`,
# `restore.sh`, the systemd units, the recovery sheet) is not a hit. `!`, `?`, `%`, `'`, `-`
# and a nested `\"` are in the left-hand set beside the letters: this tool's copy ends a
# clause with every one of them, and a hole after a question mark is the same defect as a
# hole after a full stop.
#
# Three spaces and not two, because one fake `rad` output in the integration suite lines its
# columns up with two and a gate that fires on a deliberate one gets skipped rather than read.
# Revisit if a two-space join ever reaches a user.

set -eu

# shellcheck source=ci/lib.sh
. "$(dirname "$0")/lib.sh"

gap='"[^"]*[[:alnum:],.:;)!?%'"'"'"-]   +[[:alnum:]]'
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
# `|| [ $? -eq 1 ]` and not `|| true`: grep exits 1 for "no match" and 2 for "could not read
# that file", and `true` maps both to a clean tree. A file in the index but not in the working
# tree, which is any half-applied patch, is enough to make this gate read nothing and pass.
# shellcheck disable=SC2086 # the file list is split on purpose; `rust_sources` refuses a
# tracked path with whitespace in it, which is what makes that safe.
gaps=$(grep -En "$gap" $sources || [ $? -eq 1 ])
if [ -n "$gaps" ]; then
	echo "$gaps" | sed 's/$/: a run of spaces in a message, so a line continuation was dropped/' | complain
	exit 1
fi
