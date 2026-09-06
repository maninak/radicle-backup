#!/usr/bin/env sh

# Every file SECURITY.md sends a reviewer to still exists.
#
# The audit map is the one document that promises "here is where the secrets are handled",
# and a rename breaks it silently: renaming `archive.rs` to `container.rs` left a reviewer
# following the map to a file that was not there, which is worse than no map at all.

set -eu

# shellcheck source=ci/lib.sh
. "$(dirname "$0")/lib.sh"

missing=0
checked=0
# Every backticked path in the file, not just the first of a row and not just the ones under
# `src/`: the anchored form checked one path per line, so a row naming two files was half
# unchecked, and a `src/`-only pattern walked past `ARCHIVE-FORMAT.md`, which SECURITY.md also
# sends a reader to. A file extension is what makes a backticked word a path here: `storage/`
# is a directory inside a restored home rather than a file in this repository, and everything
# else in backticks is a function or a flag and is nobody's file either.
for path in $(grep -oE '`[A-Za-z0-9_./-]+`' SECURITY.md | tr -d '`' |
	grep -E '\.(md|rs|sh|toml|nix|lock|yml)$' || [ $? -eq 1 ]); do
	if [ ! -e "$path" ]; then
		echo "SECURITY.md sends a reviewer to $path, which is not there" | complain
		missing=1
	fi
	checked=$((checked + 1))
done

# The map is a markdown table, and every row of it opens with the file that row is about. The
# loop above reads the whole document, prose included, so it cannot say whether the TABLE was
# read: comparing what it found against the row count is what makes the number mean something.
# A floor of one passed a run where the pattern had stopped matching all but a single row,
# which is a gate reporting on a map it did not read.
#
# What this cannot see is the other direction: a new file in `src/` that handles a secret and
# has no row here at all. Telling that apart from the fifty files that legitimately have none
# is a judgement, so it stays a reviewer's. Revisit if the map ever gains a marker on the
# source side that a gate could read.
rows=$(grep -cE '^\|[^|]*\|' SECURITY.md || [ $? -eq 1 ])
rows=$((rows - 2)) # the header and the `|---|---|` under it
named=$(grep -cE '^\| `[A-Za-z0-9_./-]+\.[a-z]+`' SECURITY.md || [ $? -eq 1 ])
if [ "$rows" -le 0 ] || [ "$named" -eq 0 ]; then
	echo "the audit map in SECURITY.md matched no rows, so nothing was checked" | complain
	exit 1
fi
if [ "$named" -ne "$rows" ]; then
	echo "the audit map has $rows rows and $named of them open with a file this gate could" \
		"read, so part of the map went unchecked while this reported on the rest" | complain
	missing=1
fi
exit "$missing"
