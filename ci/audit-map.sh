#!/usr/bin/env sh

# Every file SECURITY.md sends a reviewer to still exists.
#
# The audit map is the one document that promises "here is where the secrets are handled",
# and a rename breaks it silently: renaming `archive.rs` to `container.rs` left a reviewer
# following the map to a file that was not there, which is worse than no map at all.
#
# Two passes, because the document says where to look in two ways. The table is parsed as a
# table, so the count of rows read is the count of rows there are; everything else in the file
# is scanned for path-shaped words, which is what reaches the commands in the fenced block at
# the bottom. Neither pass can see the other direction, a new file in `src/` that handles a
# secret and has no row here at all: telling that apart from the fifty files that legitimately
# have none is a judgement, so it stays a reviewer's. Revisit if the map ever gains a marker
# on the source side that a gate could read.

set -eu

# shellcheck source=ci/lib.sh
. "$(dirname "$0")/lib.sh"

map=SECURITY.md
missing=0

# The first cell of every row of the audit map, which is the file that row is about. Read as
# the table it is rather than by counting `|` lines in the whole document: a second table
# anywhere in the file threw the count off and the failure blamed the map.
rows=$(awk -F'|' '
	/^\| *Read this *\|/ { inside = 1; next }
	inside && /^\|[[:space:]]*-+/ { next }
	inside && !/^\|/ { exit }
	inside { gsub(/[` ]/, "", $2); if ($2 != "") print $2 }
' "$map")
if [ -z "$rows" ]; then
	echo "the audit map in $map matched no rows, so nothing was checked. Its table opens" \
		"with a '| Read this |' header, and this reads the first cell of every row under it." |
		complain
	exit 1
fi
for path in $rows; do
	if [ ! -e "$path" ]; then
		echo "the audit map sends a reviewer to $path, which is not there" | complain
		missing=1
	fi
done

# Every other path in the document: a backticked word with a file extension, and a word
# starting with `./`, which is how the fenced block at the bottom spells the two commands it
# tells a reviewer to run. An extension is what makes a backticked word a path: `storage/` is
# a directory inside a restored home rather than a file here, and everything else in backticks
# is a function or a flag and is nobody's file either.
#
# shellcheck disable=SC2016 # the `$` in these patterns is grep's anchor, not a variable
elsewhere=$(
	grep -oE '`[A-Za-z0-9_./-]+`' "$map" | tr -d '`' |
		grep -E '\.(md|rs|sh|toml|nix|lock|yml)$' || [ $? -eq 1 ]
	grep -oE '(^|[[:space:]])\./[A-Za-z0-9_./-]+' "$map" | tr -d ' ' | sed 's|^\./||' ||
		[ $? -eq 1 ]
)
read_out=0
for path in $elsewhere; do
	if [ ! -e "$path" ]; then
		echo "$map sends a reviewer to $path, which is not there" | complain
		missing=1
	fi
	read_out=$((read_out + 1))
done

# The pass above is the one that can go quiet: change what it thinks a path looks like and it
# reads nothing while the table pass still reports on the rows. Every row's file is backticked
# and carries an extension, so it must find at least as many paths as there are rows.
table_rows=$(printf '%s\n' "$rows" | grep -c '' || [ $? -eq 1 ])
if [ "$read_out" -lt "$table_rows" ]; then
	echo "$read_out paths were read out of $map and its table alone has $table_rows rows, so" \
		"the scan over the rest of the document went quiet while this reported on the table" |
		complain
	missing=1
fi
exit "$missing"
