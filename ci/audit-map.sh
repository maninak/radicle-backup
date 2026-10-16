#!/usr/bin/env sh

# Every file SECURITY.md sends a reviewer to still exists.
#
# A rename breaks the audit map silently and sends a reviewer to a file that is not there.
# The table is parsed as a table, and the rest of the file is scanned for path-shaped words.
# A new `src/` file handling a secret with no row here stays a reviewer's call.

set -eu

# shellcheck source=ci/lib.sh
. "$(dirname "$0")/lib.sh"

map=SECURITY.md
missing=0

# The first cell of every row of the audit map, read only from the table under `| Read this |`,
# because a second table anywhere in the file would otherwise be counted as map rows
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
# starting with `./` as the fenced block spells its commands. A backticked word without an
# extension is a function, a flag or a directory inside a restored home.
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

# The scan above can go quiet while the table pass still reports. Every row's file is
# backticked with an extension, so the scan must find at least as many paths as there are rows.
table_rows=$(printf '%s\n' "$rows" | grep -c '' || [ $? -eq 1 ])
if [ "$read_out" -lt "$table_rows" ]; then
	echo "$read_out paths were read out of $map and its table alone has $table_rows rows, so" \
		"the scan over the rest of the document went quiet while this reported on the table" |
		complain
	missing=1
fi
exit "$missing"
