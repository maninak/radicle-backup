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
rows=0
# Every backticked `src/...` in the file, not just the first of a row: the anchored form
# checked one path per line, so a row naming two files was half unchecked.
for path in $(grep -o '`src/[^`]*`' SECURITY.md | tr -d '`'); do
	if [ ! -e "$path" ]; then
		echo "SECURITY.md sends a reviewer to $path, which is not there" | complain
		missing=1
	fi
	rows=$((rows + 1))
done
# Zero rows means the table stopped matching the pattern, not that the map is clean. A
# gate that passes while checking nothing reports a safety it is not providing.
if [ "$rows" -eq 0 ]; then
	echo "the audit map in SECURITY.md matched no rows, so nothing was checked" | complain
	missing=1
fi
exit "$missing"
