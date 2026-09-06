# Shared by every gate in this directory.
#
# A gate reports through `complain`, which prefixes each line with `::error::` under GitHub
# Actions so the failure is raised as an annotation on the job, and prints it plainly
# everywhere else. Reading the variable rather than taking a flag, because a recipe and a
# workflow calling the same script differently is the drift these scripts exist to end.
complain() {
	if [ -n "${GITHUB_ACTIONS:-}" ]; then
		sed 's/^/::error::/' >&2
	else
		cat >&2
	fi
}

# Every tracked Rust file, or a refusal.
#
# An empty list is a checkout the gate cannot read, not a tree with nothing in it: without
# this a gate reads zero files and still reports a pass.
#
# `core.quotePath=false`, because git otherwise renders a path with a non-ascii byte in it as
# a quoted, backslash-escaped string. The trailing quote then fails the `.rs` match and the
# file drops out of every gate here with nothing said. This repository has already shipped one
# fix for a name that is not ascii, so the shape is a live one in this tree.
#
# A path holding whitespace is refused rather than handled, because every caller splits this
# list on it. Refusing is one line and says which file; the alternative is a gate that reads
# two halves of a name as two files it cannot open and reports a clean tree.
rust_sources() {
	sources=$(git -c core.quotePath=false ls-files 'src/' 'tests/' | grep '\.rs$' || [ $? -eq 1 ])
	if [ -z "$sources" ]; then
		echo "no rust files were listed, so $1" | complain
		exit 1
	fi
	spaced=$(printf '%s\n' "$sources" | grep '[[:space:]]' || [ $? -eq 1 ])
	if [ -n "$spaced" ]; then
		printf '%s\n' "$spaced" |
			sed 's/^/a tracked path has whitespace in it, which every gate here splits on: /' |
			complain
		exit 1
	fi
	echo "$sources"
}
