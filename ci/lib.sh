# Shared by every gate in this directory.
#
# A gate reports through `complain`, which prefixes each line with `::error::` under GitHub
# Actions so the failure lands on the file it is about, and prints it plainly everywhere else.
# Reading the variable rather than taking a flag, because a recipe and a workflow calling the
# same script differently is the drift these scripts exist to end.
complain() {
	if [ -n "${GITHUB_ACTIONS:-}" ]; then
		sed 's/^/::error::/' >&2
	else
		cat >&2
	fi
}

# Every tracked Rust file, or a refusal. An empty list is a checkout the gate cannot read, not
# a tree with nothing in it: without this a gate reads zero files and still reports a pass.
rust_sources() {
	sources=$(git ls-files 'src/' 'tests/' | grep '\.rs$' || true)
	if [ -z "$sources" ]; then
		echo "no rust files were listed, so $1" | complain
		exit 1
	fi
	echo "$sources"
}
