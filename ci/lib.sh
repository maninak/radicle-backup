# shellcheck shell=sh
#
# Sourced by every gate here, so it carries a `shell` directive in place of a shebang

# Prefixes each line with `::error::` under GitHub Actions, raising it as a job annotation
complain() {
	if [ -n "${GITHUB_ACTIONS:-}" ]; then
		sed 's/^/::error::/' >&2
	else
		cat >&2
	fi
}

# Every tracked Rust file, or a refusal.
#
# An empty list means the checkout is unreadable, and a gate reading zero files reports a pass.
# `core.quotePath=false` keeps git from quoting a non-ascii path, which drops it from the `.rs`
# match. A path with whitespace is refused, because every caller splits this list on it.
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
