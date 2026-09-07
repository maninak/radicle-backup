#!/usr/bin/env sh

# Numbers and calls that mean one thing and are written in several files, held to each other.
#
# Every pin here is a fact one file owns and others repeat: the first git that checks a bundle,
# how many checks `doctor` runs. A repeated fact drifts, and each of these drifted somewhere a
# test could not see. The version boundary lives in Rust, in the shipped shell script and in
# the sheet beside it, and the two readers of an archive are meant to warn about exactly the
# same gits; the check count lives in a constant, in the command, and in what the integration
# suite asks the real binary for.
#
# A pin is only worth what its extraction is worth, so every one refuses an empty read rather
# than comparing nothing to nothing, and the count at the end refuses a run that lost a pin.

set -eu

# shellcheck source=ci/lib.sh
. "$(dirname "$0")/lib.sh"

wrong=0
pins=0

# Whatever `grep` found, or an empty string, and never the exit status of a grep that could
# not open the file: `|| true` maps "no such file" to success just as happily as "no match",
# which is how a gate comes to report a clean tree having read nothing.
found() {
	pattern=$1
	file=$2
	if [ ! -f "$file" ]; then
		echo "$file is not there, so nothing about it was checked" | complain
		exit 1
	fi
	grep -oE "$pattern" "$file" || [ $? -eq 1 ]
}

# The first git that runs `fsck` over a bundle. `src/git.rs` owns it; `assets/restore.sh` is
# the reader that runs when this tool is not installed, and it has to warn about the same gits.
pins=$((pins + 1))
boundary=$(found 'FSCK_ON_A_BUNDLE_SINCE: \(u32, u32\) = \([0-9]+, [0-9]+\)' src/git.rs)
boundary=$(echo "$boundary" | grep -oE '[0-9]+, [0-9]+' || [ $? -eq 1 ])
if [ -z "$boundary" ]; then
	echo "src/git.rs no longer spells FSCK_ON_A_BUNDLE_SINCE the way this gate reads it" |
		complain
	exit 1
fi
major=${boundary%,*}
minor=${boundary##*, }
for claim in \
	"assets/restore.sh:\[ \"\\\$git_minor\" -lt $minor \]" \
	"assets/restore.sh:\[ \"\\\$git_major\" -lt $major \]" \
	"assets/restore.sh:\[ \"\\\$git_major\" -eq $major \]" \
	"assets/restore.sh:git $major\.$minor or newer" \
	"assets/RESTORE.md:$major\.$minor" \
	"tests/end_to_end.rs:git version $major\.$minor\.0"; do
	file=${claim%%:*}
	pattern=${claim#*:}
	if [ -z "$(found "$pattern" "$file")" ]; then
		echo "$file does not say $major.$minor, which src/git.rs says is the first git that" \
			"checks the objects in a bundle. Both readers of an archive warn about this, so" \
			"they warn about the same gits or one of them is lying." | complain
		wrong=1
	fi
done

# The warning itself, which no test can watch fire on a machine whose git is new enough. The
# wording is covered by `bundle_check_notice`; this is the half that says it is still called.
pins=$((pins + 1))
if [ -z "$(found 'fsck_reaches_a_bundle' src/cmd/restore.rs)" ]; then
	echo "src/cmd/restore.rs no longer asks whether this git checks a bundle, so a restore on" \
		"an older git reports the same success as one that had checked the objects" | complain
	wrong=1
fi

# The settings a restore takes out of an archive, which three readers each spell for
# themselves: `src/cmd/restore.rs`, the `restore.sh` that rides inside every archive, and the
# commands `RESTORE.md` gives somebody to paste. All three say they apply the same allowlist,
# and a key added to one of them is a setting one reader of an archive puts back and another
# does not, which is the drift these gates exist to end. A repository config is where git
# looks for the settings whose values it RUNS, so the list is also the security boundary.
pins=$((pins + 1))
allowed=$(found 'CONFIG_ALLOWED: &\[&str\] = &\[[^]]*\]' src/cmd/restore.rs |
	grep -oE '"[a-z.]+"' | tr -d '"' | sort | tr '\n' ' ')
if [ -z "$allowed" ]; then
	echo "src/cmd/restore.rs no longer spells CONFIG_ALLOWED the way this gate reads it" |
		complain
	exit 1
fi
for reader in assets/restore.sh assets/RESTORE.md; do
	spelled=$(found 'for key in [a-z. ]+; do' "$reader" |
		sed 's/^for key in //; s/; do$//' | tr ' ' '\n' | sort | tr '\n' ' ')
	if [ "$spelled" != "$allowed" ]; then
		echo "$reader takes [$spelled] out of an archived repository config and" \
			"src/cmd/restore.rs takes [$allowed]. Both are readers of the same archive," \
			"and a config is where git looks for the settings it runs." | complain
		wrong=1
	fi
done

# How many checks `doctor` runs, which three places state and none derives.
pins=$((pins + 1))
defined=$(found '^fn check_[a-z_]+' src/cmd/doctor.rs | grep -c '' || [ $? -eq 1 ])
pinned=$(found 'CHECKS_THE_COMMAND_RUNS: usize = [0-9]+' src/cmd/doctor.rs | grep -oE '[0-9]+$' ||
	[ $? -eq 1 ])
asked=$(found 'report\["total"\], [0-9]+' tests/end_to_end.rs | grep -oE '[0-9]+$' || [ $? -eq 1 ])
if [ -z "$pinned" ] || [ -z "$asked" ] || [ "$defined" -eq 0 ]; then
	echo "the doctor check count is no longer written where this gate reads it: $defined" \
		"definitions, '$pinned' pinned, '$asked' asked of the real command" | complain
	exit 1
fi
if [ "$defined" != "$pinned" ] || [ "$defined" != "$asked" ]; then
	echo "doctor defines $defined checks, its own constant says $pinned and the integration" \
		"suite asks the real command for $asked. A check added to the command and to nothing" \
		"else is swept by none of the rules that read that list." | complain
	wrong=1
fi

# What `just check` runs, which the README and CONTRIBUTING each describe in the same sentence
# beside the same command. A gate added to the recipe and to one of them leaves the other
# telling a contributor the run covers less than it does, which is the half nobody re-reads.
pins=$((pins + 1))
recipe=$(found 'just check +# [^|]*' README.md)
if [ -z "$recipe" ]; then
	echo "README.md no longer shows the 'just check' line this gate reads" | complain
	exit 1
fi
# Read out of both files the same way, rather than looking the README's sentence up inside
# CONTRIBUTING.md: a match found there is only ever as long as what was searched for, so a
# clause added to the end of one of the two sentences would be found in the other and pass.
if [ "$(found 'just check +# [^|]*' CONTRIBUTING.md)" != "$recipe" ]; then
	echo "README.md and CONTRIBUTING.md describe 'just check' differently, so one of them is" \
		"telling a contributor the run covers something other than what it covers" | complain
	wrong=1
fi

# The gates themselves, in the order the justfile's `check` recipe runs them and the order the
# workflow's test job does. Moving them into `ci/` stopped the two spelling a gate's RULES
# differently; which gates each side runs is still written twice, and it drifted twice in one
# session before the move. A gate only one side runs is one that lands broken on whichever
# side nobody ran.
pins=$((pins + 1))
recipe_gates=$(grep -m1 '^check:' justfile | tr ' ' '\n' | sed 's/:$//' |
	while read -r name; do
		if [ -f "ci/$name.sh" ]; then echo "$name"; fi
	done)
workflow_gates=$(found '^ *run: ci/[a-z-]+\.sh$' .github/workflows/ci.yml |
	sed 's|.*run: ci/||; s|\.sh$||')
if [ -z "$recipe_gates" ] || [ -z "$workflow_gates" ]; then
	echo "neither the justfile nor the workflow names a gate this can read, so which gates" \
		"each side runs went unchecked" | complain
	exit 1
fi
if [ "$recipe_gates" != "$workflow_gates" ]; then
	echo "'just check' runs [$(echo "$recipe_gates" | tr '\n' ' ')] and the workflow runs" \
		"[$(echo "$workflow_gates" | tr '\n' ' ')]. A gate only one side runs lands broken" \
		"on whichever side nobody ran." | complain
	wrong=1
fi

# A pin that stopped running is a pin that stopped holding, and it would do it quietly.
if [ "$pins" -ne 6 ]; then
	echo "$pins pins ran, not the 6 this gate has. One was lost rather than deleted." | complain
	wrong=1
fi
exit "$wrong"
