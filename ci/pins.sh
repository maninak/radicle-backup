#!/usr/bin/env sh

# Facts one file owns and others repeat, held to each other

set -eu

# shellcheck source=ci/lib.sh
. "$(dirname "$0")/lib.sh"

wrong=0
pins=0

# Whatever `grep` found, or an empty string. A missing file fails, because `|| true` would map
# "no such file" to a clean tree.
found() {
	pattern=$1
	file=$2
	if [ ! -f "$file" ]; then
		echo "$file is not there, so nothing about it was checked" | complain
		exit 1
	fi
	grep -oE "$pattern" "$file" || [ $? -eq 1 ]
}

# The first git that runs `fsck` over a bundle. `src/git.rs` owns it, and `assets/restore.sh`
# runs without this tool and has to warn about the same gits.
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

# The call that raises the old-git warning, which no test can watch fire on a new git
pins=$((pins + 1))
if [ -z "$(found 'fsck_reaches_a_bundle' src/cmd/restore.rs)" ]; then
	echo "src/cmd/restore.rs no longer asks whether this git checks a bundle, so a restore on" \
		"an older git reports the same success as one that had checked the objects" | complain
	wrong=1
fi

# The config keys a restore takes from an archive, spelled by `src/cmd/restore.rs`,
# `restore.sh` and `RESTORE.md`. Git runs some config values, so this allowlist is a security
# boundary and all three readers must apply the same one.
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

# How many checks `doctor` runs, which three places state and none derives
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

# The sentence describing `just check`, which README and CONTRIBUTING each carry
pins=$((pins + 1))
recipe=$(found 'just check +# [^|]*' README.md)
if [ -z "$recipe" ]; then
	echo "README.md no longer shows the 'just check' line this gate reads" | complain
	exit 1
fi
# Both are read out the same way, because a search for one sentence inside the other passes
# when a clause is added only to its end
if [ "$(found 'just check +# [^|]*' CONTRIBUTING.md)" != "$recipe" ]; then
	echo "README.md and CONTRIBUTING.md describe 'just check' differently, so one of them is" \
		"telling a contributor the run covers something other than what it covers" | complain
	wrong=1
fi

# The gates, in the order the `check` recipe and the workflow's test job each run them. A gate
# only one side runs lands broken on whichever side nobody ran.
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

# Every value `RESTORE.md` interpolates into a printed `rad` command is quoted with `@sh`. The
# values come from the archive and the reader is told to run the line, so an id reading
# `x; curl ... | sh` would run a second command.
pins=$((pins + 1))
built=$(found '"rad [^"]*"' assets/RESTORE.md)
if [ -z "$built" ]; then
	echo "assets/RESTORE.md no longer builds a rad command the way this gate reads it, so" \
		"whether those commands quote what the archive put in them went unchecked" | complain
	exit 1
fi
bare=$(echo "$built" | grep -oE '\\\([^)]*\)' | grep -v '|@sh)' || [ $? -eq 1 ])
if [ -n "$bare" ]; then
	echo "assets/RESTORE.md builds a command with $(echo "$bare" | tr '\n' ' ')in it, which" \
		"comes out of the archive unquoted into a line the reader is told to run" | complain
	wrong=1
fi

# Each of the three looks at whether the home's directories point elsewhere stays in its own
# function. A link planted while a large archive unpacks is followed by the next write, and no
# test can plant one mid-run. Only `run` may ask, because nobody can consent to a later link.
pins=$((pins + 1))
for pair in "run settle_directories_that_point_elsewhere" \
	"install refuse_a_link_that_appeared_mid_restore" \
	"restore_repositories refuse_a_link_that_appeared_mid_restore"; do
	asked_in=${pair% *}
	asks=${pair#* }
	# The function body, from its signature to the next line starting at column zero
	body=$(awk -v want="fn $asked_in(" '
		index($0, want) { inside = 1 }
		inside { print }
		inside && /^\}/ { exit }
	' src/cmd/restore.rs)
	if [ -z "$body" ]; then
		echo "src/cmd/restore.rs has no fn $asked_in, so whether it asks about the home going" \
			"went unchecked" | complain
		exit 1
	fi
	if ! echo "$body" | grep -q "$asks("; then
		echo "src/cmd/restore.rs::$asked_in no longer calls $asks. A link planted while a big" \
			"archive unpacks is followed by whatever writes next, and the key or the" \
			"repositories land outside the home. The two later looks must REFUSE and not ask:" \
			"nobody can consent to a link that appeared under a running restore." | complain
		wrong=1
	fi
done

# A pin that stopped running reports nothing, so the count of pins run is checked too
if [ "$pins" -ne 8 ]; then
	echo "$pins pins ran, not the 8 this gate has. One was lost rather than deleted." | complain
	wrong=1
fi
exit "$wrong"
