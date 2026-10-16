#!/usr/bin/env sh

# Seven naming and gating rules over the Rust tree, each proved able to fail before it runs

set -eu

# shellcheck source=ci/lib.sh
. "$(dirname "$0")/lib.sh"

found=0
rules=0

# Built once, so no rule can read nothing and pass while the count at the bottom says it ran
sources=$(rust_sources "no name was checked")

control=$(mktemp -d)
trap 'rm -rf "$control"' EXIT

# The binary a file compiles into, which is its first path component (`src` or `tests`)
binary_of() {
	printf '%s' "$1" | awk -F/ '{ for (i = 1; i <= NF; i++) if ($i != "") { print $i; exit } }'
}

# Runs one rule over each line it must catch, then over the tree. A pattern that stopped
# matching reports a clean tree in the same words as a clean tree. Each control line is run
# alone, because one line proves only the one alternative of the regex it exercises.
enforce() {
	rule=$1
	bad=$2
	complaint=$3
	printf '%s\n' "$bad" | while IFS= read -r line; do
		[ -n "$line" ] || continue
		printf '%s\n' "$line" > "$control/control.rs"
		if [ -z "$("$rule" "$control/control.rs")" ]; then
			echo "$rule no longer catches a line it was written for, so what it reports about" \
				"this tree means nothing: $line" | complain
			echo x > "$control/failed"
		fi
	done
	if [ -e "$control/failed" ]; then
		rm -f "$control/failed"
		found=1
	fi
	hits=$("$rule" "$sources")
	if [ -n "$hits" ]; then
		printf '%s\n' "$hits" | sed "s|\$|: $complaint|" | complain
		found=1
	fi
	rules=$((rules + 1))
}

# A local named after how the value arrived, not what it holds. The four binding forms are
# `let`, a tuple, `if let`/`while let` and `for`. A closure parameter `|val|` cannot be told
# from a bitwise or without parsing.
placeholders='out|err|res|ret|val|tmp|data|thing|item|result'
rule_named_for_nothing() {
	# shellcheck disable=SC2086 # the file list is split on purpose, here and in every rule,
	# and `rust_sources` refuses a tracked path with whitespace in it
	grep -En "let ((mut )?\(?(mut )?($placeholders)( |:|=|,|\)|;)\
|\([^)]*, (mut )?($placeholders)[,)])\
|(if|while) let [A-Za-z_:]*\(+(mut )?($placeholders)[,)]\
|for (mut )?($placeholders) in " $1 || [ $? -eq 1 ]
}
enforce rule_named_for_nothing \
	'    let out = run();
    let (out, err) = pair();
    let mut tmp;
    if let Some(data) = read() {
    while let Some(item) = next() {
    for val in list {
    let res: Thing = one();
    let ret = two();
    let thing = three();
    let result = four();' \
	'a local named after how it arrived, not what it holds'

# A bool that does not read as a claim, so a call site cannot be checked by eye. `src/cli.rs`
# is exempt, because each field there is a long flag scripts use. A wire field renamed to pass
# keeps its old name with `#[serde(rename = ...)]`, because old archives still carry it.
claims='(is|are|has|have|was|were|can|should|must|will|does|did|uses|holds|needs|keeps|stops|starts|retires|assumes)'
visibility='(pub(\([^)]*\))? )?'
rule_bool_without_a_claim() {
	# shellcheck disable=SC2086 # split on purpose, see rule one
	grep -En "^[[:space:]]+${visibility}[a-z_]+: bool,$" $1 |
		grep -v '^src/cli.rs:' |
		grep -vE ":[[:space:]]+${visibility}([a-z_]+_)?${claims}_" |
		grep -vE ":[[:space:]]+${visibility}[a-z_]*ed: bool,$" || [ $? -eq 1 ]
}
enforce rule_bool_without_a_claim \
	'    pub delegate: bool,
    quiet: bool,
    pub(in crate::cmd) node: bool,' \
	'a bool has to read as a claim (is_, has_, was_, uses_, ...)'

# A function that reads the environment under a pure-sounding name, which no test can cover
# without setting a variable for the whole process. A constructor (`Self` in the return
# position) and a `#[test]` are exempt. The signature is collected across wrapped lines.
rule_env_reader_sounding_pure() {
	# shellcheck disable=SC2086
	for file in $1; do
		awk -v file="$file" '
			/^[[:space:]]*#\[test\]$/ { under_test = 1 }
			{
				if ($0 ~ /^[[:space:]]*(pub(\([^)]*\))? )?(const |unsafe |async )*fn [a-z_]+/) {
					match($0, /fn [a-z_]+/)
					name = substr($0, RSTART + 3, RLENGTH - 3)
					signature = $0
					is_test = under_test
					under_test = 0
					collecting = (index($0, "{") == 0 && index($0, ";") == 0)
				} else if (collecting) {
					signature = signature " " $0
					if (index($0, "{") || index($0, ";")) collecting = 0
				}
				if ($0 ~ /env::var/) {
					if (name == "") next
					if (is_test) next
					if (signature ~ /->[^{]*Self/) next
					if (name ~ /_from_env$/) next
					if (name ~ /^(read|probe|ask|require)_/) next
					printf "%s:%d: fn %s reads the environment\n", file, NR, name
				}
			}
		' "$file"
	done
}
enforce rule_env_reader_sounding_pure \
	'fn archive_dir() -> PathBuf { std::env::var("RAD_BACKUP_DIR").unwrap_or_default().into() }' \
	'so its name has to say so (read_, probe_, ask_, require_, _from_env)'

# A test staging its files straight into the shared temporary directory. `Scratch` names its
# directory after the process id and refuses an existing one, so two such tests refuse each
# other. Lines are squeezed of newlines, because rustfmt wraps the argument out of reach.
rule_scratch_in_the_shared_dir() {
	for file in $1; do
		case "$file" in src/key.rs) continue ;; esac
		squeezed=$(tr '\n' ' ' < "$file")
		if printf '%s' "$squeezed" | grep -qE 'Scratch::create\([^)]*temp_dir'; then
			echo "$file"
			continue
		fi
		for name in $(printf '%s' "$squeezed" |
			grep -oE 'let [a-z_]+ = (std::)?env::temp_dir\(\);' |
			sed 's/let \([a-z_]*\) =.*/\1/'); do
			if printf '%s' "$squeezed" | grep -qE "Scratch::create\(&?$name\)"; then
				echo "$file"
				break
			fi
		done
	done
}
enforce rule_scratch_in_the_shared_dir \
	'let scratch = Scratch::create(std::env::temp_dir().join("x"))?;
let parent = std::env::temp_dir(); let scratch = Scratch::create(&parent)?;' \
	'two tests cannot share one scratch parent; use TestScratch::create("name")'

# Two tests in one binary handed the same `TestScratch` name, so the second is refused.
# `src/` and `tests/` build separate binaries with separate pids, so names are counted per
# binary. Each grep ends in `|| true`, because `set -e` otherwise ends the subshell at a miss.
rule_duplicate_scratch_name() {
	for group in $(for file in $1; do binary_of "$file"; done | sort -u); do
		for file in $1; do
			[ "$(binary_of "$file")" = "$group" ] || continue
			tr '\n' ' ' < "$file" |
				grep -oE '(TestScratch|Fixture)::create[a-z_]*\([[:space:]]*"[^"]+"' || true
		done | sed 's/.*"\(.*\)"/\1/' | sort | uniq -d
	done
}
enforce rule_duplicate_scratch_name \
	'TestScratch::create("twice"); TestScratch::create_short("twice");' \
	'two tests ask for this scratch name, so one of them is refused'

# Two tests in one binary building their own `rad-backup-<label>-{}` directory under the shared
# temporary one with the same label. Nothing refuses the second, so they write into each other.
rule_duplicate_temp_label() {
	for group in $(for file in $1; do binary_of "$file"; done | sort -u); do
		for file in $1; do
			[ "$(binary_of "$file")" = "$group" ] || continue
			grep -oE '"rad-backup-[^"]*-\{\}' "$file" || true
		done | sed 's/"rad-backup-\(.*\)-{}/\1/' | sort | uniq -d
	done
}
enforce rule_duplicate_temp_label \
	'"rad-backup-twice-{}" "rad-backup-twice-{}"' \
	'two tests name their temporary directory this, so they share one'

# Something only unix has, reached from an item nothing gates to unix. `std::os::unix` resolves
# on linux however it is gated, so only the Windows job would fail. A gate covers the items
# nested deeper than the gated item, and ends at the next item no deeper than it.
rule_unix_without_a_gate() {
	# shellcheck disable=SC2086 # split on purpose, see rule one
	awk '
		FNR == 1 { gated = 0; pending = 0; gate_ind = 0 }
		/^[[:space:]]*#\[cfg\((not\(windows\)|unix|any\(unix)/ { pending = 1; next }
		/^[[:space:]]*(pub(\([^)]*\))? )?(async )?(unsafe )?(fn|mod|impl|struct|enum|trait) / {
			match($0, /^[[:space:]]*/); ind = RLENGTH
			if (pending) { gated = 1; gate_ind = ind; pending = 0 }
			else if (gated && ind <= gate_ind) gated = 0
		}
		/os::unix/ { if (!gated) print FILENAME ":" FNR }
	' $1
}
enforce rule_unix_without_a_gate \
	'    std::os::unix::fs::symlink(there, here).expect("a symlink is creatable");
    use std::os::unix::fs::PermissionsExt as _;' \
	'reaches for something only unix has from an item nothing gates to unix'

# A rule that never ran reports nothing, so the count of rules run is checked too
if [ "$rules" -ne 7 ]; then
	echo "the name check ran $rules of its 7 rules, so it checked less than it claims" | complain
	found=1
fi
exit "$found"
