#!/usr/bin/env sh

# Seven rules a reviewer kept having to enforce by hand.
#
# None of them is a matter of taste. A local called `out` next to one called `err` reads as a
# pair when one is a process and the other a file handle; `if record.delegate` cannot be
# checked by eye because it could as easily mean "has a delegate"; and a function that reads
# the environment behind a pure-sounding name cannot be tested without setting a variable in
# the process every other test shares. All three were found across the whole tree in one
# sweep, so all three are worth a gate rather than another sweep later.
#
# Shell-only, like the audit map, so it costs nothing on any of the three CI platforms. The
# workflow runs this same script, so a rule added here is added everywhere it runs.
#
# Every rule runs twice: over the tree, and over one line written to be caught. A pattern that
# has quietly stopped matching anything reports a clean tree in the very same words as a tree
# that is clean, and counting the rules that ran cannot tell those two apart. Changing one
# character of rule one's regex used to leave it reporting a pass over a file full of `out`.

set -eu

# shellcheck source=ci/lib.sh
. "$(dirname "$0")/lib.sh"

found=0
rules=0

# Built once and read by every rule below, so a rule that reads nothing cannot report a pass
# while the count at the bottom still says all of them ran.
sources=$(rust_sources "no name was checked")

control=$(mktemp -d)
trap 'rm -rf "$control"' EXIT

# Which binary a file is compiled into, which is its first path component: `src` builds the
# unit-test binary and `tests` the integration one. Rules five and six count within one of
# these rather than across the tree.
binary_of() {
	printf '%s' "$1" | awk -F/ '{ for (i = 1; i <= NF; i++) if ($i != "") { print $i; exit } }'
}

# One rule, over each line it must catch and then over the tree. Each rule is a function taking
# a whitespace-separated file list, which is safe to split because `rust_sources` refuses a
# tracked path with whitespace in it.
#
# Every control line is run on its own and every one has to be caught. One line proves only
# the one alternative it exercises: with a single control through `if let Some(data)`, half of
# rule one's regex could be misspelt and the control would still go green. So each shape the
# rule claims, and each word it claims to know, appears in a line of its own here.
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

# A local named after how the value arrived rather than what it holds. Every one of these
# in this tree turned out to have a real name waiting: `stdout`, `stderr`, `printed`,
# `finished`, `said`, `read_back`, `ran`.
#
# Four binding forms, because a name arrives through all of them and a rule that reads only
# `let x =` sees the least common one. `let (out, err) = ...` is the same name through a
# tuple; `if let Some(data) = ...` is the single commonest route a placeholder takes into
# Rust; `for item in ...` binds one per turn of the loop. A closure parameter is not here:
# `|val|` cannot be told from a bitwise or without parsing.
placeholders='out|err|res|ret|val|tmp|data|thing|item|result'
rule_named_for_nothing() {
	# shellcheck disable=SC2086 # the file list is split on purpose, here and in every rule:
	# `rust_sources` refuses a tracked path with whitespace in it, which is what makes it safe.
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

# A bool that does not read as a claim, so a call site cannot be checked by eye.
#
# `src/cli.rs` is exempt: a field there IS the long flag clap derives from it, so its name
# belongs to the command line and renaming one breaks somebody's script. A field that goes
# on the wire is renamed here and pinned there with `#[serde(rename = ...)]`, because an
# archive is read by versions that were never built.
#
# A past participle passes on its own: `encrypted`, `locked` and `restored` each read as a
# claim about the thing they sit on without a `was_` in front, and demanding one would rename
# perfectly legible fields for the sake of the pattern rather than the reader.
claims='(is|are|has|have|was|were|can|should|must|will|does|did|uses|holds|needs|keeps|stops|starts|retires|assumes)'
visibility='(pub(\([^)]*\))? )?'
rule_bool_without_a_claim() {
	# shellcheck disable=SC2086 # split on purpose; see rule three
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

# A function that reads the environment under a name that sounds pure. `archive_dir` was
# one, and it could not be tested at all: setting a variable to check its precedence sets
# it for every other test in the process. A constructor is exempt, told by `Self` in the
# RETURN position and not merely somewhere on the signature, because building this
# program's view of its environment is what one is for and the type name already says so.
#
# The signature is collected across the lines rustfmt wrapped it over, so a long
# constructor is not read as a plain function. `env::var` is matched however the module was
# brought into scope; `use std::env as e` would still slip past, which is a spelling
# nothing in this tree uses and no reviewer would let through.
#
# A `#[test]` is exempt. Nothing calls one, so there is no call site to mislead, and its
# name is a sentence about the behaviour under test that cannot also carry a `read_`.
#
# `pub(...)` takes anything inside the parentheses, `pub(in crate::cmd)` among them. Matching
# only `pub(crate)` meant a header the awk did not recognise was not treated as a header at
# all, and the function under it inherited the previous one's name and the previous one's
# exemption: a `read_`-prefixed neighbour above it made it invisible.
rule_env_reader_sounding_pure() {
	# The file list is split on purpose, here and in every rule: `rust_sources` refuses a
	# tracked path with whitespace in it, which is what makes that safe.
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

# A test staging its files straight into the shared temporary directory. `Scratch` names
# its directory after the process id alone and refuses one that is already there, and the
# whole test binary is one process, so two such tests running at once refuse each other:
# a failure that depends on how the runner interleaves them and names neither cause.
# `TestScratch` exists for this and gives each test a parent of its own.
#
# Read with the newlines squeezed out, because a line-based grep is evaded by rustfmt
# alone: a longer receiver wraps the argument onto its own line and the pattern stops
# matching, with nobody having decided anything. `key.rs` is where `TestScratch` itself
# reaches for the temporary directory, which is the one place that may.
#
# Two shapes, because the tree writes it both ways. Inline is the one this was written for;
# through a variable is the tree's own idiom, and the rule read past every one of them. Only
# a BARE `temp_dir()` counts through a variable: a labelled one, `temp_dir().join(...)`, is a
# parent of this test's own and is the ordinary way to write it here. Two tests sharing one
# label is a real collision, and rule six is what sees that.
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

# Two tests handed the same name share one parent directory, and `TestScratch` refuses the
# second: the interleaving-dependent failure rule four exists to stop, one layer further
# in. Names squeezed of newlines for the same reason rule four is.
#
# Counted within one binary and not across the tree. `src/` builds the unit-test binary and
# `tests/` builds the integration one, they run as two processes with two pids, and their
# helpers prefix differently as well, so one name in each is not a collision. Pooling them
# reported one and would have forced a rename that bought nothing.
#
# `|| true` where a file has no match, because `set -e` would otherwise end the whole subshell
# at the first one, which is most of them: the list came back holding whatever had been
# collected before it, and the rule reported a clean tree over a deliberate duplicate.
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

# The same collision one layer out. A test that builds its own directory under the shared
# temporary one, rather than going through `Scratch`, gets no refusal at all: two of them
# sharing a label simply write into each other, which is the same interleaving-dependent
# failure with nothing said. Rules four and five cannot see this shape, because there is no
# `Scratch::create` on the line to anchor on.
#
# The label is everything between `rad-backup-` and the process id the name ends with, so
# `rad-backup-state-{}` and `rad-backup-state-locked-{}` are two labels and not one. Per
# binary, for the reason rule five is.
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

# Something only unix has, reached from an item nothing gates to unix.
#
# `std::os::unix` resolves on the machine this is written on however it is gated, so the whole
# class compiles locally and fails on the Windows job, twenty minutes and a push later. The
# non-unix gate beside this one cannot see it either: it simulates the shape of the `cfg` tree
# by compiling for linux, where those paths exist. So this reads the gate rather than the
# compiler: an item carrying `#[cfg(unix)]` covers what is nested inside it, and anything else
# that says `os::unix` is a Windows build failure with a name and a line number.
#
# Indentation is what makes nesting work, because `#[cfg(unix)] mod platform` gates every
# function inside it and those are items in their own right. A gate ends at the next item no
# deeper than the one that carried it.
rule_unix_without_a_gate() {
	# shellcheck disable=SC2086 # split on purpose; see rule three
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

# Zero rules run means the recipe stopped doing anything, not that the tree is clean. Each
# rule above has proved it can still fail before this counts it, so this is the last of the
# three ways a gate lies: not running at all.
if [ "$rules" -ne 7 ]; then
	echo "the name check ran $rules of its 7 rules, so it checked less than it claims" | complain
	found=1
fi
exit "$found"
