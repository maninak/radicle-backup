#!/usr/bin/env sh

# Five naming rules a reviewer kept having to enforce by hand.
#
# None of them is a matter of taste. A local called `out` next to one called `err` reads as a
# pair when one is a process and the other a file handle; `if record.delegate` cannot be
# checked by eye because it could as easily mean "has a delegate"; and a function that reads
# the environment behind a pure-sounding name cannot be tested without setting a variable in
# the process every other test shares. All three were found across the whole tree in one
# sweep, so all three are worth a gate rather than another sweep later.
#
# Shell-only, like the audit map, so it costs nothing on any of the three CI platforms. CI
# spells this out itself, so a rule added here has to be added there too.

set -eu

# shellcheck source=ci/lib.sh
. "$(dirname "$0")/lib.sh"

found=0
rules=0

# Built once and read by every rule below, so a rule that reads nothing cannot report a pass
# while the count at the bottom still says all of them ran.
sources=$(rust_sources "no name was checked")

# A local named after how the value arrived rather than what it holds. Every one of these
# in this tree turned out to have a real name waiting: `stdout`, `stderr`, `printed`,
# `finished`, `said`, `read_back`, `ran`.
#
# The tuple shapes are spelled out beside the plain one: `let (out, err) = ...` is the same
# name arriving through a binding the single-name pattern does not see, and the integration
# suite had seventy-two of them while this rule read only `src/`.
placeholders='out|err|res|ret|val|tmp|data|thing|item|result'
named_for_nothing=$(grep -En \
	"let ((mut )?\(?(mut )?($placeholders)( |:|=|,|\))|\([^)]*, (mut )?($placeholders)[,)])" \
	$sources || true)
if [ -n "$named_for_nothing" ]; then
	echo "$named_for_nothing" | sed 's/$/: a local named after how it arrived, not what it holds/' | complain
	found=1
fi
rules=$((rules + 1))

# A bool that does not read as a claim, so a call site cannot be checked by eye.
#
# `src/cli.rs` is exempt: a field there IS the long flag clap derives from it, so its name
# belongs to the command line and renaming one breaks somebody's script. A field that goes
# on the wire is renamed here and pinned there with `#[serde(rename = ...)]`, because an
# archive is read by versions that were never built.
claims='(is|are|has|have|was|were|can|should|must|will|does|did|uses|holds|needs|keeps|stops|starts|retires|assumes)'
visibility='(pub(\([a-z]+\))? )?'
not_a_claim=$(grep -En "^[[:space:]]+${visibility}[a-z_]+: bool,$" $sources \
	| grep -v '^src/cli.rs:' \
	| grep -vE ":[[:space:]]+${visibility}([a-z_]+_)?${claims}_" || true)
if [ -n "$not_a_claim" ]; then
	echo "$not_a_claim" | sed 's/$/: a bool has to read as a claim (is_, has_, was_, uses_, ...)/' | complain
	found=1
fi
rules=$((rules + 1))

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
env_readers=$(for file in $sources; do
	awk -v file="$file" '
		/^[[:space:]]*#\[test\]$/ { under_test = 1 }
		{
			if ($0 ~ /^[[:space:]]*(pub(\([a-z]+\))? )?(const |unsafe |async )*fn [a-z_]+/) {
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
				if (is_test) next
				if (signature ~ /->[^{]*Self/) next
				if (name ~ /_from_env$/) next
				if (name ~ /^(read|probe|ask|require)_/) next
				printf "%s:%d: fn %s reads the environment\n", file, NR, name
			}
		}
	' "$file"
done)
if [ -n "$env_readers" ]; then
	echo "$env_readers" | sed 's/$/, so its name has to say so (read_, probe_, ask_, require_, _from_env)/' | complain
	found=1
fi
rules=$((rules + 1))

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
shared_scratch=$(for file in $sources; do
	case "$file" in src/key.rs) continue ;; esac
	if tr '\n' ' ' < "$file" | grep -qE 'Scratch::create\([^)]*temp_dir'; then
		echo "$file"
	fi
done)
if [ -n "$shared_scratch" ]; then
	echo "$shared_scratch" | sed 's/$/: two tests cannot share one scratch parent; use TestScratch::create("name")/' | complain
	found=1
fi
rules=$((rules + 1))

# Two tests handed the same name share one parent directory, and `TestScratch` refuses the
# second: the interleaving-dependent failure rule four exists to stop, one layer further
# in. Names squeezed of newlines for the same reason rule four is.
#
# `|| true` because `set -e` ends the whole subshell at the first file with no match, which
# is most of them: the list came back holding whatever had been collected before it, and
# the rule reported a clean tree over a deliberate duplicate.
duplicate_scratch=$(for file in $sources; do
	tr '\n' ' ' < "$file" | grep -oE '(TestScratch|Fixture)::create\([[:space:]]*"[^"]+"' || true
done | sed 's/.*"\(.*\)"/\1/' | sort | uniq -d)
if [ -n "$duplicate_scratch" ]; then
	echo "$duplicate_scratch" | sed 's/$/: two tests ask for this scratch name, so one of them is refused/' | complain
	found=1
fi
rules=$((rules + 1))

# The same collision one layer out. A test that builds its own directory under the shared
# temporary one, rather than going through `Scratch`, gets no refusal at all: two of them
# sharing a label simply write into each other, which is the same interleaving-dependent
# failure with nothing said. Rules four and five cannot see this shape, because there is no
# `Scratch::create` on the line to anchor on.
#
# The label is everything between `rad-backup-` and the process id the name ends with, so
# `rad-backup-state-{}` and `rad-backup-state-locked-{}` are two labels and not one.
duplicate_label=$(for file in $sources; do
	grep -oE '"rad-backup-[^"]*-\{\}' "$file" || true
done | sed 's/"rad-backup-\(.*\)-{}/\1/' | sort | uniq -d)
if [ -n "$duplicate_label" ]; then
	echo "$duplicate_label" | sed 's/$/: two tests name their temporary directory this, so they share one/' | complain
	found=1
fi
rules=$((rules + 1))

# Zero rules run means the recipe stopped doing anything, not that the tree is clean.
if [ "$rules" -ne 6 ]; then
	echo "the name check ran $rules of its 6 rules, so it checked less than it claims" | complain
	found=1
fi
exit "$found"
