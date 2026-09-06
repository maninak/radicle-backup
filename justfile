# rad-backup. `just` lists these; `just <name>` runs one.

default:
    @just --list

# What CI runs on every push, in the order that fails fastest. CI spells the cargo steps
# out itself rather than calling this, so a gate added here has to be added there too.
check: fmt-check audit-map names messages lint nonunix test

# Every file SECURITY.md sends a reviewer to still exists.
#
# The audit map is the one document that promises "here is where the secrets are handled",
# and a rename breaks it silently: renaming `archive.rs` to `container.rs` left a reviewer
# following the map to a file that was not there, which is worse than no map at all.
audit-map:
    #!/usr/bin/env sh
    set -eu
    missing=0
    rows=0
    # Every backticked `src/...` in the file, not just the first of a row: the anchored form
    # checked one path per line, so a row naming two files was half unchecked.
    for path in $(grep -o '`src/[^`]*`' SECURITY.md | tr -d '`'); do
    	if [ ! -e "$path" ]; then
    		echo "SECURITY.md sends a reviewer to $path, which is not there" >&2
    		missing=1
    	fi
    	rows=$((rows + 1))
    done
    # Zero rows means the table stopped matching the pattern, not that the map is clean. A
    # gate that passes while checking nothing reports a safety it is not providing.
    if [ "$rows" -eq 0 ]; then
    	echo "the audit map in SECURITY.md matched no rows, so nothing was checked" >&2
    	missing=1
    fi
    exit "$missing"

# No user-facing message carries a run of spaces where a line continuation should be.
#
# `cargo fmt` will not touch the inside of a literal, so a message hand-joined from two lines
# keeps whatever whitespace the join left and reaches the user as a hole in the middle of a
# sentence. One had been printing that way in `restore` for as long as the warning existed.
#
# Line-based, so it catches the run of spaces WITHIN one source line, which is the shape the
# real defect had. A literal continued to the next line with the trailing `\` dropped is a
# different shape and this does not see it: telling a literal that spans lines from a comment,
# a char literal or a raw string needs a Rust parser, and a gate that guesses would fire on
# the templates this tool ships. Revisit if that shape ever occurs.
#
# The pattern deliberately wants a word character on both sides of the run, so the indentation
# inside the multi-line templates this tool ships (`RESTORE.md`, `restore.sh`, the systemd
# units, the recovery sheet) is not a hit.
messages:
    #!/usr/bin/env sh
    set -eu
    gap='"[^"]*[[:alnum:],.:;)]   +[[:alnum:]]'
    # The pattern is tried against a line known to be bad first. A gate nobody has watched
    # fail reports a safety it may not be providing, and this one is a single regex.
    if ! printf '%s\n' 'x("a node running: the run                      that took it")' \
    	| grep -Eq "$gap"; then
    	echo "the message check no longer catches a gap it was written for" >&2
    	exit 1
    fi
    gaps=$(grep -rEn "$gap" --include='*.rs' src/ tests/ || true)
    if [ -n "$gaps" ]; then
    	echo "$gaps" | sed 's/$/: a run of spaces in a message, so a line continuation was dropped/' >&2
    	exit 1
    fi

# Three naming rules a reviewer kept having to enforce by hand.
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
names:
    #!/usr/bin/env sh
    set -eu
    found=0
    rules=0

    # A local named after how the value arrived rather than what it holds. Every one of these
    # in this tree turned out to have a real name waiting: `stdout`, `stderr`, `printed`,
    # `finished`, `said`, `read_back`.
    placeholders='out|err|res|ret|val|tmp|data|thing|item|result'
    named_for_nothing=$(grep -rEn "let (mut )?($placeholders)( |:|=)" src/ || true)
    if [ -n "$named_for_nothing" ]; then
    	echo "$named_for_nothing" | sed 's/$/: a local named after how it arrived, not what it holds/' >&2
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
    not_a_claim=$(grep -rEn "^[[:space:]]+${visibility}[a-z_]+: bool,$" src/ \
    	| grep -v '^src/cli.rs:' \
    	| grep -vE ":[[:space:]]+${visibility}([a-z_]+_)?${claims}_" || true)
    if [ -n "$not_a_claim" ]; then
    	echo "$not_a_claim" | sed 's/$/: a bool has to read as a claim (is_, has_, was_, uses_, ...)/' >&2
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
    env_readers=$(for file in $(git ls-files 'src/' | grep '\.rs$'); do
    	awk -v file="$file" '
    		{
    			if ($0 ~ /^[[:space:]]*(pub(\([a-z]+\))? )?(const |unsafe |async )*fn [a-z_]+/) {
    				match($0, /fn [a-z_]+/)
    				name = substr($0, RSTART + 3, RLENGTH - 3)
    				signature = $0
    				collecting = (index($0, "{") == 0 && index($0, ";") == 0)
    			} else if (collecting) {
    				signature = signature " " $0
    				if (index($0, "{") || index($0, ";")) collecting = 0
    			}
    			if ($0 ~ /env::var/) {
    				if (signature ~ /->[^{]*Self/) next
    				if (name ~ /_from_env$/) next
    				if (name ~ /^(read|probe|ask|require)_/) next
    				printf "%s:%d: fn %s reads the environment\n", file, NR, name
    			}
    		}
    	' "$file"
    done)
    if [ -n "$env_readers" ]; then
    	echo "$env_readers" | sed 's/$/, so its name has to say so (read_, probe_, ask_, require_, _from_env)/' >&2
    	found=1
    fi
    rules=$((rules + 1))

    # A test staging its files straight into the shared temporary directory. `Scratch` names
    # its directory after the process id alone and refuses one that is already there, and the
    # whole test binary is one process, so two such tests running at once refuse each other:
    # a failure that depends on how the runner interleaves them and names neither cause.
    # `TestScratch` exists for this and gives each test a parent of its own.
    shared_scratch=$(grep -rn 'Scratch::create(std::env::temp_dir()' src/ || true)
    if [ -n "$shared_scratch" ]; then
    	echo "$shared_scratch" | sed 's/$/: two tests cannot share one scratch parent; use TestScratch::create("name")/' >&2
    	found=1
    fi
    rules=$((rules + 1))

    # Zero rules run means the recipe stopped doing anything, not that the tree is clean.
    if [ "$rules" -ne 4 ]; then
    	echo "the name check ran $rules of its 4 rules, so it checked less than it claims" >&2
    	found=1
    fi
    exit "$found"

# Compile the suite the way a target that is not unix sees it.
#
# A helper without `#[cfg(unix)]` that calls one which has it builds here and fails on
# Windows, and that has now reached CI three times. There is no local windows build to catch
# it with, because zstd's C code wants `lib.exe`, so this turns the gates off and compiles
# that instead. Roughly a second, because only the one test crate is recompiled.
#
# The file is rewritten in place and put back by the trap, so a failing compile or a Ctrl-C
# leaves the working tree as it found it.
nonunix:
    #!/usr/bin/env bash
    set -euo pipefail
    file=tests/end_to_end.rs
    saved=$(mktemp)
    cp "$file" "$saved"
    trap 'cp "$saved" "$file"; rm -f "$saved"' EXIT
    # Zero gates means the pattern stopped matching, not that there is nothing to check.
    gates=$(grep -c '^[[:space:]]*#\[cfg(unix)\]$' "$file" || true)
    if [ "$gates" -eq 0 ]; then
    	echo "no '#[cfg(unix)]' gates matched in $file, so nothing was checked" >&2
    	exit 1
    fi
    # Indented gates count: a method inside an `impl` carries one, and leaving it while its
    # caller goes reports the caller's absence as dead code, which is this check inventing a
    # failure windows would never see.
    #
    # The second expression drops `#[cfg(not(unix))]` so its item compiles unconditionally.
    # A platform pair has two arms, and switching only the unix one off would take both away,
    # reporting an absence windows would never see.
    #
    # Reading the saved copy and writing the file, rather than `sed -i`, which spells its
    # backup suffix differently on GNU and BSD and so breaks on the macOS checkouts.
    sed -e 's/^\([[:space:]]*\)#\[cfg(unix)\]$/\1#[cfg(all(unix, any()))]/' \
    	-e '/^[[:space:]]*#\[cfg(not(unix))\]$/d' "$saved" > "$file"
    RUSTFLAGS="-D warnings" cargo clippy --all-targets --locked

fmt:
    cargo fmt

fmt-check:
    cargo fmt --check

# `--locked` on both, matching CI: a Cargo.toml requirement widened without updating
# Cargo.lock is an error here rather than a silent re-resolve that only CI notices.
#
# `-D warnings` likewise, because CI sets it for every job and this recipe claims to be what
# CI runs. Without it an unused import passed here and failed there, which is the worst thing
# a local gate can do: report a safety it is not providing. Passing it through RUSTFLAGS is
# safe despite the splitting note in `repro` below, because neither word is a path.
lint:
    RUSTFLAGS="-D warnings" cargo clippy --all-targets --locked

test:
    RUSTFLAGS="-D warnings" cargo test --locked

# Generate the man page, shell completions and the Debian changelog.
generated: build
    mkdir -p packaging/generated
    ./target/release/rad-backup man > packaging/generated/rad-backup.1
    ./target/release/rad-backup completions bash > packaging/generated/rad-backup.bash
    ./target/release/rad-backup completions zsh > packaging/generated/_rad-backup
    ./target/release/rad-backup completions fish > packaging/generated/rad-backup.fish
    # `rad restore` is the same binary under the name someone in trouble reaches for, and a
    # roff include so `man rad-restore` answers rather than saying there is no such page.
    # Windows cannot make this link without developer mode, and has no man pages to read the
    # include either, so it says so and carries on rather than failing the whole release.
    ln -sfn rad-backup packaging/generated/rad-restore \
        || echo "no rad-restore symlink on this platform; a packager must create it" >&2
    printf '.so man1/rad-backup.1\n' > packaging/generated/rad-restore.1
    printf 'radicle-backup (%s-1) stable; urgency=medium\n\n  * Upstream release %s. The changelog for it is at\n    https://github.com/maninak/radicle-backup/blob/master/CHANGELOG.md\n\n -- Konstantinos Maninakis <info@radicle.tools>  %s\n' "$(just version)" "$(just version)" "$(just rfc-date)" > packaging/generated/changelog.Debian

# The version in Cargo.toml, which is the one every artifact is named after.
version:
    @grep -m1 '^version' Cargo.toml | cut -d'"' -f2

# The one timestamp every generated artifact uses: SOURCE_DATE_EPOCH if the caller set one,
# else the commit being built. Reading the clock instead would make two builds of one commit
# produce two different .deb files.
epoch:
    @echo "${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || echo 0)}"

# That same instant as an RFC 2822 date, which is the only format a Debian changelog accepts.
# UTC, because the builder's timezone would otherwise end up in the package. GNU and BSD
# `date` spell "this epoch second" differently, and macOS builds run this too.
rfc-date:
    @TZ=UTC date -R -d "@$(just epoch)" 2>/dev/null || TZ=UTC date -R -r "$(just epoch)"

# Build twice from scratch and prove the two binaries are the same file.
repro:
    #!/usr/bin/env bash
    set -euo pipefail
    first=$(mktemp -d) && second=$(mktemp -d)
    CARGO_TARGET_DIR=$first just build-repro
    CARGO_TARGET_DIR=$second just build-repro
    a=$(sha256sum "$first/release/rad-backup" | cut -d" " -f1)
    b=$(sha256sum "$second/release/rad-backup" | cut -d" " -f1)
    rm -rf "$first" "$second"
    echo "first  $a"
    echo "second $b"
    [ "$a" = "$b" ] && echo "reproducible" || { echo "NOT reproducible" >&2; exit 1; }

# A release build with every source of build-machine noise removed.
build-repro:
    #!/usr/bin/env bash
    set -euo pipefail
    export SOURCE_DATE_EPOCH="$(just epoch)"
    # CARGO_ENCODED_RUSTFLAGS, not RUSTFLAGS: the latter is split on whitespace, so a checkout
    # in a directory whose name has a space in it would break the flags rather than the build,
    # which is a confusing way to find out.
    export CARGO_ENCODED_RUSTFLAGS="$(printf -- '--remap-path-prefix=%s=/build\x1f--remap-path-prefix=%s=/cargo' "$PWD" "${CARGO_HOME:-$HOME/.cargo}")"
    cargo build --release --locked

build:
    cargo build --release

# Build a .deb of the working tree.
deb: generated
    cargo deb --no-build

# An .rpm of the same.
rpm: generated
    cargo generate-rpm

# Run lintian over the package this repository builds natively.
lint-deb: deb
    just lint-deb-at target/debian

# Run lintian over a package built anywhere, which is how the release checks a cross-built one.
#
# The suppressed tags, in order. Uploading to Debian itself is not what this is. A static
# binary is the entire point of a musl build, which lintian grades as an error on a foreign
# architecture and a warning on the native one, so one release built the same package twice
# and only the arm64 half failed. And a static-pie binary is an ET_DYN ELF, which lintian
# reads as a shared library and then faults for declaring no dependencies, which is the same
# fact about the same build said a third way.
lint-deb-at dir:
    lintian --suppress-tags initial-upload-closes-no-bugs \
        --suppress-tags statically-linked-binary \
        --suppress-tags shared-library-lacks-prerequisites \
        {{dir}}/*.deb

# Build the release tarball for one target, as CI does.
dist target=`rustc -vV | sed -n 's|host: ||p'`: generated
    cargo build --release --target {{target}}
    mkdir -p dist
    tar -czf dist/rad-backup-{{target}}.tar.gz -C target/{{target}}/release rad-backup
    cd dist && sha256sum rad-backup-{{target}}.tar.gz >> sha256sums.txt

# Install into ~/.local/bin with completions and the man page.
install-local: generated
    install -Dm755 target/release/rad-backup ~/.local/bin/rad-backup
    ln -sfn rad-backup ~/.local/bin/rad-restore
    install -Dm644 packaging/generated/rad-backup.1 ~/.local/share/man/man1/rad-backup.1
    install -Dm644 packaging/generated/rad-backup.bash ~/.local/share/bash-completion/completions/rad-backup
    install -Dm644 packaging/generated/_rad-backup ~/.local/share/zsh/site-functions/_rad-backup
    # No backticks in this message: just evaluates them as a command, and the one that reads
    # naturally here would have run a real backup of the caller's home.
    @echo "installed; 'rad backup' works once ~/.local/bin is on PATH"

clean:
    cargo clean
    rm -rf packaging/generated dist

# Everything a release needs before the tag exists, which is the part CI cannot do for itself:
# the version bump, the changelog section CI quotes, and the tag. Stops there. Pushing the tag
# is what starts the publish, and crates.io cannot take one back, so that stays a separate act.
release version:
    #!/usr/bin/env bash
    set -euo pipefail
    v="{{version}}"
    printf '%s' "$v" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$' \
        || { echo "not a release version: $v, expected MAJOR.MINOR.PATCH[-prerelease]" >&2; exit 1; }
    [ "$(git branch --show-current)" = master ] \
        || { echo "releases are cut from master" >&2; exit 1; }
    git diff --quiet && git diff --cached --quiet \
        || { echo "uncommitted changes; the release commit carries only the bump" >&2; exit 1; }
    ! git rev-parse -q --verify "refs/tags/v$v" > /dev/null \
        || { echo "v$v already exists as a tag" >&2; exit 1; }
    # An empty [Unreleased] is a release with nothing in it, and the release page would quote
    # the blank section rather than say so.
    awk '/^## \[Unreleased\]/ { p = 1; next } p && /^## / { exit } p && NF { hit = 1 }
         END { exit !hit }' CHANGELOG.md \
        || { echo "CHANGELOG.md has no '## [Unreleased]' section with anything in it. Write" \
                  "what changed there first: a release renames that heading and leaves none" \
                  "behind, so the next change to land is what opens the next one." >&2; exit 1; }

    # A failure past this point puts the four files back, so the next run starts where this
    # one did instead of failing its own clean-tree check on the half-release it left behind.
    trap 'git checkout -- Cargo.toml Cargo.lock CHANGELOG.md ARCHIVE-FORMAT.md' ERR

    # awk rather than `sed -i`, which spells its backup suffix differently on GNU and BSD.
    awk -v v="$v" '!done && /^version = / { print "version = \"" v "\""; done = 1; next } { print }' \
        Cargo.toml > Cargo.toml.next && mv Cargo.toml.next Cargo.toml
    # --offline so a release bump cannot also drag in a dependency update nobody asked for.
    cargo update --workspace --offline
    # [Unreleased] becomes the released heading, and nothing takes its place: a shipped
    # changelog should not open with a heading that has nothing under it. The first change to
    # land after a release adds it back. `## [<version>]` is the shape release.yml greps for.
    awk -v v="$v" -v day="$(date -u +%F)" \
        '!done && /^## \[Unreleased\]/ { print "## [" v "] - " day; done = 1; next } { print }' \
        CHANGELOG.md > CHANGELOG.md.next && mv CHANGELOG.md.next CHANGELOG.md
    # Two package versions in ARCHIVE-FORMAT.md derive from nothing: the version-history row
    # naming the release that first shipped the current format, and the sample manifest, which
    # shows what this build writes. The format version is a different number and is left alone.
    awk -v v="$v" '/^\| *[0-9]+ *\| *unreleased *\|/ { sub(/unreleased/, v) } { print }' \
        ARCHIVE-FORMAT.md > ARCHIVE-FORMAT.md.next && mv ARCHIVE-FORMAT.md.next ARCHIVE-FORMAT.md
    awk -v v="$v" '/"tool": *\{ *"name": *"rad-backup", *"version":/ {
            sub(/"version": *"[^"]*"/, "\"version\": \"" v "\"") } { print }' \
        ARCHIVE-FORMAT.md > ARCHIVE-FORMAT.md.next && mv ARCHIVE-FORMAT.md.next ARCHIVE-FORMAT.md

    just check
    # The commit is about to take these four, so a failure after it must not put them back.
    trap - ERR
    git add Cargo.toml Cargo.lock CHANGELOG.md ARCHIVE-FORMAT.md
    git commit -m "chore: release $v"
    git tag -a "v$v" -m "v$v"
    echo
    echo "v$v is committed and tagged, and nothing has left this machine. Read it with"
    echo "'git show v$v', then release with:"
    echo "    git push origin master && git push origin v$v && git push github master && git push github v$v"
