# rad-backup. `just` lists these; `just <name>` runs one.

default:
    @just --list

# The workflow runs these same `ci/` gates, and `ci/pins.sh` holds the two lists equal

# What CI runs on every push, in the order that fails fastest
check: fmt-check audit-map names messages shell pins lint nonunix test

# Every file SECURITY.md sends a reviewer to still exists
audit-map:
    ci/audit-map.sh

# No user-facing message has a run of spaces left by a dropped line continuation
messages:
    ci/messages.sh

# Seven naming and gating rules over the Rust tree
names:
    ci/names.sh

# Every tracked shell script through shellcheck
shell:
    ci/shell.sh

# Facts written in several files still agree
pins:
    ci/pins.sh

# Fix a refusal with `cargo update -p <crate> --precise <older>` and rerun only the last line,
# because `just deps` would bump the crate straight back

# Bump crates, list stale actions, then refuse any crate under a week old
deps:
    cargo update --verbose
    -./.github/outdated-action-pins.sh
    ./.github/check-lockfile-age.py --base HEAD

# Compile the suite the way a target that is not unix sees it
nonunix:
    ci/nonunix.sh

fmt:
    cargo fmt

fmt-check:
    cargo fmt --check

# `--locked` and `-D warnings` match CI, so a widened Cargo.toml requirement or a warning fails
# here too. RUSTFLAGS splits on whitespace, which is safe here because neither word is a path.

# Clippy over every target, as CI runs it
lint:
    RUSTFLAGS="-D warnings" cargo clippy --all-targets --locked

test:
    RUSTFLAGS="-D warnings" cargo test --locked

# Generate the man page, shell completions and the Debian changelog
generated: build
    mkdir -p packaging/generated
    ./target/release/rad-backup man > packaging/generated/rad-backup.1
    ./target/release/rad-backup completions bash > packaging/generated/rad-backup.bash
    ./target/release/rad-backup completions zsh > packaging/generated/_rad-backup
    ./target/release/rad-backup completions fish > packaging/generated/rad-backup.fish
    # `rad restore` is the same binary, and a roff include makes `man rad-restore` answer.
    # Windows cannot make the link without developer mode, so the failure is reported and the
    # release carries on.
    ln -sfn rad-backup packaging/generated/rad-restore \
        || echo "no rad-restore symlink on this platform; a packager must create it" >&2
    printf '.so man1/rad-backup.1\n' > packaging/generated/rad-restore.1
    printf 'radicle-backup (%s-1) stable; urgency=medium\n\n  * Upstream release %s. The changelog for it is at\n    https://github.com/maninak/radicle-backup/blob/master/CHANGELOG.md\n\n -- Konstantinos Maninakis <info@radicle.tools>  %s\n' "$(just version)" "$(just version)" "$(just rfc-date)" > packaging/generated/changelog.Debian

# The version in Cargo.toml, which names every artifact
version:
    @grep -m1 '^version' Cargo.toml | cut -d'"' -f2

# Reading the clock would make two builds of one commit produce two different .deb files

# The timestamp every generated artifact uses: SOURCE_DATE_EPOCH, else the commit's time
epoch:
    @echo "${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct 2>/dev/null || echo 0)}"

# UTC keeps the builder's timezone out of the package. GNU and BSD `date` spell "this epoch
# second" differently, and macOS builds run this too.

# The epoch as an RFC 2822 date in UTC, the format a Debian changelog requires
rfc-date:
    @TZ=UTC date -R -d "@$(just epoch)" 2>/dev/null || TZ=UTC date -R -r "$(just epoch)"

# Build twice from scratch and prove the two binaries are the same file
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

# A release build with every source of build-machine noise removed
build-repro:
    #!/usr/bin/env bash
    set -euo pipefail
    export SOURCE_DATE_EPOCH="$(just epoch)"
    # CARGO_ENCODED_RUSTFLAGS, because RUSTFLAGS splits on whitespace and a checkout path with
    # a space in it would break the flags
    export CARGO_ENCODED_RUSTFLAGS="$(printf -- '--remap-path-prefix=%s=/build\x1f--remap-path-prefix=%s=/cargo' "$PWD" "${CARGO_HOME:-$HOME/.cargo}")"
    cargo build --release --locked

build:
    cargo build --release

# Build a .deb of the working tree
deb: generated
    cargo deb --no-build

# Build an .rpm of the working tree
rpm: generated
    cargo generate-rpm

# Run lintian over the package this repository builds natively
lint-deb: deb
    just lint-deb-at target/debian

# The suppressed tags, in order. This package is not uploaded to Debian. A musl build is
# static by design, and lintian grades that an error on a foreign architecture. A static-pie
# binary is an ET_DYN ELF, which lintian reads as a shared library with no dependencies.

# Run lintian over a package built anywhere, which is how the release checks a cross-built one
lint-deb-at dir:
    lintian --suppress-tags initial-upload-closes-no-bugs \
        --suppress-tags statically-linked-binary \
        --suppress-tags shared-library-lacks-prerequisites \
        {{dir}}/*.deb

# Build the release tarball for one target, as CI does
dist target=`rustc -vV | sed -n 's|host: ||p'`: generated
    cargo build --release --target {{target}}
    mkdir -p dist
    tar -czf dist/rad-backup-{{target}}.tar.gz -C target/{{target}}/release rad-backup
    cd dist && sha256sum rad-backup-{{target}}.tar.gz >> sha256sums.txt

# Install into ~/.local/bin with completions and the man page
install-local: generated
    install -Dm755 target/release/rad-backup ~/.local/bin/rad-backup
    ln -sfn rad-backup ~/.local/bin/rad-restore
    install -Dm644 packaging/generated/rad-backup.1 ~/.local/share/man/man1/rad-backup.1
    install -Dm644 packaging/generated/rad-backup.bash ~/.local/share/bash-completion/completions/rad-backup
    install -Dm644 packaging/generated/_rad-backup ~/.local/share/zsh/site-functions/_rad-backup
    # No backticks in this message, because they run as a command, and the natural one here
    # would run a real backup of the caller's home
    @echo "installed; 'rad backup' works once ~/.local/bin is on PATH"

clean:
    cargo clean
    rm -rf packaging/generated dist

# Pushing the tag starts the publish, and crates.io cannot take one back, so this stops
# before the push

# Bump the version, stamp the changelog and tag the release locally
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
    # An empty [Unreleased] would make the release page quote a blank section
    awk '/^## \[Unreleased\]/ { p = 1; next } p && /^## / { exit } p && NF { hit = 1 }
         END { exit !hit }' CHANGELOG.md \
        || { echo "CHANGELOG.md has no '## [Unreleased]' section with anything in it. Write" \
                  "what changed there first: a release renames that heading and leaves none" \
                  "behind, so the next change to land is what opens the next one." >&2; exit 1; }

    # A failure past this point puts the four files back, so the next run passes its own
    # clean-tree check
    trap 'git checkout -- Cargo.toml Cargo.lock CHANGELOG.md ARCHIVE-FORMAT.md' ERR

    # `sed -i` spells its backup suffix differently on GNU and BSD
    awk -v v="$v" '!done && /^version = / { print "version = \"" v "\""; done = 1; next } { print }' \
        Cargo.toml > Cargo.toml.next && mv Cargo.toml.next Cargo.toml
    # --offline, so a release bump pulls in no dependency update
    cargo update --workspace --offline
    # [Unreleased] becomes the released heading, and the next change to land adds it back.
    # release.yml greps for the `## [<version>]` shape.
    awk -v v="$v" -v day="$(date -u +%F)" \
        '!done && /^## \[Unreleased\]/ { print "## [" v "] - " day; done = 1; next } { print }' \
        CHANGELOG.md > CHANGELOG.md.next && mv CHANGELOG.md.next CHANGELOG.md
    # Two package versions in ARCHIVE-FORMAT.md derive from nothing, the version-history row
    # for the current format and the sample manifest. The format version is left alone.
    awk -v v="$v" '/^\| *[0-9]+ *\| *unreleased *\|/ { sub(/unreleased/, v) } { print }' \
        ARCHIVE-FORMAT.md > ARCHIVE-FORMAT.md.next && mv ARCHIVE-FORMAT.md.next ARCHIVE-FORMAT.md
    awk -v v="$v" '/"tool": *\{ *"name": *"rad-backup", *"version":/ {
            sub(/"version": *"[^"]*"/, "\"version\": \"" v "\"") } { print }' \
        ARCHIVE-FORMAT.md > ARCHIVE-FORMAT.md.next && mv ARCHIVE-FORMAT.md.next ARCHIVE-FORMAT.md

    just check
    # The commit takes these four, so a later failure must not put them back
    trap - ERR
    git add Cargo.toml Cargo.lock CHANGELOG.md ARCHIVE-FORMAT.md
    git commit -m "chore: release $v"
    git tag -a "v$v" -m "v$v"
    echo
    echo "v$v is committed and tagged, and nothing has left this machine. Read it with"
    echo "'git show v$v', then release with:"
    echo "    git push origin master && git push origin v$v && git push github master && git push github v$v"
