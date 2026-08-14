# rad-backup. `just` lists these; `just <name>` runs one.

default:
    @just --list

# Everything CI runs, in the order that fails fastest.
check: fmt-check lint test

fmt:
    cargo fmt

fmt-check:
    cargo fmt --check

lint:
    cargo clippy --all-targets

test:
    cargo test

# Generate the man page, shell completions and the Debian changelog.
generated: build
    mkdir -p packaging/generated
    ./target/release/rad-backup man > packaging/generated/rad-backup.1
    ./target/release/rad-backup completions bash > packaging/generated/rad-backup.bash
    ./target/release/rad-backup completions zsh > packaging/generated/_rad-backup
    ./target/release/rad-backup completions fish > packaging/generated/rad-backup.fish
    printf 'rad-backup (%s-1) stable; urgency=medium\n\n  * Upstream release %s. The changelog for it is at\n    https://github.com/maninak/radicle-backup/blob/master/CHANGELOG.md\n\n -- Konstantinos Maninakis <info@radicle.tools>  %s\n' "$(just version)" "$(just version)" "$(just rfc-date)" > packaging/generated/changelog.Debian

# The version in Cargo.toml, which is the one every artefact is named after.
version:
    @grep -m1 '^version' Cargo.toml | cut -d'"' -f2

# The one timestamp every generated artefact uses: SOURCE_DATE_EPOCH if the caller set one,
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

# Run lintian over the package. The suppressed tag is about uploading to Debian itself.
lint-deb: deb
    lintian --suppress-tags initial-upload-closes-no-bugs target/debian/*.deb

# Build the release tarball for one target, as CI does.
dist target=`rustc -vV | sed -n 's|host: ||p'`: generated
    cargo build --release --target {{target}}
    mkdir -p dist
    tar -czf dist/rad-backup-{{target}}.tar.gz -C target/{{target}}/release rad-backup
    cd dist && sha256sum rad-backup-{{target}}.tar.gz >> sha256sums.txt

# Install into ~/.local/bin with completions and the man page.
install-local: generated
    install -Dm755 target/release/rad-backup ~/.local/bin/rad-backup
    install -Dm644 packaging/generated/rad-backup.1 ~/.local/share/man/man1/rad-backup.1
    install -Dm644 packaging/generated/rad-backup.bash ~/.local/share/bash-completion/completions/rad-backup
    install -Dm644 packaging/generated/_rad-backup ~/.local/share/zsh/site-functions/_rad-backup
    # No backticks in this message: just evaluates them as a command, and the one that reads
    # naturally here would have run a real backup of the caller's home.
    @echo "installed; 'rad backup' works once ~/.local/bin is on PATH"

clean:
    cargo clean
    rm -rf packaging/generated dist
