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
    printf 'rad-backup (%s-1) stable; urgency=medium\n\n  * Upstream release %s. The changelog for it is at\n    https://github.com/maninak/radicle-backup/blob/master/CHANGELOG.md\n\n -- Konstantinos Maninakis <info@radicle.tools>  %s\n' "$(just version)" "$(just version)" "$(date -R)" > packaging/generated/changelog.Debian

# The version in Cargo.toml, which is the one every artefact is named after.
version:
    @grep -m1 '^version' Cargo.toml | cut -d'"' -f2

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
    @echo "installed; `rad backup` works once ~/.local/bin is on PATH"

clean:
    cargo clean
    rm -rf packaging/generated dist
