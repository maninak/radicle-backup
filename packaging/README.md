# Packaging

What ships, how it is built, and what is not wired up yet. Every channel here is either working or honestly labelled as not.

| Channel | State | Built by |
|---|---|---|
| `.deb` (amd64, arm64) | Working | `just deb` locally, the `packages` job on a tag |
| Signed apt repository | Working | `packaging/apt/publish.sh`, run by the `apt` job |
| Tarballs (linux musl, macOS, x86_64 and aarch64) | Working | the `binaries` job |
| crates.io | Working | the `crate` job |
| `.rpm` | Metadata written, needs `cargo generate-rpm` in CI | `just rpm` locally |
| Homebrew | Template only, needs a tap repository | `packaging/homebrew/render.sh` |
| AUR | Template only, needs an AUR account and repository | `packaging/aur/render.sh` |

## The generated files

`packaging/generated/` holds the man page, the shell completions and the Debian changelog. They are built by `just generated`, never committed: the binary that ships is the one that describes itself, so a stale completion file is not a state this repository can get into.

## The apt repository

A static tree on the `gh-pages` branch, served by GitHub Pages, signed with a key held in the `APT_GPG_PRIVATE_KEY` secret. `Origin` and `Label` are both `radicle-tools`, which is what lets `unattended-upgrades` target it without also targeting everything else a machine has configured.

`publish.sh` rebuilds every index from the whole pool on every run rather than appending, because an index that has drifted from the pool gives apt clients a hash mismatch and no way to work out why.

To test the whole thing without pushing anywhere: point it at a local bare repository as `origin`, then let apt itself judge the result.

```sh
apt-get update -o Dir::Etc::sourcelist=<a sources.list with a file:// line> \
               -o Dir::State::Lists=<a scratch directory> ...
```

If apt verifies `InRelease` and fetches `Packages`, the repository is correct. Nothing else is proof.

## First-time setup

1. Generate a signing key that is used for nothing else:
   ```sh
   gpg --quick-generate-key "radicle.tools packages <info@radicle.tools>" default sign never
   gpg --armor --export-secret-keys <key id>   # into the APT_GPG_PRIVATE_KEY secret
   ```
2. Enable GitHub Pages for the repository, serving from the `gh-pages` branch, root.
3. Add `CARGO_REGISTRY_TOKEN` for crates.io.
4. Tag a release: `git tag v0.1.0 && git push --tags`.
