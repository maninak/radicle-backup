# Packaging

What ships, how it is built, and what is not wired up yet. Every channel here is either working or honestly labelled as not.

| Channel | State | Built by |
|---|---|---|
| `.deb` (amd64, arm64) | Working | `just deb` locally, the `packages` job on a tag |
| Signed apt repository | Working | `packaging/apt/publish.sh`, run by the `apt` job |
| Tarballs (linux musl, macOS, x86_64 and aarch64) | Working | the `binaries` job |
| Windows `.zip` (x86_64-msvc) | Working, with the caveats in the README | the `binaries` job |
| Signed `sha256sums.txt` | Working | `packaging/release/sign.sh`, run by the `binaries` job |
| Nix flake | Working | `nix build`, checked twice by the `nix` job |
| crates.io | Working | the `crate` job |
| `.rpm` | Metadata written, needs `cargo generate-rpm` in CI | `just rpm` locally |
| Homebrew | Template only, needs a tap repository | `packaging/homebrew/render.sh` |
| AUR | Template only, needs an AUR account and repository | `packaging/aur/render.sh` |

## The generated files

`packaging/generated/` holds the man page, the shell completions and the Debian changelog. They are built by `just generated`, never committed: the binary that ships is the one that describes itself, so a stale completion file is not a state this repository can get into.

## The apt repository

A static tree in a Cloudflare R2 bucket, served at <https://apt.radicle.tools>, signed with a key held in the `APT_GPG_PRIVATE_KEY` secret. R2 charges nothing for egress, so a popular release costs the same as an ignored one; the free tier covers 10 GB of storage and ten million reads a month, which a handful of `.deb` files and their indexes will not approach. `Origin` and `Label` are both `radicle-tools`, which is what lets `unattended-upgrades` target it without also targeting everything else a machine has configured.

`publish.sh` rebuilds every index from the whole pool on every run rather than appending, because an index that has drifted from the pool gives apt clients a hash mismatch and no way to work out why. It pulls the existing pool down first for the same reason, and uploads the pool before the indexes that name it, so no client ever reads an index pointing at a package that is not there yet.

To test the whole thing without publishing anywhere: let apt itself judge a local copy of the tree.

```sh
apt-get update -o Dir::Etc::sourcelist=<a sources.list with a file:// line> \
               -o Dir::State::Lists=<a scratch directory> ...
```

If apt verifies `InRelease` and fetches `Packages`, the repository is correct. Nothing else is proof.

## Release signatures

Every release ships `sha256sums.txt` and `sha256sums.txt.sig`, an ssh signature made by the key in `packaging/release/allowed_signers` under the namespace `radicle.tools`. ssh rather than GPG because every Radicle user already has an ssh key and already trusts exactly one: their own.

```sh
./packaging/release/sign.sh   <directory holding sha256sums.txt>   # RELEASE_SIGNING_KEY, or the agent
./packaging/release/verify.sh <directory holding both files>       # what a downloader runs
```

`verify.sh` fails on an unlisted signer and on a tampered file. Both failures were watched before the script was trusted.

## Reproducible builds

`just repro` builds twice from a clean tree and compares the hashes; CI does the same in the `reproducible` job, and the `nix` job builds the flake twice and compares store paths. What makes it hold: a pinned toolchain in `rust-toolchain.toml`, `codegen-units = 1` and fat LTO, `SOURCE_DATE_EPOCH` taken from the commit, and `--remap-path-prefix` for the checkout and the cargo registry. The remapping goes through `CARGO_ENCODED_RUSTFLAGS` rather than `RUSTFLAGS`, because `RUSTFLAGS` splits on whitespace and a checkout path may contain a space.

## First-time setup

1. Generate a signing key that is used for nothing else:
   ```sh
   gpg --quick-generate-key "radicle.tools packages <info@radicle.tools>" default sign never
   gpg --armor --export-secret-keys <key id>   # into the APT_GPG_PRIVATE_KEY secret
   ```
2. In Cloudflare, create an R2 bucket (`radicle-tools-apt`), give it the custom domain `apt.radicle.tools`, and create an API token scoped to *Object Read & Write* on that bucket alone.
3. Add the repository secrets `APT_GPG_PRIVATE_KEY`, `APT_GPG_PASSPHRASE`, `R2_ENDPOINT` (`https://<account id>.r2.cloudflarestorage.com`), `R2_ACCESS_KEY_ID` and `R2_SECRET_ACCESS_KEY`. Set the variable `R2_BUCKET` if the bucket is not named `radicle-tools-apt`.
4. Add `RELEASE_SIGNING_KEY` (the private half of the key in `packaging/release/allowed_signers`) and `CARGO_REGISTRY_TOKEN` for crates.io.
5. Tag a release: `git tag v0.1.0 && git push --tags`.

Steps 2 to 4 are all skippable: a release without them still builds and publishes every artefact those steps do not sign or host, and the workflow says which it skipped rather than failing silently.
