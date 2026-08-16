# Packaging

What ships, how it is built, and what is not wired up yet.

| Channel | State | Built by |
|---|---|---|
| `.deb` (amd64, arm64) | Working | `just deb` locally, the `packages` job on a tag |
| Signed apt repository | Working | `packaging/apt/publish.sh`, run by the `apt` job |
| Tarballs (linux musl, macOS, x86_64 and aarch64) | Working | the `binaries` job |
| Windows `.zip` (x86_64-msvc) | Working, with the caveats in the README | the `binaries` job |
| FreeBSD tarball (x86_64) | Cross-built, never executed by CI, labelled untested | the `binaries` job |
| Signed `sha256sums.txt` | Working | `packaging/release/sign.sh`, run by the `binaries` job |
| Nix flake | Working | `nix build`, checked twice by the `nix` job |
| crates.io | Working | the `crate` job |
| `.rpm` | Metadata written, needs `cargo generate-rpm` in CI | `just rpm` locally |
| Homebrew | Template only, needs a tap repository | `packaging/homebrew/render.sh` |
| AUR | Template only, needs an AUR account and repository | `packaging/aur/render.sh` |

## The generated files

`packaging/generated/` holds the man page, the shell completions and the Debian changelog. They are built by `just generated` and never committed, so a completion file cannot go stale against the binary.

## The apt repository

A static tree in a Cloudflare R2 bucket, served at <https://apt.radicle.tools>, signed with a key held in the `APT_GPG_PRIVATE_KEY` secret. `Origin` and `Label` are both `radicle-tools`, which is what lets `unattended-upgrades` target it without also targeting everything else a machine has configured. `publish.sh` explains how it builds the indexes and why it uploads them in the order it does.

To judge a tree, let apt read it. Nothing else exercises the signature and the hashes the way a client will:

```sh
tree=<a directory holding pubkey.asc, dists/ and pool/>
d=$(mktemp -d) && mkdir -p "$d/lists/partial" "$d/cache"
echo "deb [signed-by=$tree/pubkey.asc] file://$tree stable main" > "$d/sources.list"
apt-get update -o Dir::Etc::sourcelist="$d/sources.list" \
               -o Dir::Etc::sourceparts=/dev/null \
               -o Dir::State::Lists="$d/lists" \
               -o Dir::Cache="$d/cache"
```

It exits 0 having fetched `InRelease` and `Packages`. It exits 100 on a signature from a key the source does not name, and on an index whose hashes do not match the signed `Release`. For the published tree, save <https://apt.radicle.tools/pubkey.asc> to a file, point `signed-by` at that file and the source at the URL.

## Release signatures

Every release ships `sha256sums.txt` and `sha256sums.txt.sig`, an ssh signature made by the key in `packaging/release/allowed_signers` under the namespace `radicle.tools`. ssh rather than GPG, because every Radicle user already has an ssh key.

```sh
./packaging/release/sign.sh   <directory holding sha256sums.txt>   # RELEASE_SIGNING_KEY, or the agent
./packaging/release/verify.sh <directory holding both files>       # what a downloader runs
```

`verify.sh` fails on an unlisted signer and on a tampered file. Both failures were watched before the script was trusted.

The signing keys live as CI secrets, and neither is a Radicle identity key: both are read unattended, and a Radicle identity cannot be reissued. A release missing them still builds and publishes every artifact they do not sign or host, and the run says which it skipped.

## Reproducible builds

`just repro` builds twice from a clean tree and compares the hashes; CI does the same in the `reproducible` job, and the `nix` job builds the flake twice and compares store paths. What makes it hold: a pinned toolchain in `rust-toolchain.toml`, `codegen-units = 1` and fat LTO, `SOURCE_DATE_EPOCH` taken from the commit, and `--remap-path-prefix` for the checkout and the cargo registry. The remapping goes through `CARGO_ENCODED_RUSTFLAGS` rather than `RUSTFLAGS`, because `RUSTFLAGS` splits on whitespace and a checkout path may contain a space.
