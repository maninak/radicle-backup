# Contributing

The Radicle repository is [`rad:zwuwC3UnuVYy2tvG9dd11QCUbA7J`](https://app.radicle.at/nodes/seed.radicle.at/rad:zwuwC3UnuVYy2tvG9dd11QCUbA7J). Clone it with `rad clone rad:zwuwC3UnuVYy2tvG9dd11QCUbA7J`.

Patches are welcome either way: `rad patch` against that clone, or a GitHub pull request.

**Issues live on Radicle only.** `rad issue open` in a clone of this repository; GitHub issues are turned off, because a bug report about Radicle tooling should not be the one thing about this project that only one company can serve. If Radicle is not an option for you, the `#support` channel on the [Radicle Zulip](https://radicle.zulipchat.com) reaches the same person.

## Before you start

Open an issue for anything that changes behaviour, adds a flag or touches the archive format. Small fixes need no ceremony.

## The bar

```sh
just check    # cargo fmt --check, the SECURITY.md audit map, then the lints, then the tests: what CI runs, in that order
```

CI runs those four on Linux, macOS and Windows, plus an MSRV check, a two-pass reproducibility check, `nix build --rebuild`, a Debian package built and linted, and the advisory, action-pin and dependency-age gates. Builds of the cross-compiled release targets run on every push to master and on a tag, not on a pull request. A pull request is ready when CI is green and the change carries a test that would have failed without it.

**Every bug fix gets a test that would have caught the bug.** Prove it is not vacuous: flip what it asserts, watch it go red, put it back.

## Code

The code follows a consistent set of habits. Match them rather than your own:

- `thiserror` and a single `Error` enum. Never `anyhow`; a caller that cannot tell one failure from another cannot act on either.
- No `unwrap`. `expect` carries a justification that reads as a proof: `expect("the vector parses")`, not `expect("should work")`.
- Enums over booleans and bare strings. A function taking `Tier` cannot be called with the wrong word.
- Wire formats parse tolerantly. An unknown `tier` in a manifest is `Unknown`, not a failed read.
- Pure functions are separated from the ones that read the environment: `Home::at(path)` beside `Home::from_env()`, so the logic is testable without a process to configure.
- Deterministic output. Sorted collections, fixed timestamps in tar headers, no iteration order leaking into a file.
- Dependencies are added reluctantly and justified in the pull request, and nothing is adopted in its first week. `.github/check-lockfile-age.py` fails CI on a crate version younger than that, and `.github/check-action-pins.sh` does the same for a GitHub Action, which must also be pinned to a commit SHA rather than a tag anybody can move. Dependabot's `cooldown` applies the same week to the updates it raises, though never to a security update, which should not wait.
- Test names are sentences about behaviour, in snake_case, with no `test_` prefix: `a_damaged_payload_is_reported_as_damage_and_not_as_a_wrong_passphrase`.
- Comments say *why*. What the code does is already written down, in the code.

Every constraint states its reason. If you meet one whose reason no longer holds, say so and propose the change; a rule nobody may question is a rule nobody can fix.

## Commits

Conventional commits, lowercase subject in the imperative mood, under 72 characters, no body unless the reason is genuinely not derivable from the diff:

```
fix: refuse an archive whose entry climbs out of the staging directory
feat: read the archive passphrase from RAD_BACKUP_PASSPHRASE_FILE
docs: say what the state tier carries and why
```

## The archive format

`ARCHIVE-FORMAT.md` is a specification other programs may implement. Changing it needs a version bump, a compatibility note, and a reason that survives the two guarantees the project does not trade away: an archive is readable without this tool, and an archive does not depend on a `rad` version.

## Releasing

Maintainer only. `just release <version>` bumps `Cargo.toml` and `Cargo.lock`, renames `CHANGELOG.md`'s `## [Unreleased]` heading to the version and its date, stamps the version into `ARCHIVE-FORMAT.md`'s version-history row and its sample manifest, runs `just check`, then commits and tags `v<version>`, all locally. Pushing the tag is the publish: `.github/workflows/release.yml` builds every artifact, signs the checksums, refreshes the apt repository and pushes the crate.

A released changelog carries no empty `## [Unreleased]` heading. The first change to land after a release opens one, in the same commit that adds the first entry under it.

## Security

Do not open a public issue or pull request for a vulnerability. `SECURITY.md` says where to send it.
