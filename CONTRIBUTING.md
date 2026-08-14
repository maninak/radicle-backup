# Contributing

Patches are welcome, as GitHub pull requests or as Radicle patches against `rad:` (this repository is seeded on the Radicle network).

## Before you start

Open an issue for anything that changes behaviour, adds a flag or touches the archive format. Small fixes need no ceremony.

## The bar

```sh
cargo clippy --all-targets    # must be silent; the lints are denials, not suggestions
cargo test                    # unit tests, plus the end-to-end suite in tests/
cargo fmt
```

CI runs the same three on Linux and macOS, plus a build of every release target. A pull request is ready when they are green and the change carries a test that would have failed without it.

**Every bug fix gets a test that would have caught the bug.** Prove it is not vacuous: flip what it asserts, watch it go red, put it back. A test that cannot fail reports a safety it is not providing.

## Code

The code follows a consistent set of habits. Match them rather than your own:

- `thiserror` and a single `Error` enum. Never `anyhow`; a caller that cannot tell one failure from another cannot act on either.
- No `unwrap`. `expect` carries a justification that reads as a proof: `expect("the vector parses")`, not `expect("should work")`.
- Enums over booleans and bare strings. A function taking `Tier` cannot be called with the wrong word.
- Wire formats parse tolerantly. An unknown `tier` in a manifest is `Unknown`, not a failed read.
- Pure functions are separated from the ones that read the environment: `Home::at(path)` beside `Home::from_env()`, so the logic is testable without a process to configure.
- Deterministic output. Sorted collections, fixed timestamps in tar headers, no iteration order leaking into a file.
- Dependencies are added reluctantly and justified in the pull request.
- Test names are sentences about behaviour, in snake_case, with no `test_` prefix: `a_damaged_payload_is_reported_as_damage_and_not_as_a_wrong_passphrase`.
- Comments say *why*. What the code does is already written down, in the code.

Every constraint states its reason. If you meet one whose reason no longer holds, say so and propose the change; a rule nobody may question is a rule nobody can fix.

## Commits

Conventional commits, lowercase subject, under 100 characters, no body unless the reason is genuinely not derivable from the diff:

```
fix: refuse an archive whose entry climbs out of the staging directory
feat: read the archive passphrase from RAD_BACKUP_PASSPHRASE_FILE
docs: say what the state tier carries and why
```

## The archive format

`ARCHIVE-FORMAT.md` is a specification other programs may implement. Changing it needs a version bump, a compatibility note, and a reason that survives the two guarantees the project does not trade away: an archive is readable without this tool, and an archive does not depend on a `rad` version.

## Security

Do not open a public issue or pull request for a vulnerability. `SECURITY.md` says where to send it.
