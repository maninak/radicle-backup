//! Checking that an archive is what it claims to be.
//!
//! Two depths, because they answer different questions. The shallow pass answers "did these
//! bytes survive": every entry is read and digested and compared with the manifest. The deep
//! pass answers "would this actually restore": the archive is unpacked into a throwaway home
//! and the identity is rebuilt from it and compared with the one on the label.

use std::path::Path;

use crate::cli::Verify;
use crate::cmd::{Ctx, Scratch};
use crate::container::Reader;
use crate::db;
use crate::error::{EXIT_CHECKS_FAILED, Result};
use crate::git::Git;
use crate::key::{Identity, SecretKey};
use crate::manifest::Manifest;
use crate::term;

/// A check's stable identity, printed as `checkId` so a script matches on it and not on the
/// message. Ids are frozen once released. Messages are wording and may change.
///
/// One id per thing looked at, never per outcome: `passed` carries how it went and `problems`
/// says why, so a script asks one question of one id. Never carries a count or a DID the way
/// the message beside it can, since those vary between runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckId {
    /// Every entry's digest against the archive's own record.
    Files,
    /// The private key's entry exists, asked of every run. The deep pass's `PrivateKey` reads
    /// it, which a shallow run never does, so the two cannot share an id.
    PrivateKeyPresent,
    PublicKey,
    PrivateKey,
    SeedingPolicies,
    Repositories,
}

impl CheckId {
    /// Spelled out rather than derived from the variant name, so renaming a variant cannot
    /// change a string scripts already match on.
    fn id(self) -> &'static str {
        match self {
            Self::Files => "files",
            Self::PrivateKeyPresent => "private-key-present",
            Self::PublicKey => "public-key",
            Self::PrivateKey => "private-key",
            Self::SeedingPolicies => "seeding-policies",
            Self::Repositories => "repositories",
        }
    }
}

/// What a verification found. Empty problems is the only passing result.
pub struct Report {
    pub manifest: Manifest,
    pub problems: Vec<String>,
    pub checks: Vec<(CheckId, String, bool)>,
    /// The archive that was checked, which is not always the one the caller named: with no
    /// argument this is whichever one was newest.
    pub archive: std::path::PathBuf,
}

impl Report {
    pub fn passed(&self) -> bool {
        self.problems.is_empty()
    }
}

pub fn run(ctx: &Ctx, args: &Verify) -> Result<std::process::ExitCode> {
    let report = check(ctx, args)?;

    if ctx.global.json {
        ctx.term.print_json(&serde_json::json!({
            "archive": report.archive.display().to_string(),
            "passed": report.passed(),
            "checks": report.checks.iter()
                .map(|(id, name, ok)| serde_json::json!({
                    "checkId": id.id(),
                    "check": name,
                    "passed": ok,
                }))
                .collect::<Vec<_>>(),
            "problems": report.problems,
            "identity": report.manifest.identity.did,
            "created": report.manifest.created,
        }))?;
    } else {
        let term = &ctx.term;
        for (_, name, passed) in &report.checks {
            if *passed {
                term.ok(name);
            } else {
                term.fail(name);
            }
        }
        for problem in &report.problems {
            term.fail(problem);
        }
        term.blank();
        if report.passed() {
            term.ok(&format!(
                "{} is complete: {} files, {}",
                report.archive.display(),
                report.manifest.entries.len(),
                term::human_bytes(report.manifest.total_bytes())
            ));
            if !args.deep {
                term.hint(
                    "run verify with --deep to also test a restore into a temporary directory",
                );
            }
        } else {
            term.fail(&format!(
                "{} has {}",
                report.archive.display(),
                crate::term::count(report.problems.len(), "problem", "problems")
            ));
        }
    }

    Ok(if report.passed() {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::from(EXIT_CHECKS_FAILED)
    })
}

pub fn check(ctx: &Ctx, args: &Verify) -> Result<Report> {
    let archive = &crate::cmd::resolve_archive(ctx, args.target.archive.as_deref())?;
    let passphrase = crate::cmd::read_archive_passphrase(ctx, archive)?;

    let mut checks = Vec::new();
    let mut problems = Vec::new();

    let reader = Reader::open(archive, passphrase.as_ref(), &ctx.identities())?;
    let scan = if args.deep {
        let parent = ctx
            .global
            .scratch_dir
            .clone()
            .unwrap_or_else(|| archive.parent().unwrap_or(Path::new(".")).to_path_buf());
        let scratch = Scratch::create(&parent)?;
        let staging = scratch.path_of("home");
        let scan = reader.unpack(archive, &staging)?;
        check_unpacked_home(&staging, &scan.manifest, &mut checks, &mut problems)?;
        scan
    } else {
        reader.scan(archive)?
    };

    let mismatches = scan.mismatches();
    checks.push((
        CheckId::Files,
        format!("{} files in the archive are intact", scan.observed.len()),
        mismatches.is_empty(),
    ));
    problems.extend(mismatches);

    let secret_key_present = scan.observed.contains_key("keys/radicle");
    checks.push((
        CheckId::PrivateKeyPresent,
        "the private key is in the archive".to_string(),
        secret_key_present,
    ));
    if !secret_key_present {
        problems.push(
            "the private key (keys/radicle) is missing from the archive. It cannot restore your \
             identity"
                .into(),
        );
    }

    Ok(Report {
        manifest: scan.manifest,
        problems,
        checks,
        archive: archive.clone(),
    })
}

/// Why a key file did not read, without the path of the throwaway copy it was read from.
fn unreadable(e: &crate::error::Error) -> String {
    match e {
        crate::error::Error::BadKey { reason, .. } => reason.clone(),
        other => other.one_line(),
    }
}

/// Rebuild what the archive holds and compare it with what the archive claims.
fn check_unpacked_home(
    staging: &Path,
    manifest: &Manifest,
    checks: &mut Vec<(CheckId, String, bool)>,
    problems: &mut Vec<String>,
) -> Result<()> {
    let public_key_path = staging.join("keys/radicle.pub");
    match Identity::read(&public_key_path) {
        Ok(identity) => {
            let matches = identity.did() == manifest.identity.did;
            checks.push((
                CheckId::PublicKey,
                format!("the public key is {}", identity.did()),
                matches,
            ));
            if !matches {
                problems.push(format!(
                    "the public key in the archive is {}, but the archive's record names {}",
                    identity.did(),
                    manifest.identity.did
                ));
            }
        }
        Err(e) => {
            checks.push((
                CheckId::PublicKey,
                "the public key is readable".to_string(),
                false,
            ));
            problems.push(format!(
                "the public key could not be read: {}",
                unreadable(&e)
            ));
        }
    }

    match SecretKey::read(staging.join("keys/radicle")) {
        Ok(secret) => match secret.identity() {
            Ok(identity) => {
                let matches = identity.did() == manifest.identity.did;
                checks.push((
                    CheckId::PrivateKey,
                    "the private key belongs to that identity".to_string(),
                    matches,
                ));
                if !matches {
                    problems.push(
                        "the private key in the archive does not match its public key".into(),
                    );
                }
            }
            Err(e) => {
                checks.push((
                    CheckId::PrivateKey,
                    "the private key is usable".to_string(),
                    false,
                ));
                problems.push(format!("the private key could not be used: {e}"));
            }
        },
        Err(e) => {
            checks.push((
                CheckId::PrivateKey,
                "the private key is readable".to_string(),
                false,
            ));
            problems.push(format!(
                "the private key could not be read: {}",
                unreadable(&e)
            ));
        }
    }

    let policies_db = staging.join("node/policies.db");
    if policies_db.is_file() {
        match db::read_policies(&policies_db) {
            Ok(policies) => {
                let seeded = policies.seeded().count();
                let matches = seeded == manifest.policies.seeded;
                checks.push((
                    CheckId::SeedingPolicies,
                    format!("{seeded} seeding policies can be restored"),
                    matches,
                ));
                if !matches {
                    problems.push(format!(
                        "the policy database holds {seeded} seeded repositories, but the \
                         archive's record says {}",
                        manifest.policies.seeded
                    ));
                }
            }
            Err(e) => {
                checks.push((
                    CheckId::SeedingPolicies,
                    "the policy database can be opened".to_string(),
                    false,
                ));
                problems.push(format!("the policy database could not be opened: {e}"));
            }
        }
    }

    let git = Git::new();
    let carried = manifest
        .repos
        .iter()
        .filter(|repo| repo.bundle.is_some())
        .count();
    if !git.is_available() {
        // Not a silent return: without git the bundles are never opened, and a report that
        // said "complete" over an unopened bundle is the same report a fully verified archive
        // gets. The archive may be fine; this run cannot say so.
        //
        // No `repositories` check here: a failed one reads the same as a broken archive, and
        // an absent one is what a check that did not run looks like.
        if carried > 0 {
            problems.push(format!(
                "git was not found, so {} in this archive could not be checked. Install git \
                 and run verify again",
                crate::term::count(carried, "repository", "repositories")
            ));
        }
        return Ok(());
    }
    let mut bundles_opened = 0;
    for repo in manifest.repos.iter().filter(|repo| repo.bundle.is_some()) {
        let bundle = staging.join(crate::git::bundle_entry(&repo.rid));
        match git.bundle_refs(&bundle) {
            Ok(refs) if !refs.is_empty() => bundles_opened += 1,
            Ok(_) => problems.push(format!(
                "{}: the archived copy of this repository is empty",
                repo.rid
            )),
            Err(e) => problems.push(format!(
                "{}: the archived copy of this repository could not be opened: {}",
                repo.rid,
                e.one_line()
            )),
        }
    }
    checks.extend(repositories_check(bundles_opened, carried));
    Ok(())
}

/// The check over the archived repositories, passed only when every one opened with work in
/// it. Present whenever the archive carries any, so one bad repository among good ones fails
/// it. `None` when it carries none, since there is nothing to report on.
fn repositories_check(opened: usize, carried: usize) -> Option<(CheckId, String, bool)> {
    if carried == 0 {
        return None;
    }
    let passed = opened == carried;
    // One wording for both outcomes, naming only what was tested: git lists each bundle's
    // refs and never unpacks it, so "restored" would claim more.
    let can_be_opened = crate::term::count(
        carried,
        "archived repository can be opened",
        "archived repositories can be opened",
    );
    let said = if passed {
        can_be_opened
    } else {
        format!("{opened} of {can_be_opened}")
    };
    Some((CheckId::Repositories, said, passed))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every check id, as the exact string a script matches on. A second copy on purpose: an
    /// edit to `CheckId::id` has to be made twice to ship. Nothing notices a variant left out
    /// of this list, so a new id needs a line here too.
    #[test]
    fn check_ids_are_pinned_because_scripts_match_on_them() {
        let pinned = [
            (CheckId::Files, "files"),
            (CheckId::PrivateKeyPresent, "private-key-present"),
            (CheckId::PublicKey, "public-key"),
            (CheckId::PrivateKey, "private-key"),
            (CheckId::SeedingPolicies, "seeding-policies"),
            (CheckId::Repositories, "repositories"),
        ];
        for (id, spelled) in pinned {
            assert_eq!(id.id(), spelled);
        }
        let distinct: std::collections::BTreeSet<_> =
            pinned.iter().map(|(id, _)| id.id()).collect();
        assert_eq!(distinct.len(), pinned.len(), "two checks share an id");
    }

    #[test]
    fn one_repository_that_did_not_open_fails_the_repositories_check_however_many_did() {
        let passed = |opened, carried| repositories_check(opened, carried).map(|check| check.2);
        assert_eq!(passed(3, 4), Some(false));
        assert_eq!(
            passed(0, 2),
            Some(false),
            "none opening is still a failed line"
        );
        assert_eq!(passed(4, 4), Some(true));
        assert_eq!(passed(0, 0), None);
    }
}
