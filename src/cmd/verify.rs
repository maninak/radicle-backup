//! Checking that an archive is what it claims to be.
//!
//! Two depths, because they answer different questions. The shallow pass answers "did these
//! bytes survive": every entry is read and digested and compared with the manifest. The deep
//! pass answers "would this actually restore": the archive is unpacked into a throwaway home
//! and the identity is rebuilt from it and compared with the one on the label.

use std::path::Path;

use crate::archive::Reader;
use crate::cli::Verify;
use crate::cmd::{Ctx, Scratch};
use crate::db;
use crate::error::{EXIT_CHECKS_FAILED, Result};
use crate::git::Git;
use crate::key::{Identity, SecretKey};
use crate::manifest::Manifest;
use crate::term;

/// What a verification found. Empty problems is the only passing result.
pub struct Report {
    pub manifest: Manifest,
    pub problems: Vec<String>,
    pub checks: Vec<(String, bool)>,
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
                .map(|(name, ok)| serde_json::json!({"check": name, "passed": ok}))
                .collect::<Vec<_>>(),
            "problems": report.problems,
            "identity": report.manifest.identity.did,
            "created": report.manifest.created,
        }))?;
    } else {
        let term = &ctx.term;
        for (name, passed) in &report.checks {
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
                "{} is complete: {} entries, {}",
                report.archive.display(),
                report.manifest.entries.len(),
                term::bytes(report.manifest.total_bytes())
            ));
            if !args.deep {
                term.hint("--deep also restores it into a throwaway home and checks the identity");
            }
        } else {
            term.fail(&format!(
                "{} has {} problem(s)",
                report.archive.display(),
                report.problems.len()
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
    let passphrase = crate::cmd::archive_passphrase(ctx, archive)?;

    let mut checks = Vec::new();
    let mut problems = Vec::new();

    let reader = Reader::open(archive, passphrase.as_ref(), ctx.identity_files())?;
    let scan = if args.deep {
        let parent = ctx
            .global
            .scratch_dir
            .clone()
            .unwrap_or_else(|| archive.parent().unwrap_or(Path::new(".")).to_path_buf());
        let scratch = Scratch::create(&parent)?;
        let staging = scratch.file("home");
        let scan = reader.unpack(archive, &staging)?;
        deep_checks(&staging, &scan.manifest, &mut checks, &mut problems)?;
        scan
    } else {
        reader.scan(archive)?
    };

    let mismatches = scan.mismatches();
    checks.push((
        format!("{} entries match their digests", scan.observed.len()),
        mismatches.is_empty(),
    ));
    problems.extend(mismatches);

    let key_present = scan.observed.contains_key("keys/radicle");
    checks.push(("the private key is in the archive".to_string(), key_present));
    if !key_present {
        problems.push("keys/radicle is not in this archive: it cannot restore an identity".into());
    }

    Ok(Report {
        manifest: scan.manifest,
        problems,
        checks,
        archive: archive.clone(),
    })
}

/// Rebuild what the archive holds and compare it with what the archive claims.
fn deep_checks(
    staging: &Path,
    manifest: &Manifest,
    checks: &mut Vec<(String, bool)>,
    problems: &mut Vec<String>,
) -> Result<()> {
    let public = staging.join("keys/radicle.pub");
    match Identity::read(&public) {
        Ok(identity) => {
            let matches = identity.did() == manifest.identity.did;
            checks.push((
                format!("the public key restores as {}", identity.did()),
                matches,
            ));
            if !matches {
                problems.push(format!(
                    "the archived public key is {}, but the manifest says {}",
                    identity.did(),
                    manifest.identity.did
                ));
            }
        }
        Err(e) => {
            checks.push(("the public key is readable".to_string(), false));
            problems.push(format!("keys/radicle.pub does not parse: {e}"));
        }
    }

    match SecretKey::read(staging.join("keys/radicle")) {
        Ok(secret) => match secret.identity() {
            Ok(identity) => {
                let matches = identity.did() == manifest.identity.did;
                checks.push((
                    "the private key belongs to that identity".to_string(),
                    matches,
                ));
                if !matches {
                    problems.push(
                        "the archived private key does not match the archived public key".into(),
                    );
                }
            }
            Err(e) => {
                checks.push(("the private key has a public half".to_string(), false));
                problems.push(format!("keys/radicle is not usable: {e}"));
            }
        },
        Err(e) => {
            checks.push(("the private key is readable".to_string(), false));
            problems.push(format!("keys/radicle does not parse: {e}"));
        }
    }

    let policies_db = staging.join("node/policies.db");
    if policies_db.is_file() {
        match db::read_policies(&policies_db) {
            Ok(policies) => {
                let seeded = policies.seeded().count();
                let matches = seeded == manifest.policies.seeded;
                checks.push((format!("{seeded} seeding policies come back"), matches));
                if !matches {
                    problems.push(format!(
                        "the policy database holds {seeded} seeded repositories, the manifest says {}",
                        manifest.policies.seeded
                    ));
                }
            }
            Err(e) => {
                checks.push(("the policy database opens".to_string(), false));
                problems.push(format!("node/policies.db does not open: {e}"));
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
        if carried > 0 {
            problems.push(format!(
                "git is not on PATH, so {} in this archive could not be opened; install git \
                 and verify again",
                crate::term::count(carried, "repository bundle", "repository bundles")
            ));
        }
        return Ok(());
    }
    let mut checked = 0;
    for repo in manifest.repos.iter().filter(|repo| repo.bundle.is_some()) {
        let bundle = staging.join(crate::git::bundle_entry(&repo.rid));
        match git.bundle_refs(&bundle) {
            Ok(refs) if !refs.is_empty() => checked += 1,
            Ok(_) => problems.push(format!("{}: its bundle holds no refs", repo.rid)),
            Err(e) => problems.push(format!("{}: its bundle does not open ({e})", repo.rid)),
        }
    }
    if checked > 0 {
        checks.push((
            format!("{checked} repository bundles open and hold refs"),
            true,
        ));
    }
    Ok(())
}
