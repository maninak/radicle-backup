//! Reporting how recoverable an identity currently is.
//!
//! This is the answer to the question the Radicle support channel keeps getting: "what is my
//! exposure, and what do I do about it". Every failing line names the command that fixes it,
//! and every check says what it actually looked at, because a score nobody can audit is a
//! score nobody should trust.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::cli::Doctor;
use crate::cmd::Ctx;
use crate::db;
use crate::error::{EXIT_CHECKS_FAILED, Result};
use crate::git::Git;
use crate::inventory::{self, Inventory};
use crate::key::{Identity, SecretKey};
use crate::manifest::RepoSelection;
use crate::rad::Rad;
use crate::state;
use crate::term;

/// How old a backup may get before it stops counting as one.
const STALE_AFTER_DAYS: i64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Pass,
    Warn,
    Fail,
    /// Something could not be looked at. Never counted as a pass.
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub name: String,
    pub verdict: Verdict,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remedy: Option<String>,
}

impl Check {
    fn new(name: &str, verdict: Verdict, detail: impl Into<String>) -> Self {
        Self {
            name: name.to_string(),
            verdict,
            detail: detail.into(),
            remedy: None,
        }
    }

    fn with_remedy(mut self, remedy: impl Into<String>) -> Self {
        self.remedy = Some(remedy.into());
        self
    }
}

pub fn run(ctx: &Ctx, args: &Doctor) -> Result<std::process::ExitCode> {
    ctx.home.require()?;
    let checks = examine(ctx, args)?;
    let failed = checks
        .iter()
        .filter(|check| check.verdict == Verdict::Fail)
        .count();
    let passed = checks
        .iter()
        .filter(|check| check.verdict == Verdict::Pass)
        .count();

    if ctx.global.json {
        ctx.term.print_json(&serde_json::json!({
            "home": ctx.home.path().display().to_string(),
            "passed": passed,
            "total": checks.len(),
            "checks": checks,
        }))?;
    } else {
        let term = &ctx.term;
        term.headline(&format!(
            "recovery posture of {}",
            ctx.home.path().display()
        ));
        term.blank();
        for check in &checks {
            let line = format!("{}: {}", check.name, check.detail);
            match check.verdict {
                Verdict::Pass => term.ok(&line),
                Verdict::Warn => term.warn(&line),
                Verdict::Fail => term.fail(&line),
                Verdict::Unknown => term.step(&line),
            }
            if let Some(remedy) = &check.remedy {
                term.hint(remedy);
            }
        }
        term.blank();
        term.headline(&format!("{passed} of {} checks pass", checks.len()));
        if failed > 0 {
            term.hint("the failing lines above are the ones that cost you an identity");
        }
    }

    Ok(if failed == 0 {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::from(EXIT_CHECKS_FAILED)
    })
}

fn examine(ctx: &Ctx, args: &Doctor) -> Result<Vec<Check>> {
    let home = &ctx.home;
    let identity = Identity::read(home.public_key())?;
    let secret = SecretKey::read(home.secret_key())?;
    let node_id = identity.node_id();

    let git = Git::new();
    let rad = Rad::new(home.path());
    let rad = rad.is_available().then_some(rad);
    let policies = db::read_policies(&home.policies_db())?;
    let routing = db::routing_counts(&home.node_db(), &node_id)?;
    let inventory = inventory::collect(
        home,
        &git,
        rad.as_ref(),
        RepoSelection::None,
        &node_id,
        &policies,
        &routing,
    )?;
    let stored = state::read(&identity.did())?;
    if let Some(complaint) = stored.complaint() {
        ctx.term.warn(&complaint);
    }
    let record = stored.record();
    let now = jiff::Timestamp::now();

    let mut checks = vec![key_protection(&secret)];
    checks.push(backup_freshness(&stored, now, args));
    checks.push(backup_encryption(record));
    checks.push(backup_locality(ctx, record));
    checks.push(private_coverage(&inventory, record));
    checks.push(delegate_quorum(&inventory));
    checks.push(replication(&inventory, &routing));
    Ok(checks)
}

fn key_protection(secret: &SecretKey) -> Check {
    match secret.protection() {
        crate::key::Protection::Encrypted { cipher, kdf } => Check::new(
            "the key has a passphrase",
            Verdict::Pass,
            format!("{cipher} with {kdf}"),
        ),
        crate::key::Protection::Plaintext => Check::new(
            "the key has a passphrase",
            Verdict::Fail,
            "it is stored in the clear, so anyone who reads the file is you",
        )
        .with_remedy("add one: ssh-keygen -p -f $RAD_HOME/keys/radicle"),
    }
}

fn backup_freshness(stored: &state::Stored, now: jiff::Timestamp, args: &Doctor) -> Check {
    if let state::Stored::Unreadable { .. } = stored {
        return Check::new(
            "a backup exists",
            Verdict::Unknown,
            "one was recorded, but the record no longer parses",
        )
        .with_remedy("take another to replace it: rad backup");
    }
    let Some(record) = stored.record() else {
        let where_to = args
            .backup_dir
            .as_ref()
            .map(|dir| format!(" --output {}", dir.display()))
            .unwrap_or_default();
        return Check::new(
            "a backup exists",
            Verdict::Fail,
            "this tool has never written one for this identity",
        )
        .with_remedy(format!("rad backup{where_to}"));
    };
    match record.age_in_days(now) {
        Some(days) if days <= STALE_AFTER_DAYS => Check::new(
            "a backup exists",
            Verdict::Pass,
            format!("{} tier, taken {}", record.tier, term::days_ago(days)),
        ),
        Some(days) => Check::new(
            "a backup exists",
            Verdict::Warn,
            format!("the newest one was taken {}", term::days_ago(days)),
        )
        .with_remedy("rad backup"),
        None => Check::new(
            "a backup exists",
            Verdict::Unknown,
            "there is a record of one, but its timestamp does not parse",
        ),
    }
}

fn backup_encryption(record: Option<&state::Record>) -> Check {
    match record {
        Some(record) if record.encrypted => Check::new(
            "the backup is encrypted",
            Verdict::Pass,
            "it cannot be read without its passphrase or key",
        ),
        Some(_) => Check::new(
            "the backup is encrypted",
            Verdict::Fail,
            "the newest archive holds your private key in the clear",
        )
        .with_remedy("take another without --plaintext, then delete the old one"),
        None => Check::new(
            "the backup is encrypted",
            Verdict::Unknown,
            "there is no backup to judge",
        ),
    }
}

fn backup_locality(ctx: &Ctx, record: Option<&state::Record>) -> Check {
    let Some(archive) = record.and_then(|record| record.archive.as_ref()) else {
        return Check::new(
            "the backup is off this disk",
            Verdict::Unknown,
            "no archive path was recorded, so this cannot be judged",
        );
    };
    let path = std::path::Path::new(archive);
    if !path.exists() {
        return Check::new(
            "the backup is off this disk",
            Verdict::Warn,
            format!("{archive} is no longer where it was written"),
        )
        .with_remedy("if you moved it somewhere safe, this is fine; if not, take another");
    }
    match state::same_device(path, ctx.home.path()) {
        Some(true) => Check::new(
            "the backup is off this disk",
            Verdict::Fail,
            "it is on the same filesystem as the home it protects",
        )
        .with_remedy("copy it to another disk, another machine, or a service you trust"),
        Some(false) => Check::new(
            "the backup is off this disk",
            Verdict::Pass,
            "it is on a different filesystem",
        ),
        None => Check::new(
            "the backup is off this disk",
            Verdict::Unknown,
            "the filesystems could not be compared",
        ),
    }
}

fn private_coverage(inventory: &Inventory, record: Option<&state::Record>) -> Check {
    const CHECK: &str = "private repositories are backed up";
    let private: Vec<&crate::manifest::RepoRecord> = inventory.private().collect();
    if private.is_empty() {
        return Check::new(CHECK, Verdict::Pass, "there are none");
    }

    // A private repository is not automatically the only copy. Its owner can allow peers to
    // hold it, and the routing table knows when one announces it. Those are different degrees
    // of safety and this check says which is which rather than crying wolf about all three.
    let missing: Vec<&&crate::manifest::RepoRecord> = private
        .iter()
        .filter(|repo| !record.is_some_and(|record| record.carries(&repo.rid)))
        .collect();
    if missing.is_empty() {
        return Check::new(
            CHECK,
            Verdict::Pass,
            format!("all {} of them are in the newest archive", private.len()),
        );
    }
    let alone = missing
        .iter()
        .filter(|repo| !repo.has_another_holder())
        .count();
    let detail = if alone == 0 {
        format!(
            "{} in no archive, though every one of them is allowed to a peer that could hold a \
             copy",
            term::count(missing.len(), "is", "are"),
        )
    } else if alone == missing.len() {
        format!(
            "{} in no archive and on no other node",
            term::count(alone, "is", "are")
        )
    } else {
        format!(
            "{} of {} in no archive, and {alone} of those on no other node",
            term::count(missing.len(), "is", "are"),
            private.len(),
        )
    };
    let verdict = if alone == 0 {
        Verdict::Warn
    } else {
        Verdict::Fail
    };
    Check::new(CHECK, verdict, detail).with_remedy("rad backup --repos private")
}

fn delegate_quorum(inventory: &Inventory) -> Check {
    let sole: Vec<&str> = inventory
        .sole_delegate()
        .map(|repo| repo.display_name())
        .collect();
    let delegated = inventory
        .records
        .iter()
        .filter(|repo| repo.delegate)
        .count();
    if sole.is_empty() {
        return Check::new(
            "no repository depends on this key alone",
            Verdict::Pass,
            if delegated == 0 {
                "you are not a delegate of anything".to_string()
            } else {
                format!(
                    "all {} you delegate have another delegate",
                    term::count(delegated, "repository", "repositories")
                )
            },
        );
    }
    Check::new(
        "no repository depends on this key alone",
        Verdict::Warn,
        format!(
            "{} have you as their only delegate: {}",
            term::count(sole.len(), "repository", "repositories"),
            sole.join(", ")
        ),
    )
    .with_remedy(
        "a backup covers loss but not theft. Three delegates survive one lost key; two are \
         worse than one, because both are still needed and there is twice the chance of \
         losing one. Add one with `rad id edit`",
    )
}

fn replication(inventory: &Inventory, routing: &BTreeMap<String, u64>) -> Check {
    let alone: Vec<&str> = inventory
        .records
        .iter()
        .filter(|repo| !repo.is_private())
        .filter(|repo| routing.get(&repo.rid).copied().unwrap_or(0) == 0)
        .map(|repo| repo.display_name())
        .collect();

    if routing.is_empty() {
        return Check::new(
            "your public repositories are seeded elsewhere",
            Verdict::Unknown,
            "the routing table is empty, so no other node is known to hold anything",
        )
        .with_remedy("start the node and let it gossip, then run this again");
    }
    if alone.is_empty() {
        return Check::new(
            "your public repositories are seeded elsewhere",
            Verdict::Pass,
            "every one of them is announced by at least one other node",
        );
    }
    Check::new(
        "your public repositories are seeded elsewhere",
        Verdict::Warn,
        format!(
            "{} of them are announced by no other node: {}",
            alone.len(),
            alone.join(", ")
        ),
    )
    .with_remedy("`rad sync --announce` them, or ask a seed to hold a copy")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plaintext_key_fails_and_says_how_to_fix_it() {
        let seed = zeroize::Zeroizing::new([1u8; 32]);
        let openssh = crate::key::openssh_from_seed(&seed, None).expect("key is buildable");
        let path = std::env::temp_dir().join(format!("rad-backup-doctor-{}", std::process::id()));
        std::fs::write(&path, &*openssh).expect("scratch key is writable");

        let secret = SecretKey::read(&path).expect("key is readable");
        let check = key_protection(&secret);
        assert_eq!(check.verdict, Verdict::Fail);
        assert!(check.remedy.is_some());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_backup_that_has_never_been_taken_fails_rather_than_being_unknown() {
        let now: jiff::Timestamp = "2026-08-14T12:00:00Z".parse().expect("a valid instant");
        let check = backup_freshness(&state::Stored::Absent, now, &Doctor { backup_dir: None });
        assert_eq!(check.verdict, Verdict::Fail);
        assert_eq!(check.remedy.as_deref(), Some("rad backup"));
    }

    #[test]
    fn a_backup_older_than_the_stale_mark_warns_but_does_not_fail() {
        let now: jiff::Timestamp = "2026-08-14T12:00:00Z".parse().expect("a valid instant");
        let mut record = record();
        record.created = "2026-05-01T12:00:00Z".to_string();
        let stored = state::Stored::Record(Box::new(record.clone()));
        let check = backup_freshness(&stored, now, &Doctor { backup_dir: None });
        assert_eq!(check.verdict, Verdict::Warn);

        record.created = "2026-08-13T12:00:00Z".to_string();
        let stored = state::Stored::Record(Box::new(record));
        let check = backup_freshness(&stored, now, &Doctor { backup_dir: None });
        assert_eq!(check.verdict, Verdict::Pass);
    }

    #[test]
    fn a_state_file_that_no_longer_parses_is_unknown_rather_than_never_taken() {
        let now: jiff::Timestamp = "2026-08-14T12:00:00Z".parse().expect("a valid instant");
        let stored = state::Stored::Unreadable {
            path: std::path::PathBuf::from("/nowhere/state.json"),
            reason: "expected value at line 1 column 1".to_string(),
        };
        let check = backup_freshness(&stored, now, &Doctor { backup_dir: None });
        assert_eq!(check.verdict, Verdict::Unknown);
        assert!(check.remedy.is_some());
    }

    #[test]
    fn a_plaintext_archive_fails_the_encryption_check() {
        let mut record = record();
        record.encrypted = false;
        assert_eq!(backup_encryption(Some(&record)).verdict, Verdict::Fail);
        record.encrypted = true;
        assert_eq!(backup_encryption(Some(&record)).verdict, Verdict::Pass);
        assert_eq!(backup_encryption(None).verdict, Verdict::Unknown);
    }

    fn record() -> state::Record {
        state::Record {
            did: "did:key:z6MkAAA".to_string(),
            archive: None,
            created: "2026-08-14T00:00:00Z".to_string(),
            tier: "state".to_string(),
            repo_selection: "private".to_string(),
            entries: 5,
            bytes: 1024,
            encrypted: true,
            repos: Default::default(),
            described: Default::default(),
            sigrefs: Default::default(),
            seeded: 0,
            followed: 0,
        }
    }
}
