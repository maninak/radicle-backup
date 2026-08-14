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
    /// What was looked at, never what was hoped for. A topic cannot be read as a claim, so a
    /// failing line can never say the opposite of what it means: "backup: no archive has ever
    /// been taken" is unambiguous where "✗ a backup exists" is a sentence arguing with itself.
    pub topic: String,
    pub verdict: Verdict,
    /// What was actually found, as a complete statement that is true on its own.
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remedy: Option<String>,
}

impl Check {
    fn new(topic: &str, verdict: Verdict, detail: impl Into<String>) -> Self {
        Self {
            topic: topic.to_string(),
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
    let tally = |wanted| {
        checks
            .iter()
            .filter(|check| check.verdict == wanted)
            .count()
    };
    let (passed, warned, failed, unknown) = (
        tally(Verdict::Pass),
        tally(Verdict::Warn),
        tally(Verdict::Fail),
        tally(Verdict::Unknown),
    );

    if ctx.global.json {
        ctx.term.print_json(&serde_json::json!({
            "home": ctx.home.path().display().to_string(),
            "passed": passed,
            "warned": warned,
            "failed": failed,
            "unknown": unknown,
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
            let line = format!("{}: {}", check.topic, check.detail);
            match check.verdict {
                Verdict::Pass => term.ok(&line),
                Verdict::Warn => term.warn(&line),
                Verdict::Fail => term.fail(&line),
                Verdict::Unknown => term.unknown(&line),
            }
            if let Some(remedy) = &check.remedy {
                term.hint(&format!("--> {remedy}"));
            }
        }
        term.blank();
        term.headline(&summary(passed, warned, failed, unknown));
        if failed > 0 {
            term.hint("every ✗ is a way to lose this identity; the line under it is the fix");
        }
    }

    Ok(if failed == 0 {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::from(EXIT_CHECKS_FAILED)
    })
}

/// Name every bucket that has something in it, rather than reporting a score.
///
/// "2 of 7 checks pass" leaves the other five to the reader's imagination, and it counts a
/// check that could not be run as one that did not pass. Naming the buckets means the line
/// adds up to the number of checks and says which of them need a person.
fn summary(passed: usize, warned: usize, failed: usize, unknown: usize) -> String {
    let total = passed + warned + failed + unknown;
    if passed == total {
        return format!("all {total} checks pass");
    }
    let mut parts = vec![format!("{passed} pass")];
    if warned > 0 {
        parts.push(format!("{warned} worth improving"));
    }
    if failed > 0 {
        parts.push(format!("{failed} failing"));
    }
    if unknown > 0 {
        parts.push(format!("{unknown} could not be checked"));
    }
    parts.join(", ")
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
    checks.push(backup_locality(home.path(), record));
    checks.push(private_coverage(&inventory, record));
    checks.push(delegate_quorum(&inventory));
    checks.push(replication(&inventory, &routing));
    Ok(checks)
}

fn key_protection(secret: &SecretKey) -> Check {
    const TOPIC: &str = "key passphrase";
    match secret.protection() {
        crate::key::Protection::Encrypted { cipher, kdf } => Check::new(
            TOPIC,
            Verdict::Pass,
            format!("the key is encrypted with {cipher} ({kdf})"),
        ),
        crate::key::Protection::Plaintext => Check::new(
            TOPIC,
            Verdict::Fail,
            "the key is stored in the clear, so anyone who can read the file is you",
        )
        .with_remedy("add one: ssh-keygen -p -f $RAD_HOME/keys/radicle"),
    }
}

fn backup_freshness(stored: &state::Stored, now: jiff::Timestamp, args: &Doctor) -> Check {
    const TOPIC: &str = "backup";
    if let state::Stored::Unreadable { .. } = stored {
        return Check::new(
            TOPIC,
            Verdict::Unknown,
            "an archive was recorded, but the record no longer parses",
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
            TOPIC,
            Verdict::Fail,
            "no archive has ever been taken for this identity",
        )
        .with_remedy(format!("rad backup{where_to}"));
    };
    match record.age_in_days(now) {
        // Ahead of this clock, so the age says nothing. Left as a Pass it pinned the staleness
        // alarm open forever: one archive taken on a machine whose clock ran fast reported
        // "taken -300 days ago" and never went stale again.
        Some(days) if days < 0 => Check::new(
            TOPIC,
            Verdict::Unknown,
            "the newest archive is stamped in the future, so its age cannot be judged",
        )
        .with_remedy("check the clock on the machine that took it, then `rad backup`"),
        Some(days) if days <= STALE_AFTER_DAYS => Check::new(
            TOPIC,
            Verdict::Pass,
            format!(
                "a {}-tier archive was taken {}",
                record.tier,
                term::days_ago(days)
            ),
        ),
        Some(days) => Check::new(
            TOPIC,
            Verdict::Warn,
            format!("the newest archive was taken {}", term::days_ago(days)),
        )
        .with_remedy("rad backup"),
        None => Check::new(
            TOPIC,
            Verdict::Unknown,
            "an archive was recorded, but its timestamp does not parse",
        ),
    }
}

fn backup_encryption(record: Option<&state::Record>) -> Check {
    const TOPIC: &str = "archive encryption";
    match record {
        Some(record) if record.encrypted => Check::new(
            TOPIC,
            Verdict::Pass,
            "the newest archive cannot be read without its passphrase or key",
        ),
        Some(_) => Check::new(
            TOPIC,
            Verdict::Fail,
            "the newest archive holds your private key in the clear",
        )
        .with_remedy("take another without --plaintext, then delete the old one"),
        None => Check::new(TOPIC, Verdict::Unknown, "there is no archive to judge"),
    }
}

fn backup_locality(home: &std::path::Path, record: Option<&state::Record>) -> Check {
    const TOPIC: &str = "archive location";
    let Some(archive) = record.and_then(|record| record.archive.as_ref()) else {
        return Check::new(
            TOPIC,
            Verdict::Unknown,
            "no archive path was recorded, so this could not be judged",
        );
    };
    let path = std::path::Path::new(archive);
    if !path.exists() {
        return Check::new(
            TOPIC,
            Verdict::Warn,
            format!("{archive} is no longer where it was written"),
        )
        .with_remedy("if you moved it somewhere safe, this is fine; if not, take another");
    }
    match state::same_device(path, home) {
        // A warning and not a failure, because the same filesystem does not mean the same
        // fate: a directory synced by MEGA, Dropbox, Drive or Syncthing is already off this
        // machine, and this tool has no way to know whether one is watching. Failing a posture
        // it cannot evaluate would make `doctor` exit 3 at somebody who is properly covered.
        Some(true) => Check::new(
            TOPIC,
            Verdict::Warn,
            "the newest archive is on the same filesystem as the home it protects",
        )
        .with_remedy(
            "one dead disk would take both, unless something replicates that directory off this \
             machine. If a sync client watches it, this line is noise; if not, copy the archive \
             to another disk, another machine, or a service you trust",
        ),
        Some(false) => Check::new(
            TOPIC,
            Verdict::Pass,
            "the newest archive is on a different filesystem from the home it protects",
        ),
        None => Check::new(
            TOPIC,
            Verdict::Unknown,
            "the two filesystems could not be compared",
        ),
    }
}

fn private_coverage(inventory: &Inventory, record: Option<&state::Record>) -> Check {
    const CHECK: &str = "private repositories";
    let private: Vec<&crate::manifest::RepoRecord> = inventory.private().collect();
    if private.is_empty() {
        return Check::new(CHECK, Verdict::Pass, "there are none to lose");
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
    let (count, verb) = (missing.len(), term::agree(missing.len()));
    let detail = if alone == 0 {
        format!(
            "{count} of {} {verb} in no archive, though every one of those is allowed to a peer \
             that could hold a copy",
            private.len(),
        )
    } else if alone == missing.len() {
        format!(
            "{count} of {} {verb} in no archive and on no other node",
            private.len()
        )
    } else {
        format!(
            "{count} of {} {verb} in no archive, and {alone} of those on no other node",
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
    const TOPIC: &str = "delegate quorum";
    if sole.is_empty() {
        return Check::new(
            TOPIC,
            Verdict::Pass,
            if delegated == 0 {
                "you are not a delegate of anything".to_string()
            } else {
                format!(
                    "all {} you delegate have another delegate too",
                    term::count(delegated, "repository", "repositories")
                )
            },
        );
    }
    let (has, whose) = if sole.len() == 1 {
        ("has", "its")
    } else {
        ("have", "their")
    };
    Check::new(
        TOPIC,
        Verdict::Warn,
        format!(
            "{} {has} you as {whose} only delegate: {}",
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

    const TOPIC: &str = "seeding elsewhere";
    if routing.is_empty() {
        return Check::new(
            TOPIC,
            Verdict::Unknown,
            "the routing table is empty, so no other node is known to hold anything",
        )
        .with_remedy("start the node and let it gossip, then run this again");
    }
    if alone.is_empty() {
        return Check::new(
            TOPIC,
            Verdict::Pass,
            "every public repository is announced by at least one other node",
        );
    }
    Check::new(
        TOPIC,
        Verdict::Warn,
        format!(
            "{} {} announced by no other node: {}",
            term::count(alone.len(), "public repository", "public repositories"),
            term::agree(alone.len()),
            alone.join(", ")
        ),
    )
    .with_remedy("`rad sync --announce` them, or ask a seed to hold a copy")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every topic the report can print, one per check, whatever the verdict turns out to be.
    fn every_topic() -> Vec<String> {
        let now: jiff::Timestamp = "2026-08-14T12:00:00Z".parse().expect("a valid instant");
        let args = Doctor { backup_dir: None };
        let empty = Inventory {
            records: Vec::new(),
            selected: Default::default(),
            warnings: Vec::new(),
        };
        vec![
            backup_freshness(&state::Stored::Absent, now, &args),
            backup_encryption(None),
            backup_locality(std::path::Path::new("/nowhere"), None),
            private_coverage(&empty, None),
            delegate_quorum(&empty),
            replication(&empty, &BTreeMap::new()),
        ]
        .into_iter()
        .map(|check| check.topic)
        .collect()
    }

    /// The bug this guards, seen in the wild: `✗ a backup exists` printed when none did.
    ///
    /// A topic phrased as a claim asserts the good state, so the marker and the words say
    /// opposite things the moment a check fails. A topic must name the subject and leave every
    /// assertion to the detail beside it, which is written to be true whatever was found.
    #[test]
    fn no_topic_asserts_a_state_so_a_failing_line_cannot_contradict_its_own_marker() {
        const CLAIMS: [&str; 7] = ["exists", " is ", " are ", " has ", " have ", "no ", "not "];
        for topic in every_topic() {
            let padded = format!(" {topic} ");
            for claim in CLAIMS {
                assert!(
                    !padded.contains(claim),
                    "the topic {topic:?} asserts a state with {claim:?}; name the subject instead"
                );
            }
        }
    }

    #[test]
    fn a_topic_does_not_change_with_the_verdict_so_two_runs_can_be_compared_line_by_line() {
        let now: jiff::Timestamp = "2026-08-14T12:00:00Z".parse().expect("a valid instant");
        let args = Doctor { backup_dir: None };
        let mut fresh = record();
        fresh.created = "2026-08-13T12:00:00Z".to_string();
        let mut stale = record();
        stale.created = "2026-05-01T12:00:00Z".to_string();

        let taken = backup_freshness(&state::Stored::Record(Box::new(fresh)), now, &args);
        let old = backup_freshness(&state::Stored::Record(Box::new(stale)), now, &args);
        let never = backup_freshness(&state::Stored::Absent, now, &args);
        assert_eq!(taken.verdict, Verdict::Pass);
        assert_eq!(old.verdict, Verdict::Warn);
        assert_eq!(never.verdict, Verdict::Fail);
        assert_eq!(taken.topic, never.topic);
        assert_eq!(old.topic, never.topic);
    }

    #[test]
    fn the_summary_names_every_bucket_rather_than_folding_them_into_a_score() {
        assert_eq!(summary(7, 0, 0, 0), "all 7 checks pass");
        assert_eq!(
            summary(2, 2, 1, 2),
            "2 pass, 2 worth improving, 1 failing, 2 could not be checked"
        );
        // The old line said "6 of 7 checks pass" here, which reads as one failure when there
        // is none: a check nobody could run is not a check that went wrong.
        assert_eq!(summary(6, 0, 0, 1), "6 pass, 1 could not be checked");
    }

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

    /// A same-disk archive may still be replicated: `/mnt/bueno/MEGA/bak` shares a filesystem
    /// with nothing that syncs it locally, but MEGA carries it off the machine. Only the
    /// person running this knows, so the check reports the fact and leaves the verdict short
    /// of a failure. Exiting 3 at somebody who is covered would train them to ignore the 3.
    #[test]
    fn an_archive_on_the_same_filesystem_warns_rather_than_fails_because_it_may_still_be_synced() {
        let dir = std::env::temp_dir().join(format!("rad-backup-locality-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch directory is creatable");
        let archive = dir.join("archive.tar.zst.age");
        std::fs::write(&archive, b"not really an archive").expect("scratch archive is writable");

        let mut record = record();
        record.archive = Some(archive.to_string_lossy().into_owned());
        let check = backup_locality(&dir, Some(&record));
        assert_eq!(check.verdict, Verdict::Warn);
        assert!(
            check.remedy.is_some_and(|remedy| remedy.contains("sync")),
            "the remedy has to name the case where the same disk is still safe"
        );

        let _ = std::fs::remove_dir_all(dir);
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
