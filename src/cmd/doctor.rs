//! Reporting how recoverable an identity currently is.
//!
//! This is the answer to the question the Radicle support channel keeps getting: "what is my
//! exposure, and what do I do about it". Every failing line names the command that fixes it,
//! and every check says what it actually looked at, because a score nobody can audit is a
//! score nobody should trust.

use std::collections::{BTreeMap, BTreeSet};

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
            // `detail` for the remedy under a check that is not a Pass, so `--quiet` cannot
            // print "you would lose this" and withhold the one line that fixes it.
            if let Some(remedy) = &check.remedy {
                let line = format!("--> {remedy}");
                match check.verdict {
                    Verdict::Pass => term.hint(&line),
                    _ => term.detail(&line),
                }
            }
        }
        term.blank();
        term.headline(&summary(passed, warned, failed, unknown));
        if failed > 0 {
            term.detail("every ✗ is a way to lose this identity; the line under it is the fix");
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

    let mut checks = vec![check_key_protection(&secret, &home.secret_key())];
    checks.push(check_backup_freshness(&stored, now, args));
    checks.push(check_backup_encryption(record));
    checks.push(check_backup_locality(home.path(), record));
    checks.push(check_private_coverage(&inventory, record));
    checks.push(check_delegate_quorum(&inventory));
    checks.push(check_replication(&inventory, &routing));
    checks.push(check_sole_holder(record));
    checks.push(check_propagation(
        &inventory,
        &db::synced_heads(&home.node_db(), &node_id)?,
        &node_id,
    ));
    Ok(checks)
}

fn check_key_protection(secret: &SecretKey, key_path: &std::path::Path) -> Check {
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
        .with_remedy(format!(
            "add one: ssh-keygen -p -f '{}'",
            key_path.display()
        )),
    }
}

fn check_backup_freshness(stored: &state::Stored, now: jiff::Timestamp, args: &Doctor) -> Check {
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

fn check_backup_encryption(record: Option<&state::Record>) -> Check {
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
            "the newest archive can be read by anyone who holds it, your key file included",
        )
        .with_remedy("take another without --plaintext, then delete the old one"),
        None => Check::new(TOPIC, Verdict::Unknown, "there is no archive to judge"),
    }
}

fn check_backup_locality(home: &std::path::Path, record: Option<&state::Record>) -> Check {
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
    match crate::perms::same_device(path, home) {
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

fn check_private_coverage(inventory: &Inventory, record: Option<&state::Record>) -> Check {
    const TOPIC: &str = "private repositories";
    let private: Vec<&crate::manifest::RepoRecord> = inventory.private().collect();
    if private.is_empty() {
        return Check::new(TOPIC, Verdict::Pass, "there are none to lose");
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
            TOPIC,
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
    Check::new(TOPIC, verdict, detail).with_remedy("rad backup --repos private")
}

fn check_delegate_quorum(inventory: &Inventory) -> Check {
    let sole: Vec<&str> = inventory
        .sole_delegate()
        .map(|repo| repo.display_name())
        .collect();
    let delegated = inventory
        .described
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

fn check_replication(inventory: &Inventory, routing: &BTreeMap<String, u64>) -> Check {
    let alone: Vec<&str> = inventory
        .described
        .iter()
        .filter(|repo| !repo.is_private())
        .filter(|repo| routing.get(&repo.rid).copied().unwrap_or(0) == 0)
        .map(|repo| repo.display_name())
        .collect();

    const TOPIC: &str = "other seeds";
    if routing.is_empty() {
        return Check::new(
            TOPIC,
            Verdict::Unknown,
            "the routing table is empty, so no other node is known to hold anything",
        )
        .with_remedy(
            "start the node with `rad node start` and let it gossip, then run this again",
        );
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

/// Work that is signed here and has reached nobody.
///
/// Distinct from `check_replication` beside it, and the distinction is the whole point: that
/// one asks whether a repository exists anywhere else, this one asks whether the LATEST work
/// in it does. A repository can be held by forty seeds and still have this morning's commits
/// on one disk, which is the loss a file copy of the home cannot see.
///
/// Private repositories are left out. They are announced to nobody by design, so counting them
/// here would report the feature working as a failure.
fn check_propagation(
    inventory: &Inventory,
    synced: &BTreeMap<String, BTreeSet<String>>,
    node_id: &str,
) -> Check {
    const TOPIC: &str = "signed refs propagation";
    if synced.is_empty() {
        return Check::new(
            TOPIC,
            Verdict::Unknown,
            "the node has no record of what any other node holds, so nothing can be compared",
        )
        .with_remedy("start the node with `rad node start` and run this again once it has synced");
    }

    let mut here_only = Vec::new();
    for repo in &inventory.described {
        if repo.is_private() {
            continue;
        }
        // No signed refs of our own means nothing of ours to propagate, not work stuck here.
        let Some(mine) = repo.sigrefs.get(node_id) else {
            continue;
        };
        let elsewhere = synced
            .get(&repo.rid)
            .is_some_and(|heads| heads.contains(mine));
        if !elsewhere {
            here_only.push(repo.display_name());
        }
    }

    if here_only.is_empty() {
        return Check::new(
            TOPIC,
            Verdict::Pass,
            "every public repository here has its current signed refs on at least one other node",
        );
    }
    Check::new(
        TOPIC,
        Verdict::Warn,
        format!(
            "the newest signed refs of {} {} on this disk and no other: {}",
            term::count(here_only.len(), "repository", "repositories"),
            term::agree(here_only.len()),
            here_only.join(", ")
        ),
    )
    .with_remedy(
        "`rad sync --announce` them, and keep an archive covering them until they have propagated",
    )
}

/// Whether another machine may still be running this identity.
///
/// Two nodes signing under one peer id is the one hazard the thread that produced this tool
/// agreed on without dissent, and a restore is how a second one comes into being: the archive
/// puts the key here while the machine it came from still holds its own copy. `move` is the
/// command that closes it, by retiring the source key as part of the run, so an archive that
/// says it was written by a move is the one case this can pass on.
fn check_sole_holder(record: Option<&state::Record>) -> Check {
    const TOPIC: &str = "key copies";
    let Some(restored) = record.and_then(|record| record.restored.as_ref()) else {
        return Check::new(
            TOPIC,
            Verdict::Pass,
            "this home was not restored from an archive, so nothing here suggests a second copy",
        );
    };

    match restored.source_retires_key {
        Some(true) => Check::new(
            TOPIC,
            Verdict::Pass,
            "this home was moved here, and a move retires the key on the machine it came from",
        ),
        // Said as a possibility, never as a finding: this tool cannot see the other machine,
        // and telling somebody their identity is being double-signed when it is not would send
        // them to retire a key they still need.
        Some(false) => Check::new(
            TOPIC,
            Verdict::Warn,
            match restored.source_node_was_running {
                true => {
                    "this home was restored from a backup, and that backup was taken from a \
                         machine with a node running"
                }
                false => {
                    "this home was restored from a backup, which leaves the key on the \
                          machine the backup was taken from"
                }
            },
        )
        .with_remedy(
            "make sure that machine is not running a node: `rad node stop` there, or `rad \
             backup move` next time, which retires its key for you",
        ),
        None => Check::new(
            TOPIC,
            Verdict::Unknown,
            "this home was restored from an archive written before archives said whether their \
             source retires its key",
        )
        .with_remedy("make sure the machine it came from is not running a node"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every topic the report can print, one per check, whatever the verdict turns out to be.
    fn every_topic() -> Vec<String> {
        let now: jiff::Timestamp = "2026-08-14T12:00:00Z".parse().expect("a valid instant");
        let args = Doctor { backup_dir: None };
        let empty = Inventory {
            described: Vec::new(),
            selected: Default::default(),
            warnings: Vec::new(),
        };
        // The key check is built the long way rather than left out: a sweep that exempts
        // one of the nine checks it exists to police is a sweep that reports a conformance
        // it is not checking.
        let seed = zeroize::Zeroizing::new([1u8; 32]);
        let openssh = crate::key::openssh_from_seed(&seed, None).expect("key is buildable");
        let path = std::env::temp_dir().join(format!("rad-backup-topics-{}", std::process::id()));
        std::fs::write(&path, &*openssh).expect("scratch key is writable");
        let secret = SecretKey::read(&path).expect("key is readable");
        let key = check_key_protection(&secret, &path);
        let _ = std::fs::remove_file(path);

        vec![
            key,
            check_backup_freshness(&state::Stored::Absent, now, &args),
            check_backup_encryption(None),
            check_backup_locality(std::path::Path::new("/nowhere"), None),
            check_private_coverage(&empty, None),
            check_delegate_quorum(&empty),
            check_replication(&empty, &BTreeMap::new()),
            check_sole_holder(None),
            check_propagation(&empty, &BTreeMap::new(), "z6MkAAA"),
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
        // ` on ` and `elsewhere` were added after `key on another machine` and `signed refs
        // elsewhere` both printed a topic the detail beside them then denied. The seven before
        // them caught neither.
        const CLAIMS: [&str; 9] = [
            "exists",
            " is ",
            " are ",
            " has ",
            " have ",
            "no ",
            "not ",
            " on ",
            "elsewhere",
        ];
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

        let taken = check_backup_freshness(&state::Stored::Record(Box::new(fresh)), now, &args);
        let old = check_backup_freshness(&state::Stored::Record(Box::new(stale)), now, &args);
        let never = check_backup_freshness(&state::Stored::Absent, now, &args);
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
    fn an_unencrypted_archive_does_not_claim_to_know_how_the_key_inside_it_is_stored() {
        // This check reads one bool: whether the ARCHIVE was encrypted. It has never been told
        // whether the key file inside carries its own passphrase, so a detail claiming the key
        // is in the clear was false for everyone whose key is not, which is everyone the check
        // above tells to add one.
        let mut plaintext = record();
        plaintext.encrypted = false;
        let check = check_backup_encryption(Some(&plaintext));
        assert_eq!(check.verdict, Verdict::Fail);
        assert!(!check.detail.contains("in the clear"), "{}", check.detail);
    }

    #[test]
    fn a_plaintext_key_fails_and_says_how_to_fix_it() {
        let seed = zeroize::Zeroizing::new([1u8; 32]);
        let openssh = crate::key::openssh_from_seed(&seed, None).expect("key is buildable");
        let path = std::env::temp_dir().join(format!("rad-backup-doctor-{}", std::process::id()));
        std::fs::write(&path, &*openssh).expect("scratch key is writable");

        let secret = SecretKey::read(&path).expect("key is readable");
        let check = check_key_protection(&secret, &path);
        assert_eq!(check.verdict, Verdict::Fail);
        // The path this home actually uses, not `$RAD_HOME`, which is unset for everyone who
        // never set it and left the one line that fixes this un-runnable as printed.
        let remedy = check.remedy.clone().expect("a failing key names its fix");
        assert!(remedy.contains(&path.display().to_string()), "{remedy}");
        assert!(!remedy.contains("RAD_HOME"), "{remedy}");

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_backup_that_has_never_been_taken_fails_rather_than_being_unknown() {
        let now: jiff::Timestamp = "2026-08-14T12:00:00Z".parse().expect("a valid instant");
        let check =
            check_backup_freshness(&state::Stored::Absent, now, &Doctor { backup_dir: None });
        assert_eq!(check.verdict, Verdict::Fail);
        assert_eq!(check.remedy.as_deref(), Some("rad backup"));
    }

    #[test]
    fn a_backup_older_than_the_stale_mark_warns_but_does_not_fail() {
        let now: jiff::Timestamp = "2026-08-14T12:00:00Z".parse().expect("a valid instant");
        let mut record = record();
        record.created = "2026-05-01T12:00:00Z".to_string();
        let stored = state::Stored::Record(Box::new(record.clone()));
        let check = check_backup_freshness(&stored, now, &Doctor { backup_dir: None });
        assert_eq!(check.verdict, Verdict::Warn);

        record.created = "2026-08-13T12:00:00Z".to_string();
        let stored = state::Stored::Record(Box::new(record));
        let check = check_backup_freshness(&stored, now, &Doctor { backup_dir: None });
        assert_eq!(check.verdict, Verdict::Pass);
    }

    #[test]
    fn a_state_file_that_no_longer_parses_is_unknown_rather_than_never_taken() {
        let now: jiff::Timestamp = "2026-08-14T12:00:00Z".parse().expect("a valid instant");
        let stored = state::Stored::Unreadable {
            path: std::path::PathBuf::from("/nowhere/state.json"),
            reason: "expected value at line 1 column 1".to_string(),
        };
        let check = check_backup_freshness(&stored, now, &Doctor { backup_dir: None });
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
        let check = check_backup_locality(&dir, Some(&record));
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
        assert_eq!(
            check_backup_encryption(Some(&record)).verdict,
            Verdict::Fail
        );
        record.encrypted = true;
        assert_eq!(
            check_backup_encryption(Some(&record)).verdict,
            Verdict::Pass
        );
        assert_eq!(check_backup_encryption(None).verdict, Verdict::Unknown);
    }

    const ME: &str = "z6MkAAA";

    /// A public repository whose current signed refs are `head`.
    fn signed(rid: &str, head: &str) -> crate::manifest::RepoRecord {
        crate::manifest::RepoRecord {
            rid: rid.to_string(),
            name: None,
            visibility: Some("public".to_string()),
            allowed: Vec::new(),
            delegate: false,
            delegates: Vec::new(),
            scope: None,
            policy: None,
            head: None,
            refs: 1,
            sigrefs: BTreeMap::from([(ME.to_string(), head.to_string())]),
            other_seeds: None,
            bundle: None,
        }
    }

    fn holding(records: Vec<crate::manifest::RepoRecord>) -> Inventory {
        Inventory {
            described: records,
            selected: Default::default(),
            warnings: Vec::new(),
        }
    }

    #[test]
    fn work_no_other_node_holds_is_named_as_being_on_this_disk_alone() {
        let inventory = holding(vec![signed("rad:zAAA", "aaa"), signed("rad:zBBB", "bbb")]);
        // Somebody else has zAAA's current head. Nobody has zBBB's: it was committed and
        // signed here and has reached nothing, which no file copy of the home can tell you.
        let synced = BTreeMap::from([
            ("rad:zAAA".to_string(), BTreeSet::from(["aaa".to_string()])),
            (
                "rad:zBBB".to_string(),
                BTreeSet::from(["older".to_string()]),
            ),
        ]);

        let check = check_propagation(&inventory, &synced, ME);
        assert_eq!(check.verdict, Verdict::Warn);
        assert!(check.detail.contains("rad:zBBB"), "{}", check.detail);
        assert!(!check.detail.contains("rad:zAAA"), "{}", check.detail);
    }

    #[test]
    fn a_private_repository_is_not_counted_as_work_that_failed_to_propagate() {
        // Private repositories are announced to nobody on purpose. Counting them here would
        // report the feature working as a fault, on every run, for everyone who has one.
        let mut private = signed("rad:zPriv", "aaa");
        private.visibility = Some("private".to_string());
        let synced =
            BTreeMap::from([("rad:zOther".to_string(), BTreeSet::from(["x".to_string()]))]);

        let check = check_propagation(&holding(vec![private]), &synced, ME);
        assert_eq!(check.verdict, Verdict::Pass, "{}", check.detail);
    }

    #[test]
    fn a_node_that_has_never_run_is_unknown_rather_than_everything_being_stranded() {
        let inventory = holding(vec![signed("rad:zAAA", "aaa")]);
        let check = check_propagation(&inventory, &BTreeMap::new(), ME);
        assert_eq!(check.verdict, Verdict::Unknown, "{}", check.detail);
    }

    #[test]
    fn a_home_restored_from_a_plain_backup_is_warned_about_the_machine_it_came_from() {
        let mut record = record();
        record.restored = Some(state::Restored {
            source_retires_key: Some(false),
            source_node_was_running: true,
        });
        let check = check_sole_holder(Some(&record));
        assert_eq!(check.verdict, Verdict::Warn);
        assert!(check.remedy.is_some(), "a warning with no way out is a nag");
    }

    #[test]
    fn a_home_that_was_moved_here_is_not_warned_about_a_key_that_was_retired() {
        let mut record = record();
        record.restored = Some(state::Restored {
            source_retires_key: Some(true),
            source_node_was_running: true,
        });
        assert_eq!(check_sole_holder(Some(&record)).verdict, Verdict::Pass);
    }

    #[test]
    fn an_archive_too_old_to_say_whether_it_retired_its_source_is_unknown_not_a_pass() {
        // The dangerous shape: silence read as safety. An archive written before the manifest
        // carried the answer cannot vouch for the machine it came from.
        let mut record = record();
        record.restored = Some(state::Restored {
            source_retires_key: None,
            source_node_was_running: false,
        });
        assert_eq!(check_sole_holder(Some(&record)).verdict, Verdict::Unknown);
    }

    #[test]
    fn a_home_that_was_never_restored_is_not_asked_about_a_machine_it_never_came_from() {
        assert_eq!(check_sole_holder(Some(&record())).verdict, Verdict::Pass);
        assert_eq!(check_sole_holder(None).verdict, Verdict::Pass);
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
            carried: Default::default(),
            described: Default::default(),
            sigrefs: Default::default(),
            seeded: 0,
            followed: 0,
            restored: None,
        }
    }
}
