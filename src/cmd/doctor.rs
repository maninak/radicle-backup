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
use crate::error::{EXIT_CHECKS_FAILED, Error, Result};
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

    /// Hold a check to what it actually looked at, when some repositories' identity documents
    /// could not be read.
    ///
    /// Visibility and delegates live in those documents, and a record that has none of them
    /// looks exactly like a public repository nobody delegates. So a pass over an incomplete
    /// reading is not a pass: "there are no private repositories to lose" is what a home with
    /// no `rad` on PATH used to be told about every private repository it had. A finding stays
    /// a finding, because the ones that were read are still findings, but its count is a floor
    /// and the sentence has to say so.
    fn qualified_by_unread(mut self, unread: usize) -> Self {
        if unread == 0 {
            return self;
        }
        self.detail = format!(
            "{}; {} could not be described, so this is what could be seen and not the whole home",
            self.detail,
            term::count(unread, "repository", "repositories")
        );
        if self.verdict == Verdict::Pass {
            self.verdict = Verdict::Unknown;
        }
        self.remedy.get_or_insert_with(|| {
            "put `rad` on PATH, or check that `rad inspect` answers here, then run again"
                .to_string()
        });
        self
    }
}

pub fn run(ctx: &Ctx, args: &Doctor) -> Result<std::process::ExitCode> {
    ctx.home.require_identity()?;
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
    let routing = db::read_routing_counts(&home.node_db(), &node_id)?;
    let inventory = inventory::collect(
        home,
        &git,
        rad.as_ref(),
        RepoSelection::None,
        &node_id,
        &policies,
        &routing,
    )?;
    // The inventory pass says out loud what it could not read, and every one of those lines
    // is why a check below has to answer "not known" instead of "none". Dropping them left
    // the reader with a report that had gone quiet about the very thing that weakened it.
    for warning in &inventory.warnings {
        ctx.term.warn(warning);
    }
    let unread = inventory.identities_not_read();
    let stored = state::read(&identity.did())?;
    if let Some(complaint) = stored.complaint() {
        ctx.term.warn(&complaint);
    }
    let record = stored.record();
    let now = jiff::Timestamp::now();

    // The archive on disk, found once and answered from twice: how old it is, and whether it
    // is encrypted. Reading it from the state file instead is how both checks came to report
    // on a run that happened rather than on the file that is there.
    let directory = crate::cmd::archive_dir_from_env(args.dir.as_deref(), record);
    let newest = crate::archives::newest(&directory, &node_id)?;

    let mut checks = vec![check_key_protection(&secret, &home.secret_key())];
    checks.push(check_backup_freshness(
        &stored,
        newest.as_ref(),
        &directory,
        now,
    ));
    checks.push(check_archive_encryption(
        &ctx.identities(),
        newest.as_ref(),
        record,
    )?);
    checks.push(check_archive_location(home.path(), newest.as_ref(), record));
    checks.push(
        check_private_coverage(&inventory, record, newest.as_ref()).qualified_by_unread(unread),
    );
    checks.push(check_sole_delegate(&inventory).qualified_by_unread(unread));
    checks.push(
        check_replication(&inventory, &routing, db::saw_schema_drift()).qualified_by_unread(unread),
    );
    checks.push(check_second_key_copy(&stored));
    checks.push(
        check_sigrefs_propagation(
            &inventory,
            &db::read_synced_heads(&home.node_db(), &node_id)?,
            &node_id,
            db::saw_schema_drift(),
        )
        .qualified_by_unread(unread),
    );
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

/// The newest archive there is evidence of, and what that evidence was.
struct Newest {
    /// Its age in whole days. `None` when the stamp it carries does not parse, which is not a
    /// failure: the archive is there, its own claim about when just cannot be read.
    days: Option<i64>,
    /// What the age was read off, so the sentence names something the reader can go and look
    /// at rather than an age from nowhere.
    named: String,
    /// Said beside the age when the file on this disk and the record disagree.
    caveat: Option<Aside>,
}

/// What has to be said beside the age, and whether it takes the shine off a pass.
///
/// An enum rather than a second boolean beside the string, because the two asides pull in
/// opposite directions and a caller cannot tell them apart by looking: one means there is no
/// archive at hand, the other means there is a fresher one somewhere else. Told apart by
/// whether a caveat was present at all, the second turned a covered home into a warning.
enum Aside {
    /// The age was read off the record, and the file it names is not there. A pass would
    /// otherwise read as "there is an archive here to restore from", and there is not.
    NotAtHand(String),
    /// A file is here, and the record remembers a newer archive that went somewhere else.
    /// The age below is right about this file; it is just not the newest one that exists.
    SomethingNewerElsewhere(String),
}

impl Aside {
    fn said(&self) -> &str {
        match self {
            Self::NotAtHand(what) | Self::SomethingNewerElsewhere(what) => what,
        }
    }

    fn downgrades_a_pass(&self) -> bool {
        matches!(self, Self::NotAtHand(_))
    }
}

/// Why the archive the record names was not among the ones listed here.
///
/// "Is not there now" was said from the record alone, without looking, and `--output
/// /backups/mine.tar.zst.age` names a file this tool writes and then does not recognise: the
/// listing wants a `-<short node id>-` in the name. So a report said an archive was gone while
/// it sat there, and `check_archive_location` two checks down said it existed, in one run.
fn not_listed_here(path: &str) -> String {
    // Anything the filesystem will not answer about is not proof of absence either.
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => format!("{path} is not there now"),
        Err(e) => format!("{path} could not be looked at: {e}"),
        Ok(_) => format!(
            "{path} is there, but is not named the way this tool lists archives, so no verb \
             that takes an archive will find it on its own"
        ),
    }
}

/// The record's own archive, when it is newer than the file found on this disk.
///
/// Both ages are needed, so a record or a file whose stamp does not parse produces nothing:
/// there is no comparison to report, and inventing one from a missing half is how a report
/// starts saying more than it knows.
fn newer_elsewhere(
    record: Option<&state::Record>,
    here: Option<i64>,
    now: jiff::Timestamp,
) -> Option<Aside> {
    let record = record?;
    let here = here?;
    let recorded = record.age_in_days(now)?;
    (recorded < here).then(|| {
        Aside::SomethingNewerElsewhere(format!(
            "this tool recorded a {} archive {}, which is not in this directory",
            record.tier,
            term::days_ago(recorded)
        ))
    })
}

/// How recently an archive of this identity was taken.
///
/// Two sources, because neither alone is the answer. The state file remembers what this user
/// on this machine last wrote, which is nothing at all when the timer runs as another user,
/// when the state directory has been wiped, or when the home came back through `restore.sh`.
/// The directory holds what is actually there, which is nothing once the last archive has been
/// pruned or carried off. Reading only the first is how "no archive has ever been taken for
/// this identity" was printed at a machine with a working nightly backup.
fn check_backup_freshness(
    stored: &state::Stored,
    newest: Option<&crate::archives::Archive>,
    directory: &std::path::Path,
    now: jiff::Timestamp,
) -> Check {
    const TOPIC: &str = "backup";
    let looked_in = directory.display().to_string();
    let record = stored.record();

    // The file that is there answers first: it is what a restore would actually use, and it is
    // there whoever wrote it. The record answers only when nothing is, because an archive
    // carried off to another disk is still an archive that was taken.
    let judged = match (newest, record) {
        (Some(archive), _) => {
            let here = archive.taken.map(|taken| term::days_between(taken, now));
            Newest {
                days: here,
                named: format!("{} in {looked_in}", archive.name()),
                // A nightly `rad backup --stdout` to another disk records an archive this
                // directory never receives. Reading only the file here, the report called a
                // year-old copy the newest backup and never mentioned last night's.
                caveat: newer_elsewhere(record, here, now),
            }
        }
        (None, Some(record)) => Newest {
            days: record.age_in_days(now),
            named: format!("the newest {} archive this tool recorded", record.tier),
            caveat: Some(Aside::NotAtHand(match &record.archive {
                Some(path) => not_listed_here(path),
                None => "it went to stdout, so this tool never knew where it landed".to_string(),
            })),
        },
        (None, None) => {
            if let state::Stored::Unreadable { .. } = stored {
                return Check::new(
                    TOPIC,
                    Verdict::Unknown,
                    format!(
                        "no archive of this identity in {looked_in}, and the record of earlier \
                         ones could not be read"
                    ),
                )
                .with_remedy("take another to replace it: rad backup");
            }
            return Check::new(
                TOPIC,
                Verdict::Fail,
                format!(
                    "no archive of this identity in {looked_in}, and this tool has no record of \
                     one anywhere"
                ),
            )
            .with_remedy(format!("rad backup --output {looked_in}"));
        }
    };

    let Newest {
        days,
        named,
        caveat,
    } = judged;
    let beside = caveat
        .as_ref()
        .map(|caveat| format!(", though {}", caveat.said()))
        .unwrap_or_default();
    let check = match days {
        // Ahead of this clock, so the age says nothing. Left as a Pass it pinned the staleness
        // alarm open forever: one archive taken on a machine whose clock ran fast reported
        // "taken -300 days ago" and never went stale again.
        Some(days) if days < 0 => Check::new(
            TOPIC,
            Verdict::Unknown,
            format!("{named} is stamped in the future, so its age cannot be judged{beside}"),
        )
        .with_remedy("check the clock on the machine that took it, then `rad backup`"),
        Some(days) if days <= STALE_AFTER_DAYS => Check::new(
            TOPIC,
            Verdict::Pass,
            format!("{named} was taken {}{beside}", term::days_ago(days)),
        ),
        Some(days) => Check::new(
            TOPIC,
            Verdict::Warn,
            format!("{named} was taken {}{beside}", term::days_ago(days)),
        )
        .with_remedy("rad backup"),
        None => Check::new(
            TOPIC,
            Verdict::Unknown,
            format!("{named} carries a timestamp that does not parse{beside}"),
        ),
    };
    // An archive that is not where it was is still an archive, but a clean pass would say it
    // is at hand, and it is not. A newer one on another disk is the opposite news and leaves
    // the pass alone.
    match check.verdict == Verdict::Pass && caveat.is_some_and(|caveat| caveat.downgrades_a_pass())
    {
        true => Check {
            verdict: Verdict::Warn,
            ..check
        }
        .with_remedy("take another where this tool will find it: rad backup"),
        false => check,
    }
}

/// Whether the newest archive can still be read by someone who is not you, and whether it can
/// still be read by you.
///
/// Read off the file, never off the state record. The record says what a run once wrote, so it
/// answered "the newest archive cannot be read without its passphrase" over a directory whose
/// only archive was a plaintext one somebody dropped there by hand. It also cannot answer the
/// half that matters more: an archive encrypted to a key nobody still holds is as lost as no
/// archive at all, and only trying the unwrap says so.
fn check_archive_encryption(
    identities: &crate::crypt::Identities,
    newest: Option<&crate::archives::Archive>,
    record: Option<&state::Record>,
) -> Result<Check> {
    const TOPIC: &str = "archive encryption";
    let Some(archive) = newest else {
        // Nothing here to open, so the record is all there is, and it is hearsay about a file
        // this run never saw. It is still worth repeating when what it remembers is bad news.
        return Ok(match record {
            Some(record) if !record.is_encrypted => Check::new(
                TOPIC,
                Verdict::Warn,
                "no archive of this identity was found here, and the last one this tool wrote \
                 was written in the clear",
            )
            .with_remedy("wherever that archive is, it can be read by anyone holding it"),
            Some(_) => Check::new(
                TOPIC,
                Verdict::Unknown,
                "no archive of this identity was found here, so none could be opened",
            ),
            None => Check::new(TOPIC, Verdict::Unknown, "there is no archive to judge"),
        });
    };

    let name = archive.name();
    if !crate::crypt::looks_encrypted(&archive.path)? {
        return Ok(Check::new(
            TOPIC,
            Verdict::Fail,
            format!("{name} can be read by anyone who holds it, your key file included"),
        )
        .with_remedy("take another without --plaintext, then delete the old one"));
    }
    if crate::crypt::needs_passphrase(&archive.path)? {
        // Not opened, because opening it means asking for the passphrase, and a health report
        // that prompts is one people stop running. The header is enough to say which key it
        // wants, and a passphrase is something its owner can test whenever they like.
        return Ok(Check::new(
            TOPIC,
            Verdict::Pass,
            format!("{name} opens only with the passphrase it was sealed under"),
        ));
    }

    if identities.files.is_empty() {
        return Ok(Check::new(
            TOPIC,
            Verdict::Unknown,
            format!("{name} is encrypted to a key, and no key was offered to try against it"),
        )
        .with_remedy("rad backup doctor --identity ~/.ssh/id_ed25519"));
    }
    // The whole point of the check: the header unwraps or it does not, and everything after it
    // (zstd, tar, the manifest) is somebody else's check. Opening far enough to build the zstd
    // decoder has already made age produce the file key, so this proves the key on hand opens
    // the archive without reading a gigabyte to find out.
    //
    // Never interactively, whatever the run outside is: a passphrase-protected ssh key is the
    // state this tool recommends, and a health report that stops to ask for its passphrase is
    // one people take off the timer.
    let silent = crate::crypt::Identities {
        is_interactive: false,
        ..identities.clone()
    };
    Ok(
        match crate::container::Reader::open(&archive.path, None, &silent) {
            Ok(_) => Check::new(
                TOPIC,
                Verdict::Pass,
                format!("{name} is encrypted to a key, and the key offered here opens it"),
            ),
            // The key never came unlocked, or came unlocked and was of a type age cannot use.
            // Either way nothing was learnt about the archive, and reported as a Fail this was
            // a permanent red line, and an exit 3 every night, for the setup the README asks
            // for.
            Err(
                Error::KeysStayedLocked { what, remedy } | Error::KeyNotUsable { what, remedy },
            ) => Check::new(TOPIC, Verdict::Unknown, format!("{name}: {what}")).with_remedy(remedy),
            Err(e) => Check::new(TOPIC, Verdict::Fail, format!("{name} did not open: {e}"))
                .with_remedy(
                    "an archive whose key is gone is not a backup; take another one you can open",
                ),
        },
    )
}

/// Whether the archive would survive whatever takes the home with it.
fn check_archive_location(
    home: &std::path::Path,
    newest: Option<&crate::archives::Archive>,
    record: Option<&state::Record>,
) -> Check {
    const TOPIC: &str = "archive location";
    // The file that is there first, then the path the record remembers, which may well be on
    // another disk entirely and is the more interesting answer when it is.
    let recorded = record.and_then(|record| record.archive.as_ref());
    let judged = newest.map(|archive| archive.path.clone()).or_else(|| {
        recorded
            .map(std::path::PathBuf::from)
            .filter(|path| path.exists())
    });
    let Some(path) = judged else {
        return match recorded {
            Some(archive) => Check::new(
                TOPIC,
                Verdict::Unknown,
                format!("{archive} is not there now, so where it sits could not be judged"),
            )
            .with_remedy("if you moved it somewhere safe, this is fine; if not, take another"),
            None => Check::new(TOPIC, Verdict::Unknown, "there is no archive to locate"),
        };
    };

    let name = path.display().to_string();
    match crate::perms::same_device(&path, home) {
        // A warning and not a failure, because the same filesystem does not mean the same
        // fate: a directory synced by MEGA, Dropbox, Drive or Syncthing is already off this
        // machine, and this tool has no way to know whether one is watching. Failing a posture
        // it cannot evaluate would make `doctor` exit 3 at somebody who is properly covered.
        Some(true) => Check::new(
            TOPIC,
            Verdict::Warn,
            format!("{name} is on the same filesystem as the home it protects"),
        )
        .with_remedy(
            "one dead disk would take both, unless something replicates that directory off this \
             machine. If a sync client watches it, this line is noise; if not, copy the archive \
             to another disk, another machine, or a service you trust",
        ),
        // A different filesystem is not always a different disk: two partitions of one drive,
        // or a loopback mount, answer the same way as a second machine would. It is the most
        // this can be told without asking the kernel about the block device under each.
        Some(false) => Check::new(
            TOPIC,
            Verdict::Pass,
            format!("{name} is on a different filesystem from the home it protects"),
        )
        .with_remedy(
            "worth confirming it is also a different disk, which two partitions of one drive \
             are not",
        ),
        None => Check::new(
            TOPIC,
            Verdict::Unknown,
            format!("{name} and the home could not be compared"),
        ),
    }
}

/// Whether the record is about the archive this run found on the disk.
///
/// `Record::carries` answers off the record, which is hearsay about a file this run may never
/// have seen: the timer may run as another user, the archive may have been pruned or moved
/// since, and `restore.sh` writes no record at all. The freshness and encryption checks were
/// moved onto the file for exactly that reason. The coverage check below still has only the
/// record to go on, because knowing which repositories are inside an archive means opening it,
/// so it says whose word it is taking instead.
fn record_is_about(record: &state::Record, newest: Option<&crate::archives::Archive>) -> bool {
    match (record.archive.as_deref(), newest) {
        (Some(recorded), Some(found)) => std::path::Path::new(recorded) == found.path,
        _ => false,
    }
}

fn check_private_coverage(
    inventory: &Inventory,
    record: Option<&state::Record>,
    newest: Option<&crate::archives::Archive>,
) -> Check {
    const TOPIC: &str = "private repositories";
    let private: Vec<&crate::manifest::RepoRecord> = inventory.private().collect();
    if private.is_empty() {
        return Check::new(TOPIC, Verdict::Pass, "there are none to lose");
    }
    let vouched = record.is_some_and(|record| record_is_about(record, newest));

    // A private repository is not automatically the only copy. Its owner can allow peers to
    // hold it, and the routing table knows when one announces it. Those are different degrees
    // of safety, and this check says which one each repository is in rather than failing them
    // all alike.
    let missing: Vec<&&crate::manifest::RepoRecord> = private
        .iter()
        .filter(|repo| !record.is_some_and(|record| record.carries(&repo.rid)))
        .collect();
    if missing.is_empty() {
        return match vouched {
            true => Check::new(
                TOPIC,
                Verdict::Pass,
                format!(
                    "all {} of them are in the newest archive here",
                    private.len()
                ),
            ),
            // A pass on the strength of a record about a file nothing here matched. Said as an
            // unknown, because "they are all backed up" about an archive this run never found
            // is the shape of claim this whole report exists not to make.
            false => Check::new(
                TOPIC,
                Verdict::Unknown,
                format!(
                    "all {} of them are in the last archive this tool recorded, which is not \
                     the newest one found here",
                    private.len()
                ),
            )
            .with_remedy(
                "point --dir at where that archive went, or take one here with `rad backup \
                 --repos private`",
            ),
        };
    }
    let alone = missing
        .iter()
        .filter(|repo| !repo.has_another_holder())
        .count();
    let (count, verb) = (missing.len(), term::is_or_are(missing.len()));
    let detail = if alone == 0 {
        format!(
            "{count} of {} {verb} in no archive, though somebody else holds every one of \
             those: a delegate, an allowed peer, or a node announcing it",
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

fn check_sole_delegate(inventory: &Inventory) -> Check {
    let sole: Vec<&str> = inventory
        .solely_delegated()
        .map(|repo| repo.display_name())
        .collect();
    let delegated = inventory
        .records
        .iter()
        .filter(|repo| repo.is_delegate)
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

/// What to tell somebody an empty table sent here.
///
/// "Start the node" is right when the node has never gossiped and wrong when it is running
/// perfectly against a schema this build cannot read, and the two arrive as the same empty map.
/// The warning naming the file and the sqlite reason is printed by the command layer either
/// way; this is only about not sending a reader to start a node that is already up.
fn empty_because(schema_has_moved_on: bool, then: &str) -> String {
    if schema_has_moved_on {
        "this build cannot read part of the node's schema; see the warnings below".to_string()
    } else {
        format!("start the node with `rad node start` and {then}")
    }
}

fn check_replication(
    inventory: &Inventory,
    routing: &BTreeMap<String, u64>,
    schema_has_moved_on: bool,
) -> Check {
    // `is_public`, not `!is_private`: a record whose identity document was never read has no
    // visibility, and passing it here put a repository that may well be private into a list
    // whose remedy is `rad sync --announce`. The caller qualifies the count with how many
    // could not be described.
    let alone: Vec<&str> = inventory
        .records
        .iter()
        .filter(|repo| repo.is_public())
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
        .with_remedy(empty_because(schema_has_moved_on, "let it gossip"));
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
            term::is_or_are(alone.len()),
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
/// here would report the feature working as a failure. A repository whose identity document
/// nothing could read is not known to be public either, which is why the caller qualifies this
/// answer the way it qualifies every other check that reads identity documents: without it, a
/// home with no `rad` on PATH was told to announce repositories that must never be announced.
fn check_sigrefs_propagation(
    inventory: &Inventory,
    synced_heads: &BTreeMap<String, BTreeSet<String>>,
    node_id: &str,
    schema_has_moved_on: bool,
) -> Check {
    const TOPIC: &str = "signed refs propagation";
    if synced_heads.is_empty() {
        return Check::new(
            TOPIC,
            Verdict::Unknown,
            "the node has no record of what any other node holds, so nothing can be compared",
        )
        .with_remedy(empty_because(
            schema_has_moved_on,
            "run this again once it has synced",
        ));
    }

    let mut here_only = Vec::new();
    for repo in &inventory.records {
        // Only a repository known to be public. One whose identity document was never read is
        // not known to be anything, and this list ends in `rad sync --announce`.
        if !repo.is_public() {
            continue;
        }
        // No signed refs of our own means nothing of ours to propagate, not work stuck here.
        let Some(mine) = repo.sigrefs.get(node_id) else {
            continue;
        };
        // When each node said so is not this check's question, and the reader no longer
        // offers it: a head that reached anybody, ever, has left this disk.
        let elsewhere = synced_heads
            .get(&repo.rid)
            .is_some_and(|heads| heads.iter().any(|head| crate::git::same_oid(head, mine)));
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
            term::is_or_are(here_only.len()),
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
///
/// Given the whole `Stored` and not just its record, because the two ways there is no record
/// are not the same answer. A missing state file is the normal shape of a home restored under
/// `sudo`, or by `restore.sh`, which writes none: reading that as "not restored from an
/// archive" printed a green line about the double-signing hazard at exactly the people most
/// likely to be in it.
fn check_second_key_copy(stored: &state::Stored) -> Check {
    const TOPIC: &str = "key copies";
    let record = match stored {
        state::Stored::Record(record) => record,
        state::Stored::Absent => {
            return Check::new(
                TOPIC,
                Verdict::Unknown,
                "this tool has no record of where this home came from, so whether another \
                 machine holds the same key is not known here",
            )
            .with_remedy(
                "if this home was restored or copied from another machine, make sure that \
                 machine is not running a node",
            );
        }
        state::Stored::Unreadable { .. } => {
            return Check::new(
                TOPIC,
                Verdict::Unknown,
                "the record of where this home came from could not be read, so whether another \
                 machine holds the same key is not known here",
            )
            .with_remedy(
                "if this home was restored or copied from another machine, make sure that \
                 machine is not running a node",
            );
        }
    };

    let Some(restored) = record.restored.as_ref() else {
        return Check::new(
            TOPIC,
            Verdict::Pass,
            "this home was not restored from an archive, so nothing here suggests a second copy",
        );
    };

    match restored.source_retires_key {
        // What the archive recorded, not what happened on the other machine: this tool has
        // never been there. `move` retires the key as part of its own run, so the claim is a
        // good one, but a sentence that stated it as fact would be stating something it cannot
        // see, and `--keep-source` is exactly the case where it would be wrong.
        Some(true) => Check::new(
            TOPIC,
            Verdict::Pass,
            "this home was moved here, and the archive records the machine it came from as \
             retiring its key",
        ),
        // Said as a possibility, never as a finding: this tool cannot see the other machine,
        // and telling somebody their identity is being double-signed when it is not would send
        // them to retire a key they still need.
        Some(false) => Check::new(
            TOPIC,
            Verdict::Warn,
            match (
                restored.source_node_was_running,
                restored.source_node_state_was_guessed,
            ) {
                (true, false) => {
                    "this home was restored from a backup, and that backup was taken from a \
                     machine with a node running"
                }
                // The source run could not reach the socket and recorded the cautious answer.
                // Repeating that as a fact is this report asserting what nothing established.
                (true, true) => {
                    "this home was restored from a backup, and the run that took it could not \
                     tell whether that machine had a node running"
                }
                (false, _) => {
                    "this home was restored from a backup, which leaves the key on the machine \
                     the backup was taken from"
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
    use age::secrecy::ExposeSecret as _;

    use super::*;
    use crate::key::tests::TestScratch;

    /// A key file for a test, owner-only inside an owner-only directory, because these used
    /// to be `std::fs::write` into `/tmp` at the umask default under a pid-guessable name.
    fn secret_file(path: &std::path::Path, contents: &str) {
        use std::io::Write as _;

        let mut file = crate::perms::create_private_file(path).expect("scratch file is creatable");
        file.write_all(contents.as_bytes())
            .expect("scratch file is writable");
    }

    /// Freshness judged with nothing on disk, which is the case every state-record test is
    /// about: what the tool remembers, when the directory it looked in holds nothing.
    fn recorded_freshness(stored: &state::Stored, now: jiff::Timestamp) -> Check {
        check_backup_freshness(stored, None, std::path::Path::new("/nowhere"), now)
    }

    /// An archive found on disk, stamped `when`. Freshness never opens one, so no file is
    /// needed to ask it how old what it found is.
    fn found(when: &str) -> crate::archives::Archive {
        crate::archives::Archive {
            path: std::path::PathBuf::from(
                "/nowhere/radicle-z6MkAAAAAAAA-20260813T120000Z.tar.zst",
            ),
            bytes: 4096,
            taken: Some(when.parse().expect("a valid instant")),
            encrypted: Some(false),
        }
    }

    /// Freshness judged on an archive that is there, which is what a covered machine looks
    /// like: the file answers, and the record beside it is never consulted.
    fn found_freshness(when: &str, now: jiff::Timestamp) -> Check {
        check_backup_freshness(
            &state::Stored::Absent,
            Some(&found(when)),
            std::path::Path::new("/nowhere"),
            now,
        )
    }

    /// The shape: a nightly `rad backup --stdout` to another disk, and one old copy lying in
    /// the directory `doctor` looks in. Read off the file alone, the report called a year-old
    /// archive the newest backup and never mentioned last night's; downgraded for having
    /// anything to say, it warned at a machine that is covered.
    #[test]
    fn a_newer_archive_the_record_remembers_is_said_beside_an_older_file_without_costing_the_pass()
    {
        let now: jiff::Timestamp = "2026-08-14T12:00:00Z".parse().expect("a valid instant");
        let mut recorded = record();
        recorded.created = "2026-08-13T00:00:00Z".to_string();
        recorded.archive = None;
        let stored = state::Stored::Record(Box::new(recorded));

        let stale_file = check_backup_freshness(
            &stored,
            Some(&found("2025-08-14T12:00:00Z")),
            std::path::Path::new("/nowhere"),
            now,
        );
        assert_eq!(stale_file.verdict, Verdict::Warn, "{}", stale_file.detail);
        assert!(
            stale_file.detail.contains("not in this directory"),
            "{}",
            stale_file.detail
        );

        // Both fresh, and the record is the fresher of the two. Still a pass: there is an
        // archive here to restore from, and another one newer still somewhere else.
        let fresh_file = check_backup_freshness(
            &stored,
            Some(&found("2026-08-12T12:00:00Z")),
            std::path::Path::new("/nowhere"),
            now,
        );
        assert_eq!(fresh_file.verdict, Verdict::Pass, "{}", fresh_file.detail);
        assert!(
            fresh_file.detail.contains("not in this directory"),
            "{}",
            fresh_file.detail
        );

        // The file here is the newer of the two, so there is nothing to add.
        let newest_here = check_backup_freshness(
            &stored,
            Some(&found("2026-08-14T00:00:00Z")),
            std::path::Path::new("/nowhere"),
            now,
        );
        assert_eq!(newest_here.verdict, Verdict::Pass, "{}", newest_here.detail);
        assert!(
            !newest_here.detail.contains("though"),
            "{}",
            newest_here.detail
        );
    }

    /// Every topic the report can print, one per check, whatever the verdict turns out to be.
    fn every_topic() -> Vec<String> {
        let now: jiff::Timestamp = "2026-08-14T12:00:00Z".parse().expect("a valid instant");
        let empty = Inventory {
            records: Vec::new(),
            selected: Default::default(),
            warnings: Vec::new(),
        };
        // The key check is built the long way rather than left out: a sweep that exempts
        // one of the checks it exists to police reports a conformance it is not checking.
        let seed = zeroize::Zeroizing::new([1u8; 32]);
        let openssh = crate::key::openssh_from_seed(&seed, None).expect("key is buildable");
        let scratch = TestScratch::create("doctor-topics");
        let path = scratch.path_of("radicle");
        secret_file(&path, &openssh);
        let secret = SecretKey::read(&path).expect("key is readable");
        let key = check_key_protection(&secret, &path);

        vec![
            key,
            check_backup_freshness(
                &state::Stored::Absent,
                None,
                std::path::Path::new("/nowhere"),
                now,
            ),
            check_archive_encryption(&Default::default(), None, None)
                .expect("no archive is not an error"),
            check_archive_location(std::path::Path::new("/nowhere"), None, None),
            check_private_coverage(&empty, None, None),
            check_sole_delegate(&empty),
            check_replication(&empty, &BTreeMap::new(), false),
            check_second_key_copy(&state::Stored::Absent),
            check_sigrefs_propagation(&empty, &BTreeMap::new(), "z6MkAAA", false),
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
        // elsewhere` both printed a topic the detail beside them then denied, and none of the
        // earlier claims caught either.
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
        let taken = found_freshness("2026-08-13T12:00:00Z", now);
        let old = found_freshness("2026-05-01T12:00:00Z", now);
        let never = recorded_freshness(&state::Stored::Absent, now);
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
        let scratch = TestScratch::create("doctor-plaintext-key");
        let path = scratch.path_of("radicle");
        secret_file(&path, &openssh);

        let secret = SecretKey::read(&path).expect("key is readable");
        let check = check_key_protection(&secret, &path);
        assert_eq!(check.verdict, Verdict::Fail);
        // The path this home actually uses, not `$RAD_HOME`, which is unset for everyone who
        // never set it and left the one line that fixes this un-runnable as printed.
        let remedy = check.remedy.clone().expect("a failing key names its fix");
        assert!(remedy.contains(&path.display().to_string()), "{remedy}");
        assert!(!remedy.contains("RAD_HOME"), "{remedy}");
    }

    #[test]
    fn a_backup_that_has_never_been_taken_fails_rather_than_being_unknown() {
        let now: jiff::Timestamp = "2026-08-14T12:00:00Z".parse().expect("a valid instant");
        let check = recorded_freshness(&state::Stored::Absent, now);
        assert_eq!(check.verdict, Verdict::Fail);
        // The remedy names where it looked, because "rad backup" alone sends the next archive
        // wherever the default points, which is where this run already found nothing.
        let remedy = check.remedy.expect("a failing backup names its fix");
        assert!(remedy.starts_with("rad backup --output "), "{remedy}");
    }

    #[test]
    fn a_backup_older_than_the_stale_mark_warns_but_does_not_fail() {
        let now: jiff::Timestamp = "2026-08-14T12:00:00Z".parse().expect("a valid instant");
        assert_eq!(
            found_freshness("2026-05-01T12:00:00Z", now).verdict,
            Verdict::Warn
        );
        assert_eq!(
            found_freshness("2026-08-13T12:00:00Z", now).verdict,
            Verdict::Pass
        );
    }

    /// The bug this half fixes: `doctor` read the state file only, so a machine whose nightly
    /// timer runs as another user, or whose home came back through `restore.sh`, was told "no
    /// archive has ever been taken for this identity" while its archives sat in the directory
    /// the same command had just been pointed at.
    #[test]
    fn an_archive_on_disk_answers_even_when_this_tool_has_no_record_of_taking_one() {
        let now: jiff::Timestamp = "2026-08-14T12:00:00Z".parse().expect("a valid instant");
        let check = found_freshness("2026-08-13T12:00:00Z", now);
        assert_eq!(check.verdict, Verdict::Pass, "{}", check.detail);
        assert!(check.detail.contains(".tar.zst"), "{}", check.detail);
    }

    /// The other half: a record fresh enough to pass, over a directory where the file it names
    /// is gone. It may have been carried off somewhere safe, so this is not a failure, but a
    /// clean pass would say the archive is at hand and it is not.
    #[test]
    fn a_recorded_backup_whose_archive_is_not_there_warns_rather_than_passing() {
        let now: jiff::Timestamp = "2026-08-14T12:00:00Z".parse().expect("a valid instant");
        let mut record = record();
        record.created = "2026-08-13T12:00:00Z".to_string();
        record.archive = Some("/media/usb/radicle.tar.zst.age".to_string());

        let check = recorded_freshness(&state::Stored::Record(Box::new(record)), now);
        assert_eq!(check.verdict, Verdict::Warn, "{}", check.detail);
        assert!(
            check.detail.contains("/media/usb/radicle.tar.zst.age"),
            "{}",
            check.detail
        );
    }

    #[test]
    fn a_state_file_that_no_longer_parses_is_unknown_rather_than_never_taken() {
        let now: jiff::Timestamp = "2026-08-14T12:00:00Z".parse().expect("a valid instant");
        let stored = state::Stored::Unreadable {
            path: std::path::PathBuf::from("/nowhere/state.json"),
            reason: "expected value at line 1 column 1".to_string(),
        };
        let check = recorded_freshness(&stored, now);
        assert_eq!(check.verdict, Verdict::Unknown);
        assert!(check.remedy.is_some());
    }

    /// A same-disk archive may still be replicated. A directory a cloud client watches shares
    /// a filesystem with nothing that copies it locally, and is carried off the machine all the
    /// same. Only the person running this knows, so the check reports the fact and leaves the
    /// verdict short of a failure. Exiting 3 at somebody who is covered trains them to ignore
    /// the 3.
    #[test]
    fn an_archive_on_the_same_filesystem_warns_rather_than_fails_because_it_may_still_be_synced() {
        let dir = std::env::temp_dir().join(format!("rad-backup-locality-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch directory is creatable");
        let archive = dir.join("archive.tar.zst.age");
        std::fs::write(&archive, b"not really an archive").expect("scratch archive is writable");

        let mut record = record();
        record.archive = Some(archive.to_string_lossy().into_owned());
        let check = check_archive_location(&dir, None, Some(&record));
        assert_eq!(check.verdict, Verdict::Warn);
        assert!(
            check.remedy.is_some_and(|remedy| remedy.contains("sync")),
            "the remedy has to name the case where the same disk is still safe"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// A real archive on disk, sealed as asked, plus the record a directory scan makes of it.
    ///
    /// Every one of these checks reads the file now, so a fixture that is only a `state::Record`
    /// would test the reading of a claim rather than the reading of an archive.
    fn archive_at(
        dir: &std::path::Path,
        name: &str,
        encryption: &crate::crypt::Encryption,
    ) -> crate::archives::Archive {
        use std::io::Write as _;

        std::fs::create_dir_all(dir).expect("scratch directory is creatable");
        let path = dir.join(name);
        let file = std::fs::File::create(&path).expect("scratch archive is creatable");
        let mut sink =
            crate::crypt::Sink::new(Box::new(file), encryption).expect("sink is buildable");
        // Empty, but genuinely zstd: opening an archive builds the decoder, and a body of
        // rubbish would fail there for a reason that has nothing to do with the key.
        let body = zstd::encode_all(std::io::empty(), 0).expect("zstd encodes nothing");
        sink.write_all(&body).expect("body is writable");
        sink.finish().expect("sink finishes");

        crate::archives::Archive {
            bytes: std::fs::metadata(&path).map(|meta| meta.len()).unwrap_or(0),
            taken: None,
            encrypted: Some(!matches!(encryption, crate::crypt::Encryption::Plaintext)),
            path,
        }
    }

    /// The bug: `rad backup --plaintext` into a directory whose state record remembers an
    /// encrypted run was reported as encrypted, because the check read the record. The record
    /// describes a run; the archive is the thing anyone would steal.
    #[test]
    fn a_plaintext_archive_fails_even_when_the_record_remembers_an_encrypted_one() {
        let dir = std::env::temp_dir().join(format!("rad-backup-crypt-{}", std::process::id()));
        let archive = archive_at(&dir, "plain.tar.zst", &crate::crypt::Encryption::Plaintext);
        let mut record = record();
        record.is_encrypted = true;

        let check = check_archive_encryption(&Default::default(), Some(&archive), Some(&record))
            .expect("the header is readable");
        assert_eq!(check.verdict, Verdict::Fail, "{}", check.detail);
        assert!(check.detail.contains("plain.tar.zst"), "{}", check.detail);

        let _ = std::fs::remove_dir_all(dir);
    }

    /// The freshness check said "is not there now" straight off the record, without looking.
    /// `rad backup --output /backups/mine.tar.zst.age` writes a name the listing does not
    /// recognise (it wants the short node id in it), so a report called an archive gone while
    /// it sat on the disk, and `archive location` in the same report said it was there.
    #[test]
    fn an_archive_the_listing_does_not_recognise_is_not_reported_as_gone() {
        let scratch = TestScratch::create("doctor-unlisted-archive");
        let here = scratch.path_of("mine.tar.zst.age");
        std::fs::write(&here, b"not an archive, but a file that is there")
            .expect("the scratch is writable");

        let said = not_listed_here(&here.display().to_string());
        assert!(said.contains("is there"), "{said}");
        assert!(!said.contains("is not there now"), "{said}");

        let gone = scratch.path_of("never-written.tar.zst.age");
        let said = not_listed_here(&gone.display().to_string());
        assert!(said.contains("is not there now"), "{said}");
    }

    #[test]
    fn an_archive_sealed_with_a_passphrase_passes_without_asking_for_it() {
        let dir = std::env::temp_dir().join(format!("rad-backup-pass-{}", std::process::id()));
        let sealed = crate::crypt::Encryption::Passphrase(zeroize::Zeroizing::new(
            "open sesame".to_string(),
        ));
        let archive = archive_at(&dir, "sealed.tar.zst.age", &sealed);

        // No passphrase is given and none is read from anywhere: a health report that stops to
        // prompt is one nobody schedules.
        let check = check_archive_encryption(&Default::default(), Some(&archive), None)
            .expect("the header is readable");
        assert_eq!(check.verdict, Verdict::Pass, "{}", check.detail);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn an_archive_encrypted_to_a_key_is_unknown_until_a_key_is_offered_and_passes_once_it_is() {
        let scratch = TestScratch::create("doctor-keyed");
        let dir = scratch.path_of("backups");
        let identity = age::x25519::Identity::generate();
        let keyed = crate::crypt::Encryption::Recipients(vec![identity.to_public().to_string()]);
        let archive = archive_at(&dir, "keyed.tar.zst.age", &keyed);

        // Nothing was offered, so nothing was tried. Calling that a pass is how an archive
        // whose key had been lost went on being reported as a working backup.
        let blind = check_archive_encryption(&Default::default(), Some(&archive), None)
            .expect("the header is readable");
        assert_eq!(blind.verdict, Verdict::Unknown, "{}", blind.detail);
        assert!(
            blind.remedy.is_some(),
            "an unknown with no way out is a nag"
        );

        let key_file = dir.join("identity.txt");
        secret_file(&key_file, identity.to_string().expose_secret());
        let offered = crate::crypt::Identities {
            files: vec![key_file],
            ..Default::default()
        };
        let opened = check_archive_encryption(&offered, Some(&archive), None)
            .expect("the header is readable");
        assert_eq!(opened.verdict, Verdict::Pass, "{}", opened.detail);

        let stranger = dir.join("stranger.txt");
        secret_file(
            &stranger,
            age::x25519::Identity::generate()
                .to_string()
                .expose_secret(),
        );
        let wrong = check_archive_encryption(
            &crate::crypt::Identities {
                files: vec![stranger],
                ..Default::default()
            },
            Some(&archive),
            None,
        )
        .expect("the header is readable");
        assert_eq!(wrong.verdict, Verdict::Fail, "{}", wrong.detail);
    }

    /// The bug: an ssh key with a passphrase on it is what the README tells people to have,
    /// and `doctor` reported the archive it opens as a failure every night, because "the key
    /// never came unlocked" was read as "the key does not open this". On a terminal it did
    /// worse and stopped to ask for the passphrase.
    #[test]
    fn a_key_that_stayed_locked_is_a_question_doctor_could_not_put_rather_than_a_failure() {
        let scratch = TestScratch::create("doctor-locked");
        let dir = scratch.path_of("backups");
        let seed = zeroize::Zeroizing::new([7u8; 32]);
        let identity = crate::key::identity_from_seed(&seed).expect("a seed makes a key");
        let keyed = crate::crypt::Encryption::Recipients(vec![
            identity.to_openssh().expect("the public half is printable"),
        ]);
        let archive = archive_at(&dir, "locked.tar.zst.age", &keyed);

        let passphrase = zeroize::Zeroizing::new("open sesame".to_string());
        let key_file = dir.join("id_ed25519");
        secret_file(
            &key_file,
            crate::key::openssh_from_seed(&seed, Some(&passphrase))
                .expect("the key is writable")
                .as_str(),
        );

        // Interactive on purpose, which is how `doctor` is usually called. What this asserts
        // is the verdict; that the check hands age a non-interactive copy of the identities
        // is visible in `check_archive_encryption` and cannot be shown from here, because a
        // test harness has no terminal for the prompt to reach either way.
        let locked = check_archive_encryption(
            &crate::crypt::Identities {
                files: vec![key_file.clone()],
                is_interactive: true,
                ..Default::default()
            },
            Some(&archive),
            None,
        )
        .expect("the header is readable");
        assert_eq!(locked.verdict, Verdict::Unknown, "{}", locked.detail);
        assert!(locked.detail.contains("stayed locked"), "{}", locked.detail);
        assert!(
            locked.remedy.is_some(),
            "an unknown with no way out is a nag"
        );

        // The same key, unlocked by a passphrase file, opens it.
        let passphrase_file = dir.join("passphrase");
        secret_file(&passphrase_file, passphrase.as_str());
        let opened = check_archive_encryption(
            &crate::crypt::Identities {
                files: vec![key_file],
                passphrase_file: Some(passphrase_file),
                is_interactive: false,
            },
            Some(&archive),
            None,
        )
        .expect("the header is readable");
        assert_eq!(opened.verdict, Verdict::Pass, "{}", opened.detail);
    }

    const ME: &str = "z6MkAAA";

    /// A public repository whose current signed refs are `head`.
    fn public_repo_signed_at(rid: &str, head: &str) -> crate::manifest::RepoRecord {
        crate::manifest::RepoRecord {
            rid: rid.to_string(),
            name: None,
            visibility: Some("public".to_string()),
            allowed: Vec::new(),
            is_delegate: false,
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
            records,
            selected: Default::default(),
            warnings: Vec::new(),
        }
    }

    #[test]
    fn work_no_other_node_holds_is_named_as_being_on_this_disk_alone() {
        let inventory = holding(vec![
            public_repo_signed_at("rad:zAAA", "aaa"),
            public_repo_signed_at("rad:zBBB", "bbb"),
        ]);
        // Somebody else has zAAA's current head. Nobody has zBBB's: it was committed and
        // signed here and has reached nothing, which no file copy of the home can tell you.
        let synced = BTreeMap::from([
            ("rad:zAAA".to_string(), BTreeSet::from(["aaa".to_string()])),
            (
                "rad:zBBB".to_string(),
                BTreeSet::from(["older".to_string()]),
            ),
        ]);

        let check = check_sigrefs_propagation(&inventory, &synced, ME, false);
        assert_eq!(check.verdict, Verdict::Warn);
        assert!(check.detail.contains("rad:zBBB"), "{}", check.detail);
        assert!(!check.detail.contains("rad:zAAA"), "{}", check.detail);
    }

    #[test]
    fn a_private_repository_is_not_counted_as_work_that_failed_to_propagate() {
        // Private repositories are announced to nobody on purpose. Counting them here would
        // report the feature working as a fault, on every run, for everyone who has one.
        let mut private = public_repo_signed_at("rad:zPriv", "aaa");
        private.visibility = Some("private".to_string());
        let synced =
            BTreeMap::from([("rad:zOther".to_string(), BTreeSet::from(["x".to_string()]))]);

        let check = check_sigrefs_propagation(&holding(vec![private]), &synced, ME, false);
        assert_eq!(check.verdict, Verdict::Pass, "{}", check.detail);
    }

    #[test]
    fn a_node_that_has_never_run_is_unknown_rather_than_everything_being_stranded() {
        let inventory = holding(vec![public_repo_signed_at("rad:zAAA", "aaa")]);
        let check = check_sigrefs_propagation(&inventory, &BTreeMap::new(), ME, false);
        assert_eq!(check.verdict, Verdict::Unknown, "{}", check.detail);
        let remedy = check.remedy.expect("an unknown says what would answer it");
        assert!(remedy.contains("rad node start"), "{remedy}");
    }

    /// An empty table has two causes, and only one of them is answered by starting a node. A
    /// reader whose node is running fine against a schema this build cannot read was being sent
    /// to start it again, which does nothing and makes the report look wrong about everything.
    #[test]
    fn a_table_this_build_cannot_read_is_not_answered_by_starting_the_node() {
        let inventory = holding(vec![public_repo_signed_at("rad:zAAA", "aaa")]);
        let check = check_sigrefs_propagation(&inventory, &BTreeMap::new(), ME, true);
        assert_eq!(check.verdict, Verdict::Unknown, "{}", check.detail);
        let remedy = check.remedy.expect("an unknown says what would answer it");
        assert!(!remedy.contains("rad node start"), "{remedy}");
        assert!(remedy.contains("schema"), "{remedy}");

        let check = check_replication(&inventory, &BTreeMap::new(), true);
        let remedy = check.remedy.expect("an unknown says what would answer it");
        assert!(!remedy.contains("rad node start"), "{remedy}");
    }

    #[test]
    fn a_home_restored_from_a_plain_backup_is_warned_about_the_machine_it_came_from() {
        let mut record = record();
        record.restored = Some(state::Restored {
            source_retires_key: Some(false),
            source_node_was_running: true,
            source_node_state_was_guessed: false,
        });
        let check = check_second_key_copy(&state::Stored::Record(Box::new(record.clone())));
        assert_eq!(check.verdict, Verdict::Warn);
        assert!(check.remedy.is_some(), "a warning with no way out is a nag");
        assert!(
            check.detail.contains("with a node running"),
            "{}",
            check.detail
        );

        // The same record, except that the run which took the archive could not reach the
        // control socket and wrote the cautious answer. Repeating that as a sighting tells
        // somebody their identity is being double-signed when nothing established it.
        record.restored = Some(state::Restored {
            source_retires_key: Some(false),
            source_node_was_running: true,
            source_node_state_was_guessed: true,
        });
        let guessed = check_second_key_copy(&state::Stored::Record(Box::new(record)));
        assert_eq!(guessed.verdict, Verdict::Warn);
        assert!(
            guessed.detail.contains("could not tell"),
            "{}",
            guessed.detail
        );
    }

    #[test]
    fn a_home_that_was_moved_here_is_not_warned_about_a_key_that_was_retired() {
        let mut record = record();
        record.restored = Some(state::Restored {
            source_retires_key: Some(true),
            source_node_was_running: true,
            source_node_state_was_guessed: false,
        });
        assert_eq!(
            check_second_key_copy(&state::Stored::Record(Box::new(record))).verdict,
            Verdict::Pass
        );
    }

    #[test]
    fn an_archive_too_old_to_say_whether_it_retired_its_source_is_unknown_not_a_pass() {
        // The dangerous shape: silence read as safety. An archive written before the manifest
        // carried the answer cannot vouch for the machine it came from.
        let mut record = record();
        record.restored = Some(state::Restored {
            source_retires_key: None,
            source_node_was_running: false,
            source_node_state_was_guessed: false,
        });
        assert_eq!(
            check_second_key_copy(&state::Stored::Record(Box::new(record))).verdict,
            Verdict::Unknown
        );
    }

    #[test]
    fn a_home_that_was_never_restored_is_not_asked_about_a_machine_it_never_came_from() {
        let stored = state::Stored::Record(Box::new(record()));
        assert_eq!(check_second_key_copy(&stored).verdict, Verdict::Pass);
    }

    /// The bug: `sudo rad-backup restore` writes its record into root's state directory, and
    /// `restore.sh` writes none at all. Both leave the user's own `doctor` with nothing to
    /// read, and reading nothing as "never restored" put a green line on the one hazard this
    /// tool exists for, at the two people most likely to be standing in it.
    #[test]
    fn a_home_with_no_record_of_its_own_origin_is_unknown_rather_than_never_restored() {
        for stored in [
            state::Stored::Absent,
            state::Stored::Unreadable {
                path: std::path::PathBuf::from("/nowhere/state.json"),
                reason: "expected value at line 1 column 1".to_string(),
            },
        ] {
            let check = check_second_key_copy(&stored);
            assert_eq!(check.verdict, Verdict::Unknown, "{}", check.detail);
            assert!(check.remedy.is_some(), "{}", check.detail);
        }
    }

    /// The coverage answer comes off the state record, which is hearsay about a file this run
    /// may never have seen: the timer may run as another user, and the archive it names may
    /// have been pruned or moved. Every other check moved onto the file on disk for that
    /// reason, and this one could not, so it has to say whose word it is taking. It used to
    /// print "all 2 of them are in the newest archive" as a Pass in the same report whose
    /// freshness line said that archive was not there.
    #[test]
    fn coverage_taken_off_the_record_is_not_a_pass_about_the_archive_that_is_here() {
        let mut private = public_repo_signed_at("rad:zAAA", "aaa");
        private.visibility = Some("private".to_string());
        let inventory = holding(vec![private]);

        let mut record = record();
        record.archive = Some("/backups/one.tar.zst.age".to_string());
        record.carried = ["rad:zAAA".to_string()].into_iter().collect();

        let found = crate::archives::Archive {
            path: std::path::PathBuf::from("/backups/one.tar.zst.age"),
            bytes: 1,
            taken: None,
            encrypted: Some(true),
        };
        let check = check_private_coverage(&inventory, Some(&record), Some(&found));
        assert_eq!(check.verdict, Verdict::Pass, "{}", check.detail);

        // The same record beside a different archive, and beside none at all.
        let other = crate::archives::Archive {
            path: std::path::PathBuf::from("/backups/another.tar.zst.age"),
            ..found
        };
        for newest in [Some(&other), None] {
            let check = check_private_coverage(&inventory, Some(&record), newest);
            assert_eq!(check.verdict, Verdict::Unknown, "{}", check.detail);
            assert!(check.detail.contains("recorded"), "{}", check.detail);
        }
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
            is_encrypted: true,
            carried: Default::default(),
            described: Default::default(),
            sigrefs: Default::default(),
            seeded: 0,
            followed: 0,
            restored: None,
        }
    }
}
