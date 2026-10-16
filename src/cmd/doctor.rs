//! Reports how recoverable an identity is now, with a remedy under every failing line.

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

/// The age in days past which a backup stops counting as one, so a timer that stopped
/// firing shows within a month.
const STALE_AFTER_DAYS: i64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Pass,
    Warn,
    Fail,
    /// A check that could not look at what it was asked about. It never counts as a pass.
    Unknown,
    /// A check with nothing yet to look at, such as an archive before the first backup. It
    /// stays apart from `Unknown`, so a first run does not read as a half-blind report.
    Skipped,
}

/// A check's stable id, printed as `checkId` for scripts to match on.
///
/// Ids are frozen once released, and topics may change. The id owns its topic, so the two
/// cannot disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckId {
    KeyPassphrase,
    Backup,
    ArchiveEncryption,
    ArchiveLocation,
    PrivateRepositories,
    SoleDelegate,
    PublicRepositories,
    KeyCopies,
    UnsharedWork,
}

impl CheckId {
    /// The id string scripts match on. Each one is spelled out, so renaming a variant cannot
    /// change it.
    fn id(self) -> &'static str {
        match self {
            Self::KeyPassphrase => "key-passphrase",
            Self::Backup => "backup",
            Self::ArchiveEncryption => "archive-encryption",
            Self::ArchiveLocation => "archive-location",
            Self::PrivateRepositories => "private-repositories",
            Self::SoleDelegate => "sole-delegate",
            Self::PublicRepositories => "public-repositories",
            Self::KeyCopies => "key-copies",
            Self::UnsharedWork => "unshared-work",
        }
    }

    fn topic(self) -> &'static str {
        match self {
            Self::KeyPassphrase => "key passphrase",
            Self::Backup => "backup",
            Self::ArchiveEncryption => "archive encryption",
            Self::ArchiveLocation => "archive location",
            Self::PrivateRepositories => "private repositories",
            Self::SoleDelegate => "sole delegate",
            Self::PublicRepositories => "public repositories",
            Self::KeyCopies => "key copies",
            Self::UnsharedWork => "unshared work",
        }
    }
}

impl Serialize for CheckId {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.id())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    #[serde(rename = "checkId")]
    pub check_id: CheckId,
    /// What was looked at, never what was hoped for, so a failing line cannot read as a claim
    /// arguing with itself, as "✗ a backup exists" would.
    pub topic: &'static str,
    pub verdict: Verdict,
    /// What was found, as a complete statement that is true on its own.
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remedy: Option<String>,
}

impl Check {
    fn new(check_id: CheckId, verdict: Verdict, detail: impl Into<String>) -> Self {
        Self {
            check_id,
            topic: check_id.topic(),
            verdict,
            detail: detail.into(),
            remedy: None,
        }
    }

    fn with_remedy(mut self, remedy: impl Into<String>) -> Self {
        self.remedy = Some(remedy.into());
        self
    }

    /// Marks a check incomplete when some repositories' identity documents could not be read.
    ///
    /// A pass turns `Unknown`, because a record missing its document looks like a public
    /// repository nobody delegates. A finding stays, and its detail says the count is a floor.
    fn qualified_by_unread(mut self, unread: usize) -> Self {
        if unread == 0 {
            return self;
        }
        self.detail = format!(
            "{}. The details of {} could not be read, so this result may be incomplete",
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
    let tallied = Tally {
        passed: tally(Verdict::Pass),
        warned: tally(Verdict::Warn),
        failed: tally(Verdict::Fail),
        unknown: tally(Verdict::Unknown),
        skipped: tally(Verdict::Skipped),
    };

    if ctx.global.json {
        ctx.term.print_json(&serde_json::json!({
            "home": ctx.home.path().display().to_string(),
            "passed": tallied.passed,
            "warned": tallied.warned,
            "failed": tallied.failed,
            "unknown": tallied.unknown,
            "skipped": tallied.skipped,
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
                Verdict::Skipped => {
                    term.step(&format!("{}: skipped, {}", check.topic, check.detail));
                }
            }
            // The remedy goes through `detail` under anything but a Pass, so `--quiet` cannot
            // print "you would lose this" and withhold the line that fixes it
            if let Some(remedy) = &check.remedy {
                let line = format!("--> {remedy}");
                match check.verdict {
                    Verdict::Pass => term.hint(&line),
                    _ => term.detail(&line),
                }
            }
        }
        term.blank();
        term.headline(&tallied.summary());
        if tallied.failed > 0 {
            term.detail(
                "each ✗ is a way to lose your identity or your data. The line under it is the fix.",
            );
        }
    }

    Ok(if tallied.is_clean() {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::from(EXIT_CHECKS_FAILED)
    })
}

/// How many checks landed in each verdict.
struct Tally {
    passed: usize,
    warned: usize,
    failed: usize,
    unknown: usize,
    skipped: usize,
}

impl Tally {
    /// Whether a report has earned an exit 0, with no failure and a pass or warning.
    ///
    /// A run that answered nothing exits 3, because `doctor --json` is a monitoring probe.
    /// Unknowns beside answers keep the exit 0, because a machine with no `rad` on PATH cannot
    /// answer several checks, and a nightly exit 3 there teaches people to ignore it.
    fn is_clean(&self) -> bool {
        self.failed == 0 && self.passed + self.warned > 0
    }

    /// Names every non-empty bucket, so the line adds up to the number of checks.
    ///
    /// A score such as "2 of 7 checks pass" counts a check that could not run as a failure.
    fn summary(&self) -> String {
        let total = self.passed + self.warned + self.failed + self.unknown + self.skipped;
        if self.passed == total {
            return format!("all {total} checks pass");
        }
        let mut parts = vec![format!("{} pass", self.passed)];
        for (count, bucket) in [
            (self.warned, "worth improving"),
            (self.failed, "failing"),
            (self.unknown, "could not be checked"),
            (self.skipped, "skipped"),
        ] {
            if count > 0 {
                parts.push(format!("{count} {bucket}"));
            }
        }
        parts.join(", ")
    }
}

fn examine(ctx: &Ctx, args: &Doctor) -> Result<Vec<Check>> {
    let home = &ctx.home;
    let identity = Identity::read(home.public_key())?;
    let secret = SecretKey::read(home.secret_key())?;
    let node_id = identity.node_id();

    let git = Git::new();
    let rad = Rad::new(home.path());
    let rad = rad.is_available().then_some(rad);
    // An unreadable database costs only the checks that read it, because `doctor` runs when
    // something is already wrong. A `?` here would end the report before any check printed.
    let (policies, _) = tolerate(
        ctx,
        "the seeding policies",
        db::read_policies(&home.policies_db()),
    );
    let (routing, routing_unreadable) = tolerate(
        ctx,
        "the node database",
        db::read_routing_counts(&home.node_db(), &node_id),
    );
    let inventory = inventory::collect(
        home,
        &git,
        rad.as_ref(),
        RepoSelection::None,
        inventory::Purpose::Inspection,
        &node_id,
        &policies,
        &routing,
    )?;
    // Each inventory warning explains a check below that answers "not known", so all of them
    // are printed
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

    // Four checks read the archive found on disk, so they report on the file that is there.
    // The state file only records a run that happened.
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
        check_private_coverage(
            &inventory,
            record,
            newest.as_ref(),
            routing_unreadable.is_some(),
        )
        .qualified_by_unread(unread),
    );
    checks.push(
        check_sole_delegate(
            &inventory,
            newest.is_some() || record.is_some_and(|record| record.restored.is_none()),
        )
        .qualified_by_unread(unread),
    );
    checks.push(
        check_replication(
            &inventory,
            &routing,
            &NothingCameBack::of(
                routing_unreadable,
                db::saw_schema_drift_in(&home.node_db(), "routing table"),
            ),
        )
        .qualified_by_unread(unread),
    );
    checks.push(check_second_key_copy(&stored));
    let (synced_heads, synced_unreadable) = tolerate(
        ctx,
        "the node database",
        db::read_synced_heads(&home.node_db(), &node_id),
    );
    checks.push(
        check_sigrefs_propagation(
            &inventory,
            &synced_heads,
            &node_id,
            &NothingCameBack::of(
                synced_unreadable,
                // Drift is asked of this table alone, because `doctor` reads `policies.db` and
                // the routing table first, and drift there says nothing about this table
                db::saw_schema_drift_in(&home.node_db(), "sync status table"),
            ),
        )
        .qualified_by_unread(unread),
    );
    Ok(checks)
}

fn check_key_protection(secret: &SecretKey, key_path: &std::path::Path) -> Check {
    const ID: CheckId = CheckId::KeyPassphrase;
    match secret.protection() {
        crate::key::Protection::Encrypted { cipher, kdf } => Check::new(
            ID,
            Verdict::Pass,
            format!("the key is encrypted with {cipher} ({kdf})"),
        ),
        crate::key::Protection::Plaintext => Check::new(
            ID,
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
    /// Its age in whole days, `None` when the record's stamp does not parse.
    days: Option<i64>,
    /// What the age was read off, so the sentence names something the reader can look at.
    named: String,
    /// Said beside the age when the file on this disk and the record disagree.
    caveat: Option<Aside>,
}

/// What has to be said beside the age, and whether it takes the shine off a pass.
///
/// The variants pull in opposite directions. `NotAtHand` downgrades a pass, and
/// `SomethingNewerElsewhere` leaves it alone.
enum Aside {
    /// The age was read off the record, and the file it names is not listed here. A plain pass
    /// would claim an archive is at hand to restore from.
    NotAtHand(String),
    /// The age was read off the record of a `--stdout` run, which leaves no file here. A
    /// nightly warning about that would push people off a documented setup.
    WentToStdout(String),
    /// A file is here, and the record remembers a newer archive that went somewhere else.
    /// The age is this file's.
    SomethingNewerElsewhere(String),
}

impl Aside {
    fn said(&self) -> &str {
        match self {
            Self::NotAtHand(what)
            | Self::WentToStdout(what)
            | Self::SomethingNewerElsewhere(what) => what,
        }
    }

    fn downgrades_a_pass(&self) -> bool {
        matches!(self, Self::NotAtHand(_))
    }
}

/// Why the archive the record names is not among the ones listed here.
///
/// The listing wants `-<short node id>-` in a file name, so an archive written with `--output
/// /backups/mine.tar.zst.age` can be there and still go unlisted.
fn not_listed_here(path: &str) -> String {
    // A filesystem error is no proof of absence, so it is reported as it is
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
/// Returns `None` when the record's stamp does not parse, because there is no comparison to
/// report.
fn newer_elsewhere(
    record: Option<&state::Record>,
    here: i64,
    now: jiff::Timestamp,
) -> Option<Aside> {
    let record = record?;
    let recorded = record.age_in_days(now)?;
    (recorded < here).then(|| {
        Aside::SomethingNewerElsewhere(format!(
            "this tool recorded a {} archive {}, which is not in this directory",
            record.tier,
            term::days_ago(recorded)
        ))
    })
}

/// How recently an archive of this identity was taken, read from the directory and the state
/// file.
///
/// The state file knows nothing when the timer runs as another user or the state was wiped or
/// restored, and the directory knows nothing once the last archive is pruned or moved.
fn check_backup_freshness(
    stored: &state::Stored,
    newest: Option<&crate::archives::Archive>,
    directory: &std::path::Path,
    now: jiff::Timestamp,
) -> Check {
    const ID: CheckId = CheckId::Backup;
    // The path is absolute, because the directory defaults to `.` and the remedy is a command
    // to paste, where `.` means a different place in every shell
    let looked_in = std::path::absolute(directory)
        .unwrap_or_else(|_| directory.to_path_buf())
        .display()
        .to_string();
    let record = stored.record();

    // The file found here answers first, because a restore would use it whoever wrote it.
    // The record gives the age only when no file does, because a moved archive still counts.
    let judged = match (newest, record) {
        (Some(archive), _) => {
            let here = term::days_between(archive.taken, now);
            Newest {
                days: Some(here),
                named: format!("{} in {looked_in}", archive.name()),
                // A nightly `--stdout` run records archives this directory never receives, so
                // an older file here may not be the newest backup
                caveat: newer_elsewhere(record, here, now),
            }
        }
        (None, Some(record)) => Newest {
            days: record.age_in_days(now),
            named: format!("the newest {} archive rad-backup recorded", record.tier),
            caveat: Some(match &record.archive {
                Some(path) => Aside::NotAtHand(not_listed_here(path)),
                None => Aside::WentToStdout(
                    "it went to standard output, so rad-backup cannot see where it is".to_string(),
                ),
            }),
        },
        (None, None) => {
            if let state::Stored::Unreadable { .. } = stored {
                return Check::new(
                    ID,
                    Verdict::Unknown,
                    format!(
                        "no archive of your identity in {looked_in}, and rad-backup's record of \
                         earlier ones could not be read"
                    ),
                )
                .with_remedy("take another to replace it: rad backup");
            }
            return Check::new(
                ID,
                Verdict::Fail,
                format!(
                    "no archive of your identity in {looked_in}, and rad-backup has no record of \
                     one"
                ),
            )
            .with_remedy(format!("rad backup --output {}", shell_word(&looked_in)));
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
        // An archive stamped in the future has no meaningful age. As a pass it would never go
        // stale, so one archive from a fast clock would silence the alarm for good.
        Some(days) if days < 0 => Check::new(
            ID,
            Verdict::Unknown,
            format!("{named} is stamped in the future, so its age cannot be judged{beside}"),
        )
        .with_remedy("check the clock on the machine that took it, then `rad backup`"),
        Some(days) if days <= STALE_AFTER_DAYS => Check::new(
            ID,
            Verdict::Pass,
            format!("{named} was taken {}{beside}", term::days_ago(days)),
        ),
        Some(days) => Check::new(
            ID,
            Verdict::Warn,
            format!("{named} was taken {}{beside}", term::days_ago(days)),
        )
        .with_remedy("rad backup"),
        None => Check::new(
            ID,
            Verdict::Unknown,
            format!("{named} carries a timestamp that does not parse{beside}"),
        ),
    };
    // An archive no longer at hand downgrades a pass, because a clean pass says it is at hand.
    // A newer archive on another disk leaves the pass alone.
    match check.verdict == Verdict::Pass && caveat.is_some_and(|caveat| caveat.downgrades_a_pass())
    {
        true => Check {
            verdict: Verdict::Warn,
            ..check
        }
        .with_remedy("take another where rad-backup can find it: rad backup"),
        false => check,
    }
}

/// Phrases a count as "it is" for one and "all 3 are" for more, never "all 1 are".
fn every(count: usize) -> String {
    match count {
        1 => "it is".to_string(),
        _ => format!("all {count} are"),
    }
}

/// What a check that needs an archive says when there is none to look at.
const NO_ARCHIVE_FOUND: &str = "no archive found";

/// Quotes `path` as one shell word when it needs quoting, so a remedy pastes as printed.
fn shell_word(path: &str) -> String {
    let plain = |c: char| c.is_ascii_alphanumeric() || "/._-+=:@,".contains(c);
    match path.chars().all(plain) && !path.is_empty() {
        true => path.to_string(),
        false => format!("'{}'", path.replace('\'', r"'\''")),
    }
}

/// Whether the newest archive is closed to others and still opens for its owner.
///
/// The verdict is read off the file whenever there is one, because a record only says what a
/// run once wrote. Trying the unwrap shows whether a key on hand still opens it.
fn check_archive_encryption(
    identities: &crate::crypt::Identities,
    newest: Option<&crate::archives::Archive>,
    record: Option<&state::Record>,
) -> Result<Check> {
    const ID: CheckId = CheckId::ArchiveEncryption;
    let Some(archive) = newest else {
        // With no file to open, the record is hearsay about a file this run never saw, so only
        // its bad news earns a warning
        return Ok(match record {
            Some(record) if !record.is_encrypted => Check::new(
                ID,
                Verdict::Warn,
                "no archive of your identity was found, and the last one rad-backup wrote was \
                 not encrypted",
            )
            .with_remedy(
                "take another without --plaintext, then find that one and delete it: anyone \
                 holding it can read it",
            ),
            Some(_) => Check::new(
                ID,
                Verdict::Unknown,
                "no archive of your identity was found, so none could be opened",
            ),
            None => Check::new(ID, Verdict::Skipped, NO_ARCHIVE_FOUND),
        });
    };

    let name = archive.name();
    if !crate::crypt::looks_encrypted(&archive.path)? {
        return Ok(Check::new(
            ID,
            Verdict::Fail,
            format!("{name} can be read by anyone who holds it, your key file included"),
        )
        .with_remedy("take another without --plaintext, then delete the old one"));
    }
    if crate::crypt::needs_passphrase(&archive.path)? {
        // A passphrase archive stays unopened, because opening it means a prompt, and people
        // stop running a health report that prompts. The header says which key it wants.
        return Ok(Check::new(
            ID,
            Verdict::Pass,
            format!("{name} opens only with the passphrase it was sealed under"),
        ));
    }

    if identities.files.is_empty() {
        return Ok(Check::new(
            ID,
            Verdict::Unknown,
            format!("{name} is encrypted to a key, and no key was offered to try against it"),
        )
        .with_remedy("rad backup doctor --identity ~/.ssh/id_ed25519"));
    }
    // Building the zstd decoder makes age produce the file key, so an open proves the key on
    // hand works without reading the whole archive. The open never prompts, because a report
    // that stops to ask for an ssh key's passphrase gets taken off the timer.
    let silent = crate::crypt::Identities {
        is_interactive: false,
        ..identities.clone()
    };
    Ok(
        match crate::container::Reader::open(&archive.path, None, &silent) {
            Ok(_) => Check::new(
                ID,
                Verdict::Pass,
                format!("{name} is encrypted to a key, and the key offered here opens it"),
            ),
            // A key that stayed locked or that age cannot use says nothing about the archive.
            // As a Fail it would exit 3 every night for the setup the README shows.
            Err(
                Error::KeysStayedLocked { what, remedy } | Error::KeyNotUsable { what, remedy },
            ) => Check::new(ID, Verdict::Unknown, format!("{name}: {what}")).with_remedy(remedy),
            Err(e) => Check::new(ID, Verdict::Fail, format!("{name} did not open: {e}"))
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
    const ID: CheckId = CheckId::ArchiveLocation;
    // The file found here answers first, then the path the record remembers, which may be on
    // another disk
    let recorded = record.and_then(|record| record.archive.as_ref());
    let judged = newest.map(|archive| archive.path.clone()).or_else(|| {
        recorded
            .map(std::path::PathBuf::from)
            .filter(|path| path.exists())
    });
    let Some(path) = judged else {
        return match (record, recorded) {
            (_, Some(archive)) => Check::new(
                ID,
                Verdict::Unknown,
                format!("{archive} is not there now, so where it is cannot be checked"),
            )
            .with_remedy(
                "if you moved it to another disk, nothing is wrong. If not, run `rad backup`",
            ),
            (Some(_), None) => Check::new(
                ID,
                Verdict::Unknown,
                "the last archive went to standard output, so where it is cannot be checked",
            ),
            (None, None) => Check::new(ID, Verdict::Skipped, NO_ARCHIVE_FOUND),
        };
    };

    let name = path.display().to_string();
    match crate::perms::same_device(&path, home) {
        // A same-disk archive warns, because a directory synced by MEGA, Dropbox, Drive or
        // Syncthing is already off this machine and this tool cannot see whether one is. A
        // Fail would exit 3 at someone who is covered.
        Some(true) => Check::new(
            ID,
            Verdict::Warn,
            format!("{name} is on the same disk as your Radicle data"),
        )
        .with_remedy("copy archives to another disk or machine, unless a sync tool already does"),
        // Two partitions of one drive are different filesystems, so the pass says filesystem
        Some(false) => Check::new(
            ID,
            Verdict::Pass,
            format!("{name} is on a different filesystem from your Radicle data"),
        ),
        None => Check::new(
            ID,
            Verdict::Unknown,
            format!("{name} and your Radicle data could not be compared"),
        ),
    }
}

/// Whether the record is about the archive this run found on disk.
///
/// A record is hearsay about a file this run may never have seen, because the timer may run as
/// another user, the archive may have moved, and `restore.sh` writes no record.
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
    routing_is_unreadable: bool,
) -> Check {
    const ID: CheckId = CheckId::PrivateRepositories;
    let private: Vec<&crate::manifest::RepoRecord> = inventory.private().collect();
    if private.is_empty() {
        return Check::new(ID, Verdict::Pass, "there are none to lose");
    }
    let vouched = record.is_some_and(|record| record_is_about(record, newest));

    // An owner can allow peers to hold a private repository, and the routing table knows when
    // one announces it, so this check says which degree of safety each repository is in
    let missing: Vec<&&crate::manifest::RepoRecord> = private
        .iter()
        .filter(|repo| !record.is_some_and(|record| record.carries(&repo.rid)))
        .collect();
    if missing.is_empty() {
        return match vouched {
            true => Check::new(
                ID,
                Verdict::Pass,
                format!("{} in the newest archive", every(private.len())),
            ),
            // A record about a file nothing here matched earns an unknown, because "they are
            // all backed up" about an archive this run never found is a claim it cannot check
            false => {
                let all = every(private.len());
                match (record.and_then(|record| record.archive.as_deref()), newest) {
                    (None, _) => Check::new(
                        ID,
                        Verdict::Unknown,
                        format!(
                            "{all} in the last archive, which went to standard output, \
                             so rad-backup cannot check it"
                        ),
                    ),
                    (Some(recorded), None) => Check::new(
                        ID,
                        Verdict::Unknown,
                        format!("{all} in {recorded}, which was not found"),
                    )
                    .with_remedy(
                        "point --dir at the directory that holds it, or run `rad backup --repos \
                         private`",
                    ),
                    (Some(recorded), Some(found)) => Check::new(
                        ID,
                        Verdict::Unknown,
                        format!(
                            "{all} in {recorded}, but the archive found is {}",
                            found.name()
                        ),
                    )
                    .with_remedy(
                        "point --dir at the directory that holds it, or run `rad backup --repos \
                         private`",
                    ),
                }
            }
        };
    }
    // The routing table is half of what `has_another_holder` answers with, so an unreadable
    // table earns an unknown. A Fail off a failed read teaches people to stop believing it.
    if routing_is_unreadable {
        let (count, verb) = (missing.len(), term::is_or_are(missing.len()));
        return Check::new(
            ID,
            Verdict::Unknown,
            format!(
                "{count} of {} {verb} in no archive, and whether any other node holds them \
                 could not be told: the node database would not open",
                private.len()
            ),
        )
        .with_remedy("rad backup --repos private");
    }
    let alone = missing
        .iter()
        .filter(|repo| !repo.has_another_holder())
        .count();
    let (count, verb) = (missing.len(), term::is_or_are(missing.len()));
    let detail = if alone == 0 {
        format!(
            "{count} of {} {verb} in no archive. Another delegate, an allowed peer or a node \
             announcing it holds each of them",
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
    Check::new(ID, verdict, detail).with_remedy("rad backup --repos private")
}

/// Whether losing the key would also cost the repositories nobody else can update.
///
/// `key_is_archived` is whether an archive of the key is known, found on disk or recorded as
/// written. A restore's record does not count, because its source may be gone. Age does not
/// matter, because an old archive holds the same key.
fn check_sole_delegate(inventory: &Inventory, key_is_archived: bool) -> Check {
    let sole: Vec<&str> = inventory
        .solely_delegated()
        .map(|repo| repo.display_name())
        .collect();
    let delegated = inventory
        .records
        .iter()
        .filter(|repo| repo.is_delegate)
        .count();
    const ID: CheckId = CheckId::SoleDelegate;
    if sole.is_empty() {
        return Check::new(
            ID,
            Verdict::Pass,
            if delegated == 0 {
                "you are not a delegate of any repository on your node".to_string()
            } else {
                "every repository you are a delegate of has another delegate too".to_string()
            },
        );
    }
    let (count, names) = (
        term::count(sole.len(), "repository", "repositories"),
        sole.join(", "),
    );
    // Most repositories start with one delegate, so this warns only when nothing could bring
    // the key back. The threshold is never read here, so the hint says how to add a delegate
    // and makes no claim about how many is best.
    if !key_is_archived {
        return Check::new(
            ID,
            Verdict::Warn,
            format!("if you lose your key, nobody can update {count}: {names}"),
        )
        .with_remedy("back up your key: rad backup");
    }
    Check::new(
        ID,
        Verdict::Pass,
        format!("you are the only delegate of {count}: {names}"),
    )
    .with_remedy(
        "if you lose your key, your backup brings it back. To add a second delegate: rad id \
         update --repo <rid> --delegate <did>",
    )
}

/// Reads a database that must not end the report, warning when the read fails.
///
/// Returns the empty value and the warning, which the check that reads it prints as its
/// remedy, so the line and its reason stay together.
fn tolerate<T: Default>(ctx: &Ctx, what: &str, read: Result<T>) -> (T, Option<String>) {
    match read {
        Ok(value) => (value, None),
        Err(e) => {
            let why = format!("{what} could not be read: {e}");
            ctx.term.warn(&why);
            (T::default(), Some(why))
        }
    }
}

/// Why a read of the node's databases handed nothing back.
///
/// A node that has not run, a schema this build cannot read and a file that will not open all
/// arrive as an empty map, and starting the node fixes only the first.
enum NothingCameBack {
    /// The database answered, so empty means the node has not gossiped or synced yet.
    NodeHasNotRun,
    /// This build cannot read part of heartwood's schema.
    SchemaHasMovedOn,
    /// The database could not be read at all, for the reason held.
    Unreadable(String),
}

impl NothingCameBack {
    /// Picks the reason, unreadable first, because a file that never opened cannot show drift.
    fn of(unreadable: Option<String>, schema_has_moved_on: bool) -> Self {
        match (unreadable, schema_has_moved_on) {
            (Some(why), _) => Self::Unreadable(why),
            (None, true) => Self::SchemaHasMovedOn,
            (None, false) => Self::NodeHasNotRun,
        }
    }
}

/// The remedy for a table that came back empty, by why it did.
///
/// `then` completes the advice to start a node that has not run. A running node whose schema
/// this build cannot read also comes back empty, and is never told to start.
fn empty_because(nothing_came_back: &NothingCameBack, then: &str) -> String {
    match nothing_came_back {
        NothingCameBack::Unreadable(why) => why.clone(),
        NothingCameBack::SchemaHasMovedOn => {
            "install a newer rad-backup. The installed rad-backup cannot read part of your \
             node's data"
                .to_string()
        }
        NothingCameBack::NodeHasNotRun => {
            format!("start the node with `rad node start` and {then}")
        }
    }
}

fn check_replication(
    inventory: &Inventory,
    routing: &BTreeMap<String, u64>,
    nothing_came_back: &NothingCameBack,
) -> Check {
    // The filter is `is_public`, because a record whose identity document was never read has
    // no visibility, and this list ends in `rad sync --announce`. The caller qualifies the
    // count with how many could not be described.
    const ID: CheckId = CheckId::PublicRepositories;
    let public = inventory.records.iter().filter(|repo| repo.is_public());
    // The check passes with none only when every identity was read, because otherwise
    // nothing is known to be public
    if public.clone().next().is_none() && inventory.identities_not_read() == 0 {
        return Check::new(ID, Verdict::Pass, "your node holds none");
    }
    let alone: Vec<&str> = public
        .filter(|repo| routing.get(&repo.rid).copied().unwrap_or(0) == 0)
        .map(|repo| repo.display_name())
        .collect();

    if routing.is_empty() {
        let found = match nothing_came_back {
            NothingCameBack::NodeHasNotRun => {
                "your node knows of no other node holding any repository yet"
            }
            _ => "which other nodes hold them could not be read",
        };
        return Check::new(ID, Verdict::Unknown, found).with_remedy(empty_because(
            nothing_came_back,
            "let it connect to other nodes",
        ));
    }
    if alone.is_empty() {
        return Check::new(
            ID,
            Verdict::Pass,
            "every one is held by at least one other node",
        );
    }
    Check::new(
        ID,
        Verdict::Warn,
        format!(
            "{} {} held by no other node: {}",
            alone.len(),
            term::is_or_are(alone.len()),
            alone.join(", ")
        ),
    )
    .with_remedy("announce them with `rad sync --announce <rid>`, or ask a seed to hold a copy")
}

/// Work signed here that has reached no other node.
///
/// `check_replication` asks whether a repository exists elsewhere, and this asks whether its
/// latest work does. Private repositories are left out, because they are announced to nobody.
fn check_sigrefs_propagation(
    inventory: &Inventory,
    synced_heads: &BTreeMap<String, BTreeSet<String>>,
    node_id: &str,
    nothing_came_back: &NothingCameBack,
) -> Check {
    const ID: CheckId = CheckId::UnsharedWork;
    // Only repositories known to be public count, because this list ends in `rad sync
    // --announce`. A repository with none of this peer's signed refs has nothing to share.
    let yours: Vec<(&crate::manifest::RepoRecord, &String)> = inventory
        .records
        .iter()
        .filter(|repo| repo.is_public())
        .filter_map(|repo| repo.sigrefs.get(node_id).map(|mine| (repo, mine)))
        .collect();
    if yours.is_empty() && inventory.identities_not_read() == 0 {
        return Check::new(
            ID,
            Verdict::Pass,
            "you have no changes in any public repository on your node",
        );
    }
    if synced_heads.is_empty() {
        let found = match nothing_came_back {
            NothingCameBack::NodeHasNotRun => {
                "your node has no record of syncing with another node yet"
            }
            _ => "what other nodes hold could not be read",
        };
        return Check::new(ID, Verdict::Unknown, found).with_remedy(empty_because(
            nothing_came_back,
            "run `rad backup doctor` again once it has synced",
        ));
    }

    // A head that reached any node, at any time, has left this disk, so sync times are ignored
    let here_only: Vec<&str> = yours
        .into_iter()
        .filter(|(repo, mine)| {
            !synced_heads
                .get(&repo.rid)
                .is_some_and(|heads| heads.iter().any(|head| crate::git::same_oid(head, mine)))
        })
        .map(|(repo, _)| repo.display_name())
        .collect();

    if here_only.is_empty() {
        return Check::new(
            ID,
            Verdict::Pass,
            "your latest changes to every public repository have reached another node",
        );
    }
    Check::new(
        ID,
        Verdict::Warn,
        format!(
            "your latest changes to {} have reached no other node: {}",
            term::count(here_only.len(), "repository", "repositories"),
            here_only.join(", ")
        ),
    )
    .with_remedy(
        "announce them with `rad sync --announce <rid>`. Keep your backups until another node \
         has them",
    )
}

/// Whether another machine may still be running this identity.
///
/// A restore puts the key here while the source machine keeps its copy, and `move` retires
/// that copy. A missing state file is no evidence either way, because a restore under `sudo`
/// or by `restore.sh` writes none.
fn check_second_key_copy(stored: &state::Stored) -> Check {
    const ID: CheckId = CheckId::KeyCopies;
    let record = match stored {
        state::Stored::Record(record) => record,
        state::Stored::Absent => {
            return Check::new(
                ID,
                Verdict::Unknown,
                "rad-backup has no record of where this machine's Radicle data came from, so \
                 it cannot tell whether another machine holds the same key",
            )
            .with_remedy(
                "if this machine's Radicle data was restored or copied from another machine, \
                 make sure that machine is not running a node",
            );
        }
        state::Stored::Unreadable { .. } => {
            return Check::new(
                ID,
                Verdict::Unknown,
                "rad-backup's record of where this machine's Radicle data came from could not \
                 be read, so it cannot tell whether another machine holds the same key",
            )
            .with_remedy(
                "if this machine's Radicle data was restored or copied from another machine, \
                 make sure that machine is not running a node",
            );
        }
    };

    // Every backup writes a record with no `restored`, so a home restored and then backed up
    // passes here too
    let Some(restored) = record.restored.as_ref() else {
        return Check::new(
            ID,
            Verdict::Pass,
            "the last thing rad-backup recorded on this machine was a backup, not a restore",
        );
    };

    match restored.source_retires_key {
        // The pass repeats what the archive recorded, because this tool cannot see the old
        // machine, and `--keep-source` is the case where the claim would be wrong
        Some(true) => Check::new(
            ID,
            Verdict::Pass,
            "your Radicle data was moved here, and the archive says the old machine retires its \
             key",
        ),
        // The warning names a possibility, because this tool cannot see the other machine and
        // a false alarm would send someone to retire a key they still need
        Some(false) => Check::new(
            ID,
            Verdict::Warn,
            match (
                restored.source_node_was_running,
                restored.source_node_state_was_guessed,
            ) {
                (true, false) => {
                    "your Radicle data was restored from a backup of a machine with a node running"
                }
                // The source run could not reach the socket and recorded the cautious answer,
                // so the sentence says "may have had"
                (true, true) => {
                    "your Radicle data was restored from a backup of a machine that may have had a \
                     node running"
                }
                (false, _) => {
                    "your Radicle data was restored from a backup, so the old machine still has the key"
                }
            },
        )
        .with_remedy(
            "make sure that machine is not running a node: `rad node stop` there, or `rad \
             backup move` next time, which retires its key for you",
        ),
        None => Check::new(
            ID,
            Verdict::Unknown,
            "your Radicle data was restored from an older archive that does not say whether the \
             old machine retires its key",
        )
        .with_remedy("make sure the machine it came from is not running a node"),
    }
}

#[cfg(test)]
mod tests {
    use age::secrecy::ExposeSecret as _;

    use super::*;
    use crate::key::tests::TestScratch;

    /// The ids are spelled a second time here, so an edit to `CheckId::id` has to be made
    /// twice to ship. A new variant needs a line here, because nothing notices one left out.
    #[test]
    fn check_ids_are_pinned_because_scripts_match_on_them() {
        let pinned = [
            (CheckId::KeyPassphrase, "key-passphrase"),
            (CheckId::Backup, "backup"),
            (CheckId::ArchiveEncryption, "archive-encryption"),
            (CheckId::ArchiveLocation, "archive-location"),
            (CheckId::PrivateRepositories, "private-repositories"),
            (CheckId::SoleDelegate, "sole-delegate"),
            (CheckId::PublicRepositories, "public-repositories"),
            (CheckId::KeyCopies, "key-copies"),
            (CheckId::UnsharedWork, "unshared-work"),
        ];
        for (id, spelled) in pinned {
            assert_eq!(
                serde_json::to_value(id).expect("a check id serializes"),
                spelled
            );
        }
        let distinct: BTreeSet<_> = pinned.iter().map(|(id, _)| id.id()).collect();
        assert_eq!(distinct.len(), pinned.len(), "two checks share an id");
    }

    fn tally(passed: usize, warned: usize, failed: usize, unknown: usize, skipped: usize) -> Tally {
        Tally {
            passed,
            warned,
            failed,
            unknown,
            skipped,
        }
    }

    #[test]
    fn a_report_that_could_not_check_anything_is_not_a_clean_one() {
        assert!(tally(9, 0, 0, 0, 0).is_clean());
        assert!(tally(7, 2, 0, 0, 0).is_clean());
        assert!(!tally(8, 0, 1, 0, 0).is_clean());
        // With no check answered, a green exit would report a posture nothing looked at
        assert!(!tally(0, 0, 0, 6, 3).is_clean());
        assert!(tally(6, 0, 0, 0, 3).is_clean());
    }

    /// A first run has nothing for the archive checks to look at, so they skip. A recorded
    /// archive this run cannot see is an unknown.
    #[test]
    fn the_archive_checks_skip_when_there_is_no_archive_and_no_record_of_one() {
        let home = std::path::Path::new("/nowhere");
        let none = check_archive_encryption(&Default::default(), None, None)
            .expect("no archive is not an error");
        assert_eq!(none.verdict, Verdict::Skipped, "{}", none.detail);
        let none = check_archive_location(home, None, None);
        assert_eq!(none.verdict, Verdict::Skipped, "{}", none.detail);

        // A `--stdout` run leaves an archive somewhere this tool cannot see
        let recorded = record();
        let elsewhere = check_archive_encryption(&Default::default(), None, Some(&recorded))
            .expect("no archive is not an error");
        assert_eq!(elsewhere.verdict, Verdict::Unknown, "{}", elsewhere.detail);
        let elsewhere = check_archive_location(home, None, Some(&recorded));
        assert_eq!(elsewhere.verdict, Verdict::Unknown, "{}", elsewhere.detail);
    }

    /// Writes a key file for a test, owner-only inside an owner-only directory.
    fn secret_file(path: &std::path::Path, contents: &str) {
        use std::io::Write as _;

        let mut file = crate::perms::create_private_file(path).expect("scratch file is creatable");
        file.write_all(contents.as_bytes())
            .expect("scratch file is writable");
    }

    /// Judges freshness from the state record alone, with nothing on disk.
    fn recorded_freshness(stored: &state::Stored, now: jiff::Timestamp) -> Check {
        check_backup_freshness(stored, None, std::path::Path::new("/nowhere"), now)
    }

    /// An archive found on disk, stamped `when`. Freshness never opens one, so the path need
    /// not exist.
    fn found(when: &str) -> crate::archives::Archive {
        crate::archives::Archive {
            path: std::path::PathBuf::from(
                "/nowhere/radicle-z6MkAAAAAAAA-20260813T120000Z.tar.zst",
            ),
            bytes: 4096,
            taken: when.parse().expect("a valid instant"),
            encrypted: Some(false),
        }
    }

    /// Judges freshness on an archive found on disk, with no state record.
    fn found_freshness(when: &str, now: jiff::Timestamp) -> Check {
        check_backup_freshness(
            &state::Stored::Absent,
            Some(&found(when)),
            std::path::Path::new("/nowhere"),
            now,
        )
    }

    /// A nightly `rad backup --stdout` goes to another disk, and one old copy sits in the
    /// directory `doctor` looks in. The report names the newer archive and keeps the pass the
    /// file here earns.
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

        // Both are fresh and the record is fresher, which still passes, because the archive
        // here can be restored from
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

        // The file here is the newer of the two, so there is nothing to add
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

    /// How many checks `examine` runs, pinned because `every_topic` below is built by hand.
    ///
    /// `ci/pins.sh` holds this, the count of `check_` functions and the integration suite's
    /// `total` to one number. The test below catches an entry dropped from `every_topic`.
    const CHECKS_THE_COMMAND_RUNS: usize = 9;

    #[test]
    fn the_sweep_reaches_every_check_the_command_runs() {
        assert_eq!(every_topic("doctor-sweep").len(), CHECKS_THE_COMMAND_RUNS);
    }

    /// Every topic the report can print, one per check, whatever the verdict turns out to be.
    ///
    /// Each caller passes its own scratch name, because `TestScratch` refuses two tests that
    /// share one parent.
    fn every_topic(scratch: &str) -> Vec<String> {
        let now: jiff::Timestamp = "2026-08-14T12:00:00Z".parse().expect("a valid instant");
        let empty = Inventory {
            records: Vec::new(),
            selected: Default::default(),
            warnings: Vec::new(),
        };
        // The key check is built in full, because a sweep that exempts a check it polices
        // reports a conformance it does not check
        let seed = zeroize::Zeroizing::new([1u8; 32]);
        let openssh = crate::key::openssh_from_seed(&seed, None).expect("key is buildable");
        let scratch = TestScratch::create(scratch);
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
            check_private_coverage(&empty, None, None, false),
            check_sole_delegate(&empty, false),
            check_replication(&empty, &BTreeMap::new(), &NothingCameBack::NodeHasNotRun),
            check_second_key_copy(&state::Stored::Absent),
            check_sigrefs_propagation(
                &empty,
                &BTreeMap::new(),
                "z6MkAAA",
                &NothingCameBack::NodeHasNotRun,
            ),
        ]
        .into_iter()
        .map(|check| check.topic.to_string())
        .collect()
    }

    /// A topic phrased as a claim asserts the good state, so a failing line such as
    /// "✗ a backup exists" contradicts its own marker. A topic names the subject and leaves
    /// every assertion to the detail.
    #[test]
    fn no_topic_asserts_a_state_so_a_failing_line_cannot_contradict_its_own_marker() {
        // ` on ` and `elsewhere` catch topics such as `key on another machine`, which a detail
        // beside it can deny
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
        for topic in every_topic("doctor-topics") {
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
    fn the_summary_names_every_bucket_rather_than_folding_them_into_a_score() {
        assert_eq!(tally(7, 0, 0, 0, 0).summary(), "all 7 checks pass");
        assert_eq!(
            tally(2, 2, 1, 2, 2).summary(),
            "2 pass, 2 worth improving, 1 failing, 2 could not be checked, 2 skipped"
        );
        // "6 of 7 checks pass" reads as one failure, and a check nobody could run did not go
        // wrong
        assert_eq!(
            tally(6, 0, 0, 1, 0).summary(),
            "6 pass, 1 could not be checked"
        );
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
        // The remedy names this home's key path, because `$RAD_HOME` is unset for most users
        // and would leave the command un-runnable as printed
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
        // wherever the default points, which is where this run already found nothing
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

    /// A timer running as another user, or a home restored by `restore.sh`, leaves no state
    /// record beside archives that are there.
    #[test]
    fn an_archive_on_disk_answers_even_when_this_tool_has_no_record_of_taking_one() {
        let now: jiff::Timestamp = "2026-08-14T12:00:00Z".parse().expect("a valid instant");
        let check = found_freshness("2026-08-13T12:00:00Z", now);
        assert_eq!(check.verdict, Verdict::Pass, "{}", check.detail);
        assert!(check.detail.contains(".tar.zst"), "{}", check.detail);
    }

    /// A fresh record whose file is gone may mean the archive was carried off somewhere safe,
    /// so the check warns. A clean pass would say the archive is at hand.
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

    /// A directory a cloud client watches shares the home's filesystem and still leaves the
    /// machine. Only the user knows, so the check warns, because an exit 3 at someone covered
    /// teaches them to ignore it.
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

    /// Writes a real archive sealed as asked, and returns the record a directory scan makes.
    ///
    /// The checks read the file, so a fixture made only of a `state::Record` tests a claim.
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
        // The body is empty zstd, because opening an archive builds the decoder, and a junk
        // body would fail there for a reason unrelated to the key
        let body = zstd::encode_all(std::io::empty(), 0).expect("zstd encodes nothing");
        sink.write_all(&body).expect("body is writable");
        sink.finish().expect("sink finishes");

        crate::archives::Archive {
            bytes: std::fs::metadata(&path).map(|meta| meta.len()).unwrap_or(0),
            taken: "2026-08-13T12:00:00Z".parse().expect("a valid instant"),
            encrypted: Some(!matches!(encryption, crate::crypt::Encryption::Plaintext)),
            path,
        }
    }

    /// The record describes a run, and the archive is the thing anyone would steal.
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

    /// The listing wants the short node id in a name, so `--output /backups/mine.tar.zst.age`
    /// writes an archive that is there and still unlisted.
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

        // No passphrase is given or read, because nobody schedules a report that prompts
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

        // With no key offered nothing is tried, and a pass would vouch for an archive whose
        // key may be lost
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

    /// An ssh key with a passphrase is the README's setup. A key that never came unlocked says
    /// nothing about the archive, and `doctor` must not prompt for it.
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

        // Interactive, as `doctor` usually runs. The test asserts the verdict, because a test
        // run has no terminal for a prompt to reach either way.
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

        // The same key, unlocked by a passphrase file, opens it
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
    fn being_the_only_delegate_warns_only_when_no_archive_holds_the_key() {
        let mut repo = public_repo_signed_at("rad:zAAA", "aaa");
        repo.is_delegate = true;
        repo.delegates = vec![ME.to_string()];
        let inventory = holding(vec![repo]);

        let unarchived = check_sole_delegate(&inventory, false);
        assert_eq!(unarchived.verdict, Verdict::Warn, "{}", unarchived.detail);
        assert!(
            unarchived.remedy.is_some(),
            "a warning with no way out is a nag"
        );

        let archived = check_sole_delegate(&inventory, true);
        assert_eq!(archived.verdict, Verdict::Pass, "{}", archived.detail);
    }

    #[test]
    fn work_no_other_node_holds_is_named_as_being_on_this_disk_alone() {
        let inventory = holding(vec![
            public_repo_signed_at("rad:zAAA", "aaa"),
            public_repo_signed_at("rad:zBBB", "bbb"),
        ]);
        // Another node has zAAA's current head. No node has zBBB's, which was signed here and
        // reached nothing, and no file copy of the home can show that.
        let synced = BTreeMap::from([
            ("rad:zAAA".to_string(), BTreeSet::from(["aaa".to_string()])),
            (
                "rad:zBBB".to_string(),
                BTreeSet::from(["older".to_string()]),
            ),
        ]);

        let check =
            check_sigrefs_propagation(&inventory, &synced, ME, &NothingCameBack::NodeHasNotRun);
        assert_eq!(check.verdict, Verdict::Warn);
        assert!(check.detail.contains("rad:zBBB"), "{}", check.detail);
        assert!(!check.detail.contains("rad:zAAA"), "{}", check.detail);
    }

    /// `git` prints an oid in whichever case it was handed, and heartwood stores whatever the
    /// announcing node sent, so heads compare without regard to case.
    #[test]
    fn a_head_another_node_holds_in_the_other_case_is_the_same_head() {
        let inventory = holding(vec![public_repo_signed_at("rad:zAAA", "abcdef01")]);
        let synced = BTreeMap::from([(
            "rad:zAAA".to_string(),
            BTreeSet::from(["ABCDEF01".to_string()]),
        )]);

        let check =
            check_sigrefs_propagation(&inventory, &synced, ME, &NothingCameBack::NodeHasNotRun);
        assert_eq!(check.verdict, Verdict::Pass, "{}", check.detail);
    }

    #[test]
    fn a_private_repository_is_not_counted_as_work_that_failed_to_propagate() {
        // Private repositories are announced to nobody, so counting them would report the
        // feature working as a fault
        let mut private = public_repo_signed_at("rad:zPriv", "aaa");
        private.visibility = Some("private".to_string());
        let synced =
            BTreeMap::from([("rad:zOther".to_string(), BTreeSet::from(["x".to_string()]))]);

        let check = check_sigrefs_propagation(
            &holding(vec![private]),
            &synced,
            ME,
            &NothingCameBack::NodeHasNotRun,
        );
        assert_eq!(check.verdict, Verdict::Pass, "{}", check.detail);
    }

    #[test]
    fn a_node_that_has_never_run_is_unknown_rather_than_everything_being_stranded() {
        let inventory = holding(vec![public_repo_signed_at("rad:zAAA", "aaa")]);
        let check = check_sigrefs_propagation(
            &inventory,
            &BTreeMap::new(),
            ME,
            &NothingCameBack::NodeHasNotRun,
        );
        assert_eq!(check.verdict, Verdict::Unknown, "{}", check.detail);
        let remedy = check.remedy.expect("an unknown says what would answer it");
        assert!(remedy.contains("rad node start"), "{remedy}");
    }

    /// An empty table has two causes, and starting a node answers only one. A node running
    /// against a schema this build cannot read must not be told to start.
    #[test]
    fn a_table_this_build_cannot_read_is_not_answered_by_starting_the_node() {
        let inventory = holding(vec![public_repo_signed_at("rad:zAAA", "aaa")]);
        let check = check_sigrefs_propagation(
            &inventory,
            &BTreeMap::new(),
            ME,
            &NothingCameBack::SchemaHasMovedOn,
        );
        assert_eq!(check.verdict, Verdict::Unknown, "{}", check.detail);
        let remedy = check.remedy.expect("an unknown says what would answer it");
        assert!(!remedy.contains("rad node start"), "{remedy}");

        let check = check_replication(
            &inventory,
            &BTreeMap::new(),
            &NothingCameBack::SchemaHasMovedOn,
        );
        let remedy = check.remedy.expect("an unknown says what would answer it");
        assert!(!remedy.contains("rad node start"), "{remedy}");
        assert!(remedy.contains("newer rad-backup"), "{remedy}");
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

        // The same record, from a run that could not reach the control socket and wrote the
        // cautious answer, which the warning must not repeat as a sighting
        record.restored = Some(state::Restored {
            source_retires_key: Some(false),
            source_node_was_running: true,
            source_node_state_was_guessed: true,
        });
        let guessed = check_second_key_copy(&state::Stored::Record(Box::new(record)));
        assert_eq!(guessed.verdict, Verdict::Warn);
        assert!(
            guessed.detail.contains("may have had"),
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
        // An archive written before the manifest carried the answer cannot vouch for the
        // machine it came from, so its silence is no pass
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

    /// `sudo rad-backup restore` writes its record into root's state directory, and
    /// `restore.sh` writes none, so the user's own `doctor` has nothing to read.
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
    /// may never have seen, so the check says whose word it is taking.
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
            taken: "2026-08-13T12:00:00Z".parse().expect("a valid instant"),
            encrypted: Some(true),
        };
        let check = check_private_coverage(&inventory, Some(&record), Some(&found), false);
        assert_eq!(check.verdict, Verdict::Pass, "{}", check.detail);

        // The same record beside a different archive, and beside none at all
        let other = crate::archives::Archive {
            path: std::path::PathBuf::from("/backups/another.tar.zst.age"),
            ..found
        };
        for newest in [Some(&other), None] {
            let check = check_private_coverage(&inventory, Some(&record), newest, false);
            assert_eq!(check.verdict, Verdict::Unknown, "{}", check.detail);
            assert!(
                check.detail.contains("/backups/one.tar.zst.age"),
                "{}",
                check.detail
            );
        }
    }

    /// "On no other node" is half an answer from the routing table, so a table that would not
    /// open must not earn a Fail.
    #[test]
    fn a_routing_table_that_would_not_open_is_not_evidence_that_nobody_else_holds_it() {
        let mut private = public_repo_signed_at("rad:zAAA", "aaa");
        private.visibility = Some("private".to_string());
        private.other_seeds = None;
        let inventory = holding(vec![private]);

        // Not in any archive, and nothing to say who else has it
        let check = check_private_coverage(&inventory, None, None, true);
        assert_eq!(check.verdict, Verdict::Unknown, "{}", check.detail);
        assert!(
            check.detail.contains("could not be told"),
            "{}",
            check.detail
        );

        // The same inventory with the table read and genuinely empty is still a finding
        let check = check_private_coverage(&inventory, None, None, false);
        assert_eq!(check.verdict, Verdict::Fail, "{}", check.detail);
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
            policies: None,
            restored: None,
        }
    }
}
