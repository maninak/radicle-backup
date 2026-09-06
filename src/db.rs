//! Reading and snapshotting the node's SQLite databases.
//!
//! Copying a live SQLite file with `cp` is the bug this module exists to avoid: the copy
//! misses whatever is still in the write-ahead log, and the orphaned `-wal` beside it makes
//! the result look intact. SQLite's own online backup API takes a consistent snapshot of a
//! database that is being written to, which is why a backup does not have to stop the node
//! for these files.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Pages per step and the pause between steps. Small enough that a busy node keeps its lock
/// turns, large enough that a database of tens of megabytes does not take minutes.
const BACKUP_PAGES_PER_STEP: std::ffi::c_int = 256;
const BACKUP_PAUSE: Duration = Duration::from_millis(25);

/// A seeding policy row: which repository, at what scope, allowed or blocked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedingPolicy {
    pub rid: String,
    pub scope: String,
    pub policy: String,
}

/// A following policy row: which peer, under what local alias, allowed or blocked.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FollowingPolicy {
    pub nid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    pub policy: String,
}

/// Everything `policies.db` holds, in a form that outlives the schema that stored it.
///
/// The database file is archived too. This export exists so that a restore into a future
/// Radicle whose schema has moved on can still replay the decisions the user made, one
/// `rad seed` or `rad follow` at a time.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Policies {
    pub seeding: Vec<SeedingPolicy>,
    pub following: Vec<FollowingPolicy>,
}

impl Policies {
    /// The seeding policies indexed by repository, for a caller that looks up one per
    /// repository: a seed has as many policies as repositories, and a scan inside that loop is
    /// quadratic in the number of repositories it is asked about.
    pub fn seeding_by_rid(&self) -> BTreeMap<&str, &SeedingPolicy> {
        self.seeding
            .iter()
            .map(|policy| (policy.rid.as_str(), policy))
            .collect()
    }

    pub fn seeded(&self) -> impl Iterator<Item = &SeedingPolicy> {
        self.seeding.iter().filter(|p| p.policy == "allow")
    }

    pub fn blocked_repos(&self) -> impl Iterator<Item = &SeedingPolicy> {
        self.seeding.iter().filter(|p| p.policy == "block")
    }

    pub fn followed(&self) -> impl Iterator<Item = &FollowingPolicy> {
        self.following.iter().filter(|p| p.policy == "allow")
    }

    pub fn blocked_peers(&self) -> impl Iterator<Item = &FollowingPolicy> {
        self.following.iter().filter(|p| p.policy == "block")
    }

    /// Every row's identifier, for a caller reporting that none of them were put back. Sorted
    /// and deduplicated, because a repository can be named by a seeding row and a blocking one
    /// and a reader counting the list would then see it twice.
    pub fn identifiers(&self) -> Vec<String> {
        self.seeding
            .iter()
            .map(|policy| policy.rid.clone())
            .chain(self.following.iter().map(|policy| policy.nid.clone()))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

/// Copy a live database consistently, using SQLite's online backup API.
pub fn snapshot(source: &Path, destination: &Path) -> Result<()> {
    let from = open_read_only(source)?;
    let mut to = Connection::open(destination)?;
    let backup = rusqlite::backup::Backup::new(&from, &mut to)?;
    backup.run_to_completion(BACKUP_PAGES_PER_STEP, BACKUP_PAUSE, None)?;
    Ok(())
}

/// Read the seeding and following tables.
pub fn read_policies(path: &Path) -> Result<Policies> {
    if !path.is_file() {
        return Ok(Policies::default());
    }
    let db = open_read_only(path)?;

    let mut seeding = Vec::new();
    let mut statement = db.prepare("select id, scope, policy from seeding order by id")?;
    let rows = statement.query_map([], |row| {
        Ok(SeedingPolicy {
            rid: row.get(0)?,
            scope: row.get(1)?,
            policy: row.get(2)?,
        })
    })?;
    for row in rows {
        seeding.push(row?);
    }

    let mut following = Vec::new();
    let mut statement = db.prepare("select id, alias, policy from following order by id")?;
    let rows = statement.query_map([], |row| {
        // Option, because the column is nullable and nothing here filters it: read as a
        // String, a NULL alias failed its row, one failed row failed the whole read, and a
        // backup died over a field this code already treats as absent when it is empty.
        let alias: Option<String> = row.get(1)?;
        Ok(FollowingPolicy {
            nid: row.get(0)?,
            alias: alias.filter(|alias| !alias.is_empty()),
            policy: row.get(2)?,
        })
    })?;
    for row in rows {
        following.push(row?);
    }

    Ok(Policies { seeding, following })
}

/// How many other nodes the routing table says announce each repository.
///
/// This is gossip, so it is a lower bound and not proof that a copy exists elsewhere. It is
/// still the only local answer to "if this disk dies, does this repository survive".
pub fn read_routing_counts(node_db: &Path, own_node_id: &str) -> Result<BTreeMap<String, u64>> {
    if !node_db.is_file() {
        return Ok(BTreeMap::new());
    }
    let db = open_read_only(node_db)?;
    let Some(mut statement) = prepare_against_heartwood(
        &db,
        node_db,
        "select repo, count(*) from routing where node != ?1 group by repo",
        "routing table",
    )?
    else {
        return Ok(BTreeMap::new());
    };
    let rows = statement.query_map([own_node_id], |row| {
        // `count(*)` is never negative. Converted and not cast, so a value sqlite could
        // not have produced reads as none instead of wrapping round to billions of seeds.
        let held_by = u64::try_from(row.get::<_, i64>(1)?).unwrap_or(0);
        Ok((row.get::<_, String>(0)?, held_by))
    })?;

    let mut counts = BTreeMap::new();
    for row in rows {
        let (repo, count) = row?;
        counts.insert(repo, count);
    }
    Ok(counts)
}

/// Which of this peer's sigrefs some other node is known to hold, per repository.
///
/// The node records, per repository and per peer, the head of *your* `rad/sigrefs` that peer
/// was last seen to carry. A repository whose current local head appears here against somebody
/// else is work that has left this machine; one whose head appears against nobody is work that
/// exists on this disk and nowhere in the world.
///
/// Heads only, and no timestamp beside them. The obvious use for the column would be to tell
/// a row a peer wrote since a restore from one that was already there. It cannot: heartwood
/// stamps each row with the
/// ANNOUNCING node's clock, and replays historical gossip with its original timestamp, so the
/// column orders nothing this reader's caller could act on. Which node said it is nobody's
/// question here either, so two nodes on one head collapse to one entry.
///
/// Empty when the node has never run or the table is not there, which a caller must read as
/// "not known" rather than as "nothing has propagated". Every repository would otherwise look
/// stranded on a machine whose node has simply never been started. The second case is also
/// recorded for `drain_schema_drift`, because "not known" has two remedies and the map alone
/// cannot say which.
pub fn read_synced_heads(
    node_db: &Path,
    own_node_id: &str,
) -> Result<BTreeMap<String, BTreeSet<String>>> {
    if !node_db.is_file() {
        return Ok(BTreeMap::new());
    }
    let db = open_read_only(node_db)?;
    let Some(mut statement) = prepare_against_heartwood(
        &db,
        node_db,
        "select repo, head from \"repo-sync-status\" where node != ?1 order by repo, head",
        "sync status table",
    )?
    else {
        return Ok(BTreeMap::new());
    };
    let rows = statement.query_map([own_node_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;

    let mut heads: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for row in rows {
        let (repo, head) = row?;
        heads.entry(repo).or_default().insert(head);
    }
    Ok(heads)
}

/// The aliases peers announced for themselves, so that a restored home shows names instead of
/// node ids from its first minute.
pub fn read_alias_book(node_db: &Path) -> Result<BTreeMap<String, String>> {
    if !node_db.is_file() {
        return Ok(BTreeMap::new());
    }
    let db = open_read_only(node_db)?;
    let Some(mut statement) = prepare_against_heartwood(
        &db,
        node_db,
        "select id, alias from nodes where alias != '' order by id",
        "nodes table",
    )?
    else {
        return Ok(BTreeMap::new());
    };
    let rows = statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;

    let mut aliases = BTreeMap::new();
    for row in rows {
        let (id, alias) = row?;
        aliases.insert(id, alias);
    }
    Ok(aliases)
}

/// Open for reading without taking a write lock on someone else's database.
///
/// A database with a write-ahead log cannot be read at all without the `-shm` index beside it,
/// and SQLite makes that file even through a read-only connection: the flag stops writes to
/// the database, not to the directory holding it. The file appears in the home whatever this
/// function promises, so it is recorded here and reported by the caller, rather than found
/// afterwards by the person whose home it is.
///
/// No fallback to a writable connection, because one cannot help: `open_with_flags` is lazy,
/// so a read-only open succeeds even when the log cannot be indexed and the first query is
/// what fails, and the only case where reading genuinely fails is a directory this process may
/// not write, where a writable connection cannot make the `-shm` any more than a read-only one
/// can.
fn open_read_only(path: &Path) -> Result<Connection> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI;
    let db = Connection::open_with_flags(path, flags).map_err(Error::Sqlite)?;
    // After the open, because the open is what creates the file. An open that failed left
    // nothing behind, and warning about it would send somebody looking for a file that is
    // not there.
    if has_write_ahead_log(path) {
        record_touched(path);
    }
    // Opening reads nothing, so this is the first call that actually goes through the log.
    // Asked here so a database that cannot be read says which one it is, instead of surfacing
    // later as a bare "unable to open database file" from whichever query happened to run.
    db.query_row("select count(*) from sqlite_schema", [], |_| Ok(()))
        .map_err(|e| Error::Malformed {
            path: path.to_path_buf(),
            reason: format!("this database could not be read: {e}"),
        })?;
    Ok(db)
}

/// Whether a write-ahead log sits beside this database, which is what makes reading it write.
fn has_write_ahead_log(path: &Path) -> bool {
    let mut log = path.as_os_str().to_os_string();
    log.push("-wal");
    Path::new(&log).exists()
}

/// Files this run created inside a home it promised only to read.
///
/// Process-wide rather than threaded back through four return types, because that is the shape
/// of the fact: somewhere in this run, reading left something behind. The command layer drains
/// this once and says so.
static TOUCHED: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

fn record_touched(path: &Path) {
    if let Ok(mut touched) = TOUCHED.lock()
        && !touched.iter().any(|seen| seen == path)
    {
        touched.push(path.to_path_buf());
    }
}

/// Take the list of such databases, leaving it empty.
pub fn drain_touched() -> Vec<PathBuf> {
    TOUCHED
        .lock()
        .map(|mut touched| std::mem::take(&mut *touched))
        .unwrap_or_default()
}

/// The warning for a database that reading touched. In one place because it is both printed
/// by the run and recorded in the manifest of a backup, and those two must not drift apart.
pub fn touched_warning(path: &Path) -> String {
    format!(
        "reading {} created the `-shm` index beside it: a database with a write-ahead log \
         cannot be read without one, and read-only stops writes to the database, not to the \
         directory it sits in",
        path.display()
    )
}

/// Prepare a statement that reads heartwood's schema, or `None` when this schema does not
/// have what it names.
///
/// Only the table or the column being absent is tolerated, because that is heartwood moving
/// its schema on, and an archive never depends on a `rad` version. Anything else, a database
/// that will not open or an image that is corrupt, is propagated: rendered as an empty map it
/// reached `doctor` as "the node has no record of what any other node holds", which sent the
/// reader to start a node that is already running.
///
/// One function for every reader, because the tolerance used to live in `read_synced_heads`
/// alone and a heartwood release that renamed `routing` or `nodes` failed `rad backup`
/// outright with an sqlite error. The absence is recorded for `drain_schema_drift`, because
/// the empty map a reader hands back is the same answer as "the node has never run", and the
/// two want different remedies.
fn prepare_against_heartwood<'db>(
    db: &'db Connection,
    path: &Path,
    sql: &str,
    wanted: &'static str,
) -> Result<Option<rusqlite::Statement<'db>>> {
    match db.prepare(sql) {
        Ok(statement) => Ok(Some(statement)),
        Err(e) if is_absent_from_this_schema(&e) => {
            record_schema_drift(path, wanted, &e);
            Ok(None)
        }
        Err(e) => Err(e.into()),
    }
}

/// Something a reader went looking for in the node's database and this schema does not have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaDrift {
    pub path: PathBuf,
    /// What was wanted, in words: "routing table", "nodes table".
    pub wanted: &'static str,
    /// What sqlite said, so a reader of the warning can tell a renamed table from a renamed
    /// column without opening the database.
    pub reason: String,
}

/// Tables and columns this run went looking for and this schema did not have.
///
/// Process-wide for the same reason `TOUCHED` is: the readers hand back maps that four
/// callers pass on as maps, and an empty one cannot say whether the node has never run or
/// heartwood renamed the table. The command layer drains this once and says so, beside the
/// touched databases.
static SCHEMA_DRIFT: Mutex<Vec<SchemaDrift>> = Mutex::new(Vec::new());

fn record_schema_drift(path: &Path, wanted: &'static str, e: &rusqlite::Error) {
    if let Ok(mut drift) = SCHEMA_DRIFT.lock()
        && !drift
            .iter()
            .any(|seen| seen.path == path && seen.wanted == wanted)
    {
        drift.push(SchemaDrift {
            path: path.to_path_buf(),
            wanted,
            reason: e.to_string(),
        });
    }
}

/// Whether the read of one table of one database met a schema it could not follow.
///
/// A peek and not a drain: the command layer owns the draining and prints every entry with the
/// file and the sqlite reason in it. A check that took them to explain itself would silence
/// that. It exists so that an empty answer is not handed to a reader with the one remedy that
/// suits the other cause of it, "start the node".
///
/// A reader that asks the process-wide question treats every other read's drift as its own, so
/// an unrelated read anywhere before it silently turns a table that was read perfectly into
/// "not known", with a warning naming a table nobody asked about. Both halves matter: `doctor`
/// reads `policies.db` before it reads the node's, and it reads two tables of the node's.
///
/// `wanted` is the same word the reader passed to `prepare_against_heartwood`.
pub fn saw_schema_drift_in(database: &Path, wanted: &str) -> bool {
    SCHEMA_DRIFT
        .lock()
        .map(|drift| {
            drift
                .iter()
                .any(|seen| seen.path == database && seen.wanted == wanted)
        })
        .unwrap_or(false)
}

/// Take the list of such absences, leaving it empty.
///
/// Drained once per run by whichever verb is finishing, `main` for most and `backup` for the
/// line it writes into the manifest, and never by a check: a check that drained it would
/// silence the report that names the file and the sqlite reason.
pub fn drain_schema_drift() -> Vec<SchemaDrift> {
    SCHEMA_DRIFT
        .lock()
        .map(|mut drift| std::mem::take(&mut *drift))
        .unwrap_or_default()
}

/// Held by every test that reads or drains the touched list.
///
/// Same shape as `while_reading_drift` below and for the same reason: `drain_touched` empties
/// a process-wide list for everybody, so one test draining between another's read and its
/// assertion turns a database that was touched into one that was not.
#[cfg(test)]
pub(crate) fn while_reading_touched() -> std::sync::MutexGuard<'static, ()> {
    static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());
    ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Held by every test that reads or drains the drift list.
///
/// The list is process-wide, a test binary is one process, and `drain_schema_drift` empties it
/// for everybody: one test draining between another's read and its assertion turns a table
/// that did not parse into a table that did, at random, on a machine under load.
#[cfg(test)]
pub(crate) fn while_reading_drift() -> std::sync::MutexGuard<'static, ()> {
    static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());
    ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The warning for a table or column this schema did not have. In one place for the same
/// reason `touched_warning` is: printed by the run and recorded in a manifest, and the two
/// must not drift apart.
pub fn schema_drift_warning(drift: &SchemaDrift) -> String {
    format!(
        "{} does not have the {} this tool reads ({}): the node's schema has moved on, so \
         whatever would have been read from it is reported as not known rather than as empty; \
         a newer rad-backup may read it",
        drift.path.display(),
        drift.wanted,
        drift.reason
    )
}

/// Whether sqlite refused a statement because what it names is not in this schema.
///
/// The node's schema is heartwood's, and this tool is not entitled to a release every time
/// heartwood adds or renames a table or a column. Every other sqlite failure, a database that
/// will not open above all, is a real one and says so.
///
/// The two spellings are not interchangeable: a missing table comes back as a generic
/// `SqliteFailure`, and a missing column as a `SqlInputError` carrying the offset of the name
/// inside the statement, for which `sqlite_error()` answers `None`. Matching only the first
/// left a renamed column aborting `doctor` outright.
fn is_absent_from_this_schema(e: &rusqlite::Error) -> bool {
    let complains_about = |what: &str| e.to_string().contains(what);
    match e {
        rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error {
                code: rusqlite::ffi::ErrorCode::Unknown,
                ..
            },
            _,
        ) => complains_about("no such table"),
        rusqlite::Error::SqlInputError { .. } => {
            complains_about("no such table") || complains_about("no such column")
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let path =
            std::env::temp_dir().join(format!("rad-backup-db-{name}-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        path
    }

    fn write_policies_fixture(path: &Path) {
        write_policies_fixture_into(&Connection::open(path).expect("scratch database opens"));
    }

    fn write_policies_fixture_into(db: &Connection) {
        db.execute_batch(
            "create table seeding (id text primary key, scope text, policy text);
             create table following (id text primary key, alias text, policy text);
             insert into seeding values ('rad:zAAA', 'all', 'allow');
             insert into seeding values ('rad:zBBB', 'followed', 'block');
             insert into following values ('z6MkAAA', 'lorenz', 'allow');
             insert into following values ('z6MkBBB', '', 'block');
             insert into following values ('z6MkCCC', null, 'allow');",
        )
        .expect("fixture schema applies");
    }

    #[test]
    fn reading_a_database_with_a_log_beside_it_is_recorded_as_touching_the_home() {
        let dir = std::env::temp_dir().join(format!("rad-backup-wal-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch directory is creatable");

        let quiet = dir.join("quiet.db");
        Connection::open(&quiet)
            .expect("a database is creatable")
            .execute("create table t (a)", [])
            .expect("a table is creatable");

        // Held open, because closing checkpoints the log away and takes the `-wal` with it.
        let noisy = dir.join("noisy.db");
        let live = Connection::open(&noisy).expect("a database is creatable");
        live.pragma_update(None, "journal_mode", "wal")
            .expect("the journal mode is settable");
        live.execute("create table t (a)", [])
            .expect("a table is creatable");
        assert!(
            noisy.with_extension("db-wal").exists(),
            "the log must be hot"
        );

        let _reading_touched = while_reading_touched();
        let _ = drain_touched();
        open_read_only(&quiet).expect("a database with no log reads");
        open_read_only(&noisy).expect("a database with a log reads");
        let touched = drain_touched();

        // Reading the one with a log creates its `-shm` in the home. That happened before and
        // was reported as nothing at all, because the recording sat behind a fallback that a
        // write-ahead log never reaches.
        assert!(touched.contains(&noisy), "{touched:?}");
        assert!(!touched.contains(&quiet), "{touched:?}");
        assert!(
            touched_warning(&noisy).contains("-shm"),
            "the warning has to name what appeared"
        );

        drop(live);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn policies_export_separates_what_is_seeded_from_what_is_blocked() {
        let path = scratch("policies");
        write_policies_fixture(&path);

        let policies = read_policies(&path).expect("policies are readable");
        assert_eq!(policies.seeding.len(), 2);
        assert_eq!(policies.seeded().count(), 1);
        assert_eq!(policies.blocked_repos().count(), 1);
        assert_eq!(policies.followed().count(), 2);
        assert_eq!(policies.blocked_peers().count(), 1);
        assert_eq!(
            policies.followed().next().and_then(|p| p.alias.as_deref()),
            Some("lorenz")
        );
        // An empty alias column is absence, not a peer called "".
        assert_eq!(
            policies
                .blocked_peers()
                .next()
                .and_then(|p| p.alias.as_deref()),
            None
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_null_alias_is_absence_rather_than_a_row_that_fails_the_whole_read() {
        let path = scratch("null-alias");
        write_policies_fixture(&path);

        let policies = read_policies(&path).expect("a null alias does not fail the read");
        let null_alias = policies
            .following
            .iter()
            .find(|policy| policy.nid == "z6MkCCC")
            .expect("the peer with the null alias is still in the export");
        assert_eq!(null_alias.alias, None);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_missing_database_reads_as_empty_rather_than_as_an_error() {
        let policies = read_policies(Path::new("/nonexistent/policies.db"))
            .expect("an absent database is not a failure");
        assert!(policies.seeding.is_empty());
        assert!(policies.following.is_empty());
    }

    /// A hot write-ahead log, because that is the only shape in which this function differs
    /// from `std::fs::copy`. Written against a closed database the two are indistinguishable,
    /// and deleting the backup API left the test green. A `policies.db` on a machine whose
    /// node is up is exactly this: rows committed, the main file not yet holding them.
    #[test]
    fn a_snapshot_carries_rows_a_plain_file_copy_would_lose() {
        let source = scratch("snapshot-source");
        let destination = scratch("snapshot-destination");
        let by_hand = scratch("snapshot-by-hand");

        // Held to the end of the test: closing the last connection checkpoints the log into
        // the database, and the two copies become the same thing again.
        let live = Connection::open(&source).expect("scratch database opens");
        live.pragma_update(None, "journal_mode", "wal")
            .expect("the journal mode is settable");
        write_policies_fixture_into(&live);
        assert!(
            source.with_extension("db-wal").exists(),
            "the log must be hot or this test proves nothing"
        );

        let _reading_touched = while_reading_touched();
        snapshot(&source, &destination).expect("snapshot succeeds");
        std::fs::copy(&source, &by_hand).expect("the source file is copyable");

        let copied = read_policies(&destination).expect("the copy is a database");
        assert_eq!(copied.seeding.len(), 2);
        assert_eq!(copied.following.len(), 3);

        // The control: what a `cp` of the file alone hands a reader, and the reason the
        // backup API is here rather than one.
        let lost = read_policies(&by_hand).unwrap_or_default();
        assert!(
            lost.seeding.is_empty() && lost.following.is_empty(),
            "a plain copy of a database with a hot log must not hold the rows: {lost:?}"
        );

        drop(live);
        for path in [&source, &destination, &by_hand] {
            let _ = std::fs::remove_file(path);
            let _ = std::fs::remove_file(path.with_extension("db-wal"));
            let _ = std::fs::remove_file(path.with_extension("db-shm"));
        }
    }

    /// The bug: only `read_synced_heads` tolerated a table heartwood had renamed. The other
    /// two readers called `?` on `prepare`, so a node database whose `routing` or `nodes`
    /// table had moved on failed `rad backup`, `doctor` and `diff` outright with an sqlite
    /// error, against the guardrail that an archive never depends on a `rad` version. And an
    /// empty map on its own is the same answer as "the node has never run", so the absence is
    /// also on record for the command layer to say.
    #[test]
    fn a_node_database_whose_tables_moved_on_reads_as_not_known_and_says_which_table_moved() {
        let path = scratch("moved-on");
        Connection::open(&path)
            .expect("scratch database opens")
            .execute_batch("create table routing_v2 (repo text, node text)")
            .expect("fixture schema applies");

        let _reading_drift = while_reading_drift();
        let _ = drain_schema_drift();
        let routing = read_routing_counts(&path, "z6MkAAA")
            .expect("a renamed routing table is not a failure");
        let aliases = read_alias_book(&path).expect("a renamed nodes table is not a failure");
        let heads = read_synced_heads(&path, "z6MkAAA")
            .expect("a renamed sync status table is not a failure");
        assert!(routing.is_empty() && aliases.is_empty() && heads.is_empty());

        // Asked per database as well. `restore` reads it that way to decide whether an empty
        // record means "nobody has reported anything else" or "this build could not read the
        // table", and the first of those is a sentence that reassures: asked about the
        // process instead, one unrelated read of a renamed table anywhere earlier in the run
        // would turn every repository into "could not be compared".
        assert!(saw_schema_drift_in(&path, "sync status table"));
        // A table of the same database that was never read, and a database nobody touched.
        assert!(!saw_schema_drift_in(&path, "issues table"));
        assert!(!saw_schema_drift_in(
            std::path::Path::new("/nonexistent.db"),
            "sync status table"
        ));

        // Other tests drain the same list, so what is asserted is presence and not the exact
        // set.
        let drift = drain_schema_drift();
        let wanted: Vec<&str> = drift
            .iter()
            .filter(|seen| seen.path == path)
            .map(|seen| seen.wanted)
            .collect();
        for table in ["routing table", "nodes table", "sync status table"] {
            assert!(
                wanted.contains(&table),
                "{table} is not on record: {drift:?}"
            );
        }
        let warning = schema_drift_warning(&drift[0]);
        assert!(
            warning.contains("no such table"),
            "the warning has to carry what sqlite said: {warning}"
        );

        let _ = std::fs::remove_file(path);
    }

    /// The predicate decides between "heartwood moved its schema on" and "this database is
    /// broken", and the shapes it reads are rusqlite's, not sqlite's: a version bump can
    /// change which variant carries which message. Asserted against the real library rather
    /// than against a remembered spelling of it.
    #[test]
    fn a_renamed_table_or_column_is_schema_drift_and_a_ruined_file_is_not() {
        let db = rusqlite::Connection::open_in_memory().expect("memory is a database");
        db.execute_batch("create table kept (rid text)")
            .expect("the table is creatable");

        let gone = db
            .prepare("select rid from \"repo-sync-status\"")
            .expect_err("the table is not there");
        assert!(is_absent_from_this_schema(&gone), "{gone:?}");

        let renamed = db
            .prepare("select head from kept")
            .expect_err("the column is not there");
        assert!(is_absent_from_this_schema(&renamed), "{renamed:?}");

        let mistyped = db
            .prepare("slect rid from kept")
            .expect_err("that is not sql");
        assert!(
            !is_absent_from_this_schema(&mistyped),
            "a statement this tool got wrong is this tool's fault: {mistyped:?}"
        );

        // A file that is not a database at all reaches the caller as a failure rather than as
        // an empty answer, and it never gets as far as the predicate: it fails on the open.
        let ruined = scratch("not-a-database");
        std::fs::write(&ruined, b"this is not an sqlite image").expect("scratch file is writable");
        let refused = read_synced_heads(&ruined, "z6MkAAA").expect_err("that is not a database");
        assert!(
            matches!(refused, Error::Malformed { .. }),
            "a ruined node database is news, not an empty map: {refused:?}"
        );
        let _ = std::fs::remove_file(ruined);
    }
}
