//! Reading and snapshotting the node's SQLite databases.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

// Backup pages per step and the pause between steps, small enough that a busy node keeps its
// lock turns and large enough that tens of megabytes copy in seconds
const BACKUP_PAGES_PER_STEP: std::ffi::c_int = 256;
const BACKUP_PAUSE: Duration = Duration::from_millis(25);

/// A seeding policy row, naming a repository, its scope and whether it is allowed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeedingPolicy {
    pub rid: String,
    pub scope: String,
    pub policy: String,
}

/// A following policy row, naming a peer, its local alias and whether it is allowed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FollowingPolicy {
    pub nid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    pub policy: String,
}

/// Everything `policies.db` holds, in a form that outlives the schema that stored it.
///
/// A restore into a Radicle whose schema has changed replays these one `rad seed` or
/// `rad follow` at a time.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Policies {
    pub seeding: Vec<SeedingPolicy>,
    pub following: Vec<FollowingPolicy>,
}

impl Policies {
    /// The seeding policies indexed by repository.
    ///
    /// A seed has as many policies as repositories, so a scan per repository is quadratic.
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

    /// Every row's identifier, sorted and listed once each.
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

/// Copies a live database consistently through SQLite's online backup API.
///
/// A plain file copy misses rows still in the write-ahead log, and the orphaned `-wal` makes
/// the result look intact. The backup API needs no node stop.
pub fn snapshot(source: &Path, destination: &Path) -> Result<()> {
    let from = open_read_only(source)?;
    let mut to = Connection::open(destination)?;
    let backup = rusqlite::backup::Backup::new(&from, &mut to)?;
    backup.run_to_completion(BACKUP_PAGES_PER_STEP, BACKUP_PAUSE, None)?;
    Ok(())
}

/// Reads the seeding and following tables, or nothing when the file is missing.
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
        // The alias column is nullable, and a NULL read as `String` fails the whole read
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

/// The number of other nodes the routing table says announce each repository.
///
/// The count comes from gossip, so it is a lower bound and not proof a copy exists elsewhere.
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
        // `try_from` turns an impossible negative count into 0, where a cast wraps to billions
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

/// The heads of this peer's `rad/sigrefs` that other nodes are known to hold, per repository.
///
/// A current local head absent from this map exists on this disk alone. An empty map means
/// "not known", because the node may never have run or the table may be missing, and
/// [`saw_schema_drift_in`] tells those two apart.
///
/// The table's timestamps come from the announcing node's clock, and replayed gossip keeps its
/// original stamp, so no reader may order rows by them.
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

/// The aliases peers announced for themselves, so a restored home shows names from its first
/// minute.
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

/// Opens a database for reading without taking a write lock.
///
/// SQLite creates the `-shm` index beside a WAL database even through a read-only connection.
/// That file stays in place, because the node shares it and deleting it can corrupt the
/// database. A writable fallback cannot help, because a directory that refuses the `-shm`
/// refuses it to both kinds of connection.
fn open_read_only(path: &Path) -> Result<Connection> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI;
    let db = Connection::open_with_flags(path, flags).map_err(Error::Sqlite)?;
    // Opening reads nothing, so this first query makes an unreadable database fail here, with
    // its path
    db.query_row("select count(*) from sqlite_schema", [], |_| Ok(()))
        .map_err(|e| Error::Malformed {
            path: path.to_path_buf(),
            reason: format!("this database could not be read: {e}"),
        })?;
    Ok(db)
}

/// Prepares a statement against heartwood's schema, or `None` when the schema lacks a table
/// or column it names.
///
/// A missing table or column is recorded for [`drain_schema_drift`]. Every other error
/// propagates, because an empty map would tell `doctor` the node has never run.
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

/// A table or column a reader looked for in the node's database and the schema lacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaDrift {
    pub path: PathBuf,
    /// What was wanted, in words, such as `routing table`.
    pub wanted: &'static str,
    /// What sqlite said, which tells a renamed table from a renamed column.
    pub reason: String,
}

/// The tables and columns this run looked for and the schema lacked.
///
/// The list is process-wide, because the readers return plain maps, and an empty map cannot
/// say whether the node never ran or heartwood renamed the table.
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

/// Whether reading `wanted` from `database` met a schema it could not follow.
///
/// `wanted` is the word the reader passed to `prepare_against_heartwood`. This peeks without
/// draining, so the run's report still names every entry. The check is per table, because
/// another read's drift must not turn a table read fine into "not known".
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

/// Takes the recorded schema drift, leaving the list empty.
///
/// The finishing command drains it once per run. A check must never drain it, or the report
/// that names the file and the sqlite reason goes silent.
pub fn drain_schema_drift() -> Vec<SchemaDrift> {
    SCHEMA_DRIFT
        .lock()
        .map(|mut drift| std::mem::take(&mut *drift))
        .unwrap_or_default()
}

/// Serializes the tests that read or drain the drift list.
///
/// The list is process-wide, so one test draining between another's read and its assertion
/// makes that test fail at random under load.
#[cfg(test)]
pub(crate) fn while_reading_drift() -> std::sync::MutexGuard<'static, ()> {
    static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());
    ONE_AT_A_TIME
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The warning for a table or column the schema lacks, printed by the run and recorded in a
/// manifest.
pub fn schema_drift_warning(drift: &SchemaDrift) -> String {
    format!(
        "{} was written by a Radicle version this rad-backup cannot fully read yet. Anything \
         that needs its {} shows as unknown. A newer rad-backup may fix this ({})",
        drift.path.display(),
        drift.wanted,
        drift.reason
    )
}

/// Whether sqlite refused a statement because a table or column it names is not in the schema.
///
/// A missing table comes back as a generic `SqliteFailure`, and a missing column as a
/// `SqlInputError`, for which `sqlite_error()` answers `None`. Both shapes must match, or a
/// renamed column aborts `doctor`.
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
        // An empty alias column is absence, not a peer called ""
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

    /// The write-ahead log is hot, as under a running node, because against a closed database
    /// a snapshot and `std::fs::copy` match and the test proves nothing.
    #[test]
    fn a_snapshot_carries_rows_a_plain_file_copy_would_lose() {
        let source = scratch("snapshot-source");
        let destination = scratch("snapshot-destination");
        let by_hand = scratch("snapshot-by-hand");

        // `live` stays open, because closing the last connection checkpoints the log
        let live = Connection::open(&source).expect("scratch database opens");
        live.pragma_update(None, "journal_mode", "wal")
            .expect("the journal mode is settable");
        write_policies_fixture_into(&live);
        assert!(
            source.with_extension("db-wal").exists(),
            "the log must be hot or this test proves nothing"
        );

        snapshot(&source, &destination).expect("snapshot succeeds");
        std::fs::copy(&source, &by_hand).expect("the source file is copyable");

        let copied = read_policies(&destination).expect("the copy is a database");
        assert_eq!(copied.seeding.len(), 2);
        assert_eq!(copied.following.len(), 3);

        // The control, showing what a plain copy of the file hands a reader
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

        // `restore` asks per database, so an unrelated renamed table earlier in the run must
        // not mark every repository as "could not be compared"
        assert!(saw_schema_drift_in(&path, "sync status table"));
        // A table of the same database that was never read, and a database nobody touched
        assert!(!saw_schema_drift_in(&path, "issues table"));
        assert!(!saw_schema_drift_in(
            std::path::Path::new("/nonexistent.db"),
            "sync status table"
        ));

        // Other tests drain the same list, so this asserts presence and not the exact set
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

    /// The error variants are rusqlite's and can change with a version bump, so this asserts
    /// against the real library.
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

        // A file that is not a database fails on the open, before the predicate, and reaches
        // the caller as an error
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
