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
/// turns, large enough that a 46 MB database does not take minutes.
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
pub fn routing_counts(node_db: &Path, own_node_id: &str) -> Result<BTreeMap<String, u64>> {
    if !node_db.is_file() {
        return Ok(BTreeMap::new());
    }
    let db = open_read_only(node_db)?;
    let mut statement =
        db.prepare("select repo, count(*) from routing where node != ?1 group by repo")?;
    let rows = statement.query_map([own_node_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
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
/// Empty when the node has never run or the table is not there, which a caller must read as
/// "not known" rather than as "nothing has propagated". Every repository would otherwise look
/// stranded on a machine whose node has simply never been started.
pub fn synced_heads(
    node_db: &Path,
    own_node_id: &str,
) -> Result<BTreeMap<String, BTreeSet<String>>> {
    if !node_db.is_file() {
        return Ok(BTreeMap::new());
    }
    let db = open_read_only(node_db)?;
    // A table this version has not met is not a failure: the node's schema is heartwood's, and
    // this tool is not entitled to a release every time heartwood adds or renames one.
    let mut statement = match db
        .prepare("select repo, head from \"repo-sync-status\" where node != ?1 order by repo, head")
    {
        Ok(statement) => statement,
        Err(_) => return Ok(BTreeMap::new()),
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
pub fn alias_book(node_db: &Path) -> Result<BTreeMap<String, String>> {
    if !node_db.is_file() {
        return Ok(BTreeMap::new());
    }
    let db = open_read_only(node_db)?;
    let mut statement = db.prepare("select id, alias from nodes where alias != '' order by id")?;
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
/// There used to be a fallback here to a writable connection, for "a log a read-only
/// connection cannot recover". It never ran, and would not have helped if it had.
/// `open_with_flags` is lazy, so a read-only open of a database whose log cannot be indexed
/// succeeds and the first query is what fails; the fallback sat behind an `Err` arm that a
/// write-ahead log never reaches. And the only case where the read genuinely fails is a
/// directory this process may not write, where a writable connection cannot make the `-shm`
/// any more than a read-only one can.
fn open_read_only(path: &Path) -> Result<Connection> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI;
    let db = Connection::open_with_flags(path, flags).map_err(Error::Sqlite)?;
    // After the open, because the open is what creates the file. An open that failed left
    // nothing behind, and warning about it would send somebody looking for a file that is
    // not there.
    if has_log(path) {
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
fn has_log(path: &Path) -> bool {
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

/// What to say about one of them. In one place because it is both printed by the run and
/// recorded in the manifest of a backup, and those two must not drift apart.
pub fn touched_warning(path: &Path) -> String {
    format!(
        "reading {} created the `-shm` index beside it: a database with a write-ahead log \
         cannot be read without one, and read-only stops writes to the database, not to the \
         directory it sits in",
        path.display()
    )
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

    fn seed_policies_db(path: &Path) {
        let db = Connection::open(path).expect("scratch database opens");
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
        seed_policies_db(&path);

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
        seed_policies_db(&path);

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

    #[test]
    fn a_snapshot_is_a_complete_copy_of_the_source_database() {
        let source = scratch("snapshot-source");
        let destination = scratch("snapshot-destination");
        seed_policies_db(&source);

        snapshot(&source, &destination).expect("snapshot succeeds");
        let copied = read_policies(&destination).expect("the copy is a database");
        assert_eq!(copied.seeding.len(), 2);
        assert_eq!(copied.following.len(), 3);

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(destination);
    }
}
