//! Reading and snapshotting the node's SQLite databases.
//!
//! Copying a live SQLite file with `cp` is the bug this module exists to avoid: the copy
//! misses whatever is still in the write-ahead log, and the orphaned `-wal` beside it makes
//! the result look intact. SQLite's own online backup API takes a consistent snapshot of a
//! database that is being written to, which is why a backup does not have to stop the node
//! for these files.

use std::collections::BTreeMap;
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
        let alias: String = row.get(1)?;
        Ok(FollowingPolicy {
            nid: row.get(0)?,
            alias: (!alias.is_empty()).then_some(alias),
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
/// A database left with a write-ahead log by a stopped node cannot be recovered through a
/// read-only connection, so that case falls back to a writable one. The fallback is reported
/// by the caller rather than taken silently, because it means touching a file we said we
/// would only read.
fn open_read_only(path: &Path) -> Result<Connection> {
    let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI;
    match Connection::open_with_flags(path, flags) {
        Ok(db) => Ok(db),
        Err(read_only_error) => {
            let db = Connection::open(path).map_err(|_| Error::Sqlite(read_only_error))?;
            record_writable_open(path);
            Ok(db)
        }
    }
}

/// Databases this run had to open writable after promising to read them.
///
/// Process-wide rather than threaded back through four return types, because that is the shape
/// of the fact: somewhere in this run, a file we said we would only read was opened for
/// writing. The command layer drains this once and says so, which is what the doc comment above
/// has always claimed happens.
static OPENED_WRITABLE: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

fn record_writable_open(path: &Path) {
    if let Ok(mut opened) = OPENED_WRITABLE.lock() {
        opened.push(path.to_path_buf());
    }
}

/// Take the list of such databases, leaving it empty.
pub fn drain_writable_opens() -> Vec<PathBuf> {
    OPENED_WRITABLE
        .lock()
        .map(|mut opened| std::mem::take(&mut *opened))
        .unwrap_or_default()
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
             insert into following values ('z6MkBBB', '', 'block');",
        )
        .expect("fixture schema applies");
    }

    #[test]
    fn policies_export_separates_what_is_seeded_from_what_is_blocked() {
        let path = scratch("policies");
        seed_policies_db(&path);

        let policies = read_policies(&path).expect("policies are readable");
        assert_eq!(policies.seeding.len(), 2);
        assert_eq!(policies.seeded().count(), 1);
        assert_eq!(policies.blocked_repos().count(), 1);
        assert_eq!(policies.followed().count(), 1);
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
        assert_eq!(copied.following.len(), 2);

        let _ = std::fs::remove_file(source);
        let _ = std::fs::remove_file(destination);
    }
}
