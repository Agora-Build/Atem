//! Each machine's local copy (offline-first) plus the outbound queue.
//! `~/.config/atem/knowledge.db`, mode 0600. Holds no secrets by construction.
use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::Path;
use crate::memory::model::{Memory, Scope, Skill};

/// Legacy, unkeyed cursor names. Only the per-account keys below are read;
/// a cursor stored under these bare names is ignored.
pub const MEMORY_CURSOR: &str = "memory_cursor";
pub const SKILL_CURSOR: &str = "skill_cursor";
pub const LAST_SYNC_AT: &str = "last_sync_at";

/// The memory pull cursor for `account` (the paired Astation id). Cursors are
/// per account: a relay seq means nothing under another account, so switching
/// Astations starts that account's pull from 0.
pub fn memory_cursor_key(account: &str) -> String {
    format!("{}:{}", MEMORY_CURSOR, account)
}

/// The skill pull cursor for `account`; see `memory_cursor_key`.
pub fn skill_cursor_key(account: &str) -> String {
    format!("{}:{}", SKILL_CURSOR, account)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum PendingOp {
    AddMemory { memory: Memory },
    DeleteMemory { id: String },
    PushSkill { skill: Skill, base_version: i64 },
    DeleteSkill { scope: Scope, project: String, name: String },
    PurgeSkill { scope: Scope, project: String, name: String, versions: Option<Vec<i64>> },
}

impl PendingOp {
    pub fn is_memory(&self) -> bool {
        matches!(self, PendingOp::AddMemory { .. } | PendingOp::DeleteMemory { .. })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HarvestStatus {
    Synced,
    HeldBack,
    Excluded,
}

impl HarvestStatus {
    fn as_str(&self) -> &'static str {
        match self {
            HarvestStatus::Synced => "synced",
            HarvestStatus::HeldBack => "held_back",
            HarvestStatus::Excluded => "excluded",
        }
    }
    fn parse(s: &str) -> HarvestStatus {
        match s {
            "held_back" => HarvestStatus::HeldBack,
            "excluded" => HarvestStatus::Excluded,
            _ => HarvestStatus::Synced,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct HarvestEntry {
    pub origin: String,
    pub memory_id: String,
    pub content_hash: String,
    pub status: HarvestStatus,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS memories (
  id TEXT PRIMARY KEY, scope TEXT NOT NULL, project TEXT NOT NULL, machine TEXT NOT NULL,
  content TEXT NOT NULL, content_hash TEXT NOT NULL, confidence TEXT NOT NULL,
  source_agent TEXT NOT NULL, source_machine TEXT NOT NULL, created_at INTEGER NOT NULL,
  deleted_at INTEGER, valid_at INTEGER, invalid_at INTEGER, superseded_by TEXT,
  seq INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS skills (
  scope TEXT NOT NULL, project TEXT NOT NULL, name TEXT NOT NULL,
  version INTEGER NOT NULL, deleted INTEGER NOT NULL DEFAULT 0, data TEXT NOT NULL,
  PRIMARY KEY (scope, project, name));
CREATE TABLE IF NOT EXISTS pending_ops (n INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sync_state (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS harvest_map (
  origin TEXT PRIMARY KEY, memory_id TEXT NOT NULL, content_hash TEXT NOT NULL, status TEXT NOT NULL);
";

/// Full-text index over `memories.content`: external content, and trigram
/// so it matches inside CJK text too. Kept in step by triggers. `memories` is
/// a rowid table (TEXT PRIMARY KEY, not WITHOUT ROWID). Never VACUUM this
/// database without `INSERT INTO memories_fts(memories_fts) VALUES ('rebuild')`
/// afterwards: VACUUM may renumber those rowids.
const FTS_SCHEMA: &str = "
CREATE VIRTUAL TABLE IF NOT EXISTS memories_fts USING fts5(
  content, content='memories', content_rowid='rowid', tokenize='trigram');
CREATE TRIGGER IF NOT EXISTS memories_fts_ai AFTER INSERT ON memories BEGIN
  INSERT INTO memories_fts(rowid, content) VALUES (new.rowid, new.content);
END;
CREATE TRIGGER IF NOT EXISTS memories_fts_ad AFTER DELETE ON memories BEGIN
  INSERT INTO memories_fts(memories_fts, rowid, content) VALUES ('delete', old.rowid, old.content);
END;
CREATE TRIGGER IF NOT EXISTS memories_fts_au AFTER UPDATE ON memories BEGIN
  INSERT INTO memories_fts(memories_fts, rowid, content) VALUES ('delete', old.rowid, old.content);
  INSERT INTO memories_fts(rowid, content) VALUES (new.rowid, new.content);
END;
";

fn memory_columns(conn: &Connection) -> Result<Vec<String>> {
    let mut stmt = conn.prepare("PRAGMA table_info(memories)")?;
    let cols = stmt.query_map([], |r| r.get::<_, String>(1))?;
    Ok(cols.collect::<rusqlite::Result<Vec<_>>>()?)
}

/// Bring a pre-1.1 `memories` table to the current shape: `deleted` →
/// `deleted_at` (deleted rows get "now"; the real time was never stored),
/// plus the validity columns. Idempotent; one transaction.
fn migrate_memories(conn: &Connection) -> Result<()> {
    let cols = memory_columns(conn)?;
    let has = |c: &str| cols.iter().any(|x| x == c);
    let wanted = ["deleted_at", "valid_at", "invalid_at", "superseded_by"];
    if !has("deleted") && wanted.iter().all(|c| has(c)) {
        return Ok(());
    }
    let tx = conn.unchecked_transaction()?;
    if !has("deleted_at") {
        tx.execute_batch("ALTER TABLE memories ADD COLUMN deleted_at INTEGER")?;
        if has("deleted") {
            tx.execute("UPDATE memories SET deleted_at = ?1 WHERE deleted != 0", params![crate::memory::model::now_secs()])?;
        }
    }
    for (c, ty) in [("valid_at", "INTEGER"), ("invalid_at", "INTEGER"), ("superseded_by", "TEXT")] {
        if !has(c) {
            tx.execute_batch(&format!("ALTER TABLE memories ADD COLUMN {} {}", c, ty))?;
        }
    }
    if has("deleted") {
        tx.execute_batch("ALTER TABLE memories DROP COLUMN deleted")?;
    }
    tx.commit()?;
    Ok(())
}

const MEM_COLS: &str = "id, scope, project, machine, content, content_hash, confidence, source_agent, source_machine, created_at, deleted_at, valid_at, invalid_at, superseded_by, seq";

fn row_to_memory(r: &rusqlite::Row) -> rusqlite::Result<Memory> {
    let scope: String = r.get(1)?;
    Ok(Memory {
        id: r.get(0)?,
        scope: Scope::parse(&scope).unwrap_or(Scope::Global),
        project: r.get(2)?,
        machine: r.get(3)?,
        content: r.get(4)?,
        content_hash: r.get(5)?,
        confidence: r.get(6)?,
        source_agent: r.get(7)?,
        source_machine: r.get(8)?,
        created_at: r.get(9)?,
        deleted_at: r.get(10)?,
        valid_at: r.get(11)?,
        invalid_at: r.get(12)?,
        superseded_by: r.get(13)?,
        seq: r.get(14)?,
    })
}

fn row_to_harvest(r: &rusqlite::Row) -> rusqlite::Result<HarvestEntry> {
    let status: String = r.get(3)?;
    Ok(HarvestEntry { origin: r.get(0)?, memory_id: r.get(1)?, content_hash: r.get(2)?, status: HarvestStatus::parse(&status) })
}

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: &Path) -> Result<Store> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Create the file with 0600 up front so there's no window where a
            // default umask (e.g. 0644) leaves it world/group readable before
            // we chmod it below. create_new: no exists-then-create race.
            match std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path) {
                Ok(f) => drop(f),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e).with_context(|| format!("creating {}", path.display())),
            }
        }
        let conn = Connection::open(path).with_context(|| format!("opening {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Self::init(conn)
    }

    #[cfg(test)]
    pub fn open_in_memory() -> Result<Store> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> Result<Store> {
        conn.execute_batch(SCHEMA)?;
        migrate_memories(&conn)?;
        let tx = conn.unchecked_transaction()?;
        let had_fts: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name = 'memories_fts')", [], |r| r.get(0))?;
        tx.execute_batch(FTS_SCHEMA)?;
        if !had_fts {
            // Index the rows that existed before the index did.
            tx.execute_batch("INSERT INTO memories_fts(memories_fts) VALUES ('rebuild')")?;
        }
        tx.commit()?;
        Ok(Store { conn })
    }

    // ── memories ────────────────────────────────────────────────────────
    /// Insert or overwrite (the relay is authoritative), except that a local
    /// invalidation the incoming row doesn't have yet is kept. Invalidation
    /// is final, so it can only be "not yet pulled", never undone.
    pub fn upsert_memory(&self, m: &Memory) -> Result<()> {
        self.conn.execute(
            "INSERT INTO memories (id, scope, project, machine, content, content_hash, confidence, source_agent, source_machine, created_at, deleted_at, valid_at, invalid_at, superseded_by, seq)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)
             ON CONFLICT(id) DO UPDATE SET scope=excluded.scope, project=excluded.project, machine=excluded.machine,
               content=excluded.content, content_hash=excluded.content_hash, confidence=excluded.confidence,
               source_agent=excluded.source_agent, source_machine=excluded.source_machine,
               created_at=excluded.created_at, deleted_at=excluded.deleted_at, valid_at=excluded.valid_at,
               invalid_at=COALESCE(excluded.invalid_at, memories.invalid_at),
               superseded_by=CASE WHEN excluded.invalid_at IS NOT NULL THEN excluded.superseded_by ELSE memories.superseded_by END,
               seq=excluded.seq",
            params![m.id, m.scope.as_str(), m.project, m.machine, m.content, m.content_hash, m.confidence,
                    m.source_agent, m.source_machine, m.created_at, m.deleted_at, m.valid_at, m.invalid_at,
                    m.superseded_by, m.seq],
        )?;
        Ok(())
    }

    pub fn get_memory(&self, id: &str) -> Result<Option<Memory>> {
        Ok(self.conn
            .query_row(&format!("SELECT {} FROM memories WHERE id = ?1", MEM_COLS), params![id], row_to_memory)
            .optional()?)
    }

    /// Valid facts: not deleted and not invalidated (what gets injected).
    pub fn live_memories(&self) -> Result<Vec<Memory>> {
        let mut stmt = self.conn.prepare(&format!("SELECT {} FROM memories WHERE deleted_at IS NULL AND invalid_at IS NULL ORDER BY created_at, id", MEM_COLS))?;
        let rows = stmt.query_map([], row_to_memory)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Everything not deleted, including invalidated facts (the history).
    pub fn history_memories(&self) -> Result<Vec<Memory>> {
        let mut stmt = self.conn.prepare(&format!("SELECT {} FROM memories WHERE deleted_at IS NULL ORDER BY created_at, id", MEM_COLS))?;
        let rows = stmt.query_map([], row_to_memory)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// A valid fact with this dedup key. Invalid facts never match, so a fact
    /// that becomes true again is added as a new memory.
    pub fn find_live_by_hash(&self, scope: Scope, project: &str, machine: &str, hash: &str) -> Result<Option<Memory>> {
        Ok(self.conn
            .query_row(
                &format!("SELECT {} FROM memories WHERE deleted_at IS NULL AND invalid_at IS NULL AND scope = ?1 AND project = ?2 AND machine = ?3 AND content_hash = ?4 LIMIT 1", MEM_COLS),
                params![scope.as_str(), project, machine, hash],
                row_to_memory,
            )
            .optional()?)
    }

    /// Tombstone: also clears the text so it doesn't linger locally. The
    /// first deletion time is kept.
    pub fn mark_memory_deleted(&self, id: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE memories SET deleted_at = COALESCE(deleted_at, ?2), content = '', content_hash = '' WHERE id = ?1",
            params![id, crate::memory::model::now_secs()],
        )?;
        Ok(())
    }

    pub fn set_memory_seq(&self, id: &str, seq: i64) -> Result<()> {
        self.conn.execute("UPDATE memories SET seq = ?2 WHERE id = ?1", params![id, seq])?;
        Ok(())
    }

    /// The relay deduped our add to an existing id.
    pub fn rewrite_memory_id(&self, old: &str, new: &str) -> Result<()> {
        if old == new {
            return Ok(());
        }
        let exists: bool = self.conn.query_row("SELECT EXISTS(SELECT 1 FROM memories WHERE id = ?1)", params![new], |r| r.get(0))?;
        if exists {
            self.conn.execute("DELETE FROM memories WHERE id = ?1", params![old])?;
        } else {
            self.conn.execute("UPDATE memories SET id = ?2 WHERE id = ?1", params![old, new])?;
        }
        self.conn.execute("UPDATE harvest_map SET memory_id = ?2 WHERE memory_id = ?1", params![old, new])?;
        Ok(())
    }

    // ── skills (latest version per scope/project/name) ─────────────────
    pub fn put_skill(&self, s: &Skill) -> Result<()> {
        let data = serde_json::to_string(s)?;
        self.conn.execute(
            "INSERT INTO skills (scope, project, name, version, deleted, data) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(scope, project, name) DO UPDATE SET version=excluded.version, deleted=excluded.deleted, data=excluded.data",
            params![s.scope.as_str(), s.project, s.name, s.version, s.deleted as i64, data],
        )?;
        Ok(())
    }

    pub fn get_skill(&self, scope: Scope, project: &str, name: &str) -> Result<Option<Skill>> {
        let data: Option<String> = self.conn
            .query_row("SELECT data FROM skills WHERE scope = ?1 AND project = ?2 AND name = ?3",
                       params![scope.as_str(), project, name], |r| r.get(0))
            .optional()?;
        data.map(|d| serde_json::from_str(&d).map_err(anyhow::Error::from)).transpose()
    }

    /// Includes deleted skills (apply uses them to remove directories).
    pub fn all_skills(&self) -> Result<Vec<Skill>> {
        let mut stmt = self.conn.prepare("SELECT data FROM skills ORDER BY scope, project, name")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(serde_json::from_str(&row?)?);
        }
        Ok(out)
    }

    pub fn live_skills(&self) -> Result<Vec<Skill>> {
        Ok(self.all_skills()?.into_iter().filter(|s| !s.deleted).collect())
    }

    // ── pending ops ─────────────────────────────────────────────────────
    pub fn enqueue(&self, op: &PendingOp) -> Result<()> {
        self.conn.execute("INSERT INTO pending_ops (payload) VALUES (?1)", params![serde_json::to_string(op)?])?;
        Ok(())
    }

    pub fn pending(&self) -> Result<Vec<(i64, PendingOp)>> {
        let mut stmt = self.conn.prepare("SELECT n, payload FROM pending_ops ORDER BY n")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (n, p) = row?;
            out.push((n, serde_json::from_str(&p)?));
        }
        Ok(out)
    }

    pub fn ack(&self, n: i64) -> Result<()> {
        self.conn.execute("DELETE FROM pending_ops WHERE n = ?1", params![n])?;
        Ok(())
    }

    pub fn pending_count(&self) -> Result<usize> {
        let n: i64 = self.conn.query_row("SELECT COUNT(*) FROM pending_ops", [], |r| r.get(0))?;
        Ok(n as usize)
    }

    // ── sync state ──────────────────────────────────────────────────────
    pub fn get_state(&self, key: &str) -> Result<i64> {
        Ok(self.conn
            .query_row("SELECT value FROM sync_state WHERE key = ?1", params![key], |r| r.get(0))
            .optional()?
            .unwrap_or(0))
    }

    pub fn set_state(&self, key: &str, value: i64) -> Result<()> {
        self.conn.execute(
            "INSERT INTO sync_state (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    // ── harvest map ─────────────────────────────────────────────────────
    pub fn harvest_get(&self, origin: &str) -> Result<Option<HarvestEntry>> {
        Ok(self.conn
            .query_row("SELECT origin, memory_id, content_hash, status FROM harvest_map WHERE origin = ?1", params![origin], row_to_harvest)
            .optional()?)
    }

    pub fn harvest_put(&self, e: &HarvestEntry) -> Result<()> {
        self.conn.execute(
            "INSERT INTO harvest_map (origin, memory_id, content_hash, status) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(origin) DO UPDATE SET memory_id=excluded.memory_id, content_hash=excluded.content_hash, status=excluded.status",
            params![e.origin, e.memory_id, e.content_hash, e.status.as_str()],
        )?;
        Ok(())
    }

    /// Exact prefix match (no LIKE wildcards).
    pub fn harvest_with_prefix(&self, prefix: &str) -> Result<Vec<HarvestEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT origin, memory_id, content_hash, status FROM harvest_map WHERE substr(origin, 1, length(?1)) = ?1 ORDER BY origin",
        )?;
        let rows = stmt.query_map(params![prefix], row_to_harvest)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Every harvested file linked to this memory (several files, or files on
    /// several machines' map, can dedupe to one memory).
    pub fn harvest_entries_for_memory(&self, memory_id: &str) -> Result<Vec<HarvestEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT origin, memory_id, content_hash, status FROM harvest_map WHERE memory_id = ?1 ORDER BY origin",
        )?;
        let rows = stmt.query_map(params![memory_id], row_to_harvest)?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn harvest_remove(&self, origin: &str) -> Result<()> {
        self.conn.execute("DELETE FROM harvest_map WHERE origin = ?1", params![origin])?;
        Ok(())
    }

    pub fn held_back_count(&self) -> Result<usize> {
        let n: i64 = self.conn.query_row("SELECT COUNT(*) FROM harvest_map WHERE status = 'held_back'", [], |r| r.get(0))?;
        Ok(n as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::model::{content_hash, skill_hash};
    use std::collections::BTreeMap;

    fn ids(ms: Vec<Memory>) -> Vec<String> {
        ms.into_iter().map(|m| m.id).collect()
    }

    fn fts_hits(s: &Store, q: &str) -> Vec<String> {
        let mut st = s.conn.prepare(
            "SELECT m.id FROM memories_fts JOIN memories m ON m.rowid = memories_fts.rowid WHERE memories_fts MATCH ?1 ORDER BY m.id",
        ).unwrap();
        st.query_map(params![q], |r| r.get(0)).unwrap().map(|x| x.unwrap()).collect()
    }

    #[test]
    fn legacy_db_is_migrated_once() {
        let td = tempfile::tempdir().unwrap();
        let p = td.path().join("knowledge.db");
        {
            let c = Connection::open(&p).unwrap();
            c.execute_batch("CREATE TABLE memories (
              id TEXT PRIMARY KEY, scope TEXT NOT NULL, project TEXT NOT NULL, machine TEXT NOT NULL,
              content TEXT NOT NULL, content_hash TEXT NOT NULL, confidence TEXT NOT NULL,
              source_agent TEXT NOT NULL, source_machine TEXT NOT NULL, created_at INTEGER NOT NULL,
              deleted INTEGER NOT NULL DEFAULT 0, seq INTEGER NOT NULL DEFAULT 0);
            INSERT INTO memories VALUES ('mem_live','global','','','DialF uses TCP 8765','h1','medium','cli','m',1,0,4);
            INSERT INTO memories VALUES ('mem_gone','global','','','','','medium','cli','m',1,1,5);").unwrap();
        }
        let before = crate::memory::model::now_secs();
        let s = Store::open(&p).unwrap();
        let cols = memory_columns(&s.conn).unwrap();
        for c in ["deleted_at", "valid_at", "invalid_at", "superseded_by"] {
            assert!(cols.iter().any(|x| x == c), "{c}");
        }
        assert!(!cols.iter().any(|x| x == "deleted"));
        let gone = s.get_memory("mem_gone").unwrap().unwrap();
        assert!(gone.deleted_at.unwrap() >= before);
        let live = s.get_memory("mem_live").unwrap().unwrap();
        assert_eq!((live.deleted_at, live.valid_at, live.invalid_at, live.superseded_by.clone(), live.seq), (None, None, None, None, 4));
        assert_eq!(fts_hits(&s, "\"tcp 876\""), vec!["mem_live"]); // rebuilt over existing rows
        drop(s);
        let s = Store::open(&p).unwrap(); // idempotent
        assert_eq!(s.get_memory("mem_gone").unwrap().unwrap().deleted_at, gone.deleted_at);
        assert_eq!(ids(s.live_memories().unwrap()), vec!["mem_live"]);
        assert_eq!(fts_hits(&s, "\"tcp 876\""), vec!["mem_live"]);
    }

    #[test]
    fn fts_index_follows_inserts_updates_and_deletes() {
        let s = Store::open_in_memory().unwrap();
        s.upsert_memory(&mem("mem_a", "DialF uses TCP 8765")).unwrap();
        assert_eq!(fts_hits(&s, "\"8765\""), vec!["mem_a"]);
        s.upsert_memory(&mem("mem_a", "DialF uses TCP 9000")).unwrap();
        assert!(fts_hits(&s, "\"8765\"").is_empty());
        assert_eq!(fts_hits(&s, "\"9000\""), vec!["mem_a"]);
        s.rewrite_memory_id("mem_a", "mem_b").unwrap();
        assert_eq!(fts_hits(&s, "\"9000\""), vec!["mem_b"]);
        s.mark_memory_deleted("mem_b").unwrap();
        assert!(fts_hits(&s, "\"9000\"").is_empty());
    }

    #[test]
    fn live_means_valid_and_history_keeps_invalid() {
        let s = Store::open_in_memory().unwrap();
        s.upsert_memory(&mem("mem_a", "A")).unwrap();
        let mut b = mem("mem_b", "B");
        b.invalid_at = Some(10);
        b.superseded_by = Some("mem_a".into());
        s.upsert_memory(&b).unwrap();
        s.upsert_memory(&mem("mem_c", "C")).unwrap();
        s.mark_memory_deleted("mem_c").unwrap();
        assert_eq!(ids(s.live_memories().unwrap()), vec!["mem_a"]);
        assert_eq!(ids(s.history_memories().unwrap()), vec!["mem_a", "mem_b"]);
        // An invalid fact is not a dedup target: re-adding it makes a new memory.
        assert!(s.find_live_by_hash(Scope::Global, "", "", &content_hash("B")).unwrap().is_none());
        let c = s.get_memory("mem_c").unwrap().unwrap();
        assert!(c.is_deleted() && c.content.is_empty());
    }

    #[test]
    fn pulled_row_without_invalidation_keeps_a_local_one() {
        let s = Store::open_in_memory().unwrap();
        let mut a = mem("mem_a", "A");
        a.invalid_at = Some(10);
        a.superseded_by = Some("mem_b".into());
        s.upsert_memory(&a).unwrap();
        // The relay hasn't seen the invalidation yet.
        let mut stale = mem("mem_a", "A");
        stale.seq = 9;
        s.upsert_memory(&stale).unwrap();
        let got = s.get_memory("mem_a").unwrap().unwrap();
        assert_eq!((got.invalid_at, got.superseded_by.as_deref(), got.seq), (Some(10), Some("mem_b"), 9));
        // The relay's invalidation wins when it has one.
        let mut server = mem("mem_a", "A");
        server.invalid_at = Some(7);
        server.superseded_by = Some("mem_c".into());
        s.upsert_memory(&server).unwrap();
        let got = s.get_memory("mem_a").unwrap().unwrap();
        assert_eq!((got.invalid_at, got.superseded_by.as_deref()), (Some(7), Some("mem_c")));
    }

    fn mem(id: &str, content: &str) -> Memory {
        Memory {
            id: id.into(), scope: Scope::Global, project: String::new(), machine: String::new(),
            content: content.into(), content_hash: content_hash(content), confidence: "medium".into(),
            source_agent: "cli".into(), source_machine: "m".into(), created_at: 1, seq: 0, ..Default::default()
        }
    }

    fn skill(name: &str, version: i64) -> Skill {
        let mut files = BTreeMap::new();
        files.insert("SKILL.md".to_string(), b"# s".to_vec());
        Skill {
            scope: Scope::Global, project: String::new(), name: name.into(), version,
            content_hash: skill_hash(&files), files,
            source_agent: "cli".into(), source_machine: "m".into(), created_at: 1, deleted: false, seq: 0,
        }
    }

    #[test]
    fn memory_roundtrip_and_live_filter() {
        let s = Store::open_in_memory().unwrap();
        s.upsert_memory(&mem("mem_a", "A")).unwrap();
        s.upsert_memory(&mem("mem_b", "B")).unwrap();
        assert_eq!(s.get_memory("mem_a").unwrap().unwrap().content, "A");
        s.mark_memory_deleted("mem_b").unwrap();
        let b = s.get_memory("mem_b").unwrap().unwrap();
        assert!(b.is_deleted() && b.content.is_empty() && b.content_hash.is_empty());
        assert_eq!(s.live_memories().unwrap().len(), 1);
    }

    #[test]
    fn find_live_by_hash_matches_scope_key() {
        let s = Store::open_in_memory().unwrap();
        s.upsert_memory(&mem("mem_a", "Same Fact")).unwrap();
        let h = content_hash("same  fact");
        assert!(s.find_live_by_hash(Scope::Global, "", "", &h).unwrap().is_some());
        assert!(s.find_live_by_hash(Scope::Project, "", "", &h).unwrap().is_none());
    }

    #[test]
    fn rewrite_id_moves_row_and_harvest_link() {
        let s = Store::open_in_memory().unwrap();
        s.upsert_memory(&mem("mem_a", "A")).unwrap();
        s.harvest_put(&HarvestEntry { origin: "o".into(), memory_id: "mem_a".into(), content_hash: "h".into(), status: HarvestStatus::Synced }).unwrap();
        s.rewrite_memory_id("mem_a", "mem_z").unwrap();
        assert!(s.get_memory("mem_a").unwrap().is_none());
        assert!(s.get_memory("mem_z").unwrap().is_some());
        assert_eq!(s.harvest_get("o").unwrap().unwrap().memory_id, "mem_z");
        s.upsert_memory(&mem("mem_q", "Q")).unwrap();
        s.rewrite_memory_id("mem_q", "mem_z").unwrap(); // target exists → old row dropped
        assert!(s.get_memory("mem_q").unwrap().is_none());
    }

    #[test]
    fn skill_roundtrip() {
        let s = Store::open_in_memory().unwrap();
        s.put_skill(&skill("demo", 1)).unwrap();
        s.put_skill(&skill("demo", 2)).unwrap();
        assert_eq!(s.get_skill(Scope::Global, "", "demo").unwrap().unwrap().version, 2);
        let mut d = skill("gone", 1);
        d.deleted = true;
        s.put_skill(&d).unwrap();
        assert_eq!(s.all_skills().unwrap().len(), 2);
        assert_eq!(s.live_skills().unwrap().len(), 1);
    }

    #[test]
    fn pending_queue_is_fifo_and_ackable() {
        let s = Store::open_in_memory().unwrap();
        s.enqueue(&PendingOp::AddMemory { memory: mem("mem_a", "A") }).unwrap();
        s.enqueue(&PendingOp::DeleteMemory { id: "mem_a".into() }).unwrap();
        s.enqueue(&PendingOp::PurgeSkill { scope: Scope::Global, project: String::new(), name: "demo".into(), versions: None }).unwrap();
        let p = s.pending().unwrap();
        assert_eq!(p.len(), 3);
        assert!(p[0].1.is_memory() && p[1].1.is_memory() && !p[2].1.is_memory());
        s.ack(p[0].0).unwrap();
        assert_eq!(s.pending_count().unwrap(), 2);
    }

    #[test]
    fn cursor_keys_are_per_account() {
        assert_eq!(memory_cursor_key("astation-a"), "memory_cursor:astation-a");
        assert_eq!(skill_cursor_key("astation-a"), "skill_cursor:astation-a");
        let s = Store::open_in_memory().unwrap();
        s.set_state(&memory_cursor_key("astation-a"), 42).unwrap();
        s.set_state(MEMORY_CURSOR, 99).unwrap(); // legacy, unkeyed
        assert_eq!(s.get_state(&memory_cursor_key("astation-b")).unwrap(), 0);
        assert_eq!(s.get_state(&memory_cursor_key("astation-a")).unwrap(), 42);
    }

    #[test]
    fn state_defaults_to_zero() {
        let s = Store::open_in_memory().unwrap();
        assert_eq!(s.get_state(MEMORY_CURSOR).unwrap(), 0);
        s.set_state(MEMORY_CURSOR, 42).unwrap();
        s.set_state(MEMORY_CURSOR, 43).unwrap();
        assert_eq!(s.get_state(MEMORY_CURSOR).unwrap(), 43);
    }

    #[test]
    fn harvest_map_prefix_and_counts() {
        let s = Store::open_in_memory().unwrap();
        for (o, st) in [("m:/d/a.md", HarvestStatus::Synced), ("m:/d/b.md", HarvestStatus::HeldBack), ("m:/d2/c.md", HarvestStatus::Synced)] {
            s.harvest_put(&HarvestEntry { origin: o.into(), memory_id: "x".into(), content_hash: "h".into(), status: st }).unwrap();
        }
        assert_eq!(s.harvest_with_prefix("m:/d/").unwrap().len(), 2);
        assert_eq!(s.held_back_count().unwrap(), 1);
        let linked: Vec<String> = s.harvest_entries_for_memory("x").unwrap().into_iter().map(|e| e.origin).collect();
        assert_eq!(linked, vec!["m:/d/a.md", "m:/d/b.md", "m:/d2/c.md"]);
        assert!(s.harvest_entries_for_memory("nope").unwrap().is_empty());
        s.harvest_remove("m:/d/a.md").unwrap();
        assert!(s.harvest_get("m:/d/a.md").unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn db_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let td = tempfile::tempdir().unwrap();
        let p = td.path().join("sub/knowledge.db");
        Store::open(&p).unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn db_file_created_private_even_with_permissive_umask() {
        use std::os::unix::fs::PermissionsExt;

        // Fresh path: the file doesn't exist yet, so open() must create it
        // 0600 from the start (no window at a default/permissive umask).
        let td = tempfile::tempdir().unwrap();
        let fresh = td.path().join("fresh/knowledge.db");
        Store::open(&fresh).unwrap();
        assert_eq!(std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777, 0o600);

        // Pre-existing file created with a permissive mode (simulating an
        // older atem version or a permissive umask): open() must still
        // tighten it to 0600.
        let td2 = tempfile::tempdir().unwrap();
        let existing = td2.path().join("knowledge.db");
        std::fs::write(&existing, b"").unwrap();
        std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o644)).unwrap();
        Store::open(&existing).unwrap();
        assert_eq!(std::fs::metadata(&existing).unwrap().permissions().mode() & 0o777, 0o600);
    }
}
