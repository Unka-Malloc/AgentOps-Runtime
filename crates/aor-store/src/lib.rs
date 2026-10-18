//! aor-store — production SQLite implementation of `aor::Store`.
//!
//! `SqliteStore` is the runtime's durable evidence store: gate records,
//! raw observations, threshold counters, tracked todos and curated memory
//! all persist to one SQLite database. Ordering matches
//! `aor::mem::MemStore`: `records` and `memory` return newest-first.
//!
//! This crate is shared machinery, not a gate — it declares no
//! `DESCRIPTOR` and implements no `Gate`.

use aor::{Enforcement, Error, MemoryEntry, Record, Severity, Store, Todo};
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

/// Current schema version. Bump and append a migration step on change.
const SCHEMA_VERSION: i64 = 1;

const MIGRATION_V1: &str = "
CREATE TABLE IF NOT EXISTS records(
    id INTEGER PRIMARY KEY,
    ts_ms INTEGER NOT NULL,
    gate TEXT NOT NULL,
    channel TEXT,
    severity TEXT NOT NULL,
    summary TEXT NOT NULL,
    artifact TEXT
);
CREATE INDEX IF NOT EXISTS idx_records_gate_ts ON records(gate, ts_ms);

CREATE TABLE IF NOT EXISTS observations(
    id INTEGER PRIMARY KEY,
    ts_ms INTEGER NOT NULL,
    kind TEXT NOT NULL,
    detail TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS counters(
    \"key\" TEXT NOT NULL,
    ts_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_counters_key_ts ON counters(\"key\", ts_ms);

CREATE TABLE IF NOT EXISTS todos(
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    state TEXT NOT NULL,
    owner TEXT,
    updated_ms INTEGER NOT NULL,
    detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_todos_state ON todos(state);

CREATE TABLE IF NOT EXISTS memory(
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    tags TEXT,
    source TEXT,
    created_ms INTEGER NOT NULL,
    updated_ms INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_memory_kind ON memory(kind);
";

fn err(e: impl std::fmt::Display) -> Error {
    Error::msg(e.to_string())
}

/// SQLite-backed `aor::Store`. Cheap to share: the connection lives
/// behind a `Mutex` (`rusqlite::Connection` is `Send` but not `Sync`),
/// so the store itself is `Send + Sync` as the `Store` trait requires.
pub struct SqliteStore {
    conn: Mutex<Connection>,
}

impl SqliteStore {
    /// Open (creating if needed) the database at `path` and run pending
    /// migrations. Parent directories are created. Use `":memory:"` for
    /// an ephemeral database.
    pub fn open(path: impl AsRef<Path>) -> aor::Result<SqliteStore> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(err)?;
            }
        }
        let mut conn = Connection::open(path).map_err(err)?;
        migrate(&mut conn)?;
        Ok(SqliteStore {
            conn: Mutex::new(conn),
        })
    }

    /// `$AGENTOPS_HOME/agentops.db`, or `~/.agentops/agentops.db` when
    /// `AGENTOPS_HOME` is unset.
    pub fn default_path() -> PathBuf {
        if let Some(home) = std::env::var_os("AGENTOPS_HOME") {
            return PathBuf::from(home).join("agentops.db");
        }
        home_dir().join(".agentops").join("agentops.db")
    }

    fn lock(&self) -> aor::Result<MutexGuard<'_, Connection>> {
        self.conn.lock().map_err(err)
    }
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn migrate(conn: &mut Connection) -> aor::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations(
            version INTEGER PRIMARY KEY,
            applied_ms INTEGER NOT NULL
        );",
    )
    .map_err(err)?;
    let version: i64 = conn
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .map_err(err)?;
    if version < 1 {
        let tx = conn.transaction().map_err(err)?;
        tx.execute_batch(MIGRATION_V1).map_err(err)?;
        tx.execute(
            "INSERT INTO schema_migrations(version, applied_ms) VALUES (1, ?1)",
            params![aor::now_ms() as i64],
        )
        .map_err(err)?;
        tx.commit().map_err(err)?;
    }
    conn.pragma_update(None, "user_version", SCHEMA_VERSION)
        .map_err(err)?;
    Ok(())
}

// Enums persist as their serde kebab-case text ("warn", "managed-dispatch").
fn severity_to(sev: &Severity) -> aor::Result<String> {
    match serde_json::to_value(sev).map_err(err)? {
        serde_json::Value::String(s) => Ok(s),
        _ => Err(Error::msg("severity did not serialize to a string")),
    }
}

fn severity_from(s: String) -> aor::Result<Severity> {
    serde_json::from_value(serde_json::Value::String(s)).map_err(err)
}

fn channel_to(ch: &Enforcement) -> aor::Result<String> {
    match serde_json::to_value(ch).map_err(err)? {
        serde_json::Value::String(s) => Ok(s),
        _ => Err(Error::msg("channel did not serialize to a string")),
    }
}

fn channel_from(s: String) -> aor::Result<Enforcement> {
    serde_json::from_value(serde_json::Value::String(s)).map_err(err)
}

impl Store for SqliteStore {
    fn append_record(&self, r: &Record) -> aor::Result<i64> {
        let conn = self.lock()?;
        let channel = r.channel.as_ref().map(channel_to).transpose()?;
        conn.execute(
            "INSERT INTO records(ts_ms, gate, channel, severity, summary, artifact)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                r.ts_ms as i64,
                r.gate,
                channel,
                severity_to(&r.severity)?,
                r.summary,
                r.artifact
            ],
        )
        .map_err(err)?;
        Ok(conn.last_insert_rowid())
    }

    fn records(&self, gate: Option<&str>, limit: usize) -> aor::Result<Vec<Record>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, ts_ms, gate, channel, severity, summary, artifact
                 FROM records
                 WHERE (?1 IS NULL OR gate = ?1)
                 ORDER BY id DESC
                 LIMIT ?2",
            )
            .map_err(err)?;
        let rows = stmt
            .query_map(params![gate, limit as i64], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<String>>(6)?,
                ))
            })
            .map_err(err)?;
        let mut out = Vec::new();
        for row in rows {
            let (id, ts_ms, gate, channel, severity, summary, artifact) = row.map_err(err)?;
            out.push(Record {
                id,
                ts_ms: ts_ms as u64,
                gate,
                channel: channel.map(channel_from).transpose()?,
                severity: severity_from(severity)?,
                summary,
                artifact,
            });
        }
        Ok(out)
    }

    fn append_observation(
        &self,
        kind: &str,
        detail: &serde_json::Value,
        ts_ms: u64,
    ) -> aor::Result<i64> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO observations(ts_ms, kind, detail) VALUES (?1, ?2, ?3)",
            params![
                ts_ms as i64,
                kind,
                serde_json::to_string(detail).map_err(err)?
            ],
        )
        .map_err(err)?;
        Ok(conn.last_insert_rowid())
    }

    fn counter_hit(&self, key: &str, ts_ms: u64) -> aor::Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO counters(\"key\", ts_ms) VALUES (?1, ?2)",
            params![key, ts_ms as i64],
        )
        .map_err(err)?;
        Ok(())
    }

    fn counter_count(&self, key: &str, since_ms: u64) -> aor::Result<u64> {
        let conn = self.lock()?;
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM counters WHERE \"key\" = ?1 AND ts_ms >= ?2",
                params![key, since_ms as i64],
                |row| row.get(0),
            )
            .map_err(err)?;
        Ok(n as u64)
    }

    fn upsert_todo(&self, t: &Todo) -> aor::Result<()> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO todos(id, title, state, owner, updated_ms, detail)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(id) DO UPDATE SET
                 title = excluded.title,
                 state = excluded.state,
                 owner = excluded.owner,
                 updated_ms = excluded.updated_ms,
                 detail = excluded.detail",
            params![
                t.id,
                t.title,
                t.state,
                t.owner,
                t.updated_ms as i64,
                serde_json::to_string(&t.detail).map_err(err)?
            ],
        )
        .map_err(err)?;
        Ok(())
    }

    fn todos(&self, state: Option<&str>) -> aor::Result<Vec<Todo>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, title, state, owner, updated_ms, detail
                 FROM todos
                 WHERE (?1 IS NULL OR state = ?1)
                 ORDER BY rowid",
            )
            .map_err(err)?;
        let rows = stmt
            .query_map(params![state], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, Option<String>>(5)?,
                ))
            })
            .map_err(err)?;
        let mut out = Vec::new();
        for row in rows {
            let (id, title, state, owner, updated_ms, detail) = row.map_err(err)?;
            out.push(Todo {
                id,
                title,
                state,
                owner,
                updated_ms: updated_ms as u64,
                detail: detail
                    .map(|s| serde_json::from_str(&s).unwrap_or(serde_json::Value::Null))
                    .unwrap_or(serde_json::Value::Null),
            });
        }
        Ok(out)
    }

    fn append_memory(&self, m: &MemoryEntry) -> aor::Result<i64> {
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO memory(kind, title, body, tags, source, created_ms, updated_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                m.kind,
                m.title,
                m.body,
                serde_json::to_string(&m.tags).map_err(err)?,
                m.source,
                m.created_ms as i64,
                m.updated_ms as i64
            ],
        )
        .map_err(err)?;
        Ok(conn.last_insert_rowid())
    }

    fn memory(&self, kind: Option<&str>, limit: usize) -> aor::Result<Vec<MemoryEntry>> {
        let conn = self.lock()?;
        let mut stmt = conn
            .prepare(
                "SELECT id, kind, title, body, tags, source, created_ms, updated_ms
                 FROM memory
                 WHERE (?1 IS NULL OR kind = ?1)
                 ORDER BY id DESC
                 LIMIT ?2",
            )
            .map_err(err)?;
        let rows = stmt
            .query_map(params![kind, limit as i64], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, Option<String>>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            })
            .map_err(err)?;
        let mut out = Vec::new();
        for row in rows {
            let (id, kind, title, body, tags, source, created_ms, updated_ms) = row.map_err(err)?;
            out.push(MemoryEntry {
                id,
                kind,
                title,
                body,
                tags: tags
                    .map(|s| serde_json::from_str(&s).unwrap_or_default())
                    .unwrap_or_default(),
                source,
                created_ms: created_ms as u64,
                updated_ms: updated_ms as u64,
            });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db_path() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agentops.db");
        (dir, path)
    }

    fn record(gate: &str, summary: &str, ts_ms: u64) -> Record {
        Record {
            id: 0,
            ts_ms,
            gate: gate.to_string(),
            channel: Some(Enforcement::ManagedDispatch),
            severity: Severity::Warn,
            summary: summary.to_string(),
            artifact: Some(format!("artifacts/{summary}.md")),
        }
    }

    #[test]
    fn open_creates_schema_and_roundtrips() {
        let (_dir, path) = db_path();
        let store = SqliteStore::open(&path).unwrap();

        // record
        let rid = store
            .append_record(&record("handoff", "first", 1_000))
            .unwrap();
        assert_eq!(rid, 1);
        let recs = store.records(None, 10).unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].id, rid);
        assert_eq!(recs[0].ts_ms, 1_000);
        assert_eq!(recs[0].gate, "handoff");
        assert_eq!(recs[0].channel, Some(Enforcement::ManagedDispatch));
        assert_eq!(recs[0].severity, Severity::Warn);
        assert_eq!(recs[0].summary, "first");
        assert_eq!(recs[0].artifact.as_deref(), Some("artifacts/first.md"));

        // observation (no trait query — verify the stored row directly)
        let oid = store
            .append_observation("tool-call", &serde_json::json!({"tool": "sh"}), 1_500)
            .unwrap();
        assert_eq!(oid, 1);
        {
            let conn = store.conn.lock().unwrap();
            let (kind, detail): (String, String) = conn
                .query_row(
                    "SELECT kind, detail FROM observations WHERE id = ?1",
                    params![oid],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!(kind, "tool-call");
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&detail).unwrap(),
                serde_json::json!({"tool": "sh"})
            );
        }

        // counter
        store.counter_hit("sweep", 2_000).unwrap();
        assert_eq!(store.counter_count("sweep", 0).unwrap(), 1);
        assert_eq!(store.counter_count("other", 0).unwrap(), 0);

        // todo
        let todo = Todo {
            id: "t-1".to_string(),
            title: "ship it".to_string(),
            state: "in_progress".to_string(),
            owner: Some("agent".to_string()),
            updated_ms: 3_000,
            detail: serde_json::json!({"note": "draft"}),
        };
        store.upsert_todo(&todo).unwrap();
        let todos = store.todos(None).unwrap();
        assert_eq!(todos.len(), 1);
        assert_eq!(todos[0].id, "t-1");
        assert_eq!(todos[0].title, "ship it");
        assert_eq!(todos[0].state, "in_progress");
        assert_eq!(todos[0].owner.as_deref(), Some("agent"));
        assert_eq!(todos[0].updated_ms, 3_000);
        assert_eq!(todos[0].detail, serde_json::json!({"note": "draft"}));

        // upsert replaces
        let mut done = todo.clone();
        done.state = "done".to_string();
        store.upsert_todo(&done).unwrap();
        assert_eq!(store.todos(None).unwrap().len(), 1);
        assert_eq!(store.todos(Some("done")).unwrap()[0].state, "done");

        // memory
        let m = MemoryEntry {
            id: 0,
            kind: "decision".to_string(),
            title: "sqlite store".to_string(),
            body: "single db file".to_string(),
            tags: vec!["store".to_string(), "sqlite".to_string()],
            source: Some("design".to_string()),
            created_ms: 4_000,
            updated_ms: 4_500,
        };
        let mid = store.append_memory(&m).unwrap();
        assert_eq!(mid, 1);
        let mem = store.memory(None, 10).unwrap();
        assert_eq!(mem.len(), 1);
        assert_eq!(mem[0].id, mid);
        assert_eq!(mem[0].kind, "decision");
        assert_eq!(mem[0].tags, vec!["store", "sqlite"]);
        assert_eq!(mem[0].source.as_deref(), Some("design"));
        assert_eq!(mem[0].created_ms, 4_000);
        assert_eq!(mem[0].updated_ms, 4_500);
    }

    #[test]
    fn records_newest_first_and_gate_filter() {
        let (_dir, path) = db_path();
        let store = SqliteStore::open(&path).unwrap();
        store.append_record(&record("a", "r1", 100)).unwrap();
        store.append_record(&record("b", "r2", 200)).unwrap();
        store.append_record(&record("a", "r3", 300)).unwrap();

        let all = store.records(None, 10).unwrap();
        assert_eq!(all.iter().map(|r| r.id).collect::<Vec<_>>(), vec![3, 2, 1]);

        let gate_a = store.records(Some("a"), 10).unwrap();
        assert_eq!(gate_a.iter().map(|r| r.id).collect::<Vec<_>>(), vec![3, 1]);
        assert!(gate_a.iter().all(|r| r.gate == "a"));

        let limited = store.records(None, 2).unwrap();
        assert_eq!(limited.iter().map(|r| r.id).collect::<Vec<_>>(), vec![3, 2]);

        assert!(store.records(Some("missing"), 10).unwrap().is_empty());
    }

    #[test]
    fn counter_window_excludes_older_hits() {
        let (_dir, path) = db_path();
        let store = SqliteStore::open(&path).unwrap();
        store.counter_hit("k", 100).unwrap();
        store.counter_hit("k", 200).unwrap();
        store.counter_hit("k", 300).unwrap();

        assert_eq!(store.counter_count("k", 0).unwrap(), 3);
        assert_eq!(store.counter_count("k", 200).unwrap(), 2);
        assert_eq!(store.counter_count("k", 301).unwrap(), 0);
        assert_eq!(store.counter_count("k", 250).unwrap(), 1);
    }

    #[test]
    fn migration_is_idempotent() {
        let (_dir, path) = db_path();
        let store = SqliteStore::open(&path).unwrap();
        store.append_record(&record("a", "persist", 1)).unwrap();
        drop(store);

        // Reopening the same file must not fail or duplicate schema.
        let store = SqliteStore::open(&path).unwrap();
        assert_eq!(store.records(None, 10).unwrap().len(), 1);

        let conn = store.conn.lock().unwrap();
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        let applied: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(applied, 1);
    }
}
