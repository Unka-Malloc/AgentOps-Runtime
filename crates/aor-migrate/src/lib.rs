//! aor-migrate — import and parity tooling for AgentOps-Runtime.
//!
//! One-time absorption of external ledgers into the runtime's stores:
//! SQLite tables land in the raw observation stream, markdown vaults and
//! JSONL memory inboxes land in curated memory. Every importer is
//! read-only on its source: source data is never modified or deleted.
//! Per-item failures are counted and noted in the `ImportReport`; only
//! unusable sources (missing file/table, non-directory vault) are errors.

use aor::{now_ms, Error, MemoryEntry, Result, Store};
use rusqlite::{types::ValueRef, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

/// Outcome of one import run. `skipped` counts items the importer saw
/// but did not absorb (malformed lines, empty files, unrepresentable
/// values); `notes` explains each skip.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ImportReport {
    /// Identity of the absorbed source (path, or path + table).
    pub source: String,
    /// Items successfully written to the store.
    pub imported: u64,
    /// Items seen but not imported. Each skip should leave a note.
    pub skipped: u64,
    /// Human-readable per-skip and per-source remarks.
    pub notes: Vec<String>,
}

impl ImportReport {
    /// True when nothing was skipped — every item in the source landed.
    pub fn is_clean(&self) -> bool {
        self.skipped == 0
    }
}

/// Expected-vs-actual count for one imported item kind.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ParityReport {
    /// The item under comparison (e.g. a memory kind).
    pub item: String,
    /// Count recorded in the source system.
    pub expected: u64,
    /// Count observed in the runtime store.
    pub actual: u64,
}

/// True when every report's `actual` equals its `expected`.
pub fn all_match(reports: &[ParityReport]) -> bool {
    reports.iter().all(|r| r.expected == r.actual)
}

/// Columns consulted for a row timestamp, in priority order.
const TS_COLUMNS: &[&str] = &["ts_ms", "ts", "created"];

/// Import every row of a SQLite table into the observation stream.
///
/// Opens `src` read-only (`SQLITE_OPEN_READ_ONLY` — the source is never
/// created or modified) and runs `SELECT rowid, *`. Each row becomes one
/// `store.append_observation(kind, row_json, ts)` call where `row_json`
/// is the row as a JSON object keyed by column name: NULL → `null`,
/// INTEGER → i64, REAL → f64, TEXT → string, BLOB → the row is skipped
/// with a note. `ts` comes from a `ts_ms`/`ts`/`created` column when
/// present and numeric, else `now_ms()`.
///
/// A missing table (or an unopenable file) is `Err`: importing from
/// nothing is a bug, not a skip.
pub fn import_sqlite_table(
    src: &Path,
    table: &str,
    kind: &str,
    store: &dyn Store,
) -> Result<ImportReport> {
    let mut report = ImportReport {
        source: format!("{}:{table}", src.display()),
        ..ImportReport::default()
    };
    let conn = Connection::open_with_flags(src, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| Error::msg(format!("open {}: {e}", src.display())))?;
    let sql = format!("SELECT rowid, * FROM \"{}\"", table.replace('"', "\"\""));
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| Error::msg(format!("prepare `{sql}` on {}: {e}", src.display())))?;
    let col_names: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
    let col_count = stmt.column_count();
    let ts_idx: Vec<usize> = col_names
        .iter()
        .enumerate()
        .filter(|(_, n)| TS_COLUMNS.contains(&n.as_str()))
        .map(|(i, _)| i)
        .collect();

    let mut rows = stmt
        .query([])
        .map_err(|e| Error::msg(format!("query `{sql}`: {e}")))?;
    let mut row_idx: u64 = 0;
    while let Some(row) = rows.next().map_err(|e| Error::msg(e.to_string()))? {
        row_idx += 1;
        let mut obj = serde_json::Map::with_capacity(col_count);
        let mut ts: Option<u64> = None;
        let mut skip: Option<String> = None;
        for (i, name) in col_names.iter().enumerate() {
            let v = row
                .get_ref(i)
                .map_err(|e| Error::msg(format!("row {row_idx} column {name}: {e}")))?;
            if ts.is_none() && ts_idx.contains(&i) {
                ts = value_as_ms(&v);
            }
            match v {
                ValueRef::Null => {
                    obj.insert(name.clone(), serde_json::Value::Null);
                }
                ValueRef::Integer(n) => {
                    obj.insert(name.clone(), n.into());
                }
                ValueRef::Real(f) => {
                    let v = serde_json::Number::from_f64(f)
                        .map_or(serde_json::Value::Null, serde_json::Value::Number);
                    obj.insert(name.clone(), v);
                }
                ValueRef::Text(bytes) => match std::str::from_utf8(bytes) {
                    Ok(s) => {
                        obj.insert(name.clone(), s.into());
                    }
                    Err(_) => {
                        skip = Some(format!("column '{name}' holds invalid UTF-8"));
                        break;
                    }
                },
                ValueRef::Blob(_) => {
                    skip = Some(format!("column '{name}' holds a BLOB"));
                    break;
                }
            }
        }
        if let Some(reason) = skip {
            report.skipped += 1;
            report
                .notes
                .push(format!("row {row_idx}: {reason}; row skipped"));
            continue;
        }
        let ts_ms = ts.unwrap_or_else(now_ms);
        store.append_observation(kind, &serde_json::Value::Object(obj), ts_ms)?;
        report.imported += 1;
    }
    Ok(report)
}

/// Interpret a column value as an epoch-milliseconds timestamp.
fn value_as_ms(v: &ValueRef<'_>) -> Option<u64> {
    match v {
        ValueRef::Integer(n) if *n >= 0 => Some(*n as u64),
        ValueRef::Real(f) if *f >= 0.0 => Some(*f as u64),
        ValueRef::Text(t) => std::str::from_utf8(t).ok()?.trim().parse::<u64>().ok(),
        _ => None,
    }
}

/// Parsed bits of a markdown file's optional YAML frontmatter.
#[derive(Default)]
struct Frontmatter {
    kind: Option<String>,
    tags: Vec<String>,
}

/// Naive frontmatter parse: a `---` block at the top of the file, `key:
/// value` lines only. Recognizes `kind: x` and `tags: [a,b]` (or a bare
/// comma list). Everything else is ignored.
fn parse_frontmatter(text: &str) -> Frontmatter {
    let mut fm = Frontmatter::default();
    let mut lines = text.lines();
    if lines.next().map(str::trim) != Some("---") {
        return fm;
    }
    for line in lines {
        let trimmed = line.trim();
        if trimmed == "---" || trimmed == "..." {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            let value = value.trim();
            match key.trim() {
                "kind" if !value.is_empty() => fm.kind = Some(value.to_string()),
                "tags" => {
                    let inner = value.trim_start_matches('[').trim_end_matches(']');
                    fm.tags = inner
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .collect();
                }
                _ => {}
            }
        }
    }
    fm
}

/// File modification time in epoch ms; falls back to `now_ms()` when the
/// platform can't supply one (import must not fail on metadata alone).
fn file_mtime_ms(path: &Path) -> u64 {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
        .unwrap_or_else(now_ms)
}

/// Collect `*.md` files under `dir` recursively. Dot-prefixed entries
/// (hidden dirs and files) are skipped; symlinks are not followed.
fn collect_markdown(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let entries = std::fs::read_dir(dir)
        .map_err(|e| Error::msg(format!("read dir {}: {e}", dir.display())))?;
    for entry in entries {
        let entry = entry.map_err(|e| Error::msg(e.to_string()))?;
        if entry.file_name().to_string_lossy().starts_with('.') {
            continue;
        }
        let path = entry.path();
        let file_type = entry.file_type().map_err(|e| Error::msg(e.to_string()))?;
        if file_type.is_dir() {
            collect_markdown(&path, out)?;
        } else if file_type.is_file() && path.extension().is_some_and(|ext| ext == "md") {
            out.push(path);
        }
    }
    Ok(())
}

/// Import a markdown vault into curated memory.
///
/// Every `*.md` file under `dir` (recursive, dot-entries skipped)
/// becomes one `MemoryEntry`: `kind` from frontmatter `kind:` or
/// `"fact"`, `title` from the file stem, `body` the full file text,
/// `tags` from frontmatter `tags:`, `source` the path relative to `dir`,
/// `created_ms`/`updated_ms` the file mtime. Empty files are skipped.
/// A `dir` that isn't a directory is `Err`.
pub fn import_vault(dir: &Path, store: &dyn Store) -> Result<ImportReport> {
    if !dir.is_dir() {
        return Err(Error::msg(format!(
            "vault is not a directory: {}",
            dir.display()
        )));
    }
    let mut report = ImportReport {
        source: dir.display().to_string(),
        ..ImportReport::default()
    };
    let mut files = Vec::new();
    collect_markdown(dir, &mut files)?;
    files.sort();

    for path in files {
        let rel = path
            .strip_prefix(dir)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                report.skipped += 1;
                report.notes.push(format!("{rel}: unreadable: {e}"));
                continue;
            }
        };
        if text.trim().is_empty() {
            report.skipped += 1;
            report.notes.push(format!("{rel}: empty file"));
            continue;
        }
        let fm = parse_frontmatter(&text);
        let mtime = file_mtime_ms(&path);
        let entry = MemoryEntry {
            id: 0,
            kind: fm.kind.unwrap_or_else(|| "fact".to_string()),
            title: path
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| rel.clone()),
            body: text,
            tags: fm.tags,
            source: Some(rel),
            created_ms: mtime,
            updated_ms: mtime,
        };
        store.append_memory(&entry)?;
        report.imported += 1;
    }
    Ok(report)
}

/// Import an agent-memory JSONL inbox into curated memory.
///
/// Each non-empty line is one JSON object `{kind, title, body, tags?,
/// source?, created_ms?, updated_ms?, ...}`; `{"noop": true}` lines are
/// skipped. Lines missing `kind`/`title`/`body` and malformed JSON are
/// skipped with a line-numbered note — one bad line never aborts the
/// file. An unreadable `file` is `Err`.
pub fn import_jsonl_inbox(file: &Path, store: &dyn Store) -> Result<ImportReport> {
    let text = std::fs::read_to_string(file)
        .map_err(|e| Error::msg(format!("read {}: {e}", file.display())))?;
    let mut report = ImportReport {
        source: file.display().to_string(),
        ..ImportReport::default()
    };
    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                report.skipped += 1;
                report
                    .notes
                    .push(format!("line {line_no}: malformed JSON: {e}"));
                continue;
            }
        };
        if v.get("noop").and_then(serde_json::Value::as_bool) == Some(true) {
            report.skipped += 1;
            continue;
        }
        let (kind, title, body) = (
            v.get("kind").and_then(serde_json::Value::as_str),
            v.get("title").and_then(serde_json::Value::as_str),
            v.get("body").and_then(serde_json::Value::as_str),
        );
        let (Some(kind), Some(title), Some(body)) = (kind, title, body) else {
            report.skipped += 1;
            report
                .notes
                .push(format!("line {line_no}: missing kind/title/body"));
            continue;
        };
        let tags = v
            .get("tags")
            .and_then(serde_json::Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(serde_json::Value::as_str)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();
        let source = v
            .get("source")
            .and_then(serde_json::Value::as_str)
            .map(String::from);
        let now = now_ms();
        let entry = MemoryEntry {
            id: 0,
            kind: kind.to_string(),
            title: title.to_string(),
            body: body.to_string(),
            tags,
            source,
            created_ms: v
                .get("created_ms")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(now),
            updated_ms: v
                .get("updated_ms")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(now),
        };
        store.append_memory(&entry)?;
        report.imported += 1;
    }
    Ok(report)
}

/// Compare expected counts against what the store actually holds.
///
/// For each `(kind, expected)` pair the actual count is
/// `store.memory(Some(kind), usize::MAX).len()`. A store error reports
/// `actual` as 0, surfacing as a mismatch rather than a panic.
pub fn parity(pairs: &[(&str, u64)], store: &dyn Store) -> Vec<ParityReport> {
    pairs
        .iter()
        .map(|(kind, expected)| ParityReport {
            item: (*kind).to_string(),
            expected: *expected,
            actual: store
                .memory(Some(kind), usize::MAX)
                .map(|v| v.len() as u64)
                .unwrap_or(0),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aor::mem::MemStore;
    use aor::{Record, Todo};
    use std::sync::Mutex;

    /// MemStore plus a spy on the observation stream (MemStore keeps
    /// observations private).
    struct SpyStore {
        inner: MemStore,
        observations: Mutex<Vec<(String, serde_json::Value, u64)>>,
    }

    impl SpyStore {
        fn new() -> Self {
            Self {
                inner: MemStore::new(),
                observations: Mutex::new(Vec::new()),
            }
        }

        fn observations(&self) -> std::sync::MutexGuard<'_, Vec<(String, serde_json::Value, u64)>> {
            self.observations.lock().unwrap()
        }
    }

    impl Store for SpyStore {
        fn append_record(&self, r: &Record) -> Result<i64> {
            self.inner.append_record(r)
        }
        fn records(&self, gate: Option<&str>, limit: usize) -> Result<Vec<Record>> {
            self.inner.records(gate, limit)
        }
        fn append_observation(
            &self,
            kind: &str,
            detail: &serde_json::Value,
            ts_ms: u64,
        ) -> Result<i64> {
            self.observations
                .lock()
                .unwrap()
                .push((kind.to_string(), detail.clone(), ts_ms));
            self.inner.append_observation(kind, detail, ts_ms)
        }
        fn counter_hit(&self, key: &str, ts_ms: u64) -> Result<()> {
            self.inner.counter_hit(key, ts_ms)
        }
        fn counter_count(&self, key: &str, since_ms: u64) -> Result<u64> {
            self.inner.counter_count(key, since_ms)
        }
        fn upsert_todo(&self, t: &Todo) -> Result<()> {
            self.inner.upsert_todo(t)
        }
        fn todos(&self, state: Option<&str>) -> Result<Vec<Todo>> {
            self.inner.todos(state)
        }
        fn append_memory(&self, m: &MemoryEntry) -> Result<i64> {
            self.inner.append_memory(m)
        }
        fn memory(&self, kind: Option<&str>, limit: usize) -> Result<Vec<MemoryEntry>> {
            self.inner.memory(kind, limit)
        }
    }

    fn fixture_db(dir: &tempfile::TempDir) -> PathBuf {
        let db = dir.path().join("ledger.db");
        let conn = Connection::open(&db).unwrap();
        conn.execute(
            "CREATE TABLE ledger (note TEXT, amount REAL, ts_ms INTEGER)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO ledger (note, amount, ts_ms) VALUES ('alpha', 1.5, 1000)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO ledger (note, amount, ts_ms) VALUES (NULL, 2.5, 2000)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO ledger (note, amount, ts_ms) VALUES ('gamma', NULL, NULL)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO ledger (note, amount, ts_ms) VALUES (x'0102', 0.0, 3000)",
            [],
        )
        .unwrap();
        db
    }

    #[test]
    fn sqlite_table_imports_rows_as_observations() {
        let dir = tempfile::tempdir().unwrap();
        let db = fixture_db(&dir);
        let store = SpyStore::new();

        let report = import_sqlite_table(&db, "ledger", "ledger-row", &store).unwrap();
        assert_eq!(report.imported, 3);
        assert_eq!(report.skipped, 1); // the BLOB row
        assert!(!report.is_clean());
        assert_eq!(report.notes.len(), 1);
        assert!(report.notes[0].contains("BLOB"));

        let obs = store.observations();
        assert_eq!(obs.len(), 3);
        let (kind, detail, ts) = &obs[0];
        assert_eq!(kind, "ledger-row");
        assert_eq!(*ts, 1000);
        assert_eq!(detail["rowid"], 1);
        assert_eq!(detail["note"], "alpha");
        assert_eq!(detail["amount"], 1.5);
        assert_eq!(detail["ts_ms"], 1000);
        // NULL column serializes as JSON null.
        assert_eq!(obs[1].1["note"], serde_json::Value::Null);
        // Row without a ts column value falls back to now_ms().
        assert!(obs[2].2 > 3000);
        assert_eq!(obs[2].1["note"], "gamma");
    }

    #[test]
    fn sqlite_missing_table_is_err() {
        let dir = tempfile::tempdir().unwrap();
        let db = fixture_db(&dir);
        let store = SpyStore::new();
        assert!(import_sqlite_table(&db, "nope", "k", &store).is_err());
    }

    #[test]
    fn sqlite_missing_file_is_err() {
        let dir = tempfile::tempdir().unwrap();
        let store = SpyStore::new();
        let missing = dir.path().join("gone.db");
        assert!(import_sqlite_table(&missing, "ledger", "k", &store).is_err());
        // Read-only open must not create the file.
        assert!(!missing.exists());
    }

    #[test]
    fn vault_imports_markdown_as_memory() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault");
        std::fs::create_dir_all(vault.join("sub")).unwrap();
        std::fs::create_dir_all(vault.join(".hidden")).unwrap();
        std::fs::write(
            vault.join("sub").join("one.md"),
            "---\nkind: decision\ntags: [alpha, beta]\n---\nchose sqlite\n",
        )
        .unwrap();
        std::fs::write(vault.join("two.md"), "plain body\n").unwrap();
        std::fs::write(vault.join("empty.md"), "").unwrap();
        std::fs::write(vault.join("data.txt"), "not markdown").unwrap();
        std::fs::write(vault.join(".hidden").join("secret.md"), "hidden").unwrap();

        let store = SpyStore::new();
        let report = import_vault(&vault, &store).unwrap();
        assert_eq!(report.imported, 2);
        assert_eq!(report.skipped, 1); // empty.md
        assert!(report.notes[0].contains("empty"));

        let mem = store.memory(None, usize::MAX).unwrap();
        assert_eq!(mem.len(), 2);
        // Newest-first: two.md was appended after sub/one.md.
        let two = &mem[0];
        assert_eq!(two.kind, "fact");
        assert_eq!(two.title, "two");
        assert_eq!(two.body, "plain body\n");
        assert_eq!(two.source.as_deref(), Some("two.md"));
        assert!(two.tags.is_empty());
        assert!(two.created_ms > 0);

        let one = &mem[1];
        assert_eq!(one.kind, "decision");
        assert_eq!(one.title, "one");
        assert_eq!(one.tags, vec!["alpha", "beta"]);
        assert_eq!(one.source.as_deref(), Some("sub/one.md"));
        assert!(one.body.contains("chose sqlite"));
    }

    #[test]
    fn vault_non_directory_is_err() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("afile");
        std::fs::write(&file, "x").unwrap();
        let store = SpyStore::new();
        assert!(import_vault(&file, &store).is_err());
        assert!(import_vault(&dir.path().join("missing"), &store).is_err());
    }

    #[test]
    fn jsonl_inbox_imports_valid_skips_rest() {
        let dir = tempfile::tempdir().unwrap();
        let inbox = dir.path().join("inbox.jsonl");
        std::fs::write(
            &inbox,
            concat!(
                "{\"kind\":\"fact\",\"title\":\"t1\",\"body\":\"b1\",\"tags\":[\"x\"],\"source\":\"s\",\"created_ms\":7,\"updated_ms\":9}\n",
                "{\"noop\":true}\n",
                "\n",
                "{\"kind\":\"decision\",\"title\":\"t2\",\"body\":\"b2\"}\n",
                "not json at all\n",
                "{\"kind\":\"fact\"}\n"
            ),
        )
        .unwrap();

        let store = SpyStore::new();
        let report = import_jsonl_inbox(&inbox, &store).unwrap();
        assert_eq!(report.imported, 2);
        assert_eq!(report.skipped, 3); // noop, malformed, missing fields
        assert!(!report.is_clean());
        assert!(report.notes.iter().any(|n| n.contains("line 5")));
        assert!(report.notes.iter().any(|n| n.contains("line 6")));

        let mem = store.memory(None, usize::MAX).unwrap();
        assert_eq!(mem.len(), 2);
        let t2 = &mem[0];
        assert_eq!(t2.kind, "decision");
        assert_eq!(t2.title, "t2");
        assert!(t2.tags.is_empty());
        assert!(t2.source.is_none());
        let t1 = &mem[1];
        assert_eq!(t1.kind, "fact");
        assert_eq!(t1.tags, vec!["x"]);
        assert_eq!(t1.source.as_deref(), Some("s"));
        assert_eq!(t1.created_ms, 7);
        assert_eq!(t1.updated_ms, 9);
    }

    #[test]
    fn jsonl_missing_file_is_err() {
        let dir = tempfile::tempdir().unwrap();
        let store = SpyStore::new();
        assert!(import_jsonl_inbox(&dir.path().join("gone.jsonl"), &store).is_err());
    }

    #[test]
    fn parity_reports_match_and_mismatch() {
        let store = SpyStore::new();
        for (kind, title) in [("fact", "f1"), ("fact", "f2"), ("rule", "r1")] {
            store
                .append_memory(&MemoryEntry {
                    id: 0,
                    kind: kind.to_string(),
                    title: title.to_string(),
                    body: "b".to_string(),
                    tags: vec![],
                    source: None,
                    created_ms: 1,
                    updated_ms: 1,
                })
                .unwrap();
        }

        let reports = parity(&[("fact", 2), ("rule", 1)], &store);
        assert!(all_match(&reports));
        assert_eq!(reports[0].item, "fact");
        assert_eq!(reports[0].expected, 2);
        assert_eq!(reports[0].actual, 2);

        let reports = parity(&[("fact", 2), ("rule", 3), ("decision", 1)], &store);
        assert!(!all_match(&reports));
        assert_eq!(reports[1].expected, 3);
        assert_eq!(reports[1].actual, 1);
        assert_eq!(reports[2].actual, 0);

        assert!(all_match(&[]));
    }
}
