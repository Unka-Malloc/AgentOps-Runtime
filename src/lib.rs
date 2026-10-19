//! aor — AgentOps-Runtime core contracts.
//!
//! The runtime owns gate orchestration logic; host adapters own execution
//! strength. Every gate is its own crate (`aor-<gate>`) depending on `aor`
//! and nothing else. This crate holds only gate-neutral machinery: the
//! gate contract, event/finding/record types, the `Store` and
//! `ArtifactSink` traits, the `Threshold` primitive (collect to a
//! threshold, then emit — never block), and in-memory implementations for
//! gate tests and dry runs.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Error(pub String);

impl Error {
    pub fn msg(m: impl Into<String>) -> Self {
        Self(m.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Error {}

/// Unix epoch milliseconds — the runtime's single timestamp unit.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Execution channel a gate profile targets. Strength is decided by the
/// host adapter that runs the profile, not by the gate definition.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Enforcement {
    /// Managed-dispatch channel. The host executes the dispatch itself, so a
    /// profile here may fail closed.
    ManagedDispatch,
    /// Lifecycle-hook observation channel. Observation, collection and
    /// threshold-triggered events only; never blocks native host behavior.
    HookObserve,
    /// outbound boundary. Fail-closed checker entry for
    /// irreversible operations (push / PR / release).
    OutboundBoundary,
}

/// Implementation state of a declared profile. Partial support is declared
/// as `Incomplete`; a profile is never silently dropped.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProfileState {
    Implemented,
    Incomplete,
}

/// One enforcement profile a gate declares.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Profile {
    pub enforcement: Enforcement,
    pub state: ProfileState,
}

impl Profile {
    pub const fn new(enforcement: Enforcement, state: ProfileState) -> Self {
        Self { enforcement, state }
    }
}

/// Static identity and declared coverage of a gate. Gate crates expose
/// theirs as a `pub const DESCRIPTOR` plus `pub fn descriptor()`.
#[derive(Clone, Debug)]
pub struct GateDescriptor {
    /// Stable gate id, e.g. `"handoff"`. Matches the crate suffix.
    pub name: &'static str,
    pub summary: &'static str,
    /// Every enforcement channel the gate applies to. Empty is a bug:
    /// a gate with no channel does nothing anywhere.
    pub profiles: &'static [Profile],
}

/// What kind of lifecycle/tool moment an event represents.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EventKind {
    /// Before a sub-agent dispatch.
    Dispatch,
    /// Before context compaction or session handoff.
    Compact,
    /// Before a verification command runs.
    Verify,
    /// Before a delivery/task is marked closed.
    Close,
    /// Any other intercepted tool call.
    ToolCall,
    /// Periodic runtime sweep tick (not host-driven).
    Sweep,
}

/// Lifecycle or tool event delivered to observing gates. `detail` is
/// host-provided JSON; gates document the fields they read.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub kind: EventKind,
    #[serde(default)]
    pub detail: serde_json::Value,
    pub ts_ms: u64,
}

impl Event {
    pub fn new(kind: EventKind, detail: serde_json::Value) -> Self {
        Self {
            kind,
            detail,
            ts_ms: now_ms(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    Info,
    Warn,
    High,
}

/// A gate output. Gates emit findings; whether a finding blocks is the
/// host channel's decision, never the gate's.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub gate: &'static str,
    pub severity: Severity,
    pub message: String,
    /// Optional durable artifact backing this finding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<String>,
}

impl Finding {
    pub fn new(gate: &'static str, severity: Severity, message: impl Into<String>) -> Self {
        Self {
            gate,
            severity,
            message: message.into(),
            artifact: None,
        }
    }
}

/// The aggregated answer a host asks before it owns an action.
/// Gates only emit findings; `Verdict` folds them into one decision the
/// channel applies — `managed-dispatch` and `outbound-boundary` hosts
/// treat `Refuse` as fail-closed, `hook-observe` treats it as advisory.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    Allow,
    Warn,
    Refuse,
}

impl Verdict {
    /// Worst-severity fold: any `High` finding refuses, `Warn` warns.
    pub fn of(findings: &[Finding]) -> Self {
        findings
            .iter()
            .fold(Verdict::Allow, |v, f| match f.severity {
                Severity::High => Verdict::Refuse,
                Severity::Warn if v == Verdict::Allow => Verdict::Warn,
                _ => v,
            })
    }

    pub fn refused(&self) -> bool {
        matches!(self, Verdict::Refuse)
    }
}

/// Evidence record persisted by the runtime's stores. The shared schema
/// keeps every gate's output queryable by the same projections.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Record {
    /// 0 = unassigned (store fills it in).
    #[serde(default)]
    pub id: i64,
    pub ts_ms: u64,
    pub gate: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<Enforcement>,
    pub severity: Severity,
    /// Sanitized summary; secrets, tokens and private machine details are
    /// never recorded.
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<String>,
}

/// A tracked work item. `state` is free-form so host
/// adapters can carry their native vocabulary; gates document the values
/// they understand (`in_progress`, `blocked`, `done`, ...).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Todo {
    pub id: String,
    pub title: String,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    pub updated_ms: u64,
    #[serde(default)]
    pub detail: serde_json::Value,
}

/// Curated durable memory. Raw streams go to
/// `observations`/`records`; entries here passed a curation decision.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MemoryEntry {
    #[serde(default)]
    pub id: i64,
    /// rule | decision | preference | design | fact
    pub kind: String,
    pub title: String,
    pub body: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    pub created_ms: u64,
    pub updated_ms: u64,
}

/// The store contract every gate persists through. SQLite is the
/// production implementation (`aor-store`); `mem::MemStore` serves tests
/// and dry runs.
pub trait Store: Send + Sync {
    fn append_record(&self, r: &Record) -> Result<i64>;
    fn records(&self, gate: Option<&str>, limit: usize) -> Result<Vec<Record>>;

    /// Raw observation stream — uncurated, real-time.
    fn append_observation(&self, kind: &str, detail: &serde_json::Value, ts_ms: u64)
        -> Result<i64>;

    /// Threshold primitives: record a hit and count hits in a window.
    fn counter_hit(&self, key: &str, ts_ms: u64) -> Result<()>;
    fn counter_count(&self, key: &str, since_ms: u64) -> Result<u64>;

    fn upsert_todo(&self, t: &Todo) -> Result<()>;
    fn todos(&self, state: Option<&str>) -> Result<Vec<Todo>>;

    fn append_memory(&self, m: &MemoryEntry) -> Result<i64>;
    fn memory(&self, kind: Option<&str>, limit: usize) -> Result<Vec<MemoryEntry>>;
}

/// Durable artifact sink: handoff indexes, decision memos, evidence files.
/// Returns a stable artifact id (a path or digest) callers embed in
/// records and references.
pub trait ArtifactSink: Send + Sync {
    fn write(&self, name: &str, bytes: &[u8]) -> Result<String>;
    fn read(&self, artifact: &str) -> Result<Vec<u8>>;
}

/// Collect-to-threshold primitive: hits accumulate in `Store` counters;
/// when `limit` hits land inside `window_ms` and no firing happened within
/// `cooldown_ms`, `hit` returns `true` once (an event, not a block).
pub struct Threshold {
    pub limit: u64,
    pub window_ms: u64,
    pub cooldown_ms: u64,
}

impl Threshold {
    pub const fn new(limit: u64, window_ms: u64, cooldown_ms: u64) -> Self {
        Self {
            limit,
            window_ms,
            cooldown_ms,
        }
    }

    pub fn hit(&self, store: &dyn Store, key: &str, now_ms: u64) -> Result<bool> {
        store.counter_hit(key, now_ms)?;
        let window_start = now_ms.saturating_sub(self.window_ms);
        if store.counter_count(key, window_start)? < self.limit {
            return Ok(false);
        }
        let fired_key = format!("{key}:__fired");
        let cooldown_start = now_ms.saturating_sub(self.cooldown_ms);
        if store.counter_count(&fired_key, cooldown_start)? > 0 {
            return Ok(false);
        }
        store.counter_hit(&fired_key, now_ms)?;
        Ok(true)
    }
}

/// Services the runtime hands a gate during `observe`/`sweep`.
pub trait GateContext {
    fn store(&self) -> &dyn Store;
    fn artifacts(&self) -> &dyn ArtifactSink;
    /// Queue a record for the runtime to persist after the gate returns.
    fn emit(&mut self, record: Record);
}

/// The gate contract. Crates implement this over their `DESCRIPTOR`.
pub trait Gate {
    fn descriptor(&self) -> &'static GateDescriptor;

    /// Handle one observed event. Default: no-op.
    fn observe(&self, _event: &Event, _ctx: &mut dyn GateContext) -> Result<Vec<Finding>> {
        Ok(Vec::new())
    }

    /// Periodic sweep (stale-state harvest, reconciliation). Default: no-op.
    fn sweep(&self, _ctx: &mut dyn GateContext) -> Result<Vec<Finding>> {
        Ok(Vec::new())
    }
}

/// In-memory implementations for gate tests, dry runs and projections.
/// Not a production store — `aor-store` owns SQLite.
pub mod mem {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct State {
        records: Vec<Record>,
        observations: Vec<(u64, String, serde_json::Value)>,
        counters: Vec<(String, u64)>,
        todos: Vec<Todo>,
        memory: Vec<MemoryEntry>,
    }

    /// In-memory `Store`. Order of `records`/`memory` results is
    /// newest-first, matching `aor-store` semantics.
    #[derive(Default)]
    pub struct MemStore {
        state: Mutex<State>,
    }

    impl MemStore {
        pub fn new() -> Self {
            Self::default()
        }
    }

    impl Store for MemStore {
        fn append_record(&self, r: &Record) -> Result<i64> {
            let mut s = self.state.lock().map_err(|e| Error::msg(e.to_string()))?;
            let mut r = r.clone();
            r.id = s.records.len() as i64 + 1;
            s.records.push(r);
            Ok(s.records.len() as i64)
        }

        fn records(&self, gate: Option<&str>, limit: usize) -> Result<Vec<Record>> {
            let s = self.state.lock().map_err(|e| Error::msg(e.to_string()))?;
            Ok(s.records
                .iter()
                .rev()
                .filter(|r| gate.is_none_or(|g| r.gate == g))
                .take(limit)
                .cloned()
                .collect())
        }

        fn append_observation(
            &self,
            kind: &str,
            detail: &serde_json::Value,
            ts_ms: u64,
        ) -> Result<i64> {
            let mut s = self.state.lock().map_err(|e| Error::msg(e.to_string()))?;
            s.observations
                .push((ts_ms, kind.to_string(), detail.clone()));
            Ok(s.observations.len() as i64)
        }

        fn counter_hit(&self, key: &str, ts_ms: u64) -> Result<()> {
            let mut s = self.state.lock().map_err(|e| Error::msg(e.to_string()))?;
            s.counters.push((key.to_string(), ts_ms));
            Ok(())
        }

        fn counter_count(&self, key: &str, since_ms: u64) -> Result<u64> {
            let s = self.state.lock().map_err(|e| Error::msg(e.to_string()))?;
            Ok(s.counters
                .iter()
                .filter(|(k, ts)| k == key && *ts >= since_ms)
                .count() as u64)
        }

        fn upsert_todo(&self, t: &Todo) -> Result<()> {
            let mut s = self.state.lock().map_err(|e| Error::msg(e.to_string()))?;
            if let Some(existing) = s.todos.iter_mut().find(|x| x.id == t.id) {
                *existing = t.clone();
            } else {
                s.todos.push(t.clone());
            }
            Ok(())
        }

        fn todos(&self, state: Option<&str>) -> Result<Vec<Todo>> {
            let s = self.state.lock().map_err(|e| Error::msg(e.to_string()))?;
            Ok(s.todos
                .iter()
                .filter(|t| state.is_none_or(|st| t.state == st))
                .cloned()
                .collect())
        }

        fn append_memory(&self, m: &MemoryEntry) -> Result<i64> {
            let mut s = self.state.lock().map_err(|e| Error::msg(e.to_string()))?;
            let mut m = m.clone();
            m.id = s.memory.len() as i64 + 1;
            s.memory.push(m);
            Ok(s.memory.len() as i64)
        }

        fn memory(&self, kind: Option<&str>, limit: usize) -> Result<Vec<MemoryEntry>> {
            let s = self.state.lock().map_err(|e| Error::msg(e.to_string()))?;
            Ok(s.memory
                .iter()
                .rev()
                .filter(|m| kind.is_none_or(|k| m.kind == k))
                .take(limit)
                .cloned()
                .collect())
        }
    }

    /// In-memory `ArtifactSink` keyed by artifact id.
    #[derive(Default)]
    pub struct MemArtifacts {
        inner: Mutex<std::collections::HashMap<String, Vec<u8>>>,
    }

    impl MemArtifacts {
        pub fn new() -> Self {
            Self::default()
        }
    }

    impl ArtifactSink for MemArtifacts {
        fn write(&self, name: &str, bytes: &[u8]) -> Result<String> {
            let mut m = self.inner.lock().map_err(|e| Error::msg(e.to_string()))?;
            // Artifact id == the caller's name, matching FsArtifacts'
            // relative-path semantics: read() resolves the same string.
            let id = name.trim_start_matches('/').to_string();
            m.insert(id.clone(), bytes.to_vec());
            Ok(id)
        }

        fn read(&self, artifact: &str) -> Result<Vec<u8>> {
            let m = self.inner.lock().map_err(|e| Error::msg(e.to_string()))?;
            m.get(artifact)
                .cloned()
                .ok_or_else(|| Error::msg(format!("artifact not found: {artifact}")))
        }
    }

    /// Filesystem `ArtifactSink` rooted at a data directory (e.g.
    /// `~/.agentops/artifacts`). Artifact ids are relative paths.
    pub struct FsArtifacts {
        root: std::path::PathBuf,
    }

    impl FsArtifacts {
        pub fn new(root: impl Into<std::path::PathBuf>) -> Self {
            Self { root: root.into() }
        }
    }

    impl FsArtifacts {
        /// Resolve `name` inside `root`, refusing `..`, root and prefix
        /// components so an artifact id can never escape the sink.
        fn contained(&self, name: &str) -> Result<(std::path::PathBuf, String)> {
            use std::path::Component;
            let mut rel = std::path::PathBuf::new();
            for component in std::path::Path::new(name).components() {
                match component {
                    Component::Normal(seg) => rel.push(seg),
                    Component::CurDir => {}
                    _ => {
                        return Err(Error::msg(format!(
                            "artifact name escapes the sink root: {name}"
                        )))
                    }
                }
            }
            if rel.as_os_str().is_empty() {
                return Err(Error::msg("empty artifact name"));
            }
            let id = rel.to_string_lossy().to_string();
            Ok((self.root.join(&rel), id))
        }
    }

    impl ArtifactSink for FsArtifacts {
        fn write(&self, name: &str, bytes: &[u8]) -> Result<String> {
            let (path, id) = self.contained(name)?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| Error::msg(e.to_string()))?;
            }
            std::fs::write(&path, bytes).map_err(|e| Error::msg(e.to_string()))?;
            Ok(id)
        }

        fn read(&self, artifact: &str) -> Result<Vec<u8>> {
            let (path, _) = self.contained(artifact)?;
            std::fs::read(path).map_err(|e| Error::msg(e.to_string()))
        }
    }

    /// Ready-made `GateContext` for gate tests and dry runs: drains emitted
    /// records into `emitted` for assertions.
    pub struct TestContext<S = MemStore, A = MemArtifacts>
    where
        S: Store,
        A: ArtifactSink,
    {
        pub store: S,
        pub artifacts: A,
        pub emitted: Vec<Record>,
    }

    impl<S: Store, A: ArtifactSink> TestContext<S, A> {
        pub fn new(store: S, artifacts: A) -> Self {
            Self {
                store,
                artifacts,
                emitted: Vec::new(),
            }
        }
    }

    impl<S: Store, A: ArtifactSink> GateContext for TestContext<S, A> {
        fn store(&self) -> &dyn Store {
            &self.store
        }
        fn artifacts(&self) -> &dyn ArtifactSink {
            &self.artifacts
        }
        fn emit(&mut self, record: Record) {
            self.emitted.push(record);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mem::FsArtifacts;
    use super::ArtifactSink;

    #[test]
    fn fs_artifacts_refuses_escape_names() {
        let dir = std::env::temp_dir().join(format!("aor-fsart-{}", std::process::id()));
        let sink = FsArtifacts::new(&dir);
        for name in ["../evil", "/abs/evil", "a/../../b", "..", "/"] {
            assert!(sink.write(name, b"x").is_err(), "accepted {name}");
            assert!(sink.read(name).is_err(), "read {name}");
        }
        let id = sink.write("memo/ok.json", b"{}").unwrap();
        assert_eq!(id, "memo/ok.json");
        assert_eq!(sink.read(&id).unwrap(), b"{}");
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[cfg(test)]
mod verdict_tests {
    use super::{Finding, Severity, Verdict};

    #[test]
    fn verdict_folds_worst_severity() {
        let f = |s: Severity| Finding::new("g", s, "m");
        assert_eq!(Verdict::of(&[]), Verdict::Allow);
        assert_eq!(Verdict::of(&[f(Severity::Info)]), Verdict::Allow);
        assert_eq!(
            Verdict::of(&[f(Severity::Warn), f(Severity::Info)]),
            Verdict::Warn
        );
        assert_eq!(
            Verdict::of(&[f(Severity::Warn), f(Severity::High)]),
            Verdict::Refuse
        );
        assert!(Verdict::Refuse.refused());
        assert!(!Verdict::Warn.refused());
    }
}
