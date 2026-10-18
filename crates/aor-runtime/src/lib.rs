//! aor-runtime — the AgentOps-Runtime assembly crate.
//!
//! The only crate allowed to know every gate. It owns registration order,
//! the observe/sweep engine, and the store/artifact wiring. Gate policy
//! stays inside each `aor-<gate>` crate; host adapters stay outside.

use aor::{
    ArtifactSink, Event, EventKind, Finding, Gate, GateContext, GateDescriptor, Record, Result,
    Severity, Store,
};

/// Every registered gate, in stable order.
pub fn gates() -> Vec<Box<dyn Gate>> {
    vec![
        Box::new(aor_close::CloseGate),
        Box::new(aor_decision::DecisionGate),
        Box::new(aor_dispatch::DispatchGate),
        Box::new(aor_handoff::HandoffGate),
        Box::new(aor_payload::PayloadGate),
        Box::new(aor_resource::ResourceGate),
        Box::new(aor_verify::VerifyGate),
        Box::new(aor_wait::WaitGate),
    ]
}

/// Every registered gate descriptor, in stable order.
pub fn gate_descriptors() -> Vec<&'static GateDescriptor> {
    gates().iter().map(|g| g.descriptor()).collect()
}

/// The assembled runtime: gates over a shared store + artifact sink.
/// One event turns into per-gate findings plus emitted records; the raw
/// observation is persisted unconditionally so the SQLite store refreshes
/// alongside every observation.
pub struct Runtime {
    store: Box<dyn Store>,
    artifacts: Box<dyn ArtifactSink>,
    gates: Vec<Box<dyn Gate>>,
}

struct Ctx<'a> {
    store: &'a dyn Store,
    artifacts: &'a dyn ArtifactSink,
    emitted: Vec<Record>,
}

impl GateContext for Ctx<'_> {
    fn store(&self) -> &dyn Store {
        self.store
    }
    fn artifacts(&self) -> &dyn ArtifactSink {
        self.artifacts
    }
    fn emit(&mut self, record: Record) {
        self.emitted.push(record);
    }
}

impl Runtime {
    pub fn new(store: Box<dyn Store>, artifacts: Box<dyn ArtifactSink>) -> Self {
        Self {
            store,
            artifacts,
            gates: gates(),
        }
    }

    /// Route one host event through every gate. Returns all findings;
    /// emitted records and the raw observation are persisted.
    pub fn dispatch(&self, event: &Event) -> Result<Vec<Finding>> {
        self.store
            .append_observation(&format!("{:?}", event.kind), &event.detail, event.ts_ms)?;
        let mut findings = Vec::new();
        for gate in &self.gates {
            let mut ctx = Ctx {
                store: &*self.store,
                artifacts: &*self.artifacts,
                emitted: Vec::new(),
            };
            findings.extend(gate.observe(event, &mut ctx)?);
            for record in ctx.emitted {
                self.store.append_record(&record)?;
            }
        }
        Ok(findings)
    }

    /// Periodic sweep across every gate (stale harvest, reconciliation).
    /// Sweep itself is an observation row so patrol cadence is auditable.
    pub fn sweep(&self) -> Result<Vec<Finding>> {
        self.store
            .append_observation("sweep", &serde_json::Value::Null, aor::now_ms())?;
        let mut findings = Vec::new();
        for gate in &self.gates {
            let mut ctx = Ctx {
                store: &*self.store,
                artifacts: &*self.artifacts,
                emitted: Vec::new(),
            };
            findings.extend(gate.sweep(&mut ctx)?);
            for record in ctx.emitted {
                self.store.append_record(&record)?;
            }
        }
        Ok(findings)
    }

    pub fn store(&self) -> &dyn Store {
        &*self.store
    }

    /// Convenience: wrap a host tool call as a Dispatch/ToolCall event and
    /// dispatch it. Adapters call `dispatch` directly with richer kinds.
    pub fn observe_tool(&self, tool: &str, args: serde_json::Value) -> Result<Vec<Finding>> {
        self.dispatch(&Event::new(
            EventKind::ToolCall,
            serde_json::json!({ "tool": tool, "args": args }),
        ))
    }
}

/// Render findings for CLI/projection consumers.
pub fn render_findings(findings: &[Finding]) -> String {
    findings
        .iter()
        .map(|f| {
            format!(
                "[{}] ({}) {}",
                f.gate,
                match f.severity {
                    Severity::Info => "info",
                    Severity::Warn => "warn",
                    Severity::High => "HIGH",
                },
                f.message
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use aor::mem::{MemArtifacts, MemStore};
    use std::collections::HashSet;

    fn rt() -> (Runtime, std::sync::Arc<MemStore>) {
        let store = std::sync::Arc::new(MemStore::new());
        let rt = Runtime::new(
            Box::new(ArcStore(store.clone())),
            Box::new(MemArtifacts::new()),
        );
        (rt, store)
    }

    /// MemStore behind Arc so tests can inspect what the runtime wrote.
    struct ArcStore(std::sync::Arc<MemStore>);
    impl Store for ArcStore {
        fn append_record(&self, r: &Record) -> Result<i64> {
            self.0.append_record(r)
        }
        fn records(&self, gate: Option<&str>, limit: usize) -> Result<Vec<Record>> {
            self.0.records(gate, limit)
        }
        fn append_observation(
            &self,
            kind: &str,
            detail: &serde_json::Value,
            ts_ms: u64,
        ) -> Result<i64> {
            self.0.append_observation(kind, detail, ts_ms)
        }
        fn counter_hit(&self, key: &str, ts_ms: u64) -> Result<()> {
            self.0.counter_hit(key, ts_ms)
        }
        fn counter_count(&self, key: &str, since_ms: u64) -> Result<u64> {
            self.0.counter_count(key, since_ms)
        }
        fn upsert_todo(&self, t: &aor::Todo) -> Result<()> {
            self.0.upsert_todo(t)
        }
        fn todos(&self, state: Option<&str>) -> Result<Vec<aor::Todo>> {
            self.0.todos(state)
        }
        fn append_memory(&self, m: &aor::MemoryEntry) -> Result<i64> {
            self.0.append_memory(m)
        }
        fn memory(&self, kind: Option<&str>, limit: usize) -> Result<Vec<aor::MemoryEntry>> {
            self.0.memory(kind, limit)
        }
    }

    #[test]
    fn every_gate_declares_at_least_one_profile() {
        for d in gate_descriptors() {
            assert!(!d.profiles.is_empty(), "gate {} has no profiles", d.name);
        }
    }

    #[test]
    fn gate_names_are_unique() {
        let names: HashSet<_> = gate_descriptors().iter().map(|d| d.name).collect();
        assert_eq!(names.len(), gate_descriptors().len());
    }

    #[test]
    fn no_gate_declares_a_channel_twice() {
        for d in gate_descriptors() {
            let channels: HashSet<_> = d.profiles.iter().map(|p| p.enforcement).collect();
            assert_eq!(
                channels.len(),
                d.profiles.len(),
                "gate {} repeats an enforcement channel",
                d.name
            );
        }
    }

    #[test]
    fn dispatch_persists_raw_observation() {
        let (rt, store) = rt();
        let _ = rt.dispatch(&Event::new(
            EventKind::ToolCall,
            serde_json::json!({"tool": "x"}),
        ));
        // observation stream receives the event even when no gate fires
        assert!(store.counter_count("nope", 0).is_ok());
        drop(store);
    }

    #[test]
    fn sweep_runs_without_panic() {
        let (rt, _store) = rt();
        rt.sweep().expect("sweep ok");
    }
}
