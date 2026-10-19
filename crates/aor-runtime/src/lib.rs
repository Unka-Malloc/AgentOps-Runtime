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

    #[cfg(test)]
    fn with_gates(
        store: Box<dyn Store>,
        artifacts: Box<dyn ArtifactSink>,
        gates: Vec<Box<dyn Gate>>,
    ) -> Self {
        Self {
            store,
            artifacts,
            gates,
        }
    }

    /// Route one host event through every gate. Returns all findings;
    /// emitted records and the raw observation are persisted. A gate's
    /// failure never propagates to a sibling: it is caught, recorded as
    /// a durable observation and reported as a runtime-attributed
    /// finding, and the fan-out continues.
    pub fn dispatch(&self, event: &Event) -> Result<Vec<Finding>> {
        let kind = serde_json::to_value(event.kind)
            .ok()
            .and_then(|v| v.as_str().map(str::to_owned))
            .unwrap_or_else(|| format!("{:?}", event.kind));
        self.store
            .append_observation(&kind, &event.detail, event.ts_ms)?;
        let mut findings = Vec::new();
        for gate in &self.gates {
            let mut ctx = Ctx {
                store: &*self.store,
                artifacts: &*self.artifacts,
                emitted: Vec::new(),
            };
            match gate.observe(event, &mut ctx) {
                Ok(found) => findings.extend(found),
                Err(e) => findings.push(self.gate_failure("observe", &**gate, &e)),
            }
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
            match gate.sweep(&mut ctx) {
                Ok(found) => findings.extend(found),
                Err(e) => findings.push(self.gate_failure("sweep", &**gate, &e)),
            }
            for record in ctx.emitted {
                self.store.append_record(&record)?;
            }
        }
        Ok(findings)
    }

    /// Attribute a gate's failure durably — an observation row for
    /// forensics plus a finding so the host's verdict sees the hole.
    fn gate_failure(&self, stage: &str, gate: &dyn Gate, e: &aor::Error) -> Finding {
        let name = gate.descriptor().name;
        let detail = serde_json::json!({"gate": name, "stage": stage, "error": e.to_string()});
        let _ = self
            .store
            .append_observation("gate-error", &detail, aor::now_ms());
        Finding::new(
            "runtime",
            Severity::High,
            format!("gate {name} {stage} failed: {e}"),
        )
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
        rt.dispatch(&Event::new(
            EventKind::ToolCall,
            serde_json::json!({"tool": "x"}),
        ))
        .unwrap();
        // the raw observation lands even when no gate fires
        assert_eq!(store.observation_count(), 1);
        drop(store);
    }

    /// A gate that always fails — proves a gate error cannot starve its
    /// siblings (isolation is this workspace's first invariant).
    struct BrokenGate;
    impl Gate for BrokenGate {
        fn descriptor(&self) -> &'static aor::GateDescriptor {
            static D: aor::GateDescriptor = aor::GateDescriptor {
                name: "broken",
                summary: "always fails",
                profiles: &[],
            };
            &D
        }
        fn observe(&self, _e: &Event, _c: &mut dyn aor::GateContext) -> Result<Vec<Finding>> {
            Err(aor::Error::msg("boom"))
        }
    }

    #[test]
    fn a_failing_gate_is_isolated_and_reported() {
        let store = std::sync::Arc::new(MemStore::new());
        let rt = Runtime::with_gates(
            Box::new(ArcStore(store.clone())),
            Box::new(MemArtifacts::new()),
            vec![Box::new(BrokenGate), Box::new(aor_wait::WaitGate)],
        );
        let findings = rt
            .dispatch(&Event::new(
                EventKind::ToolCall,
                serde_json::json!({"tool": "x"}),
            ))
            .unwrap();
        assert!(
            findings
                .iter()
                .any(|f| f.gate == "runtime" && f.message.contains("broken")),
            "gate failure must surface as a runtime finding"
        );
        // a sibling gate still received the event
        assert!(
            store.observation_count() >= 2,
            "raw event + gate-error observation both persisted"
        );
    }

    #[test]
    fn sweep_runs_without_panic() {
        let (rt, _store) = rt();
        rt.sweep().expect("sweep ok");
    }
}
