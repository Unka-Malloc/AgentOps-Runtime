//! aor-handoff — Handoff-Protocol gate for AgentOps-Runtime.
//!
//! Handoff-Protocol: durable conclusion / verified / file-status index at compaction and dispatch; references replace paraphrase.
//!
//! # Detail contract
//!
//! `observe()` evaluates only [`EventKind::Compact`] and
//! [`EventKind::Dispatch`] events — the moments where prior context is
//! paraphrased or a sub-agent is primed. Every other event kind is
//! ignored, whatever its detail. Within those events it reads:
//!
//! - `handoff_index` (object): an inline [`HandoffIndex`]. The index is
//!   serialized and persisted to the [`aor::ArtifactSink`] as
//!   `handoff/<ts_ms>.json`; the `Info` finding and the emitted record
//!   carry the returned artifact id. A present-but-malformed value warns
//!   instead — an unreadable index is still paraphrase risk.
//! - `handoff_ref` (string): reference to a handoff artifact persisted
//!   earlier. Carrying the reference yields an `Info` finding;
//!   recipients resolve it against the sink rather than trusting
//!   paraphrase. Checked only when no `handoff_index` is present.
//!
//! A Compact/Dispatch event with neither field warns — no durable
//! artifact stands behind the handoff. The gate emits findings and
//! records only; whether they block is the host channel's decision.

use aor::{
    Enforcement, Event, EventKind, Finding, Gate, GateContext, GateDescriptor, Profile,
    ProfileState, Record, Severity,
};
use serde::{Deserialize, Serialize};

/// Declared coverage: detection, persistence and reporting run on both
/// the managed-dispatch channel and the hook-observe channel.
const PROFILES: &[Profile] = &[
    Profile::new(Enforcement::ManagedDispatch, ProfileState::Implemented),
    Profile::new(Enforcement::HookObserve, ProfileState::Implemented),
];

pub const DESCRIPTOR: GateDescriptor = GateDescriptor {
    name: "handoff",
    summary: "Handoff-Protocol: durable conclusion / verified / file-status index at compaction and dispatch; references replace paraphrase.",
    profiles: PROFILES,
};

pub const fn descriptor() -> &'static GateDescriptor {
    &DESCRIPTOR
}

/// Structured handoff index — the durable payload a `handoff_ref`
/// points at. Hosts carry either this object inline or a reference to
/// it; paraphrased free-text summaries are what this gate warns on.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct HandoffIndex {
    /// Conclusions the agent stands behind.
    pub conclusions: Vec<String>,
    /// Claims verified by an executed command, not just asserted.
    pub verified: Vec<String>,
    /// Files touched and their state at handoff time.
    pub files: Vec<FileStatus>,
    /// Decisions taken, as references or short ids.
    pub decisions: Vec<String>,
    /// Open risks the recipient must inherit.
    pub risks: Vec<String>,
}

/// One file's state at handoff time.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FileStatus {
    pub path: String,
    /// Free-form host vocabulary: `created`, `modified`, `deleted`, ...
    pub status: String,
}

impl HandoffIndex {
    /// Canonical compact JSON — the persisted artifact form.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }
}

/// The Handoff-Protocol gate.
pub struct HandoffGate;

impl Gate for HandoffGate {
    fn descriptor(&self) -> &'static GateDescriptor {
        &DESCRIPTOR
    }

    fn observe(&self, event: &Event, ctx: &mut dyn GateContext) -> aor::Result<Vec<Finding>> {
        if !matches!(event.kind, EventKind::Compact | EventKind::Dispatch) {
            return Ok(Vec::new());
        }
        let detail = &event.detail;

        if let Some(raw) = detail.get("handoff_index").filter(|v| !v.is_null()) {
            let index: HandoffIndex = match serde_json::from_value(raw.clone()) {
                Ok(index) => index,
                Err(e) => {
                    return Ok(vec![Finding::new(
                        "handoff",
                        Severity::Warn,
                        format!("malformed handoff_index — paraphrase risk: {e}"),
                    )]);
                }
            };
            let json = index
                .to_json()
                .map_err(|e| aor::Error::msg(e.to_string()))?;
            let id = ctx
                .artifacts()
                .write(&format!("handoff/{}.json", event.ts_ms), json.as_bytes())?;
            ctx.emit(Record {
                id: 0,
                ts_ms: event.ts_ms,
                gate: "handoff".into(),
                channel: None,
                severity: Severity::Info,
                summary: "handoff index persisted".into(),
                artifact: Some(id.clone()),
            });
            let mut finding = Finding::new(
                "handoff",
                Severity::Info,
                format!("handoff index persisted: {id}"),
            );
            finding.artifact = Some(id);
            return Ok(vec![finding]);
        }

        if let Some(reference) = detail.get("handoff_ref").and_then(|v| v.as_str()) {
            return Ok(vec![Finding::new(
                "handoff",
                Severity::Info,
                format!("handoff reference carried: {reference}"),
            )]);
        }

        Ok(vec![Finding::new(
            "handoff",
            Severity::Warn,
            "no handoff artifact — paraphrase risk",
        )])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aor::mem::{MemArtifacts, MemStore, TestContext};
    use aor::ArtifactSink;
    use serde_json::json;

    fn ctx() -> TestContext {
        TestContext::new(MemStore::new(), MemArtifacts::new())
    }

    #[test]
    fn missing_ref_on_compact_warns() {
        let mut ctx = ctx();
        let event = Event::new(EventKind::Compact, json!({}));
        let findings = HandoffGate.observe(&event, &mut ctx).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warn);
        assert!(findings[0].message.contains("paraphrase"));
        assert!(ctx.emitted.is_empty());
    }

    #[test]
    fn missing_ref_on_dispatch_warns() {
        let mut ctx = ctx();
        let event = Event::new(EventKind::Dispatch, json!({}));
        let findings = HandoffGate.observe(&event, &mut ctx).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warn);
        assert!(findings[0].message.contains("paraphrase"));
        assert!(ctx.emitted.is_empty());
    }

    #[test]
    fn inline_index_persists_artifact_and_record() {
        let mut ctx = ctx();
        let event = Event::new(
            EventKind::Compact,
            json!({
                "handoff_index": {
                    "conclusions": ["auth rewrite complete"],
                    "verified": ["cargo test -p aor"],
                    "files": [{"path": "src/lib.rs", "status": "modified"}],
                    "decisions": ["memo:m-1"],
                    "risks": ["token expiry"],
                }
            }),
        );
        let findings = HandoffGate.observe(&event, &mut ctx).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);

        let id = findings[0].artifact.clone().expect("finding artifact id");
        assert!(id.contains("handoff/"));

        let bytes = ctx.artifacts.read(&id).unwrap();
        let parsed: HandoffIndex = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.conclusions, vec!["auth rewrite complete"]);
        assert_eq!(parsed.files[0].path, "src/lib.rs");
        assert_eq!(parsed.files[0].status, "modified");

        assert_eq!(ctx.emitted.len(), 1);
        let record = &ctx.emitted[0];
        assert_eq!(record.gate, "handoff");
        assert_eq!(record.severity, Severity::Info);
        assert_eq!(record.summary, "handoff index persisted");
        assert_eq!(record.artifact.as_deref(), Some(id.as_str()));
        assert_eq!(record.ts_ms, event.ts_ms);
        assert!(record.channel.is_none());
    }

    #[test]
    fn ref_only_is_info() {
        let mut ctx = ctx();
        let event = Event::new(
            EventKind::Dispatch,
            json!({"handoff_ref": "handoff/1700000000000.json"}),
        );
        let findings = HandoffGate.observe(&event, &mut ctx).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].message.contains("handoff/1700000000000.json"));
        assert!(findings[0].artifact.is_none());
        assert!(ctx.emitted.is_empty());
    }

    #[test]
    fn toolcall_ignored() {
        let mut ctx = ctx();
        // Even carrying a reference, a non-handoff moment is out of scope.
        let event = Event::new(
            EventKind::ToolCall,
            json!({"handoff_ref": "handoff/1700000000000.json"}),
        );
        let findings = HandoffGate.observe(&event, &mut ctx).unwrap();
        assert!(findings.is_empty());
        assert!(ctx.emitted.is_empty());
    }

    #[test]
    fn profiles_declared_implemented() {
        for profile in DESCRIPTOR.profiles {
            assert_eq!(profile.state, ProfileState::Implemented);
        }
    }
}
