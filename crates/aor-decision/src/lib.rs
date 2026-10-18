//! aor-decision — Decision-Memo gate for AgentOps-Runtime.
//!
//! Decision-Memo: decision artifacts with stable id and digest; handoffs carry references, recipients read the artifact.
//!
//! # Detail contract
//!
//! `observe()` is event-kind agnostic — a memo reference can travel on
//! any lifecycle or tool event. It reads these `event.detail` fields:
//!
//! - `memo_id` (string): id of a [`DecisionMemo`] previously persisted
//!   via [`DecisionMemo::write`]. The gate reads `memo/<memo_id>.json`
//!   from the [`aor::ArtifactSink`]; a missing artifact warns.
//! - `memo_sha256` (string): sha256 hex the caller declares for the memo
//!   artifact bytes. The gate recomputes the digest over the stored
//!   bytes — a mismatch yields a `High` "content drifted" finding, a
//!   match yields `Info` plus an emitted record. A `memo_id` declared
//!   without `memo_sha256` cannot be verified and also rates `High`.
//! - `requires_memo` (bool): the host marks this decision context as
//!   memo-mandatory. `true` with no `memo_id` warns — the decision is
//!   travelling without its memo.
//!
//! Events carrying none of these fields are ignored. The gate emits
//! findings and records only; whether they block is the host channel's
//! decision.

use aor::{
    ArtifactSink, Enforcement, Event, Finding, Gate, GateContext, GateDescriptor, Profile,
    ProfileState, Record, Severity,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;

/// Declared coverage: memo verification and reporting run on both the
/// managed-dispatch channel and the hook-observe channel.
const PROFILES: &[Profile] = &[
    Profile::new(Enforcement::ManagedDispatch, ProfileState::Implemented),
    Profile::new(Enforcement::HookObserve, ProfileState::Implemented),
];

pub const DESCRIPTOR: GateDescriptor = GateDescriptor {
    name: "decision",
    summary: "Decision-Memo: decision artifacts with stable id and digest; handoffs carry references, recipients read the artifact.",
    profiles: PROFILES,
};

pub const fn descriptor() -> &'static GateDescriptor {
    &DESCRIPTOR
}

/// A decision memo — the durable artifact `memo_id` references point at.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DecisionMemo {
    /// Stable memo id; artifacts persist as `memo/<id>.json`.
    pub id: String,
    pub title: String,
    /// Why a decision was needed.
    pub context: String,
    /// Options that were on the table.
    pub options: Vec<String>,
    /// The option chosen.
    pub decision: String,
    /// Risks accepted with the choice.
    pub risks: Vec<String>,
}

impl DecisionMemo {
    /// Canonical compact JSON — field order is fixed by declaration, so
    /// this is the persisted and hashed form.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }

    /// sha256 hex of the canonical JSON — the digest handoffs declare
    /// as `memo_sha256`.
    pub fn digest(&self) -> aor::Result<String> {
        let json = self.to_json().map_err(|e| aor::Error::msg(e.to_string()))?;
        Ok(sha256_hex(json.as_bytes()))
    }

    /// Persist as `memo/<id>.json`; returns the sink's artifact id.
    pub fn write(&self, artifacts: &dyn ArtifactSink) -> aor::Result<String> {
        let json = self.to_json().map_err(|e| aor::Error::msg(e.to_string()))?;
        artifacts.write(&format!("memo/{}.json", self.id), json.as_bytes())
    }
}

/// Lowercase hex sha256 of raw artifact bytes — what `observe`
/// recomputes on read.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The Decision-Memo gate.
pub struct DecisionGate;

impl Gate for DecisionGate {
    fn descriptor(&self) -> &'static GateDescriptor {
        &DESCRIPTOR
    }

    fn observe(&self, event: &Event, ctx: &mut dyn GateContext) -> aor::Result<Vec<Finding>> {
        let detail = &event.detail;

        if let Some(memo_id) = detail.get("memo_id").and_then(|v| v.as_str()) {
            let name = format!("memo/{memo_id}.json");
            let bytes = match ctx.artifacts().read(&name) {
                Ok(bytes) => bytes,
                Err(_) => {
                    return Ok(vec![Finding::new(
                        "decision",
                        Severity::Warn,
                        format!("memo artifact not found: {name}"),
                    )]);
                }
            };
            let computed = sha256_hex(&bytes);
            return match detail.get("memo_sha256").and_then(|v| v.as_str()) {
                Some(declared) if declared.eq_ignore_ascii_case(&computed) => {
                    ctx.emit(Record {
                        id: 0,
                        ts_ms: event.ts_ms,
                        gate: "decision".into(),
                        channel: None,
                        severity: Severity::Info,
                        summary: format!("memo {memo_id} verified"),
                        artifact: Some(name.clone()),
                    });
                    let mut finding = Finding::new(
                        "decision",
                        Severity::Info,
                        format!("memo {memo_id} matches declared digest"),
                    );
                    finding.artifact = Some(name);
                    Ok(vec![finding])
                }
                Some(_) => {
                    let mut finding = Finding::new(
                        "decision",
                        Severity::High,
                        format!("memo content drifted from declared digest: {name}"),
                    );
                    finding.artifact = Some(name);
                    Ok(vec![finding])
                }
                None => {
                    let mut finding = Finding::new(
                        "decision",
                        Severity::High,
                        format!("memo digest not declared — cannot verify: {name}"),
                    );
                    finding.artifact = Some(name);
                    Ok(vec![finding])
                }
            };
        }

        if detail.get("requires_memo").and_then(|v| v.as_bool()) == Some(true) {
            return Ok(vec![Finding::new(
                "decision",
                Severity::Warn,
                "decision context lacks memo reference",
            )]);
        }

        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aor::mem::{MemStore, TestContext};
    use aor::{Error, EventKind};
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Name-keyed artifact sink: artifact id == write name, so the
    /// gate's `memo/<id>.json` reads resolve like `FsArtifacts` does.
    #[derive(Default)]
    struct NameArtifacts(Mutex<HashMap<String, Vec<u8>>>);

    impl ArtifactSink for NameArtifacts {
        fn write(&self, name: &str, bytes: &[u8]) -> aor::Result<String> {
            self.0
                .lock()
                .map_err(|e| Error::msg(e.to_string()))?
                .insert(name.to_string(), bytes.to_vec());
            Ok(name.to_string())
        }

        fn read(&self, artifact: &str) -> aor::Result<Vec<u8>> {
            self.0
                .lock()
                .map_err(|e| Error::msg(e.to_string()))?
                .get(artifact)
                .cloned()
                .ok_or_else(|| Error::msg(format!("artifact not found: {artifact}")))
        }
    }

    fn ctx() -> TestContext<MemStore, NameArtifacts> {
        TestContext::new(MemStore::new(), NameArtifacts::default())
    }

    fn memo() -> DecisionMemo {
        DecisionMemo {
            id: "m-1".into(),
            title: "use references".into(),
            context: "handoffs paraphrase".into(),
            options: vec!["references".into(), "paraphrase".into()],
            decision: "references".into(),
            risks: vec!["stale artifact".into()],
        }
    }

    #[test]
    fn drift_detected() {
        let mut ctx = ctx();
        memo().write(&ctx.artifacts).unwrap();
        let event = Event::new(
            EventKind::Dispatch,
            json!({"memo_id": "m-1", "memo_sha256": "00".repeat(32)}),
        );
        let findings = DecisionGate.observe(&event, &mut ctx).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].message.contains("drifted"));
        assert!(ctx.emitted.is_empty());
    }

    #[test]
    fn missing_artifact_warns() {
        let mut ctx = ctx();
        let event = Event::new(
            EventKind::Dispatch,
            json!({"memo_id": "m-404", "memo_sha256": "ab".repeat(32)}),
        );
        let findings = DecisionGate.observe(&event, &mut ctx).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warn);
        assert!(findings[0].message.contains("not found"));
        assert!(ctx.emitted.is_empty());
    }

    #[test]
    fn match_info_and_record() {
        let mut ctx = ctx();
        let memo = memo();
        let artifact = memo.write(&ctx.artifacts).unwrap();
        let digest = memo.digest().unwrap();
        let event = Event::new(
            EventKind::Close,
            json!({"memo_id": "m-1", "memo_sha256": digest}),
        );
        let findings = DecisionGate.observe(&event, &mut ctx).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(findings[0].artifact.as_deref(), Some(artifact.as_str()));

        assert_eq!(ctx.emitted.len(), 1);
        let record = &ctx.emitted[0];
        assert_eq!(record.gate, "decision");
        assert_eq!(record.severity, Severity::Info);
        assert_eq!(record.artifact.as_deref(), Some(artifact.as_str()));
        assert_eq!(record.ts_ms, event.ts_ms);
    }

    #[test]
    fn requires_memo_without_ref_warns() {
        let mut ctx = ctx();
        let event = Event::new(EventKind::Dispatch, json!({"requires_memo": true}));
        let findings = DecisionGate.observe(&event, &mut ctx).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warn);
        assert!(findings[0].message.contains("lacks memo reference"));
    }

    #[test]
    fn unrelated_event_ignored() {
        let mut ctx = ctx();
        for detail in [json!({}), json!({"requires_memo": false}), json!("other")] {
            let event = Event::new(EventKind::ToolCall, detail);
            let findings = DecisionGate.observe(&event, &mut ctx).unwrap();
            assert!(findings.is_empty());
        }
        assert!(ctx.emitted.is_empty());
    }

    #[test]
    fn profiles_declared_implemented() {
        for profile in DESCRIPTOR.profiles {
            assert_eq!(profile.state, ProfileState::Implemented);
        }
    }
}
