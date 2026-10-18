//! aor-dispatch — Dispatch-Gate gate for AgentOps-Runtime.
//!
//! Dispatch-Gate: dispatch contract with completion channel, observation window, exclusive write paths and acceptance criteria.
//!
//! ## Detail contract (`EventKind::Dispatch`)
//!
//! `event.detail` is host-provided JSON. A well-formed dispatch contract
//! declares all of:
//!
//! - `completion_channel` — non-empty string; the channel the dispatched
//!   agent reports completion on.
//! - `write_paths` — non-empty array of non-empty strings; the exclusive
//!   write paths owned by this dispatch.
//! - `acceptance` — non-empty string, or non-empty array of non-empty
//!   strings; the acceptance criteria the dispatch result is checked
//!   against.
//! - `notification` — non-empty string; the observation/notification
//!   mode (e.g. `"on_complete"`, `"backoff"`).
//!
//! Each missing or empty field produces one Warn finding
//! (`"dispatch contract missing: <field>"`). A complete contract produces
//! one Info finding (`"dispatch contract complete"`) plus an emitted
//! `Record` (`"contract ok: <n> write paths"`). The gate never blocks —
//! the managed-dispatch adapter calls [`missing_fields`] to fail closed.

use aor::{
    Enforcement, Event, EventKind, Finding, Gate, GateContext, GateDescriptor, Profile,
    ProfileState, Record, Result, Severity,
};

/// Declared coverage: dispatch-contract validation runs identically on
/// the managed-dispatch channel (fail-closed adapter) and the hook-observe
/// channel.
const PROFILES: &[Profile] = &[
    Profile::new(Enforcement::ManagedDispatch, ProfileState::Implemented),
    Profile::new(Enforcement::HookObserve, ProfileState::Implemented),
];

pub const DESCRIPTOR: GateDescriptor = GateDescriptor {
    name: "dispatch",
    summary: "Dispatch-Gate: dispatch contract with completion channel, observation window, exclusive write paths and acceptance criteria.",
    profiles: PROFILES,
};

pub const fn descriptor() -> &'static GateDescriptor {
    &DESCRIPTOR
}

/// Dispatch-Gate: validates the dispatch contract on `EventKind::Dispatch`.
pub struct DispatchGate;

impl Gate for DispatchGate {
    fn descriptor(&self) -> &'static GateDescriptor {
        &DESCRIPTOR
    }

    fn observe(&self, event: &Event, ctx: &mut dyn GateContext) -> Result<Vec<Finding>> {
        if event.kind != EventKind::Dispatch {
            return Ok(Vec::new());
        }
        let missing = missing_fields(&event.detail);
        if !missing.is_empty() {
            return Ok(missing
                .iter()
                .map(|field| {
                    Finding::new(
                        DESCRIPTOR.name,
                        Severity::Warn,
                        format!("dispatch contract missing: {field}"),
                    )
                })
                .collect());
        }
        let write_paths = event
            .detail
            .get("write_paths")
            .and_then(|v| v.as_array())
            .map_or(0, Vec::len);
        ctx.emit(Record {
            id: 0,
            ts_ms: event.ts_ms,
            gate: DESCRIPTOR.name.to_string(),
            channel: None,
            severity: Severity::Info,
            summary: format!("contract ok: {write_paths} write paths"),
            artifact: None,
        });
        Ok(vec![Finding::new(
            DESCRIPTOR.name,
            Severity::Info,
            "dispatch contract complete",
        )])
    }
}

/// Names of the required contract fields missing from `detail`, in
/// contract order. Pure check shared with the managed-dispatch adapter, which fails
/// closed when this returns non-empty.
pub fn missing_fields(detail: &serde_json::Value) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if !non_empty_str(detail.get("completion_channel")) {
        missing.push("completion_channel");
    }
    if !non_empty_str_list(detail.get("write_paths")) {
        missing.push("write_paths");
    }
    let acceptance = detail.get("acceptance");
    if !non_empty_str(acceptance) && !non_empty_str_list(acceptance) {
        missing.push("acceptance");
    }
    if !non_empty_str(detail.get("notification")) {
        missing.push("notification");
    }
    missing
}

fn non_empty_str(v: Option<&serde_json::Value>) -> bool {
    v.and_then(|v| v.as_str())
        .is_some_and(|s| !s.trim().is_empty())
}

fn non_empty_str_list(v: Option<&serde_json::Value>) -> bool {
    v.and_then(|v| v.as_array()).is_some_and(|a| {
        !a.is_empty()
            && a.iter()
                .all(|x| x.as_str().is_some_and(|s| !s.trim().is_empty()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aor::mem::{MemArtifacts, MemStore, TestContext};
    use serde_json::json;

    fn ctx() -> TestContext {
        TestContext::new(MemStore::new(), MemArtifacts::new())
    }

    fn dispatch(detail: serde_json::Value) -> Event {
        Event::new(EventKind::Dispatch, detail)
    }

    fn complete_detail() -> serde_json::Value {
        json!({
            "completion_channel": "task-result",
            "write_paths": ["src/", "docs/"],
            "acceptance": ["tests pass"],
            "notification": "on_complete",
        })
    }

    #[test]
    fn each_missing_field_is_detected() {
        assert!(missing_fields(&complete_detail()).is_empty());
        for field in [
            "completion_channel",
            "write_paths",
            "acceptance",
            "notification",
        ] {
            let mut detail = complete_detail();
            detail.as_object_mut().unwrap().remove(field);
            assert_eq!(missing_fields(&detail), vec![field], "field {field}");
        }
    }

    #[test]
    fn empty_values_count_as_missing() {
        let detail = json!({
            "completion_channel": "  ",
            "write_paths": [],
            "acceptance": "",
            "notification": "",
        });
        assert_eq!(
            missing_fields(&detail),
            vec![
                "completion_channel",
                "write_paths",
                "acceptance",
                "notification"
            ]
        );
        // acceptance also rejects a non-string array
        let mut detail = complete_detail();
        detail["acceptance"] = json!([1, 2]);
        assert_eq!(missing_fields(&detail), vec!["acceptance"]);
        // acceptance as a plain string is valid
        detail["acceptance"] = json!("tests pass");
        assert!(missing_fields(&detail).is_empty());
    }

    #[test]
    fn observe_warns_once_per_missing_field() {
        let gate = DispatchGate;
        let mut ctx = ctx();
        let ev = dispatch(json!({
            "write_paths": ["src/"],
            "notification": "backoff",
        }));
        let findings = gate.observe(&ev, &mut ctx).unwrap();
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|f| f.severity == Severity::Warn));
        assert_eq!(
            findings[0].message,
            "dispatch contract missing: completion_channel"
        );
        assert_eq!(findings[1].message, "dispatch contract missing: acceptance");
        assert!(ctx.emitted.is_empty());
    }

    #[test]
    fn complete_contract_emits_info_and_record() {
        let gate = DispatchGate;
        let mut ctx = ctx();
        let ev = dispatch(complete_detail());
        let findings = gate.observe(&ev, &mut ctx).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].gate, "dispatch");
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(findings[0].message, "dispatch contract complete");
        assert_eq!(ctx.emitted.len(), 1);
        let record = &ctx.emitted[0];
        assert_eq!(record.gate, "dispatch");
        assert_eq!(record.severity, Severity::Info);
        assert_eq!(record.summary, "contract ok: 2 write paths");
        assert_eq!(record.ts_ms, ev.ts_ms);
    }

    #[test]
    fn non_dispatch_events_are_ignored() {
        let gate = DispatchGate;
        let mut ctx = ctx();
        for kind in [
            EventKind::Compact,
            EventKind::Verify,
            EventKind::Close,
            EventKind::ToolCall,
            EventKind::Sweep,
        ] {
            let ev = Event::new(kind, json!({}));
            assert!(gate.observe(&ev, &mut ctx).unwrap().is_empty());
        }
        assert!(ctx.emitted.is_empty());
    }

    #[test]
    fn profiles_are_implemented() {
        assert!(DESCRIPTOR
            .profiles
            .iter()
            .all(|p| p.state == ProfileState::Implemented));
    }
}
