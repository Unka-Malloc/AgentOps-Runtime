//! aor-payload — Payload-Gate gate for AgentOps-Runtime.
//!
//! Payload-Gate: payload size budget before dispatch; windowed-read strategy and oversized-input split authorization.
//!
//! ## Detail contract (`EventKind::Dispatch`)
//!
//! `event.detail` is host-provided JSON; the gate reads:
//!
//! - `content` — optional string; inline task content. When this single
//!   field alone exceeds [`WARN_BYTES`], the finding message carries
//!   `"; large inline content — prefer path reference"`. Every field in
//!   `detail` still counts toward the serialized size estimate.
//!
//! The estimate is the byte length of `serde_json::to_string(&detail)`
//! (see [`estimate_bytes`]). Payloads over [`WARN_BYTES`] produce a Warn
//! finding, over [`HIGH_BYTES`] a High finding — message
//! `"payload ~<size>B exceeds <budget>B — split task or window reads"` —
//! plus an emitted `Record` (`"payload <size>B over <level> budget"`).
//! Under budget the gate stays silent. The gate never blocks — the managed-dispatch adapter
//! adapter owns the fail-closed dispatch decision.

use aor::{
    Enforcement, Event, EventKind, Finding, Gate, GateContext, GateDescriptor, Profile,
    ProfileState, Record, Result, Severity,
};

/// Serialized payload size at which the gate warns.
pub const WARN_BYTES: usize = 64 * 1024;
/// Serialized payload size at which the gate escalates to High.
pub const HIGH_BYTES: usize = 256 * 1024;

/// Declared coverage: the size budget applies identically on the
/// managed-dispatch channel (fail-closed adapter) and the hook-observe
/// channel.
const PROFILES: &[Profile] = &[
    Profile::new(Enforcement::ManagedDispatch, ProfileState::Implemented),
    Profile::new(Enforcement::HookObserve, ProfileState::Implemented),
    Profile::new(Enforcement::OutboundBoundary, ProfileState::Implemented),
];

pub const DESCRIPTOR: GateDescriptor = GateDescriptor {
    name: "payload",
    summary: "Payload-Gate: payload size budget before dispatch; windowed-read strategy and oversized-input split authorization.",
    profiles: PROFILES,
};

pub const fn descriptor() -> &'static GateDescriptor {
    &DESCRIPTOR
}

/// Payload-Gate: enforces the pre-dispatch payload size budget on
/// `EventKind::Dispatch`.
pub struct PayloadGate;

impl Gate for PayloadGate {
    fn descriptor(&self) -> &'static GateDescriptor {
        &DESCRIPTOR
    }

    fn observe(&self, event: &Event, ctx: &mut dyn GateContext) -> Result<Vec<Finding>> {
        if event.kind != EventKind::Dispatch {
            return Ok(Vec::new());
        }
        let size = estimate_bytes(&event.detail);
        let (severity, budget, level) = if size > HIGH_BYTES {
            (Severity::High, HIGH_BYTES, "high")
        } else if size > WARN_BYTES {
            (Severity::Warn, WARN_BYTES, "warn")
        } else {
            return Ok(Vec::new());
        };
        let mut message =
            format!("payload ~{size}B exceeds {budget}B — split task or window reads");
        if large_inline_content(&event.detail) {
            message.push_str("; large inline content — prefer path reference");
        }
        ctx.emit(Record {
            id: 0,
            ts_ms: event.ts_ms,
            gate: DESCRIPTOR.name.to_string(),
            channel: None,
            severity,
            summary: format!("payload {size}B over {level} budget"),
            artifact: None,
        });
        Ok(vec![Finding::new(DESCRIPTOR.name, severity, message)])
    }
}

/// Serialized byte size of `detail` — the payload estimate the budget is
/// applied to. Pure check shared with the managed-dispatch adapter.
pub fn estimate_bytes(detail: &serde_json::Value) -> usize {
    serde_json::to_string(detail).unwrap_or_default().len()
}

/// Whether the `content` field is a string that alone exceeds
/// [`WARN_BYTES`] — inline bulk that belongs behind a path reference.
fn large_inline_content(detail: &serde_json::Value) -> bool {
    detail
        .get("content")
        .and_then(|v| v.as_str())
        .is_some_and(|s| s.len() > WARN_BYTES)
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

    #[test]
    fn under_budget_is_silent() {
        let gate = PayloadGate;
        let mut ctx = ctx();
        let ev = dispatch(json!({"task": "fix the typo", "content": "small"}));
        assert!(gate.observe(&ev, &mut ctx).unwrap().is_empty());
        assert!(ctx.emitted.is_empty());
    }

    #[test]
    fn warn_tier_finding_and_record() {
        let gate = PayloadGate;
        let mut ctx = ctx();
        // ~80 KiB total, no `content` field -> warn, no inline hint.
        let ev = dispatch(json!({
            "a": "x".repeat(40 * 1024),
            "b": "y".repeat(40 * 1024),
        }));
        let size = estimate_bytes(&ev.detail);
        assert!(size > WARN_BYTES && size <= HIGH_BYTES);
        let findings = gate.observe(&ev, &mut ctx).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].gate, "payload");
        assert_eq!(findings[0].severity, Severity::Warn);
        assert_eq!(
            findings[0].message,
            format!("payload ~{size}B exceeds {WARN_BYTES}B — split task or window reads")
        );
        assert_eq!(ctx.emitted.len(), 1);
        let record = &ctx.emitted[0];
        assert_eq!(record.gate, "payload");
        assert_eq!(record.severity, Severity::Warn);
        assert_eq!(record.summary, format!("payload {size}B over warn budget"));
    }

    #[test]
    fn high_tier_finding_and_record() {
        let gate = PayloadGate;
        let mut ctx = ctx();
        // ~300 KiB total via two non-`content` fields -> high, no hint.
        let ev = dispatch(json!({
            "a": "x".repeat(150 * 1024),
            "b": "y".repeat(150 * 1024),
        }));
        let size = estimate_bytes(&ev.detail);
        assert!(size > HIGH_BYTES);
        let findings = gate.observe(&ev, &mut ctx).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(
            findings[0].message,
            format!("payload ~{size}B exceeds {HIGH_BYTES}B — split task or window reads")
        );
        assert_eq!(ctx.emitted.len(), 1);
        assert_eq!(ctx.emitted[0].severity, Severity::High);
        assert_eq!(
            ctx.emitted[0].summary,
            format!("payload {size}B over high budget")
        );
    }

    #[test]
    fn large_content_appends_hint() {
        let gate = PayloadGate;
        let mut ctx = ctx();
        // `content` alone over WARN_BYTES, total under HIGH_BYTES.
        let ev = dispatch(json!({"content": "x".repeat(WARN_BYTES + 1024)}));
        let findings = gate.observe(&ev, &mut ctx).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warn);
        assert!(findings[0]
            .message
            .ends_with("; large inline content — prefer path reference"));
        assert_eq!(ctx.emitted.len(), 1);
    }

    #[test]
    fn estimate_bytes_matches_serialization() {
        let detail = json!({"a": 1, "b": ["x", "y"], "c": {"d": null}});
        assert_eq!(
            estimate_bytes(&detail),
            serde_json::to_string(&detail).unwrap().len()
        );
    }

    #[test]
    fn non_dispatch_events_are_ignored() {
        let gate = PayloadGate;
        let mut ctx = ctx();
        let big = "x".repeat(HIGH_BYTES + 1024);
        for kind in [
            EventKind::Compact,
            EventKind::Verify,
            EventKind::Close,
            EventKind::ToolCall,
            EventKind::Sweep,
        ] {
            let ev = Event::new(kind, json!({"content": big}));
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
