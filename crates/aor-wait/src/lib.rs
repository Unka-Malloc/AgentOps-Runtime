//! aor-wait — Wait discipline gate for AgentOps-Runtime.
//!
//! Wait discipline: completion notifications over polling, bounded backoff,
//! progress feedback.
//!
//! ## Observed events
//!
//! [`WaitGate`] observes [`EventKind::ToolCall`]. `Event.detail` fields:
//!
//! - `tool` (string): tool/command name. Missing or non-string → the event
//!   is ignored entirely.
//! - `args` (object/array, optional): normalized with `serde_json`
//!   (`Value::to_string` — canonical, sorted-key compact JSON since
//!   serde_json's default map is a `BTreeMap`) and folded into a std
//!   [`DefaultHasher`] digest. Absent `args` hash as `null`.
//!
//! The per-identity counter key is `wait.<tool>.<8-hex-of-args-hash>`; the
//! same tool with different arguments therefore keeps separate counters.
//!
//! ## Threshold
//!
//! [`Threshold`] — 5 identical calls inside 10 minutes, 30 minutes
//! cooldown — fires a single `Warn` finding plus one [`Record`]. Hits below
//! the limit or inside the cooldown emit nothing; the gate never blocks.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use aor::{
    Enforcement, Event, EventKind, Finding, Gate, GateContext, GateDescriptor, Profile,
    ProfileState, Record, Result, Severity, Threshold,
};

/// Identical-call limit inside [`WINDOW_MS`]; the [`Threshold`] then keeps
/// the gate quiet for [`COOLDOWN_MS`].
const LIMIT: u64 = 5;
const WINDOW_MS: u64 = 10 * 60_000;
const COOLDOWN_MS: u64 = 30 * 60_000;

/// Declared coverage: dispatch-time guidance on the managed-dispatch channel and pure
/// observation on the hook-observe channel.
const PROFILES: &[Profile] = &[
    Profile::new(Enforcement::ManagedDispatch, ProfileState::Implemented),
    Profile::new(Enforcement::HookObserve, ProfileState::Implemented),
];

pub const DESCRIPTOR: GateDescriptor = GateDescriptor {
    name: "wait",
    summary: "Wait discipline: completion notifications over polling, bounded backoff, progress feedback.",
    profiles: PROFILES,
};

pub const fn descriptor() -> &'static GateDescriptor {
    &DESCRIPTOR
}

/// The Wait discipline gate. Stateless; all memory lives in `Store`
/// counters managed by [`Threshold`].
#[derive(Default)]
pub struct WaitGate;

impl WaitGate {
    pub const fn new() -> Self {
        Self
    }
}

impl Gate for WaitGate {
    fn descriptor(&self) -> &'static GateDescriptor {
        &DESCRIPTOR
    }

    fn observe(&self, event: &Event, ctx: &mut dyn GateContext) -> Result<Vec<Finding>> {
        if event.kind != EventKind::ToolCall {
            return Ok(Vec::new());
        }
        let Some(tool) = event.detail.get("tool").and_then(|t| t.as_str()) else {
            return Ok(Vec::new());
        };
        let args = event.detail.get("args").cloned().unwrap_or_default();
        let mut hasher = DefaultHasher::new();
        args.to_string().hash(&mut hasher);
        let key = format!("wait.{tool}.{:08x}", hasher.finish() as u32);

        let fired =
            Threshold::new(LIMIT, WINDOW_MS, COOLDOWN_MS).hit(ctx.store(), &key, event.ts_ms)?;
        if !fired {
            return Ok(Vec::new());
        }
        let n = ctx
            .store()
            .counter_count(&key, event.ts_ms.saturating_sub(WINDOW_MS))?;
        let message = format!(
            "repeated identical calls to {tool} ({n}x/10min) — prefer completion notification or bounded backoff"
        );
        ctx.emit(Record {
            id: 0,
            ts_ms: event.ts_ms,
            gate: DESCRIPTOR.name.to_string(),
            channel: None,
            severity: Severity::Warn,
            summary: message.clone(),
            artifact: None,
        });
        Ok(vec![Finding::new(DESCRIPTOR.name, Severity::Warn, message)])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aor::mem::{MemArtifacts, MemStore, TestContext};
    use serde_json::json;

    const T0: u64 = 1_000_000;

    fn call(tool: &str, args: serde_json::Value, ts_ms: u64) -> Event {
        Event {
            kind: EventKind::ToolCall,
            detail: json!({ "tool": tool, "args": args }),
            ts_ms,
        }
    }

    #[test]
    fn first_four_identical_calls_are_silent() {
        let gate = WaitGate::new();
        let mut ctx = TestContext::new(MemStore::new(), MemArtifacts::new());
        for i in 0..4u64 {
            let e = call("exec", json!({ "cmd": "sleep 60" }), T0 + i * 60_000);
            assert!(gate.observe(&e, &mut ctx).unwrap().is_empty(), "call {i}");
        }
        assert!(ctx.emitted.is_empty());
    }

    #[test]
    fn fifth_identical_call_warns_once_and_records() {
        let gate = WaitGate::new();
        let mut ctx = TestContext::new(MemStore::new(), MemArtifacts::new());
        let mut findings_total = 0;
        for i in 0..5u64 {
            let f = gate
                .observe(
                    &call("exec", json!({ "cmd": "sleep 60" }), T0 + i * 60_000),
                    &mut ctx,
                )
                .unwrap();
            if i < 4 {
                assert!(f.is_empty(), "call {i}");
            } else {
                assert_eq!(f.len(), 1);
                assert_eq!(f[0].severity, Severity::Warn);
                assert!(f[0].message.contains("exec"));
                assert!(f[0].message.contains("5x/10min"));
            }
            findings_total += f.len();
        }
        assert_eq!(findings_total, 1);
        assert_eq!(ctx.emitted.len(), 1);
        assert_eq!(ctx.emitted[0].gate, "wait");
        assert_eq!(ctx.emitted[0].severity, Severity::Warn);
    }

    #[test]
    fn calls_inside_cooldown_stay_silent() {
        let gate = WaitGate::new();
        let mut ctx = TestContext::new(MemStore::new(), MemArtifacts::new());
        // 8 identical calls inside the 10-min window: only the 5th fires.
        let mut findings_total = 0;
        for i in 0..8u64 {
            findings_total += gate
                .observe(
                    &call("exec", json!({ "cmd": "sleep 60" }), T0 + i * 60_000),
                    &mut ctx,
                )
                .unwrap()
                .len();
        }
        assert_eq!(findings_total, 1);
        assert_eq!(ctx.emitted.len(), 1);
    }

    #[test]
    fn different_args_do_not_share_a_counter() {
        let gate = WaitGate::new();
        let mut ctx = TestContext::new(MemStore::new(), MemArtifacts::new());
        // 4 calls with args A then 4 with args B: a shared counter would
        // have fired at B's first call.
        for i in 0..4u64 {
            let e = call("exec", json!({ "cmd": "sleep 60" }), T0 + i * 60_000);
            assert!(gate.observe(&e, &mut ctx).unwrap().is_empty());
        }
        for i in 4..8u64 {
            let e = call("exec", json!({ "cmd": "sleep 90" }), T0 + i * 60_000);
            assert!(gate.observe(&e, &mut ctx).unwrap().is_empty(), "call {i}");
        }
        // B's 5th identical call now crosses the limit — exactly once.
        let f = gate
            .observe(
                &call("exec", json!({ "cmd": "sleep 90" }), T0 + 8 * 60_000),
                &mut ctx,
            )
            .unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Warn);
    }

    #[test]
    fn missing_or_malformed_tool_is_ignored() {
        let gate = WaitGate::new();
        let mut ctx = TestContext::new(MemStore::new(), MemArtifacts::new());
        for detail in [
            json!({ "args": { "cmd": "sleep 60" } }),
            json!({ "tool": 7, "args": {} }),
            json!({}),
        ] {
            let e = Event {
                kind: EventKind::ToolCall,
                detail,
                ts_ms: T0,
            };
            assert!(gate.observe(&e, &mut ctx).unwrap().is_empty());
        }
        assert!(ctx.emitted.is_empty());
    }

    #[test]
    fn non_toolcall_events_are_ignored() {
        let gate = WaitGate::new();
        let mut ctx = TestContext::new(MemStore::new(), MemArtifacts::new());
        let e = Event {
            kind: EventKind::Verify,
            detail: json!({ "tool": "exec", "args": { "cmd": "sleep 60" } }),
            ts_ms: T0,
        };
        assert!(gate.observe(&e, &mut ctx).unwrap().is_empty());
    }
}
