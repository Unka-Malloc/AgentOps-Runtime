//! aor-close — Close-Gate gate for AgentOps-Runtime.
//!
//! Close-Gate: delivery closure as a sweep-based advisory. The gate's
//! work is `sweep()` — a stale-state harvest over the todo store — plus
//! an advisory `observe()` on close events. Like every gate it emits
//! findings and records only; whether a stale or duplicate delivery
//! blocks a close is the host channel's decision, never the gate's.
//!
//! ## Todo `detail` fields read (sweep)
//!
//! - `detail.scope` — string, delivery scope (e.g. `"main"`,
//!   `"worktree"`). Todos sharing a `title` while carrying different
//!   `scope` values flag a duplicate delivery state. Todos without a
//!   string `scope` take no part in the duplicate check.
//!
//! ## Event `detail` fields read (observe)
//!
//! On `EventKind::Close` only:
//! - `detail.todo_id` — string, id of the delivery being closed.
//!
//! ## Outputs
//!
//! `sweep` findings — each fires at most once per sweep and lists its
//! members inline:
//! - `N stale in-progress deliveries: <ids>` — `Warn`; `in_progress`
//!   todos whose `updated_ms` is older than [`STALE_MS`].
//! - `N long-blocked deliveries: <ids>` — `High`; `blocked` todos whose
//!   `updated_ms` is older than [`BLOCKED_MS`].
//! - `duplicate delivery state: <titles>` — `Warn`; titles carried by
//!   todos under more than one distinct `detail.scope`.
//!
//! When any of the three counts is nonzero, `sweep` also queues one
//! summary `Record` (`severity: Info`) via `ctx.emit`:
//! `sweep: N stale, M blocked, K duplicates`.
//!
//! `observe` findings:
//! - `close requested for <id> — definition-of-done applies` — `Info`.
//!   Advisory only; the store is not consulted. Non-`Close` kinds and
//!   `Close` events lacking a string `detail.todo_id` are ignored.

use aor::{
    Enforcement, Event, EventKind, Finding, Gate, GateContext, GateDescriptor, Profile,
    ProfileState, Record, Severity,
};
use std::collections::{BTreeMap, BTreeSet};

/// Age after which an `in_progress` delivery counts as stale: 7 days.
pub const STALE_MS: u64 = 7 * 24 * 3600 * 1000;

/// Age after which a `blocked` delivery counts as long-blocked: 14 days.
pub const BLOCKED_MS: u64 = 14 * 24 * 3600 * 1000;

/// Declared coverage. Both channels run the same advisory sweep and
/// close-observation logic; strength is the host adapter's decision.
const PROFILES: &[Profile] = &[
    Profile::new(Enforcement::ManagedDispatch, ProfileState::Implemented),
    Profile::new(Enforcement::HookObserve, ProfileState::Implemented),
];

pub const DESCRIPTOR: GateDescriptor = GateDescriptor {
    name: "close",
    summary: "Close-Gate: stale in-progress harvest, main/worktree state reconciliation and a definition-of-done checklist.",
    profiles: PROFILES,
};

pub const fn descriptor() -> &'static GateDescriptor {
    &DESCRIPTOR
}

/// Close-Gate. Stateless; every check reads through `GateContext`.
pub struct CloseGate;

impl Gate for CloseGate {
    fn descriptor(&self) -> &'static GateDescriptor {
        &DESCRIPTOR
    }

    fn observe(&self, event: &Event, _ctx: &mut dyn GateContext) -> aor::Result<Vec<Finding>> {
        if event.kind != EventKind::Close {
            return Ok(Vec::new());
        }
        let Some(id) = event.detail.get("todo_id").and_then(|v| v.as_str()) else {
            return Ok(Vec::new());
        };
        Ok(vec![Finding::new(
            "close",
            Severity::Info,
            format!("close requested for {id} — definition-of-done applies"),
        )])
    }

    fn sweep(&self, ctx: &mut dyn GateContext) -> aor::Result<Vec<Finding>> {
        let now = aor::now_ms();
        let mut findings = Vec::new();

        let stale_ids: Vec<String> = ctx
            .store()
            .todos(Some("in_progress"))?
            .into_iter()
            .filter(|t| now.saturating_sub(t.updated_ms) > STALE_MS)
            .map(|t| t.id)
            .collect();
        if !stale_ids.is_empty() {
            findings.push(Finding::new(
                "close",
                Severity::Warn,
                format!(
                    "{} stale in-progress deliveries: {}",
                    stale_ids.len(),
                    stale_ids.join(", ")
                ),
            ));
        }

        let blocked_ids: Vec<String> = ctx
            .store()
            .todos(Some("blocked"))?
            .into_iter()
            .filter(|t| now.saturating_sub(t.updated_ms) > BLOCKED_MS)
            .map(|t| t.id)
            .collect();
        if !blocked_ids.is_empty() {
            findings.push(Finding::new(
                "close",
                Severity::High,
                format!(
                    "{} long-blocked deliveries: {}",
                    blocked_ids.len(),
                    blocked_ids.join(", ")
                ),
            ));
        }

        // Duplicate delivery state: one title tracked under more than one
        // scope (e.g. a main checkout and a worktree). Todos without a
        // string `detail.scope` are excluded.
        let mut scopes_by_title: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        for t in ctx.store().todos(None)? {
            if let Some(scope) = t.detail.get("scope").and_then(|v| v.as_str()) {
                scopes_by_title
                    .entry(t.title)
                    .or_default()
                    .insert(scope.to_string());
            }
        }
        let dup_titles: Vec<&str> = scopes_by_title
            .iter()
            .filter(|(_, scopes)| scopes.len() > 1)
            .map(|(title, _)| title.as_str())
            .collect();
        if !dup_titles.is_empty() {
            findings.push(Finding::new(
                "close",
                Severity::Warn,
                format!("duplicate delivery state: {}", dup_titles.join(", ")),
            ));
        }

        if !stale_ids.is_empty() || !blocked_ids.is_empty() || !dup_titles.is_empty() {
            ctx.emit(Record {
                id: 0,
                ts_ms: now,
                gate: "close".to_string(),
                channel: None,
                severity: Severity::Info,
                summary: format!(
                    "sweep: {} stale, {} blocked, {} duplicates",
                    stale_ids.len(),
                    blocked_ids.len(),
                    dup_titles.len()
                ),
                artifact: None,
            });
        }

        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aor::mem::{MemArtifacts, MemStore, TestContext};
    use aor::{Store, Todo};

    fn make_ctx() -> TestContext {
        TestContext::new(MemStore::new(), MemArtifacts::new())
    }

    fn todo(id: &str, title: &str, state: &str, updated_ms: u64, scope: Option<&str>) -> Todo {
        let detail = match scope {
            Some(s) => serde_json::json!({ "scope": s }),
            None => serde_json::Value::Null,
        };
        Todo {
            id: id.to_string(),
            title: title.to_string(),
            state: state.to_string(),
            owner: None,
            updated_ms,
            detail,
        }
    }

    #[test]
    fn stale_in_progress_harvest_fires_once_listing_ids() {
        let mut ctx = make_ctx();
        let old = aor::now_ms() - STALE_MS - 1_000;
        ctx.store
            .upsert_todo(&todo("t1", "alpha", "in_progress", old, None))
            .unwrap();
        ctx.store
            .upsert_todo(&todo("t2", "beta", "in_progress", old, None))
            .unwrap();

        let findings = CloseGate.sweep(&mut ctx).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].gate, "close");
        assert_eq!(findings[0].severity, Severity::Warn);
        assert!(findings[0]
            .message
            .contains("2 stale in-progress deliveries"));
        assert!(findings[0].message.contains("t1"));
        assert!(findings[0].message.contains("t2"));

        assert_eq!(ctx.emitted.len(), 1);
        assert_eq!(
            ctx.emitted[0].summary,
            "sweep: 2 stale, 0 blocked, 0 duplicates"
        );
        assert_eq!(ctx.emitted[0].severity, Severity::Info);
    }

    #[test]
    fn fresh_in_progress_is_silent() {
        let mut ctx = make_ctx();
        ctx.store
            .upsert_todo(&todo("t1", "alpha", "in_progress", aor::now_ms(), None))
            .unwrap();
        assert!(CloseGate.sweep(&mut ctx).unwrap().is_empty());
        assert!(ctx.emitted.is_empty());
    }

    #[test]
    fn long_blocked_fires_high_tier() {
        let mut ctx = make_ctx();
        let old = aor::now_ms() - BLOCKED_MS - 1_000;
        ctx.store
            .upsert_todo(&todo("b1", "gamma", "blocked", old, None))
            .unwrap();

        let findings = CloseGate.sweep(&mut ctx).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].message, "1 long-blocked deliveries: b1");
        assert_eq!(
            ctx.emitted[0].summary,
            "sweep: 0 stale, 1 blocked, 0 duplicates"
        );
    }

    #[test]
    fn recently_blocked_is_silent() {
        let mut ctx = make_ctx();
        ctx.store
            .upsert_todo(&todo("b1", "gamma", "blocked", aor::now_ms(), None))
            .unwrap();
        assert!(CloseGate.sweep(&mut ctx).unwrap().is_empty());
        assert!(ctx.emitted.is_empty());
    }

    #[test]
    fn duplicate_title_across_scopes_flagged() {
        let mut ctx = make_ctx();
        let now = aor::now_ms();
        ctx.store
            .upsert_todo(&todo(
                "m1",
                "ship release",
                "in_progress",
                now,
                Some("main"),
            ))
            .unwrap();
        ctx.store
            .upsert_todo(&todo("w1", "ship release", "done", now, Some("worktree")))
            .unwrap();

        let findings = CloseGate.sweep(&mut ctx).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warn);
        assert_eq!(
            findings[0].message,
            "duplicate delivery state: ship release"
        );
        assert_eq!(
            ctx.emitted[0].summary,
            "sweep: 0 stale, 0 blocked, 1 duplicates"
        );
    }

    #[test]
    fn same_title_same_scope_is_not_duplicate() {
        let mut ctx = make_ctx();
        let now = aor::now_ms();
        ctx.store
            .upsert_todo(&todo("a", "t", "in_progress", now, Some("main")))
            .unwrap();
        ctx.store
            .upsert_todo(&todo("b", "t", "done", now, Some("main")))
            .unwrap();
        assert!(CloseGate.sweep(&mut ctx).unwrap().is_empty());
        assert!(ctx.emitted.is_empty());
    }

    #[test]
    fn title_without_scope_is_not_duplicate() {
        let mut ctx = make_ctx();
        let now = aor::now_ms();
        ctx.store
            .upsert_todo(&todo("a", "t", "in_progress", now, None))
            .unwrap();
        ctx.store
            .upsert_todo(&todo("b", "t", "done", now, Some("main")))
            .unwrap();
        assert!(CloseGate.sweep(&mut ctx).unwrap().is_empty());
    }

    #[test]
    fn empty_store_sweeps_clean() {
        let mut ctx = make_ctx();
        assert!(CloseGate.sweep(&mut ctx).unwrap().is_empty());
        assert!(ctx.emitted.is_empty());
    }

    #[test]
    fn observe_close_is_advisory_info() {
        let mut ctx = make_ctx();
        let ev = Event::new(EventKind::Close, serde_json::json!({ "todo_id": "t9" }));
        let findings = CloseGate.observe(&ev, &mut ctx).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert!(findings[0].message.contains("t9"));
        assert!(findings[0].message.contains("definition-of-done"));
    }

    #[test]
    fn observe_ignores_other_kinds_and_missing_id() {
        let mut ctx = make_ctx();
        let other = Event::new(EventKind::Dispatch, serde_json::json!({ "todo_id": "t9" }));
        assert!(CloseGate.observe(&other, &mut ctx).unwrap().is_empty());
        let no_id = Event::new(EventKind::Close, serde_json::json!({}));
        assert!(CloseGate.observe(&no_id, &mut ctx).unwrap().is_empty());
    }

    #[test]
    fn descriptor_declares_both_channels_implemented() {
        let d = CloseGate.descriptor();
        assert_eq!(d.name, "close");
        assert_eq!(d.profiles.len(), 2);
        assert!(d
            .profiles
            .iter()
            .all(|p| p.state == ProfileState::Implemented));
    }
}
