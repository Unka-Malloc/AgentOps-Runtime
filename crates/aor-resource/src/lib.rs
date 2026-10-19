//! aor-resource — Resource-Registry gate for AgentOps-Runtime.
//!
//! Resource-Registry: manifest-declared shared/exclusive resources with
//! dispatch-time intersection checks. A `resources.toml` manifest names
//! each resource, its `kind` (`"path"`, `"port"`, `"device"`, `"index"`,
//! ...) and whether it is `exclusive`. At `EventKind::Dispatch` the gate
//! intersects the dispatch's required resources with the leases already
//! held: an exclusive resource present in both lists is a conflict.
//! Findings are advisory — whether a conflict blocks the dispatch is the
//! host channel's decision.
//!
//! ## Manifest shape (`resources.toml`)
//!
//! ```toml
//! [[resource]]
//! name = "db-port"
//! kind = "port"
//! exclusive = true
//!
//! [[resource]]
//! name = "docs"
//! kind = "path"
//! paths = ["docs/", "README.md"]
//! ```
//!
//! The TOML key is `resource` — a singular array-of-tables — which
//! deserializes into [`Manifest::resources`].
//!
//! ## Event `detail` fields read (observe, `EventKind::Dispatch`)
//!
//! - `resources` — array of strings: resource names this dispatch
//!   requires. Missing or non-array → treated as empty.
//! - `active_leases` — array of strings: resource names currently held.
//!   Missing or non-array → treated as empty.
//! - `manifest` — string: inline `resources.toml` text. Wins over
//!   `manifest_path` when both are present. Parse failure → `Warn`.
//! - `manifest_path` — string: path to a `resources.toml` file read via
//!   `std::fs`. Read or parse failure → `Warn`.
//!
//! ## Outputs (observe)
//!
//! - `exclusive resource conflict: <names>` — `High`; names exclusive in
//!   the manifest and present in both `resources` and `active_leases`.
//! - `resource check clean` — `Info`; manifest loaded, no conflicts.
//! - `no resource manifest supplied for conflict check` — `Warn`; neither
//!   `manifest` nor `manifest_path` is a string.
//! - manifest read/parse failures — `Warn` carrying the error.
//!
//! Non-`Dispatch` kinds are ignored. `sweep` is a no-op: resource state
//! arrives on dispatch events, not in the store.

use aor::{
    Enforcement, Event, EventKind, Finding, Gate, GateContext, GateDescriptor, Profile,
    ProfileState, Severity,
};
use serde::Deserialize;

/// One manifest-declared resource.
#[derive(Clone, Debug, Deserialize)]
pub struct Resource {
    /// Stable resource name referenced by dispatch detail fields.
    pub name: String,
    /// Resource class: `"path"`, `"port"`, `"device"`, `"index"`, ...
    /// Free-form; the gate does not interpret it.
    pub kind: String,
    /// Exclusive resources may not be held twice — overlapping required
    /// and active sets conflict. Shared (`false`) resources may overlap.
    #[serde(default)]
    pub exclusive: bool,
    /// Paths this resource covers (meaningful for `kind = "path"`).
    #[serde(default)]
    pub paths: Vec<String>,
}

/// A `resources.toml` manifest: the `[[resource]]` array-of-tables.
#[derive(Clone, Debug, Deserialize)]
pub struct Manifest {
    #[serde(rename = "resource")]
    pub resources: Vec<Resource>,
}

impl Manifest {
    /// Parse a `resources.toml` document.
    pub fn parse(toml_str: &str) -> aor::Result<Manifest> {
        toml::from_str(toml_str)
            .map_err(|e| aor::Error::msg(format!("invalid resource manifest: {e}")))
    }

    /// Look up a resource by name.
    pub fn find(&self, name: &str) -> Option<&Resource> {
        self.resources.iter().find(|r| r.name == name)
    }
}

/// Names exclusive in `m` and present in both `required` and `active`.
/// Order follows `required`; duplicates are reported once.
pub fn conflicts(required: &[String], active: &[String], m: &Manifest) -> Vec<String> {
    let mut reported = std::collections::HashSet::new();
    let mut out = Vec::new();
    for name in required {
        if !active.contains(name) {
            continue;
        }
        if !m.find(name).is_some_and(|r| r.exclusive) {
            continue;
        }
        if reported.insert(name.as_str()) {
            out.push(name.clone());
        }
    }
    out
}

/// Pull an array-of-strings detail field out as owned strings;
/// missing, non-array or non-string entries yield nothing.
fn string_list(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Resource-Registry gate. Stateless; the manifest arrives per event.
pub struct ResourceGate;

impl ResourceGate {
    fn warn(message: impl Into<String>) -> aor::Result<Vec<Finding>> {
        Ok(vec![Finding::new("resource", Severity::Warn, message)])
    }
}

impl Gate for ResourceGate {
    fn descriptor(&self) -> &'static GateDescriptor {
        &DESCRIPTOR
    }

    fn observe(&self, event: &Event, _ctx: &mut dyn GateContext) -> aor::Result<Vec<Finding>> {
        if event.kind != EventKind::Dispatch {
            return Ok(Vec::new());
        }

        let manifest = if let Some(inline) = event.detail.get("manifest").and_then(|v| v.as_str()) {
            match Manifest::parse(inline) {
                Ok(m) => m,
                Err(e) => return Self::warn(e.to_string()),
            }
        } else if let Some(path) = event.detail.get("manifest_path").and_then(|v| v.as_str()) {
            match std::fs::read_to_string(path) {
                Ok(text) => match Manifest::parse(&text) {
                    Ok(m) => m,
                    Err(e) => return Self::warn(e.to_string()),
                },
                Err(e) => {
                    return Self::warn(format!("failed to read resource manifest {path}: {e}"));
                }
            }
        } else {
            return Self::warn("no resource manifest supplied for conflict check");
        };

        let required = string_list(&event.detail["resources"]);
        let active = string_list(&event.detail["active_leases"]);
        let names = conflicts(&required, &active, &manifest);

        if names.is_empty() {
            Ok(vec![Finding::new(
                "resource",
                Severity::Info,
                "resource check clean",
            )])
        } else {
            Ok(vec![Finding::new(
                "resource",
                Severity::High,
                format!("exclusive resource conflict: {}", names.join(", ")),
            )])
        }
    }
}

/// Declared coverage. Both channels run the same advisory intersection
/// check; strength is the host adapter's decision.
const PROFILES: &[Profile] = &[
    Profile::new(Enforcement::ManagedDispatch, ProfileState::Implemented),
    Profile::new(Enforcement::HookObserve, ProfileState::Implemented),
    Profile::new(Enforcement::OutboundBoundary, ProfileState::Implemented),
];

pub const DESCRIPTOR: GateDescriptor = GateDescriptor {
    name: "resource",
    summary: "Resource-Registry: manifest-declared shared/exclusive resources with dispatch-time intersection checks.",
    profiles: PROFILES,
};

pub const fn descriptor() -> &'static GateDescriptor {
    &DESCRIPTOR
}

#[cfg(test)]
mod tests {
    use super::*;
    use aor::mem::{MemArtifacts, MemStore, TestContext};

    const MANIFEST: &str = r#"
[[resource]]
name = "db-port"
kind = "port"
exclusive = true

[[resource]]
name = "docs"
kind = "path"
paths = ["docs/", "README.md"]

[[resource]]
name = "gpu0"
kind = "device"
exclusive = true
"#;

    fn make_ctx() -> TestContext {
        TestContext::new(MemStore::new(), MemArtifacts::new())
    }

    fn dispatch(detail: serde_json::Value) -> Event {
        Event::new(EventKind::Dispatch, detail)
    }

    #[test]
    fn manifest_parse_roundtrip() {
        let m = Manifest::parse(MANIFEST).unwrap();
        assert_eq!(m.resources.len(), 3);

        let db = m.find("db-port").unwrap();
        assert_eq!(db.kind, "port");
        assert!(db.exclusive);
        assert!(db.paths.is_empty());

        let docs = m.find("docs").unwrap();
        assert_eq!(docs.kind, "path");
        assert!(!docs.exclusive);
        assert_eq!(docs.paths, vec!["docs/", "README.md"]);

        assert!(m.find("nope").is_none());
    }

    #[test]
    fn manifest_parse_rejects_garbage() {
        assert!(Manifest::parse("[[[nope").is_err());
    }

    #[test]
    fn conflicts_finds_exclusive_overlap() {
        let m = Manifest::parse(MANIFEST).unwrap();
        let required = vec!["db-port".to_string(), "docs".to_string()];
        let active = vec!["db-port".to_string(), "docs".to_string()];
        assert_eq!(conflicts(&required, &active, &m), vec!["db-port"]);
    }

    #[test]
    fn conflicts_ignores_unknown_and_unheld_names() {
        let m = Manifest::parse(MANIFEST).unwrap();
        // "nope" is in both lists but not exclusive (not even declared).
        let required = vec!["nope".to_string(), "gpu0".to_string()];
        let active = vec!["nope".to_string()];
        assert!(conflicts(&required, &active, &m).is_empty());
    }

    #[test]
    fn dispatch_exclusive_conflict_is_high() {
        let mut ctx = make_ctx();
        let ev = dispatch(serde_json::json!({
            "resources": ["db-port"],
            "active_leases": ["db-port", "gpu0"],
            "manifest": MANIFEST,
        }));
        let findings = ResourceGate.observe(&ev, &mut ctx).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].gate, "resource");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].message, "exclusive resource conflict: db-port");
    }

    #[test]
    fn dispatch_shared_overlap_is_clean() {
        let mut ctx = make_ctx();
        let ev = dispatch(serde_json::json!({
            "resources": ["docs"],
            "active_leases": ["docs"],
            "manifest": MANIFEST,
        }));
        let findings = ResourceGate.observe(&ev, &mut ctx).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Info);
        assert_eq!(findings[0].message, "resource check clean");
    }

    #[test]
    fn dispatch_without_manifest_warns() {
        let mut ctx = make_ctx();
        let ev = dispatch(serde_json::json!({
            "resources": ["db-port"],
            "active_leases": ["db-port"],
        }));
        let findings = ResourceGate.observe(&ev, &mut ctx).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warn);
        assert_eq!(
            findings[0].message,
            "no resource manifest supplied for conflict check"
        );
    }

    #[test]
    fn dispatch_manifest_path_conflict() {
        let mut ctx = make_ctx();
        let path = std::env::temp_dir().join(format!(
            "aor-resource-test-{}-{}.toml",
            std::process::id(),
            aor::now_ms()
        ));
        std::fs::write(&path, MANIFEST).unwrap();

        let ev = dispatch(serde_json::json!({
            "resources": ["gpu0"],
            "active_leases": ["gpu0"],
            "manifest_path": path.to_str().unwrap(),
        }));
        let findings = ResourceGate.observe(&ev, &mut ctx).unwrap();
        std::fs::remove_file(&path).unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].message, "exclusive resource conflict: gpu0");
    }

    #[test]
    fn dispatch_manifest_path_read_failure_warns() {
        let mut ctx = make_ctx();
        let ev = dispatch(serde_json::json!({
            "resources": ["gpu0"],
            "manifest_path": "/nonexistent/aor-resource-test.toml",
        }));
        let findings = ResourceGate.observe(&ev, &mut ctx).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warn);
        assert!(findings[0]
            .message
            .contains("failed to read resource manifest"));
    }

    #[test]
    fn dispatch_invalid_inline_manifest_warns() {
        let mut ctx = make_ctx();
        let ev = dispatch(serde_json::json!({
            "resources": ["gpu0"],
            "manifest": "[[[garbage",
        }));
        let findings = ResourceGate.observe(&ev, &mut ctx).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Warn);
        assert!(findings[0].message.contains("invalid resource manifest"));
    }

    #[test]
    fn observe_ignores_non_dispatch() {
        let mut ctx = make_ctx();
        let ev = Event::new(EventKind::Close, serde_json::json!({}));
        assert!(ResourceGate.observe(&ev, &mut ctx).unwrap().is_empty());
    }

    #[test]
    fn descriptor_declares_all_channels_implemented() {
        let d = ResourceGate.descriptor();
        assert_eq!(d.name, "resource");
        assert_eq!(d.profiles.len(), 3);
        assert!(d
            .profiles
            .iter()
            .all(|p| p.state == ProfileState::Implemented));
    }
}
