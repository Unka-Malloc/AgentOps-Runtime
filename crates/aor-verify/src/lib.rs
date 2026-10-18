//! aor-verify — Verify-Budget gate for AgentOps-Runtime.
//!
//! Verify-Budget: targeted checks run freely, full regression is a one-shot
//! event, outbound evidence binds HEAD.
//!
//! ## Observed events
//!
//! [`VerifyGate`] observes [`EventKind::Verify`]. `Event.detail` fields:
//!
//! - `command` (string, **required**): the verification command about to
//!   run. Missing or non-string → a `Warn` finding and nothing else.
//! - `task` (string, default `"default"`): work-item id; scopes the
//!   full-regression counter key `verify.full.<task>` (24 h window).
//! - `head_sha` (string, optional): commit the run validates.
//! - `result` (string, optional): outcome vocabulary owned by the host
//!   (`"pass"`, `"fail"`, ...); stored verbatim, never interpreted.
//!
//! When both `head_sha` and `result` are present, a [`VerifyEvidence`]
//! artifact is written as `verify/<task>-<head_sha>.json` and a [`Record`]
//! carrying the artifact id is emitted — the evidence an outbound-boundary checker
//! consumes at the outbound-boundary channel.
//!
//! ## Full vs targeted
//!
//! [`classify`] marks a command [`VerifyClass::Full`] when it plausibly runs
//! the whole suite, [`VerifyClass::Targeted`] otherwise:
//!
//! - `cargo test` / `cargo nextest run`: `Full` only with no positional
//!   filter and no subset selector (`-p`/`--package`, `--bin`, `--test`,
//!   `--example`, `--bench`, `--exclude`, `-E`/`--filter-expr`, `--skip`).
//! - `pytest` / `py.test`: `Full` only with no path argument and no
//!   `-k`/`-m`/`--deselect`/`--ignore`/`--lf`/`--ff` filter.
//! - `flutter test`: `Full` only with no path and no
//!   `--plain-name`/`--tags`/`--exclude-tags` filter.
//! - `npm test` / `npm run test`: `Full` only when bare.
//!
//! Scope-neutral flags are skipped, including the separate value token of
//! known flags (`cargo test --features x`, `pytest -n auto`). Anything
//! unrecognized — including unknown commands and filter-looking positionals
//! — errs toward `Targeted`: a missed `Full` only delays a budget hint,
//! while a false `Full` would nag on every targeted check.

use aor::{
    Enforcement, Event, EventKind, Finding, Gate, GateContext, GateDescriptor, Profile,
    ProfileState, Record, Result, Severity,
};
use serde::{Deserialize, Serialize};

/// 24 h window for the per-task full-regression counter.
const FULL_WINDOW_MS: u64 = 24 * 60 * 60 * 1_000;

/// Flags that reduce a `cargo test`/`nextest` run to a subset → `Targeted`.
const CARGO_SELECT: &[&str] = &[
    "-p",
    "--package",
    "--bin",
    "--test",
    "--example",
    "--bench",
    "--exclude",
    "-E",
    "--filter-expr",
    "--skip",
];
/// Scope-neutral `cargo`/`nextest`/libtest flags taking a separate value.
const CARGO_VALUE: &[&str] = &[
    "-j",
    "--jobs",
    "--features",
    "--target",
    "--target-dir",
    "--manifest-path",
    "--config",
    "--profile",
    "--color",
    "-Z",
    "--test-threads",
    "--format",
    "--report-time",
    "--logfile",
    "--partition",
    "--run-count",
    "--retries",
    "-P",
];
/// Flags that reduce a `pytest` run to a subset → `Targeted`.
const PYTEST_SELECT: &[&str] = &[
    "-k",
    "-m",
    "--deselect",
    "--ignore",
    "--ignore-glob",
    "--lf",
    "--last-failed",
    "--ff",
    "--failed-first",
];
/// Scope-neutral `pytest` flags taking a separate value.
const PYTEST_VALUE: &[&str] = &[
    "-n",
    "-c",
    "-o",
    "-p",
    "-W",
    "--maxfail",
    "--junitxml",
    "--junit-xml",
    "--tb",
    "--rootdir",
    "--basetemp",
    "--confcutdir",
    "--color",
    "--verbosity",
    "--pythonwarnings",
];
/// Flags that reduce a `flutter test` run to a subset → `Targeted`.
const FLUTTER_SELECT: &[&str] = &["--plain-name", "--tags", "--exclude-tags"];
/// Scope-neutral `flutter test` flags taking a separate value.
const FLUTTER_VALUE: &[&str] = &[
    "-r",
    "--reporter",
    "-j",
    "--concurrency",
    "--timeout",
    "--platform",
    "--device-id",
    "-d",
    "--flavor",
    "--dart-define",
    "--dart-define-from-file",
    "--test-randomize-ordering-seed",
    "--coverage-path",
];

/// Declared coverage: regression discipline on the dispatch + observation
/// channels, evidence production for the outbound boundary.
const PROFILES: &[Profile] = &[
    Profile::new(Enforcement::ManagedDispatch, ProfileState::Implemented),
    Profile::new(Enforcement::HookObserve, ProfileState::Implemented),
    Profile::new(Enforcement::OutboundBoundary, ProfileState::Implemented),
];

pub const DESCRIPTOR: GateDescriptor = GateDescriptor {
    name: "verify",
    summary: "Verify-Budget: targeted checks run freely, full regression is a one-shot event, outbound evidence binds HEAD.",
    profiles: PROFILES,
};

pub const fn descriptor() -> &'static GateDescriptor {
    &DESCRIPTOR
}

/// Scope of a verification command, per [`classify`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifyClass {
    /// Runs (or plausibly runs) the whole suite.
    Full,
    /// Explicitly filtered / pathed / packaged run — or anything the
    /// heuristic cannot prove `Full`.
    Targeted,
}

/// Classify a verification command by suite scope.
///
/// Token-based heuristic: find a runner token (`cargo`, `pytest`, `flutter`,
/// `npm`) at command start or right after a shell separator, then scan its
/// arguments. A positional token is a test-name filter or path (`Targeted`);
/// a flag in the runner's select-list is a subset selector (`Targeted`);
/// other flags are scope-neutral, with known value-taking flags also
/// consuming the next token. Rules per runner are documented in the module
/// docs; anything unrecognized returns [`VerifyClass::Targeted`].
pub fn classify(command: &str) -> VerifyClass {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    for (i, tok) in tokens.iter().enumerate() {
        // A runner only counts at command start or after a shell separator,
        // so `echo cargo test` and paths like `bin/pytest` do not match.
        let preceded = i == 0 || matches!(tokens[i - 1], "&&" | "||" | ";" | "|");
        if !preceded {
            continue;
        }
        let rest = &tokens[i + 1..];
        match *tok {
            "cargo" if rest.first() == Some(&"test") => {
                return classify_rest(&rest[1..], CARGO_SELECT, CARGO_VALUE);
            }
            "cargo" if rest.first() == Some(&"nextest") => {
                let args = if rest.get(1) == Some(&"run") {
                    &rest[2..]
                } else {
                    &rest[1..]
                };
                return classify_rest(args, CARGO_SELECT, CARGO_VALUE);
            }
            "pytest" | "py.test" => {
                return classify_rest(rest, PYTEST_SELECT, PYTEST_VALUE);
            }
            "flutter" if rest.first() == Some(&"test") => {
                return classify_rest(&rest[1..], FLUTTER_SELECT, FLUTTER_VALUE);
            }
            "npm" if rest.first() == Some(&"test") => {
                return if rest.len() == 1 {
                    VerifyClass::Full
                } else {
                    VerifyClass::Targeted
                };
            }
            "npm" if rest.first() == Some(&"run") => {
                return if rest.len() == 2 && rest.get(1) == Some(&"test") {
                    VerifyClass::Full
                } else {
                    VerifyClass::Targeted
                };
            }
            _ => {}
        }
    }
    VerifyClass::Targeted
}

/// Joined short-flag form of a subset selector, e.g. `-pfoo` or `-kexpr`.
fn joined_select(token: &str, select: &[&str]) -> bool {
    !token.starts_with("--")
        && token.len() > 2
        && select.iter().any(|s| s.len() == 2 && token.starts_with(s))
}

/// Scan a runner's arguments: positional → `Targeted`, subset selector →
/// `Targeted`, neutral flag → skip (known value flags skip one extra token).
fn classify_rest(rest: &[&str], select: &[&str], value_flags: &[&str]) -> VerifyClass {
    let mut i = 0;
    while i < rest.len() {
        let token = rest[i];
        if matches!(token, "&&" | "||" | ";" | "|") {
            break; // next shell command — this runner's scope is decided
        }
        let flag = token.split('=').next().unwrap_or(token);
        if select.contains(&flag) || joined_select(token, select) {
            return VerifyClass::Targeted;
        }
        if token.starts_with('-') {
            i += if value_flags.contains(&flag) { 2 } else { 1 };
            continue;
        }
        return VerifyClass::Targeted; // positional → filter / path
    }
    VerifyClass::Full
}

/// Evidence that a verification ran against a specific HEAD. Written to the
/// artifact sink as `verify/<task>-<head_sha>.json`; an outbound-boundary checker at
/// the outbound-boundary channel later binds it to the outbound commit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct VerifyEvidence {
    pub task: String,
    pub head_sha: String,
    pub command: String,
    pub result: String,
    pub ts_ms: u64,
}

impl VerifyEvidence {
    /// Canonical JSON form written to the artifact sink.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("VerifyEvidence is infallibly serializable")
    }
}

/// The Verify-Budget gate. Stateless; all memory lives in `Store` counters.
#[derive(Default)]
pub struct VerifyGate;

impl VerifyGate {
    pub const fn new() -> Self {
        Self
    }
}

impl Gate for VerifyGate {
    fn descriptor(&self) -> &'static GateDescriptor {
        &DESCRIPTOR
    }

    fn observe(&self, event: &Event, ctx: &mut dyn GateContext) -> Result<Vec<Finding>> {
        if event.kind != EventKind::Verify {
            return Ok(Vec::new());
        }
        let Some(command) = event.detail.get("command").and_then(|c| c.as_str()) else {
            return Ok(vec![Finding::new(
                DESCRIPTOR.name,
                Severity::Warn,
                "verify event missing detail.command",
            )]);
        };
        let task = event
            .detail
            .get("task")
            .and_then(|t| t.as_str())
            .unwrap_or("default");
        let mut findings = Vec::new();

        match classify(command) {
            VerifyClass::Targeted => findings.push(Finding::new(
                DESCRIPTOR.name,
                Severity::Info,
                "targeted verification",
            )),
            VerifyClass::Full => {
                let key = format!("verify.full.{task}");
                ctx.store().counter_hit(&key, event.ts_ms)?;
                let count = ctx
                    .store()
                    .counter_count(&key, event.ts_ms.saturating_sub(FULL_WINDOW_MS))?;
                if count == 1 {
                    findings.push(Finding::new(
                        DESCRIPTOR.name,
                        Severity::Info,
                        "first full regression recorded",
                    ));
                } else {
                    findings.push(Finding::new(
                        DESCRIPTOR.name,
                        Severity::Warn,
                        format!(
                            "repeated full regression #{count} for task {task} — reuse evidence or justify"
                        ),
                    ));
                }
            }
        }

        // HEAD-bound evidence is produced for targeted and full runs alike —
        // the outbound-boundary checker needs it regardless of suite scope.
        let head_sha = event.detail.get("head_sha").and_then(|v| v.as_str());
        let result = event.detail.get("result").and_then(|v| v.as_str());
        if let (Some(head_sha), Some(result)) = (head_sha, result) {
            let evidence = VerifyEvidence {
                task: task.to_string(),
                head_sha: head_sha.to_string(),
                command: command.to_string(),
                result: result.to_string(),
                ts_ms: event.ts_ms,
            };
            let artifact = ctx.artifacts().write(
                &format!("verify/{task}-{head_sha}.json"),
                evidence.to_json().as_bytes(),
            )?;
            let sha8 = head_sha.get(..8).unwrap_or(head_sha);
            ctx.emit(Record {
                id: 0,
                ts_ms: event.ts_ms,
                gate: DESCRIPTOR.name.to_string(),
                channel: None,
                severity: Severity::Info,
                summary: format!("evidence bound to HEAD {sha8}"),
                artifact: Some(artifact),
            });
        }
        Ok(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aor::mem::{MemArtifacts, MemStore, TestContext};
    use aor::ArtifactSink;
    use serde_json::json;

    fn ev(detail: serde_json::Value, ts_ms: u64) -> Event {
        Event {
            kind: EventKind::Verify,
            detail,
            ts_ms,
        }
    }

    #[test]
    fn suite_wide_commands_classify_full() {
        for c in [
            "cargo test",
            "cargo test --workspace --all-features",
            "cargo test --features foo",
            "cargo nextest run",
            "cargo nextest run --release",
            "cd crates && cargo test",
            "pytest",
            "pytest -xvs",
            "pytest -n auto",
            "pytest --maxfail 2 -q",
            "flutter test",
            "flutter test --coverage",
            "npm test",
            "npm run test",
        ] {
            assert_eq!(classify(c), VerifyClass::Full, "{c}");
        }
    }

    #[test]
    fn filtered_commands_classify_targeted() {
        for c in [
            "cargo test my_test",
            "cargo test -p aor-verify",
            "cargo test --package=aor-verify",
            "cargo test --test integration",
            "cargo test -- it_filters",
            "cargo nextest run --filter-expr 'test(foo)'",
            "cargo build",
            "echo cargo test",
            "pytest tests/test_foo.py",
            "pytest -k login",
            "pytest -klogin",
            "pytest --deselect tests/x.py",
            "pytest --lf",
            "flutter test test/widget_test.dart",
            "flutter test --plain-name login",
            "npm test -- --watch",
            "npm run test:e2e",
            "npm run build",
            "make test",
            "",
        ] {
            assert_eq!(classify(c), VerifyClass::Targeted, "{c}");
        }
    }

    #[test]
    fn non_verify_events_are_ignored() {
        let gate = VerifyGate::new();
        let mut ctx = TestContext::new(MemStore::new(), MemArtifacts::new());
        let e = Event {
            kind: EventKind::ToolCall,
            detail: json!({ "command": "cargo test" }),
            ts_ms: 1,
        };
        assert!(gate.observe(&e, &mut ctx).unwrap().is_empty());
        assert!(ctx.emitted.is_empty());
    }

    #[test]
    fn missing_command_warns() {
        let gate = VerifyGate::new();
        let mut ctx = TestContext::new(MemStore::new(), MemArtifacts::new());
        for detail in [json!({ "task": "t1" }), json!({ "command": 7 })] {
            let f = gate.observe(&ev(detail, 1), &mut ctx).unwrap();
            assert_eq!(f.len(), 1);
            assert_eq!(f[0].severity, Severity::Warn);
            assert!(f[0].message.contains("command"));
        }
    }

    #[test]
    fn targeted_verification_is_info_without_record() {
        let gate = VerifyGate::new();
        let mut ctx = TestContext::new(MemStore::new(), MemArtifacts::new());
        let f = gate
            .observe(
                &ev(json!({ "command": "cargo test -p aor-verify" }), 1),
                &mut ctx,
            )
            .unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Info);
        assert_eq!(f[0].message, "targeted verification");
        assert!(ctx.emitted.is_empty());
    }

    #[test]
    fn first_full_regression_is_info() {
        let gate = VerifyGate::new();
        let mut ctx = TestContext::new(MemStore::new(), MemArtifacts::new());
        let f = gate
            .observe(
                &ev(json!({ "command": "cargo test", "task": "t1" }), 1_000),
                &mut ctx,
            )
            .unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Info);
        assert_eq!(f[0].message, "first full regression recorded");
    }

    #[test]
    fn repeated_full_regression_warns() {
        let gate = VerifyGate::new();
        let mut ctx = TestContext::new(MemStore::new(), MemArtifacts::new());
        let t0 = 1_000_000;
        let detail = json!({ "command": "cargo test", "task": "t1" });

        gate.observe(&ev(detail.clone(), t0), &mut ctx).unwrap();

        let f = gate
            .observe(&ev(detail.clone(), t0 + 60_000), &mut ctx)
            .unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Warn);
        assert!(f[0].message.contains("repeated full regression #2"));
        assert!(f[0].message.contains("t1"));

        let f = gate.observe(&ev(detail, t0 + 120_000), &mut ctx).unwrap();
        assert_eq!(f[0].severity, Severity::Warn);
        assert!(f[0].message.contains("#3"));
    }

    #[test]
    fn full_counters_are_scoped_by_task() {
        let gate = VerifyGate::new();
        let mut ctx = TestContext::new(MemStore::new(), MemArtifacts::new());
        for task in ["a", "b"] {
            let f = gate
                .observe(
                    &ev(json!({ "command": "cargo test", "task": task }), 1_000),
                    &mut ctx,
                )
                .unwrap();
            assert_eq!(f[0].severity, Severity::Info, "task {task}");
            assert_eq!(f[0].message, "first full regression recorded");
        }
    }

    #[test]
    fn evidence_binds_head_and_emits_record() {
        let gate = VerifyGate::new();
        let mut ctx = TestContext::new(MemStore::new(), MemArtifacts::new());
        let e = ev(
            json!({
                "command": "cargo test",
                "task": "t1",
                "head_sha": "abcdef1234567890",
                "result": "pass",
            }),
            42,
        );
        let f = gate.observe(&e, &mut ctx).unwrap();
        assert_eq!(f.len(), 1); // the first-full Info finding

        assert_eq!(ctx.emitted.len(), 1);
        let rec = &ctx.emitted[0];
        assert_eq!(rec.gate, "verify");
        assert!(rec.summary.contains("abcdef12"));

        let id = rec.artifact.clone().expect("artifact id");
        assert_eq!(id, "verify/t1-abcdef1234567890.json");
        let bytes = ctx.artifacts.read(&id).unwrap();
        let parsed: VerifyEvidence = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed.task, "t1");
        assert_eq!(parsed.head_sha, "abcdef1234567890");
        assert_eq!(parsed.command, "cargo test");
        assert_eq!(parsed.result, "pass");
        assert_eq!(parsed.ts_ms, 42);
    }

    #[test]
    fn evidence_is_written_for_targeted_runs_too() {
        let gate = VerifyGate::new();
        let mut ctx = TestContext::new(MemStore::new(), MemArtifacts::new());
        let e = ev(
            json!({
                "command": "cargo test -p aor-verify",
                "head_sha": "deadbeef00",
                "result": "fail",
            }),
            7,
        );
        let f = gate.observe(&e, &mut ctx).unwrap();
        assert_eq!(f[0].message, "targeted verification");
        assert_eq!(ctx.emitted.len(), 1);
        assert_eq!(
            ctx.emitted[0].artifact.as_deref(),
            Some("verify/default-deadbeef00.json")
        );
    }

    #[test]
    fn evidence_needs_both_head_sha_and_result() {
        let gate = VerifyGate::new();
        let mut ctx = TestContext::new(MemStore::new(), MemArtifacts::new());
        let e = ev(
            json!({ "command": "cargo test", "head_sha": "abcdef1234567890" }),
            1,
        );
        gate.observe(&e, &mut ctx).unwrap();
        assert!(ctx.emitted.is_empty());
    }
}
