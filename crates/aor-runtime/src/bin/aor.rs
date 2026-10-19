//! aor — AgentOps-Runtime CLI.
//!
//! Subcommands: registry | observe | sweep | records | memory | import.
//! Data home: `$AGENTOPS_HOME` or `~/.agentops` (agentops.db + artifacts/).

use aor::{Enforcement, Event, EventKind, MemoryEntry, ProfileState};
use aor_runtime::{gate_descriptors, render_findings, Runtime};
use std::path::PathBuf;

fn data_home() -> PathBuf {
    if let Ok(h) = std::env::var("AGENTOPS_HOME") {
        return PathBuf::from(h);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".agentops")
}

fn open_runtime() -> aor::Result<Runtime> {
    let home = data_home();
    let store = aor_store::SqliteStore::open(home.join("agentops.db"))?;
    let artifacts = aor::mem::FsArtifacts::new(home.join("artifacts"));
    Ok(Runtime::new(Box::new(store), Box::new(artifacts)))
}

fn flag_value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn usage() -> ! {
    eprintln!(
        "usage:\n  aor registry\n  aor observe <dispatch|compact|verify|close|toolcall> '<json>'\n  aor check <dispatch|compact|verify|close|toolcall> '<json>'\n        exit 0 allow, 10 warn, 20 refuse — the outbound-boundary entry\n  aor sweep\n  aor records [--gate G] [--limit N]\n  aor memory list [--kind K] [--limit N]\n  aor memory add --kind K --title T --body B [--tags a,b] [--source S]\n  aor import sqlite <db> <table> <kind>\n  aor import vault <dir>\n  aor import inbox <file>"
    );
    std::process::exit(2)
}

fn event_kind(s: &str) -> Option<EventKind> {
    match s {
        "dispatch" => Some(EventKind::Dispatch),
        "compact" => Some(EventKind::Compact),
        "verify" => Some(EventKind::Verify),
        "close" => Some(EventKind::Close),
        "toolcall" => Some(EventKind::ToolCall),
        _ => None,
    }
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> aor::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("registry") => {
            for d in gate_descriptors() {
                let profiles = d
                    .profiles
                    .iter()
                    .map(|p| {
                        let channel = match p.enforcement {
                            Enforcement::ManagedDispatch => "managed-dispatch",
                            Enforcement::HookObserve => "hook-observe",
                            Enforcement::OutboundBoundary => "outbound-boundary",
                        };
                        let state = match p.state {
                            ProfileState::Implemented => "ok",
                            ProfileState::Incomplete => "incomplete",
                        };
                        format!("{channel}:{state}")
                    })
                    .collect::<Vec<_>>()
                    .join("  ");
                println!("{:<9} {:<55} {}", d.name, profiles, d.summary);
            }
        }
        Some("observe") => {
            let kind = args.get(1).and_then(|s| event_kind(s));
            let detail = args
                .get(2)
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or(serde_json::Value::Null);
            let kind = kind.ok_or_else(|| aor::Error::msg("unknown event kind"))?;
            let rt = open_runtime()?;
            let findings = rt.dispatch(&Event::new(kind, detail))?;
            let out = render_findings(&findings);
            if !out.is_empty() {
                println!("{out}");
            }
        }
        Some("check") => {
            let kind = args.get(1).and_then(|s| event_kind(s));
            let detail = args
                .get(2)
                .and_then(|s| serde_json::from_str(s).ok())
                .unwrap_or(serde_json::Value::Null);
            let kind = kind.ok_or_else(|| aor::Error::msg("unknown event kind"))?;
            let rt = open_runtime()?;
            let findings = rt.dispatch(&Event::new(kind, detail))?;
            let out = render_findings(&findings);
            if !out.is_empty() {
                println!("{out}");
            }
            match aor::Verdict::of(&findings) {
                aor::Verdict::Allow => println!("verdict: allow"),
                aor::Verdict::Warn => {
                    println!("verdict: warn");
                    std::process::exit(10);
                }
                aor::Verdict::Refuse => {
                    println!("verdict: refuse");
                    std::process::exit(20);
                }
            }
        }
        Some("sweep") => {
            let rt = open_runtime()?;
            let findings = rt.sweep()?;
            let out = render_findings(&findings);
            println!("{}", if out.is_empty() { "clean".into() } else { out });
        }
        Some("records") => {
            let rt = open_runtime()?;
            let limit = flag_value(&args, "--limit")
                .and_then(|s| s.parse().ok())
                .unwrap_or(50);
            let gate = flag_value(&args, "--gate");
            for r in rt.store().records(gate.as_deref(), limit)? {
                println!("{}", serde_json::to_string(&r).unwrap_or_default());
            }
        }
        Some("memory") => match args.get(1).map(String::as_str) {
            Some("list") => {
                let rt = open_runtime()?;
                let limit = flag_value(&args, "--limit")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(50);
                let kind = flag_value(&args, "--kind");
                for m in rt.store().memory(kind.as_deref(), limit)? {
                    println!("{} [{}] {}", m.id, m.kind, m.title);
                }
            }
            Some("add") => {
                let rt = open_runtime()?;
                let need = |n: &str| -> aor::Result<String> {
                    flag_value(&args, n).ok_or_else(|| aor::Error::msg(format!("missing {n}")))
                };
                let now = aor::now_ms();
                let id = rt.store().append_memory(&MemoryEntry {
                    id: 0,
                    kind: need("--kind")?,
                    title: need("--title")?,
                    body: need("--body")?,
                    tags: flag_value(&args, "--tags")
                        .map(|t| t.split(',').map(String::from).collect())
                        .unwrap_or_default(),
                    source: flag_value(&args, "--source"),
                    created_ms: now,
                    updated_ms: now,
                })?;
                println!("memory id={id}");
            }
            _ => usage(),
        },
        Some("import") => {
            let rt = open_runtime()?;
            let report = match args.get(1).map(String::as_str) {
                Some("sqlite") => {
                    let db = args.get(2).ok_or_else(|| aor::Error::msg("missing db"))?;
                    let table = args
                        .get(3)
                        .ok_or_else(|| aor::Error::msg("missing table"))?;
                    let kind = args.get(4).ok_or_else(|| aor::Error::msg("missing kind"))?;
                    aor_migrate::import_sqlite_table(
                        std::path::Path::new(db),
                        table,
                        kind,
                        rt.store(),
                    )?
                }
                Some("vault") => {
                    let dir = args.get(2).ok_or_else(|| aor::Error::msg("missing dir"))?;
                    aor_migrate::import_vault(std::path::Path::new(dir), rt.store())?
                }
                Some("inbox") => {
                    let f = args.get(2).ok_or_else(|| aor::Error::msg("missing file"))?;
                    aor_migrate::import_jsonl_inbox(std::path::Path::new(f), rt.store())?
                }
                _ => usage(),
            };
            println!(
                "{}: imported={} skipped={}",
                report.source, report.imported, report.skipped
            );
            for n in &report.notes {
                println!("  note: {n}");
            }
        }
        _ => usage(),
    }
    Ok(())
}
