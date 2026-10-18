# AgentOps-Runtime

Rust runtime that turns recurring agent-workflow failure modes into
registered **gates** — one mechanism, one crate — executed through host
adapters. The minimal ReAct agent (Pi) is the design baseline; every gate
is defined against what a plain agent loop provably emits.

Design premise: **the runtime language is maximal** — gates define full
semantics and host adapters project the subset each host can express.
The complementary bottom-up direction (agent-native capability lifted
into a common language) is
[Adapter-For-All-Agents](https://github.com/Unka-Malloc/Adapters-for-All-Agents)
(`a4aa`) and
[Agents-With-Profiles](https://github.com/Unka-Malloc/Agents-With-Profiles)
(`agents-with-profiles`). See
[docs/design-direction.md](docs/design-direction.md).

```
Pi agent (baseline executor)
        │
AgentOps-Runtime (this repo)
  aor            core contracts: gate trait, events, findings, records
  aor-<gate>     one crate per mechanism — policy only, no host code
  aor-runtime    assembly: gate registry + the `aor` binary
        │
┌───────┴────────┐
managed-dispatch    hook-observe       outbound-boundary
fail-closed      observe + events     fail-closed checker
managed agents   arbitrary hosts      push / PR / release
```

## Gates

| gate | crate | mechanism |
|---|---|---|
| handoff | `aor-handoff` | conclusion/verified/file-status index; references replace paraphrase |
| dispatch | `aor-dispatch` | dispatch contract: completion channel, exclusive writes, acceptance |
| payload | `aor-payload` | payload budget; windowed reads; oversized-input split |
| verify | `aor-verify` | targeted checks free; full regression once; HEAD-bound evidence |
| close | `aor-close` | stale delivery harvest; main/worktree reconciliation; DoD |
| decision | `aor-decision` | decision artifacts with stable id+digest; reference, not paraphrase |
| resource | `aor-resource` | manifest-declared shared/exclusive resources; intersection checks |
| wait | `aor-wait` | completion notifications over polling; bounded backoff |

## Enforcement model

Gate definitions are host-neutral. The same gate runs at different
strengths depending on which adapter executes it:

- `managed-dispatch` — a managed host owns the dispatch itself, so profiles here
  may fail closed.
- `hook-observe` — a lifecycle-hook host observes and raises threshold
  events; it never blocks native host behavior.
- `outbound-boundary` — outbound checkers; fail-closed on
  irreversible operations.

Every channel a gate applies to is declared in the gate's `profiles`;
partial support is `Incomplete`, never silently dropped.

## Storage (planned)

SQLite is the single source of truth — `records`, `rot_ledger`,
`todos_gates`, `memory`. Markdown, dashboards and any vault export are
read-only projections. Existing ledgers and curated notes migrate
through a one-time import with parity checks.

## Verify

`scripts/verify.sh` — fmt + clippy + tests.
