# Agent rules for AgentOps-Runtime

## Gate independence (hard rule)

Gates — `handoff`, `dispatch`, `payload`, `verify`, `close`, `decision`,
`resource`, `wait` — are separate mechanisms, not variants of one.
Architecture keeps them isolated in both directions:

- **Runtime**: a gate's failure never propagates to another gate. No gate
  holds global state a sibling gate depends on.
- **Code**: `aor-<gate>` must not import another gate's internals. Shared
  machinery lives in `aor` core — gate contract, event/finding types,
  record schema, store handles, sweep scheduling. When two gates need the
  same helper, move it into `aor` instead of importing across gates.
- **Development**: work on one gate must not require changes to a sibling
  gate. `aor-runtime` is the only crate allowed to depend on every gate;
  host adapters (managed-dispatch, hook-observe, outbound-boundary) live outside gate crates.
- **Dependency shape**: `aor-<gate>` depends on `aor` and nothing else.

## Gate completeness (hard rule)

Every enforcement channel a gate applies to is declared in its
`DESCRIPTOR.profiles`: `managed-dispatch` (managed-dispatch channel —
the host executes dispatches itself, may fail closed), `hook-observe` (lifecycle-observation channel —
observe + collect + threshold events only), `outbound-boundary`
(outbound checker channel).. A partially implemented profile is declared
`Incomplete` — never claimed implemented, and never silently dropped
because "another channel covers it".

## Enforcement ownership (hard rule)

Gate crates emit findings and verdicts; they never block host operations
themselves. Fail-closed execution belongs to the executor that owns the
action — the managed-dispatch host for dispatch, the outbound boundary for
outbound. The hook-observe
channel observes, collects and raises threshold events; native host
behavior is respected, not overridden.

## Verify

`scripts/verify.sh` — fmt + clippy + tests across the workspace.
