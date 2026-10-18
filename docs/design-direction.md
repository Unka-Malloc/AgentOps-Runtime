# Design direction: runtime-max gates vs native-max adapters

Two complementary frameworks abstract over agent hosts in **opposite
directions**. They are complementary, not competing:

- [Adapter-For-All-Agents](https://github.com/Unka-Malloc/Adapters-for-All-Agents)
  (crate [`a4aa`](https://crates.io/crates/a4aa)) and
  [Agents-With-Profiles](https://github.com/Unka-Malloc/Agents-With-Profiles)
  (crate [`agents-with-profiles`](https://crates.io/crates/agents-with-profiles))
  take the **bottom-up** direction: agent-native capability → common
  language. The native agent is maximal; the framework translates
  whatever the agent natively offers and never invents semantics.
- AgentOps-Runtime (this repo) takes the **top-down** direction: a
  standard runtime language → the subset each host can express. The
  runtime language is maximal; gates define full semantics and a host
  receives the projection its native capabilities can carry.

| | AgentOps-Runtime (this repo) | a4aa / awp |
|---|---|---|
| Direction | **Top-down**: standard runtime language → projected subset per host | **Bottom-up**: agent-native capability → common language |
| What is maximal | **The runtime language.** Gates define full semantics; a host receives the subset its native capabilities can express | **The native agent.** The framework translates whatever the agent natively offers; it never invents semantics the agent lacks |
| Completeness rule | Every enforcement channel a gate applies to is declared in `profiles`; a host's weaker projection is marked `Incomplete` — never silently removed | Every interaction form an agent natively offers gets its own adapter; partial support is declared, never dropped |
| Failure attribution | A weak projection is a host capability boundary — not a defect in the language | Missing coverage is an adapter gap |

Both directions share one rule: **partial support is an explicit
declaration, never silent removal.** AgentOps-Runtime encodes it as
profile completeness (`GateDescriptor.profiles`); a4aa encodes it as
lane completeness (`capabilities()`).

## What this means for AgentOps-Runtime

Gate crates own the **standard language of agent-runtime semantics**:
dispatch contracts, payload budgets, handoff artifacts, verification
evidence, closure sweeps, decision integrity, resource exclusivity,
wait discipline. That language is defined at full strength — including
fail-closed verdicts — independent of what any single host can do.

Host adapters **project a subset** of that language onto a host's native
capabilities:

- `managed-dispatch` — a managed host executes dispatches itself, so the
  full profile lands, including fail-closed rejection.
- `hook-observe` — a lifecycle-hook host can observe and raise threshold
  events but never blocks native behavior; that subset is the complete
  hook-observe projection, not a crippled gate.
- `outbound-boundary` — an outbound-boundary host executes outbound
  operations; the evidence subset lands as a checker entry.

Corollaries:

- Gate semantics **never shrink to fit a weak host**. A host without a
  pre-compaction hook simply cannot project Handoff-Protocol's Compact
  surface — the profile reports `Incomplete`; the gate's definition
  stays whole.
- Gate crates **never block** — blocking is a semantic the language
  contains, executed only by hosts that are the actor (managed-dispatch,
  outbound-boundary). The hook-observe projection is advisory by
  construction.
- New gates are added at language strength; subset adequacy is a
  per-adapter question answered later.

## Composition

The two abstractions describe the same hosts on different axes:

- a4aa answers *"what does this host natively speak?"* — its per-agent
  descriptor crates are a capability map.
- AgentOps-Runtime answers *"which subset of the runtime language lands
  here?"* — its adapters project gate semantics onto whatever the host
  can express.

A capability map produced by the native-max direction is the natural
input for this runtime's subset projection: it tells the runtime how
much of the language a host can carry, and the runtime reports the
remainder as an explicit `Incomplete` rather than shrinking its
semantics to fit.
