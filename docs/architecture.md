# docs/architecture.md — Nanokernel + Capability Packs

> **Purpose:** define CrustCore's nanokernel-plus-capability-packs architecture —
> the sync deterministic kernel, the boundary adapters that translate the dirty
> outside world into kernel events, the crate workspace map, and the hard rules
> for what the kernel must never know about.

**Cross-links:** [`ROADMAP.md` §5](../ROADMAP.md) (architecture overview),
[`ROADMAP.md` §6](../ROADMAP.md) (project structure), [`ROADMAP.md` §2](../ROADMAP.md)
(product tiers), [`CLAUDE.md` §3](../CLAUDE.md) (architecture in one page),
[`INVARIANTS.md`](../INVARIANTS.md) (the 20 product laws).
**Sibling docs:** [`nano-size-budget.md`](./nano-size-budget.md),
[`policy.md`](./policy.md), [`event-log.md`](./event-log.md),
[`receipts.md`](./receipts.md), [`backend-contract.md`](./backend-contract.md),
[`security-model.md`](./security-model.md), [`sandbox.md`](./sandbox.md).

---

## 1. The core concept: a nanokernel, not a framework

CrustCore is a **nanokernel plus capability packs** ([`ROADMAP.md` §5.1](../ROADMAP.md)).
The trusted core is a tiny, synchronous, deterministic state machine. Everything
that touches the network, a TLS stack, a database, a provider SDK, a chat
transport, or arbitrary code execution lives *outside* the kernel, in adapters
and sidecars that translate the outside world into kernel events and translate
kernel actions back out.

```text
crustcore-kernel
  - sync deterministic state machine
  - task/job state
  - policy/risk decisions
  - capability tokens
  - approval state
  - event/receipt framing
  - artifact handles
  - backend result contract

adapters / sidecars
  - model transport       (crustcore-net)
  - Telegram, GitHub      (crustcore-net / crustcore-daemon)
  - MCP gateway/client    (crustcore-mcp)
  - code intelligence     (crustcore-index)
  - memory / index        (crustcore-index)
  - external workers      (Codex CLI, Claude Code)
  - telemetry
```

This split is what makes the flagship size claim (`crustcore-nano` < 800kB
stripped) *achievable as architecture*, not as a compiler trick. It is also what
makes the kernel **auditable**: a maintainer can read the whole kernel, prove
what is allowed, and replay what happened, because the kernel never drags in a
multi-megabyte async/TLS/DB stack. See [`nano-size-budget.md`](./nano-size-budget.md)
for why size is treated as an architectural property and how it is enforced
(invariants 19, 20).

The rationale is drawn from the three reference projects ([`ROADMAP.md` §1](../ROADMAP.md)):
NilCore (verifier-owned completion, throwaway worktrees, bounded autonomy),
NullClaw (size-is-architecture, swappable subsystems behind small contracts,
loopback posture, allowlists), and ZeroClaw (feature-flagged layered crates, risk
profiles, tool receipts, provider routing) — without becoming any of them.

---

## 2. The kernel step function

The kernel is a single deterministic reducer. The entire trusted control flow is
expressed as `event -> state mutation -> bounded action list`.

```rust
pub struct Kernel {
    tasks: TaskArena,
    jobs: JobArena,
    approvals: ApprovalArena,
    budgets: BudgetState,
    policy: PolicySnapshot,
    ready: VecDeque<JobId>,
}

impl Kernel {
    pub fn step(&mut self, event: Event) -> SmallVec<[Action; 4]> {
        // deterministic event -> state mutation -> bounded action list
    }
}
```

### 2.1 Why this shape

- **`&mut self` + owned `Event` in, `SmallVec<[Action; 4]>` out.** The kernel does
  not perform side effects; it *describes* them as `Action`s for adapters to
  execute. This is the structural enforcement of invariant 8 (*every side effect
  passes through policy*): an effect cannot happen unless the kernel emits an
  action for it, and actions are only emitted after policy has been consulted
  inside `step`.
- **`SmallVec<[Action; 4]>`** keeps the common case (zero to four actions)
  allocation-free. Most events produce a small, bounded fan-out. The `4` is a
  measured inline capacity, not a hard cap — larger fan-outs spill to the heap
  but should be rare; a step that routinely spills is a design smell.
- **Arenas (`TaskArena`, `JobArena`, `ApprovalArena`)** hold state in compact,
  index-addressed storage rather than scattered `Box`/`Rc` graphs. This keeps the
  hot path cache-friendly and the allocation profile flat (see hot-path budgets
  in [`nano-size-budget.md`](./nano-size-budget.md) §3).
- **`PolicySnapshot`** is an immutable, point-in-time view of policy that the step
  reads. Policy is *data the kernel evaluates*, not behavior the kernel imports.
  See [`policy.md`](./policy.md).

### 2.2 Properties of `step` (non-negotiable)

```text
- synchronous
- deterministic
- allocation-light
- easy to benchmark
- no async runtime
- no network
- no database
- no tool execution
```

These properties are tested and budgeted:

- **Deterministic:** the same `(state, event)` always yields the same
  `(state', actions)`. This is what makes replay (`crustcore inspect`,
  [`event-log.md`](./event-log.md)) and golden tests possible. Property tests
  assert impossible transitions never occur (Phase 1, P1.6): a killed task emits
  no new tool actions; an irreversible action cannot be emitted without an
  approval path (invariant 14); budget exhaustion pauses the task (invariant 11).
- **Synchronous / no async:** there is no `.await` in the kernel. I/O latency,
  retries, and concurrency belong to adapters. The kernel reasons about *leases,
  heartbeats, and timeouts* as state and timer events, not as futures (invariant
  12).
- **Allocation-light + benchmarkable:** `benches/kernel_step.rs` targets
  sub-microsecond typical step time ([`ROADMAP.md` §17.2](../ROADMAP.md)). The
  `SmallVec` return and arena storage exist to hit that.
- **No tool execution / no DB / no network:** the kernel cannot open a socket,
  run a process, or query a store. It can only emit an `Action` asking an adapter
  to do so. This is the load-bearing boundary for invariants 8, 9, and 10.

### 2.3 Edge cases & testing notes

- **Idempotent re-delivery:** adapters may redeliver an event (e.g., a Telegram
  update retried). The kernel keys mutations on monotonic `EventSeq` /
  identifiers so replays of an already-applied event are no-ops, not double
  effects. Test: feed the same `ToolCompleted` twice; assert one state change and
  no duplicate action.
- **Bounded fan-out:** a single event must never produce an unbounded action list
  (e.g., "notify every task"). Tests assert the action count stays bounded.
- **Killed/terminal states are absorbing:** events arriving for a `Killed` /
  `Completed` / `Failed` task produce at most audit actions, never tool actions.
  Acceptance criterion in [`ROADMAP.md` §18 Phase 1](../ROADMAP.md).
- **No panics on hostile input:** the kernel receives only typed `Event`s (the
  adapter already parsed raw JSON), but malformed/contradictory state must
  degrade to a `RiskDetected`/`Failed` transition, never a panic. Kernel code is
  `#![forbid(unsafe_code)]` ([`CLAUDE.md` §6.5](../CLAUDE.md)).

---

## 3. Boundary adapters and the event/action translation table

Adapters are the only code allowed to touch raw external formats. They translate
**external realities into kernel events**, and **kernel actions into external
operations** ([`ROADMAP.md` §5.3](../ROADMAP.md)).

```text
Telegram raw update -> InboundEnvelope    -> Event::UserTurn
GitHub webhook      -> GitHubEnvelope     -> Event::GitHubObserved
Model response      -> AgentObservation   -> Event::ModelOutput
Tool result         -> ToolReceipt + Artifact -> Event::ToolCompleted
Kernel action       -> adapter-specific operation
```

| External reality | Adapter normalization | Kernel event |
| --- | --- | --- |
| Telegram raw update (JSON) | `InboundEnvelope` (dedup, normalize, chat-ID bind) | `Event::UserTurn` |
| GitHub webhook (JSON) | `GitHubEnvelope` (untrusted comment/issue body wrapped as data) | `Event::GitHubObserved` |
| Model response (provider-specific) | `AgentObservation` (provider format stripped) | `Event::ModelOutput` |
| Tool result + artifact | `ToolReceipt` + `Artifact` handle | `Event::ToolCompleted` |
| Provider/transport/process error | error envelope (secrets redacted) | `Event::*Failed` / `Event::RiskDetected` |

The corresponding `EventKind` enum (the on-log representation) lives in
[`event-log.md`](./event-log.md) and [`ROADMAP.md` §7.3](../ROADMAP.md).

### 3.1 The translation rules

- **The kernel never sees raw Telegram/GitHub/MCP/provider JSON** ([`ROADMAP.md`
  §5.3](../ROADMAP.md), [`CLAUDE.md` §3](../CLAUDE.md)). If a struct in
  `crustcore-kernel` contains a provider-shaped field, that is a layering bug.
- **All inbound external content is untrusted data** (invariant 7). Adapters wrap
  repo files, issue/PR comments, web pages, MCP output, and shell output as data,
  with the invariant reminder attached ([`security-model.md`](./security-model.md),
  [`ROADMAP.md` §9.3](../ROADMAP.md)). Untrusted content never becomes a control
  signal for policy, secrets, approvals, or user communication.
- **Receipts and artifacts are minted at the boundary.** A tool result only
  becomes a kernel event (`Event::ToolCompleted`) accompanied by a `ToolReceipt`
  generated by CrustCore (invariant 10; [`receipts.md`](./receipts.md)). No
  receipt → the kernel will not surface the result as a model-visible tool claim.
- **Actions are interpreted, not executed, by the kernel.** When `step` emits
  `Action::RunCommand`, `Action::SendTelegram`, `Action::OpenPr`, the relevant
  adapter performs it under the appropriate capability token and sandbox profile
  (invariants 8, 9). Irreversible actions carry an `Approved<…>` token
  ([`policy.md`](./policy.md), invariant 14).

### 3.2 Data flow: kernel ↔ adapters (end to end)

```text
  [ outside world ]                [ adapter ]                 [ kernel ]
  Telegram update     ─normalize─▶ InboundEnvelope ─event─▶ Kernel::step
  GitHub webhook      ─normalize─▶ GitHubEnvelope  ─event─▶      │
  Model response      ─normalize─▶ AgentObservation ─event─▶     │  (mutates
  Tool result+receipt ─frame────▶ ToolReceipt+Artifact ─event─▶ │   arenas)
                                                                  │
                                                          SmallVec<[Action;4]>
                                                                  │
  adapter executes  ◀─interpret── Action::RunCommand / SendTelegram /
                                  OpenPr / RequestApproval / AppendEvent ...
```

Every meaningful state change the kernel makes is also written to the
append-only, hash-chained event log ([`event-log.md`](./event-log.md)) so the run
is replayable and tamper-evident. The kernel emits `Action::AppendEvent`; the
eventlog adapter frames and chains it.

---

## 4. The crate workspace map

Recommended workspace ([`ROADMAP.md` §6](../ROADMAP.md), [`CLAUDE.md` §5](../CLAUDE.md)).
The `crates/`, `tests/`, `benches/`, `xtask/` trees are created in Phase 0; until
then the repo is documentation-first.

| Crate | Purpose |
| --- | --- |
| `crustcore` | The top-level binary package. The flagship **`crustcore-nano`** artifact is this package built with `--no-default-features --features nano` under the `nano` profile (what the CI size gate builds with `-p crustcore`). "nano" is a feature/profile of `crustcore`, **not** a separate crate. |
| `crustcore-kernel` | Tiny sync state machine: tasks/jobs/events/actions, policy outcomes, budgets, approvals, receipt/event framing. The trusted core. |
| `crustcore-types` | Shared IDs/enums with no heavy deps (`TaskId`, `JobId`, `EventSeq`, …). Keeps the kernel and adapters speaking the same types without coupling. |
| `crustcore-policy` | Compact risk/capability/approval evaluator. Produces `PolicySnapshot` and capability tokens. See [`policy.md`](./policy.md). |
| `crustcore-eventlog` | Compact append-only event log + hash chain + JSONL export. See [`event-log.md`](./event-log.md). |
| `crustcore-receipts` | Tool receipts + MAC/hash chain. See [`receipts.md`](./receipts.md). |
| `crustcore-path` | `ConfinedPath` types, symlink-safe path resolution, worktree confinement. |
| `crustcore-secrets` | Secret handles/types; native keychain/vault store only outside nano. See [`secrets.md`](./secrets.md). |
| `crustcore-runner` | Process runner; minimal in nano (spawn, bounded capture, timeout/kill). |
| `crustcore-sandbox` | `CommandSpec` + sandbox backend wrappers (Landlock/bubblewrap/seatbelt/...). See [`sandbox.md`](./sandbox.md). |
| `crustcore-worktree` | Git worktree wrapper (throwaway worktree per task). |
| `crustcore-backend` | The one `CodingBackend` contract (`BackendResult`, Unverified/VerifiedPatch). See [`backend-contract.md`](./backend-contract.md). |
| `crustcore-cli` | Tiny CLI for nano; rich CLI is a feature outside nano. CLI is setup/admin/emergency only (invariant 16). |
| `crustcore-net` | Provider/Telegram/GitHub helper sidecar (Tokio/TLS/providers). |
| `crustcore-daemon` | Long-running runtime (Telegram/GitHub loops, leases, supervision). |
| `crustcore-mcp` | MCP gateway/client/server + code-mode. |
| `crustcore-index` | Optional repo memory / code intelligence. |
| `crustcore-eval` | Eval and red-team harness. |
| `crustcore-full` | All-in-one convenience composition (never the flagship size claim). |

Supporting trees: `docs/` (this file and siblings), `tests/{redteam,golden,fixtures}`,
`benches/{kernel_step,event_append,policy_check,path_confine}.rs`,
`xtask/{size_check,release,verify}`.

---

## 5. Dependency policy by crate

Hard rules ([`ROADMAP.md` §6.1](../ROADMAP.md), [`CLAUDE.md` §5.1](../CLAUDE.md)).
These exist to enforce invariants 19 and 20: nothing heavy leaks into nano, and
unused capabilities cost zero linked code.

| Crate | Allowed | Forbidden |
| --- | --- | --- |
| `crustcore-kernel` | `std`, measured `smallvec`/`arrayvec`, `thiserror` if measured | tokio, reqwest, serde_json, clap, sqlx, rmcp, axum |
| `crustcore-nano` | kernel crates, tiny CLI parser, process runner, eventlog, path/sandbox/worktree | embedded TLS, DB, MCP SDK, rich CLI, provider SDKs |
| `crustcore-net` | tokio, minimal HTTP/TLS, serde/serde_json, provider clients | — |
| `crustcore-mcp` | `rmcp` or custom MCP depending on feature | leaking any of it into nano |
| `crustcore-full` | convenience dependencies | **any** dependency leaking into nano |

Nano may **invoke external commands** but may not **link** their stacks:

```text
- git
- sandbox backend command
- codex
- claude
- crustcore-net helper
- crustcore-mcp helper
```

A dependency may enter nano only if it replaces more code than it adds, pulls no
second runtime/TLS/DB stack, stays within the size budget, has a clear
maintenance/security story, and ships `cargo-bloat` output on the PR
([`CLAUDE.md` §6.4](../CLAUDE.md), [`ROADMAP.md` §20.3](../ROADMAP.md)).

---

## 6. Product tiers

CrustCore is a **family of binaries/crates**, not one forced all-in-one binary
([`ROADMAP.md` §2](../ROADMAP.md), [`CLAUDE.md` §3](../CLAUDE.md)).

| Tier | Size target | Purpose |
| --- | --- | --- |
| `crustcore` / `crustcore-nano` | **< 800kB** stripped (stretch < 600kB) | the trustworthy local coding verifier harness |
| `crustcore-net` | 3–8MB | network + provider sidecar (Tokio, minimal HTTP/TLS, OpenAI/Anthropic/OpenRouter/local adapters, Telegram, GitHub, credential proxy) |
| `crustcore-daemon` | 4–10MB | long-running runtime: Telegram channel, GitHub task/PR loop, admin socket, leases/heartbeats/recovery, provider health |
| `crustcore-mcp` | 3–10MB | MCP gateway/client/server, code-mode stubs, per-server trust registry, per-tool policy, redaction |
| `crustcore-index` | 2–8MB | repo memory / code-intelligence: summaries, symbol graph, optional AST/embeddings, failure/convention memory |
| `crustcore-full` | 8–25MB+ | all-in-one convenience build; **not** the flagship size claim |

The nano tier contains exactly the trusted control plane ([`ROADMAP.md` §2.1](../ROADMAP.md)):
sync deterministic kernel, tiny CLI parser, task/job state machine, policy/risk
engine, typed capabilities/approvals/confined paths, compact append-only event
log, tool receipts, artifact handles, worktree manager wrapper, structured
file/patch/git tools, sandbox command wrapper, process runner, external
transport/helper protocol, verify loop, inspect/export. Everything else is a
sidecar or capability pack.

---

## 7. What the kernel must never know about

The kernel is deliberately ignorant. It **must not** contain or depend on:

```text
- HTTP / TLS                 (lives in crustcore-net)
- Telegram payload shapes    (adapter normalizes to Event::UserTurn)
- GitHub JSON shapes         (adapter normalizes to Event::GitHubObserved)
- MCP transports             (crustcore-mcp)
- SQL / any database         (crustcore-index, optional)
- provider-specific APIs     (crustcore-net adapters)
- an async runtime (tokio)   (kernel is synchronous)
- tool execution             (runner/sandbox adapters do this under tokens)
- raw secret material        (only handles cross into kernel space; see secrets.md)
```

If any of these appear inside `crustcore-kernel` (or are linked into
`crustcore-nano`), that is an architecture violation and a CI failure
([`nano-size-budget.md`](./nano-size-budget.md), invariants 19, 20). The
forbidden-dependency check in `cargo xtask verify` ([`CLAUDE.md` §9.1](../CLAUDE.md))
exists precisely to catch this.

The positive framing — the sentence the architecture is built to make true
([`ROADMAP.md` §23](../ROADMAP.md), [`CLAUDE.md` §12](../CLAUDE.md)):

```text
I can read the kernel.
I can prove what is allowed.
I can replay what happened.
I can verify a patch shipped because tests passed.
I can show secrets did not enter prompts.
I can disable every optional surface and keep the harness tiny.
```

That sentence is achievable only because the kernel is small, synchronous,
deterministic, and ignorant of everything heavy. Keep it that way.
