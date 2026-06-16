# docs/event-log.md — Append-Only Hash-Chained Event Log

> **Purpose:** define CrustCore's append-only, hash-chained event log — the
> `EventKind` set, the nano binary event frame format, hash-chaining and tamper
> detection, the append/read/verify chain, `crustcore inspect`, JSONL export,
> compact snapshots, and nano storage.

**Cross-links:** [`ROADMAP.md` §7.3](../ROADMAP.md) (events + frame format),
[`ROADMAP.md` §16.1](../ROADMAP.md) (nano storage),
[`ROADMAP.md` §18 Phase 2](../ROADMAP.md) (event log & receipts phase),
[`INVARIANTS.md` #10, #12](../INVARIANTS.md), [`CLAUDE.md` §10](../CLAUDE.md).
**Sibling docs:** [`receipts.md`](./receipts.md) (tool receipts ride on the log),
[`architecture.md`](./architecture.md) (kernel emits `Action::AppendEvent`),
[`backend-contract.md`](./backend-contract.md), [`policy.md`](./policy.md).

---

## 1. Why an append-only hash-chained log

Inspectability is a feature ([`ROADMAP.md` §1.1](../ROADMAP.md), NilCore lesson:
"there must be a local `inspect` command that verifies the audit chain and
explains what happened"). The event log is how a maintainer can *replay what
happened* and *prove what was allowed* ([`CLAUDE.md` §12](../CLAUDE.md)).

It is:

- **Append-only:** events are never mutated or deleted in place; corrections are
  new events. This makes the history a faithful record, not a mutable database.
- **Hash-chained:** each frame commits to the previous frame's hash, so any
  tampering with an earlier event invalidates every later frame. This is the
  enforcement substrate for invariant 10 (receipts) and part of invariant 12
  (job lifecycle is reconstructable from the log).
- **Compact + binary in nano:** the nano tier uses a compact binary event log
  with **JSONL export** for human inspection ([`ROADMAP.md` §1.1](../ROADMAP.md),
  §16.1). Nano links no database (invariant 19; forbidden-deps list in
  [`nano-size-budget.md`](./nano-size-budget.md)).

Every meaningful state change the kernel makes is an event
([`ROADMAP.md` §7.3](../ROADMAP.md)). The kernel emits `Action::AppendEvent`; the
`crustcore-eventlog` adapter frames, chains, and persists it
([`architecture.md` §3.2](./architecture.md)).

---

## 2. EventKind — the full set

```rust
pub enum EventKind {
    TaskCreated,
    TaskPlanned,
    JobQueued,
    JobLeased,
    ModelRequestStarted,
    ModelOutputReceived,
    ToolCallRequested,
    ToolCallApproved,
    ToolCallDenied,
    ToolCallStarted,
    ToolCallCompleted,
    SandboxStarted,
    CommandStarted,
    CommandOutputCaptured,
    CommandCompleted,
    PatchProposed,
    PatchVerified,
    PatchRejected,
    ApprovalRequested,
    ApprovalResolved,
    UserMessageQueued,
    UserSteerReceived,
    GitHubOperationRequested,
    GitHubOperationCompleted,
    SecretRequested,
    SecretHandleStored,
    RiskDetected,
    TaskCompleted,
    TaskFailed,
    TaskKilled,
}
```

These group along the system's spine:

- **Task/job lifecycle:** `TaskCreated`, `TaskPlanned`, `JobQueued`, `JobLeased`,
  `TaskCompleted`, `TaskFailed`, `TaskKilled` — the audit trail for invariants 11
  and 12 (budgets, leases/heartbeats/recovery).
- **Model interaction:** `ModelRequestStarted`, `ModelOutputReceived` — model
  output is recorded as untrusted observation (invariant 7).
- **Tool lifecycle:** `ToolCallRequested` → `ToolCallApproved`/`ToolCallDenied` →
  `ToolCallStarted` → `ToolCallCompleted`. Every `ToolCallCompleted` that becomes
  model-visible has a receipt (invariant 10; [`receipts.md`](./receipts.md)).
- **Execution:** `SandboxStarted`, `CommandStarted`, `CommandOutputCaptured`,
  `CommandCompleted` — proof that execution went through a sandbox profile
  (invariant 9; [`sandbox.md`](./sandbox.md)).
- **Patch flow:** `PatchProposed`, `PatchVerified`, `PatchRejected` — the
  verifier-owned completion trail (invariant 13; [`backend-contract.md`](./backend-contract.md)).
- **Approvals:** `ApprovalRequested`, `ApprovalResolved` — every approval is
  logged (invariants 4, 14; [`policy.md`](./policy.md)).
- **User comms:** `UserMessageQueued`, `UserSteerReceived` — queue/steer semantics
  ([`ROADMAP.md` §3.1](../ROADMAP.md); [`telegram.md`](./telegram.md)).
- **GitHub:** `GitHubOperationRequested`, `GitHubOperationCompleted`.
- **Secrets:** `SecretRequested`, `SecretHandleStored` — note these record the
  *handle* and the *request*, never secret material (invariants 1–3;
  [`secrets.md`](./secrets.md)).
- **Risk:** `RiskDetected` — any policy/sandbox/injection risk surfaced during a run.

---

## 3. The nano binary event frame format

Each event is written as a frame with these fields ([`ROADMAP.md` §7.3](../ROADMAP.md)):

```text
magic
version
seq
timestamp
task_id          (optional)
job_id           (optional)
actor
kind
visibility
redaction_state
payload_len
payload_hash
prev_hash
payload
frame_hash
```

| Field | Role / rationale |
| --- | --- |
| `magic` | file/format identifier; rejects non-CrustCore data fast |
| `version` | frame format version; lets the format evolve while old logs stay readable |
| `seq` | monotonic `EventSeq` (u64); ordering + idempotent re-delivery key ([`architecture.md` §2.3](./architecture.md)) |
| `timestamp` | wall-clock time of the event |
| `task_id?` | owning `TaskId` if any (optional) |
| `job_id?` | owning `JobId` if any (optional) |
| `actor` | who/what caused the event (kernel, adapter, user, worker) |
| `kind` | the `EventKind` discriminant |
| `visibility` | model-visible vs internal; gates what may enter model context |
| `redaction_state` | whether/how the payload was redacted (taint tracking — [`security-model.md`](./security-model.md)) |
| `payload_len` | length of the payload bytes |
| `payload_hash` | hash of the payload, so the chain commits to content without re-reading it |
| `prev_hash` | the previous frame's `frame_hash` — **the chain link** |
| `payload` | the (possibly redacted) event body |
| `frame_hash` | hash over the whole frame header + `payload_hash` + `prev_hash` |

Notes:

- **`visibility` + `redaction_state`** are first-class frame fields, not buried in
  the payload, so a verifier/inspector can reason about model-visibility and
  redaction *without parsing the payload*. Tainted/secret-bearing data must be
  redacted before it is written into any model-visible frame (invariants 2, 3;
  [`secrets.md`](./secrets.md), [`security-model.md`](./security-model.md)).
- **`payload_hash` separate from `payload`** lets verification and snapshotting
  commit to content cheaply and lets compaction drop bulky payloads while keeping
  the chain intact (§6).

---

## 4. Hash-chaining and tamper detection

The chain:

```text
frame[n].prev_hash  == frame[n-1].frame_hash
frame[n].frame_hash == H(header_fields ‖ payload_hash ‖ prev_hash)
```

```text
 ┌──────────┐      ┌──────────┐      ┌──────────┐
 │ frame n-1│      │ frame n  │      │ frame n+1│
 │ frame_hash├─────▶ prev_hash│      │          │
 │          │      │ frame_hash├─────▶ prev_hash│
 └──────────┘      └──────────┘      └──────────┘
```

Because every frame commits to the prior frame's hash, **any** modification,
reordering, insertion, or deletion of an earlier frame breaks the chain from that
point forward: the recomputed `frame_hash` no longer matches the `prev_hash`
stored in the next frame. The log is therefore **tamper-evident** — a maintainer
or `crustcore inspect` can detect that history was altered even though the log is
an ordinary file.

This is *tamper-evidence*, not *tamper-prevention*: an attacker with write access
can rewrite the whole chain from the tampered point onward. Detection of *that*
class of attack is layered with the receipt MAC chain ([`receipts.md`](./receipts.md),
which keys on a MAC the model/worker does not hold) and out-of-band anchoring of
the head hash where required.

---

## 5. The append / read / verify chain API

Phase 2 implements the three core operations ([`ROADMAP.md` §18 Phase 2](../ROADMAP.md),
tasks P2.1–P2.2):

- **append(event) → seq:** frame the event, set `prev_hash` to the current head's
  `frame_hash`, compute `payload_hash` and `frame_hash`, write the frame, advance
  the head. Target: event-append encoding < 50µs excluding fsync
  ([`nano-size-budget.md` §3](./nano-size-budget.md), [`ROADMAP.md` §17.2](../ROADMAP.md)).
- **read(range) → frames:** stream frames by `seq` range / `task_id` / `kind` for
  inspection and replay.
- **verify() → ChainStatus:** walk the log from genesis, recompute each
  `payload_hash` and `frame_hash`, assert `frame[n].prev_hash == frame[n-1].frame_hash`,
  and report the first break (if any). This is what backs the chain-status line in
  `crustcore inspect`.

**Edge cases / testing notes:**

- **Genesis frame:** the first frame's `prev_hash` is a fixed genesis constant;
  `verify` checks it.
- **Truncated/partial last frame:** a crash mid-append can leave a partial frame;
  `read`/`verify` must detect a short/partial trailing frame and report it rather
  than panic.
- **Idempotent re-delivery:** duplicate `seq` indicates corruption or replay;
  `verify` flags it.

---

## 6. Compact snapshots

Nano storage includes **periodic compact snapshots** ([`ROADMAP.md` §16.1](../ROADMAP.md)).
A snapshot captures kernel state (task/job/approval/budget state) at a known
`seq`, so replay/inspection does not always have to start from genesis, and so
the log can be compacted: old bulky payloads can be dropped (the
`payload_hash`/`frame_hash` still pin the chain) while the snapshot preserves the
reconstructable state. Snapshots are an optimization layered on top of the
append-only chain; they never replace it as the source of truth and never break
chain verification.

---

## 7. Nano storage

The nano storage stack ([`ROADMAP.md` §16.1](../ROADMAP.md)):

```text
append-only binary event log
content-addressed artifact store
periodic compact snapshots
JSONL export for inspection
```

The **content-addressed artifact store** holds large artifacts (diffs, logs,
transcripts — [`ROADMAP.md` §16.3](../ROADMAP.md)) by hash; events and receipts
reference artifacts by `ArtifactId([u8; 32])` rather than inlining megabytes of
text ([`receipts.md`](./receipts.md), invariant 20 / bounded everything in
[`CLAUDE.md` §6.5](../CLAUDE.md)). Nano links **no SQLite/redb/database** by
default ([`nano-size-budget.md` §5](./nano-size-budget.md)); a real store is the
optional `crustcore-index` tier ([`ROADMAP.md` §16.2](../ROADMAP.md)), and memory
there is never authority.

---

## 8. `crustcore inspect` and JSONL export

`crustcore inspect` (Phase 2 task P2.4) verifies the audit chain and explains what
happened ([`ROADMAP.md` §1.1](../ROADMAP.md), §18 Phase 2). It must show, per the
acceptance criteria, a **task summary** and the **chain status** (intact vs first
break). It is a CLI surface — setup/admin/inspect/emergency only, not a chat
channel (invariant 16; [`CLAUDE.md` §4](../CLAUDE.md)).

**JSONL export** (task P2.5) renders the binary log as one JSON object per line
for human reading and tooling — the readability win NilCore got from JSONL, kept
as an *export* so nano's on-disk format stays compact binary ([`ROADMAP.md` §1.1](../ROADMAP.md)).
Export must respect `visibility`/`redaction_state`: secret-bearing/tainted
payloads stay redacted in the export (invariants 2, 3).

---

## 9. Phase 2 tasks, acceptance, and tamper tests

**Tasks** ([`ROADMAP.md` §18 Phase 2](../ROADMAP.md)):

```text
P2.1 Define EventFrame binary format.
P2.2 Implement append/read/verify chain.
P2.3 Implement ToolReceipt generation.        (see receipts.md)
P2.4 Implement `crustcore inspect`.
P2.5 Implement JSONL export.
P2.6 Add tamper tests.
```

**Acceptance** ([`ROADMAP.md` §18 Phase 2](../ROADMAP.md)):

```text
Tampered log is detected.
Tool result without receipt cannot become model-visible.   (receipts.md)
`inspect` shows task summary and chain status.
```

**Tamper tests** (P2.6) — each must cause `verify` to report a break at the right
`seq`:

- flip a byte in an early `payload` → `payload_hash` mismatch detected.
- alter an early frame's `kind`/`timestamp`/`actor` → `frame_hash` mismatch.
- reorder two frames → `prev_hash` chain mismatch.
- delete a frame → chain gap detected.
- insert a forged frame → chain mismatch at the insertion point.
- truncate the trailing frame → partial-frame detection (§5).

These satisfy the v0.1 DoD items #6 ("the event log is hash-chained and
inspectable") and feed #11 (red-team fixtures pass) — including the
"tampered event logs" threat ([`ROADMAP.md` §9.2](../ROADMAP.md), §22;
[`THREAT_MODEL.md`](../THREAT_MODEL.md)).
