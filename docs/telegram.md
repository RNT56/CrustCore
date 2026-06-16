# docs/telegram.md — Telegram Runtime Channel

> **Purpose:** specify CrustCore's single default runtime human channel — its
> command set, queue/steer semantics, chat-ID binding, inbound normalization,
> and what may and may not be streamed to the user.

**Source of truth:** [`ROADMAP.md` §3.1](../ROADMAP.md) (human surfaces),
[`ROADMAP.md` §18 Phase 9](../ROADMAP.md) (tasks/acceptance).
**Governs / governed by:** invariants **5, 15, 16** in
[`INVARIANTS.md`](../INVARIANTS.md); [`CLAUDE.md` §4](../CLAUDE.md).
**Siblings:** [`github.md`](./github.md), [`model-routing.md`](./model-routing.md),
[`advisor-executor.md`](./advisor-executor.md),
[`maintainer-agent.md`](./maintainer-agent.md).

---

## 1. Why Telegram, and why only Telegram

Invariant **15** states: *runtime user communication goes through Telegram only
by default.* Invariant **16** states: *the CLI is setup/admin/emergency, not a
hidden second chat channel.* Together they give CrustCore **exactly one auditable
runtime control plane** for a running task. Every approval, every steer, every
status query during a live task flows through this one channel and is recorded
in the event log.

The rationale is not Telegram-specific affection — it is **channel
minimalism**:

- One channel = one place to audit "who told the agent what, and when."
- One channel = one capability to guard. The runtime user-channel capability is
  Telegram-bound by default; any other channel requires explicit policy
  (invariant 15). There is no second, ungoverned chat path.
- A single channel makes the *subagent → user* prohibition (invariant 5)
  enforceable: only the supervisor holds the Telegram channel capability;
  subagents physically cannot reach it.

Telegram is a **sidecar concern**. It lives in `crustcore-net` (Bot API client)
and is driven by `crustcore-daemon` (polling loop, command dispatch, approval
state). **It is not in nano** (invariant 20 — unused capabilities cost zero
linked code; the sub-800kB kernel never links the Telegram stack). The kernel
sees only normalized `Event::UserTurn` / `Event::UserSteerReceived` /
`Event::ApprovalResolved`, never raw Telegram JSON
([`CLAUDE.md` §3](../CLAUDE.md)).

```text
Telegram raw update
  -> [crustcore-net Bot API client]
  -> [crustcore-daemon: allowlist check, dedupe, normalize]
  -> InboundEnvelope
  -> Event::UserTurn | Event::UserSteerReceived | Event::ApprovalResolved
  -> Kernel::step(event) -> Action(s)
  -> [daemon renders allowed outbound message] -> Telegram
```

---

## 2. Command set

The runtime channel supports the full command list from
[`ROADMAP.md` §3.1](../ROADMAP.md). Commands are **typed verbs**, parsed by the
daemon into kernel events — they are never free-text passed to a model.

| Command | Argument | Effect | Reversibility |
| --- | --- | --- | --- |
| `/status` | — | Snapshot of active tasks, budgets, channel health | read-only |
| `/tasks` | — | List tasks with status (see `TaskStatus`) | read-only |
| `/task` | `<id>` | Detail on one task: plan, current job, last events | read-only |
| `/approve` | `<approval_id>` | Resolve a pending approval **approve** | mints `Approved<T>` |
| `/deny` | `<approval_id>` | Resolve a pending approval **deny** | blocks the gated action |
| `/pause` | `<task_id>` | Pause task at next safe boundary | reversible |
| `/resume` | `<task_id>` | Resume a paused task | reversible |
| `/kill` | `<task_id>` | Cancel task + jobs; tear down worktrees | terminal |
| `/diff` | `<task_id>` | Render the current/candidate diff (bounded) | read-only |
| `/logs` | `<task_id>` | Tail bounded, **redacted** task logs | read-only |
| `/budget` | — | Show budget consumption vs limits | read-only |
| `/policy` | — | Show effective policy/risk profile | read-only |
| `/repo` | — | Show bound repo/ref and GitHub posture | read-only |
| `/help` | — | List commands and usage | read-only |

Notes and edge cases:

- **`/approve` and `/deny` are the only commands that mint or consume an
  approval token.** They are nonce-bound (§5). An `/approve` without a matching
  pending nonce is rejected and logged as `RiskDetected`, not silently ignored —
  a stray approval ID is a signal worth surfacing.
- **`/kill`** is terminal: it transitions the task toward `Killed`, cancels
  every child job (cancellation token / process-tree kill), and the kernel must
  emit **no further tool actions** for a killed task (Phase 1 acceptance,
  [`ROADMAP.md` §18](../ROADMAP.md)).
- **`/logs`** returns logs already passed through the redactor. Tainted,
  secret-bearing data can never reach a Telegram message (invariants 2, 15;
  [`docs/secrets.md`](./secrets.md) when present). If redaction cannot prove a
  span is clean, it is withheld, not sent.
- Unknown commands, malformed arguments, and commands referencing a non-existent
  / not-owned task ID return a typed error reply; they never fall through to a
  model as a prompt.

---

## 3. Queue and steer semantics

A running task has **safe boundaries** — points between proposed tool calls
where new user input can be applied without corrupting in-flight work. Runtime
messages are interpreted relative to those boundaries
([`ROADMAP.md` §3.1](../ROADMAP.md)):

```text
normal message during a task  -> queue for next safe boundary
message prefixed with !       -> steer before pending model/tool actions execute
/cancel or /kill              -> explicit cancellation path
approval buttons              -> approve/deny the exact nonce-bound operation
```

### 3.1 Queue (default)

A plain message arriving while a task runs becomes a **queued user turn**. It is
recorded as `Event::UserMessageQueued` and delivered to the agent context at the
**next safe boundary** — never mid-tool-call. This preserves determinism: the
agent is not interrupted in the middle of applying a patch or interpreting tool
output. Queued turns are ordered (FIFO) and bounded (queue-depth budget;
invariant 11).

### 3.2 Steer (`!` prefix)

A message prefixed with `!` is a **steer**: it is injected **before pending
model/tool actions execute**, recorded as `Event::UserSteerReceived`. Steering
lets the user redirect ("`!stop touching the auth module, focus on the failing
test`") *before* the queued/proposed action fires, rather than waiting for the
next boundary.

Steer is still **advisory to the agent's reasoning**, not to policy. A steer can
change *what the agent tries next*; it cannot grant capabilities, approve
irreversible actions, or override sandbox/secret rules. Those still require the
typed approval path (invariants 4, 8, 14). Edge case: a steer that *asks* for an
irreversible action results in the agent **requesting an approval**, which the
user must then `/approve` — the steer alone never authorizes it.

### 3.3 Cancellation

`/cancel` (soft) and `/kill` (hard) are the explicit cancellation path. `/cancel`
requests a graceful stop at the next boundary; `/kill` forces teardown. Both are
distinct from `/pause` (which is resumable). Cancellation flows through the job
lifecycle's cancellation token (invariant 12) so that long-running sandboxed
processes are actually terminated, not just logically abandoned.

---

## 4. Allowed chat-ID binding (the NullClaw lesson)

Telegram delivers updates from any chat that can reach the bot token. CrustCore
binds control to an **explicit allowlist of chat IDs**. This is the NullClaw
pairing/allowlist discipline ([`ROADMAP.md` §1.2](../ROADMAP.md)):

```text
empty allowlist            -> DENY ALL (the bot controls nothing)
explicit chat-id present   -> that chat may issue runtime commands
"*" wildcard               -> explicit opt-in only, never a default
```

Rules and edge cases:

- **Empty allowlist means deny-all**, not allow-all. A freshly configured bot
  with no bound chat ID is inert: it ignores every command. This is the single
  most important failure-safe default — a leaked or guessed bot token is useless
  without a bound chat.
- Binding happens through the **trusted setup/admin path** (CLI, invariant 16),
  not by a message from an unknown chat claiming to be the owner. There is no
  "DM the bot to pair yourself" flow that an attacker could race.
- Messages from non-allowlisted chats are dropped at the daemon boundary,
  counted, and (rate-limited) surfaced as `RiskDetected` — never normalized into
  a kernel `UserTurn`.
- Allowed chat IDs sit in the **Trusted** zone ([`ROADMAP.md` §9.1](../ROADMAP.md));
  everything Telegram delivers *before* the allowlist check is **untrusted**.

---

## 5. Inbound envelope normalization and dedupe

Raw channel payloads are normalized and deduplicated **before** they reach the
runtime — the ZeroClaw request-lifecycle discipline
([`ROADMAP.md` §1.3](../ROADMAP.md)) and Phase 9 task P9.3
([`ROADMAP.md` §18](../ROADMAP.md)).

The daemon converts each raw Telegram update into a typed `InboundEnvelope`:

```text
InboundEnvelope {
  source_chat_id      // checked against allowlist
  update_id           // Telegram monotonic id, used for dedupe
  message_id
  received_at         // host timestamp (trusted), not client-claimed time
  kind                // Command | Text | CallbackQuery(approval) | ...
  normalized_text     // trimmed, control-stripped, length-bounded
  steer_flag          // true if "!"-prefixed
}
```

Normalization handles, at minimum:

- **Dedupe by `update_id`.** Telegram long-polling can redeliver updates on
  retry; the daemon tracks the high-water `update_id` and discards
  already-seen updates. Replays must not double-apply an `/approve` or
  double-queue a steer (Phase 9 acceptance: spoof/dedupe tests, P9.7).
- **Length and rate bounds** (invariant 11). Oversized messages are truncated to
  a bounded text type; flooding is rate-limited per chat.
- **Trusted timestamps.** The host's receive time is authoritative; a
  client-supplied timestamp is data, never used for ordering or expiry checks.
- **Spoof resistance.** Identity is the *allowlisted chat ID*, not a display
  name or claimed username, both of which are untrusted, mutable strings.

Only after the allowlist check and dedupe does the envelope become a kernel
event. The kernel never sees a raw update ([`CLAUDE.md` §3](../CLAUDE.md)).

---

## 6. Approvals: nonce-bound, operation-bound, expiring

Approvals are the typed gate for irreversible actions (invariants 4, 14). On
Telegram they appear as **inline buttons** (and equivalent `/approve` /
`/deny` commands) carrying a **nonce bound to the exact operation**
([`ROADMAP.md` §3.1](../ROADMAP.md)).

```text
ApprovalRequest -> Telegram message with inline buttons
  approve button callback_data = nonce(approval_id, op_hash)
  deny    button callback_data = nonce(approval_id, op_hash)
```

Properties:

- **Operation-bound.** The nonce binds to a hash of the specific operation
  (e.g. "push branch `claude/p10-fix` to `repo X`"). Approving operation A can
  never authorize operation B, even if the user fat-fingers an ID. The resulting
  token is `Approved<T>` for *that* `T` only.
- **Minted by the approval engine, from a human.** `Approved<T>` is created only
  from an authorized-user resolution via the allowlisted chat (or CLI). It is
  **never** minted from model output — that is invariant 4, tested by policy
  tests that reject model-originated "approvals"
  ([`INVARIANTS.md` §4](../INVARIANTS.md)).
- **Expiring.** Each `Approved<T>` carries `expires_at`. A stale approval is
  rejected; the action must be re-requested. Phase 9 acceptance:
  *"Approvals expire and are operation-bound."*
- **Single-use.** A nonce is consumed on resolution; re-pressing the button after
  resolution is a no-op (and a dedupe target via `update_id`/callback id).

Edge cases:

- A button pressed from a **non-allowlisted chat** is dropped (the callback
  carries the chat ID; it is allowlist-checked exactly like a message).
- An approval whose task has since been `Killed` or whose budget is exhausted is
  rejected with a typed reason, not applied to a dead task.

---

## 7. What gets streamed — and what never does

CrustCore **does not promise hidden chain-of-thought streaming**
([`ROADMAP.md` §3.1](../ROADMAP.md)). The runtime channel streams the things a
human operator needs to supervise, drawn from the event log, not the model's raw
internal tokens.

**Streamed to the user:**

```text
progress updates
plans / milestones
visible reasoning summaries (deliberate, bounded — not raw CoT)
status transitions
tool plans (what the agent intends to run, before it runs)
verifier output (pass/fail, evidence)
approval requests
completion messages
```

**Never streamed:**

```text
raw/hidden chain-of-thought token streams
unredacted secret-bearing logs (invariants 2, 15)
arbitrary model-authored Telegram text (see §8)
raw provider/Telegram/GitHub JSON
```

Tool plans are streamed *before* execution precisely so the queue/steer/approve
loop (§3) has something to act on: the user sees "about to run `cargo test` in
sandbox profile X" and can steer or deny before it fires.

---

## 8. The model does not speak Telegram directly

A core boundary: **the model does not send arbitrary text to Telegram.** Phase 9
acceptance is explicit: *"Model does not send arbitrary Telegram text directly."*

Outbound runtime messages are **rendered by CrustCore** from typed, structured
sources — status snapshots, plan summaries, verifier results, approval requests —
not by handing a model a `send_message(text)` tool. Reasons:

- It closes a prompt-injection exfiltration path. If repo/MCP/issue content
  (untrusted, invariant 7) could coerce the model into emitting a chosen string,
  and that string went straight to Telegram, untrusted data would control user
  communication. Rendering from typed events breaks that edge.
- It keeps the redactor in the loop. Every outbound payload is built by trusted
  code that runs redaction (invariant 2) before send.
- It preserves the supervisor-only channel capability (invariant 5): the channel
  is driven by the supervisor/daemon, not exposed as a freely callable model
  tool.

A model's *intent* ("tell the user the build is green") is realized as a
**structured status/summary event** that CrustCore renders — bounded, redacted,
attributable — not as raw model text injected verbatim.

---

## 9. Where it lives, and what nano sees

| Concern | Crate | In nano? |
| --- | --- | --- |
| Bot API HTTP client | `crustcore-net` | No |
| Polling loop, command dispatch, allowlist, dedupe, approval state | `crustcore-daemon` | No |
| Kernel events (`UserTurn`, `UserSteerReceived`, `ApprovalResolved`) | `crustcore-kernel` | Yes (events only) |

Nano links **none** of the Telegram stack (invariants 19, 20). A nano-only build
runs local, CLI-driven verifier tasks with no runtime chat channel at all — the
Telegram capability is purely additive and zero-cost when unused.

---

## 10. Phase 9 tasks and acceptance

From [`ROADMAP.md` §18 Phase 9](../ROADMAP.md):

```text
P9.1 Implement Telegram polling in net/daemon.
P9.2 Bind allowed chat IDs.
P9.3 Normalize inbound envelope.
P9.4 Implement commands.
P9.5 Implement queue/steer logic.
P9.6 Implement nonce approval buttons/commands.
P9.7 Add spoof/dedupe tests.
```

**Acceptance criteria:**

```text
Only allowed chat can control runtime.        -> §4
Normal message queues; !message steers.       -> §3
Approvals expire and are operation-bound.      -> §6
Model does not send arbitrary Telegram text.   -> §8
```

### 10.1 Testing notes

- **Allowlist:** empty allowlist denies all; non-allowlisted chat/button dropped
  and counted; only bound chat IDs control the runtime.
- **Dedupe/spoof (P9.7):** replayed `update_id` does not double-apply
  `/approve`; spoofed username/display-name does not grant control; client-claimed
  timestamps never affect ordering or expiry.
- **Queue/steer:** a queued message is applied only at a safe boundary; a `!`
  steer lands before the pending action; neither grants capabilities.
- **Approvals:** approving op A never authorizes op B; expired approvals are
  rejected; model-originated approval attempts are rejected (cross-check
  invariant 4).
- **Redaction:** `/logs` and all outbound renders pass the secret-leak matrix
  ([`INVARIANTS.md`](../INVARIANTS.md) red-team requirement); no secret reaches a
  Telegram draft.
- **Kill semantics:** after `/kill`, the kernel emits no further tool actions for
  that task (cross-check Phase 1).
