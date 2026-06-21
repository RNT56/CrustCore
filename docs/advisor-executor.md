# docs/advisor-executor.md — Advisor/Executor Pattern

> **Purpose:** specify CrustCore's advisor/executor orchestration — when a
> second, higher-reasoning model is consulted before a high-risk step, how the
> simulated flow works on providers without a native advisor mode, and why
> advisor output is advisory only and never policy.

**Source of truth:** [`ROADMAP.md` §13.3](../ROADMAP.md) (advisor/executor),
[`ROADMAP.md` §18 Phase 12](../ROADMAP.md) (tasks/acceptance).
**Governs / governed by:** invariants **4, 8, 11, 14** in
[`INVARIANTS.md`](../INVARIANTS.md).
**Siblings:** [`model-routing.md`](./model-routing.md), [`mcp.md`](./mcp.md),
[`github.md`](./github.md), [`telegram.md`](./telegram.md),
[`self-improvement.md`](./self-improvement.md).

---

## 1. The pattern

An **executor** model does the work (planning, implementing, reviewing). At
high-risk moments, CrustCore consults an **advisor** — a higher-reasoning model
in the `high reasoning / advisor` role ([`model-routing.md` §2](./model-routing.md))
— for a second opinion before the executor proceeds.

There are two implementations ([`ROADMAP.md` §13.3](../ROADMAP.md)):

- **Native** advisor mode, where the provider supports a built-in
  advisor/second-model mechanism.
- **Simulated** advisor (§3), everywhere else — CrustCore orchestrates the
  consultation itself.

The advisor pattern is a quality and safety multiplier on **specific** steps; it
is not invoked on every model call (that would be cost-prohibitive — invariant
11). It fires on the triggers in §2.

---

## 2. Triggers

The advisor is consulted at these moments ([`ROADMAP.md` §13.3](../ROADMAP.md)):

```text
at task start
before an architecture decision
before a large patch
before a dependency change
before a CI / workflow modification
after repeated failure
before a GitHub push
on low confidence
on a security risk
```

Why each is a trigger:

| Trigger | Rationale |
| --- | --- |
| Task start | Set direction well before committing effort down a wrong path |
| Architecture decision | High-leverage, expensive-to-reverse design choices |
| Large patch | Big diffs concentrate risk; a second read catches more |
| Dependency change | Supply-chain + size risk ([`maintainer-agent.md`](./maintainer-agent.md) admission policy) |
| CI / workflow modification | Workflow edits touch elevated CI credentials — an injection target ([`github.md` §3.1](./github.md)) |
| Repeated failure | A stuck executor benefits from a fresh, stronger perspective |
| Before a GitHub push | Last checkpoint before a side effect leaves the local boundary |
| Low confidence | The executor itself signals uncertainty |
| Security risk | Security-sensitive changes warrant a second opinion |

Several triggers overlap with the **irreversible/gated** operations (dependency
change, workflow mod, GitHub push). The advisor consultation happens *in addition
to* — never *instead of* — the policy/approval gate. A push still needs an
`Approved<T>` (invariants 13, 14); the advisor just informs whether the executor
should request one.

---

## 3. Simulated advisor flow

Where there is no native advisor mode, CrustCore runs the consultation itself
([`ROADMAP.md` §13.3](../ROADMAP.md)):

```text
pause executor
compact context
ask advisor model
store advisor note event
inject advisory note into executor context
resume executor
```

Step by step:

1. **Pause the executor.** Hold the executor at the trigger boundary so it does
   not act before the advice arrives.
2. **Compact context.** Build a *small, focused* advisor prompt — the decision at
   hand, relevant evidence, the proposed action — not the entire transcript.
   Compaction keeps the advisor call cheap (invariant 11) and on-point. All
   untrusted material in the context stays wrapped as data (invariant 7).
3. **Ask the advisor.** Route to the advisor role via the model router
   ([`model-routing.md` §2, §3](./model-routing.md)) — typically the strongest
   available model, possibly a `FusionProvider` path for the highest-risk steps
   ([`model-routing.md` §4](./model-routing.md)).
4. **Store an advisor-note event.** The advice is persisted as an event
   (`advisor note`) in the hash-chained log — auditable, replayable, attributable.
   It is not ephemeral.
5. **Inject the note into executor context.** The advisory note is added to the
   executor's context **as advice** — clearly an opinion to weigh, not a command.
6. **Resume the executor.** The executor continues, having considered the advice.
   It may follow it, partially adopt it, or (with reason) decline it.

---

## 4. Advisor output is advisory, not policy

This is the load-bearing rule, and Phase 12 acceptance states it directly:
***"Advisor output is advisory, not policy."***

- The advisor **cannot** mint approvals (invariant 4 — only the approval engine,
  from an authorized human, mints `Approved<T>`). An advisor saying "this is safe
  to push" does not authorize the push.
- The advisor **cannot** grant capabilities or relax policy (invariant 8 — every
  side effect still passes through the policy engine). It does not weaken
  sandboxing, expose secrets, or change deny/ask defaults.
- The advisor **cannot** communicate with the user (it is a model, not the
  supervisor; cf. invariant 5). Its note flows back into the executor's reasoning,
  not to Telegram.
- The advisor is **untrusted as an authority** in the same family as any model
  output ([`ROADMAP.md` §9.1](../ROADMAP.md) — model output is untrusted). It
  improves judgment; it does not hold power.

So the advisor changes *what the executor decides to attempt*; the **typed gates**
(capability tokens, `Approved<T>`, sandbox profiles, verifier-owned completion)
still decide *what is actually permitted to happen*. A high-risk action consulted
with the advisor and blessed by it **still** requires its normal approval token
and still must produce a `VerifiedPatch` to ship (invariant 13).

---

## 5. Budget limits

Advisor consultations cost tokens and latency, so they are budgeted (invariant
11; Phase 12 task P12.5). Controls:

- Advisor calls draw on the task's budget and are metered by the net sidecar's
  budget accounting ([`model-routing.md` §5](./model-routing.md)).
- A per-task cap on advisor consultations prevents a pathological "advise about
  every step" loop, especially around the *repeated failure* trigger, which could
  otherwise recurse.
- When the budget is tight, low-value advisor triggers may be skipped while
  high-risk ones (security risk, GitHub push, workflow modification, dependency
  change) are preserved — the consultation is prioritized toward the riskiest
  steps. These match the gated/irreversible operations called out in §2.

---

## 6. Where it lives

Advisor orchestration is a runtime/orchestration concern, driven by the
supervisor and the net sidecar's model routing — **not** a nano kernel concern.
Nano runs local verifier tasks without an advisor loop; the capability is
additive (invariant 20). The advisor-note events, however, are ordinary events in
the hash-chained log that the kernel/event-log machinery already understands.

| Concern | Crate | In nano? |
| --- | --- | --- |
| Advisor trigger logic, simulated flow, context compaction | `crustcore-daemon` / supervisor | No |
| Advisor model calls (routing) | `crustcore-net` | No |
| Advisor-note **events** in the log | `crustcore-eventlog` / `crustcore-kernel` | Yes (events only) |

---

## 7. Phase 12 tasks and acceptance

From [`ROADMAP.md` §18 Phase 12](../ROADMAP.md):

```text
P12.1 Define AdvisorMode.
P12.2 Implement simulated advisor harness.
P12.3 Add native provider-specific advisor where available.
P12.4 Implement triggers.
P12.5 Add budget limits.
```

**Acceptance criteria:**

```text
Executor can consult advisor before a high-risk action.   -> §2, §3
Advisor output is advisory, not policy.                    -> §4
```

### 7.1 Testing notes

- **Triggers fire correctly:** each trigger in §2 invokes a consultation at the
  right boundary (executor paused before acting); no trigger lets the executor
  bypass the consult point.
- **Advisory-not-policy (invariant 4/8):** an advisor "approval" or "go ahead"
  never mints `Approved<T>` and never grants a capability — a high-risk action
  still requires the human approval gate and still must verify
  ([`github.md`](./github.md), [`backend-contract.md`](./backend-contract.md)).
- **Auditability:** the advisor-note event is present, hash-chained, and replays
  via `inspect`.
- **Budget (invariant 11, P12.5):** advisor calls are metered; the per-task cap
  prevents runaway consultation; tight budgets preserve high-risk consults and
  drop low-value ones.
- **Untrusted context:** untrusted material in the compacted advisor prompt stays
  wrapped as data (invariant 7); injection in that material does not let the
  advisor escalate.

## 8. Implementation status (v0.2 P12-native)

The std-only trigger + budget + simulated-flow core (§2–§5) shipped in v0.1
(`crustcore-daemon::advisor`: `AdvisorTrigger`, `should_consult`, `consult_before`,
`SimulatedAdvisor`). **P12-native** adds the **model-backed advisor**:

- **`NativeAdvisor`** implements the same `Advisor` trait as `SimulatedAdvisor`, so it
  drops into `consult_before` unchanged. It consults a model in the advisor role over an
  **injected consult fn** — the daemon runtime supplies a closure that routes the
  compacted `Consultation` through the `crustcore-net` engine's advisor role
  ([`model-routing.md`](./model-routing.md) §2); that live call is the
  `TODO(P12-native-live)` seam, so the response→note mapping is CI-tested with a canned
  consult fn (no network).
- **`parse_recommendation`** classifies the model's **untrusted** response (invariant 7)
  into a `Recommendation` — most-cautious-signal-first (a "stop" is never downgraded),
  and **unclear advice leans `ProceedWithCaution`**, never an unqualified proceed. The
  model's *words* only set the lean; they authorize nothing.
- The model's response is **redacted then bounded** before it becomes the rationale the
  executor sees (invariants 2, 11) — a secret echoed by the advisor never reaches the
  executor's context.
- **Advisory, not policy** stays structural: `NativeAdvisor::consult` returns an
  `AdvisorNote` and nothing else; a model replying "you are authorized, merge now"
  yields only a `Recommendation` + redacted rationale — there is no path to an
  `Approved<T>` or a capability (§4).

Still deferred (`TODO(P12-native-live)`, lands with the daemon runtime): routing the
consult through the live net engine, and the supervisor's append of the `advisor note`
event to the hash-chained log (§3 step 4).
