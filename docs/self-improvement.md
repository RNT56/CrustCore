# docs/self-improvement.md — Safe Self-Improvement

> **Purpose:** specify how CrustCore improves itself — through PRs, evals, and a
> contract-file gate — while never live-mutating the running kernel and never
> silently weakening policy, sandboxing, or secrets.

**Source of truth:** [`ROADMAP.md` §18 Phase 15](../ROADMAP.md)
(tasks/acceptance), [`ROADMAP.md` §16.2](../ROADMAP.md) (memory is never
authority), [`ROADMAP.md` §20.2](../ROADMAP.md) (contract files).
**Governs / governed by:** invariant **18** (and 3, 8, 9 for what may not be
weakened) in [`INVARIANTS.md`](../INVARIANTS.md).
**Siblings:** [`maintainer-agent.md`](./maintainer-agent.md),
[`advisor-executor.md`](./advisor-executor.md), [`github.md`](./github.md),
[`policy.md`](./policy.md) (when present), [`secrets.md`](./secrets.md)
(when present), [`sandbox.md`](./sandbox.md) (when present).

---

## 1. The one rule: no live self-mutation

Invariant **18**: *self-improvement happens through PRs/evals, not live mutation
of the running kernel.* A kernel that can rewrite its own policy, sandbox, or
secret handling **while running** cannot be audited or trusted — the very thing
you would inspect could have changed itself out from under you.

So CrustCore improves itself the same way any other repository is improved: it
**proposes changes as PRs**, gated by **evals** and a **contract-file gate**, and
a **human maintainer merges**. There is no path from "the agent learned
something" to "the running kernel's policy/sandbox/secret behavior changed"
without a reviewed, merged, re-deployed PR.

```text
NOT ALLOWED:  running kernel -> mutates its own policy/sandbox/secret code in place
ALLOWED:      agent observes failure -> proposes PR -> evals + contract gate -> maintainer merges -> redeploy
```

This is the self-application of the north star ([`CLAUDE.md`](../CLAUDE.md)):
*models may propose; only CrustCore (and its human maintainer) may authorize,
verify, persist, expose, or integrate* — including changes to CrustCore itself.

---

## 2. Memory is never authority

A related boundary ([`ROADMAP.md` §16.2](../ROADMAP.md)): **memory is never
authority.** Failure memory, convention memory, decision memory, and the failure
classifier (§3) are *retrieved as context and marked as prior observation* — they
inform proposals, they do not grant power. A memory entry that says "last time we
disabled the sandbox to make tests pass" is a prior observation to learn *from*,
not an instruction to *repeat*. Memory feeds the improvement loop's *inputs*; it
never bypasses its *gates*.

---

## 3. The improvement loop

```text
failure / signal
  -> failure classifier            (categorize what went wrong)
  -> improvement proposal artifact (typed, reviewable proposal)
  -> eval / regression generation  (prove it helps, prove it breaks nothing)
  -> self-PR workflow              (draft PR, like any other change)
  -> contract-file gate            (block silent weakening; require maintainer approval)
  -> maintainer review + merge     (the only way it ships)
```

### 3.1 Failure classifier

The classifier (Phase 15 task P15.1) categorizes failures — wrong approach, flaky
verifier, missing context, prompt deficiency, tool gap, recurring error class — so
improvements target a real, named cause rather than a one-off. It draws on
failure memory ([`ROADMAP.md` §16.2](../ROADMAP.md)), which is prior observation,
not authority (§2).

### 3.2 Improvement proposal artifact

A proposal (P15.2) is a **typed artifact**, not a free-text suggestion: what to
change, why, the failure class it addresses, the expected effect, and the risk.
Permitted scope:

```text
ALLOWED to propose:   prompt improvements
                      tool definitions / tool ergonomics
                      config / defaults (non-contract)
```

Phase 15 acceptance: *"Agent can propose prompt/tool/config improvements."*

### 3.3 Eval / regression generation

Every proposal (P15.3) must come with **evals/regressions** that demonstrate the
improvement and guard against regression — the same evidence discipline the
verifier applies to any change. A proposal without evidence that it helps (and
does not break existing behavior) does not advance. This plugs the improvement
loop into the existing eval suite ([`ROADMAP.md` §19](../ROADMAP.md)).

### 3.4 Self-PR workflow

The proposal becomes a **draft PR** (P15.4) through the normal GitHub path
([`github.md` §6](./github.md)) — `VerifiedPatch` → draft PR, never auto-merge
(invariants 13, 14). A self-improvement PR is not privileged; it is a PR like any
other, reviewed by a human.

---

## 4. The contract-file gate

The gate (P15.5) is what keeps self-improvement from quietly removing its own
guardrails. Phase 15 acceptance: ***"Agent cannot weaken policy/sandbox/secrets
silently"*** and ***"Contract files require explicit maintainer approval."***

**Contract files** ([`ROADMAP.md` §20.2](../ROADMAP.md),
[`CLAUDE.md` §7.3](../CLAUDE.md)):

```text
INVARIANTS.md
THREAT_MODEL.md
SECURITY.md
docs/policy.md
docs/secrets.md
docs/sandbox.md
docs/backend-contract.md
crates/crustcore-kernel/src/event.rs
crates/crustcore-kernel/src/action.rs
crates/crustcore-policy/src/decision.rs
crates/crustcore-secrets/src/lib.rs
Cargo.toml
Cargo.lock
```

How the gate behaves:

- A self-PR that **touches any contract file** is flagged and **requires explicit
  maintainer approval** — it cannot be auto-advanced, and the change to the
  contract file must be serialized (one at a time;
  [`CLAUDE.md` §7.3](../CLAUDE.md)).
- The agent **may not bundle** a contract-file change into an unrelated
  improvement to slip it through. Contract changes route through a dedicated,
  serialized task (mirrors [`maintainer-agent.md`](./maintainer-agent.md) work
  discipline).
- The gate specifically catches the *silent weakening* attack: an "improvement"
  that loosens a policy decision, widens a sandbox profile, or relaxes a secret
  type is a contract-file change and therefore cannot ship without a human
  explicitly approving the weakening, eyes open.

Because the dangerous states are *also* enforced by the type system
([`INVARIANTS.md`](../INVARIANTS.md)) — `SecretMaterial` cannot become
model-visible (invariant 3), side effects require capability tokens (invariant
8), execution requires a sandbox profile (invariant 9) — a self-improvement PR
that tried to weaken them would have to change typed contract code, which the
gate stops at review.

---

## 5. What self-improvement may and may not do

| May propose (via PR + evals) | May **not** do |
| --- | --- |
| Prompt improvements | Live-mutate the running kernel (invariant 18) |
| Tool definitions / ergonomics | Weaken policy/sandbox/secrets silently (§4) |
| Non-contract config / defaults | Treat memory as authority ([§2](#2-memory-is-never-authority)) |
| Evals / regression tests | Bundle contract changes into unrelated PRs |
| Failure-classification rules (non-contract) | Self-merge any PR (invariant 14) |

---

## 6. Where it lives, and scope

Self-improvement is a Phase-15, full-runtime concern — not a nano kernel feature
(invariant 20). It is also **explicitly out of scope for v0.1**
([`ROADMAP.md` §21](../ROADMAP.md), [`CLAUDE.md` §2.3](../CLAUDE.md)): build the
trusted core and the verified task loop first; the self-improvement loop comes
after. This doc is the contract that loop must satisfy when it is built.

| Concern | Crate | In nano? |
| --- | --- | --- |
| Failure classifier, proposal artifacts, self-PR workflow | `crustcore-daemon` / supervisor + `crustcore-eval` | No |
| Eval / regression harness | `crustcore-eval` | No |
| Contract-file gate (CI check) | CI / `xtask verify` | n/a |

---

## 7. Phase 15 tasks and acceptance

From [`ROADMAP.md` §18 Phase 15](../ROADMAP.md):

```text
P15.1 Implement failure classifier.
P15.2 Implement improvement proposal artifact.
P15.3 Implement eval/regression generation.
P15.4 Implement self-PR workflow.
P15.5 Add contract-file gate.
```

**Acceptance criteria:**

```text
Agent can propose prompt/tool/config improvements.        -> §3.2
Agent cannot weaken policy/sandbox/secrets silently.       -> §4
Contract files require explicit maintainer approval.        -> §4
```

### 7.1 Testing notes

- **No live mutation (invariant 18):** assert there is no code path from the
  running kernel to in-place modification of its own policy/sandbox/secret code;
  improvements only ever emit proposals/PRs.
- **Contract gate (P15.5):** a self-PR touching any contract file is flagged and
  blocked from auto-advance; it requires explicit maintainer approval; a bundled
  contract change is rejected.
- **Silent-weakening red team:** a proposal that tries to loosen a policy
  decision, widen a sandbox profile, or relax a secret type is caught — either it
  fails to compile (type enforcement) or it trips the contract gate.
- **Evals required:** a proposal without supporting evals/regressions does not
  advance (P15.3).
- **Memory non-authority (§2):** a memory/classifier entry cannot, by itself,
  authorize a change — it only seeds a proposal that still passes every gate.
- **No self-merge:** self-improvement PRs cannot self-merge (cross-check
  invariant 14, [`github.md` §6](./github.md)).
