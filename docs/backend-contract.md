# docs/backend-contract.md — The One Backend Contract

> **⚠️ CONTRACT FILE.** This is a
> [contract file](../CLAUDE.md#73-contract-files--serialized-changes-only):
> changes are serialized (one PR at a time) and require maintainer approval. Do
> not edit it in parallel with other work, and do not bundle a backend-contract
> change into unrelated tasks.

> **Purpose:** define CrustCore's single backend contract — `BackendResult`,
> `UnverifiedPatch`, `VerifiedPatch` — the one backend shape shared by the native
> agent, Codex CLI, Claude Code, and future workers; the external-worker input
> contract and supervisor validation; and the rule that only a `VerifiedPatch`
> may integrate, complete, or open a PR.

**Cross-links:** [`ROADMAP.md` §7.5](../ROADMAP.md) (verified patch model),
[`ROADMAP.md` §11.4](../ROADMAP.md) (external worker contract),
[`ROADMAP.md` §1.1](../ROADMAP.md) (NilCore lesson: one backend contract),
[`ROADMAP.md` §18 Phase 5–6](../ROADMAP.md),
[`INVARIANTS.md` #6, #13](../INVARIANTS.md), [`CLAUDE.md` §9.3](../CLAUDE.md).
**Sibling docs:** [`policy.md`](./policy.md) (approval/capability tokens),
[`receipts.md`](./receipts.md) (the receipt inside a VerifiedPatch),
[`event-log.md`](./event-log.md) (patch lifecycle events),
[`sandbox.md`](./sandbox.md) (verifier runs in a clean sandbox),
[`secrets.md`](./secrets.md), [`architecture.md`](./architecture.md).

---

## 1. One backend shape (the NilCore lesson)

> **One backend contract.** Native agent, Codex CLI, Claude Code, and future
> workers all return the same `BackendResult` shape. ([`ROADMAP.md` §1.1](../ROADMAP.md))

A coding backend is anything that produces a candidate change: the native
implementer agent, an external `codex` subprocess, an external `claude` (Claude
Code) subprocess, or any future worker. CrustCore treats them all through **one**
`CodingBackend` contract (the `crustcore-backend` crate —
[`architecture.md` §4](./architecture.md)). The supervisor never special-cases a
worker's privileges based on which backend produced the result. This is what
makes the safety model uniform: every backend's output is *a proposal*, and every
proposal goes through the same verification gate.

This pairs with the **verifier-owned completion** north star
([`CLAUDE.md` §1](../CLAUDE.md)): *a patch is not done because a model says so; it
is done only after verifier evidence.*

---

## 2. The types

```rust
pub struct BackendResult {
    pub backend: BackendKind,
    pub summary: BoundedText,
    pub patch: Option<PatchRef>,
    pub self_claimed_done: bool,
    pub commands_run: Vec<CommandRecord>,
    pub risks: Vec<Risk>,
}

pub struct UnverifiedPatch(PatchRef);

pub struct VerifiedPatch {
    pub patch: PatchRef,
    pub verifier: VerifierName,
    pub commands: Vec<CommandEvidence>,
    pub passed_at: Timestamp,
    pub receipt: ToolReceipt,
}
```
([`ROADMAP.md` §7.5](../ROADMAP.md))

### 2.1 `BackendResult` — what a backend returns

| Field | Meaning / rationale |
| --- | --- |
| `backend: BackendKind` | which backend produced this (native / Codex / Claude Code / external command). Provenance, not privilege. |
| `summary: BoundedText` | a bounded human/model summary — never an unbounded dump ([`CLAUDE.md` §6.5](../CLAUDE.md) "bounded everything"). |
| `patch: Option<PatchRef>` | a *reference* to the produced patch (in the artifact store — [`event-log.md` §7](./event-log.md)), not inline megabytes. May be `None` (e.g., a research-only result). |
| `self_claimed_done: bool` | the backend's **claim** that it is done. **Advisory metadata, never authority** ([`CLAUDE.md` §9.3](../CLAUDE.md)). |
| `commands_run: Vec<CommandRecord>` | what the backend says it ran — untrusted, used for context and cross-checking, not as proof. |
| `risks: Vec<Risk>` | risks the backend surfaced. |

The critical design choice: **`self_claimed_done` is a `bool` the backend
controls, and it grants nothing.** A backend can set it to `true` and still not
complete a task. That is invariant 6 in a single field.

### 2.2 `UnverifiedPatch` — a proposal

`UnverifiedPatch(PatchRef)` is a newtype wrapping a patch reference. It is the
*only* thing a backend can produce. It carries no verifier evidence, so the type
system makes it **impossible to pass an `UnverifiedPatch` where a `VerifiedPatch`
is required** — integration/PR/completion APIs accept only `VerifiedPatch` (§3).
The newtype exists precisely so "a patch that hasn't been verified" is a distinct,
non-interchangeable type.

### 2.3 `VerifiedPatch` — verifier evidence

| Field | Meaning / rationale |
| --- | --- |
| `patch: PatchRef` | the patch that passed. |
| `verifier: VerifierName` | which verifier ran (e.g., the user-provided verify command). |
| `commands: Vec<CommandEvidence>` | the real command evidence from the clean-sandbox verify run — not the backend's self-reported `commands_run`. |
| `passed_at: Timestamp` | when verification passed. |
| `receipt: ToolReceipt` | the receipt tying the passing run to real, MAC-verified tool calls ([`receipts.md`](./receipts.md), invariant 10). |

A `VerifiedPatch` can only be minted by CrustCore's verifier path, never by a
backend. Its `receipt` field is what makes "the tests passed" *evidence* rather
than *narration* ([`receipts.md` §4](./receipts.md)).

---

## 3. Only a VerifiedPatch may integrate / complete / PR (invariant 13)

> Only `VerifiedPatch` may enter integration, GitHub PR creation, or completion.
> ([`ROADMAP.md` §7.5](../ROADMAP.md), **invariant 13**)

The integration, completion, and PR-creation APIs take `VerifiedPatch` by type:

```text
fn integrate(patch: VerifiedPatch, ...) -> ...
fn complete_task(patch: VerifiedPatch, ...) -> ...
fn open_pr(cap: &Approved<GitHubWriteCap>, patch: VerifiedPatch, ...) -> ...
```

Because these accept only `VerifiedPatch`, and only the verifier mints one, there
is no path for a self-claimed or unverified patch to ship. PR creation
*additionally* requires an `Approved<GitHubWriteCap>` (irreversible — invariant
14; [`policy.md`](./policy.md)). The patch lifecycle is recorded as events:
`PatchProposed` → `PatchVerified`/`PatchRejected` ([`event-log.md` §2](./event-log.md)).

**Enforcement is by type** ([`INVARIANTS.md` #13](../INVARIANTS.md)): a
`BackendResult` from any backend is *unverified* until CrustCore reruns the
verifier in a **clean sandbox** ([`sandbox.md`](./sandbox.md)) and produces a
`VerifiedPatch` ([`CLAUDE.md` §9.3](../CLAUDE.md)).

**Tested by** the golden task "fix failing test" — completion is blocked until
verify passes ([`INVARIANTS.md` #13](../INVARIANTS.md), [`ROADMAP.md` §19.4](../ROADMAP.md)).

---

## 4. External workers are patch producers, not truth authorities (invariant 6)

> Codex CLI and Claude Code are external workers. They are **not privileged
> peers**. ([`ROADMAP.md` §11.4](../ROADMAP.md))

External workers produce `UnverifiedPatch`es and `self_claimed_done` claims —
both of which are untrusted (invariants 6, 7). A worker that claims done but whose
patch fails the verifier **does not complete the task**
([`INVARIANTS.md` #6](../INVARIANTS.md), worker-contract tests).

### 4.1 External worker input contract

The supervisor hands an external worker exactly this ([`ROADMAP.md` §11.4](../ROADMAP.md)):

```json
{
  "task_id": "...",
  "goal": "...",
  "repo_root": "/sandbox/worktree",
  "allowed_roots": ["/sandbox/worktree", "/sandbox/tmp"],
  "forbidden_paths": ["~/.ssh", "~/.config", "/etc", "/var"],
  "network": "deny",
  "secrets": "none",
  "max_seconds": 1800,
  "max_output_mb": 50,
  "must_return": ["summary", "diff", "tests_run", "commands_run", "risks", "files_changed"]
}
```

Notes on the contract:

- `repo_root` / `allowed_roots` confine the worker to a throwaway worktree (+ a
  tmp area). Writes outside these are rejected (§4.3).
- `forbidden_paths` explicitly excludes sensitive home/system paths.
- `network: "deny"` — default network posture is deny-all egress
  ([`policy.md` §6](./policy.md), [`sandbox.md`](./sandbox.md), invariant 9).
- `max_seconds` / `max_output_mb` are budgets (invariant 11); bounded output
  capture ([`CLAUDE.md` §6.5](../CLAUDE.md)).
- `must_return` is the worker's reporting obligation — but everything it returns is
  treated as *untrusted claims* and re-derived/verified by the supervisor (§4.2).
- **No secrets are passed to workers.** `"secrets": "none"` is an explicit field
  in the input contract ([`ROADMAP.md` §11.4](../ROADMAP.md); invariants 1–3;
  [`secrets.md`](./secrets.md)) — not merely implied by the deny posture. Git
  that needs credentials goes through the credential proxy, not worker env
  ([`github.md`](./github.md)).

### 4.2 Supervisor validation steps

The supervisor validates every external-worker result ([`ROADMAP.md` §11.4](../ROADMAP.md)):

```text
capture transcript
extract actual diff from worktree
reject outside-root changes
classify changed files
rerun verifier in clean sandbox
run reviewer/security pass
only integrate VerifiedPatch
```

| Step | Why |
| --- | --- |
| **capture transcript** | record what the worker did as an artifact (untrusted data; possibly secret-bearing → redacted — [`secrets.md`](./secrets.md), invariant 2). |
| **extract actual diff from worktree** | trust the worktree, not the worker's self-reported diff — the real change is what's on disk. |
| **reject outside-root changes** | enforce confinement: any write outside `allowed_roots` rejects the result (§4.3). |
| **classify changed files** | flag sensitive files (CI workflows, auth, deps) for the reviewer/security pass and deny/ask defaults ([`policy.md`](./policy.md)). |
| **rerun verifier in clean sandbox** | the worker's `commands_run`/`self_claimed_done` are not evidence; CrustCore reruns the verifier itself ([`sandbox.md`](./sandbox.md), invariant 9, 13). |
| **run reviewer/security pass** | reviewer + security auditor can block integration ([`ROADMAP.md` §12.6](../ROADMAP.md), §11.2). |
| **only integrate VerifiedPatch** | the gate (§3) — nothing ships without a minted `VerifiedPatch`. |

### 4.3 Hard rules for workers

- **No secrets to workers.** Workers never receive raw credentials or
  secret-bearing logs (invariants 1, 2). Credentialed operations go through
  proxies ([`secrets.md`](./secrets.md), [`github.md`](./github.md)).
- **Writes outside the worktree are rejected.** Any change outside `allowed_roots`
  fails the result ([`ROADMAP.md` §18 Phase 6](../ROADMAP.md) acceptance). **Tested
  by** the red-team fixture "external worker writes outside worktree"
  ([`ROADMAP.md` §19.3](../ROADMAP.md), [`INVARIANTS.md` red-team requirement](../INVARIANTS.md)).
- **Worker output is untrusted data** (invariant 7): a worker transcript that says
  "ignore policy" or "reveal the token" is data, not instruction
  ([`security-model.md`](./security-model.md)).
- **Workers are not truth authorities** (invariant 6): `self_claimed_done` is
  advisory; only the verifier completes a task.

---

## 5. Phase 5 & 6 tasks and acceptance

### 5.1 Phase 5 — Worktree and verify loop ([`ROADMAP.md` §18 Phase 5](../ROADMAP.md))

**Goals:** local single-task coding harness; verifier-owned completion.

```text
P5.1 Create/reuse git worktree per task.
P5.2 Detect or accept verify command.
P5.3 Run verify in sandbox.
P5.4 Produce UnverifiedPatch and VerifiedPatch flow.
P5.5 Implement completion only from VerifiedPatch.
P5.6 Add golden task: fix failing test.
```

**Acceptance:**

```text
`crustcore run -dir . -goal ... -verify ...` creates task and runs verify.
Patch cannot complete until verifier passes.
Failing verify loops or exits with clear state.
```

### 5.2 Phase 6 — External backend protocol ([`ROADMAP.md` §18 Phase 6](../ROADMAP.md))

**Goals:** backend contract; external helper model transport; Codex/Claude Code
subprocess adapters.

```text
P6.1 Define BackendResult schema.
P6.2 Implement external command backend.
P6.3 Implement Codex CLI adapter.
P6.4 Implement Claude Code adapter.
P6.5 Implement transcript capture and diff extraction.
P6.6 Add worker contract tests.
```

**Acceptance:**

```text
Any backend result is unverified until verifier passes.
External workers cannot access secrets.
External worker writes outside worktree are rejected.
```

These satisfy v0.1 DoD #3–#5 (local repo task in a disposable worktree; verify
command determines completion; an unverified patch cannot complete) and the
external-backend-contract proof point ([`ROADMAP.md` §22, §21](../ROADMAP.md),
[`CLAUDE.md` §2.2](../CLAUDE.md)).

---

## 6. Summary: the gate in one picture

```text
 native agent ┐
 Codex CLI    ├─▶ BackendResult { self_claimed_done, patch: UnverifiedPatch, ... }
 Claude Code  │            │   (untrusted claim — invariants 6, 7)
 future worker┘            ▼
                  supervisor validation (§4.2)
                  + rerun verifier in CLEAN SANDBOX
                           │
                  ┌────────┴────────┐
              fails │             passes
                    ▼                 ▼
             PatchRejected       VerifiedPatch { receipt, commands, passed_at }
             (no completion)          │
                                      ▼
                    integrate / complete / open PR   (invariant 13)
                    (PR also needs Approved<GitHubWriteCap> — invariant 14)
```

A patch is done only after verifier evidence. Everything before the verifier is a
proposal.
