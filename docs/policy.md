# docs/policy.md — Risk / Capability / Approval Engine

> **⚠️ CONTRACT FILE.** This is a
> [contract file](../CLAUDE.md#73-contract-files--serialized-changes-only):
> changes are serialized (one PR at a time) and require maintainer approval. Do
> not edit it in parallel with other work, and do not bundle a policy-contract
> change into unrelated tasks.

> **Purpose:** define CrustCore's risk/capability/approval engine — typed
> capability tokens, typed approval tokens, the `PolicySnapshot` every side effect
> passes through, deny/ask defaults, and risk profiles adapted to coding.

**Cross-links:** [`ROADMAP.md` §8](../ROADMAP.md) (typed safety model),
[`ROADMAP.md` §15.2](../ROADMAP.md) (GitHub deny/ask defaults),
[`ROADMAP.md` §1.3](../ROADMAP.md) (ZeroClaw risk profiles),
[`INVARIANTS.md` #4, #8, #14](../INVARIANTS.md),
[`CLAUDE.md` §4](../CLAUDE.md).
**Sibling docs:** [`architecture.md`](./architecture.md) (kernel emits actions
gated by policy), [`secrets.md`](./secrets.md), [`sandbox.md`](./sandbox.md),
[`backend-contract.md`](./backend-contract.md), [`github.md`](./github.md),
[`receipts.md`](./receipts.md).

---

## 1. Principle: pass authority objects, not booleans

CrustCore's Rust-specific advantage is making dangerous states **impossible to
represent** ([`ROADMAP.md` §8](../ROADMAP.md), [`CLAUDE.md` §6.5](../CLAUDE.md)).
The policy engine's core rule:

> **Do not pass booleans like `can_write`. Pass authority objects.**
> ([`ROADMAP.md` §8.3](../ROADMAP.md))

A boolean `can_write: bool` carries no scope, no expiry, no provenance, and is
trivially forged or defaulted to `true`. A capability *token* is an unforgeable
value that can only be **minted by the policy engine** and that carries the exact
authority it grants — which root, which scope, which repo, which sandbox profile.
A tool that needs authority takes the token *by reference* in its signature; if
you do not hold the token, the call does not type-check. This is the structural
enforcement of **invariant 8** (*every side effect passes through policy*): no
token, no effect.

---

## 2. Capability tokens

The capability set ([`ROADMAP.md` §8.3](../ROADMAP.md)):

```rust
pub struct FsReadCap     { root: WorktreeRoot,  scope: ScopeId }
pub struct FsWriteCap    { root: WorktreeRoot,  scope: ScopeId }
pub struct NetworkCap    { allowlist: DomainAllowlist, scope: ScopeId }
pub struct GitHubWriteCap { repo: RepoRef, branch_prefix: BranchPrefix, scope: ScopeId }
pub struct SandboxExecCap { profile: SandboxProfileRef, scope: ScopeId }
```

| Token | Grants | Bound to |
| --- | --- | --- |
| `FsReadCap` | structured reads/search | a `WorktreeRoot` + `ScopeId` |
| `FsWriteCap` | structured writes / patch apply | a `WorktreeRoot` + `ScopeId` |
| `NetworkCap` | egress | a `DomainAllowlist` (empty = deny all) + `ScopeId` |
| `GitHubWriteCap` | branch/PR writes | a `RepoRef` + `BranchPrefix` + `ScopeId` |
| `SandboxExecCap` | command execution | a `SandboxProfileRef` + `ScopeId` |

**Rationale & rules:**

- Each token names *exactly* its authority. An `FsWriteCap` is bound to one
  `WorktreeRoot`; it cannot write outside that root because the confined-path
  types ([`ROADMAP.md` §8.2](../ROADMAP.md)) only resolve relative to that root.
- `NetworkCap` carries a `DomainAllowlist`. Per the NullClaw allowlist lesson
  ([`ROADMAP.md` §1.2](../ROADMAP.md)), an **empty allowlist means deny all**, and
  `*` is an explicit opt-in, never a default. Default network posture is
  deny-all egress ([`sandbox.md`](./sandbox.md), [`ROADMAP.md` §10.3](../ROADMAP.md)).
- `SandboxExecCap` is bound to a `SandboxProfileRef`: there is **no** host-shell
  escape hatch. Every execution-capable operation runs under an explicit profile
  (**invariant 9**). See [`sandbox.md`](./sandbox.md).
- `ScopeId` ties a token to a task/job scope so it can be revoked and audited;
  capabilities do not float free of the work that justified them.

### 2.1 Tools require tokens (signatures)

Side-effecting tools take the token in their signature ([`ROADMAP.md` §8.3](../ROADMAP.md)):

```rust
fn write_file(cap: &FsWriteCap, path: ConfinedWritePath<'_>, bytes: &[u8]) -> Result<()>;
fn run_command(cap: &SandboxExecCap, spec: CommandSpec) -> Result<CommandResult>;
fn push_branch(cap: &Approved<GitHubWriteCap>, branch: BranchRef) -> Result<()>;
```

Note the asymmetry that *is the design*:

- `write_file` takes both a `FsWriteCap` **and** a `ConfinedWritePath`. The cap
  authorizes "may write under this root"; the confined path proves "this exact
  path is inside that root and symlink-safe" ([`ROADMAP.md` §8.2](../ROADMAP.md)).
  A raw `&str` path can never reach a write tool.
- `run_command` takes `SandboxExecCap` — there is no `run_command` without a
  sandbox profile.
- `push_branch` takes `Approved<GitHubWriteCap>`, not a bare `GitHubWriteCap`,
  because pushing a branch is irreversible enough to require an approval token
  (§4, invariant 14).

**Edge cases / testing notes:**

- A "no-token side effect" audit ([`INVARIANTS.md` #8](../INVARIANTS.md)) scans
  for any side-effecting path that does not require a token.
- Compile-time: removing the cap parameter must break the build, not just a test.
- A capability is *not* transferable across scopes: tests assert a token minted
  for scope A cannot be replayed against scope B.

---

## 3. The PolicySnapshot — every side effect passes through policy

The kernel holds an immutable `PolicySnapshot` ([`architecture.md` §2](./architecture.md),
[`ROADMAP.md` §5.2](../ROADMAP.md)). It is a point-in-time, deterministic view of
the active policy that `Kernel::step` reads when deciding whether to emit an
action and which tokens to mint.

Flow for any side effect (**invariant 8**):

```text
proposed effect (model/subagent/worker)   <- a request, not authority
        │
        ▼
Kernel::step consults PolicySnapshot
        │
        ├── denied   -> Event::ToolCallDenied / RiskDetected, no action
        ├── ask      -> Action::RequestApproval (ApprovalRequested event)
        └── allow    -> mint capability token, emit Action with that token
```

Because the kernel only ever *emits actions* (it never performs effects itself —
[`architecture.md` §2](./architecture.md)), and an action is only emitted after
the snapshot is consulted, there is no code path for an ungoverned side effect.
Policy is **data the kernel evaluates**, not behavior the kernel imports: the
`PolicySnapshot` is deterministic so the same `(state, event, snapshot)` always
yields the same decision — which is what makes policy decisions unit-testable and
replayable ([`event-log.md`](./event-log.md)).

**Determinism note:** approval *resolution* (a human pressing approve) arrives as
a later event; the snapshot does not change underneath an in-flight step.

---

## 4. Approval tokens

Reversibility classification and the approval wrapper ([`ROADMAP.md` §8.4](../ROADMAP.md)):

```rust
pub enum Reversibility {
    Reversible,
    ReversibleWithCleanup,
    Irreversible,
    Destructive,
}

pub struct Approved<T> {
    pub value: T,
    pub approval_id: ApprovalId,
    pub approved_by: AuthorizedUser,
    pub expires_at: Timestamp,
}
```

**Rules:**

- **Irreversible operations require `Approved<IrreversibleAction>`**
  ([`ROADMAP.md` §8.4](../ROADMAP.md), **invariant 14**). The type forces it: an
  API that performs an irreversible action takes `Approved<…>`, so it cannot be
  called without a real approval token. Merge, deploy, write secrets, force-push,
  publish, and branch-protection changes are the canonical irreversible set
  ([`CLAUDE.md` §6.3](../CLAUDE.md), [`ROADMAP.md` §15.2](../ROADMAP.md)).
- `Approved<T>` is **generic** so the same approval machinery wraps any authority:
  `Approved<GitHubWriteCap>`, `Approved<IrreversibleAction>`, etc. The wrapper
  carries *who* approved (`AuthorizedUser`), *which* approval (`approval_id`,
  nonce-bound), and *when it expires* (`expires_at`).
- Approvals **expire** and are **operation-bound** ([`ROADMAP.md` §3.1](../ROADMAP.md)
  queue/steer; [`telegram.md`](./telegram.md) nonce approvals). An approval for
  one exact nonce-bound operation cannot be replayed for a different operation or
  after expiry.
- `Reversibility` is the typed gate deciding *which* operations need approval.
  Reversible work (edit/build/test/lint/local commit/worktree ops) runs
  autonomously; irreversible/destructive work gates ([`CLAUDE.md` §6.3](../CLAUDE.md)).

### 4.1 Edge cases / testing notes

- **Expired approval:** an `Approved<T>` past `expires_at` must be rejected at use
  time, not merely at mint time. Test: approve, advance the clock, attempt the
  operation, assert denial.
- **Wrong-operation replay:** an approval minted for operation X must not satisfy
  operation Y. Test the nonce binding.
- **Per-class coverage:** policy tests cover each irreversible operation class
  ([`INVARIANTS.md` #14](../INVARIANTS.md)).

---

## 5. The model cannot approve its own side effects (invariant 4)

> **Self-approval defeats the entire safety model.** ([`INVARIANTS.md` #4](../INVARIANTS.md))

`Approved<T>` tokens are minted **only** by the approval engine, **only** from an
authorized human (a Telegram nonce or the local CLI), and **never** from model
output ([`INVARIANTS.md` #4](../INVARIANTS.md), [`ROADMAP.md` §8.4](../ROADMAP.md)).

The structural enforcement:

- There is no constructor for `Approved<T>` reachable from model-derived data.
  Model output enters the kernel as `Event::ModelOutput` (untrusted —
  [`architecture.md` §3](./architecture.md), invariant 7); it can *request* an
  action but cannot *carry* an approval token.
- `approved_by: AuthorizedUser` cannot be populated from model context. The set of
  authorized users is bound at setup (approved Telegram chat IDs / local CLI —
  [`ROADMAP.md` §9.1](../ROADMAP.md), trust zones [`security-model.md`](./security-model.md)).
- A model-originated string claiming "approved" is just untrusted data. **Tested
  by** policy tests asserting model-originated "approvals" are rejected
  ([`INVARIANTS.md` #4](../INVARIANTS.md)).

This is the policy-layer twin of invariant 6 (external workers are patch
producers, not truth authorities — [`backend-contract.md`](./backend-contract.md)):
neither a model nor a worker can self-authorize a side effect.

---

## 6. Deny / ask defaults

Defaults are deny- or ask-biased. The canonical defaults for GitHub
([`ROADMAP.md` §15.2](../ROADMAP.md), see also [`github.md`](./github.md)):

| Operation | Default |
| --- | --- |
| merge PR | **ask always** |
| force-push | **deny default** |
| delete tag/release | **ask / high risk** |
| write GitHub secrets | **ask always** |
| change branch protection | **deny default** |
| modify GitHub Actions workflow | **ask always** |

Network defaults ([`ROADMAP.md` §10.3](../ROADMAP.md)): deny all egress;
allowlist per task/profile; package install requires approval; a new host
requires approval. Empty allowlist means deny all; `*` is an explicit opt-in
([`ROADMAP.md` §1.2](../ROADMAP.md)).

These defaults are *policy data* in the `PolicySnapshot`, so they are testable and
auditable, and they map cleanly onto the three outcomes in §3
(allow / ask → `RequestApproval` / deny).

---

## 7. Risk profiles (adapted to coding)

CrustCore adapts ZeroClaw's `readonly` / `supervised` / `full` profiles to
**coding-specific** risk ([`ROADMAP.md` §1.3](../ROADMAP.md)), aligned with the
sandbox execution tiers ([`sandbox.md`](./sandbox.md), [`ROADMAP.md` §10.1](../ROADMAP.md)):

| Profile | Reads | Structured writes | Sandboxed exec | Irreversible (merge/push/deploy) |
| --- | --- | --- | --- | --- |
| **readonly** | yes | no | no (Tier 0: plan/review/summarize) | no |
| **supervised** | yes | yes (worktree-confined) | yes (Tier 1–2: tests/builds/shell) | only with `Approved<…>` (ask) |
| **full** | yes | yes | yes (up to Tier 3 hostile, network-denied) | only with `Approved<…>` (ask) |

Key adaptations to coding:

- Even **full** never makes irreversible GitHub actions auto-allowed: merge /
  force-push / secret-write / branch-protection still gate per §6 and invariant
  14. "Full" widens *reversible* autonomy (more execution tiers, broader
  allowlists), not the irreversible gate.
- The profile selects the *default* `PolicySnapshot`; explicit per-task policy and
  per-tool MCP policy ([`mcp.md`](./mcp.md)) refine it.
- Profiles compose with capability scoping: a `supervised` task still operates
  through `FsWriteCap`/`SandboxExecCap` tokens bound to its worktree and profile.

---

## 8. How policy ties the system together

- Every model-visible tool result that policy allowed still carries a **receipt**
  (invariant 10, [`receipts.md`](./receipts.md)); policy decides *whether*, the
  receipt proves *that* it ran.
- Every policy decision and approval is an **event** in the hash-chained log
  (`ApprovalRequested`, `ApprovalResolved`, `ToolCallApproved`, `ToolCallDenied`,
  `RiskDetected` — [`event-log.md`](./event-log.md), [`ROADMAP.md` §7.3](../ROADMAP.md)),
  so `crustcore inspect` can replay exactly what was allowed and why.
- Secrets never flow through policy as values — policy authorizes a *tool* to
  receive a one-shot secret view or use a credential proxy; the model sees only
  handles ([`secrets.md`](./secrets.md), invariants 1–3).

**Acceptance / testing summary:**

- Policy decision unit tests + the ungoverned-side-effect audit (invariant 8).
- Per-irreversible-class approval tests (invariant 14).
- Model-originated-approval rejection tests (invariant 4).
- Red-team fixture: "model asks user to approve unsafe action with misleading
  text" ([`ROADMAP.md` §19.3](../ROADMAP.md), [`THREAT_MODEL.md`](../THREAT_MODEL.md)) —
  approval text must describe the exact bound operation, and approval is
  nonce/operation-bound so misleading framing cannot retarget it.
