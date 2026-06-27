# docs/product-stack.md — CrustCore As The Proof Layer

> **Purpose:** define where CrustCore sits in a full agentic coding product and
> how the product layers may move fast without widening the trusted kernel.

CrustCore's strongest product shape is not "another coding model." It is the
proof-native control plane below powerful coding agents: models and workers may
plan, explore, and propose; CrustCore authorizes, confines, verifies, receipts,
and decides what becomes real.

```text
Product surfaces
  GitHub App, web cockpit, CLI/chat, optional Telegram, later IDE extension

Agent orchestration
  task queue, planner, executor registry, fan-out, repair loop, budget manager

Verification intelligence
  repo profile, test graph, verifier planner, CI monitor, evidence bundle builder

CrustCore trust core
  policy, approvals, secrets, receipts, event log, sandbox, VerifiedPatch

Execution layer
  Codex, Claude Code, local models, MCP tools, shell/git/test runners

State and memory
  session/artifacts, repo index, vector/RAG pack, telemetry, audit store
```

## Product Promise

```text
Delegate coding work and receive a draft PR with proof, not vibes.
```

The product should feel fast during exploration and strict only when work tries
to become real. The strict boundary is the value: a candidate patch must be
confined, verified, receipted, and approved before it opens a draft PR or claims
completion.

## Stack Responsibilities

| Layer | Owns | Must not own |
| --- | --- | --- |
| Product surfaces | onboarding, issue commands, cockpit views, approvals, status | verifier authority, raw secrets |
| Orchestration | routing, fan-out, retries, repair attempts, task budgets | final "done" decisions |
| Verification intelligence | selecting/ordering checks, weak-evidence warnings, evidence bundle assembly | bypassing failed checks |
| Trust core | policy, approvals, sandbox, receipts, event log, `VerifiedPatch` | provider SDKs, databases, UX state |
| Execution layer | producing candidate changes and tool results | user communication or integration authority |
| State/memory | sessions, artifacts, repo facts, retrieval, telemetry | policy decisions or approvals |

## First Wedge

The first serious product wedge is the **GitHub PR Supervisor for small
engineering teams**:

1. Install/configure CrustCore for a repo.
2. Delegate an issue or chat task.
3. Run one or more executors in isolated worktrees.
4. Rerun the repo verifier in a sandbox.
5. Mint a `VerifiedPatch` only on success.
6. Push a scoped branch and open a draft PR with an evidence bundle.
7. Monitor CI and run bounded repair attempts.
8. Surface a clear completed or blocked state.

## Product Contracts

The product layer starts with four stable contracts in
`crustcore_daemon::product`:

- `RepoProfile`: parsed from `crustcore.yml`, trusted setup only.
- `RepoSignals` + `TaskShape`: adapter-supplied repo facts and product task
  classification; `RepoSignals::from_paths` and
  `TaskShape::from_changed_paths` provide deterministic path-based defaults,
  never authority.
- `VerifierPlan`: deterministic check ordering, task gates, and weak-evidence
  warnings before execution.
- `TaskLifecycle`: product-facing states such as `Queued`, `Verifying`,
  `MonitoringCi`, `Repairing`, `Blocked`, `Completed`.
- `ExecutorCapability`: executor metadata for routing and UX; never authority.
- `EvidenceBundle`: stable evidence artifact for draft PR bodies, cockpit views,
  and audit export.

Example `crustcore.yml`:

```yaml
policy_mode: verified
risk_tier: standard
branch_prefix: crustcore
verify:
  - cargo test --workspace
  - cargo clippy --workspace -- -D warnings
executors:
  - codex
  - claude-code
budget:
  max_wall_ms: 1800000
  max_output_bytes: 1048576
  max_tokens: 200000
  repair_attempts: 2
github:
  repo: RNT56/CrustCore
  base_branch: main
  open_draft_pr: true
  labels: crustcore, needs-human-review
ui:
  cockpit: true
  telegram: false
```

## Non-Negotiables

- The product may add aggressive routing, UX, and repair loops; it may not add a
  second authority path around `VerifiedPatch`.
- Repo files, GitHub content, CI logs, MCP output, and model text remain
  untrusted data.
- Secrets stay behind the broker/credential proxy; raw credentials never enter
  prompts, logs, sandboxes, or config files.
- Live sockets are thin adapters; deterministic decision cores stay CI-testable.
- Nano remains the trusted harness and never links HTTP/TLS/DB/provider stacks.
