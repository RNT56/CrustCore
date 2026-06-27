# docs/world-class-agent-roadmap.md — Proof-Native Agent Product Roadmap

> **Purpose:** turn the CrustCore verifier kernel into a high-value autonomous
> coding product while preserving the kernel and its invariants.

This roadmap implements the first product wedge: a **GitHub PR Supervisor for
small engineering teams**. The product delegates to strong models and external
workers, but CrustCore remains the only authority for policy, secrets,
approvals, sandboxed execution, receipts, completion, and integration.

## Phase 0 — Truth Baseline

**Goal:** make the product direction durable and implementation-ready.

- Keep release metadata honest: when a release is cut, align workspace version,
  changelog, README badges, release notes, and git tags together.
- Keep `docs/product-stack.md` as the stack-positioning source.
- Keep this roadmap as the execution overlay for product work; it does not
  replace `ROADMAP.md` or `CLAUDE.md`.
- Preserve the kernel. Product code lives in sidecars/capability packs unless a
  contract-file change is explicitly serialized and reviewed.

**Acceptance gates**

- `cargo xtask verify`
- `cargo xtask full-size`
- no new nano dependency leakage
- release metadata consistency before any tag/publish step
- manual live smoke checklist updated before release

## Phase 1 — GitHub PR Supervisor MVP

**Goal:** one issue can become one evidence-backed draft PR.

- GitHub App onboarding: install app, select repo, choose branch prefix,
  configure verifier commands, confirm sandbox readiness, and store credentials
  through the broker or vault.
- Issue intake: normalize issue/comment/webhook content as untrusted data and
  create a bounded supervised task.
- Draft PR loop: worker patch -> sandbox verify -> `VerifiedPatch` -> scoped
  branch push through the credential proxy -> draft PR from verifier evidence.
- CI monitor: watch checks, ingest logs as untrusted data, create bounded repair
  tasks, stop after configured attempts, and surface blocked state.
- PR evidence body: verifier commands, check status, changed files summary,
  unresolved risks, receipts/event-log refs, and "human review required."

**Acceptance gates**

- Golden `issue-to-draft-pr` passes against deterministic GitHub fixtures.
- A real repo issue can be delegated in a live smoke without raw model-held
  GitHub tokens.
- No unverified patch can open a PR.
- Failed CI creates at most the configured repair attempts.

**Current foothold:** `crustcore-eval` now runs a deterministic
`golden_issue_to_pr_flow` over untrusted issue text, a sandboxed worker,
`VerifiedPatch`, approved draft PR intent, canned GitHub REST, and bounded repair
decisions. The remaining Phase 1 gap is the live branch push / real draft PR
smoke with maintainer-owned credentials.

## Phase 2 — Verification Intelligence

**Goal:** CrustCore can explain "done," "not done," and "not enough evidence."

- Parse `crustcore.yml` into `RepoProfile`.
- Build verifier planning from repo shape and profile: targeted checks first,
  full checks before completion, weak-evidence warnings when the configured
  verifier is shallow.
- Add task-specific gates: regression test for bug fixes, browser smoke for UI
  changes, lockfile/security checks for dependency changes, lighter checks for
  docs-only changes.
- Emit an `EvidenceBundle` for every attempt and reference it from PR/cockpit
  views.

**Acceptance gates**

- `RepoProfile` parser fails closed on unknown policy/executor keys.
- Evidence bundle is insufficient without verifier commands, patch hash, and
  receipts.
- PR body rendering is evidence-first and review-gated.

## Phase 3 — Strongest Execution Layer

**Goal:** use the best executor for the job without trusting any executor.

- Treat Codex, Claude Code, local model loops, external commands, and MCP tools
  as replaceable executor capabilities.
- Route quick fixes to a single executor; route features to fan-out; route risky
  work through advisor/security review; route large projects through
  planner/decomposer flows.
- Upgrade fan-out from first-passing to scored verified candidates: correctness
  gate first, then smaller diff, lower risk, stronger tests, and clearer PR
  evidence.
- Persist repo memory: prior failures, common verifier commands, flaky tests,
  ownership hints, file clusters, and previous successful repairs.

**Acceptance gates**

- Multiple executor candidates can be compared without honoring self-claims.
- Winner selection only considers verifier-accepted candidates.
- Executor metadata never grants capabilities or approvals.

## Phase 4 — Product UX

**Goal:** a developer can delegate and review without reading raw logs; an
auditor can still inspect every proof.

- Extend the loopback dev UI into a cockpit: tasks, lifecycle, logs, evidence
  bundles, approvals, diffs, CI state, and "why blocked."
- Add GitHub-native controls: `/crustcore run`, `/crustcore retry`,
  `/crustcore explain`, `/crustcore stop`, plus evidence/risk labels.
- Keep chat and Telegram as operator channels; make GitHub + cockpit the default
  team workflow.
- Use progressive disclosure: normal view shows status/evidence; advanced view
  opens receipts, event frames, sandbox logs, and policy decisions.

**Acceptance gates**

- UX renders queued/running/blocked/completed states from `TaskLifecycle`.
- Evidence bundle rendering is available in PR and cockpit paths.
- No UX path can approve, complete, or integrate without existing typed gates.

## Phase 5 — Team And Enterprise Hardening

**Goal:** teams can run CrustCore with clear admin controls and proof exports.

- Org policy profiles: allowed repos, allowed executors, maximum budgets,
  forbidden paths, approval requirements, workflow-edit gates, and merge
  prohibition.
- Deployment modes: local single-user, self-hosted team daemon, GitHub App
  installation, and air-gapped/offline.
- Observability: task success rate, verifier failure reasons, repair attempts,
  cost/tokens, executor win rate, time-to-PR, and redaction canaries.
- Audit export: JSONL/SARIF-style evidence exports for review and compliance.

**Acceptance gates**

- Policy profile cannot be weakened by repo/GitHub/model content.
- Audit export carries evidence refs without raw secrets.
- Deployment docs include backup/restore and rollback.

## Phase 6 — Ecosystem And Platform

**Goal:** other agent products can use CrustCore as their proof layer.

- Stabilize SDK surfaces for task submission, evidence bundle readout, approval
  requests, executor plugins, and verifier plugins.
- Publish templates: GitHub auto-fix bot, CI repair bot, dependency update
  verifier, security patch reviewer, docs updater.
- Add plugin registry metadata while keeping plugin execution behind sandbox,
  receipt, and policy gates.

**Acceptance gates**

- SDK consumers cannot construct `VerifiedPatch`.
- Plugins cannot bypass receipts, sandboxing, or redaction.
- Templates ship with golden and red-team fixtures.

## Manual Live Smoke Checklist

These are intentionally not CI jobs because they require real network, secrets,
or maintainer-owned release steps.

```text
1. Build:
   cargo xtask verify
   cargo xtask full-size

2. Chat:
   cargo run -p crustcore --features chat -- chat
   Ask one converse question and one task-like request; confirm task routing.

3. GitHub App:
   Configure a test repo with a branch prefix such as crustcore/smoke.
   Mint an installation token through the broker path.
   Confirm classic PAT mode emits a warning if used.

4. PR Supervisor:
   Delegate a small issue in a disposable test repo.
   Confirm worker output is an unverified proposal.
   Confirm sandbox verifier mints a VerifiedPatch only on pass.
   Confirm draft PR body includes verifier evidence and human-review notice.

5. CI Repair:
   Force a failing check in the test repo.
   Confirm CI logs are treated as untrusted data.
   Confirm repair attempts stop at the configured cap.

6. Audit:
   Run crustcore inspect/export on the produced log.
   Confirm evidence bundle references receipts/event frames.
   Confirm no raw token appears in output, logs, PR body, or evidence.
```
