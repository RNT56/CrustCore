# docs/roadmap-v0.6.md — Post-v0.5.0 Execution Overlay

> **Purpose:** the concrete, ready-to-build task overlay for the wave of work
> that follows v0.5.0. This document does **not** replace [`ROADMAP.md`](../ROADMAP.md)
> or [`CLAUDE.md`](../CLAUDE.md), and it does not restate product vision —
> [`docs/world-class-agent-roadmap.md`](./world-class-agent-roadmap.md) owns the
> Phase 0–6 product narrative. This is the *execution overlay*: dependency-ordered,
> file-grounded task specs that turn that vision into buildable units of work.

---

## Where v0.5.0 left things

By v0.5.0 the trusted core and the capability packs are feature-complete and
merged: the sync/deterministic `Kernel::step`, hash-chained event log + tool
receipts, path confinement, the runner/sandbox stack, the worktree verify loop
minting type-sealed `VerifiedPatch`, and every Track A/B/C capability pack
(net, daemon, mcp, index, the v0.4 ergonomics packs) as std-only decision cores
behind `live` features.

On top of that, the **GitHub PR Supervisor foundation (PR #66)** landed the
deterministic product spine: `RepoProfile` / `VerifierPlan` / `EvidenceBundle` /
`TaskLifecycle` and `RepoSignals` in `crustcore_daemon::product`, the
`golden_issue_to_pr_flow` decision path, the credential-proxy push validator
(`parse_push_argv` / `validate_push` in `crustcore_daemon::github`), the
`open_pr` intent core (`crustcore_backend::integrate`), the `RestGitHub` REST
client (`crustcore_net::github`), the hardened webhook verifier, and the bounded
live path adapter `crustcore_daemon::repo_profiler`.

**What this overlay covers** is the next wave: closing the GitHub PR-supervisor
*live seams* end-to-end, layering verification intelligence and a scored
execution layer on top of the existing decision cores, building the product UX
surfaces (cockpit, GitHub commands, Slack), and hardening the long-running
daemon for real operation. Everything here is grounded in files that exist
today; each spec separates the **CI-testable pure core** from the **irreducible
live seam** (real network, secrets, sandbox backend, or filesystem), and the
irreversible maintainer-owned steps are isolated in an appendix.

**The contract still holds.** No task here widens the trust boundary. Nano is
untouched (all work lives in `crustcore-daemon`, `crustcore-net`,
`crustcore-backend`, `crustcore-index`, `crustcore-session`, and
`crustcore-dev`, all non-nano and already `live`-gated). Only a `VerifiedPatch`
completes or opens a PR (invariant 13); only typed `Approved<T>` authorizes
irreversible actions (invariant 14); the model never approves its own side
effects (invariant 4).

---

## Dependency-ordered phase plan

The tasks group into six phases. The ordering reflects what unblocks what, not
calendar time. Phases A and F are independent of everything and can start
immediately; B and C build the intelligence layer; D wires it live; E is the
product-facing surface that consumes all of it.

| Phase | Theme | Unblocked by |
| --- | --- | --- |
| **A. PR Supervisor go-live** | Close the five GitHub live seams: onboarding → push → draft PR → CI repair → smoke | PR #66 foundation (done) |
| **B. Verification intelligence** | Richer verifier test-graph, scored candidates, persistent repo memory | PR #66 foundation (done) |
| **C. Execution routing & review** | Task-shape executor routing, multi-verifier advisory gate, evidence rendering | B (signals/scoring help) |
| **D. Live executor wiring** | Connect routing + advisory to the live `WorktreeSubagentExecutor` | A.1, C.1, C.2 |
| **E. Product UX & channels** | Cockpit supervisor, GitHub `/crustcore` commands, Slack channel, CoT streaming analysis | C.3 (evidence), D (live tasks) |
| **F. Daemon hardening** | Cross-process recovery, admin socket, multi-repo, live-socket runbook | independent |

**Critical path:** A.1 (onboarding) → A.2/A.3 (push + draft PR) → A.4 (CI repair)
→ A.5 (smoke). In parallel: B.1/B.4 → B.2/C.1/C.2 → C.3 → D.1 → E. Phase F runs
beside everything.

---

## Phase A — PR Supervisor go-live

> Theme: make the supervisor drive a real repo end-to-end. The decision cores
> exist and are CI-tested; these tasks close the live network/credential seams.

### A.1 — `app-onboarding`: GitHub App install + credential mint + repo config

- **Goal:** a user installs the GitHub App on a repo, authorizes CrustCore to
  write PRs, mints short-lived installation tokens, and persists repo-scoped
  write capabilities.
- **Design (real refs):** capture the install redirect (`installation_id` +
  `setup_id`), confirm via `GET /app/installations/{id}`, and register the repo
  in `RepoRegistry` (`crustcore_daemon::github`). On first dispatch, mint via the
  stubbed `mint_installation_token(...)` (`crustcore_net::githubapp`, `live`-gated);
  the PEM key comes from the broker as `SecretMaterial`, never plaintext config.
  Cache the 1-hour token and refresh on expiry. Read `crustcore.yml` from the
  default branch and parse with the pure `RepoProfile::parse()`. Bind the
  onboarding GitHub user as an `AuthorizedUser` and mint an
  `Approved<GitHubWriteCap>` stored in daemon state.
- **CI core:** `RepoRegistry::register`/`cap_for`, approval minting
  (`AuthorizedUser::bind(...).approve(cap, id, now)`), `RepoProfile` parsing from
  `tests/fixtures/crustcore.yml.*`, expired-approval rejection (already covered
  by `merge_requires_a_valid_approval`).
- **Live seam (`#[ignore]`, `TODO(app-onboarding-live)`):** the real install
  redirect + `GET /app/installations/{id}` + token mint against a test App.
- **Invariants:** 1 (App key is `SecretMaterial`), 3 (token short-lived), 13/14
  (only a minted `Approved<GitHubWriteCap>` authorizes PR opening).
- **Acceptance:** canned test registers repo + capability; canned test parses a
  real `crustcore.yml`; `cargo test` green with no live socket; ignored smoke
  confirms install + mint.
- **Deps:** PR #66 cores. **Effort:** M. **Risk:** install redirect can fail
  silently (clear error messaging); token expiry can strand late tasks
  (refresh-on-expiry guard); missing `crustcore.yml` must guide the user, not
  silently default.

### A.2 — `cred-proxy-branch-push`: live branch push via the credential proxy

- **Goal:** run `git push origin crustcore/task:crustcore/task` in the sandbox
  without the token ever entering the subprocess; the proxy validates every ref
  against the `GitHubWriteCap` and mints a scoped short-lived credential outside
  the sandbox boundary.
- **Design (real refs):** a credential-helper subprocess (not the kernel, not the
  verifier runner). Git invokes it; it parses argv with `parse_push_argv` and
  validates with `validate_push(&cap, &req)` (both pure, CI-tested in
  `crustcore_daemon::github`). On pass it mints an installation token from the
  broker and returns it in the credential-helper protocol. The worktree git
  config (`crustcore_worktree::WorktreeManager`) is set to call *only* this
  helper — no fallback to `.git/credentials` or SSH.
- **CI core:** `parse_push_argv` (every force-flag spelling), `validate_push`
  (refspec smuggling, multi-ref, protected branches), token-minting path
  (mocked). Integration tests with a local git repo + mock helper: protected
  branch rejected, force rejected, in-prefix accepted.
- **Live seam (`#[ignore]`, `TODO(cred-proxy-live)`):** the helper-subprocess
  exec + the real push to GitHub.
- **Invariants:** 1 (token never enters sandbox), 9 (push confined to cap repo +
  prefix), 13 (push only after `run_verify`).
- **Acceptance:** unit + fixture tests green; ignored smoke pushes a real
  verified patch; out-of-prefix / protected-branch pushes fail; no token in
  worker/verifier env or logs.
- **Deps:** A.1 (registered repos + token mint). **Effort:** L. **Risk:** git
  credential-helper protocol is finicky (test with real git early); token expiry
  mid-push; helper crash detection; validate the git-config path against symlink
  escape.

### A.3 — `real-draft-pr-create`: wire draft PR creation end-to-end

- **Goal:** turn a `VerifiedPatch` + `Approved<GitHubWriteCap>` into a real
  GitHub draft PR whose body carries verifier evidence, not model claims.
- **Design (real refs):** call `open_pr(&approval, patch, head, base, now)`
  (`crustcore_backend::integrate`, pure + tested) to get a `PrIntent`; map it to
  a `CreatePrRequest`; call `RestGitHub::create_pull` (`crustcore_net::github`)
  with a broker-sourced token. Record the PR number/URL in the event log
  (`Event::GitHubObserved` or a new `Event::PrOpened`) chained to the patch
  receipt.
- **CI core:** `open_pr` draft-intent shape, body excludes `self_claimed_done`,
  `PrIntent → CreatePrRequest` mapping (new), canned `RestGitHub` create + parse,
  non-2xx (401/404/422) mapped to typed errors (never fake success).
- **Live seam (`#[ignore]`, `TODO(draft-pr-live)`):** the real `POST .../pulls`.
- **Invariants:** 6 (body is evidence, not model claim), 13 (only `VerifiedPatch`
  reaches `open_pr`), 14 (requires `Approved<GitHubWriteCap>`).
- **Acceptance:** PR created with correct title/base/head; body has verifier
  evidence + "human review required" notice, no secrets/self-claims; non-2xx
  handled gracefully.
- **Deps:** A.1 (cap + token). **Effort:** S. **Risk:** existing head branch →
  422 (retry with new branch or surface); token expiry mid-call; add timeout +
  backoff.

### A.4 — `ci-monitor-repair-loop`: watch checks, bounded repair attempts

- **Goal:** poll the PR's check-runs, decide repair-vs-surface, and spawn at most
  N repair tasks (`budget.repair_attempts`, default 2) before giving up.
- **Design (real refs):** poll `RestGitHub::check_state` (`crustcore_net::github`)
  with backoff; aggregate into `CheckState` (Pending/Passed/Failed); route through
  the pure `repair_decision(outcome, attempts, budget)` →
  `Green` / `SpawnRepair` / `StopExhausted` (`crustcore_daemon::github`). A repair
  task is a bounded sub-task: new worktree, re-derived changed files, worker fix,
  push to the same branch, re-watch checks, with its own verifier + approval gate.
  `TaskLifecycle` transitions `MonitoringCi → Repairing → MonitoringCi` (or
  `Blocked` on exhaustion).
- **CI core:** `repair_decision` over all outcome/attempt/budget combos,
  `CheckState` aggregation from canned check-runs, decision routing (`Passed→Green`,
  `Failed@0/2→SpawnRepair`, `Failed@2/2→StopExhausted`), repair-task shape +
  failure-context injection.
- **Live seam (`#[ignore]`, `TODO(ci-monitor-live)`):** the real polling loop.
- **Invariants:** 11 (repair bounded by budget), 4 (CrustCore decides repair, not
  a model comment), 7 (CI logs are untrusted; decision uses aggregated state, not
  log text).
- **Acceptance:** fixture PR with failing checks → repair spawned while under
  budget; `StopExhausted` after the cap; lifecycle transitions logged.
- **Deps:** A.3 (PRs must exist to monitor). **Effort:** L. **Risk:** long check
  runs vs. polling lease expiry (heartbeat/cancellation); branch race with a user
  push (lock or detect-and-surface); strictly enforce the budget + log metrics.

### A.5 — `live-issue-to-pr-smoke`: end-to-end issue → draft PR

- **Goal:** delegate a real GitHub issue in a test repo and watch the full loop
  (intake → worker → verify → push → PR) complete with no mock clients; assert
  the PR body is evidence, not claims.
- **Design (real refs):** lives behind `#[ignore]` in `crustcore-eval` (kept with
  the golden tests). Setup: disposable repo, installed App (A.1), a `crustcore.yml`
  with simple verify commands, a seeded TODO. Test: create an issue, ingest as
  untrusted data, spawn a worker, run the verifier, `open_pr`, poll checks. Env:
  `CRUSTCORE_GH_INSTALLATION_ID`, `_APP_ID`, `_APP_KEY_PEM`, `_TEST_REPO`.
- **CI core:** none new — this is purely integrative; the
  `golden_issue_to_pr_flow` already exercises the decision path with canned
  responses.
- **Live seam:** the entire test (real GitHub secrets + repo).
- **Invariants:** all 20 (holistic check).
- **Acceptance:** PR created with the issue id in the branch name; body has the
  human-review notice + verifier command/status; no token in logs/body; PR is a
  draft; re-runnable with unique branch prefixes.
- **Deps:** A.1–A.4. **Effort:** S. **Risk:** slow/flaky (external service); use a
  unique branch prefix per run; clean up PRs after (close + delete branch).

---

## Phase B — Verification intelligence

> Theme: make the verifier plan task-aware and let the supervisor remember.
> Pure decision cores layered on the PR #66 `VerifierPlan`/`RepoSignals`.

### B.1 — Richer verifier test-graph & task-specific gates

- **Goal:** emit test-graph fingerprints (changed paths → affected test ids) and
  explained per-task gate recommendations from changed files, risk tier, and
  prior failures.
- **Design (real refs):** extend `VerifierPlan` (`crustcore_daemon::product`,
  which already has `TaskShape`/`TaskGate`/`RepoSignals::with_changed_path_hints`)
  with `test_graph: TestGraph`, `gate_reasons: Vec<(TaskGate, String)>`, and a
  gate-affinity command ranking. Pure: `TestGraph::from_signals_and_changed_paths`
  and `TestGraph::command_order`. Caps: `MAX_GATE_REASONS = 16`,
  `MAX_TEST_GRAPH_ENTRIES = 64`. Keep the structure simple (paths → test-ids +
  ranking) — do not leak filesystem knowledge into the pure planner.
- **CI core:** changed-path → inferred gates + ranking; every `TaskGate` appears
  in `gate_reasons` for the right reason; security paths
  (`CLAUDE.md`/`SECURITY.md`/`crates/crustcore-secrets/`) override to
  `SecuritySensitive` regardless of file type.
- **Live seam (`#[ignore]`, `TODO(P2-live-graph)`):** `parse_test_manifest(root)`
  reading a real `pytest.ini` / `jest.config.js` / `.cargo/config.toml` for
  test-group/flaky/tier metadata — the only filesystem read in this phase.
- **Invariants:** 7 (plan is deterministic; no policy from file contents), 11
  (bounded entries), 13 (gates inform, only the verifier completes).
- **Acceptance:** `crustcore-daemon` tests green; `VerifierPlan::warnings`
  explains each gate; ignored live manifest test compiles on Linux/macOS.
- **Deps:** none. **Effort:** M. **Risk:** over-parameterizing the structure;
  strictly separate pure signals/gates from the optional live manifest read.

### B.2 — Scored verified candidates (fan-out upgrade)

- **Goal:** score each verifier-accepted candidate (correctness, diff size, risk,
  gates passed) and return the highest-scored, not merely the first accepted.
- **Design (real refs):** extend `run_fanout` (`crustcore_daemon::exec`) with a
  pure `score_candidate(metadata, risk_tier) → f32` and a `PatchScore` /
  `FanoutResult { candidates, winner, verified }`. Correctness dominates
  (verified +100); then smaller diff, lower risk budget, gates passed (blocking
  gates weighted higher). Deterministic tie-break: first proposed wins.
- **CI core:** verified always > unverified; same gates/tests → smaller diff
  ranks higher; SecurityReview pass boosts; golden 3-proposer scenario (fail /
  pass-large / pass-small) ranks pass-small highest; tie → proposal order.
- **Live seam (`#[ignore]`, `TODO(P3-live-scoring)`):** the live
  `SubagentExecutor` extracts diff metadata from the real `VerifiedPatch`; the
  scorer stays pure (default missing metadata to 0, never fail).
- **Invariants:** 6 (scoring never bypasses verifier acceptance), 13 (every
  winner passed the verifier; scoring is a tie-break, not a short-circuit), 11
  (f32 score, candidate list bounded by proposer count).
- **Acceptance:** `run_fanout` returns ranked `candidates`; golden test ranks the
  smallest fully-passing candidate highest; ignored live test compiles.
- **Deps:** B.1 helps (gate/risk metadata) but not required. **Effort:** M.
  **Risk:** mis-tuned weights (start simple: verify + size); not all
  `BackendResult` types carry diff size (default 0).

### B.3 — Persistent repo memory

- **Goal:** persist prior failures, working verifier commands, and flaky-test
  hints across runs in a dependency-free bounded file format.
- **Design (real refs):** add `MemoryStore::save(path)` / `load(path)` to
  `crustcore_index` (which already has the in-memory `MemoryStore`/`MemoryEntry`/
  `MemoryKind` query API). Frame format mirrors the event log: magic `CCMS` +
  version + varint count + per-entry `[kind|key|value|source]`, all fields capped
  (`MAX_MEMORY_FIELD = 64 KiB`, `MAX_MEMORY_ENTRIES`). Helpers:
  `record_failure(key, msg)` (key = hash of changed paths; msg redacted, ≤1 KiB),
  `record_successful_verifier(key, command, wall_ms)`, `get_prior_failure`,
  `flaky_test_hints`.
- **CI core:** save/load roundtrip; version-mismatch rejected; malformed file →
  error not panic; oversize file gracefully capped; failure messages redacted
  before save; helper + query coverage. No real filesystem in pure tests.
- **Live seam (`#[ignore]`, `TODO(P3-live-memory-persist)`):** the daemon's
  actual `save`/`load` syscalls across a restart.
- **Invariants:** 2 (failures redacted before save — coordinate with
  `crustcore_secrets::Redactor`), 7 (memory is hint, not authority), 11 (all
  fields/count/size capped).
- **Acceptance:** roundtrip green; malformed/oversize handled without panic;
  ignored cross-run persistence test compiles.
- **Deps:** none. **Effort:** S. **Risk:** format versioning (reject on mismatch);
  secret redaction in failure text.

---

## Phase C — Execution routing & review

> Theme: route the right executor at the right risk, gate the dangerous changes
> through human/agent review, and render evidence a human can read.

### C.1 — Task-shape executor routing

- **Goal:** deterministically select single-executor (quick), fan-out (feature),
  advisory plan (risky), or blocked (workflow/policy) from task shape, risk, and
  configured executors.
- **Design (real refs):** a pure `decide_routing(task, risk, context_budget,
  configured) → RoutingDecision` in a new `crustcore_daemon::router`, reusing
  `TaskShape`/`ExecutorKind`/`ExecutorCapability` (`product.rs`) and
  `run_fanout`/`run_subagent` (`exec.rs`). Rules: DocsOnly/quick → `SingleExecutor`
  (Native if configured else ClaudeCode); Feature/UiChange@Standard → `FanOut`
  if two configured else single; SecuritySensitive/Critical → `RequiresPlan`;
  WorkflowChange → `Blocked`. Keep to ~4–5 rules.
- **CI core:** every shape/risk/config combo has a documented decision; chooses
  only from the configured list; graceful fallback when no executor matches.
- **Live seam (`#[ignore]`, `TODO(P3-live-routing)`):** the supervisor's
  `process_task` actually spawning agents per the decision.
- **Invariants:** 4 (Blocked structures refusal; advisory paths use separate
  roles), 6 (routing selects a worker, not authority), 13 (routing informs
  selection, not completion).
- **Acceptance:** `decide_routing` pure; golden test over all combos; ignored
  live spawn test compiles.
- **Deps:** B.1 helps (large-refactor detection). **Effort:** M. **Risk:**
  over-routing (cap the branches); handle "no configured executor" (default to
  first-available or Blocked).

### C.2 — Multi-verifier advisory path (Reviewer / Security / Tester gates)

- **Goal:** route high-risk and workflow changes through Reviewer +
  SecurityAuditor + Tester verdicts before integration; verdicts alone gate it.
- **Design (real refs):** reuse `decide_integration` / `IntegrationDecision` /
  `Verdict` / `Role::{Reviewer,SecurityAuditor,Tester}` (`supervisor.rs`, from
  Phase 11). Add a `ReviewerOrchestration` (in `supervisor.rs` or a new
  `reviewer.rs`) that posts `MessageKind::CapabilityRequest` per blocking role on
  the blackboard, collects verdicts posted back as `MessageKind::Finding`, and
  calls `decide_integration(&verdicts, verified)`. Low-risk DocsOnly@Standard
  skips the advisory path.
- **CI core:** high-risk/workflow → advisory path; low-risk skips it; missing
  blocking verdict blocks; a Reviewer block vetoes even if SecurityAuditor
  approves; golden workflow-change requires Reviewer + Security verdicts.
- **Live seam (`#[ignore]`, `TODO(P3-live-advisory)`):** waiting for real human/
  agent verdicts from Telegram/cockpit.
- **Invariants:** 4 (verdicts are vetoes, not model self-approval), 13
  (integration needs verifier pass AND advisor approval), 5 (verdicts via
  blackboard; supervisor acts).
- **Acceptance:** high-risk routes to `ReviewerOrchestration`;
  `decide_integration` called with all verdicts; golden test green; ignored live
  test compiles.
- **Deps:** C.1 (detect high-risk), B.1 (mark security paths). **Effort:** M.
  **Risk:** deadlock waiting for verdicts (add timeout → Blocked, not hung);
  clear rule for which reviewer when (Security/Workflow always; High-risk if
  configured; Low-risk skips).

### C.3 — Evidence bundle rendering (PR body + audit JSON)

- **Goal:** render `EvidenceBundle` to Markdown (PR body, cockpit) and a stable
  JSON schema v1 (audit/replay).
- **Design (real refs):** add `EvidenceBundle::to_markdown()` and `to_json()` to
  `crustcore_daemon::product`, rendering task shape, risk, lifecycle, verifier
  commands + results, gates (passed/warning/unplanned), receipts, risk summary,
  and the "🔴 Human review required" notice. JSON schema
  `crustcore.evidence_bundle.v1` carries evidence refs, redacted results, and
  warnings. Cap markdown (~500 lines) — defer full detail to the cockpit.
- **CI core:** headers render per shape; commands listed with stages; gates with
  status; security/workflow shows the review notice; JSON matches the schema and
  roundtrips for audit.
- **Live seam (`#[ignore]`, `TODO(P3-live-evidence-render)`):** the supervisor
  appending the markdown to a real draft PR body.
- **Invariants:** 2 (tool-result redaction in the export), 10 (every receipt
  included), 11 (bounded export, no unbounded dumps).
- **Acceptance:** readable markdown per shape; stable JSON v1; golden per-shape
  evidence body; ignored live append test compiles.
- **Deps:** B.1 (richer gate explanations), B.3 (prior-failure hints).
  **Effort:** M. **Risk:** markdown bloat (cap it); schema versioning (reject
  newer versions on old readers).

---

## Phase D — Live executor wiring

> Theme: connect the routing + advisory decision cores to the real sandboxed
> executor so a delegated task runs end-to-end.

### D.1 — Wire `WorktreeSubagentExecutor` into the daemon task loop

- **Goal:** connect `run_subagent`/`run_fanout` to the live
  `WorktreeSubagentExecutor` so a chat/Telegram task is routed, executed in a
  worktree, verified, and proposed.
- **Design (real refs):** add an `ExecutorRegistry { repo_root, executor:
  Box<dyn SubagentExecutor>, budgets }` and a task-processing loop (in a new
  `task_loop.rs` or extending `supervisor.rs`) that reads a queued task, calls
  `decide_routing` (C.1), dispatches `run_subagent` (SingleExecutor) or
  `run_fanout` (FanOut) against the live `WorktreeSubagentExecutor`
  (`crustcore_daemon::exec`, Phase 11), then `decide_integration` (C.2) if
  advisory is required, then the credential-proxy draft-PR path (A.2/A.3).
- **CI core:** registry construction (sandbox config injected, no I/O); routing
  decision → mock-executor spawn; quick-task single-executor flow; feature-task
  fan-out + scoring; security-task advisory path; budget enforcement. No
  filesystem/sandbox in pure tests.
- **Live seam (`#[ignore]`, `TODO(P3-live-executor-wire)`):** real repo + real
  sandbox + real worker → `VerifiedPatch` → integrate. The reduced seam that
  cannot run in CI without a sandbox backend.
- **Invariants:** 5 (outcomes via blackboard), 6 (executor is a producer), 9
  (workers run in the sandbox profile — already enforced by
  `WorktreeSubagentExecutor`), 13 (integrate only after verifier pass).
- **Acceptance:** registry instantiable with repo root + sandbox config; mock
  flows green; ignored end-to-end test documents the live flow.
- **Deps:** C.1, C.2, A.1–A.3, Phase 11 executor + Phase 13 socket. **Effort:** M.
  **Risk:** worktree teardown on all paths (the executor already handles it — the
  loop must not interfere); verdict timeouts.

---

## Phase E — Product UX & channels

> Theme: a developer delegates and reviews without reading raw logs; an auditor
> still inspects every proof. All surfaces consume the existing redacted
> read-model and typed approval gates — none can approve, complete, or integrate.

### E.1 — Cockpit: loopback dev-UI task supervisor

- **Goal:** extend the read-only `/dev/ui` (`crustcore-dev`, C7-devui) into a
  task/evidence/approval cockpit driven by the existing event-log read-model.
- **Design (real refs):** new bounded views in `crustcore-dev/src/views/`:
  `TaskDetailView`, `EvidenceSummaryView`, `ApprovalFormView`, all over
  `&ReadOnlyBackend`, sourced from `RunInspectorView` + `ApprovalView` +
  `DevSnapshot` (already redacted/bounded, streamed via `/ws`). Web layer (behind
  the `serve` feature): `GET /api/tasks`, `/api/task/:id`, `/api/task/:id/diff`
  (reuse `Backend::task_diff`), `POST /api/approval/:id/resolve` routed to the
  existing `ApprovalEngine`. Minimal vanilla-JS SPA (status grid + detail +
  approval pane) consuming `/ws` with cursor-resume on reconnect.
- **CI core:** view bounds; evidence carries refs only (no raw secrets);
  approval-form nonce binding (resolving nonce A never approves op B); task-list
  pagination (`MAX_SNAPSHOT_TASKS`); full cockpit frame over `MockDevBackend`;
  approval-resolution routes to `ApprovalDispatch` with the right `Approved<T>`.
- **Live seam (`TODO(C7-serve-live)`, `#[ignore]`):** the axum bind, `/ws` tick
  loop, HTML/JS assets, TLS if exposed beyond loopback.
- **Invariants:** 2 (fields from redacted sources), 5 (supervisor-only,
  bearer-token, mints no capabilities), 11 (lists capped), 13 (renders evidence,
  never mints a `VerifiedPatch`), 14 (buttons carry the operation-bound nonce).
- **Acceptance:** views compose into a snapshot over `MockDevBackend`;
  `/api/task/:id` returns a bounded object; resolve POST mints `Approved<T>` only
  on success; cockpit nonce matches the Telegram nonce;
  `cargo test --features serve` and `--lib` both green.
- **Deps:** C.3 (evidence rendering), D.1 (live tasks to show). **Effort:** M.
  **Risk:** frontend scope creep (ship the MVP grid first); centralize nonce
  construction in one `ApprovalNonce` type shared with Telegram; cap the task
  list.

### E.2 — GitHub `/crustcore` commands from PR/issue comments

- **Goal:** parse `/crustcore run|retry|cancel|explain` from comments into typed
  events, routed through the same dispatch as Telegram — never free text to a
  model.
- **Design (real refs):** the webhook already delivers comments as a redacted
  `GitHubEnvelope` (`crustcore_daemon::webhook`, B2-gh-app). Add a pure
  `crustcore_daemon::github_commands` with `parse_commands(text) →
  Vec<GithubCommand>` (`Run{repo,branch,goal}` | `Retry{id}` | `Cancel{id}` |
  `Explain{id}`). Flag-style args (`--goal`, `--dir`); one command per comment
  (rest logged); goal ≤512 chars; ids parse as u64. Malformed → `RiskDetected`,
  never silent. Route into `runtime::dispatch_event` as a new `GitHubCommand`
  branch → `LaunchTask`/`CancelTask`.
- **CI core:** minimal/`--goal`/retry/multiple(first-wins)/injection-as-literal/
  comment-prose-isolation parsing; command → runtime event; unknown verb logs
  `RiskDetected` without panic.
- **Live seam (`live`):** the comment-author authorization check (GitHub
  collaborator / `RepoRegistry::is_authorized`, may need `TODO(B2-webhook-live)`);
  the full webhook→parse→dispatch round-trip; an ignored real-PR `/crustcore run`
  smoke (needs sandbox + repo).
- **Invariants:** 4 (commands from GitHub users, parsed by the daemon, never from
  model output), 7 (comment text untrusted; only verb + bounded args extracted,
  never passed as a prompt), 8 (dispatch through the same policy gate as
  Telegram), 11 (bounded), 16 (same dispatch logic — not a parallel ungoverned
  surface).
- **Acceptance:** parser + enum landed; malformed logs `RiskDetected`;
  `/crustcore run` → `LaunchTask` with repo/branch context; injection treated as
  literal strings; `cargo test -p crustcore-daemon` includes the parser tests.
- **Deps:** E.1 (`explain` can link to a cockpit task). **Effort:** S. **Risk:**
  arg ambiguity (require flag-style args); authority confusion (check author
  permissions before honoring cancel).

### E.3 — Slack as a runtime control plane

- **Goal:** add Slack alongside Telegram + cockpit, mirroring the allowlist,
  redaction, and approval-nonce model, feeding the same `RuntimeEvent` stream.
- **Design (real refs):** the daemon's `dispatch_event(event, state)` is
  transport-agnostic (`crustcore_daemon::telegram::RuntimeEvent`). Add
  `crustcore_daemon::slack` (pure core): `SlackAllowlist` (per-workspace +
  per-channel, deny-all empty), `normalize_message(payload, allowlist) →
  Option<RuntimeEvent>` (plain → `QueuedTurn`, `!prefix` → `Steer`, slash →
  `Command`, reaction → `ApprovalCallback` with the same nonce format), and an
  `OutboundRenderer` (`Outbound` → Slack blocks). Credentials via the broker
  (`CRUSTCORE_SLACK_BOT_TOKEN`, signing secret for webhook HMAC). CLI-side binding
  (not via DM), same as Telegram. Wire `SlackPoller` beside `TelegramPoller` in
  `runtime::run_serve_loop`.
- **CI core:** empty allowlist denies all; allowed/blocked user; plain/steer/
  command/reaction normalization; event dedupe; outbound rendering; redaction
  enforced (no raw secret reaches a message); unknown-workspace rejected; Slack
  command flows through `dispatch_event` like Telegram.
- **Live seam (`live`, `#[ignore]`):** the Slack Bot API HTTP client (spawned
  `crustcore-net` helper, Telegram pattern) and Events-API/Socket-Mode listener;
  real-workspace round-trip.
- **Invariants:** 1/3 (only redacted `ModelVisibleText`), 4 (approvals from Slack
  users), 5 (supervisor-only, allowlist-enforced), 7 (message text untrusted), 11
  (bounded), 15 (Slack is opt-in, never the default — operator binds it via CLI).
- **Acceptance:** allow/deny parity with Telegram; events map to the right
  variants; approval reactions carry the operation-bound nonce; dispatch routes
  through the same gates; secret-like text redacted; tests run without a real
  workspace; `cargo test -p crustcore-daemon` includes Slack tests.
- **Deps:** Telegram (done) — Slack mirrors it. **Effort:** M. **Risk:** workspace
  scoping (nested allowlist + tests); reaction-as-approval noise (prefer block
  buttons, emoji fallback); Slack API drift; threads deferred to a later phase.

### E.4 — Token-by-token CoT streaming feasibility (analysis-first)

- **Goal:** decide whether raw token-by-token chain-of-thought streaming is
  compatible with the redaction boundary, and produce a design *or* a documented
  limitation. **Not a build task** — gather evidence first.
- **Design:** prototype a `TokenRedactor { secrets, buffer }` that buffers tokens
  to a redaction boundary (sentence/line), scans the buffer with the existing
  `Redactor` algorithm, and yields redacted chunks. Test red-team scenarios:
  secret split across tokens, secret split across lines, false positives, and
  worst-case latency with no boundaries (bounded buffer with a max-size emit
  policy). Produce a design doc if feasible, or a constraint statement (why
  token-level redaction is unsafe and what would have to change).
- **CI core (if feasible):** `accept_token(&mut self, token) → Option<Vec<u8>>`;
  secret-at-boundary caught; false-positive tradeoff documented; worst-case
  latency bounded (no unbounded buffering).
- **Live seam:** the provider must stream tokens incrementally; the
  `crustcore-net` helper must expose a token stream; the dispatch loop emits
  redacted chunks.
- **Invariants:** 2/3 (no unredacted secret reaches the user), behind a
  `reveal_reasoning` opt-in (already in `docs/chat.md`).
- **Acceptance:** prototype redacts a mock stream without leaking; worst-case
  added latency <500ms; red-team scenarios pass; a design doc or limitation
  statement is written with explicit tradeoffs.
- **Deps:** chat/Telegram surfaces, model-routing streaming capability.
  **Effort:** S (analysis only, ~4–6h). **Risk:** redaction-resistant secrets
  (document which types are safe mid-stream); user distrust of imperfect
  streaming (opt-in flag); the analysis may conclude it requires model-side
  tokenization guarantees.

---

## Phase F — Daemon hardening

> Theme: make the long-running daemon survive restarts, give operators control
> beyond Telegram, and supervise multiple repos. Independent of A–E; can run
> beside everything. None of these widen the trust boundary or touch nano.

### F.1 — Cross-process task lease recovery (`TODO(daemon-recover-xproc)`)

- **Goal:** survive a daemon restart and re-adopt running tasks via a
  snapshot/adopt protocol, closing the recovery half of invariant 12.
- **Design (real refs):** the `TaskRegistry` (`crustcore_daemon::registry`)
  already reserves a `LeaseOwner(u64)` field for this, and `crustcore-session`
  already resumes from event-log + receipt verification. Add a `TaskSnapshot`
  (task id, chat id, route, phase, lease expiry + usage, worktree path, optional
  `Approved<GitHubWriteCap>`), `snapshot_all() → Vec<TaskSnapshot>` (pure), and
  `adopt_from_snapshot(snapshot, now) → Result<TaskId, AdoptError>` (a pure
  state-machine step like `admit()` — re-leases under a new instance id, marks
  Pending). Persist via `dump_snapshots`/`load_snapshots` (JSON/bincode in a
  cache dir), dumped on a SIGTERM hook. **Channel resume is the trap:** an
  `mpsc::Sender/Receiver` pair cannot survive a restart — re-adopted tasks are
  marked **Pending** and the loop spawns a fresh worker that resumes from the
  log (mirroring `crustcore-session`), tailing a worktree progress log rather
  than reconnecting a channel.
- **CI core:** snapshot/adopt roundtrip (stable ids, re-charged budgets);
  budget-breach adopted as terminal; lease refreshed under the new `LeaseOwner`;
  absent worktree → immediate `Expired`.
- **Live seam (`#[ignore]`, `TODO(daemon-recover-xproc-live)`):** file I/O, the
  SIGTERM dump, process re-attach (PID + UUID check / log tail), and an
  end-to-end kill-and-restart smoke.
- **Invariants:** 12 (recovery survives restart), 13 (re-adopted tasks still
  complete only on `VerifiedPatch`), 11 (re-charge budgets).
- **Acceptance:** snapshot/adopt unit-tested in isolation; load-and-re-adopt
  wired into startup; `cargo xtask verify` green; ignored smoke demonstrates
  re-adoption; no nano impact.
- **Deps:** none. **Effort:** M. **Risk:** channel resume is impossible — use
  file-based progress logging; PID reuse — verify a worktree UUID; snapshot
  staleness — refuse adoption if the audit trail is broken (same as
  `crustcore-session`).

### F.2 — Remote admin socket (`TODO(daemon-admin)`)

- **Goal:** an authenticated loopback/Unix socket for operators (or a paired
  supervising agent) to query status and cancel/kill tasks without Telegram.
- **Design (real refs):** add `crustcore_daemon::admin` with `AdminCommand`
  (`Status` | `TaskDetail(id)` | `Cancel{id}` | `Kill{id}`) and `AdminResponse`.
  Transport: `UnixListener` (`#[cfg(unix)]`, mode 0600) with a TCP-loopback
  fallback for non-unix. Auth: a startup nonce in `~/.crustcore/admin.nonce`
  (0600), sent in the first message; mismatch drops the connection. Framing:
  `[len: u32 LE][json]`. Dispatch in `run_serve_loop` alongside Telegram, feeding
  the same `request_cancel`/`request_kill` into the registry.
- **CI core:** status over a mock returns the current snapshot; cancel is
  owner-scoped (same gate as Telegram); kill marks `Done(Killed)`; nonce mismatch
  rejected.
- **Live seam (`#[ignore]`, `TODO(daemon-admin-live)`):** the real listener +
  framing + a socket roundtrip.
- **Invariants:** 5 (operator-only, not model-facing), 12 (feeds the same
  cancel/kill path as Telegram).
- **Acceptance:** enums + mock dispatcher landed and tested; listener wired; nonce
  auth works; `cargo xtask verify` green; ignored smoke shows query + cancel; no
  nano impact.
- **Deps:** benefits from F.1 + F.3 (sees recovered/multi-repo tasks) but
  parallel-safe. **Effort:** M. **Risk:** Unix-socket portability (TCP fallback,
  documented); nonce-file permissions (enforce 0600, warn if world-readable);
  blocking socket (non-blocking I/O + select timeout, or thread-per-socket).

### F.3 — Multi-repo orchestration skeleton

- **Goal:** bind multiple repos at startup (distinct paths/verify/PR targets) and
  route chat launches to the right one.
- **Design (real refs):** the `TaskRegistry` is already repo-agnostic. Add a
  `RepoProfile { id, path, verify, pr, backend }` to `product.rs`, extend
  `ServeConfig` (`runtime.rs`) to `repos: BTreeMap<RepoId, RepoProfile>`, add a
  pure `classify_repo(intent, hints) → Option<RepoId>` (keyword match; fallback to
  the sole repo; `None` on ambiguity → dispatch asks "which repo?"), and thread a
  `repo: RepoId` through `LaunchTask` / `TaskHandle::spawn`. Concurrency cap stays
  global.
- **CI core:** explicit hint recognized; sole-repo default; ambiguity → `None`;
  launch routes to the right profile; registry supervises multi-repo tasks under
  the global cap.
- **Live seam (`#[ignore]`, `TODO(P10-multi-repo-live)`):** multi-repo CLI startup
  (`--repo id=/path`) and a simultaneous-task smoke; classifier tuning needs real
  operator data.
- **Invariants:** 7 (repo paths from config/CLI, not model/user input), 11 (shared
  global concurrency cap).
- **Acceptance:** `RepoProfile` + config parsing; `classify_repo` tested;
  `dispatch_event` routes by repo; `cargo xtask verify` green; ignored smoke shows
  parallel repos; no nano impact.
- **Deps:** none. **Effort:** S–M. **Risk:** ambiguous selection (start with
  "operator must specify", helpful failure); budget sharing across repos (shared
  global cap initially; truly independent repos run separate daemons).

---

## Appendix — Maintainer-owned & infra-gated

This appendix separates work that **cannot run in CI** from the buildable tasks
above. Nothing here blocks the pure cores; all of it requires real infra,
secrets, or an irreversible maintainer decision.

### Live-socket validation runbook (`docs/live-socket-validation.md`)

A maintainer-ready checklist enumerating the ~30 `#[ignore]` live-socket tests
and the infra each needs, so validation is systematic rather than ad-hoc. This
is **documentation, not code** — the tests already exist behind `#[ignore]`.

For each seam, record: feature gate + test name; what irreducible socket it
exercises; the CI-testable core already passing; prerequisites; validation
commands; success criteria; risks. Group by infra:

- **A. Model/provider keys** — Anthropic/OpenAI/etc. live adapters, advisor, flow.
- **B. GitHub** — App credentials, REST API, webhook listener (the Phase A seams).
- **C. Sandbox backend** — `bubblewrap` (Linux) / `sandbox-exec` (macOS); the
  Phase D executor smoke.
- **D. Vector/embed/telemetry** — Qdrant, LanceDB, OTLP collector.
- **E. MCP & discovery** — MCP server sockets, subprocess discovery.
- **F. Runtime & loops** — Telegram polling, chat surface, Slack (E.3),
  self-improvement loop, daemon recovery (F.1), admin socket (F.2).

Add a validation matrix (test → category → feature → runbook section → CI status)
and quick-start commands (`cargo test --workspace --lib` for the cores;
`CRUSTCORE_*=... cargo test --features live <name> -- --ignored --nocapture` for
a single live test). Add a CI lint (`validate_live_socket_runbook.sh`) that greps
for every `TODO(*-live)` / `#[ignore]` and fails if one is missing from the
runbook, so it cannot go stale. **Effort:** S. **Risk:** staleness (the lint
catches it); some infra is maintainer-only (Firecracker, a real App) — mark the
difficulty per entry.

### Irreversible maintainer steps (CLAUDE.md §6.3)

These are gated on explicit maintainer approval and are **out of scope for
autonomous agents**:

- The signed/checksummed release workflow and any `git tag` / publish step.
- Branch-protection and GitHub Actions workflow edits.
- Signing keys and any secret provisioning.
- Release-metadata alignment at tag time (workspace version, CHANGELOG roll,
  README badges, release notes, git tag) — per `world-class-agent-roadmap.md`
  Phase 0.
- The manual live smoke checklist in `world-class-agent-roadmap.md` (build →
  chat → GitHub App → PR supervisor → CI repair → audit), run before a release.

---

## Sequencing recommendation

If you execute this overlay, do these first, in this order, and why:

1. **Appendix runbook (S, independent).** Cheapest high-leverage move: it maps
   every live seam before you touch one, so Phase A/D validation is systematic
   rather than exploratory. No code churn.
2. **A.1 `app-onboarding` (M).** The hard gate for the whole product wedge —
   A.2/A.3 cannot push or open a PR without registered repos + a minted
   `Approved<GitHubWriteCap>`. Critical-path root.
3. **B.3 persistent memory (S) and B.1 test-graph (M), in parallel.** Both are
   independent pure cores with no live dependency; B.3 is a quick win and B.1
   feeds routing (C.1) and evidence (C.3) downstream.
4. **A.2 + A.3 (L + S), after A.1.** Close the push and draft-PR seams together —
   they share the token-mint path and turn the supervisor from a decision core
   into something that drives a real repo.
5. **C.1 routing (M) → D.1 live wiring (M).** Once a repo can receive a PR,
   routing + the live `WorktreeSubagentExecutor` make delegation real end-to-end;
   D.1 is where the pieces compose.

Everything else (A.4/A.5, B.2, C.2/C.3, all of E, F.1–F.3) layers on top of these
five and can be parallelized across subagents on disjoint file globs per
CLAUDE.md §7. Keep contract-file changes serialized; keep every live seam behind
`#[ignore]` with a `TODO(*-live)` marker so the CI gate stays green and honest
about what is proven versus what awaits real infra.
