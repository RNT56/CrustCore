# Changelog

All notable changes to CrustCore are recorded here. This file is the
**agent/PR progress log** as well as the release changelog: every agent and
subagent records its work here so the project stays auditable across many
sessions. See [`CLAUDE.md` §8](./CLAUDE.md) for the rules.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html),
extended with a CrustCore **Agent Log** subsection that captures the
agent/PR/role/size/invariant audit trail.

## How to add an entry (read before editing)

- Put in-progress work under **[Unreleased]**, in the correct group
  (`Added` / `Changed` / `Deprecated` / `Removed` / `Fixed` / `Security`).
- Add a matching line to **Agent Log** with: phase/task id (e.g. `P1.3`),
  PR/branch, owning agent/role, nano size impact (Δ kB or `n/a`), and
  invariants touched/verified.
- Update this file in the **same PR** as the change.
- In parallel work, subagents **report** their lines to the supervisor, which
  writes the consolidated entries (avoids merge conflicts). See
  [`CLAUDE.md` §7.2](./CLAUDE.md).
- On release, move `[Unreleased]` items into a dated `[x.y.z] - YYYY-MM-DD`
  section and start a fresh `[Unreleased]`.

---

## [Unreleased]

### Added

- **Remote admin socket protocol (roadmap-v0.6 F.2).** Added `crustcore_daemon::admin`:
  an authenticated operator control plane (`status` / `detail <id>` / `cancel <id>` /
  `kill <id>`) over a length-prefixed framed socket. Pure protocol core —
  `parse_admin_command`, `frame`/`try_deframe` (bounded; a hostile length is rejected
  before allocating — invariant 11), `authenticate` (constant-length nonce compare; the
  startup nonce file gates every command), and `dispatch_admin` which feeds the **same
  owner-scoped `request_cancel`/`request_kill`** path as Telegram (invariant 12). It is
  **operator-only, never model-facing** (invariant 5). The real `UnixListener` (0600) /
  TCP-loopback bind is the `#[ignore]`d `daemon_admin_live_socket_smoke`
  (`TODO(daemon-admin-live)`), catalogued in runbook §F.4. 6 new tests; daemon-only;
  **zero nano impact**.

- **Evidence bundle rendering (roadmap-v0.6 C.3).** Added
  `EvidenceBundle::to_markdown()` and `to_json()` to `crustcore_daemon::product`.
  `to_markdown` is the **bounded** canonical PR-body/cockpit renderer: it opens with
  the 🔴 "Human review required before merge" notice (CrustCore opens *draft* PRs — a
  human approves the merge, invariant 14), lists verifier commands (status + redacted
  note), receipts, and unresolved risks — each **capped to the same export bounds**
  with a "…N more (see audit JSON)" overflow note so the body can never become an
  unbounded dump (invariant 11), every fitting receipt included (invariant 10), and
  notes/risks pre-redacted (invariant 2). `to_json` is the stable
  `crustcore.evidence_bundle.v1` schema (audit/replay). `draft_pr_body` now delegates
  to `to_markdown` (single renderer). The supervisor appending the markdown to a real
  draft PR is the `#[ignore]`d `live_evidence_render_append_smoke`
  (`TODO(P3-live-evidence-render)`), catalogued in runbook §B.7. 4 new tests;
  daemon-only; **zero nano impact**.
- **Task-loop wiring (roadmap-v0.6 D.1).** Added `crustcore_daemon::task_loop`,
  composing the v0.6 decision cores into one pipeline: `plan_task` (routing C.1 →
  `ExecutionPlan`: Single / Fanout / AdvisoryOnly / Blocked) and `finalize_task`
  (verifier result + `orchestrate_review` C.2 → terminal `TaskOutcome`:
  ReadyToIntegrate / AwaitingReview / ReviewTimedOut / ReviewBlocked / Failed /
  AdvisoryRequested / Blocked). Completion stays **verifier-owned** — an unverified
  run is `Failed` regardless of any advisory approval (invariants 6, 13); advisory
  verdicts only *further* gate (invariant 4); outcomes flow to the supervisor, not the
  user (invariant 5). Pure decision cores (no sandbox/clock); the sandboxed
  `run_fanout`/`WorktreeSubagentExecutor` run → verify → draft PR is the `#[ignore]`d
  `live_executor_wire_smoke` (`TODO(P3-live-executor-wire)`), catalogued in runbook
  §C.6. 8 new tests; daemon-only; **zero nano impact**.

- **Real draft-PR creation mapping (roadmap-v0.6 A.3).** Added the `live`-gated
  `crustcore_daemon::github::pr_intent_to_create_request`: maps the backend's
  `PrIntent` (minted by `open_pr` **only** from a `VerifiedPatch` + a valid
  `Approved<GitHubWriteCap>` — invariants 13, 14) onto the net layer's
  `CreatePrRequest` for the live `POST …/pulls`. It carries the **verifier-evidence
  body verbatim** (invariant 6 — never a model `self_claimed_done`) and preserves
  `draft = true`. The net layer already maps non-2xx (401/404/422) to typed
  `GitHubError` (never a fake success). The real POST is the `#[ignore]`d
  `draft_pr_live_post_smoke` (`TODO(draft-pr-live)`), catalogued in runbook §B.6.
  Daemon-only (live feature); **zero nano impact**.

- **Credential-proxy branch push (roadmap-v0.6 A.2).** Added the git
  **credential-helper protocol** to `crustcore_daemon::github`, the mechanism that
  hands `git` a short-lived installation token **without it ever entering the
  sandbox** (invariant 1): `parse_credential_request` (git's `get` stdin →
  protocol/host/path, bounded), `authorize_credential` (issues a credential **only**
  for `https://github.com/<registered-repo>`, binding the token to a `GitHubWriteCap`
  — invariants 1, 9), `credential_helper_response` (`x-access-token` + token, pipe-only,
  never logged), and `confining_git_config` (reset-then-set-*only*-ours +
  `useHttpPath`, so the worktree can never fall back to `.git/credentials` or SSH).
  Composes with the existing `parse_push_argv`/`validate_push` refspec/force/protected-branch
  gate. The helper-subprocess exec + the real push is the `#[ignore]`d
  `cred_proxy_live_push_smoke` (`TODO(cred-proxy-live)`), catalogued in the runbook
  §B.5. 5 new tests; daemon-only; **zero nano impact**.

- **Multi-verifier advisory path (roadmap-v0.6 C.2).** Added
  `crustcore_daemon::reviewer`: `required_reviewers(task, risk)` decides which
  blocking review roles a change needs (SecuritySensitive/WorkflowChange/
  DependencyChange → Reviewer + SecurityAuditor; any other ≥High-risk → Reviewer;
  low-risk docs skip the panel), and `orchestrate_review(...)` folds the collected
  verdicts + the verifier result through the existing `decide_integration`. Verdicts
  are **vetoes, not model self-approval** (invariant 4 — a Reviewer `Block` stops
  integration even if SecurityAuditor approves); integration needs **both** verifier
  evidence *and* the blocking-role approvals (invariant 13 — an approved-but-unverified
  patch still returns `NotVerified`); verdicts arrive via the blackboard and the
  supervisor acts (invariant 5). A stalled panel **times out into a refusal, never a
  hang** (`AdvisoryOutcome::TimedOut`). 7 tests; daemon-only; **zero nano impact**.
- **Task-shape executor routing (roadmap-v0.6 C.1).** Added
  `crustcore_daemon::router`: a pure, total `decide_routing(task, risk,
  context_budget, configured) → RoutingDecision` that selects how to run a task —
  `SingleExecutor` (docs/low-risk, preferring Native→ClaudeCode→first configured),
  `FanOut` (Feature/UiChange at ≤Standard risk with ≥2 executors and enough budget,
  bounded to `MAX_FANOUT`), `RequiresPlan` (SecuritySensitive or ≥Critical — an
  advisory role, not autonomous execution), or `Blocked` (WorkflowChange needs human
  approval; or no executor configured). Routing selects a *worker, never authority*
  (invariant 6); a `Blocked` decision structures a refusal (invariant 4); the verifier
  still owns completion (invariant 13). The live spawn reuses the existing
  `exec::run_fanout`/`run_subagent` seams — no new live seam. 7 tests incl. a full
  shape×risk×config×budget combination sweep proving totality + that every chosen
  executor comes from the configured list. Daemon-only; **zero nano impact**.
- **Persistent repo-memory helpers (roadmap-v0.6 B.3).** Added prior-failure /
  verifier / flaky-hint helpers to `crustcore_index::MemoryStore` (whose bounded,
  dependency-free `CCMS` snapshot `save`/`load` already persists across restarts):
  `record_failure(key, msg, redactor)` **redacts the message through
  `crustcore_secrets::Redactor` before persisting** (invariant 2 — no secret text
  ever lands in memory) and bounds it to `MAX_FAILURE_MSG` (1 KiB);
  `record_successful_verifier(key, command, wall_ms)`; `get_prior_failure` (latest
  wins); `flaky_test_hints` (keys with *both* a failure and a success);
  `changed_paths_key` (an order-independent, content-free digest key derived from
  changed paths). Memory is an untrusted hint, never authority (invariant 7); all
  fields stay bounded (invariant 11). A restart roundtrip test proves
  helper-written memory survives `save`→drop→`load`. 6 new tests; index-only;
- **Verifier test-graph & explained gates (roadmap-v0.6 B.1).** Extended
  `crustcore_daemon::product`'s `VerifierPlan` with `gate_reasons: Vec<(TaskGate,
  String)>` (every expected gate now carries a deterministic, content-free
  explanation — bug-fix→regression, high-risk/security→security-review, etc.,
  bounded by `MAX_GATE_REASONS`) and a `TestGraph` mapping changed paths → the
  verifier ids they affect (`crates/<crate>/…` → `cargo test -p <crate>` then the
  full suite; JS/TS→`npm test`; Python→pytest; security paths override to
  `security-review` regardless of file type), with `TestGraph::command_order`
  ranking targeted checks before the full gate so callers can fail fast. Built
  purely from path strings + `RepoSignals` (no filesystem, no policy from file
  contents — invariant 7), bounded by `MAX_TEST_GRAPH_ENTRIES`, attached via the
  new `RepoProfile::plan_verification_with_changed_paths`. The graph is advisory
  ranking only — it never replaces the full-suite gate and cannot prove a task
  (invariant 13). The one filesystem inch (`parse_test_manifest`, pure over text;
  the real on-disk read is `#[ignore]`d `live_parse_test_manifest_reads_a_real_manifest`,
  `TODO(P2-live-graph)`) is catalogued in the runbook. 8 new tests; daemon-only;
  **zero nano impact**.
- **GitHub App onboarding core (roadmap-v0.6 A.1).** Added
  `crustcore_daemon::onboarding`: turns an untrusted GitHub App **install
  redirect** into a registered, write-capable repo through the existing typed
  primitives — `cap_from_redirect` validates the redirect (non-zero
  `installation_id`; a strict `owner/repo` slug that rejects whitespace, control
  chars, and `.`/`..` path-confusion segments) and builds a `GitHubWriteCap`
  scoped to the repo + `crustcore/` prefix; `onboard` registers it in the
  `RepoRegistry` and mints an `Approved<GitHubWriteCap>` bound to the onboarding
  operator (`AuthorizedUser`, never model/comment data — invariant 4);
  `TokenLease::needs_refresh` refreshes the 1-hour installation token early so a
  late task is never handed an expired token (invariant 3); `load_profile` runs
  `crustcore.yml` through the bounded `RepoProfile::parse` and *guides* the user on
  a missing/invalid file instead of silently defaulting. Pure decision core (no
  network, clock, or secret material), 9 unit tests. The real install-confirm
  (`GET /app/installations/{id}`) + token mint is the `#[ignore]`d
  `app_onboarding_live_smoke` (`TODO(app-onboarding-live)`), catalogued in the
  live-socket runbook. Daemon-only; **zero nano impact**.

- **Live-socket validation runbook + CI lint (roadmap-v0.6 Appendix).** Added
  [`docs/live-socket-validation.md`](./docs/live-socket-validation.md): a
  maintainer-ready catalogue of every `#[ignore]`d live seam (22 named tests +
  16 `TODO(*-live)` tags) grouped by the infra each needs — A. provider keys,
  B. GitHub (App/REST/webhook), C. sandbox backend + git, D. vector/embed/OTLP,
  E. MCP, F. runtime loops — with a validation matrix, per-seam prereqs +
  exact `--ignored` commands + success criteria, and a "seam tags without a
  smoke test" table (the maintainer/infra-only Firecracker + Windows tiers).
  Added `scripts/validate_live_socket_runbook.sh`, wired as a new
  `cargo xtask runbook-check` step inside `cargo xtask verify`: it fails CI if any
  `#[ignore = "…"]` test or `TODO(*-live)` tag is missing from the runbook, so the
  map cannot silently go stale. Docs + a shell lint + an xtask step only — no
  kernel, no nano, no dependency, no workflow-file change.

- **`docs/roadmap-v0.6.md` — post-v0.5.0 execution overlay.** A consolidated, dependency-ordered,
  execution-ready plan for the next wave: Phase A (PR Supervisor go-live), B (verification
  intelligence), C (execution routing & review), D (live executor wiring), E (product UX +
  channels: cockpit, GitHub `/crustcore` commands, Slack, CoT analysis), F (daemon hardening:
  cross-process recovery, admin socket, multi-repo). Each task carries goal · design with real
  file refs · CI-testable core vs live seam · tests · invariants · acceptance · effort · deps ·
  risk. Includes a live-socket validation runbook (grouped by infra) + the irreversible
  maintainer steps, and a sequencing recommendation. Complements `docs/world-class-agent-roadmap.md`
  (the product-vision overlay from #66) with concrete, ready-to-build specs. Docs only.

- **Release CI workflow (draft) — prebuilt, checksummed binaries on tag.**
  `.github/workflows/release.yml`: on a `vX.Y.Z` tag, builds the three user-facing artifacts on
  Linux x86_64 + macOS arm64 — `crustcore` (the trusted verifier; on Linux via
  `cargo xtask release`, so the reproducible build + `release-manifest.txt` are produced),
  `crustcore-net` (the model helper), and `crustcore-full` (the single-binary all-in-one) —
  emits a combined `SHA256SUMS`, and assembles a **draft** GitHub release. It **never signs or
  publishes** (no signing key/credential in CI; CLAUDE.md §6.3): the maintainer reviews the
  draft, signs `SHA256SUMS` out-of-band, and publishes manually. `workflow_dispatch` is a
  build-only dry-run. First-party actions only. This is the last step toward a zero-Rust casual
  install: download a prebuilt `crustcore-full` → `setup` → `chat`. n/a to nano.
- **World-class GitHub PR Supervisor product foundation.** Added
  `crustcore_daemon::product`, a pure non-nano product contract module for the
  first GitHub PR Supervisor wedge: `RepoProfile` / `crustcore.yml` parsing
  (fail-closed on unknown policy/executor keys), `TaskLifecycle` states for
  product UX, `ExecutorCapability` metadata for routing without authority, and
  `EvidenceBundle` / `EvidenceVerdict` for evidence-backed draft PR bodies and
  cockpit views. Added [`docs/product-stack.md`](./docs/product-stack.md) and
  [`docs/world-class-agent-roadmap.md`](./docs/world-class-agent-roadmap.md) to
  make the stack position, phases, smoke gates, and kernel-preservation boundary
  durable. No kernel or nano changes; no new dependencies.
- **Deterministic issue-to-draft-PR golden.** Un-deferred
  `golden_issue_to_pr_flow` so CI now exercises the Phase 1 decision path:
  untrusted issue ingestion, sandboxed worker patch production, verifier-minted
  `VerifiedPatch`, approval-gated draft `PrIntent`, sidecar `CreatePrRequest`
  rendering through canned GitHub REST, and bounded CI repair decisions. This is
  still socket-free; the real GitHub push/REST smoke remains a live/manual gate.
- **Verifier-intelligence planner.** Added pure product-layer verifier planning
  in `crustcore_daemon::product`: `RepoSignals`, `TaskShape`, task gates,
  staged verifier commands, and `VerifierPlan` strength/warning output. The
  planner ranks targeted checks before full-suite gates, infers conservative
  Rust/Node/Python/Make verifier commands when no profile verifier exists, and
  calls out weak evidence for bug-fix, UI, dependency, docs-only, workflow, and
  security-sensitive tasks. No kernel or nano changes; no new dependencies.
- **Path-based repo signal detector.** Added deterministic
  `RepoSignals::from_paths` and `TaskShape::from_changed_paths` defaults so
  product adapters can classify repo stacks, browser/docs/audit markers, and
  changed-file risk shape without filesystem IO or authority. Sensitive and
  workflow paths fail closed into stronger task shapes; bug fixes are still not
  inferred from filenames alone. No kernel or nano changes; no new dependencies.
- **Bounded evidence bundle export.** Added
  `EvidenceBundle::from_verifier_plan`, `export_json`, and `export_jsonl_line`
  so PR, cockpit, and audit surfaces can share the same stable
  `crustcore.evidence_bundle.v1` artifact. The export is manually bounded and
  escaped without adding serialization dependencies; planned verifier commands
  remain non-evidence until actual command results are attached. No kernel or
  nano changes; no new dependencies.
- **Changed-path verifier hints.** Extended `RepoSignals` with sanitized
  targeted verifier hints derived from repo-marker paths plus changed-file
  paths. Rust crate, Python test, and JavaScript/TypeScript test hints run
  before full-suite gates, while unsafe path fragments are rejected and cannot
  become command text. No kernel or nano changes; no new dependencies.
- **Bounded repo profiler adapter.** Added
  `crustcore_daemon::repo_profiler::RepoPathSnapshot`, a deterministic
  filesystem path observer that records marker paths only, skips symlinks and
  generated directories, caps depth/path count, and feeds `RepoSignals` /
  `VerifierPlan` without reading repo contents or granting authority. No kernel
  or nano changes; no new dependencies.

### Changed

- **Workspace version bumped `0.4.0` → `0.5.0`.** Aligns the `[workspace.package]`
  version (and all 26 internal path-dependency pins) with the rolled `[0.5.0]`
  changelog section, so prebuilt artifacts (`crustcore --version`, the release
  manifest, and the draft-release names) report `0.5.0`. Metadata only — no code,
  no dependency, and zero nano size impact (forbidden-deps + size gate unchanged).
  The maintainer-owned tag/sign/publish remains the only release step left.

### Agent Log

| Date | Phase/Task | Change | PR / Branch | Agent / Role | Nano Δ | Invariants |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-06-28 | v0.6/F.2 | Admin socket protocol: parse/frame(bounded)/nonce-auth + `dispatch_admin` (status/detail/cancel/kill) feeding the same owner-scoped path as Telegram; live listener `#[ignore]`d | `claude/v06-f2-adminsock` | Claude (Implementer) | 0 kB (daemon-only) | Enforces 5, 11, 12; operator-only, owner-scoped cancel/kill |
| 2026-06-28 | v0.6/C.3 | `EvidenceBundle::to_markdown` (bounded PR-body/cockpit render, 🔴 review notice, per-list overflow) + `to_json` (schema v1); `draft_pr_body` delegates | `claude/v06-c3-evidence` | Claude (Implementer) | 0 kB (daemon-only) | Enforces 2, 10, 11; bounded redacted evidence, every receipt included |
| 2026-06-28 | v0.6/D.1 | Task-loop wiring `plan_task`/`finalize_task` composing routing (C.1) + advisory gate (C.2) into a terminal `TaskOutcome`; sandboxed run `#[ignore]`d | `claude/v06-d1-executor-wire` | Claude (Implementer) | 0 kB (daemon-only) | Enforces 4, 5, 6, 13; verifier-owned completion, advisory only gates |
| 2026-06-28 | v0.6/A.3 | `pr_intent_to_create_request`: PrIntent→CreatePrRequest for the live draft-PR POST; evidence body verbatim, draft=true; real POST `#[ignore]`d | `claude/v06-a3-draftpr` | Claude (Implementer) | 0 kB (daemon/live-only) | Enforces 6, 13, 14; body is evidence not a model claim |
| 2026-06-28 | v0.6/A.2 | Git credential-helper protocol: `parse_credential_request`/`authorize_credential`/`credential_helper_response`/`confining_git_config` — token reaches git only over the helper pipe, bound to a registered cap; live exec/push `#[ignore]`d | `claude/v06-a2-credproxy` | Claude (Implementer) | 0 kB (daemon-only) | Enforces 1, 9, 13; no raw token in the sandbox, push confined to cap repo+prefix |
| 2026-06-28 | v0.6/C.2 | Multi-verifier advisory gate: `required_reviewers` + `orchestrate_review` folding Reviewer/SecurityAuditor verdicts + verifier result via `decide_integration`; veto-not-approval, times out into refusal | `claude/v06-c2-reviewer` | Claude (Implementer) | 0 kB (daemon-only) | Enforces 4, 5, 13; verdicts veto, verifier still completes |
| 2026-06-28 | v0.6/C.1 | Pure `decide_routing` executor router (single/fan-out/advisory/blocked) over task shape+risk+budget+configured; selection only, verifier still completes | `claude/v06-c1-router` | Claude (Implementer) | 0 kB (daemon-only) | Enforces 4, 6, 13; routing picks a worker, never authority |
| 2026-06-28 | v0.6/B.3 | Persistent repo-memory helpers (`record_failure` redacts via Redactor before persist, `record_successful_verifier`, `get_prior_failure`, `flaky_test_hints`, `changed_paths_key`) on `MemoryStore` | `claude/v06-b3-memory` | Claude (Implementer) | 0 kB (index-only) | Enforces 2, 7, 11; memory is a redacted, bounded hint, never authority |
| 2026-06-28 | v0.6/B.1 | Verifier test-graph (`TestGraph`/`command_order`) + explained `gate_reasons` on `VerifierPlan`; pure path→test fingerprints, bounded; `parse_test_manifest` pure + `#[ignore]`d live read | `claude/v06-b1-testgraph` | Claude (Implementer) | 0 kB (daemon-only) | Enforces 7, 11, 13; graph is advisory ranking, never authority |
| 2026-06-28 | v0.6/A.1 | GitHub App onboarding core: `InstallRedirect`→`cap_from_redirect`→`onboard` (register + mint `Approved<GitHubWriteCap>`), `TokenLease` refresh, `load_profile`; live install/mint seam `#[ignore]`d | `claude/v06-a1-onboarding` | Claude (Implementer) | 0 kB (daemon-only) | Enforces 3, 4, 7, 13, 14; redirect is untrusted, only an operator-bound approval authorizes a PR |
| 2026-06-28 | v0.6/runbook | Live-socket validation runbook (`docs/live-socket-validation.md`) + `scripts/validate_live_socket_runbook.sh` lint wired as `cargo xtask runbook-check` (fails CI if a live seam is uncatalogued) | `claude/v06-runbook` | Claude (Maintainer) | 0 kB (docs/script/xtask) | Preserves 1, 13, 14; documents but never relaxes the live-seam trust rules |
| 2026-06-28 | release-prep | Workspace version `0.4.0`→`0.5.0` (workspace.package + 26 internal dep pins) to match the rolled `[0.5.0]` changelog | `claude/version-0.5.0` | Claude (Maintainer) | 0 kB (metadata) | Preserves 19, 20; no code/dep change |
| 2026-06-27 | WCA-0/WCA-2 | Product-stack docs + daemon product contracts for `crustcore.yml`, lifecycle states, executor metadata, and evidence bundles | `codex/world-class-agent-foundation` | Codex (Architect/Implementer) | n/a (daemon/docs only) | Preserves 6, 7, 8, 13, 14, 19, 20; no authority path added |
| 2026-06-27 | WCA-1 | Deterministic GitHub issue-to-draft-PR golden over untrusted issue data, `VerifiedPatch`, approved draft PR intent, canned REST create, and bounded CI repair | `codex/world-class-agent-foundation` | Codex (Implementer) | n/a (eval/sidecar only) | Preserves 1, 6, 7, 8, 9, 13, 14; no live token or unverified PR path |
| 2026-06-27 | WCA-2 | Verifier planner for repo/task signals, staged check ordering, task gates, and weak-evidence warnings | `codex/world-class-agent-foundation` | Codex (Implementer) | n/a (daemon/docs only) | Preserves 6, 7, 8, 13, 19, 20; no authority path added |
| 2026-06-27 | WCA-2 | Path-based repo signal and changed-file task classifier feeding verifier planning without filesystem IO | `codex/world-class-agent-foundation` | Codex (Implementer) | n/a (daemon/docs only) | Preserves 6, 7, 8, 13, 19, 20; no authority path added |
| 2026-06-27 | WCA-2 | Bounded evidence bundle JSON/JSONL export and verifier-plan initialization for PR/cockpit/audit surfaces | `codex/world-class-agent-foundation` | Codex (Implementer) | n/a (daemon/docs only) | Preserves 6, 7, 8, 13, 19, 20; no authority path added |
| 2026-06-27 | WCA-2 | Sanitized changed-path targeted verifier hints before full-suite gates | `codex/world-class-agent-foundation` | Codex (Implementer) | n/a (daemon/docs only) | Preserves 6, 7, 8, 13, 19, 20; untrusted paths are token-checked before command text |
| 2026-06-27 | WCA-2 | Bounded repo path profiler adapter feeding verifier planning without reading contents | `codex/world-class-agent-foundation` | Codex (Implementer) | n/a (daemon/docs only) | Preserves 6, 7, 8, 13, 19, 20; filesystem observations are untrusted data |

## [0.5.0] - 2026-06-26

### Added

- **`crustcore-full` — a single-binary, casual-user front door.** The architecture is
  multi-binary by design (a sub-800kB `crustcore` that *spawns* a `crustcore-net` model
  helper + an optional `crustcore-daemon` bot) — right for the trusted core, but three
  artifacts + PATH + env wiring for a casual default. The new `crustcore-full` binary
  (`--features all`) bundles the chat front door, the Telegram bot, and the model helper into
  **one executable that spawns itself** as that helper (busybox-style, via a
  `CRUSTCORE_FULL_HELPER` marker), so there is nothing to put on PATH: `crustcore-full setup`
  / `chat` / `serve --pair`. It reads a `KEY=VALUE` config file (model keys + bot token) so a
  casual user never juggles shell env vars; with no provider configured it answers from the
  deterministic mock (offline), going live when `CRUSTCORE_NET_PROVIDERS` is set. It only
  *wires* the existing tested entry points (`crustcore_chat::run_terminal`,
  `crustcore_daemon::runtime::run_serve_loop`, the `crustcore_net` helper engine) — the trust
  boundary (redaction, allowlist, sandbox, verifier-owned completion) is unchanged and lives
  in those. Pure config/command parsing is CI-tested; the self-spawn was validated end-to-end
  (chat answers via the bundled mock helper, no network). Adversarial review: no defects.
  Invariants 19/20 intact — **zero nano impact** (a separate package; forbidden-deps green).

- **Track the all-capability-packs flagship binary size (`cargo xtask full-size`).** A new
  xtask command + CI step builds `crustcore --features full` — *every* capability pack (net +
  daemon + mcp + index + chat) linked into **one** binary — under the nano profile and reports
  its size, with a generous 2 MiB regression tripwire (a heavy live stack leaking into the
  convenience binary trips it; those belong in spawned sidecars). Measured by CI on every push,
  surfaced in the README. The headline result: linking **every** pack is **576.7 KiB** (Linux
  x86_64) — only +98 KiB over nano and *still under the 600 KiB stretch goal*, because the heavy
  live I/O (HTTP/TLS, DBs, tree-sitter) never links in. README + CLAUDE.md size tables updated.
  Invariant 19/20 (the same size-discipline thesis, now measured for the full build too).

### Fixed

- **Docs accuracy — corrected the nano size figures + test count (a final-polish audit
  finding).** The contract/overview docs cited **412.0 KiB / 51.5%** as the flagship "Linux
  x86_64" nano size, but that is the **macOS** figure — the CI size gate reports Linux x86_64
  at **478.7 KiB (490184 bytes), 59.8%** of the 800 kB budget (still within the < 600 kB
  *stretch* goal). The macOS figure is the smaller one (~412 KiB). Corrected across
  `CLAUDE.md`, `README.md` (badge + prose + tier table + size-check example), and
  `docs/roadmap-v0.2.md` (intro). Also refreshed the stale workspace **test count
  (~663 → ~834)**. No code change — nano is byte-identical across this session's feature work
  (confirmed: no nano-linked crate changed); the figures were simply mislabeled/stale.

- **Chat front-door polish — two gaps found by an end-to-end completeness audit, closed.**
  (1) **Route-aware budgets:** the chat classifier emits 4 execution routes
  (QuickFix/Feature/Project/Continue) and threaded them to `LoopAction::LaunchTask.route`, but
  the runtime *discarded* `route` and launched every task with one default budget — a dangling
  feature. `runtime::budget_for_route` now honors it with tiered per-task budgets (QuickFix
  tight → Project the generous default; Continue → Feature tier), wired through `TaskRunner::
  launch` and the PR-gated path. (2) **Abuse suppressor:** `telegram::AbuseSuppressor` (bounded,
  per-chat, deterministic over injected time) rate-limits how often a not-allowlisted chat's
  rejections are surfaced, so a flooding chat can't spam the risk signal (`docs/telegram.md`
  §4) — the allowlist still rejects every message; this only smooths reporting. 5 new tests.
  The audit also **refuted a false high-severity finding** (task progress reaching the user
  unredacted — `renderer.notice` IS the sanctioned declassifier) and confirmed all 20 invariants
  are structurally enforced + tested. Invariants 11. Nano: n/a (daemon-only).

### Added

- **Supervisor fan-out coordinator (`P11`) — race verified proposers, the verifier picks the
  winner.** `crustcore_daemon::exec::run_fanout` is the multi-proposer extension of
  `run_subagent`: it runs each proposer agent at the **same** goal via `run_subagent`
  (registry-bound identity, bounded `Scheduler` concurrency, per-agent `AgentBudget`,
  blackboard-posted to the supervisor — never the user) and **stops at the first proposer the
  verifier accepts**. The winner is chosen by the verifier (`SubagentOutcome.accepted` ⇐
  `VerifiedPatch`), never by a worker's `self_claimed_done` (invariants 6, 13); early-stop
  keeps fan-out bounded (invariant 11); an unknown/over-budget/errored proposer yields a typed
  `RunRefused` and the race continues. Pure + deterministic + CI-tested over a keyed mock
  executor (5 tests: first-winner stop, no-winner, verifier-owned selection, unknown-agent
  skip, per-agent budget). This completes the P11 supervisor control plane; wiring it to a
  live entry over a real `WorktreeSubagentExecutor` is the existing `TODO(P11-exec-live)` seam.
  Adversarial review: no defects (all 5 invariant claims verified). Invariants 5, 6, 11, 13.
  Nano: n/a (daemon-only).

- **Multi-task supervised runtime (`P10-net`, invariant 12).** The daemon ran **one** chat
  task at a time (`active: Option<TaskHandle>`); it now supervises **several** under a pure,
  CI-tested `crustcore_daemon::registry::TaskRegistry` — bounded concurrency, per-task
  lease + heartbeat, cooperative cancel + hard kill, and recovery. The registry is a
  deterministic state machine over injected `now` (no threads/clock): `admit` reserves a
  `supervisor::Scheduler` slot + grants a lease; `observe_progress`/`heartbeat` refresh the
  lease (a healthy task — even a long *silent* verify — never falsely expires; the lease
  reflects "the supervisor holds the live thread"); `tick` charges the per-task
  `AgentBudget`/`AgentUsage` (invariant 11), reclaims an expired (orphaned) lease, kills a
  runaway/over-budget task, and frees its slot — returning a bounded `RegistryAction` list
  the live loop executes against the real `TaskHandle`s. It **reuses** the existing
  `Scheduler`/`AgentBudget`/`AgentUsage` primitives verbatim and mirrors the kernel's lease
  model in-process. `/tasks` and `/task <id>` now list/detail real tasks, `/cancel <id>` and
  `/kill <id>` resolve against the registry (typed verbs, never a model prompt — invariant
  16); tasks still never touch the user directly (the loop renders + redacts every line —
  invariants 2, 5). 18 new tests (registry lifecycle/lease/budget/concurrency + command +
  heartbeat). Cross-process recovery, an admin socket, and multi-repo stay marked
  `TODO(daemon-*)` seams. Invariants 5, 11, 12, 13, 16, 19, 20. Nano: n/a (daemon-only).

- **Dev-UI live `/ws` snapshot streaming (`C7-serve-live`).** The loopback inspector's `/ws`
  route now streams live runtime snapshots over **Server-Sent Events**. A new pure,
  always-compiled core (`crustcore_dev::stream`: `next_snapshot(&dyn ReadOnlyBackend,
  SnapshotCursor) -> SnapshotBatch`) reads the existing read-model (run inspector + pending
  approvals), bounds it (`MAX_SNAPSHOT_APPROVALS`/`MAX_SNAPSHOT_TASKS`), debounces on a
  cursor, and emits a changed frame — **no socket, no async**, fully CI-tested over
  `MockDevBackend` (6 tests incl. a redaction leak-canary + bounding). The `serve`-gated
  `/ws` handler funnels through the **same** core `route` gate (auth + loopback) before
  opening, then drives an SSE stream off a `tokio::time::interval`; SSE is strictly
  server→client so it can never become an inbound control channel (invariant 16), is
  read-only by type (`&dyn ReadOnlyBackend`), and inherits the view models' redaction
  (invariant 2). The interval tick loop over a real socket is the reduced
  `TODO(C7-serve-live)` seam — an `#[ignore]`d smoke (`live_ws_sse_emits_a_snapshot`)
  exercises it end-to-end. Cargo: `tokio` gains `time`/`io-util` + a `serve`-gated
  `tokio-stream` (`IntervalStream`) — non-nano, confirmed absent from the nano graph
  (forbidden-deps clean). Invariants 2, 11, 16, 19, 20. Nano: n/a (sidecar, `serve`).

- **Chat → draft PR (the approval flow, lit up end-to-end).** A chat task can now open a
  **draft** PR, gated on a per-launch human approval (invariant 14). New
  `crustcore-daemon serve --open-pr --repo <owner/name> [--base main] [--branch-prefix
  crustcore]`: in PR mode an execution request first asks the operator to approve (the
  ✅/🚫 inline buttons), and only on approval does the task run — verifying, then minting an
  `Approved<GitHubWriteCap>` and producing a verifier-evidenced draft `PrIntent` via
  `crustcore_backend::integrate::open_pr`. The approve-first design keeps the
  `VerifiedPatch` from ever crossing a thread/approval boundary: the cap (Send data) moves
  into the task thread, where the patch is produced and consumed in one place. Two new
  pure, CI-tested security helpers — `runtime::mint_github_write_cap` (the **only** chat
  path to GitHub write authority; requires an allowlisted chat → `AuthorizedUser`, returns
  `None` otherwise) and `runtime::pr_approval_match`. The actual git push + GitHub REST
  `create_pull` remain the reduced live socket (`TODO(P10-net-live)`). Invariants 4, 13,
  14, 17. Nano: n/a (daemon-only, `live`).

- **Inline keyboards — 🛑 Steer + approve/deny buttons.** `crustcore_net::telegram::
  InlineKeyboard` (bounded: ≤8 rows × 8 cols, fields ≤64 bytes) threads through
  `send_message`'s new `reply_markup` arg; every converse answer carries a **🛑 Steer**
  button (a tap arms the next message as a steer — a new `RuntimeEvent::SteerButton`,
  handled by `normalize`/`route`/`dispatch_event` + `ChatBridge`), and
  `runtime::approval_keyboard` renders nonce-bound **✅ approve / 🚫 deny** buttons whose
  `callback_data` is op-bound exactly like the `/approve` command. Buttons carry only
  fixed labels + callback ids — never a secret. CI-tested.

- **The runnable Telegram bot — `crustcore-daemon serve` actually runs now.** The chat
  front door is no longer just building blocks: a real long-poll → dispatch → reply loop
  drives it, launching verified tasks from chat.
  - `runtime::dispatch_event` — the pure, CI-tested dispatch core (no I/O, injected
    model): one `(chat, RuntimeEvent)` → redacted `Outbound` messages + an optional
    `LoopAction` (launch/cancel a task). Handles `/help` `/status` `/tasks` `/budget`,
    `/approve`/`/deny` (resolve through the nonce engine), `/cancel`, approval-button
    callbacks, and converse/steer turns. `poll_routed` now pairs each event with its
    allowlisted source chat so the loop knows where to reply.
  - `runtime::run_serve_loop` (behind `live`) — wires the real transports (spawned
    `crustcore-net` helper for the model; `RestTelegram` over `UreqClient`), runs the
    loop, streams task progress, and gates irreversible actions on `/approve`. The bot
    token is resolved into the URL path by the net client and never logged.
  - `runtime::run_pair_discovery` + `serve --pair` — the chat-id discovery helper:
    message the bot and it prints your chat id to bind with `--chat-id` (binding stays
    CLI-side, never a DM-to-pair flow; `docs/telegram.md` §4).
  - `task::TaskHandle`/`TaskSpec` (behind `live`) — chat-launched tasks run the **same**
    worktree → sandbox → verifier flow as `crustcore run` (completion is verifier-owned;
    the chat only picks the flow), on a background thread so the bot stays responsive,
    streaming bounded status and cancellable via `/cancel`. One task at a time.
  - `crustcore-daemon serve` rewired: `--pair`/`--chat-id`/`--dir`/`--verify`/`--backend`/
    `--helper`, the bot token from `CRUSTCORE_TELEGRAM_TOKEN` (a credential, never an
    arg), with a setup guide in `--help`. Pure `parse_serve_opts` unit-tested.
  113 daemon tests (103 lib + 10 bin); the real HTTPS/sandbox sockets stay `#[ignore]`d.
  `cargo xtask verify` green (incl. daemon-`live` + all-features); nano unchanged.

- **`crustcore-full` gains an `all` feature — the single "build everything" switch —
  and is no longer stale.** `crustcore-full` now re-exports *every* runtime crate (it
  was missing the chat front door + the Track C packs: `crustcore-chat`, `-flow`,
  `-session`, `-telemetry`, `-dev`, `-index-rag`, `-toolkit`). Its new `all` feature
  turns on **every** optional capability across every pack at once (net `live`+
  `github-app`, secrets `vault-file`+`macos-keychain`+`linux-keyring`, index/`ast`,
  index-rag `live`/`persist`/`ast`/`qdrant`/`lancedb`, telemetry `otlp`, mcp `http`,
  sandbox `firecracker`+`windows-native`, daemon `live`, chat `terminal`, dev `serve`,
  flow `live-flow`, session `live-session`). Default `crustcore-full` and the nano build
  link **none** of the heavy stacks (verified by `cargo tree` + `forbidden-deps`).

- **`cargo xtask verify` now runs an `all-features` composition gate** (`cargo build
  --workspace --all-features --all-targets`) so a feature that only breaks when
  *combined* with another can never regress. Verified the whole matrix composes:
  `build`/`clippy -D warnings`/`test` all pass under `--workspace --all-features`
  (0 failures). Does not touch the nano build (separate package + profile).

- **Daemon live-runtime wiring (`crustcore-daemon`, new `live` feature; default stays
  mock-driven & CI-green).** Connects the std-only decision cores to the net-side live
  transports — each `TODO(*-live)` reduced to the irreducible socket (`#[ignore]`d), the
  adapter glue CI-tested:
  - **P9-net-live:** `telegram::LiveTelegramApi` wraps `crustcore_net::telegram::RestTelegram`
    and implements the daemon `TelegramApi` (net `TgUpdate`→`RawUpdate` mapping tested;
    `send_message` still redacted-`ModelVisibleText`-only).
  - **P10/B2:** `github::mint_installation_token` (over the net `AppTokenMinter`),
    `parse_push_argv` (git push argv → the structured `PushRequest` the fail-closed
    `validate_push` consumes — can't smuggle a protected/force ref), and a std-only
    (no axum/hyper) `webhook::serve_webhooks_once` HTTP edge that runs a bounded POST
    through the existing `WebhookVerifier` → `GitHubEnvelope`.
  - **P11-exec-live:** `exec::WorktreeSubagentExecutor` — disposable worktree →
    sandboxed `run_external_worker` → `run_verify`, `verified` set **only** from a
    verifier-minted `VerifiedPatch`; backend bound to the registry role, never a claim.
  - **P12-native-live:** `advisor::consult_via_net_helper` routes a bounded,
    untrusted-wrapped `Role::Advisor` consult through the net helper; any failure
    degrades to "proceed with caution," never an unqualified proceed.
  - **B5-autoloop-live:** `selfimprove::LiveEvalRunner` (emits an `EvalRef` only for a
    verifier-passing eval) + `draft_pr_request` (gate preserved: `open_pr` needs a
    `VerifiedPatch` by value + `Approved<GitHubWriteCap>`, always `draft:true`;
    `CycleOutcome` still tops out at `DraftReady`/`BlockedForMaintainer` — no
    Merged/Applied, no live kernel mutation, contract-file gate intact).
  78 default + 91 `--features live` tests (6 live-socket smokes `#[ignore]`d); xtask
  gates `crustcore-daemon --features live`. Non-nano; forbidden-deps confirms the
  default net helper + nano are unaffected.

- **`P9-net-live` Telegram Bot API + GitHub-App auth (`crustcore-net`).** A
  `telegram::RestTelegram` client over the `HttpClient` transport — `getUpdates`
  long-poll + `sendMessage`, the bot token resolved per-call via a new
  `CredentialSource::bot_token` and spliced into the URL path (never logged, never in an
  error body). And `githubapp` (behind a new `github-app` feature): RS256 JWT minting
  (`{alg:RS256}`, `iat`/`exp≤10min`/`iss`) + installation-token exchange, the RSA key
  resolved through the broker, `AppRsaKey`/`InstallationToken` non-`Debug`. `rsa`/`sha2`/
  `base64` optional + gated (default tree links none). Telegram build/parse and the JWT
  sign+verify are CI-tested (ephemeral keypair); the live HTTPS/exchange is `#[ignore]`d.

- **`P14-exec` + `P14-intel` (`crustcore-index`).** Live repo enumeration via a
  **hardened** `git ls-files` / `git grep -n` (scrubbed env, `core.hooksPath=/dev/null`,
  no pager/attr drivers — an untrusted repo gets no config code-exec; bounded output)
  feeding the existing `RepoMap`/`GrepCodeIntel` transforms (parsing CI-tested; live
  `git` `#[ignore]`d). Plus `ast::AstCodeIntel` (off-by-default `ast` feature, optional
  `tree-sitter` 0.25 + `tree-sitter-rust` 0.24): precise Rust symbol-definition lookup,
  iterative + bounded, falling back to `GrepCodeIntel` on unknown ext / parse failure /
  feature-off. tree-sitter never in nano.

- **`B4-firecracker` / `B4-windows` — Tier-3 microVM + Windows backends
  (`crustcore-sandbox`).** A `FirecrackerBackend` (Tier-3 Hostile microVM) behind an
  off-by-default `firecracker` feature: dependency-free (shells out to `firecracker`),
  deny-all egress + worktree-confined writes + env sanitization, wired into
  `select_backend`/`run_command` so a Tier-3 task **can** select it when present —
  **still refuse-if-no-backend, no downgrade** (a Tier-3 task with only Tier-2 backends
  is refused). A selectable `WindowsBackend` stub behind `windows-native` (real Win32
  confinement deferred — it needs a *safe* wrapper crate because this nano-linked crate
  is `#![forbid(unsafe_code)]`). No `unsafe`, no new deps, off by default; nano
  unchanged (`forbidden-deps` still 0 third-party). Live VM boot is `TODO(B4-firecracker-live)`.

- **`C5-qdrant-live` / `C5-lancedb-live` — external vector-store clients
  (`crustcore-index-rag`).** Real HTTP clients behind the `qdrant` / `lancedb` features:
  Qdrant REST (`/points`, `/points/search`, `/points/delete`) and the LanceDB
  remote/Cloud HTTP+JSON surface. API keys resolve **only** via the broker →
  `CredentialProxy`, injected as an outbound header at send time (never env/log/
  model-visible); responses are bounded and scores sanitized, and the planner's
  **no-trust-store-score** cosine re-rank is unchanged. `ureq`/`serde_json` optional +
  gated (default tree links neither). Request-build/response-parse CI-tested (incl. a
  hostile-response test); the live socket is `#[ignore]`d.

- **`P13-net-http` — `HttpMcp` remote transport (`crustcore-mcp`).** A JSON-RPC 2.0
  over HTTP MCP transport behind the `http` feature: shared envelope builder, `ureq`
  POST with `Content-Type: application/json`, the body bounded by `MAX_MESSAGE_BYTES`.
  This is where `McpAuthMode::BrokerSecret` auth reaches the wire (the resolved header
  is read only at the socket boundary — never in `params`, the result, the receipt, or
  the model). `ureq` optional + gated (default links no HTTP). Envelope/parse CI-tested;
  live POST `#[ignore]`d.

- **`C6-otlp-live` — real OTLP/HTTP+JSON trace exporter (`crustcore-telemetry`,
  `otlp` feature).** Replaces the buffer-dropping stub: serializes the post-redaction
  span IR to the OTLP/HTTP **JSON** schema (resourceSpans → scopeSpans → spans;
  `intValue` for numeric attrs like `gen_ai.usage.*`, `stringValue` otherwise) and POSTs
  to the endpoint (default `127.0.0.1:4318/v1/traces`) via `ureq` — **not** the heavy
  OTel/tonic/tokio SDK. Per-request auth resolves **only** through the broker →
  `CredentialProxy::bearer` at send time; a `BrokerBearer` endpoint refuses to POST
  unauthenticated (fail-closed); errors never panic or leak. `ureq` 2.12 + `serde_json`
  are optional/gated to `otlp` (default tree links neither — confirmed). The IR→JSON
  serialization is CI-tested; only the live socket is `#[ignore]`d.

- **`B3-embed-live` — `NetEmbedder` (`crustcore-index`).** Live text→vector embedding
  via the spawned `crustcore-net` helper over the std-only `crustcore-netproto`
  protocol, behind the existing `Embedder` trait. `HashEmbedder` stays the CI default;
  `NetEmbedder` falls back to it on any protocol/provider error (the trait is
  infallible) — a degraded embedding only changes *which* inert observation surfaces.
  Protocol round-trip CI-tested over an in-memory helper; the spawned path is
  `#[ignore]`d. Only std-only `crustcore-netproto` added; nano unaffected.

- **`P13-net` — MCP broker-secret injection (`crustcore-mcp`).** `call_tool` now
  resolves `McpAuthMode::BrokerSecret` via the broker → `CredentialProxy` and injects
  an `Authorization` header at the `McpTransport` boundary (the trait `call` gained an
  `Option<&HeaderInjection>` auth arg). Fails closed
  (`CallOutcome::CredentialUnavailable`) if the credential can't be minted — never an
  unauthenticated call. The secret never reaches the model, the receipt, or `McpResult`
  (red-team: a server echoing the token gets it `[REDACTED]`). Only the live HTTP
  transport (`TODO(P13-net-http)`) remains.

- **`P8-store` OS keychain loaders (`crustcore-secrets`, `macos-keychain` /
  `linux-keyring` features).** Dependency-free loaders that fetch secrets from the
  macOS Keychain (`security find-generic-password -w`) or Linux Secret Service
  (`secret-tool lookup`) **into an `InMemoryStore`** the broker reads — the same
  decrypt-into pattern as the encrypted-file vault. The argv-building, output-parsing
  (macOS trailing-newline strip; empty→not-found), and fail-closed store population
  (one failed entry fails the whole load) are tested over an injected `CommandRunner`
  mock; the real shell-out (`SystemCommandRunner`, `env_clear`ed) is the only
  `TODO(P8-store-live)` part. No secret bytes appear in errors. Off by default, never
  in nano (`forbidden-deps` confirms); xtask gates `macos-keychain`. 7 tests. First
  Tier-B item.

- **Conversational front door — `crustcore-chat` (new non-nano capability pack).**
  A NilCore-parity chat surface built as a std-only, deterministic **decision core**
  (no network in the core; the live model transport is the spawned `crustcore-net`
  helper, behind the `terminal` feature — never linked into nano). Pieces:
  - `route` — a non-authoritative intent **classifier** (`ChatRoute`:
    quickfix / feature / project / converse / continue) with a model-backed path that
    is *honored as-is when parseable* and a pure-function heuristic fallback otherwise
    (no retry). A route grants nothing; it only selects which kernel flow starts.
  - `persona` — a `Persona` (default "terse senior engineer" voice) + `OperatorSteering`
    (`CRUSTCORE.md`/`AGENTS.md`) assembled into the model-role **system preamble**. A
    fixed `SAFETY_PREAMBLE` always leads and overrides the persona/steering, which are
    scoped *below* the safety core. Neither type has any method yielding a capability,
    `Approved<T>`, or secret — persona shapes tone, never authority (red-team tested).
  - `converse` — the `ConverseRenderer` boundary: a model answer is **redacted then
    bounded then re-sealed** as `ModelVisibleText` (the sole `Redactor`-minted type), so
    a converse turn is redacted/bounded/attributable and a secret split by the byte
    bound still cannot leak. Optional `reveal_reasoning` (owner-authorized, off by
    default) streams reasoning, still redacted.
  - `steer` — the queue/steer state machine: plain message queues (FIFO, bounded); a
    `!`/`/steer` cancels the in-flight **model** call and jumps to the front; a steer
    arriving while a **tool** runs is *buffered* and never kills the tool; `/cancel`
    aborts. Mirrors NilCore's exact hard safety rule.
  - `session` — `ChatSession`, the single front door tying it together over an injected
    model consult; produces typed `Turn`s (`Answer`/`StartTask`/`Notice`), never raw
    model text. Plus a `Principal` channel trust line: only an authorized principal's
    message becomes a user turn (else dropped).
  - `terminal` — a CI-testable REPL (`run_repl`, generic over streams + the model
    consult) + a `complete_text` adapter over the std-only `NetHelper`, plus
    `run_terminal` which spawns the `crustcore-net` helper. The local operator is an
    authorized principal; a converse answer is redacted+bounded before it prints. A
    full-pipeline red-team test proves a secret in the model's answer is redacted in
    the REPL output.
- **Runnable `crustcore chat` subcommand (binary, `chat` feature).** Mirrors the
  `net` subcommand: gated on a new `chat` feature (`dep:crustcore-chat`), dispatched
  before CLI parse, with a stub in the base/nano build. Loads an optional `persona.md`
  + `CRUSTCORE.md`/`AGENTS.md` steering from the project root, spawns the net helper,
  and runs the terminal REPL. **Zero nano impact** — `cargo xtask verify` green; nano
  unchanged at 412.0 KiB (Linux) / 428.1 KiB (macOS); forbidden-deps clean (the chat
  pack links only the std-only protocol, no HTTP/TLS). 39 chat-pack tests + the binary
  feature build all green. Remaining for full parity: the Telegram converse channel,
  and the contract amendment of invariants 15/16 + `docs/telegram.md` §8 (owner-
  authorized) with new `docs/chat.md` / `docs/persona.md`.

- **`C5-persist` implemented — persistent `LocalVectorStore` snapshot
  (`crustcore-index-rag`, `persist` feature).** A dependency-free, versioned (`CCRG`
  v1), length-prefixed little-endian snapshot of the per-namespace
  `(ChunkId, embedding, ChunkMeta)` entries, mirroring `crustcore-index::MemoryStore`'s
  discipline: a panic-free, fail-closed, bounded decoder that pre-checks every
  count/dim/field cap **before** allocation and rejects bad magic / unknown version /
  truncation. 8 feature-gated tests. Off by default; never in nano.

- **`C5-ast` implemented — tree-sitter AST symbol spans (`crustcore-index-rag`, `ast`
  feature).** Precise chunk-boundary spans for **Rust** top-level items (fn / struct /
  enum / impl / mod / trait) via optional `tree-sitter` 0.25 + `tree-sitter-rust` 0.24,
  structured for additive grammars. Fail-closed to the existing line/grep fallback on
  unknown extension / oversize / parse failure (default behavior byte-for-byte
  unchanged); iterative walk (no recursion), bounded (≤4096 spans), never panics on
  hostile input. 7 feature-gated tests. The deps are optional and off by default —
  `cargo tree` confirms tree-sitter is **absent from the nano graph** (invariants 11,
  19, 20).

- **`B3-ann` implemented — approximate nearest-neighbor index (`crustcore-index`,
  dependency-free).** An additive `AnnIndex` using multi-table random-hyperplane LSH
  (10 tables × 8 bits, Hamming-radius-2 probe, hyperplanes from a fixed seed via an
  internal `SplitMix64` — deterministic, no wall clock / std rng), candidates
  **re-ranked by the existing exact `cosine`**. `VectorMemory` is untouched. Measured
  **top-3 recall 0.90 / top-1 1.00** vs brute force; 5 tests. Std-only.

- **`C6-genai-usage` implemented — trusted GenAI model/usage attributes in
  `crustcore-telemetry`.** The model spans now carry `gen_ai.request.model` /
  `gen_ai.response.model`, `gen_ai.usage.input_tokens`, and
  `gen_ai.usage.output_tokens` — sourced **only** from a new trusted carrier
  (`usage::RecordedUsage` + `usage::UsageBySeq`, keyed by frame `seq`) that only
  trusted code populates (the mediator's recorded `ModelCard` id + provider-reported
  token counts), **never** from untrusted model output/payload (invariants 7, 17).
  `FrameMeta` is unchanged; the carrier is threaded alongside it through
  `semconv::project_frame`, `EventProjector::project_with_usage`, `FrameInput.usage`,
  and `run_log(.., usage, ..)`. A frame without recorded usage emits no model/usage
  attrs (no fabricated tokens); the model id still passes the single `redact`
  chokepoint and is dropped on a tainted/secret value; Internal/Redacted model frames
  still project to kind+seq only. `gen_ai.system = "crustcore"` (the mediator) is
  preserved, and span/metric names remain enum-derived. New tests cover the trusted
  source, the absence case, the untrusted-name-cannot-inject case, the
  tool-seq-cannot-leak case, the redact-chokepoint case, and the Internal/Redacted
  case (unit + end-to-end through `run_log`).

- **`C7-devui` SPA served — real embedded inspector (`crustcore-dev`).** The `/` and
  `/assets` placeholders now serve a dependency-free single-page inspector (inline
  HTML/CSS/JS, no CDN): seven panels (run inspector, replay, providers, MCP, flow,
  sessions, approvals) that `fetch()` the existing typed read endpoints with the
  per-launch bearer token in an `Authorization` header (the token is obtained
  client-side from the URL fragment and **never embedded** in any served byte).
  Loopback-only + read/mutate type split + route count are unchanged; `/ws` returns a
  documented non-streaming note (live websocket push remains `TODO(C7-serve-live)`).
  10 new tests; the `serve` feature still compiles clean.

- **`crustcore-daemon` binary + `serve` subcommand.** The runtime now has an entry
  point: a tiny hand-rolled CLI (no clap) dispatching `serve`/`doctor`/`version`/`help`.
  `serve` wires the std-only runtime pieces — a deny-all-default `ChatAllowlist` (from
  `--chat-id`/`CRUSTCORE_TELEGRAM_ALLOW`), a `TelegramPoller`, and a `ChatBridge`
  (persona + steering) — and prints a readiness report; the live Bot-API long-poll loop
  stays `TODO(P9-net-live)` (no fake network loop). Pure `parse_args` unit-tested (11
  tests). Non-nano, no new deps, nano unaffected.

### Changed

- **Invariants 15 & 16 amended (owner-authorized) to sanction the chat front door.**
  Invariant 15 broadens from "Telegram only by default" to "**authorized, redacted
  channels** (Telegram by default; the `crustcore chat` front door)" — the *channel*
  widened, the *boundary* (one redacted, principal-authenticated path) did not.
  Invariant 16 changes from "not a hidden second chat channel" to "the only sanctioned
  conversational surface is the **explicit, redacted, policy-gated** `crustcore chat`" —
  no *ungoverned* parallel control plane. Updated in [`INVARIANTS.md`](./INVARIANTS.md)
  (canonical, with amendment notes), [`CLAUDE.md`](./CLAUDE.md) §4, [`README.md`](./README.md),
  [`docs/telegram.md`](./docs/telegram.md) §8.1 (the converse-turn carve-out), and the
  `crustcore-cli` doc framing. New specs: [`docs/chat.md`](./docs/chat.md) and
  [`docs/persona.md`](./docs/persona.md). The security properties are unchanged and, by
  being stated generally, strengthened — verified by the chat pack's principal-trust,
  non-authoritative-classifier, persona-cannot-authorize, and converse-redaction tests.

- **CI now runs on Linux and macOS.** The `verify` job is a matrix over
  `ubuntu-latest` + `macos-latest` (`fail-fast: false`), so `cargo xtask verify`
  (fmt, clippy `-D warnings`, the full test suite, forbidden-deps, the size gate)
  runs on both — and the macOS live `sandbox-exec` confinement tests run in CI. The
  bubblewrap install and the `cargo-bloat` size report stay Linux-only (macOS uses
  the built-in `sandbox-exec`; the flagship size claim is the Linux nano binary).

### Agent Log

- **`C6-genai-usage`** — branch `claude/complete-crustcore-and-chat-frontdoor`,
  agent role: implementer. Scope: `crustcore-telemetry` only (no new deps, no
  `Cargo.toml`/`Cargo.lock` edits). Added `src/usage.rs`
  (`RecordedUsage`/`UsageBySeq`); threaded a trusted `Option<&RecordedUsage>` through
  `semconv::project_frame`, `project::EventProjector::project_with_usage`,
  `run::FrameInput.usage`, and `run::run_log` (new `&UsageBySeq` arg); emitted the
  three `gen_ai.*` model/usage attrs from that trusted source only. Nano size impact:
  **n/a** (non-nano, feature-gated crate; never linked into nano). Invariants
  verified: 6 (telemetry mints nothing / never authoritative — carrier is read-only),
  7 & 17 (attrs from trusted recorded metadata, never untrusted payload/model output),
  1–3 (model id passes the single redact chokepoint, dropped on taint), 11 (bounded,
  count-capped, range-bounded). Verify: `cargo test -p crustcore-telemetry` (37 + 14 +
  4 green), same with `--features otlp`, `cargo clippy --all-targets -- -D warnings`
  clean (also with `otlp`), `cargo fmt --check` clean.

## [0.4.0] - 2026-06-21

First tagged release. Bundles the trusted verifier core, the live capability
surfaces, and the higher-level ergonomics packs accumulated since the project
began. It runs on **Linux and macOS** — sandboxed execution via `bubblewrap` and
`sandbox-exec` (Seatbelt) respectively, same deny-all-egress / writes-confined posture.
The flagship `crustcore-nano` binary is **412.0 KiB** stripped and the build is
reproducible on both platforms (`cargo xtask reproduce`).

### Added

- **Reproducible macOS builds (`xtask`).** `reproducible_env` now adds
  `-C link-arg=-Wl,-no_uuid` on macOS, omitting the linker-stamped Mach-O `LC_UUID`
  (derived from input paths, so it otherwise differed between `target/` and a temp
  build dir). With it, `cargo xtask release`, `reproduce`, and `size-check` produce
  **byte-identical** nano binaries on macOS — `reproduce` now actually validates the
  shipped artifact's digest on both platforms. macOS-only via `cfg!(target_os)`; the
  Linux ELF path is unchanged (it has no equivalent field under these flags).

- **macOS sandbox backend — `SeatbeltBackend` (`crustcore-sandbox`):** a Tier-2
  `sandbox-exec` (Seatbelt) backend so CrustCore can run verified tasks on macOS
  with the **same security posture as the Linux bubblewrap backend** — deny-all
  network egress and writes confined to the worktree (invariant 9). Previously
  `run_command` returned `NoBackend` on macOS and refused all execution.
  - All macOS code is behind `#[cfg(target_os = "macos")]`; the pure SBPL profile
    builder (`build_seatbelt_profile`/`sbpl_escape`) is `#[cfg(any(target_os = "macos", test))]`
    so the deterministic profile-shape test runs on every platform while a non-macOS
    release build links nothing extra. Linux path untouched (verified by an
    `x86_64-unknown-linux-gnu` clippy cross-check). `crustcore-sandbox` stays
    **std-only / in nano** (no new deps; `forbidden-deps` green).
  - The generated profile uses the robust "allow-all → deny `network*` → deny
    `file-write*` → re-allow worktree + temp dirs" recipe; the worktree and
    `TMPDIR` are `canonicalize`d (macOS `/tmp`→`/private/tmp`, `/var`→`/private/var`,
    `/var/folders/...` symlinks) before embedding, escaping `"`/`\`, and the backend
    **fails closed** (`SandboxError::Setup`) if a path cannot be resolved.
  - Wired into `run_command`'s backend assembly (macOS Tier-2 selected; a Tier-3
    hostile task is still refused without a microVM — unchanged).
  - Tests: a deterministic profile-shape test (deny rules present, canonical
    worktree allowed, no arbitrary outside write, deny precedes re-allow, paths
    escaped) plus **macOS live confinement tests** proving on the host that
    write-inside succeeds, write-outside is denied, network egress is denied
    (`nc 1.1.1.1:53`), and env sanitation strips a credential var. Fixed
    `refuses_when_no_backend_available` to skip when *any* real backend (bwrap or
    seatbelt) is present.
  - Contract: additive macOS-backend subsection (`docs/sandbox.md` §3.1).
  - Phase/task: Track "cross-platform / macOS". Branch `claude/cross-platform-macos`.
    Size impact: n/a (cfg-gated off-platform; nano unaffected, 53.5% of budget on
    this host). Invariants verified: **9** (sandbox profile for all execution; no
    unsandboxed degrade), supports **2** (no inherited secrets).


- **v0.4 Track C C7-devui — `crustcore-dev`: a loopback-only, read-only-by-default local
  developer/inspection UI built fail-safe so it CANNOT become a back door.** A new
  NON-NANO crate (also intended as `crustcore-daemon serve`) split into a PURE,
  deterministic CORE (default features, no axum/tokio/hyper — fully CI-tested over a mock
  backend) and a thin `serve` feature that wires the real loopback HTTP server. The
  trust story is preserved structurally, not by convention:
  - **`backend`** — a `DevBackend` decoupling trait split into **two disjoint
    capability traits**: `ReadOnlyBackend` (inspector/replay/provider/MCP/flow/session
    view models — every method borrows; none mints/writes/appends/verifies) and
    `MutatingBackend` (the single side-effecting op: dispatching an operation-bound
    approval resolution). A read handler is handed `&dyn ReadOnlyBackend`, which has NO
    method returning a `MutatingBackend` — reaching a side effect from a read view is a
    **compile error**, proven by a `compile_fail` doctest (dimension (c)). `MockDevBackend`
    is the CI fake; flat redacted view models carry no live/secret types.
  - **`request` / `route_class`** — a transport-agnostic `DevRequest`
    (`{method, path, headers, query, body}`) with every untrusted field length-bounded +
    validated and unknown verbs rejected at the door (invariant 7); a `RouteClass`
    `ReadOnly`/`Mutating` split + route table (assets/ws registered so auth covers them).
  - **`auth`** — a per-launch `BearerToken` (256-bit, OS-CSPRNG in `serve`), required on
    EVERY route, constant-time compared, redacted in `Debug`, never in a response/log
    (dimension (b)).
  - **`config`** — loopback `127.0.0.1` default; off-loopback (incl. `0.0.0.0`/`::`) is an
    explicit, warned opt-in via `bind_host(.., acknowledge_exposure=true)` and otherwise
    fails closed (dimension (a)); mutating routes are off unless explicitly unlocked.
  - **`views`** — `inspector`/`replay` (read-only over `EventLog::inspect`/`verify`/`iter`
    + the P5-join `verify_against_log`/`FrameRef`; reports `Intact`/`Broken`, respects
    `visibility`/`redaction_state`, inlines no payload, references artifacts by id);
    `provider` (renders `ModelCardView`/usage metadata only — never a key, redactor on
    every field); `mcp` (gate decisions from `gateway_check`/`tool_policies` + manifest
    drift — never server self-description); `flow` (loads a C3 `Flow` and SIMULATES
    single-stepping with a no-op driver — dispatches no `Action`, appends no frame,
    never reaches `run_verify`, mints no `VerifiedPatch`); `approvals` (surfaces pending
    approvals read-only).
  - **`mutation`** — the approval/mutation gate + the single request-dispatch chokepoint
    (auth → loopback → classify → read-only vs gated-mutate). A resolution is dispatched
    into the EXISTING `crustcore_daemon::telegram::ApprovalEngine` (where
    `AuthorizedUser::approve` is the sole `Approved<T>` minter); the UI never constructs
    an `Approved<T>` and a resolution is operation-bound (op-hash) so it cannot approve a
    different operation than the one shown, and mutating routes refuse without the launch
    flag (dimensions (c), (d)).
  - **`serve` / `serve_entry`** (feature-gated) — an axum/hyper loopback server mapping
    HTTP → the core `route` chokepoint, plus the `crustcore-daemon serve` alias entry;
    real provider/MCP/spawned-helper wiring is `TODO(C7-serve-live)`. axum/tokio are
    OPTIONAL deps enabled only by `serve`; the default build and the nano graph link
    none of them.
  - **`tests/redteam_devui.rs`** — 18 deterministic red-team tests over `MockDevBackend`
    covering dimensions (a)–(g): no off-loopback default, non-loopback peer rejected,
    auth required on every route (assets/ws included), token never in a response,
    read-views cause no log side effect, flow simulation never completes/mints a
    `VerifiedPatch`, mutating route off by default, cannot approve a different operation
    or as a non-allowlisted identity, no sentinel secret in any response, redacted
    payloads never inlined, oversized/unknown input rejected, and no chat/free-text
    channel to model or user (invariants 15/16).
- **v0.4 Track C C3-flow — `crustcore-flow`: a typed, deterministic workflow DSL over
  CrustCore's supervisor/subagent/verify primitives WITHOUT widening the trust
  boundary.** A new NON-NANO sidecar crate giving an ergonomic, typed `Flow` graph
  (`model` · `tool` · `verify` · `review` · `parallel` · `loop_until` · `route` ·
  `join`). The engine is a **pure deterministic scheduler that owns no I/O** — every
  effectful node delegates to an INJECTED driver (the project's seam pattern), so the
  whole graph is CI-testable with `FakeDrivers` and live transports drop in behind the
  `live-flow` feature with the engine unchanged. **A Flow is a plan, not an
  authority** — the trust story is preserved structurally:
  - **`graph` + `builder`** — `Node` enum, opaque `NodeId`, typed `FlowState`
    (predicates read this and only this), `FlowError`, `Flow`, and a `FlowBuilder`
    whose constructors default every classification to the MOST RESTRICTIVE posture
    (`ToolSpec::fail_closed` ⇒ `Reversibility::Destructive` + execution-capable;
    `FlowBudget::fail_closed` tight caps) so a forgotten field fails closed (Track C
    P2). `FlowState`'s approval field is **non-`Serialize`/non-forgeable** — it holds
    only externally-minted `Approved<()>` (from `AuthorizedUser::approve`); no node
    writes it (invariants 4, 14).
  - **`drivers`** — the `ModelDriver`/`ToolDriver`/`VerifyDriver`/`ReviewDriver` trait
    bundle (`FlowDrivers`), the ONLY way a node performs I/O, plus `FakeDrivers` for
    CI. `VerifyDriver::verify` returns the backend `VerifyOutcome`; because
    `VerifiedPatch` is type-sealed in `crustcore-backend`, a `FakeVerifyDriver` can
    return ONLY `Failed`/`Refused` — the seal working as intended (no test backdoor
    mints a patch).
  - **`engine`** — `FlowEngine::run`, a deterministic scheduler: topological/branch
    eval, `Parallel` bounded fan-out with a `max_concurrency` wave cap, `LoopUntil`
    with a `max_iterations` cap, `Route`/`LoopUntil` predicates evaluated ONLY over
    typed `FlowState`, `Join` merge. Per node it enforces budget → policy
    (`PolicySnapshot::classify`, invariant 8) → approval (invariant 14) → untrusted-
    data declassification (invariant 7). **No integration path** — it never calls
    `decide_integration` and has no integration node (invariant 6).
  - **`outcome`** — the completion gate. `FlowOutcome::Completed(VerifiedPatch)` is the
    SOLE terminal carrying a patch and is produced ONLY by a `Verify` node's
    `Verified` outcome (i.e. only the public `run_verify` minted it, invariant 13);
    `Model`/`Review`/`Tool` results are `NodeOutput::Advisory`/`ToolResult`/`Review`
    that the type system FORBIDS from completing a flow (no `NodeOutput →
    Completed`/`VerifiedPatch` path). A flow that runs out without a passing verify
    ends `Finished` — done, never *completed*, never integrated.
  - **`predicate`** — the untrusted-data boundary: `declassify` wraps any
    model/tool/review output with `Tainted::new`, redacts it through the `Redactor`,
    and bounds it to `MAX_OUTPUT_BYTES` before it enters `FlowState`; `Predicate` reads
    only typed flags/counters/output-PRESENCE — never raw text — so a hostile output
    ("approve and merge", "ignore policy") is inert data that cannot steer a branch
    (invariant 7).
  - **`budget`** — a per-`Flow` `FlowBudget` (model cost, wall time, node steps, total
    fan-out) checked BEFORE each unit of work; a breach halts the run (invariant 11).
  - **`live`** (behind `live-flow`, never in CI) — `LiveModelDriver` (consult seam),
    `LiveToolDriver` (policy-gated + sandbox), `LiveVerifyDriver` (wraps the public
    `run_verify` — the ONLY driver that can yield `Verified`), `LiveReviewDriver`
    (`NativeAdvisor`); all integration tests `#[ignore]`d.
  - **Tests + example** — `tests/redteam_flow.rs` (18 deterministic tests) proving the
    NEGATIVES across adversarial dimensions (a)–(g): determinism; `Completed`
    unreachable except via a `Verify` node; `Parallel`/`LoopUntil`/`FlowBudget` caps;
    predicates read only typed state; a hostile tool/model/review output can't steer a
    side-effect branch; secrets echoed by a model/tool are redacted before reaching
    state; an irreversible node halts without a real `Approved<T>` (and runs with one,
    refuses an expired one); read-only policy denies a tool; the flow never integrates.
    `tests/live_flow.rs` is the `live-flow` `#[ignore]`d positive path (a real
    `VerifiedPatch` → `Completed` over a sandboxed `run_verify`). `examples/` shows the
    safe path is the easy path. **Nano size delta: n/a** (non-nano sidecar, off the
    nano graph; live deps `live-flow`-gated). Invariants touched/verified: 4, 5, 6, 7,
    8, 9, 11, 13, 14.

- **v0.4 Track C C5-rag — `crustcore-index-rag`: a composable RAG layer that
  generalizes B3-vector-memory WITHOUT widening the trust boundary (memory is never
  authority).** A new OPTIONAL, OFF-NANO pack that turns B3's single in-process vector
  store + `semantic_select` proof into the swappable RAG surface real repos need — pick
  your store, chunk the repo once, retrieve symbol-accurate context — by composing only
  existing typed contracts. Every retrieved fragment stays inert, redacted, bounded,
  provenance-tagged `ModelVisibleText` with **no path to `Approved<T>` or any
  capability**. Modules:
  - **`store`** — a pluggable `VectorStore` adapter trait (`upsert` /
    `nearest(query, k, floor)` / `delete` / namespace scoping), **retrieval-only —
    grants nothing**, mirroring `VectorMemory::nearest`. `ChunkMeta { path, byte_span,
    symbol: Option<..>, source: MemorySource, redact_required }` is a **pure data tag
    with no capability/approval field** (dangerous "memory-as-authority" state is
    unrepresentable). `k` is capped to `MAX_NEAREST_K`; returned hits truncated to
    `MAX_STORE_HITS`.
  - **`store::local`** — the DEFAULT **dependency-free** backend over
    `crustcore-index`'s in-memory set, reusing `crustcore_index::embed::cosine` verbatim;
    preserves `VectorMemory` query semantics exactly (positively-similar only,
    descending score with deterministic insertion-order ties) plus an explicit floor.
    Persistence is the `TODO(C5-persist)` seam behind the off-by-default `persist`
    feature.
  - **`store::mock`** — a controllable `MockVectorStore` for CI that can be told to
    misbehave like a hostile backend (oversized payloads, NaN/inf/negative scores,
    duplicate-forged `ChunkId`s) so the planner's bounding/sanitization/redaction is
    what's under test.
  - **`store::qdrant` / `store::lancedb`** — thin adapters, each behind its OWN
    off-by-default cargo feature, routing any auth via `crustcore_secrets::CredentialProxy`
    (key never to model/sandbox env); the real client is `TODO(C5-<backend>-live)`.
  - **`chunk`** — a bounded repo `Chunker`: line-oriented fragments with overlap,
    **defaulting to whole-line, bounded, deny-large chunks** (fail-safe). Every fragment
    is `<= MAX_CHUNK_BYTES` (a giant single line is split at a UTF-8 boundary); per-file
    and per-call fan-out are capped. `ChunkMeta` defaults to `redact_required = true`,
    `symbol = None`.
  - **`chunk::symbol`** — symbol-aware metadata via the EXISTING
    `crustcore_index::CodeIntel` trait (backed by the real `GrepCodeIntel`): aligns chunk
    boundaries to symbol spans and tags `ChunkMeta.symbol`. **Conservative line-chunk
    fallback is the DEFAULT** whenever symbol info is absent (fail-closed, never
    unbounded). Malformed/inverted/out-of-range symbol spans are sanitized, never
    trusted. A tree-sitter/AST backend is `TODO(C5-ast)` behind the off-by-default `ast`
    feature.
  - **`plan`** — the `QueryPlanner` trust chokepoint: embed the (bounded) query via the
    B3-owned `crustcore_index::embed::Embedder`, build a bounded `RetrievalPlan
    { namespace, k (capped), floor }`, run the store NN, dedup forged `ChunkId`s, then
    push every hit through the **existing** `semantic_select` redact-then-bound boundary
    (`Redactor` + the `MAX_CONTEXT_*` caps) — emitting a `ContextBundle` of inert,
    provenance-tagged fragments. The store score is NOT trusted for ranking;
    `semantic_select` re-ranks by cosine, so a NaN/forged store score cannot reorder or
    smuggle a fragment.
  - **`index`** — `index_repo(files, &Chunker, &Embedder, &mut VectorStore, source)`:
    chunk → embed → upsert, all bounded; **write-to-store only** (no chunk content enters
    model context — it returns an opaque `IndexedContent` resolver, not a bundle); the
    live indexer reads via confined paths.
  - Reused verbatim (never re-implemented): the `Embedder` trait, `HashEmbedder`,
    `cosine`, `VectorMemory` semantics, `semantic_select`/`build_bundle`'s
    redact-then-bound boundary, `CodeIntel`/`GrepCodeIntel`, and
    `crustcore_secrets::{Redactor, CredentialProxy}`. Seams left for live work:
    `TODO(B3-embed-live)` (`live` feature), `TODO(C5-ast)` (`ast`), `TODO(C5-persist)`
    (`persist`), `TODO(C5-<backend>-live)` (`qdrant`/`lancedb`).
  - **Tests (deterministic, CI):** chunker bounds every fragment to `MAX_CHUNK_BYTES`
    incl. the giant-line / multibyte cases; the `ast`-off / symbol-absent line-chunk
    fallback is always exercised; symbol metadata aligns to `CodeIntel` spans; the local
    backend matches `VectorMemory` semantics; the planner caps `k`, applies the floor,
    and bounds+redacts every fragment; a precision@1 eval over a canned corpus meets a
    floor (3/4); retrieval is deterministic across runs. **Red-team (`redteam_rag.rs`):**
    the B3 `sk-VECSENTINEL` hostile chunk, ranked nearest, stays inert + redacted +
    provenance-tagged with no `Approved<T>` path — run through the planner over BOTH the
    local backend AND `MockVectorStore`; a malicious backend (10k oversized hits,
    NaN/inf/negative scores, forged duplicate ids) does not bypass bounding or panic;
    missing classification fails closed; indexing is write-to-store only. Covers
    dimensions (a)–(g).
  - **Nano size: ZERO delta.** New off-nano pack; `crustcore-index` is already never
    linked into nano; the default build links no heavy third-party dep, and all
    external-store / `ast` / `live` / `persist` deps are behind off-by-default cargo
    features. Confirmed: `crustcore-index-rag` absent from
    `cargo tree -p crustcore --no-default-features --features nano`; `cargo xtask
    forbidden-deps` green (nano tree first-party only).

- **v0.4 Track C C6-telemetry — `crustcore-telemetry`: a read-only OpenTelemetry /
  GenAI-semconv PROJECTION of the audit log (mints nothing, never authoritative).** A
  new NON-NANO sidecar crate that turns CrustCore's already-authoritative hash-chained
  event log + MAC-chained tool receipts into standard OTel spans/metrics under the
  GenAI semantic conventions — so model calls, tool runs, verify outcomes, and budget
  burn become Grafana/Honeycomb/Jaeger-native *without widening the trust boundary*.
  The event log stays the single source of truth; telemetry is a derived projection
  that changes no state, so a deleted/altered span cannot affect a verdict, budget, or
  `VerifiedPatch`. Modules:
  - **`project`** — `EventProjector`, a pure, sync, SDK-free mapper from a *borrowed*
    `FrameMeta` (+ its joined `ToolReceipt`) to a neutral in-crate IR
    (`SpanModel { name, attrs }` / `MetricSample { name, value, labels }`). Reads only
    typed header/receipt fields, never payload bytes; deterministic and idempotent.
  - **`semconv`** — the `EventKind` → span/metric mapping table. Model frames →
    `gen_ai.model_request`/`gen_ai.model_response` (`gen_ai.system = crustcore` + the
    operation; conservative — no model name/usage from untrusted output, inv 17);
    `ToolCall*` + joined receipt → `crustcore.tool.*` (receipt hashes/MAC/ids only,
    never tool name/args/result values, inv 10); `Patch*` → `crustcore.verify.*`;
    budget deltas → `crustcore.budget.<axis>` metrics. **Span/metric NAMES come ONLY
    from the closed `EventKind`/`BudgetAxis` enums via an exhaustive `match`** — never
    payload (inv 6, 7).
  - **`redact`** — the MANDATORY redaction gate as the SOLE emission chokepoint:
    every attribute value + metric label passes `Redactor::redact`, then is bounded by
    `MAX_ATTR_LEN` (per-value, char-safe, AFTER redaction so no fragment leaks) and
    `MAX_ATTRS` (per span/metric, excess dropped with a `crustcore.telemetry.attrs_dropped`
    marker). `redact_frame` is the only IR→exporter path.
  - **`export`** — an `Exporter` trait consuming ONLY the post-redaction IR (never a
    raw frame), an `InMemoryExporter` (CI default; `all_strings()` for leak scans), and
    an `OtlpExporter` behind the `otlp` feature (minimal buffering stub; real socket
    `TODO(C6-otlp-live)`).
  - **`auth`** — broker-mediated OTLP endpoint auth seam: `OtlpEndpointAuth` holds only
    a `SecretHandle`, never bytes; the `otlp`-gated `inject` resolves the bearer per
    request via `SecretBroker`→`ApprovedSecretView`→`CredentialProxy::bearer`, never
    env/span/model-visible (inv 1; `TODO(C6-otlp-live)`).
  - **`run`** — the driver: `run` over typed `FrameInput`s and `run_log` over an
    `EventLog` + receipts (range-filtered in-crate, receipt↔log join via P5-join's
    `verify_against_log`, consumed not re-implemented). Project → redact → export;
    `batch_bound`/`sample_rate` bound the work; Internal/`Redacted` frames emit only
    kind+seq; `enabled = false` default (fail-closed).
  - **`config`** — opt-in config defaulting fully OFF, in-memory exporter, loopback
    collector (`127.0.0.1:4318`), bounded batch.
  43 deterministic CI tests (29 unit + 10 integration + 4 red-team) over synthetic
  `EventLog`+receipt fixtures: each `EventKind` → expected span name + `gen_ai.*`/
  `crustcore.*` attrs; attr count/length bounding; Internal-visibility + `Redacted`
  frames emit no payload-derived attrs; read-only (log bytes/head unchanged, idempotent);
  forged receipt seq doesn't bind to an unrelated span; **C6T.7 leak-canary** — a log
  whose payloads embed sentinel `sk-LEAKCANARY-7f3a` (+ a `Tainted<T>` frame + a
  `Redacted` frame) emits NO sentinel in any span attr, metric label, span name, or
  metric name, and `would_leak` is false on every emitted string. Workspace `Cargo.toml`
  touched additively only (1 member + 1 internal path dep). Default build links zero
  third-party crates; `cargo xtask forbidden-deps` green (telemetry/OTel absent from
  nano); nano 412.0 KiB, zero delta.

- **v0.4 Track C C4-session — `crustcore-session`: a conversation/session/artifact
  service as a redacted, verify-or-refuse VIEW over the hash-chained event log
  (never a competing store).** A new NON-NANO crate giving the daemon, `crustcore-flow`
  (C3), and the C7 dev UI the application-level session model CrustCore lacked, while
  preserving the trust boundary structurally. The `crustcore-eventlog` chain remains the
  single source of truth; a session is an *index*, a snapshot a *derived projection at a
  `seq`*, a resumable run a *replay-and-verify* of a frame range. Modules:
  - **`id`** — opaque `SessionId`/`ConversationId` newtypes (a session is "a run" of one
    `TaskId`).
  - **`view`** — a borrowing `SessionView` that indexes an `EventLog` by `task_id`/`job_id`/
    `seq` range (built on `EventFrame`/`iter`), and a `ConversationView` over the
    user/model/tool turn frames. The view holds `&EventLog` and re-derives on demand — it
    never copies the chain into a second mutable store and exposes no completion/integration
    method.
  - **`snapshot`** — `Snapshot { session, at_seq, head_hash, turns }` derived by replaying
    frames up to a `seq`, including **only** `Visibility::ModelVisible` frames (Internal/
    unclassified excluded — FAIL CLOSED via a positive match), passing every retained text
    field through `Redactor`. Structurally carries no `SecretMaterial`/`Tainted<T>` field
    (invariant 3); `Serialize`/`Deserialize` for on-disk persistence (serde, sidecar-only).
    A reloaded snapshot is UNTRUSTED until `Snapshot::verify_against` re-checks its
    `head_hash` against the live log via `verify_to_head`.
  - **`resume`** — `resume`/`resume_to_head` run `EventLog::verify` (or `verify_to_head`
    against a persisted head) AND `crustcore_receipts::join::verify_against_log`, returning
    a `SessionView` only when `is_intact()` AND `is_joined()`, else `ResumeRefused`
    carrying the exact `BreakReason`/`JoinBreak`. Resume reconstructs a VIEW; it mutates no
    kernel state and never completes/integrates (invariants 13, 18).
  - **`lease`** — re-derives lease/heartbeat/cancellation/recovery (invariant 12) from
    `JobLeased`/`TaskKilled`/`TaskFailed` frames; `LeaseView::owned_by` ASSERTS ownership
    rather than claiming it, and surfaces a kill/cancellation rather than silently
    re-running.
  - **`artifact`** — opaque `ArtifactHandle(ArtifactId)`; contents NEVER inlined into any
    view/snapshot/projection (invariant 20); a `BoundedArtifact` accessor caps reads
    (`MAX_ARTIFACT_BYTES`) for trusted, non-projection code only.
  - **`compact`** — `CompactionPolicy` (keep-last-N / summarize-older / drop-bulk-to-handles):
    redact-then-bound with `MAX_COMPACT_BYTES`/`MAX_COMPACT_TURNS`/`MAX_TURN_BYTES` caps
    mirroring `crustcore-index`'s posture; output is never-authority `ModelVisibleText`.
    The default policy is the most restrictive bounded form (drop-bulk-to-handles).
  - **`service`** — a `SessionService` facade (`open`/`snapshot`/`resume`/`compact`/`list`)
    that is strictly READ/DERIVE/VERIFY-ONLY. It exposes NO method returning `Approved<T>`,
    a `VerifiedPatch`, a capability/approval token, or any side-effect trigger — enforced by
    construction (the crate does not depend on `crustcore-backend`/`-policy`, so no such
    type is in scope). Completion remains solely `crustcore_backend::verify::run_verify`
    (explicit non-goal stated in the module doc).
  - **Tests (fully CI-testable, no net/secrets/binaries):** 41 unit + 14 integration
    (`session_roundtrip.rs`) + 9 red-team (`redteam_session.rs`) = 64 deterministic tests
    over synthetic + a committed on-disk `EventLog` fixture (`fixtures/clean_session.cclog`,
    regenerated by `examples/gen_fixture.rs`). Covers snapshot derive→serialize→restore
    round-trip + `head_hash` re-verify; Internal/unclassified frames excluded fail-closed;
    each event-log tamper class (flipped payload, deleted/reordered/inserted/truncated
    frame, clean-trailing-removal-under-head-anchor) and each forged-receipt `JoinBreak`
    class returning the exact `ResumeRefused`; compaction never exceeds the `MAX_*` caps;
    artifact handles never inline bytes into a projection; and red-team dimensions (a)–(h),
    notably (h) no facade path completes/integrates/authorizes and (b) no sentinel secret
    reaches a serialized snapshot. **Nano size delta: n/a** — non-nano sidecar; `serde`/
    `serde_json` stay off the nano graph (proven by `cargo xtask forbidden-deps` + `cargo
    tree -p crustcore --features nano`). Workspace `Cargo.toml` touched additively only
    (one `members` line + one `[workspace.dependencies]` path entry).
- **v0.4 Track C C2-toolmacro — the `#[crust_tool]` tool-authoring macro
  (schema · bounded I/O · redaction · host-minted receipts · fail-safe risk).** Two
  new NON-NANO crates that make authoring a *safe* capability-pack tool trivial by
  CONSUMING the existing policy/secrets/receipts/types contracts UNCHANGED — the safe
  path is the easy path, and a forgotten classification fails CLOSED (Track C
  principle P2).
  - **`crustcore-toolkit`** (std-only, ZERO new third-party runtime deps) holds the
    REAL safety logic so it is unit-testable without the macro: the `CrustTool` trait
    (`schema() -> ToolSchema`, `default_reversibility() -> Reversibility`,
    `invoke(&ToolArgs) -> Result<ToolOutcome, ToolError>`); `ToolOutcome { visible:
    ModelVisibleText, artifacts: Vec<ArtifactRef> }` where `visible` is the ONLY
    model-visible channel (type-enforced — `ModelVisibleText`'s sole constructor is
    `Redactor::to_model_visible`, so a tool cannot return un-redacted visible text);
    a small JSON-schema value type (`SchemaType`/`ParamSchema`/`ToolSchema`, with
    `is_concrete()` proving no `Any`); bounded `ToolArgs` (refuses oversize input);
    `ToolError` (incl. `InputTooLarge`/`OutputTooLarge`); and the host-side
    `finalize`/`HostTool::emit` helper that performs the fixed order **redact → bound
    (refuse-on-overrun) → mint receipt over the EXACT redacted+bounded bytes**. The
    HOST owns the `MacKey`/`ReceiptChain` (passed by `&mut`); the helper takes them by
    reference — generated code never holds a `MacKey`, never calls
    `ReceiptChain::mint`, and never references `Approved<T>`/`AuthorizedUser::approve`.
    `classify_tool::<T>(policy)` forwards the risk decision to
    `PolicySnapshot::classify` (never inlined).
  - **`crustcore-tool-macro`** (proc-macro crate; `syn`/`quote`/`proc-macro2` are
    BUILD-TIME ONLY) — `#[crust_tool]` on a free function generates: a `CrustTool`
    impl whose `ToolSchema` is DERIVED from the typed signature (String, the integer
    types, bool, `Option<T>`, `Vec<T>` of those; an UNSUPPORTED type is a HARD COMPILE
    ERROR, never a permissive `Any`); `default_reversibility()` returning the most
    restrictive `Reversibility::Destructive` UNLESS the author writes
    `#[crust_tool(reversibility = "Reversible")]` etc. (an unknown/typo'd value is a
    hard error); and an `invoke` that decodes the bounded untrusted args and delegates
    result handling to the toolkit's `finalize`. Generated code uses fully-qualified
    `::crustcore_toolkit::…` paths + hygienic identifiers and emits a per-tool
    `#[cfg(test)]` fixture (schema concrete, oversize input refused, sentinel secret
    redacted + `would_leak` false, fail-safe classification). The macro is *wiring
    only* — it never embeds an allow/deny decision and never lets generated code
    self-authorize or forge a receipt.
  - **C2.7 migration deferred (approved scoping):** to keep this PR's blast radius
    small (no edits to the `crustcore-mcp`/`crustcore-daemon` trust paths or their
    tests), a representative end-to-end EXAMPLE exercising the full safe path ships
    instead (`crustcore-toolkit/examples/safe_tool.rs` hand-written +
    `crustcore-tool-macro/examples/crust_tool_demo.rs` via the macro). Migrating a
    live pack tool to `#[crust_tool]` is a mechanical follow-up swap.
  - **Testing:** runtime tests are the gate (`crustcore-toolkit/tests/safe_path.rs`,
    `crustcore-tool-macro/tests/generated_tool.rs`); the bypass-attempt
    `compile_fail`/trybuild UI tests (`tests/compile_fail.rs` + `tests/ui/*`) are
    gated behind a `trybuild` cargo feature and are OFF in the default
    `cargo test --workspace` (pinned `.stderr` is rustc-version-sensitive). **Nano
    impact ZERO:** neither crate (nor `syn`/`quote`/`proc-macro2`) is in the nano
    feature graph — proven by `cargo tree`/`cargo xtask forbidden-deps` (nano stays
    412.0 KiB, 51.5% of budget). Workspace `Cargo.toml` gained the two members + two
    internal path entries (minimal additive contract-file change, integrator-owned).
- **v0.4 Track C C1-providers — unified multi-modal capability registry
  (embedding + rerank).** Generalized `crustcore-net`'s completion-only routing core
  into one multi-modal registry without touching the frozen P7-live contract. The
  `Provider`/`Engine`/`select_candidates`/`apply_budget`/`run_reliable`/streaming
  sink/`BudgetLedger` are reused verbatim; C1 adds **sibling** capability traits
  `EmbedProvider`/`RerankProvider` (sync, mirroring `Provider`'s `id`/`probe`/call
  shape; credentials resolve per-call via the same `CredentialSource`/`AuthHeader`,
  never stored) and per-modality `EmbedEngine`/`RerankEngine` that reuse the same
  hard-constraint-then-role-order filter (`select_candidates_for`), the same
  `run_reliable`-shaped fallback, and the **same single `BudgetLedger` instance**
  across all three modalities (invariant 11 — proven by a cross-modality accumulation
  test). New value types `EmbeddingRequest`/`EmbeddingResponse` (bounded by `MAX_BATCH`
  + `MAX_TEXT_BYTES`) and `RerankRequest`/`RerankResponse` (bounded by `MAX_DOCS`); a
  new `MultiModalEngine` + `serve` wiring routes all three (completion-only `serve`
  kept working). **Additive** capability fields `embeddings: bool`/`rerank: bool`/
  `embedding_dims: u32` (all **default-off**, unlike `streaming`) flow through *both*
  `ModelCard` (net) **and** its wire mirror `ModelInfo` (netproto) via `ModelCard::to_info`
  — completion routing byte-for-byte unchanged. New bounded wire variants
  `Request::Embed`/`Request::Rerank` + `Response::Embedding`/`Response::Ranking`
  (flat-JSON delimited encoding; non-finite floats sanitized to `0.0`; default-off
  decode of absent capability keys, invariant 17) + `NetHelper::embed`/`rerank` client
  methods. Live adapters: an OpenAI-compatible `/v1/embeddings` `EmbedProvider`
  (`embed.rs`) and a Cohere/Jina-style `/v1/rerank` `RerankProvider` (`rerank.rs`),
  both over the `HttpClient` boundary (CI-tested with `ReplayClient`), 429/5xx/timeout
  → `Unavailable`, 400/context → `Capability`, else `Other` via the shared status-only
  `map_status_error`, and **rerank scores/indices treated as untrusted — out-of-range
  and duplicate indices dropped, non-finite scores sanitized, never propagated raw**
  (invariant 7). Deterministic `MockEmbedProvider`/`MockRerankProvider` + a
  `default_mock_multimodal_engine` so the default/CI build links nothing new; the real
  `UreqClient` path stays behind the existing `live` feature. A red-team fixture
  (`tests/redteam_c1_modality.rs`, 10 tests) covers the (a)–(g) dimensions: credential
  never leaks through any embed/rerank error/garbage path, no panic/over-read on
  malformed/oversized bytes, out-of-range/duplicate rerank indices can't corrupt
  selection, capability-missing requests fail closed, config/decode omission can't flip
  a capability on, and a failing embedder emits no partial output before fallback.
  `docs/model-routing.md` §1.2 documents the registry and names B3-vector-memory as the
  `EmbedProvider` consumer. **No new deps** (`serde_json` already present, `ureq` already
  `live`-gated); `crustcore-net`/`crustcore-netproto`/`docs/model-routing.md` are not
  contract files. `cargo xtask forbidden-deps` + `size-check` green: nano unchanged at
  412.0 KiB, **zero nano delta** (all new code in the non-nano sidecar; netproto adds
  protocol-only bounded variants). (size impact: 0 kB)
- **v0.4 Track C (compose & adopt) — roadmap planning (C1–C7).** Added a new
  **Track C** to [`docs/roadmap-v0.2.md`](./docs/roadmap-v0.2.md) — the RIG/ADK-Rust
  *ergonomics* track — with seven fully-specified phases ready for multi-worker
  execution: **C1-providers** (unified multi-modal provider/capability registry —
  `EmbedProvider`/`RerankProvider` siblings beside the frozen `Provider`/`Engine`,
  named to avoid colliding with B3's consumer-side `crustcore-index::embed::Embedder`),
  **C2-toolmacro** (`#[crust_tool]` proc-macro: schema + bounded I/O + redaction +
  host-minted receipts + fail-safe `Reversibility::Destructive` default),
  **C3-flow** (`crustcore-flow` typed workflow graph where the `verify` node is the
  sole completion path), **C4-session** (session/artifact service as a redacted,
  verify-or-refuse *view* over the event log), **C5-rag** (`crustcore-index-rag`
  extending B3-vector-memory + P14-live with pluggable vector stores, a chunker, and
  symbol-aware metadata), **C6-telemetry** (read-only OTel/GenAI-semconv projection of
  the audit log, redaction-gated), and **C7-devui** (`crustcore-dev` loopback-only
  read-only inspector/replay/provider-tester/MCP/workflow-debugger UI). Each phase
  carries the full per-phase template (goal, leverage, prerequisites, task table with
  owned globs, deferral boundary, contract-file impact, test/verify strategy,
  adversarial-review dimensions, parallelization, best practices, risks, DoD, nano size
  impact), plus a Track C intro, dependency waves (C-1/C-2/C-3), cross-cutting
  principles, a v0.4 definition of done, and an out-of-scope note. Front-matter spliced:
  title, intro, "How to read this", and a v0.4 milestone slice. **Drafted by a
  multi-agent workflow (8 units × design + adversarial review, then synthesis) and
  integrated by the supervisor**; the review caught and fixed real inaccuracies
  (`Embedder` lives in `crustcore-index::embed` per B3; `run_verify_with` is
  module-private — flow calls public `run_verify`; `Tainted<T>` is string-bound/
  non-`Clone`; `Approved<T>`'s sole constructor is `AuthorizedUser::approve`; receipts
  mint via `ReceiptChain::mint` keyed by a host-held `MacKey`). Documentation/planning
  only — no code. Every Track C surface is a non-nano sidecar/feature-gated pack with
  **zero nano impact**, consumes the existing typed contracts unchanged, defaults
  fail-safe, and cannot become a side-effect/completion/user-comms path. (size impact: n/a)
- **v0.3 B6-release-infra — reproducible builds (B6.2).** The nano binary now builds
  **deterministically** — *verified* same-machine, not just asserted. `cargo xtask` builds
  nano under a deterministic env (`reproducible_env`): `--remap-path-prefix` strips every
  machine-specific absolute prefix — the workspace path, the cargo home, **and the rustup
  toolchain sysroot** — so the binary embeds none of the builder's install paths;
  `SOURCE_DATE_EPOCH=0` pins any embedded timestamp; `CARGO_INCREMENTAL=0` disables the
  non-deterministic cache — which, with the `nano` profile (`codegen-units=1`/`lto=fat`/
  `strip`/`panic=abort`) and the pinned `rust-toolchain.toml`, makes the build
  deterministic. A new **`cargo xtask reproduce`** builds nano twice into independent target
  dirs and asserts the two SHA-256 digests match (it passed). `size-check`/`release`/
  `reproduce` now measure the **same** binary, so the released digest can be re-derived
  rather than trusted. **Adversarial review: 8 findings, 4 confirmed and fixed** — all about
  the same overclaim: `reproduce` proves *same-machine* determinism, not the cross-machine
  "anyone can rebuild" I'd written; fixed by (a) genuinely **adding the rustup/sysroot
  remap** (a real cross-machine variance source I'd missed), and (b) rewriting `docs/releasing.md`
  §9 to state honestly what `reproduce` proves vs. what full cross-machine bit-identity still
  needs (a `1.x.y` toolchain-version pin — `stable` is a channel, not a pin — and the same
  target triple), reconciling it with §2. `docs/releasing.md` §9 added. **No new deps**;
  nano steady at 412.0 KiB (the remap leaves the stripped binary's size unchanged).
  **Maintainer-owned (not agent-wired):** the signed GitHub Actions release workflow (B6.1)
  and the `cargo-bloat`/fuzz CI jobs (B6.3) edit `.github/workflows/**` — an irreversible,
  CI-credentialed step (CLAUDE.md §6.3); the optional rich TUI + package publishing (B6.4)
  remain separate non-nano artifacts.
- **v0.3 B5-autoloop — self-improvement loop runner (B5.1/B5.2).** Drive the PR/eval-gated
  self-improvement cycle end to end over the (complete) P15 core, in
  `crustcore-daemon::selfimprove`. New `run_cycle(proposal, changed_paths, &dyn EvalRunner)`
  composes the gates: run the proposal's evals via an **`EvalRunner` seam** (live: sandboxed
  P11-exec workers running the real eval suite, `TODO(B5-autoloop-live)`; a mock drives CI —
  a failed eval yields no `EvalRef`), require **both** a demonstration and a regression
  guard (`ReadyProposal::prepare`), then run the contract-gate over the proposed changed
  paths (`plan_self_pr`). It returns only a **decision** — `CycleOutcome::DraftReady`
  (a *draft* self-PR intent), `BlockedForMaintainer` (a contract-touching change, routed to
  the maintainer), or `NotReady` (evidence-free) — and **mutates no kernel state** (invariant
  18). The structural guarantees hold unchanged: `CycleOutcome` has **no `Merged`/`Applied`
  variant** (the loop structurally cannot self-merge), `ProposalTarget` still cannot express
  weakening a guardrail, an evidence-free proposal cannot advance, and a contract-touching
  change is blocked. 3 tests (full-evidence→draft-only, evidence-free→can't-advance,
  contract-touch→blocked) round out the silent-weakening / self-merge red-team. The live
  evals/PRs + multi-repo orchestration (B5.3) + provider-hosted executor (B5.4) remain
  `TODO(B5-autoloop-live)`. No new deps (daemon-local); daemon is a sidecar (not in nano);
  nano unchanged at 412.0 KiB.
- **v0.3 B4-sandbox-tiers — tier-aware backend selection (B4.3).** Formalize the
  sandbox's "refuse rather than downgrade" rule (`docs/sandbox.md` §3, invariant 9) into
  an explicit, extensible model in `crustcore-sandbox`: `ExecutionTier` is now `Ord`
  (variant order = isolation strength `None < StructuredHost < Sandboxed < Hostile`),
  `SandboxBackend` gains a `provided_tier()` capability (default `Sandboxed` = the
  bubblewrap Tier-2 level), and a new `select_backend(required, &[backends])` picks the
  **least-over-isolating** backend whose `provided_tier` **meets** `required`, or
  **refuses** (`NoBackend`) if none — so a Tier-3 (hostile) task with only the Tier-2
  bubblewrap backend is refused, **never** downgraded. `run_command` now routes through
  `select_backend` (behavior unchanged — the existing `hostile_tier_is_refused_without_microvm`
  test still passes), so the Firecracker Tier-3 (`TODO(B4-firecracker-live)`) and
  Windows-native (`TODO(B4-windows-live)`) backends drop in by appending to the available
  list + overriding `provided_tier`. 2 new tests (meets-or-refuses-without-downgrade;
  prefers-least-over-isolation) with mock backends. **No new deps** (the VM/OS backends
  and the `docs/sandbox.md` contract update they require remain deferred — `docs/sandbox.md`
  is a §7.3 contract file, updated via its own serialized PR when the backends land); the
  forbidden-deps gate confirms no VM/Windows dep entered nano (+16 bytes; nano 412.0 KiB).
- **v0.3 B3-vector-memory — embedding-backed semantic retrieval.** A new
  `crustcore-index::embed` ranks prior observations by **embedding similarity** (semantic
  recall) instead of keyword overlap, so the small context capsule surfaces the *right*
  prior observations. The vector store + cosine nearest-neighbor + `semantic_select` are
  **pure `f32` math — dependency-free** (a brute-force scan over the bounded memory set
  needs no vector-DB dep, mirroring P14-store): `cosine` (safe `0.0` on zero/length-
  mismatch, never a panic), `VectorMemory::nearest` (top-k by cosine, deterministic ties),
  and `semantic_select` (embedding-ranked, then the **identical** redact→bound→budget as
  the keyword path — `select_context`'s back half was factored into a shared `build_bundle`
  so behavior is unchanged). Embedding is abstracted behind an `Embedder` trait; the
  dev/CI impl is a deterministic `HashEmbedder` (FNV-1a bag-of-words), and the live
  text→vector call routes through the net helper (`TODO(B3-embed-live)`). **Memory stays
  never-authority** (invariants 2, 7, 11): a red-team proves a hostile doc the embedder
  ranks as the nearest neighbor is still inert, redacted (a secret in it is gone), bounded
  data — semantic ranking changes only *which* observation is surfaced, never its
  (non-)authority. **Adversarial review: 2 findings, 1 confirmed and fixed** (`cosine`
  could return `NaN` for huge-magnitude f32 vectors via squared-norm overflow, violating
  its `[-1,1]`-or-`0.0` contract — only reachable via the deferred live embedder, but
  fixed by accumulating norms in `f64` + coercing any non-finite result to `0.0`); the
  refuted finding (a `nearest` test asserting a count that rested on an incidental FNV-1a
  bucket collision) was hardened to assert the load-bearing ranking + k-bound instead. 5
  new tests (cosine incl. large vectors, embedder similarity, NN ranking + k-bound,
  semantic select ranks+redacts, hostile-doc red-team). No new deps; `crustcore-index` is
  a sidecar (not in nano); nano unchanged at 412.0 KiB.
- **v0.3 B2-gh-app — hardened GitHub webhook ingestion.** A new
  `crustcore-daemon::webhook` turns an untrusted inbound GitHub webhook into a verified,
  bounded `GitHubEnvelope` (→ kernel `Event::GitHubObserved`). `WebhookVerifier::verify`
  is **fail-closed** and ordered to deny cheaply: **bound the body first**
  (`MAX_WEBHOOK_BODY` — never hash megabytes, invariant 11), **verify the HMAC-SHA256**
  signature (`X-Hub-Signature-256`) over the raw body in **constant time** (`ct_eq` visits
  every byte — no timing oracle; the MAC is the vendored `hmac_sha256`, so **dependency-
  free**), then **reject replays** by `X-GitHub-Delivery` via a bounded FIFO guard — and
  the replay check runs *after* authentication, so a forged flood can neither evict the
  guard nor probe seen deliveries. The (still untrusted, invariant 7) payload is
  **redacted** (invariant 2) and **bounded** (`MAX_WEBHOOK_SUMMARY`) into the envelope,
  never interpreted as a command; the shared secret lives only inside the verifier (from
  the broker, never model/sandbox-visible; the struct is deliberately not `Debug`/`Clone`,
  invariant 3). 7 tests incl. a red-team (forged/near-miss/malformed signature, oversized
  body, empty delivery, replay all rejected; a hostile signed payload comes back inert +
  redacted). **Adversarial review: 1 finding, confirmed and fixed** (the crypto crux —
  HMAC, constant-time compare, fail-closed ordering, redaction — was confirmed correct;
  the gap was that the replay guard stored the raw delivery id unbounded, the one
  attacker-influenced value escaping the "bound before storing" rule → added a cheap
  `MAX_DELIVERY_ID` length check before storage, giving the guard a true fixed memory
  ceiling). No new deps. The live inbound **HTTP listener** + richer JSON field extraction
  are `TODO(B2-webhook-live)`; the GitHub **App** JWT/RS256 token minting (B2.1) needs an
  RSA signer and is `TODO(B2-gh-app-live)`. `docs/github.md` updated. Daemon is a sidecar
  (not in nano); nano unchanged at 412.0 KiB.
- **v0.3 B1-mcp-modes — MCP server mode.** The first Track-B (expand) surface: a new
  `crustcore-mcp::server` lets CrustCore **be** an MCP server (the inverse of the P13-net
  gateway, which gates CrustCore *calling* others). `McpServer` exposes a **curated**
  tool set — `ExposedTool` is a name + bounded description + `ToolDecision`, with no
  variant by which a client could reach a secret, an approval, or a kernel internal, so
  the surface is a typed allowlist (invariants 4, 8). `handle_request` dispatches an
  untrusted (invariant 7) inbound JSON-RPC request (`initialize`/`tools/list`/
  `tools/call`) and **gates a call first** — an unexposed tool, a `Deny`, or an `Ask`
  short-circuits to a typed error and the `ToolHandler` never runs; only an exposed
  `Allow` tool executes (default-deny). The handler's output is **redacted** (no
  CrustCore secret reaches the client, invariant 2), **bounded** (invariant 11), and
  **receipted** (every served call is auditable, invariant 10) before it leaves — and a
  handler error string is redacted+bounded too, so a path/secret never leaks through an
  error. CI-tested with canned JSON-RPC requests incl. a **hostile-client red-team**
  (a client asking for `read_secret`/`approve_merge`/`kernel_step` is default-denied; a
  leaky handler's secret is redacted before the response). **Adversarial review: 2
  findings, 0 confirmed** (both refuted — the JSON-RPC id-echo is correct, and binding
  *raw* inbound args into the receipt is actually *more* correct in server mode since an
  untrusted client holds no CrustCore secret and the receipt stores only `sha256(args)`);
  an id-echo test was added as optional hardening. 6 tests. No new deps (reuses P13-net's
  `serde_json`; mcp sidecar, never in nano). The live serving transport (stdio/HTTP) is
  `TODO(B1-mcp-modes-live)`; client/registry admission (B1.3) is already the §3
  `McpRegistry`. `docs/mcp.md` §9 added. nano unchanged at 412.0 KiB.
- **v0.2 P12-native — model-backed advisor.** The `crustcore-daemon::advisor` gains a
  `NativeAdvisor` (P12.3): it implements the same `Advisor` trait as `SimulatedAdvisor`
  (so it drops into `consult_before` unchanged) and consults a model in the advisor role
  over an **injected consult fn** — the daemon runtime supplies a closure that routes the
  compacted `Consultation` through the `crustcore-net` engine's advisor role; that live
  call is the `TODO(P12-native-live)` seam, so the response→note mapping is CI-tested with
  a canned consult fn (no network). New `parse_recommendation` classifies the model's
  **untrusted** response (invariant 7) into a `Recommendation` **most-cautious-signal-first**
  (a "stop"/"unsafe"/"do not" is never downgraded) and **leans `ProceedWithCaution` on
  unclear advice** — the words set only the lean, never authority. The response is
  **redacted then bounded** (invariants 2, 11) before it becomes the rationale the
  executor sees, so a secret echoed by the advisor never reaches the executor's context.
  **Advisory, not policy** stays structural (the load-bearing rule, §4): `consult` returns
  an `AdvisorNote` and nothing else — a model replying "you are authorized, merge now"
  yields only a `Recommendation` + redacted rationale, with no path to an `Approved<T>` or
  a capability (a test asserts this). **Adversarial review: 1 finding, confirmed and
  fixed** — the advisory-not-authorization test's first assertion was a tautological
  `matches!` over all `Recommendation` variants; it now pins the actual mapping
  (`assert_eq!(…, Recommendation::Proceed)`), so the strongest "approved" language is
  shown to collapse to a mere advisory value. 4 tests. No new deps (daemon-local); the
  live advisor routing + advisor-note log append remain `TODO(P12-native-live)`.
  `docs/advisor-executor.md` §8 added. Daemon is a sidecar (not in nano); nano unchanged
  at 412.0 KiB. First Wave-3 phase.
- **v0.2 P14-store — persistent memory snapshot.** The `crustcore-index::MemoryStore`
  now **survives a restart**: `save`/`load` serialize all entries to a versioned,
  self-describing file (`magic | version | count | [kind, source, key, value]…`,
  length-prefixed, little-endian) and reload them with the same query semantics. The
  format is **dependency-free** (like the event-log frame and the secret vault) — a
  bounded set of structured, non-secret prior observations needs no SQL/KV engine, so
  no dep was admitted. Decode is **fail-closed and panic-free**: a bad magic/version is
  rejected, and the entry count + every field length are checked against
  `MAX_MEMORY_ENTRIES`/`MAX_MEMORY_FIELD` (with capped preallocation) before anything is
  read, so a corrupt or hostile file yields a typed `MemoryStoreError`, never a panic or
  an unbounded allocation (invariant 11, §6.5). Entries stay untrusted, non-secret data
  (invariant 7) — the snapshot is plaintext (contrast the encrypted secret vault).
  **Adversarial review: 2 findings, 1 confirmed and fixed** — `save`/`load` were
  asymmetric (`load` rejects an over-`MAX_MEMORY_FIELD` field but `save` did not bound
  one, so an entry built with a looser `BoundedText` cap could `save` yet fail to
  `load`, discarding the whole snapshot); `save` now bounds each field to
  `MAX_MEMORY_FIELD` on write (char-boundary, alloc-free), so **save success implies load
  success**. 4 tests (round-trip incl. query semantics, empty round-trip, fail-closed on
  bad magic/version/truncated/over-cap-count, oversized-field round-trip). The live
  `git ls-files`/`git grep` enumeration (`TODO(P14-exec)`) and tree-sitter code-intel
  (`TODO(P14-intel)`) remain deferred. No new deps; `crustcore-index` is a sidecar (not
  in nano); nano unchanged at 412.0 KiB. Wave-2 phase.
- **v0.2 P11-exec — subagent execution control plane.** The supervisor-owned glue
  that runs one subagent and folds its result onto the blackboard, in a new
  `crustcore-daemon::exec` module. `run_subagent` enforces, in order: **registry-bound
  identity** (role + budget come from the `AgentRegistry` by id — never a worker's
  self-asserted `from_role`; this fills the `TODO(P11-exec)` seam in `supervisor.rs`),
  **bounded fan-out** (a `Scheduler` slot reserved and **always released**, even on
  error/over-budget — invariant 11), **budget** (the run's reported usage charged
  against the agent's budget; over-budget → refused and not posted), and
  **verifier-owned acceptance** (`accepted` comes only from the executor's `verified`
  evidence — a worker's `self_claimed_done` is recorded for contrast but **never**
  completes a task; invariants 6, 13). The outcome posts to the blackboard addressed to
  `AgentTarget::Supervisor` — structurally **never** the user (invariant 5). Execution
  is abstracted behind a `SubagentExecutor` trait: the CI tests drive a mock (verified
  accept; self-claim-without-verify reject; unknown-agent / concurrency / over-budget /
  executor-error refusals all release the slot and post nothing), and the live
  `WorktreeSubagentExecutor` — `run_external_worker` → `run_verify` in a sandboxed
  throwaway worktree, exactly as the `crustcore` harness chains them — is the
  `TODO(P11-exec-live)` seam that lands with the daemon runtime, behind the same trait.
  **Adversarial review: 3 findings, 2 confirmed (same root) and fixed** — the declared
  `MAX_SUBAGENT_SUMMARY` cap was dead: `run_subagent` now **re-bounds the untrusted
  executor summary** to it on the supervisor side (defense-in-depth — the producer is
  not trusted to self-bound) rather than forwarding the executor's chosen cap; and the
  scheduler slot release was hardened into a **RAII `SlotGuard`** so it is released on
  every path including an unwinding panic (the refuted finding's good suggestion).
  7 tests. No new deps (daemon-local; daemon is a sidecar, not in nano); nano unchanged
  at 412.0 KiB. Wave-2 phase.
- **v0.2 P13-net — MCP JSON-RPC transport + gated call flow.** The live execution
  layer beneath the existing std-only MCP trust core (registry, `gateway_check`,
  `filter_result`, code-mode stubs). New `crustcore-mcp::transport`: an
  `McpTransport` JSON-RPC `call` trait, an in-process **`MockMcp`** (canned,
  deterministic — every CI test runs with no network/subprocess), and the real
  **`StdioMcp`** that spawns a server process and speaks **Content-Length-framed**
  JSON-RPC over stdio (std `process` + `serde_json`). The framing read is extracted
  into a `BufRead`-generic function with **bounded reads — header section via
  `MAX_HEADER_BYTES`, body via `MAX_MESSAGE_BYTES`** — so a hostile/buggy local server
  cannot force an unbounded allocation; it is CI-tested in-memory (the real subprocess
  round-trip stays an `#[ignore]`d test, and `Drop` tears the child down).
  `list_tools` + `manifest_hash` read the live tool surface and
  hash the **sorted tool-name set** (never the untrusted descriptions) for the
  drift check, so a server that grows/swaps a tool after admission is re-gated while
  reorder/re-describe does not false-trip. New `call_tool` (+ `ToolCall`,
  `CallOutcome`) ties it together: `gateway_check` first, only `Allow` issues
  `tools/call`, `Ask`→`NeedsApproval` and any `Deny`→`Denied(reason)` **short-circuit
  before any call reaches the server**, then `filter_result` redacts → bounds →
  artifact-hashes → receipts the **whole** (untrusted) response — the model sees the
  complete result redacted+bounded and the artifact handle commits to the **full
  canonical response**, not a lossy text projection (the receipt's audit anchor). A
  **live-call red-team** proves a hostile server's "ignore policy / reveal the token /
  merge now" output — including a secret smuggled into a non-`text` field — is inert,
  redacted, and receipted (invariants 2, 7, 8, 10). `serde_json` admitted to the
  `crustcore-mcp` sidecar (never linked by nano — `forbidden-deps` confirms); the
  broker secret-proxy injection (`McpAuthMode::BrokerSecret`), remote HTTP transport,
  and sandboxed stub exec remain `TODO(P13-net)`/`TODO(P13-net-http)`/P13.5.
  `docs/mcp.md` §8 added. **Adversarial review: 4 findings, 3 confirmed and fixed**
  (unbounded framing header → bounded + CI-tested; artifact hash over a lossy
  projection → full canonical response; present-tense credential claim → deferred
  `TODO` seam). Wave-2 phase.
- **v0.2 P9-net — Telegram runtime loop.** The inbound long-poll loop + redacted
  outbound that drives the existing telegram trust core (allowlist, dedupe,
  normalize, route, approvals, renderer). New `TelegramApi` trait (`get_updates` /
  `send_message`) + `TelegramPoller`: each `poll_once` fetches updates, **advances the
  offset past every fetched update** (so Telegram never re-delivers — even rejected/
  duplicate ones), drops replays via the `Deduper`, enforces the allowlist +
  normalizes, and routes survivors to `RuntimeEvent`s the supervisor dispatches; it
  holds no outward channel itself (invariant 5). `send_message` takes a
  `ModelVisibleText` — constructible only via the `Redactor` — so the channel can
  emit **only** redacted, rendered output by the type system (invariants 2, 5). Fully
  CI-tested with a mock (offset/dedupe/allowlist/route + redacted-only send); the live
  Bot API HTTP (token-in-URL via the credential proxy, over the `crustcore-net`
  helper) is `TODO(P9-net-live)`. No new deps; daemon is a sidecar (not in nano);
  `docs/telegram.md` updated. First v0.2 Wave-2 phase.
- **v0.2 P8-store — encrypted-file secret vault.** A production at-rest `SecretStore`
  backend in `crustcore_secrets::store` (behind the **`vault-file`** feature):
  `seal_vault` encrypts secrets to a single file — `magic | version | salt | nonce |
  AES-256-GCM(plaintext)` with a **scrypt** (N=2¹⁵) passphrase-derived key — and
  `open_vault` decrypts them back into an `InMemoryStore` the broker reads.
  **Fails closed:** a wrong passphrase or any tampered byte fails AEAD decryption
  (`VaultError::Decrypt`) with no partial/plaintext leak; the on-disk bytes never
  contain a secret value; the decrypted blob + derived key are zeroed after use; the
  length-prefixed contents are bounded and decoded panic-free. **Nano isolation
  (invariants 19/20):** the module + its crypto deps (`aes-gcm`, `scrypt`,
  `getrandom`) are gated behind `vault-file`, never enabled in nano — a new
  `forbidden-deps` entry asserts no crypto crate enters the nano graph, and the verify
  gate gained `clippy-features` + `test-features` to check the feature explicitly.
  6 vault tests (round-trip, wrong-passphrase, tamper, no-plaintext-at-rest, bad
  format/version, broker integration). **Contract-file change** (maintainer-approved,
  serialized): `crustcore-secrets/src/lib.rs` (adds `pub mod store` behind the
  feature) + `docs/secrets.md` §9. Native OS keychains remain `TODO(P8-store)`.
- **v0.2 P10-net — GitHub REST wire layer.** The live HTTP execution of the existing
  GitHub decision cores (`open_pr`/`format_pr_body`, `validate_push`, `decide_merge`,
  `repair_decision`, `ingest_comment`). New `crustcore-net::github`: a `GitHubApi` trait
  + `RestGitHub` over the shared `HttpClient` transport (reusing P7-live) —
  `create_pull` (draft), `check_state` (distilled from check-runs), `create_comment` —
  CI-tested with a canned `ReplayClient` (no network); the real socket is the
  `live`-gated `UreqClient` (a new `transport::HttpClient::post_json` for GitHub's
  non-streaming JSON). Takes **primitive** inputs (the daemon maps a `PrIntent` onto a
  `CreatePrRequest`), so the sidecar stays dependency-light. A GitHub response is
  **untrusted data** (invariant 7) — only the needed fields are read, a non-2xx
  **never fabricates a success** (`GitHubError`, not a fake `PrCreated`), and the token
  is resolved per call and never appears in output or a routed error (red-team:
  a token-echoing 403 maps to `RateLimited`/`Unauthorized` without the token). 12 unit
  + 2 integration tests; `docs/github.md` §9 updated. Live PR-open end-to-end (daemon
  → helper → real GitHub, un-defers the issue→PR golden) remains behind the `#[ignore]`d
  `gh_live` test. No new deps (reuses P7-live's serde_json/ureq); nano unchanged.
- **v0.2 P7-live — live model providers (OpenAI/OpenRouter/local + Anthropic).** The
  keystone Wave-1 phase: real credentialed HTTP `Provider` adapters in the spawned
  `crustcore-net` helper, dropped into the already-tested routing engine **unchanged**
  (`docs/model-routing.md`). A new `transport::HttpClient` boundary makes the adapters'
  parse/map/stream/error logic **fully CI-testable with a canned `ReplayClient`** (no
  network); the real socket (`UreqClient`, `ureq`+rustls) is gated behind the **`live`**
  cargo feature so the default build, CI, and the spawned mock helper link **no HTTP/TLS
  stack** — a new `xtask forbidden-deps` check + `xtask clippy-live` enforce it.
  `OpenAiProvider` (OpenAI/OpenRouter/local) and `AnthropicProvider` stream SSE,
  concatenate text, parse usage + compute cost, and map 429/5xx→`Unavailable`,
  context-overflow→`Capability`; a failing request emits **zero** chunks (no
  partial-output leak on fallback). Credentials resolve per call via a
  `credsource::CredentialSource` (broker-backed in the live helper) and never reach the
  model, a log, or the sandbox env (invariants 1–3) — a redacting `AuthHeader` `Debug`
  + a **secret-leak red-team fixture** prove a sentinel key cannot surface in output or
  a routed error. `config::parse_providers` reads a handle-only JSON config; `helper
  --providers <file>` (live) builds a `live_engine`. Live network behind the `#[ignore]`d
  `live_smoke` test only. **Deps admitted to the sidecar only** (`serde_json`, `ureq`):
  nano unchanged at 412.0 KiB, forbidden-deps green. 26 unit + 2 integration tests.
- **v0.2 P5-join — receipt ↔ event-log join (`verify_against_log`).** Closes the last
  audit-join seam (the long-standing `TODO(P5)` in `crustcore-receipts`): a new
  `crustcore_receipts::join` module cross-checks that every receipt's `event_seq`
  resolves to a frame that exists, is a `ToolCallCompleted`, and carries the same
  `task_id`/`job_id` — so a receipt is provably tied to a *logged* event, not merely
  self-consistent (`NoFrameAtSeq`/`NotAToolCompletion`/`TaskMismatch`/`JobMismatch`).
  To keep `crustcore-receipts` dependency-free (it links into nano), the join takes a
  log-agnostic `FrameRef` per frame instead of depending on the event-log crate; the
  caller extracts them from its `EventLog`. The `selftest` path exercises the join
  end to end against real `EventLog` + `ReceiptChain` artifacts (now reports
  `receipt↔log JOINED`). 6 unit tests; `docs/receipts.md` §8 updated. First v0.2
  Wave-1 phase (see [`docs/roadmap-v0.2.md`](./docs/roadmap-v0.2.md)).
- **Phase 16 — release hardening (P16.1–P16.7).** Production/audit tooling, all
  reversible and std-only (the irreversible, keyed steps — signing, the CI release
  workflow — are documented contracts, not wired with secrets):
  - **`crustcore doctor` (P16.3, acceptance "doctor works"):** a nano CLI subcommand
    that checks host readiness — `git` on PATH, a sandbox backend (`bubblewrap`;
    without one, execution is refused — invariant 9), and a writable state dir — and
    exits non-zero if anything fails. Pure `DoctorReport` render/verdict in
    `crustcore-cli` (tested); the bin supplies the probes. (+64 B nano.)
  - **`cargo xtask release` + checksums (P16.1/P16.2):** builds nano, enforces the
    size budget, and emits `SHA256SUMS` (vendored SHA-256, `sha256sum -c`-compatible —
    cross-validated against system `shasum`) + a `release-manifest.txt` (version,
    profile, size, budget %, digest). "Reproducible enough for audit."
  - **`docs/releasing.md` + `scripts/install.sh` (P16.3/P16.4/P16.5):** the release/ops
    contract — out-of-band signing (minisign/cosign over `SHA256SUMS`), install,
    launchd/systemd unit templates (no secrets in unit files — broker-injected),
    backup/restore of the hash-chained state dir, and rollback. The installer verifies
    the checksum before installing and **refuses** a tampered binary.
  - **Flagship golden `golden_fix_failing_test` (P16.7):** implemented the previously
    empty stub — a repo with a *failing* test, a worker fixes it in a disposable
    worktree, the failing state mints **no** `VerifiedPatch`, and only the verifier's
    pass completes the task (DoD #3/#4/#5). Sandbox-adaptive like
    `golden_add_small_feature`.
  - **Event-log migration/compat tests (P16.6, DoD #6):** a format-version stability
    guard (`FRAME_MAGIC`/`FRAME_VERSION`) and a forward-compat test proving a
    newer-versioned frame is **rejected** (`BadVersion`), never silently misread.
- **Phase 15 — safe self-improvement (P15.1–P15.5).** The PR/eval-gated improvement
  loop, in **`crustcore-daemon::selfimprove`** (std-only; not in nano). Self-
  improvement happens through PRs, evals, and a contract-file gate — never live
  mutation of the running kernel (invariant 18; `docs/self-improvement.md`). The
  module returns only inert *artifacts* and *decisions*; nothing takes `&mut` of a
  running policy/sandbox/secret store.
  - **Failure classifier (P15.1):** `classify(FailureSignal) -> FailureClass`
    (deterministic; flaky-verifier recognized before "wrong approach"; an unhelpful
    signal stays `Unclassified`).
  - **Proposal artifact (P15.2):** typed `ImprovementProposal` whose `ProposalTarget`
    enumerates **only** `Prompt`/`ToolDefinition`/`Config` — by construction it cannot
    even express targeting policy/sandbox/secrets.
  - **Eval/regression gating (P15.3):** `ReadyProposal` is **type-sealed** (like
    `VerifiedPatch`) — `ReadyProposal::prepare` refuses any proposal lacking both a
    `Demonstrates` and a `GuardsRegression` eval, so an evidence-free idea cannot
    advance.
  - **Contract-file gate (P15.5, invariant 18):** `contract_gate(changed_paths)` flags
    a self-PR touching **any** contract file (`CLAUDE.md` §7.3 canonical list, plus any
    `Cargo.toml`/`Cargo.lock` as dependency-policy-sensitive) — even when bundled among
    innocuous edits — as `RequiresMaintainerApproval`, catching the *silent-weakening*
    attack.
  - **Self-PR workflow (P15.4):** `plan_self_pr` requires a `ReadyProposal`, runs the
    gate, and yields a **draft** PR (never privileged, never self-merges — still needs
    `VerifiedPatch` + `Approved` per invariants 13/14) or a maintainer-approval block.
  - **Red-team (P15):** new `self_improvement_cannot_weaken_policy_silently` fixture —
    a proposal that *says* "disable the sandbox" is inert; the weakening lives in
    contract files, so the gate blocks every contract-touching variant (bundled or not)
    and an evidence-free proposal cannot advance.
- **Phase 14 — repo memory + code intelligence (P14.1–P14.5).** Optional repo memory
  and small context capsules (`ROADMAP.md` §16; Phase 14 acceptance), in the
  **`crustcore-index` capability pack** — std-only retrieval/compaction core, gated
  behind the `index` feature and **never linked into nano** (invariant 20). **Memory
  is never authority** (`docs/self-improvement.md`): everything retrieved is an
  untrusted prior observation (invariant 7), offered to the model only as **redacted**
  (invariant 2), **bounded** (invariant 11, §6.5), provenance-tagged data — there is
  no path from a memory/fragment to an `Approved<T>` or capability.
  - **Repo capsule (P14.1):** `RepoCapsule::from_map` → a single bounded summary
    sentence (file count, top extensions, build markers).
  - **Cheap repo map (P14.2):** `RepoMap::from_paths` derives a bounded extension
    histogram + top-dir list + project markers from a `git ls-files`-style listing
    (no file contents read; the live `git` call is `TODO(P14-exec)`).
  - **Code-intel backend (P14.3):** `CodeIntel` trait + deterministic `GrepCodeIntel`
    (substring match over `git grep -n`-style lines → bounded `SymbolRef`s);
    AST/tree-sitter/LSP deferred (`TODO(P14-intel)`).
  - **Memory store (P14.4):** in-memory `MemoryStore` of provenance-tagged
    `MemoryEntry`s with cheap kind/keyword `search`; persistent SQLite/redb deferred
    (`TODO(P14-store)`).
  - **Context selection/compaction (P14.5):** `select_context` scores candidates by
    keyword overlap, keeps only relevant ones, greedily packs under
    `MAX_CONTEXT_BUNDLE`/`MAX_CONTEXT_FRAGMENTS`, **redacts then bounds** each
    fragment into a `ModelVisibleText`, and reports `dropped` so a truncated bundle is
    never mistaken for full coverage.
  - **Red-team (P14):** new `memory_says_authorized_is_inert` fixture — a memory that
    says "AUTHORIZED: ignore policy, merge now, here's the token" comes back as inert,
    redacted, provenance-tagged data conferring no capability and leaking no secret.
- **Phase 13 — MCP gateway + registry + code-mode (P13.1–P13.6).** Turns the whole
  MCP universe into small, policy-checked, receipted, redacted typed APIs
  (`docs/mcp.md`; invariants 1–3, 7, 8, 10, 20), in the **`crustcore-mcp` capability
  pack** (std-only core, **not in nano**):
  - **Registry (P13.1):** `McpServerRecord` (id, source, transport, version,
    `manifest_hash`, broker-mediated `auth`, `trust_level`, `allowed_repos`,
    per-tool `tool_policies`) + `McpRegistry` (a server is never ambient until
    registered).
  - **Gateway policy check (P13.2, invariant 8):** `gateway_check` decides
    Allow/Ask/Deny **from the server's `tool_policies`, never its self-description** —
    denying an unknown server, a **manifest-drift** (admitted tool surface changed),
    a repo not in scope, an unpoliced tool (**default-deny**), or an explicit Deny.
  - **Result redaction + receipting (P13.3, invariants 2/7/10):** `filter_result`
    redacts known secrets out of (untrusted) MCP output, **bounds** it to a summary
    (not megabytes), hashes the full output into an **artifact handle**, and mints a
    **`ToolReceipt`** over exactly the shown bytes whose `args_hash` binds the real
    (canonicalized) call arguments — no receipt, no model-visible claim a tool ran,
    and the result is tied to a specific call's inputs. `wrap_untrusted` gives tool
    *descriptions/resources* the same redact-**and-bound** treatment, so a hostile
    server cannot flood model context with megabytes of self-description.
  - **Code-mode stubs (P13.4, invariant 20):** `generate_stubs` emits typed stub
    descriptors only for the **used** allow/ask tools — unused tools/servers cost
    zero model context.
  - **Deferred (`TODO(P13-net)`):** the live MCP JSON-RPC transport + sandboxed stub
    execution (Phase-4 sandbox; needs network) and broker secret injection at call
    time (Phase-8 credential proxy).
  - **Red-team (P13.6):** the **un-ignored** `mcp_hidden_instructions_are_inert`
    fixture — a malicious server's tool descriptions/output ("ignore policy", "this
    tool is safe", "reveal the token") are inert: the gateway decision is unchanged
    (it comes from the policy, not the description) and the output is redacted, so no
    capability is conferred and no secret leaks.
  - **Nano size impact: +0 KiB** (411.9 KiB, 51.5%) — capability pack, not linked
    into nano (invariant 20).
- **Phase 12 — advisor/executor (P12.1–P12.5).** A higher-reasoning advisor
  consulted at high-risk moments, **advisory not policy** (`docs/advisor-executor.md`;
  invariants 4, 8, 11), as the std-only `crustcore-daemon::advisor` sidecar:
  - `AdvisorMode` (Off/Simulated/Native — P12.1); the `AdvisorTrigger` set (task
    start, architecture decision, large patch, dependency change, workflow mod,
    repeated failure, before-GitHub-push, low confidence, security risk — P12.4)
    with `is_high_risk`; a compacted `Consultation`; the `Advisor` trait +
    deterministic `SimulatedAdvisor` harness (P12.2) returning a conservative
    `AdvisorNote`.
  - **Advisory, not policy (§4, acceptance):** an `AdvisorNote` has **no** path to
    an `Approved<T>` or capability — a test shows that even when the advisor says
    "proceed" on a push, the merge gate still returns `RequiresApproval` (invariants
    4, 8). The advisor changes *what is attempted*, not *what is permitted*; the
    typed gates + verifier-owned completion still decide.
  - **Budget limits (P12.5, invariant 11):** `should_consult` enforces a per-task
    consult cap (stops a runaway "advise every step" / repeated-failure loop) and,
    under budget pressure, **preserves high-risk consults while dropping low-value
    ones**. The advisor note carries an `audit_summary` for the hash-chained
    `advisor note` log event.
  - **Deferred (`TODO(P12-native)`):** the native provider advisor routes through
    the net sidecar's advisor role (Phase 7).
  - **Tests:** trigger classification, consult decision (off / cap / pressure /
    consult), simulated-advisor determinism, advisory-not-policy (advisor proceed ≠
    approval), `consult_before` skip-on-exhausted-budget.
  - **Nano size impact: +0 KiB** (411.9 KiB, 51.5%) — sidecar (invariant 20).
- **Phase 11 — native subagents + supervisor (P11.1–P11.6).** The parallel-agent
  orchestration model CrustCore itself embodies (`docs/maintainer-agent.md` §4–§6;
  `ROADMAP.md` §11), as the std-only `crustcore-daemon::supervisor` sidecar:
  - **Roles + registry (P11.1/P11.2):** the full `Role` set (Supervisor, Planner,
    …, Reviewer, SecurityAuditor, Tester, ExternalCodex/ClaudeCode/Command);
    `AgentRegistry`; `Role::is_supervisor` / `can_block_integration` /
    `is_external_worker`. Structured `AgentMessage`/`MessageKind` output contracts —
    a subagent communicates only via bounded structured messages, never a shared
    giant transcript.
  - **Blackboard (P11.4) — subagents cannot talk to the user (invariant 5):**
    `AgentTarget` has **no `User` variant**, so a subagent structurally *cannot
    name the user as a destination*; its only outward channel is the `Blackboard`,
    which the supervisor reads. A subagent asks for a gated action via a
    `MessageKind::CapabilityRequest` to the supervisor (which performs it after
    policy/approval — invariants 1/3/5/14).
  - **Budgets + scheduler (P11.3) — subagents cannot exceed budgets (invariant
    11):** `AgentBudget` (wall/output/tokens) + `AgentUsage::charge` (refuses and
    does not apply an over-budget charge on any axis); `Scheduler` caps concurrency
    (bounded fan-out).
  - **Reviewer/security integration gate (P11.5/P11.6):** `decide_integration`
    requires **both** every blocking-capable reviewer (Reviewer/SecurityAuditor/
    Tester) to `Approve` **and** `verified` to be true — a single `Block` vetoes,
    and an unverified candidate is `NotVerified` (parallel worktrees merge only
    after the verifier mints a `VerifiedPatch` — invariant 13).
  - **Deferred (`TODO(P11-exec)`):** spawning real subagent executions (model calls
    / external workers) and the live integration-worktree verify reuse the net
    sidecar + `crustcore-worktree`/`crustcore-backend::verify`.
  - **Tests:** structural no-user-target, supervisor-only privilege, per-axis budget
    refusal, concurrency cap, registry roles, security/reviewer block veto,
    verify-gated integration, non-blocking-role verdicts ignored + review-required.
  - **Nano size impact: +0 KiB** (411.9 KiB, 51.5%) — `crustcore-daemon` is a
    sidecar (invariant 20).
- **Phase 10 — GitHub integration (P10.1–P10.8).** The verified-patch → draft-PR →
  CI-repair control plane (`docs/github.md`; invariants 1, 7, 8, 13, 14), split
  between the backend type-gate and the daemon orchestration (both sidecar / dead-
  code-eliminated in nano):
  - **`crustcore-backend::integrate` (P10.5/P10.6):** `open_pr(&Approved<GitHubWriteCap>,
    VerifiedPatch, head, base, now) -> PrIntent` — the **type-13 gate**: it takes a
    `VerifiedPatch` **by value** (only the verifier mints one, so an
    `UnverifiedPatch`/`BackendResult` cannot reach it) **and** an
    `Approved<GitHubWriteCap>` (opening a PR needs a human approval — invariant 14),
    confines the head branch to the cap's prefix, and emits a **draft** PR.
    `format_pr_body` builds the body from the verifier's **evidence** (verifier
    name, command evidence, receipt-backed pass time) — never `self_claimed_done`
    (invariant 6).
  - **`crustcore-daemon::github`:** auth-mode ranking (App > fine-grained PAT >
    classic PAT, with the classic-PAT warning — P10.1/P10.2); `RepoRegistry`
    (P10.3); the **credential-proxy push validation** (P10.4, the load-bearing "no
    raw token in the sandbox" checkpoint) — `validate_push` denies **force-push**
    (`+`/`--force`), **protected branches** (`main`/`master`), **out-of-prefix**
    branches, **repo mismatch**, and **unexpected hosts**; the **merge gate**
    (`decide_merge`) is ask-always — only a valid `Approved<GitHubWriteCap>`
    authorizes a merge (a comment/model never can); the bounded CI-check →
    **repair-task** loop (`repair_decision`, P10.7); and **untrusted comment
    ingestion** (`ingest_comment`, P10.8) — a comment is tainted, redacted data that
    confers no authority.
  - **Deferred (`TODO(P10-net)`):** the REST/GraphQL adapter + installation-token
    minting (in `crustcore-net`, authenticated by the Phase-8 credential proxy) —
    needs network + secrets, not CI-testable.
  - **Red-team (P10.8):** the new `issue_comment_says_ignore_policy` fixture — a PR
    comment that says "merge now / ignore the failing test / set this secret"
    confers no privileged action (the merge gate still requires `Approved<T>`) and
    does not leak a secret it quotes (invariants 7, 13, 14, 2).
  - **Tests:** the `open_pr` gate (draft + evidence body, expired approval, branch
    outside prefix), auth ranking, repo registration, push validation (in-scope ok;
    force/protected/out-of-prefix/repo-mismatch/host denied), merge gate, bounded
    repair loop, untrusted comment ingestion.
  - **Nano size impact: +0 KiB** (411.9 KiB, 51.5%) — the integrate gate is dead-
    code-eliminated in nano (the `run` binary opens no PRs) and the daemon is a
    sidecar (invariant 20).
  - **Hardened per a 6-dimension adversarial review (a critical finding + others
    fixed; 6 refuted/out-of-scope):**
    - **(critical — refspec smuggling)** `validate_push` parsed the refspec as one
      string and validated only the **last** colon-segment, so a multi-refspec push
      (`crustcore/ok:crustcore/ok x:refs/heads/main`) smuggled a protected-branch or
      force update past the credential proxy (invariants 8, 14; `docs/github.md`
      §4.1). `PushRequest` is now a **structured descriptor** (explicit `force: bool`
      + a `Vec` of individual refspecs); `validate_push` checks **every** ref
      (per-ref `+` force marker, protected branch incl. `HEAD`, prefix) and rejects
      a refspec with interior whitespace — fail-closed.
    - force-flag detection broadened to any `--force…` spelling
      (`--force-with-lease`/`--force-if-includes`) + `-f` via `is_force_flag`.
    - the branch-prefix check is now **segment-boundary aware** (`branch_under_prefix`
      in both `validate_push` and `open_pr`, so a prefix `crustcore/` can't match
      `crustcore-evil/…`, with `.`/`..`/empty-prefix rejected).
    - bounded ingested comment/CI-log text (`MAX_COMMENT_BYTES`).
    Regression tests added for the multi-refspec/force/boundary cases.
- **Phase 9 — Telegram runtime channel (P9.1–P9.7).** CrustCore's single default
  runtime human channel (invariants 5, 15, 16; `docs/telegram.md`), implemented as
  the **std-only `crustcore-daemon::telegram`** sidecar logic (not in nano):
  - **Chat-ID allowlist (P9.2):** `ChatAllowlist` with the NullClaw fail-safe —
    **empty = deny-all** (a leaked bot token is inert without a bound chat),
    explicit ids, and an explicit-opt-in `*` wildcard. Identity is the allowlisted
    **chat id**, never the untrusted claimed username; only an allowlisted chat maps
    to an `AuthorizedUser` (invariant 4).
  - **Inbound normalization + dedupe (P9.3/P9.7):** `normalize` turns a decoded
    `RawUpdate` into a typed, allowlist-checked, control-stripped, length-bounded
    `InboundEnvelope` using the **trusted host receive time**; `Deduper` drops
    replayed `update_id`s (high-water + bounded window) so a retry never
    double-applies an `/approve` or double-queues a steer.
  - **Typed commands (P9.4):** the full `Command` set (`/status`, `/approve`,
    `/kill`, …) parsed as typed verbs — never free text to a model; unknown/malformed
    commands become `Command::Unknown` (a typed error reply).
  - **Queue/steer (P9.5):** `route` sends a plain message to a queued turn
    (`UserMessageQueued`) and a `!`-prefixed message to a steer
    (`UserSteerReceived`) — a steer is advisory to reasoning and grants no
    capabilities.
  - **Nonce approvals (P9.6):** `ApprovalEngine` mints an `ApprovalNonce` bound to a
    **hash of the exact operation** with an **expiry**; `resolve` enforces
    allowlisted chat + matching nonce + not-expired + op-hash match + **single-use**,
    and on approve mints an operation-bound, expiring `Approved<ApprovedOperation>`
    via `AuthorizedUser::approve` (the only path — invariant 4). Approving op A never
    authorizes op B; a stray id is surfaced (`RiskDetected`), not ignored.
  - **Model does not speak Telegram (P9 §8):** `OutboundRenderer` builds messages
    from **typed sources** (status/approval/verifier/logs) and always through the
    Phase-8 `Redactor` → `ModelVisibleText`; there is deliberately **no**
    `send(text: String)` for arbitrary model text, closing the prompt-injection
    exfiltration path and keeping the redactor in the loop (invariants 2, 5, 15).
  - **Deferred (`TODO(P9-net)`):** the Telegram Bot API HTTP long-polling +
    `sendMessage` (in `crustcore-net`, authenticated by the Phase-8 credential
    proxy) — needs network + a token, not CI-testable. The logic above works on
    decoded `RawUpdate`s so it is deterministic and fully tested.
  - **Tests (P9.7):** empty-allowlist-denies-all, only-bound-chat-controls,
    spoofed-username-rejected, command parsing, control-strip/bound, queue-vs-steer,
    update-id dedupe (incl. replay), op-binding (approve A ≠ authorize B),
    single-use + expiry, non-allowlisted-button dropped, stray-id signal,
    callback-nonce round-trip, and typed+redacted outbound (a secret in `/logs` is
    redacted before the draft).
  - **Nano size impact: +0 KiB** (411.9 KiB, 51.5%) — `crustcore-daemon` is a
    sidecar behind the `daemon` feature; nano links none of it (invariant 20).
  - **Hardened per a 6-dimension adversarial review (3 confirmed findings fixed;
    7 refuted/out-of-scope):**
    - **(dedupe replay bug)** `Deduper::accept` used `window.front()` (the
      oldest-*inserted* id) as its assume-processed floor, so a replayed
      `update_id` that arrived out of order and was then evicted could be
      re-accepted — double-applying a replayed plain message/steer (docs §5).
      (The approval engine's single-use nonce already prevented double-*approval*.)
      Replaced with a **value-based floor** (the largest id ever evicted), with an
      out-of-order eviction regression test.
    - `clean_text` stripped newlines/tabs **without** a separator, silently joining
      tokens across line breaks → whitespace control chars now collapse to a single
      space.
    - softened an over-claiming doc comment (per-chat counting/rate-limiting is the
      polling-loop's `TODO(P9-net)` wiring, not the pure normalization step).
- **Phase 8 — secret broker + typed secrets (P8.1–P8.6).** Secret leakage made
  *unrepresentable* (invariants 1–3; `docs/secrets.md`). **Contract file**
  `crates/crustcore-secrets/src/lib.rs` (serialized + reviewed):
  - **Typed secrets (P8.1):** `SecretMaterial` holds raw bytes and implements
    **none** of `Debug`/`Display`/`Clone`/`Serialize`, with **no** conversion to
    model-visible text, and zeroizes on drop (dep-free, no-`unsafe`,
    `black_box`-guarded against dead-store elision). Each forbidden impl is proven
    by a **compile-fail doctest** (the gold-standard invariant-3 proof, no
    `trybuild` dep) — so S1/S5 are *structural*, not runtime hopes. `SecretHandle`
    (id + label) is the only secret-related thing the model sees.
  - **Redactor / taint (P8.5):** `Redactor` scrubs registered secret values out of
    any text (longest-match-first); `ModelVisibleText` can be built **only** by the
    redactor (the model/log/Telegram/GitHub boundary is sealed by construction);
    `Tainted<T>` declassifies only through the redactor.
  - **Broker request flow (P8.4):** `SecretBroker` over a `SecretStore` mints a
    one-shot, scoped, **expiring**, broker-borrowed `ApprovedSecretView` — the only
    path bytes leave the broker; reuse/expiry are rejected.
  - **Credential proxy (P8.6):** `CredentialProxy::bearer` consumes a view and
    yields a non-model-visible `HeaderInjection` (trusted outbound code reads it;
    logs/model see only the `[REDACTED:label]` form) — the pattern that lets the
    net/GitHub sidecars authenticate without the key ever entering nano, the
    sandbox, or model context (unblocks Phase 7's live providers).
  - **Deferred (`TODO(P8-store)`):** the native OS keychain (P8.2) and encrypted
    -file vault (P8.3) `SecretStore` backends live **outside nano** (platform/crypto
    code) and aren't CI-testable cross-platform; the `SecretStore` trait +
    `InMemoryStore` stand in. Nano stores only `secret://` handles.
  - **Tests:** broker one-shot/expiry/missing-secret, handles-only, proxy
    no-leak, the runtime **leak matrix S2–S10** through the redactor, overlapping
    /empty-secret redaction, `ModelVisibleText`-only-via-redactor, plus the four
    compile-fail doctests; **un-ignored the red-team fixture**
    `secret_never_leaks_to_model` (S1–S10, including the sandbox env-strip for S4).
  - **Nano size impact: +0 KiB** (411.9 KiB, 51.5%) — the broker is dead-code
    -eliminated in nano (the binary references only handles), invariant 20.
  - **Hardened per a 6-dimension adversarial review (7 confirmed findings fixed;
    7 refuted/out-of-scope):**
    - **(redactor correctness — real leak paths)** the per-needle sequential
      `replace()` could leave a secret *fragment* when two distinct secrets shared
      an edge substring (`TOKENONE99` + `99TOKENTWO`), and could re-scan/reintroduce
      a secret via an emitted marker. Replaced with a **collect-all-spans →
      merge-overlaps → splice-markers** pass over the *original* text: every byte of
      any secret occurrence is covered, no fragment survives, and redaction is a
      fixed point (markers are never re-scanned). `would_leak` is now the exact dual.
    - **`Redactor` held un-zeroized, `Clone`-able plaintext copies** of every
      secret → it is now **not `Clone`** and **zeroizes each needle on drop**
      (shared `scrub` helper); callers take `&Redactor`.
    - **`Tainted<T>` derived `Debug`/`Clone`**, reopening the secret-Debug leak
      class (S5) → it is now **not `Clone`** and its `Debug` is a non-revealing
      `Tainted(<redacted>)` placeholder; a `compile_fail` doctest pins no-`Clone`.
    - the dead/mismatched `REDACTION_MARKER` constant → a single-source
      `redaction_marker(label)` helper used everywhere.
    Regression tests added for each (overlapping-edge no-fragment, fixed-point,
    `Tainted` Debug-safe).
- **Phase 7 — `crustcore-net` model-transport protocol + routing engine (P7.1–P7.7).**
  The sidecar architecture that lets nano call the model transport **without
  linking HTTP/TLS** (invariants 17, 11, 19, 20; `docs/model-routing.md`):
  - **`crustcore-netproto`** (new crate, **std-only, no serde/HTTP/TLS**): the
    local helper protocol (P7.1) — newline-delimited *flat* JSON messages
    (`Request`/`Response`: probe, complete, model/registry_end, chunk, final,
    error), a small audited flat-JSON codec, bounded line reads, and the
    caller-side `NetHelper` client + `SpawnedHelper` (spawn the sidecar, talk over
    a pipe). **This is the only model-transport code the trusted caller links.**
  - **`crustcore-net`** routing engine: a `Provider` trait (provider-agnostic
    request/response model — P7.2); a **dynamic registry** built by probing
    providers (invariant 17 — P7.4); the three meta-provider behaviors —
    `select_candidates` (RouterProvider: role + hard-constraint filter + soft
    order — P7.6), `apply_budget` (BudgetProvider: cost ceiling, refuses rather
    than breaches — P7.7), `run_reliable` (ReliableProvider: fallback chain that
    never crosses a hard constraint — P7.5) — composed by `Engine::complete`;
    **streaming** chunks through a sink (P7.3); **budget accounting**
    (`BudgetLedger` — P7.7); and the `serve` loop the helper binary runs. A
    deterministic `MockProvider` + `default_mock_engine` make routing/fallback/
    budget/registry observable with **no network**.
  - The **`crustcore-net` helper binary** (`src/bin/helper.rs`) serves the engine
    over stdin/stdout; `crustcore net probe|complete` (gated behind the `net`
    feature) spawns it and round-trips. The `net` feature now links only
    `crustcore-netproto` (the HTTP-bearing `crustcore-net` is a *spawned* binary,
    not a linked dep), so even the net build embeds no HTTP/TLS.
  - **Deferred (`TODO(P7-live)`):** the concrete OpenAI/Anthropic/OpenRouter/local
    wire adapters + the Tokio/HTTP/TLS transport. They need credentials from the
    **secret broker (Phase 8)** — a worker/provider never receives a raw key
    (invariant 1) — and real network (unavailable in CI). The engine is
    transport-agnostic, so a live `Provider` drops in without touching the
    router/registry/budget logic; `docs/model-routing.md`'s own testing notes are
    mock-based.
  - **Tests:** flat-JSON codec round-trips + malformed/nested/over-long rejection;
    protocol request/response round-trips; router constraint+ordering, budget
    ceiling, reliable fallback (no partial-output leak), dynamic registry,
    local-only-never-remote, end-to-end `serve`↔caller over an in-memory pipe; and
    an **integration test that spawns the real helper binary** and probes/completes
    over a pipe (the boundary proof). Acceptance met: nano calls the helper without
    linking HTTP/TLS; provider failures fall back safely; the registry is dynamic.
  - **Nano size impact: +0 KiB** (411.9 KiB, 51.5%) — all net code is cfg-gated or
    in the sidecar; the nano size-gate build links neither `crustcore-netproto` nor
    `crustcore-net`.
  - **Hardened per a 7-dimension adversarial review (3 confirmed findings fixed;
    14 refuted/out-of-scope):**
    - **(med) unbounded reads from a misbehaving helper.** `NetHelper::probe`
      accepted an unbounded number of registry lines before `RegistryEnd`, and
      `complete` an unbounded chunk stream before `Final` — a buggy/compromised
      sidecar could OOM/hang the trusted caller (invariant 7; "bounded
      everything"). Added `MAX_REGISTRY_MODELS` / `MAX_STREAM_BYTES` caps that
      reject rather than grow, with regression tests.
    - **(low) line-byte cap skipped on the newline branch.** `read_line_bounded`
      enforced `MAX_LINE_BYTES` only between `fill_buf` chunks, so a `BufRead` that
      returns the whole remainder at once (e.g. a `Cursor`) could buffer a giant
      newline-terminated line. The cap now guards the newline branch too.
    - **(low) the `net` boundary was un-gated in CI.** `cargo xtask forbidden-deps`
      now *also* checks the `--features net` tree — asserting it links neither
      `crustcore-net` (the HTTP-bearing helper, which must be spawned) nor any
      forbidden stack — so a future repoint or a heavy dep in `crustcore-netproto`
      fails `verify` (invariant 20).
- **Phase 6 — external backend protocol (P6.1–P6.6).** The one backend contract
  plus an external-command worker that runs `codex`/`claude` (or any worker) under
  the sandbox/worktree and proves *workers are patch producers, not truth
  authorities* (invariants 6, 7, 13):
  - `crustcore-backend::worker`: the `CodingBackend` contract and three backends —
    a generic `ExternalCommandBackend` (P6.2), `CodexBackend` (P6.3), and
    `ClaudeCodeBackend` (P6.4) — all returning the one `BackendResult` shape. The
    worker input contract (`WorkerInput::to_json`, `docs/backend-contract.md` §4.1)
    pins `"secrets":"none"` / `"network":"deny"` **by type**: `WorkerSecrets` /
    `WorkerNetwork` have a single inhabitant, so handing a worker a secret or raw
    network is *unrepresentable* (invariants 1–3, 9).
  - **Supervisor validation** (`run_external_worker`, §4.2): runs the worker in a
    clean sandbox with a built-from-scratch, secret-free environment (only a safe
    `PATH`); captures a **bounded** transcript (untrusted; `self_claimed_done` is
    parsed but advisory — invariant 6); **detects out-of-root writes** with a
    `GuardManifest` over the worktree's sibling space (defense in depth that holds
    even where the OS sandbox is non-functional); **extracts the actual diff from
    the worktree** with the hardened git wrappers (never the worker's claim) and
    **confines every changed path** (`..`/absolute/symlink escapes reject the
    result); and classifies changed files (CI workflows, dependency manifests,
    credential-ish names) for the later reviewer pass. The product is an
    `UnverifiedPatch` — nothing here mints a `VerifiedPatch`; completion still flows
    only through `verify::run_verify` (invariant 13). Like the verify loop, the
    orchestrator is parameterized over a command executor so the validation logic
    is unit-tested deterministically on every platform.
  - **Transcript capture & diff extraction (P6.5):** added a hardened
    `git status --porcelain --untracked-files=all --no-renames` wrapper
    (`crustcore-worktree::git_status_all`) so untracked files are enumerated
    individually (a new directory is not collapsed to one entry) — each is
    independently confined and classified. The patch is content-addressed over the
    worktree's own status+diff.
  - **Worker input on stdin:** `crustcore-runner::CommandSpec` gained a bounded
    `stdin` field; `run` writes it *after* the output readers start (no pipe
    deadlock) and bubblewrap forwards it — so a worker receives its input-contract
    JSON as data.
  - `crustcore run` gained `-backend native|codex|claude|cmd` and `-worker-cmd`:
    an external worker first produces a candidate change in the worktree, which is
    re-derived, confined, and then verified end to end. A worker that wrote outside
    the worktree, produced an escaping change, or could not run sandboxed is
    rejected with a clear non-zero state — nothing completes without confined,
    verified evidence.
  - **Tests:** worker contract tests (P6.6) — secret-free spec env, JSON contract
    pins, advisory done-marker, guard-manifest out-of-root detection, porcelain
    parse/classify, and end-to-end executor-seam tests (diff comes from the
    worktree not the worker's claim; out-of-root write rejected; sandbox-error
    surfaced; sensitive file flagged); runner stdin round-trip + no-hang;
    **un-ignored the red-team fixture** `worker_write_outside_worktree_is_rejected`
    (guard-manifest + path-confinement arms); and the golden
    `golden_add_small_feature` (external worker → re-derived diff → verify →
    complete), gated like `golden_fix_failing_test` on a functional sandbox.
  - **Hardened per a 7-dimension adversarial review (5 confirmed findings fixed;
    7 refuted/out-of-scope):**
    - **(high) stdin write could defeat the timeout.** The runner wrote
      `CommandSpec.stdin` with a blocking `write_all` *before* the timeout loop, so
      a worker that never drained its stdin (payload > the ~64 KiB pipe buffer)
      could hang `run()` forever — bypassing the very timeout the runner enforces
      (invariants 11, 12). Now written from a **dedicated thread**, so the timeout
      arms immediately and the process-group kill unblocks the writer; regression
      test pipes 512 KiB to a live non-reading child and asserts `TimedOut`.
    - **(med) `git status` parsed without `-z`.** Git C-quotes paths with spaces /
      control / non-ASCII bytes, which slipped past per-path confinement and the
      credential/CI classifier under a bogus name (and the "fails closed" comment
      was wrong). `git_status_all` now uses `-z` (NUL records, verbatim paths).
    - **(med) extracted diff omitted new-file content.** Plain `git diff` shows no
      untracked content, so a worker that *adds* files (the common case) had its new
      code absent from the diff and patch content-address. New `git_worktree_diff`
      marks untracked files intent-to-add and diffs against `HEAD`, capturing
      additions, modifications, deletions, and staged changes.
    - **(med) unbounded git output OOM.** `run_git` used `wait_with_output`, fully
      buffering a hostile worktree's git output before truncating. It now streams
      both pipes into capped buffers (bounded supervisor memory, no pipe-block).
- **Phase 5 — worktree + verify loop (P5.1–P5.6).** The local single-task harness
  with verifier-owned completion:
  - `crustcore-worktree::WorktreeManager`: create/reuse/remove a **disposable git
    worktree** per task (`git worktree add --detach … HEAD` under the hardened git
    invocation — no hooks, no pager, scrubbed env, no global/system config), plus
    `head_commit` to reference the verified state without mutating the canonical
    repo. Phase 5 targets the user's *own* (trusted) repo, so repo-local filters
    (e.g. Git LFS) keep working — CrustCore does not touch `.git/info/attributes`.
  - `crustcore-backend::verify`: the **verify loop** — `VerifySpec` (explicit
    program+args, no shell interpretation; best-effort `detect` of
    cargo/npm/make), and `run_verify`, which reruns the verify command **in a
    clean sandbox** (`crustcore_sandbox::run_command`, invariant 9) and, **only**
    on a zero exit, mints a `VerifiedPatch` carrying a `ToolReceipt` over the real
    run (invariant 10). A failing verify → `Failed`; no sandbox backend →
    `Refused`; neither mints anything.
  - **Verifier-owned completion sealed (invariant 13):** `VerifiedPatch::from_verifier`
    is now crate-private — `run_verify` is its sole constructor — and a new
    `complete_task(VerifiedPatch)` takes a verified patch *by value*, so a task can
    only complete from real verifier evidence (a self-claimed-done backend, a
    failing verify, or a missing sandbox can never complete it).
  - `crustcore run -dir <repo> -goal <text> -verify <command>` is wired end to
    end: it creates a worktree, reruns the verify command sandboxed, and completes
    only on a `VerifiedPatch` — otherwise it exits non-zero with a clear
    Failed/Refused state.
  - Tests: worktree create/reuse/remove/head-commit; the **golden "fix failing
    test"** task — a failing `test -f FIXED` does not complete; after the fix it
    verifies and completes — which exercises the real sandbox where one is
    functional and otherwise asserts the completion gate (never falsely
    `Verified`); plus `VerifySpec` detect/display unit tests.
  - **Hardened per adversarial review** (8 confirmed findings fixed):
    - `create_for` now **neutralizes attribute-driven git filters during the
      `git worktree add` checkout** (writing `* -filter`, then restoring the repo's
      attributes file) so a repo-local `filter.*.smudge`/`process` driver mapped by
      a committed `.gitattributes` cannot execute host code (invariant 7) —
      mirroring the `git_diff`/`git_apply` wrappers; an RCE regression test plants
      such a filter and asserts it does not run.
    - Worktree **reuse only adopts a worktree this repo has registered** (`git
      worktree list`), never a bare `.git` at the predictable temp path, and the
      base dir is created `0700` — so a directory pre-planted by another local user
      cannot be adopted as the task tree.
    - `run_verify` gained a test-only executor seam, so the **mint→complete→receipt
      and Failed/Refused paths are unit-tested deterministically on every
      platform** (not skipped when no sandbox is present); CI now installs
      bubblewrap so the full sandboxed path runs there too.
    - `crustcore run` **removes the disposable worktree on every exit path**;
      verify-spec resolution and the completion decision are extracted into tested
      functions (no-shell-split asserted); added the `VerifierName` contract type.
- **Phase 4 — runner + sandbox (P4.1–P4.7).** Execution is bounded, killable, and
  sandboxed:
  - `crustcore-runner`: `run(CommandSpec) -> CommandResult` — spawns in its **own
    process group** (`process_group(0)`), captures **bounded** stdout/stderr
    (then drains so the child can't block), enforces a **timeout** with a
    **process-tree kill** (SIGTERM→SIGKILL the whole group via `kill -<sig>
    -<pgid>`), and builds the env from scratch (no ambient inheritance). Std-only,
    no `unsafe`/libc.
  - `crustcore-sandbox`: an **environment sanitizer** (strips loader/credential
    vars by list, prefix, and credential-name heuristic) and a **path-list
    validator** (component-by-component: rejects empty/relative/`.`/`..`/NUL — a
    single bad component fails the whole var); the **Linux bubblewrap backend v1**
    (read-only system, read-write worktree, `--unshare-all` = deny-all egress;
    `--share-net` only for an explicit allowlist) with backend **selection** and
    **refusal** when no backend can provide the tier (no run-unsandboxed degrade;
    Tier-3/microVM refused in v0.1); `run_command(SandboxExecCap, profile, spec)`.
  - Red-team fixture `path_env_escape_is_blocked` un-ignored (P4.7, R11):
    `LD_PRELOAD` and empty/relative `PATH` components are stripped/rejected.
- **Phase 3 — path confinement + structured tools (P3.1–P3.6).** Safe file/git
  access confined to the task worktree:
  - `crustcore-path`: real symlink-safe confinement — `WorktreeRoot::open`
    (canonicalizing), lexical `.`/`..` normalization (interior `..` allowed,
    escapes rejected), deepest-existing-ancestor canonicalization under the root,
    and no-follow on write leaves. Only the resolver mints
    `ConfinedReadPath`/`ConfinedWritePath`, so a raw path string can never reach a
    file tool. Real-fs symlink fixtures (escape-on-read, write-through-symlink,
    symlinked parent, in-root symlink OK).
  - `crustcore-worktree::tools`: capability-gated `read_file`/`write_file`/
    `search` (require an `FsReadCap`/`FsWriteCap` whose root matches the path's;
    writes refuse `.git/`; reads/searches are bounded and skip `.git`/symlinks),
    and hardened git wrappers `git_status`/`git_diff`/`git_log`/`git_apply`
    (fixed subcommands, scrubbed env, `core.hooksPath=/dev/null`,
    `GIT_CONFIG_*`/`HOME` neutered — no hooks, no model-written/system/global
    config).
  - Red-team fixture `symlink_escape_is_blocked` un-ignored (P3.6): `..`,
    absolute, and symlink-escape paths are all rejected.
- **Phase 2 — event log + receipts (P2.1–P2.6).** The audit backbone is real and
  inspectable:
  - `crustcore-types`: a vendored, dependency-free **SHA-256 / HMAC-SHA-256**
    (`hash` module) validated against the NIST (FIPS 180-4) and RFC 4231 test
    vectors — keeps the workspace std-only and offline-buildable instead of
    pulling `sha2`/`blake3`.
  - `crustcore-eventlog`: the compact binary **`EventFrame`** format + append/
    read/**verify** hash chain (`prev_hash` links each frame's `frame_hash`), so
    any modification, reorder, insertion, deletion, or truncation is detected
    (`ChainStatus`/`BreakReason`); `crustcore inspect` (chain status + per-task
    summary) and `crustcore export` (JSONL, redaction-respecting); a hostile-bytes
    no-panic fuzz over the untrusted decoder.
  - `crustcore-receipts`: **`ToolReceipt`** generation + verification — a MAC
    chain keyed by a CrustCore-held `MacKey` (the model never holds it, so
    receipts are unforgeable) plus `prev_receipt_hash` linkage; `result_matches`
    binds a shown result to its hash (invariant 10).
  - The `crustcore` nano binary wires `inspect`/`export <log>` and the selftest
    now drives the event-log pipeline; an `examples/write_demo_log` produces a
    sample log to try them.
  - Red-team fixture `fabricated_tool_result_is_rejected` un-ignored (P2.6): a
    receipt forged under the wrong key, or a swapped result, fails verification.
- **Phase 1 — kernel state machine (P1.1–P1.7).** The trusted `Kernel::step`
  reducer is now real: a synchronous, deterministic, allocation-light
  `event -> state mutation -> bounded action list` over compact `Vec`-of-records
  arenas (tasks/jobs/approvals), with **no** async/network/db and **no wall clock**
  (all time is event-carried, so replay is deterministic).
  - `crustcore-types`: a `budget` module (`Budget`/`Meter`/`BudgetDelta`/
    `BudgetCheck`/`BudgetAxis`, integer-only, saturating) modelling all eight
    invariant-11 axes; `LeaseOwner`; `EventSeq::next_saturating`;
    `ApprovalStatus`/`ApprovalResolution`; `JobStatus::is_terminal`.
  - `crustcore-kernel`: pure, **exhaustive, total** task/job transition tables
    (`state.rs`); the `step` safety-ordered gates (idempotency frontier → terminal
    absorb → budget pause → source-state effect gate → bounded ready-drain);
    typed budget pause to `Blocked` (resumable); the approval request/resolution
    flow with operation-binding, expiry-at-use, one-pending-per-task, and the
    authorized-user-only guard; lease grant/expiry and stale-worker rejection.
  - `crustcore-policy`: `Approved<T>` minting is now crate-private behind
    `AuthorizedUser::approve` — the only path to an approval token requires an
    `AuthorizedUser`, so model/worker output can never mint one (invariant 4).
  - Tests: exhaustive impossible-transition property tests, a deterministic-LCG
    no-panic fuzz, determinism/idempotency/bounded-fan-out tests, and one negative
    test per acceptance criterion and per touched invariant.
  - `kernel_step` microbench wired (`benches/kernel_step.rs`, std-timer,
    `harness = false`): ~40 ns p50, well under the 1 µs budget (P1.7).
- Project documentation foundation: single-source-of-truth `CLAUDE.md`;
  authoritative `ROADMAP.md`; product laws in `INVARIANTS.md`; `THREAT_MODEL.md`,
  `SECURITY.md`, `CONTRIBUTING.md`, and `README.md`.
- Subsystem deep-dive docs under `docs/`: `architecture.md`,
  `nano-size-budget.md`, `security-model.md`, `secrets.md`, `sandbox.md`,
  `policy.md`, `event-log.md`, `receipts.md`, `backend-contract.md`,
  `telegram.md`, `github.md`, `mcp.md`, `model-routing.md`,
  `advisor-executor.md`, `self-improvement.md`, `maintainer-agent.md`.
- This `CHANGELOG.md` with the agent-log convention.
- GitHub issue templates and a documentation map.
- `AGENTS.md` — a thin router to `CLAUDE.md` so agents that look for `AGENTS.md`
  first (e.g. Codex) get the same single source of truth. Added to the contract
  file list.
- **Phase 0 workspace bootstrap (P0.1–P0.5).** A compiling Cargo workspace with
  all 19 crates + `xtask`: the `crustcore` nano binary (`--version`, `--help`,
  hidden `selftest`); trusted-core crates with real type-true skeletons
  (`crustcore-types` IDs/status/text/refs, `crustcore-kernel` event/action/step,
  `crustcore-policy` capability + approval tokens + decision, `crustcore-secrets`
  non-exfiltratable `SecretMaterial`, `crustcore-path` confined paths,
  `crustcore-eventlog` frame/chain, `crustcore-receipts` `ToolReceipt`,
  `crustcore-backend` `Unverified`/`VerifiedPatch`, `crustcore-runner`,
  `crustcore-sandbox`, `crustcore-worktree`, `crustcore-cli`); std-only sidecar
  skeletons (`crustcore-net`/`-daemon`/`-mcp`/`-index`/`-eval`/`-full`) with
  `TODO(Pn)` markers.
- `xtask` task runner (`verify`, `size-check`, `forbidden-deps`, `fmt`, `clippy`,
  `test`, `nano-build`) wired as `cargo xtask`; release profiles incl.
  `[profile.nano]`; `rust-toolchain.toml`; `.cargo/config.toml` aliases.
- CI (`.github/workflows/ci.yml`) running `cargo xtask verify` + a separate nano
  size-gate job + a best-effort `cargo-bloat`/`cargo-tree` report; `CODEOWNERS`
  enforcing maintainer review on every contract file.
- Documented `tests/{redteam,golden,fixtures}` and `benches/` trees;
  `#[ignore]`d red-team/golden test stubs in `crustcore-eval` so the suite never
  reports false green.
- **Apache License 2.0**: `LICENSE`, `NOTICE`, SPDX headers on all source files,
  and `license = "Apache-2.0"` across the workspace.

### Fixed

- **Final v0.2 audit follow-ups (5 low-severity findings from a 5-dimension
  workspace audit, all adversarially verified).** **NET-001:** `Engine::complete`'s
  `BudgetLedger` accumulation now uses `saturating_add` (matching the kernel's
  monotonic-counter convention) instead of bare `+=`. **NET-002:** the Anthropic
  adapter now **estimates output tokens** when a stream is truncated (network drop or
  `MAX_BODY_BYTES` cap) after content but before the `message_delta` usage event, so
  produced output is never billed as zero cost (invariant 11) — mirrors the OpenAI
  path; new regression test. **Doc drift:** refreshed the stale test-count
  (267 → **297**) and nano-size (411.9 → **412.0 KiB**) numbers in `README.md` and
  `docs/roadmap-v0.2.md` after the v0.2 phases. (The same numbers in the `CLAUDE.md`
  §7.3 status line are updated via a separate serialized PR.)

### Changed

- **Contract-file status refresh (serialized, §7.3).** Doc-only updates to the trust-
  boundary files after the v0.2/v0.3 merges: `CLAUDE.md`'s status block now reflects
  Track A **and** Track B (B1–B6) merged (was "Track A in progress" and listed done
  phases as "remaining"), fixes the stale nano figure (`~296 KiB` → `412.0 KiB`), and the
  test count (`~300` → `~350`); the kernel `Action` doc drops the already-done `TODO(P1.3)`
  and **removes the dead, never-emitted `Action::Noop` variant**; the policy `classify`
  doc drops the done `TODO(P1.4/P1.5)` (budget + approval state are implemented); and the
  root `Cargo.toml` note is updated to describe the now-admitted feature-gated sidecar deps
  (still none in nano — `forbidden-deps` proves it). No behavior change beyond removing the
  unreferenced `Noop` variant; `cargo xtask verify` green.
- **Codebase polish pass (post-Track-B).** A workspace-wide quality sweep (drift +
  stale-doc + dead-code) after the v0.2/v0.3 merges: refreshed the `README` status
  section to reflect Track A/B merged + the test badge `298 → 352` (prose `~350`); fixed
  stale `TODO(P*-live)`/`TODO(Pn)` markers that pointed at now-merged work
  (`crustcore-net` Provider/`default_mock_engine` docs, `crustcore-backend::integrate`
  `PrIntent`, `crustcore-worktree::tools` "Phase 4 will…", `crustcore-index/Cargo.toml`,
  the `crustcore-eval` red-team/golden suite docs, the `xtask` `verify` description, the
  `crustcore-kernel` crate-doc `step` sketch → `ActionVec`, `docs/roadmap-v0.2.md`);
  removed the dead, never-constructed `crustcore_net::NetCapability` enum; and **added a
  `branch_under_prefix` segment-boundary / `..`-traversal / empty-prefix-fail-closed unit
  test** (`crustcore-backend::integrate`) that the P10 hardening had left only
  indirectly covered. No behavior change; `cargo xtask verify` green; nano 412.0 KiB.
  (Contract-file status drift — `CLAUDE.md`'s stale `~296 KiB`/`~300 tests`/"Track A in
  progress" — is handled in a separate serialized contract PR.)
- Set the project license to **Apache-2.0** (was TBD): updated `README.md`,
  `CONTRIBUTING.md` (inbound=outbound contribution terms), and crate metadata.
- Updated status in `README.md` and `CLAUDE.md` from "documentation-first /
  pre-Phase-0" to "Phase 0 — workspace bootstrapped"; recorded the measured nano
  baseline (~296 KiB, 37% of budget) in `docs/nano-size-budget.md`.
- Reconciled documentation inconsistencies end to end: added `/cancel` as a

- Reconciled documentation inconsistencies end to end: added `/cancel` as a
  first-class graceful-cancellation command (distinct from `/kill`); clarified
  that `crustcore-nano` is the `crustcore` package built with `--features nano`
  (no separate crate) and added `crustcore` to the workspace/crate maps; added
  `crustcore-mcp`/`crustcore-index` to the §17.1 size-budget table; made the
  nano MCP-lite "no rmcp" constraint explicit; made "no secrets to external
  workers" an explicit `"secrets": "none"` field in the worker input contract;
  unified the contract-file list across `CLAUDE.md` §7.3 and `ROADMAP.md` §20.2
  (now including `CLAUDE.md` and `AGENTS.md`); fixed approximate roadmap
  list-item anchors in `THREAT_MODEL.md` and `docs/sandbox.md`.

### Fixed

- **Phase 4 — timeout process-tree kill on Linux CI (`crustcore-runner`).** The
  group kill shelled out to `kill -<sig> -<pgid>`; Linux `procps-ng kill`, when
  given that exact argv, silently returns success **without delivering** to the
  negative-pid process group (it needs a `--` end-of-options separator). The
  timeout therefore fired but the process tree survived and `wait()` blocked for
  the full child lifetime — `cargo xtask verify` hung the two runner timeout tests
  for 30s each and failed CI on `ubuntu-latest` while passing on macOS (BSD `kill`
  accepts the bare form). Fix: issue **both** argument forms (`-<sig> -<pgid>` and
  `-<sig> -- -<pgid>`; signals are idempotent), and additionally SIGKILL the
  leader directly via its `Child` handle — a std-only guarantee that does not
  depend on an external `kill` binary or its argv parsing. Reproduced and verified
  fixed in a faithful `ubuntu:24.04` container (the committed pre-fix code hung
  60s there; the fixed code passes in 0.3s).

### Security

- **Full-codebase audit hardening (post-Track-B).** A holistic 8-dimension adversarial
  audit (secrets, verifier/approval, sandbox/exec, untrusted-data, path-confinement,
  receipts/eventlog, panic/bounds, nano-deps/kernel), each finding independently refuted,
  surfaced **2 confirmed structural gaps** (neither exploitable today; both now fixed):
  - **Sealed `Approved<T>` + `AuthorizedUser`** (`crustcore-policy`, invariants 4/14).
    Both had **public fields**, so the documented "only `AuthorizedUser::approve` mints an
    `Approved<T>`" seal was bypassable by a struct literal from any workspace crate. Made
    the fields private with read-only accessors (`value()`/`approval_id()`/`approved_by()`/
    `expires_at()`/`id()`) and a single named mint path `AuthorizedUser::bind`, mirroring the
    `VerifiedPatch` seal — so the central authority object for approvals now *enforces* what
    its docs claim. Added a `compile_fail` doctest proving a forged tuple-literal does not
    compile. No behavioral change to any call site.
  - **Nano forbidden-deps gate is now an allowlist** (`xtask`, invariants 19/20). It was a
    fixed 15-name **denylist** that omitted HTTP/TLS/async crates the same file flags as
    dangerous (`ureq`/`ring`/`native-tls`), so a feature repoint leaking a sidecar dep into
    nano could slip past (the size gate has ~388 KiB of headroom). The nano check now
    **fails on any non-`crustcore*` crate** in the nano tree (first-party-only is the real
    invariant-20 property); the named denylist is kept as a friendlier secondary message.
  `cargo xtask verify` green; nano steady at 412.0 KiB.
- **Phase 4 review hardening (`crustcore-runner`, `crustcore-sandbox`).** Address
  confirmed findings from the Phase 4 adversarial review:
  - Removed the clean-exit process-group SIGKILL sweep (a narrow pid-reuse TOCTOU:
    it signalled `pgid` *after* `wait()` reaped the leader, so a reused pid could
    receive an errant cross-group SIGKILL); the bounded reader drain — and, in the
    real path, the bubblewrap pid namespace — already guarantee `run()` returns.
  - Env sanitizer now strips the JVM (`JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`,
    `JDK_JAVA_OPTIONS`), Go (`GOFLAGS`, `GOENV`), zsh (`ZDOTDIR`), pager
    (`LESSOPEN`, `LESSCLOSE`), and interpreter library-path
    (`RUBYLIB`, `PERLLIB`, `PYTHONHOME`) code-execution variables that previously
    passed through.
  - Env sanitizer rejects `HOME` / `XDG_CONFIG_HOME` that are relative or resolve
    inside the model-writable worktree — closing a git-config
    (`core.pager`/`alias`/`core.fsmonitor`) code-execution vector that survived
    even when no `*_OPTIONS` variable did.

### Agent Log

| Date | Phase/Task | Change | PR / Branch | Agent / Role | Nano Δ | Invariants |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-06-16 | Pre-P0 | Author CLAUDE.md single source of truth + full documentation set from approved roadmap | `claude/crustcore-project-docs-q0kr2p` | Maintainer agent (DocumentationWriter) | n/a (docs only) | Documents all 20; none weakened |
| 2026-06-16 | Pre-P0 | Add AGENTS.md router; reconcile flagged doc inconsistencies end to end | `claude/crustcore-docs-reconcile-q0kr2p` (PR) | Maintainer agent (DocumentationWriter) | n/a (docs only) | Clarifies 1–3, 13, 15, 19, 20; none weakened |
| 2026-06-16 | P0.1–P0.5 | Bootstrap compiling workspace (19 crates + xtask), CI + nano size gate + CODEOWNERS, Apache-2.0 license; `cargo xtask verify` green | `claude/crustcore-project-docs-q0kr2p` | Maintainer agent (Architect/Implementer) | +296 KiB baseline (37% of 800 KiB budget) | Enforces/encodes 8, 9, 13, 14, 16, 19, 20; embeds 1–3 in types; none weakened |
| 2026-06-17 | P1.1–P1.7 | Implement the kernel state machine: transition tables, budgets, approvals, lease/expiry; exhaustive property tests + no-panic fuzz + microbench; design & two adversarial-review passes. **Contract file touched:** `crates/crustcore-kernel/src/event.rs` (additive payload fields, reviewed). | `claude/p1-kernel` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB (295.5 KiB, 36.9% of budget; within section alignment) | Enforces 4, 8, 11, 14 in code; partial 12 (lease/expiry/stale-owner); verifies determinism/idempotency/bounded-fan-out/no-panic; none weakened |
| 2026-06-17 | P2.1–P2.6 | Implement the hash-chained event log + tool receipts: vendored SHA-256/HMAC (NIST/RFC vectors), `EventFrame` binary format + append/verify, `ToolReceipt` MAC chain, `crustcore inspect`/`export`, tamper tests + hostile-bytes decoder fuzz; un-ignore the fabricated-tool-result red-team fixture. Stacked on `claude/p1-kernel`. | `claude/p2-eventlog` (PR #4, merged) | Maintainer agent (Architect/Implementer) | +0.1 KiB (295.6 KiB, 37.0% of budget) | Enforces 10 (receipts) + the event-log half of the audit story; verifies tamper-evidence + no-panic decode; none weakened |
| 2026-06-17 | P3.1–P3.6 | Implement symlink-safe path confinement (`crustcore-path`) + capability-gated file tools and hardened git wrappers (`crustcore-worktree::tools`); real-fs symlink fixtures; un-ignore the symlink-escape red-team fixture. **Two rounds of critical git-RCE fixes** (textconv/external-diff, then clean/smudge filters via `* -filter` in info/attributes) + a no-follow neutralizer fix, across three review passes. | `claude/p3-path` (PR #5, merged) | Maintainer agent (Architect/Implementer) | +0 KiB (295.6 KiB, 37.0%; tools dead-code-eliminated until wired) | Enforces 7 (untrusted paths) + 8 (cap-gated file/git ops); verifies symlink/absolute/`..` escapes fail and git can't run hooks/model config/filters; none weakened |
| 2026-06-17 | P4.1–P4.7 | Implement the process runner (bounded capture, timeout, process-group kill, env-from-scratch) and the sandbox (env sanitizer, path-list validator, Linux bubblewrap backend v1 + selection/refusal, `run_command`); un-ignore the path-env-escape red-team fixture. | `claude/p4-sandbox` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB (295.6 KiB, 37.0%; runner/sandbox dead-code-eliminated until wired) | Enforces 9 (sandboxed execution), 11 (bounded output/timeout), 12 (kill/cancel); deny-all egress + no inherited secrets; Tier-3 microVM out of v0.1 scope; none weakened |
| 2026-06-17 | P4 hardening | Fix the Linux-CI timeout-kill hang (procps-ng needs `kill -- -<pgid>`; also SIGKILL the leader via its `Child` handle) — root-caused and verified in a faithful `ubuntu:24.04` container. Address Phase-4 review findings: drop the pid-reuse-TOCTOU clean-exit group sweep; strip JVM/Go/zsh/pager/interpreter-lib exec env vars; reject `HOME`/`XDG_CONFIG_HOME` inside the worktree. | `claude/p4-sandbox` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB (295.6 KiB, 37.0%) | Strengthens 9 (sandbox env), 12 (reliable process-tree kill); none weakened |
| 2026-06-17 | P5.1–P5.6 | Implement the worktree + verify loop: `WorktreeManager` (disposable `git worktree` create/reuse/remove, hardened), `crustcore-backend::verify` (`VerifySpec`/`run_verify` rerun-in-sandbox → mint `VerifiedPatch`+receipt only on pass), seal `VerifiedPatch::from_verifier` crate-private + `complete_task` by value, wire `crustcore run -dir/-goal/-verify`; golden "fix failing test" + worktree lifecycle tests. **Hardened per a 7-dimension adversarial review (8 confirmed findings fixed):** worktree-add filter neutralization+restore (RCE), registered-only worktree reuse + 0700 base, executor-seam unit tests for the mint/Failed/Refused paths, worktree teardown on all `run` paths, `VerifierName` type, extracted+tested verify-spec/exit logic. CI now installs bubblewrap so the real sandbox path runs. Full sandbox path validated in a privileged `ubuntu:24.04` container. | `claude/p5-verify` (PR) | Maintainer agent (Architect/Implementer) | +99.9 KiB (395.5 KiB, 49.4%; runner/sandbox/verify now reachable via `run`) | Enforces 13 (verifier-owned completion, type-sealed), 9 (verify in sandbox), 10 (receipt over the real run), 7 (worktree-add RCE neutralized); none weakened |
| 2026-06-17 | P6.1–P6.6 | Implement the external backend protocol: the `CodingBackend` contract + `ExternalCommandBackend`/`CodexBackend`/`ClaudeCodeBackend`; `WorkerInput` (type-pinned `secrets:none`/`network:deny`) and JSON contract; `run_external_worker` supervisor validation (sandboxed secret-free run, bounded transcript, `GuardManifest` out-of-root detection, worktree-confined diff extraction via new `git_status_all`, per-path confinement, sensitive-file classification) → `UnverifiedPatch` only; `CommandSpec.stdin` delivery through runner+bwrap; wire `crustcore run -backend/-worker-cmd` (produce → re-derive → confine → verify). Worker-contract tests + runner stdin tests; **un-ignore the `worker_write_outside_worktree_is_rejected` red-team fixture**; implement the `golden_add_small_feature` golden. Full sandboxed worker→verify→complete path validated in a privileged container. | `claude/p6-backend` (PR) | Maintainer agent (Architect/Implementer) | +16.4 KiB (411.9 KiB, 51.5%; worker module + CLI wiring) | Enforces 6 (workers are patch producers, not authorities), 7 (out-of-root/escape rejection), 1–3 + 9 (no-secret, deny-net, sandboxed worker), 13 (only the verifier completes); none weakened |
| 2026-06-20 | P10.1–P10.8 | Implement GitHub integration: `crustcore-backend::integrate::open_pr` (the type-13 gate — `VerifiedPatch` by value + `Approved<GitHubWriteCap>` → draft `PrIntent`; `format_pr_body` from verifier evidence, not self-claims) and `crustcore-daemon::github` (auth-mode ranking + classic-PAT warning, `RepoRegistry`, the credential-proxy `validate_push` denying force-push/protected/out-of-prefix/repo-mismatch/host, the ask-always `decide_merge` gate, the bounded `repair_decision` loop, untrusted `ingest_comment`). Live REST/token-minting deferred to `TODO(P10-net)`. New red-team fixture `issue_comment_says_ignore_policy` (P10.8). 13 tests across the two crates. No contract files touched (reused VerifiedPatch + GitHubWriteCap + Approved). | `claude/p10-github` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB (411.9 KiB, 51.5%; integrate DCE'd in nano, daemon is a sidecar) | Enforces 13 (only a VerifiedPatch opens a PR), 14 (PR/merge need Approved<T>), 1 (no token in sandbox — proxy injection), 7 (GitHub content + comments untrusted), 8 (writes through policy); none weakened |
| 2026-06-20 | P16.1–P16.7 | Release hardening (reversible, std-only): `crustcore doctor` (P16.3) — nano CLI readiness check (git/sandbox/state-dir → exit non-zero on FAIL; pure `DoctorReport` in crustcore-cli, probes in the bin); `cargo xtask release` (P16.1/P16.2) — build nano + size gate + emit `SHA256SUMS` (vendored SHA-256, `sha256sum -c`-compatible, cross-validated vs system shasum) + `release-manifest.txt`; `docs/releasing.md` + `scripts/install.sh` (P16.3/4/5) — signing (out-of-band minisign/cosign over SHA256SUMS), launchd/systemd unit templates (no secrets in unit files), backup/restore of the hash-chained state dir, rollback; installer verifies the checksum and refuses a tampered binary; implement the flagship `golden_fix_failing_test` (P16.7) — failing test mints no VerifiedPatch, only the verifier's pass completes (DoD #3/4/5), sandbox-adaptive; event-log migration/compat tests (P16.6) — `FRAME_VERSION` stability guard + future-version frame rejected `BadVersion` not misread (DoD #6). Added `crustcore-types` dep to xtask (std-only). The CI release workflow + live signing key are intentionally NOT wired (irreversible/keyed — maintainer/serialized). No contract files touched. | `claude/p16-release` (PR) | Maintainer agent (Architect/Implementer) | +0.1 KiB (411.9 KiB, 51.5%; `doctor` +64 B) | Enforces/verifies 9 (doctor: no sandbox → not ready), 13 (golden: only the verifier completes), 19 (release runs the size gate), 16 (doctor/release are admin tooling), 6 (event-log format versioned + migration-tested); none weakened |
| 2026-06-20 | P15.1–P15.5 | Implement safe self-improvement in `crustcore-daemon::selfimprove` (std-only, NOT in nano): `classify(FailureSignal)→FailureClass` (P15.1), typed `ImprovementProposal` with `ProposalTarget` enumerating ONLY prompt/tool/config — cannot express policy/sandbox/secret weakening (P15.2), type-sealed `ReadyProposal::prepare` requiring both `Demonstrates`+`GuardsRegression` evals or it cannot advance (P15.3), `plan_self_pr` → **draft** PR (never privileged/self-merge; still needs VerifiedPatch+Approved) (P15.4), and `contract_gate(changed_paths)` flagging ANY contract-file touch (CLAUDE.md §7.3 list + any Cargo.toml/lock) even bundled → `RequiresMaintainerApproval` (P15.5, invariant 18). **No live mutation**: every fn returns inert artifacts/decisions, no `&mut` of running policy/sandbox/secrets. New red-team fixture `self_improvement_cannot_weaken_policy_silently`. 4 crate tests + 1 fixture. No new deps. No contract files touched. | `claude/p15-selfimprove` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB (411.9 KiB, 51.5%; daemon is a sidecar) | Enforces 18 (no live self-mutation — proposals/PRs only), 13/14 (self-PR is a draft, never self-merges), 7 (memory/idea is not authority — evals required), 8/9/3 (silent weakening of policy/sandbox/secrets caught by the gate or unrepresentable); none weakened |
| 2026-06-20 | P15 hardening | Address the Phase-15 adversarial review (2 confirmed low findings, both `is_contract_file` normalization gaps). Add `normalize_contract_path` so the contract gate folds the path variants a non-canonical/adversarial source could use to dodge an exact match — repeated slashes (`docs//policy.md`), backslash separators, leading `./`/`/`, trailing slash, and **case** (`Docs/Policy.md`) — matching the case-insensitive convention of the sibling guards in `crustcore-worktree::tools` and `crustcore-sandbox` ("err toward flagging"). No false-positive suffix matching (`vendor/CLAUDE.md` stays unflagged). New `contract_gate_is_normalization_robust` test. Review confirmed `CONTRACT_FILES` is complete vs `CLAUDE.md` §7.3 and all structural properties hold (no live mutation, unforgeable `ReadyProposal`, no self-merge). No contract files touched. | `claude/p15-selfimprove` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB (411.9 KiB, 51.5%) | Strengthens 18 (contract gate harder to bypass); none weakened |
| 2026-06-20 | P14.1–P14.5 | Implement repo memory + code intelligence in `crustcore-index` (std-only capability pack, gated behind the `index` feature, NOT in nano): `RepoCapsule`/`RepoMap::from_paths` (bounded repo summary + cheap map from a `git ls-files` listing — P14.1/P14.2), `CodeIntel` trait + `GrepCodeIntel` (deterministic substring lookup → bounded `SymbolRef`s — P14.3), in-memory `MemoryStore` of provenance-tagged `MemoryEntry`s + keyword `search` (P14.4), and `select_context` (relevance-rank → greedy pack under `MAX_CONTEXT_BUNDLE` → **redact-then-bound** each fragment into `ModelVisibleText`, report `dropped` — P14.5). **Memory is never authority**: every fragment is untrusted prior observation (redacted, bounded, provenance-tagged) with no path to `Approved<T>`/capability. Live `git ls-files`/`git grep` (`TODO(P14-exec)`), persistent SQLite/redb (`TODO(P14-store)`), AST/tree-sitter/LSP (`TODO(P14-intel)`) deferred. New red-team fixture `memory_says_authorized_is_inert`. 5 crate tests + 1 fixture. Added `crustcore-secrets` dep to crustcore-index + index dep to crustcore-eval. No contract files touched. | `claude/p14-index` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB (411.9 KiB, 51.5%; capability pack, off in nano) | Enforces 7 (memory/observations untrusted — hostile memory inert), 2 (redacted context), 11/§6.5 (bounded context bundle), 20 (off in nano, only relevant fragments enter context); none weakened |
| 2026-06-20 | P13.1–P13.6 | Implement MCP gateway + registry + code-mode in `crustcore-mcp` (std-only capability pack, NOT in nano): `McpServerRecord`/`McpRegistry` (P13.1), `gateway_check` (Allow/Ask/Deny from tool_policies — never the server's untrusted self-description; denies unknown server / manifest-drift / out-of-repo / unpoliced-default-deny / explicit-deny — inv 8), `filter_result` (redact untrusted MCP output + bound to a summary + artifact-hash handle + ToolReceipt — inv 2/7/10), `wrap_untrusted` for tool descriptions, `generate_stubs` (only used allow/ask tools — inv 20). Live MCP transport + sandboxed stubs + broker injection deferred (`TODO(P13-net)`). **Un-ignored** the `mcp_hidden_instructions_are_inert` red-team fixture (P13.6). 5 tests. Added secrets+receipts deps to crustcore-mcp + mcp dep to crustcore-eval. No contract files touched. | `claude/p13-mcp` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB (411.9 KiB, 51.5%; capability pack) | Enforces 7 (MCP output/descriptions untrusted — hidden instructions inert), 8 (policy-checked calls), 10 (receipted results), 2 (redacted output), 1-3 (broker-mediated auth, never model-visible), 20 (only used stubs in context); none weakened |
| 2026-06-20 | P13 hardening | Address the Phase-13 adversarial review (2 confirmed low findings). **UR-1:** `wrap_untrusted` now redacts **and bounds** untrusted descriptions/resources to `MAX_MCP_SUMMARY` (was redact-only) — closes the unbounded-untrusted-text-into-model-context gap, symmetric with `filter_result` ("bounded everything", §6.5). **UR-2:** `filter_result` takes a `call_args` parameter so the receipt's `args_hash` binds the real (canonicalized) call arguments instead of the tool name; added `ToolReceipt::args_matches`. Regression asserts in the unit test + red-team fixture. No contract files touched. | `claude/p13-mcp` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB (411.9 KiB, 51.5%) | Strengthens 11/§6.5 (bounded untrusted text), 10 (receipt binds real call args); none weakened |
| 2026-06-20 | P12.1–P12.5 | Implement advisor/executor in `crustcore-daemon::advisor` (std-only sidecar): `AdvisorMode`, the `AdvisorTrigger` set + `is_high_risk`, compacted `Consultation`, `Advisor` trait + deterministic `SimulatedAdvisor` → advisory `AdvisorNote`; `should_consult` budget control (per-task cap + pressure-preserves-high-risk); `consult_before` flow. Advisory-NOT-policy is structural: no path from AdvisorNote to Approved<T>/capability (a test shows advisor-proceed still leaves `decide_merge` at RequiresApproval). Native provider advisor deferred (`TODO(P12-native)`). 8 tests. No contract files touched. | `claude/p12-advisor` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB (411.9 KiB, 51.5%; sidecar) | Enforces 4 (advisor can't mint approvals), 8 (advisor grants no capability/relaxes no policy), 11 (budgeted consults); none weakened |
| 2026-06-20 | P11.1–P11.6 | Implement native subagents + supervisor in `crustcore-daemon::supervisor` (std-only sidecar): `Role` set + `AgentRegistry`, structured `AgentMessage`/`MessageKind`, `Blackboard` with `AgentTarget` that has **no User variant** (subagents structurally can't address the user — invariant 5; `CapabilityRequest` is how they ask the supervisor), `AgentBudget`/`AgentUsage::charge` (refuses over-budget per axis — invariant 11) + `Scheduler` concurrency cap, and `decide_integration` (Reviewer/SecurityAuditor/Tester block veto + verify-gated → invariant 13). Subagent execution + live integration-worktree verify deferred (`TODO(P11-exec)`). 8 tests. No contract files touched. | `claude/p11-subagents` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB (411.9 KiB, 51.5%; daemon is a sidecar) | Enforces 5 (subagents can't message the user — structural), 11 (subagents can't exceed budgets), 13 (parallel worktrees merge only after verification), 1/3 (subagents don't resolve secrets — CapabilityRequest to supervisor); none weakened |
| 2026-06-20 | P10 hardening | Fix the critical refspec-smuggling finding (+ others) from a 6-dimension adversarial review (6 refuted): `validate_push` validated only the last colon-segment, so a multi-refspec push smuggled a protected-branch/force update past the credential proxy → restructured `PushRequest` (explicit `force` + per-ref `Vec`), validate EVERY ref, reject interior whitespace (fail-closed); broaden force-flag detection to all `--force…` spellings (`is_force_flag`); segment-boundary `branch_under_prefix` in both `validate_push` and `open_pr`; bound ingested comment text. Multi-refspec/force/boundary regression tests added. | `claude/p10-github` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB (411.9 KiB, 51.5%) | Strengthens 8/14 (no smuggled destructive/protected push), 4.1 refspec-smuggling contract; none weakened |
| 2026-06-20 | P9 hardening | Fix the 3 confirmed findings from a 6-dimension adversarial review (7 refuted/out-of-scope): correct `Deduper::accept` (value-based evicted floor instead of the oldest-*inserted* id, so an out-of-order replayed `update_id` can't be re-accepted — docs §5; the approval engine's single-use nonce already blocked double-*approval*); `clean_text` maps whitespace control chars to a space (no token-joining across newlines); soften an over-claiming rate-limit doc comment. Out-of-order replay regression test added. | `claude/p9-telegram` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB (411.9 KiB, 51.5%) | Strengthens P9.7 replay/dedupe (docs/telegram.md §5); none weakened |
| 2026-06-20 | P9.1–P9.7 | Implement the Telegram runtime channel logic in `crustcore-daemon::telegram` (std-only sidecar, not in nano): `ChatAllowlist` (empty=deny-all, explicit ids, opt-in wildcard; identity = chat id not username), `normalize` (typed `InboundEnvelope`, control-strip+bound, trusted host time) + `Deduper` (update_id high-water+window), typed `Command` set, `route` (queue vs `!`-steer → `UserMessageQueued`/`UserSteerReceived`), `ApprovalEngine` nonce approvals (operation-bound via op-hash, expiring, single-use → `Approved<ApprovedOperation>` only via `AuthorizedUser::approve`), `OutboundRenderer` (typed sources → redacted `ModelVisibleText`, no model-text path). Bot API HTTP polling/send deferred to `TODO(P9-net)`. 13 spoof/dedupe/approval/redaction tests. No contract files touched (reused existing kernel events + policy approval API). | `claude/p9-telegram` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB (411.9 KiB, 51.5%; daemon is a sidecar) | Enforces 5 (supervisor-only channel; subagents can't reach it), 15 (single runtime channel), 16 (allowlist via setup, not DM-to-pair), 4 (only AuthorizedUser mints approvals), 2 (redacted outbound); none weakened |
| 2026-06-17 | P8.1–P8.6 | Implement the secret broker + typed secrets: `SecretMaterial` (no Debug/Display/Clone/Serialize, no model-visible conversion, zeroize-on-drop; forbidden impls proven by compile-fail doctests), `SecretHandle`, `Redactor`/`ModelVisibleText`/`Tainted` (the taint boundary, S2–S10), `SecretBroker`/`SecretStore`/`InMemoryStore` + one-shot/expiring/borrowed `ApprovedSecretView` (P8.4), `CredentialProxy`→`HeaderInjection` (P8.6). Native keychain (P8.2) + encrypted vault (P8.3) deferred to `TODO(P8-store)` outside nano. Un-ignored the `secret_never_leaks_to_model` red-team fixture (full S1–S10 matrix). **Contract file touched:** `crates/crustcore-secrets/src/lib.rs` (this is the phase that implements it; flagged for review). | `claude/p8-secrets` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB (411.9 KiB, 51.5%; broker dead-code-eliminated in nano) | Enforces 1 (no raw creds to LLM), 2 (no unredacted secret logs), 3 (SecretMaterial not Debug/Serialize/Clone/model-visible — compile-fail-proven); credential proxy unblocks P7-live; none weakened |
| 2026-06-17 | P7.1–P7.7 | Implement the `crustcore-net` model-transport protocol + routing engine: new **std-only `crustcore-netproto`** (flat-JSON helper protocol + codec + `NetHelper`/`SpawnedHelper` client — the only transport code the caller links, no HTTP/TLS); `crustcore-net` engine (`Provider` trait, dynamic registry/probe, `select_candidates`/`apply_budget`/`run_reliable` = Router/Budget/Reliable meta-providers, streaming, `BudgetLedger`, `serve`); `MockProvider`/`default_mock_engine` + helper binary; `crustcore net probe\|complete` gated behind the `net` feature (links only netproto). Live HTTP adapters deferred to `TODO(P7-live)` (need the Phase 8 secret broker + network). Unit + protocol + end-to-end + real-subprocess integration tests. **Contract files touched:** `Cargo.toml`/`Cargo.lock` (add the `crustcore-netproto` workspace member; repoint the `net` feature). | `claude/p7-net` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB (411.9 KiB, 51.5%; all net code cfg-gated/sidecar) | Enforces 17 (dynamic registry, no hard-coded models), 11 (budget ceiling + accounting), 19/20 (nano links no HTTP/TLS; net is a spawned helper); pin-by-construction for the no-secret-to-worker path (live providers gated on Phase 8); none weakened |
| 2026-06-17 | P8 hardening | Fix the 7 confirmed findings from a 6-dimension adversarial review (7 refuted/out-of-scope): rewrite `Redactor::redact` as collect-spans→merge-overlaps→splice (fixes a real fragment-leak when two secrets share an edge substring + makes redaction a fixed point, RC-1/RC-2/ROB-1); make `Redactor` non-`Clone` + zeroize needles on drop (SC-1); make `Tainted<T>` non-`Clone` with a non-revealing `Debug` placeholder (LTS-1/CDF-1, S5); single-source the redaction marker (CDF-2). Regression tests added. | `claude/p8-secrets` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB (411.9 KiB, 51.5%) | Strengthens 1/2 (no secret fragment crosses a boundary), 3 (taint carrier no longer Debug-leaks); none weakened |
| 2026-06-17 | P7 hardening | Fix the 3 confirmed findings from a 7-dimension adversarial review (14 refuted/out-of-scope): (med) cap `NetHelper::probe`/`complete` reads from a misbehaving helper (`MAX_REGISTRY_MODELS`/`MAX_STREAM_BYTES`) so it cannot OOM/hang the caller; (low) enforce `MAX_LINE_BYTES` on the newline branch of `read_line_bounded`; (low) `xtask forbidden-deps` now also gates the `--features net` tree (no `crustcore-net`/HTTP-TLS linked). Regression tests added. | `claude/p7-net` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB (411.9 KiB, 51.5%) | Strengthens 7 (bounded untrusted helper output), 20 (net-boundary now CI-gated); none weakened |
| 2026-06-17 | P6 hardening | Fix the 5 confirmed findings from a 7-dimension adversarial review (7 refuted/out-of-scope): (high) move the runner stdin write to a dedicated thread so a non-draining worker can't hang `run()` past the timeout (invariants 11/12); (med) parse `git status -z` so quoted/space/non-ASCII paths reach confinement+classification verbatim; (med) new `git_worktree_diff` (intent-to-add + `diff HEAD`) so new-file content is in the diff and patch content-address; (med) stream `run_git` output into capped buffers (no unbounded-output OOM from a hostile worktree). Added regression tests for each. Full sandboxed path re-validated in a privileged container. | `claude/p6-backend` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB (411.9 KiB, 51.5%) | Strengthens 11/12 (bounded/killable execution), 7 (verbatim-path confinement), 6 (faithful re-derived diff); none weakened |
| 2026-06-20 | v0.2 P5-join | Implement the receipt↔event-log join, closing the `TODO(P5)` in crustcore-receipts: new `join` module — `verify_against_log(&[ToolReceipt], &[FrameRef]) -> JoinStatus` cross-checks every receipt's `event_seq` resolves to an existing `ToolCallCompleted` frame with matching task/job (`NoFrameAtSeq`/`NotAToolCompletion`/`TaskMismatch`/`JobMismatch`). Kept dependency-free (no eventlog dep) via a log-agnostic `FrameRef` the caller extracts — receipts stays nano-tiny. Wired end-to-end through `selftest` (now prints `receipt↔log JOINED`); resolved the `event_seq` TODO doc; updated `docs/receipts.md` §8. 6 unit tests; no contract files touched. First v0.2 Wave-1 phase. | `claude/p5-join` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB (412.0 KiB, 51.5%; +32 B) | Strengthens 10 (a receipt is provably tied to a logged event, not just self-consistent); none weakened |
| 2026-06-20 | v0.2 P7-live | Implement live model providers in the spawned `crustcore-net` helper: `transport::HttpClient` boundary + `ReplayClient` (CI) + `UreqClient` (`live` feature only); `OpenAiProvider` (OpenAI/OpenRouter/local) + `AnthropicProvider` over it (SSE streaming, usage+cost, 429/5xx→Unavailable, ctx→Capability, success-path-only emission, no-panic on bad SSE); `credsource::CredentialSource`/`StaticCredentials` (per-call header, redacting `AuthHeader` Debug); `config::parse_providers` (handle-only JSON); `live_engine` + `helper --providers`. Engine unchanged (pure drop-in). Maintainer-approved dep admission (user: "proceed — admit the deps"): `serde_json` (sidecar, non-optional) + `ureq` (optional, `live`); **new forbidden-deps check + `xtask clippy-live`** assert the default crustcore-net build links no HTTP/TLS and nano is untouched. Secret-leak red-team fixture (sentinel key never in output/errors) + engine-level cross-adapter fallback over real adapters. Live network behind `#[ignore]`d `live_smoke` only. 26 unit + 2 integration tests; `docs/model-routing.md` §7 updated. No §7.3 contract files touched (Cargo.lock gains the maintainer-approved external deps; crates/crustcore-net/Cargo.toml is not a contract file). | `claude/p7-live` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB nano (412.0 KiB, 51.5%; sidecar-only; HTTP/TLS feature-gated) | Enforces 1–3 (no key to model/log/sandbox — per-call resolution, redacting Debug, leak red-team), 17 (config-driven dynamic registry), 11 (bounded responses, success-only emission), 19/20 (HTTP/TLS confined to the `live`-gated sidecar, nano clean); none weakened |
| 2026-06-20 | v0.2 P10-net | Implement the GitHub REST wire layer in `crustcore-net::github`: `GitHubApi` trait + `RestGitHub` over the shared `transport::HttpClient` (reuse P7-live) — `create_pull` (draft), `check_state` (distil check-runs → Pending/Passed/Failed), `create_comment`; added `transport::HttpClient::post_json` (non-streaming JSON) + ReplayClient/UreqClient impls. Primitive inputs (daemon maps `PrIntent`→`CreatePrRequest`) keep the sidecar dep-light. Untrusted responses (inv 7): only needed fields read, non-2xx → typed `GitHubError` (never a fake `PrCreated`), `BadResponse` on junk 2xx; token resolved per-call via the credential proxy and never in output/errors (status-mapped). Red-team: token-echoing 403 → RateLimited/Unauthorized without the token. CI-tested via ReplayClient; live `UreqClient` behind `live`. 12 unit + 2 integration tests; `docs/github.md` §9 updated. No new deps (reuses serde_json/ureq); nano unchanged. Live end-to-end PR-open (daemon→helper→GitHub, un-defers the issue→PR golden) behind `#[ignore]`d `gh_live`. No §7.3 contract files touched. | `claude/p10-net` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB nano (412.0 KiB, 51.5%; sidecar-only) | Enforces 7 (GitHub responses untrusted, non-2xx never fabricates success), 1–3 (token never in output/errors — credential proxy + status-mapped), 13/14 (executes only the gate's draft PrIntent), 19/20 (sidecar-only); none weakened |
| 2026-06-20 | v0.2 final audit | Address the 5 low-severity confirmed findings of a complete 5-dimension workspace audit (invariants/security, v0.2-net, consistency, gate-honesty, robustness — each adversarially verified; 1 refuted). **NET-001:** `Engine::complete` BudgetLedger uses `saturating_add` (kernel convention), not `+=`. **NET-002:** Anthropic adapter estimates output tokens on a truncated stream (after content, before `message_delta`) so produced output is never billed zero (inv 11); + regression test. **Doc drift:** README + docs/roadmap-v0.2.md test count 267→297 and nano 411.9→412.0 KiB. CLAUDE.md §7.3 status numbers updated via a separate serialized PR. `cargo xtask verify` green. | `claude/final-audit-fixes` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB nano (412.0 KiB, 51.5%) | Strengthens 11 (no zero-cost produced output; non-wrapping ledger); none weakened |
| 2026-06-20 | v0.2 P8-store | Implement the encrypted-file secret vault in `crustcore_secrets::store` (behind the `vault-file` feature): `seal_vault`/`open_vault` — AES-256-GCM + scrypt(N=2^15) over `magic\|version\|salt\|nonce\|ciphertext`, decrypting into an `InMemoryStore` the broker reads. Fails closed (wrong passphrase / tamper → `VaultError::Decrypt`, no leak); no plaintext at rest; blob+key zeroed on **every** path via RAII `Scrubbed`/`ScrubbedKey` guards using the crate's `black_box`-fenced `scrub` (review fix — the only confirmed findings were error-path zeroing, all low; AEAD construction confirmed sound); bounded panic-free decode. **Maintainer-approved CONTRACT-FILE change** (serialized, user OK'd): `crustcore-secrets/src/lib.rs` (`pub mod store` behind the feature) + `docs/secrets.md` §9. Admitted feature-gated crypto deps (`aes-gcm`/`scrypt`/`getrandom`); added them to the nano forbidden-deps list (15 checked, none in nano) and added `xtask` `clippy-features`+`test-features` so the gated vault is clippy- and test-checked in CI. 6 vault tests. Native OS keychains remain TODO(P8-store). nano untouched at 412.0 KiB. | `claude/p8-store` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB nano (412.0 KiB, 51.5%; crypto feature-gated out of nano) | Enforces 1–3 (secrets sealed at rest, fail-closed, no plaintext on disk, SecretMaterial still non-Debug/Serialize/Clone), 19/20 (crypto never in nano — forbidden-deps + feature gate), 11/§6.5 (bounded, no-panic decode); none weakened |
| 2026-06-20 | v0.2 P9-net | Implement the Telegram runtime loop in `crustcore-daemon::telegram`: `TelegramApi` trait (`get_updates`/`send_message`) + `TelegramPoller` driving the existing trust core (allowlist/dedupe/normalize/route/approvals/renderer). `poll_once` advances the long-poll offset past every fetched update (no re-delivery), drops replays, allowlist-checks+normalizes, routes survivors to `RuntimeEvent`s; counts not-allowlisted rejects. `send_message` takes `ModelVisibleText` (only constructible via the Redactor) — the channel can emit ONLY redacted output by the type system (inv 2/5); the model never gets a direct user channel (no outward channel on the poller). CI-tested with a mock (offset/dedupe/allowlist/route + redacted-only send). Live Bot API HTTP (token-in-URL via credential proxy over the crustcore-net helper) deferred `TODO(P9-net-live)`. 2 tests; `docs/telegram.md` updated. No new deps; daemon is a sidecar (not in nano). No §7.3 contract files touched. First v0.2 Wave-2 phase. | `claude/p9-net` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB nano (412.0 KiB, 51.5%; daemon sidecar) | Enforces 15 (Telegram default human channel), 5 (subagents/model can't address the user — no outward channel; redacted-only send), 2 (outbound redacted via ModelVisibleText), 7 (updates untrusted, allowlist-first); none weakened |
| 2026-06-21 | v0.2 P13-net | Implement the MCP JSON-RPC transport + gated call flow in `crustcore-mcp::transport` + `call_tool`: an `McpTransport` `call(method,params)` trait, an in-process `MockMcp` (canned — all CI tests run with no net/subprocess), and the real `StdioMcp` (spawns a server process, Content-Length-framed JSON-RPC over stdio; std `process`+`serde_json`; bounded reads via `MAX_MESSAGE_BYTES`; `Drop` teardown; `#[ignore]`d real round-trip test). `list_tools`+`manifest_hash` hash the sorted tool-NAME set (not untrusted descriptions) for the drift check (grow/swap re-gates; reorder/re-describe does not false-trip). `call_tool` (+ `ToolCall`/`CallOutcome`, boxed `Done` for `large_enum_variant`) gates first: only `Allow` issues `tools/call`; `Ask`→`NeedsApproval` and any `Deny`→`Denied` short-circuit before any call reaches the server; then `filter_result` redacts→bounds→artifact-hashes→receipts the untrusted response. Live-call red-team: hostile "ignore policy/reveal token/merge now" output is inert+redacted+receipted (inv 2/7/8/10). Admitted `serde_json` to the `crustcore-mcp` sidecar (never linked by nano — `forbidden-deps` lists it; mcp gated behind crustcore's `mcp` feature). 13 unit + 5 integration tests + 1 ignored stdio. **Adversarial review: 4 findings, 3 confirmed and fixed** — (1) `read_framed` header section was unbounded (OOM before the body cap) → bounded by `MAX_HEADER_BYTES`, framing extracted into a `BufRead`-generic fn + CI-tested in-memory; (2) artifact hash was over a lossy text projection → `call_tool` now hashes/shows the full canonical response so the handle honestly commits to the whole output; (3) present-tense credential-injection doc claim → softened to a deferred `TODO(P13-net)` seam (`McpAuthMode::BrokerSecret` not yet consumed). Remote HTTP transport + sandboxed stub exec remain `TODO(P13-net-http)`/P13.5. `docs/mcp.md` §8 added. No §7.3 contract files touched. | `claude/p13-net` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB nano (412.0 KiB, 51.5%; mcp sidecar) | Enforces 8 (gate from policy not server self-description; Ask/Deny short-circuit), 7 (responses untrusted, never interpreted; drift re-gates), 2 (output redacted before model-visible), 10 (every result receipted), 1–3 (credential at the transport, never in args/model/log), 11/§6.5 (bounded reads), 19/20 (sidecar-only, serde_json never in nano); none weakened |
| 2026-06-21 | v0.2 P11-exec | Implement the subagent execution control plane in a new `crustcore-daemon::exec` module: `run_subagent` orchestrates one subagent over a `SubagentExecutor` trait, enforcing (in order) **registry-bound identity** (role+budget from `AgentRegistry` by id, never the worker's self-asserted `from_role` — fills the `TODO(P11-exec)` seam at `supervisor.rs`'s `AgentMessage::from_role`), **bounded fan-out** (`Scheduler` slot reserved + **always released** even on error/over-budget, inv 11), **budget** (run usage charged vs the agent's `AgentBudget`; over-budget → refused, not posted/charged, inv 11), and **verifier-owned acceptance** (`accepted` only from the executor's `verified` evidence; the worker's `self_claimed_done` is recorded but never completes, inv 6/13). Outcome posts to the blackboard addressed to `AgentTarget::Supervisor` — structurally never the user (inv 5). CI-tested with a `MockExecutor`: verified-accept→`PatchProposal`; self-claim-without-verify→not accepted, `TestResult`; unknown-agent/concurrency-cap/over-budget/executor-error all refuse, release the slot, post nothing. Live `WorktreeSubagentExecutor` (`run_external_worker`→`run_verify` in a sandboxed throwaway worktree, mirroring `crustcore/src/main.rs`) is the `TODO(P11-exec-live)` seam, lands with the daemon runtime behind the same trait. **Adversarial review: 3 found, 2 confirmed (same root) + fixed** — declared `MAX_SUBAGENT_SUMMARY` was unenforced dead code → `run_subagent` now re-bounds the untrusted executor summary to it on the supervisor side (defense-in-depth); slot release hardened into a RAII `SlotGuard` (released on every path incl. panic unwind — the refuted finding's good suggestion). 7 tests. No new deps (daemon-local; daemon sidecar, not in nano). No §7.3 contract files touched. Wave-2 phase. | `claude/p11-exec` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB nano (412.0 KiB, 51.5%; daemon sidecar) | Enforces 5 (subagent can't address the user — posts only to Supervisor), 6/13 (verifier-owned acceptance; self-claim never completes), 11 (bounded concurrency + budget; slot always released), and binds privilege to the registry not a self-asserted role; none weakened |
| 2026-06-21 | v0.2 P14-store | Implement the persistent memory snapshot in `crustcore-index::MemoryStore`: `save`/`load` serialize all entries to a versioned, self-describing file (`magic("CCMS")\|version(1)\|count(u32)\|[kind(u8),source(u8),key(len+bytes),value(len+bytes)]…`, little-endian) and reload them with identical query semantics, so memory survives a restart (`TODO(P14-store)` realized). **Dependency-free** (mirrors the event-log frame + secret vault formats — a bounded set of structured non-secret observations needs no SQL/KV engine), so no dep admitted. Decode is **fail-closed + panic-free**: bad magic/version rejected; entry count + every field length checked vs `MAX_MEMORY_ENTRIES`/`MAX_MEMORY_FIELD` with capped preallocation before any read (a tiny file claiming a huge count cannot amplify into a big alloc) → typed `MemoryStoreError`, never a panic/unbounded alloc (inv 11/§6.5). Entries stay untrusted, non-secret data (inv 7); snapshot is plaintext (contrast the encrypted secret vault). **Review: 2 found, 1 confirmed+fixed** — save/load field-size asymmetry (load rejects an over-`MAX_MEMORY_FIELD` field but save didn't bound one → an entry with a looser `BoundedText` cap could save yet fail to load, dropping the whole snapshot); save now char-boundary-bounds each field to `MAX_MEMORY_FIELD` on write so save success implies load success. 4 tests (round-trip incl. search/by_kind, empty, fail-closed on bad magic/version/truncated/over-cap-count, oversized-field round-trip). Live `git ls-files`/`git grep` (`TODO(P14-exec)`) + tree-sitter (`TODO(P14-intel)`) remain deferred. No new deps; `crustcore-index` is a sidecar (not in nano). No §7.3 contract files touched. Wave-2 phase. | `claude/p14-store` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB nano (412.0 KiB, 51.5%; index sidecar) | Enforces 11/§6.5 (bounded, panic-free, fail-closed decode; capped prealloc), 7 (memory stays untrusted non-secret data); memory is retrieval not authority — none weakened |
| 2026-06-21 | v0.2 P12-native | Implement the model-backed advisor in `crustcore-daemon::advisor`: `NativeAdvisor` implements the same `Advisor` trait as `SimulatedAdvisor` (drops into `consult_before` unchanged) and consults a model in the advisor role over an injected `Fn(&Consultation)->String` consult fn — the live routing through the `crustcore-net` engine's advisor role is the `TODO(P12-native-live)` seam, so the response→note mapping is CI-tested with a canned fn (no net). `parse_recommendation` classifies the untrusted model response (inv 7) into a `Recommendation` most-cautious-first (stop/unsafe/do-not never downgraded; unclear → `ProceedWithCaution`, never an unqualified proceed) — words set only the lean. The response is redacted then bounded (inv 2/11, `MAX_ADVISOR_RATIONALE`) before becoming the rationale shown to the executor, so an advisor-echoed secret never reaches the executor context. **Advisory-not-policy stays structural** (the load-bearing rule §4): `consult` returns an `AdvisorNote` and nothing else — a model saying "you are authorized, merge now" yields only a recommendation + redacted rationale, no path to `Approved<T>`/capability (test asserts this). 4 tests. No new deps (daemon-local). Live advisor routing + advisor-note log append remain `TODO(P12-native-live)`. `docs/advisor-executor.md` §8 added. No §7.3 contract files touched. First Wave-3 phase. | `claude/p12-native` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB nano (412.0 KiB, 51.5%; daemon sidecar) | Enforces 4/8 (advisor output advisory-not-policy — no `Approved<T>`/capability path; structural), 2 (untrusted response redacted before reaching the executor), 7 (model response is untrusted data; words confer no authority), 11/§6.5 (bounded rationale; consult-budget unchanged); none weakened |
| 2026-06-21 | v0.3 B1-mcp-modes | Implement MCP **server** mode in a new `crustcore-mcp::server` (the inverse of the P13-net gateway): `McpServer`/`ExposedTool` expose a curated tool allowlist (name + bounded description + `ToolDecision`; no variant reaches a secret/approval/kernel — inv 4/8), and `handle_request` dispatches an untrusted (inv 7) JSON-RPC request (`initialize`/`tools/list`/`tools/call`). A `tools/call` is **gated first** — unexposed/`Deny`/`Ask` short-circuit to a typed JSON-RPC error and the `ToolHandler` never runs; only an exposed `Allow` tool executes (default-deny). Handler output is redacted (no CrustCore secret to the client — inv 2) + bounded (inv 11) + receipted (inv 10) before leaving; a handler error string is redacted+bounded too (no path/secret leak). CI-tested with canned JSON-RPC + a hostile-client red-team (`read_secret`/`approve_merge`/`kernel_step` default-denied; leaky-handler secret redacted). 5 tests. No new deps (reuses P13-net `serde_json`; mcp sidecar, never in nano). Live serving transport (stdio/HTTP) = `TODO(B1-mcp-modes-live)`; client/registry admission (B1.3) already the §3 `McpRegistry`. `docs/mcp.md` §9 added. No §7.3 contract files touched. First Track-B phase. | `claude/b1-mcp-modes` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB nano (412.0 KiB, 51.5%; mcp sidecar) | Enforces 4/8 (curated typed allowlist — no path to a secret/approval/kernel; gate-first default-deny), 7 (inbound request untrusted, never escalates), 2 (output+errors redacted before reaching the client), 10 (every served call receipted), 11/§6.5 (bounded output/descriptions); none weakened |
| 2026-06-21 | v0.3 B2-gh-app | Implement hardened GitHub webhook ingestion in a new `crustcore-daemon::webhook`: `WebhookVerifier::verify` turns an untrusted inbound webhook into a verified, bounded `GitHubEnvelope` (→ kernel `Event::GitHubObserved`). Fail-closed, ordered to deny cheaply: **bound body first** (`MAX_WEBHOOK_BODY` — never hash megabytes, inv 11) → **HMAC-SHA256 verify** (`X-Hub-Signature-256`) over the raw body in **constant time** (`ct_eq` visits every byte — no timing oracle; vendored `hmac_sha256`, dependency-free) → **replay-reject** by `X-GitHub-Delivery` via a bounded FIFO guard, AFTER authentication (a forged flood can't evict the guard or probe seen deliveries). Untrusted payload (inv 7) redacted (inv 2) + bounded (`MAX_WEBHOOK_SUMMARY`) into the envelope, never interpreted as a command. Shared secret lives only in the verifier (broker-supplied, never model/sandbox-visible; struct not `Debug`/`Clone` — inv 3). 7 tests incl. red-team (forged/near-miss/malformed sig, oversized, empty-delivery, replay rejected; hostile signed payload inert+redacted). No new deps. Live HTTP listener + JSON field extraction = `TODO(B2-webhook-live)`; GitHub App JWT/RS256 token minting (B2.1) needs an RSA signer = `TODO(B2-gh-app-live)`. `docs/github.md` updated. No §7.3 contract files touched. | `claude/b2-gh-app` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB nano (412.0 KiB, 51.5%; daemon sidecar) | Enforces 7 (inbound webhook untrusted, redacted, never a command), 2 (payload redacted), 11/§6.5 (size-bounded body + payload + replay guard; bound-before-hash), 3 (webhook secret not Debug/Clone/model-visible), and constant-time MAC compare (no timing oracle); none weakened |
| 2026-06-21 | v0.3 B3-vector-memory | Implement embedding-backed semantic retrieval in a new `crustcore-index::embed`: `cosine` (safe 0.0 on zero/length-mismatch, panic-free), `VectorMemory::nearest` (brute-force top-k by cosine, deterministic ties), `semantic_select` (embedding-ranked context selection), and an `Embedder` trait with a dep-free deterministic `HashEmbedder` (FNV-1a bag-of-words) for dev/CI. **Pure `f32` math, dependency-free** — a brute-force scan over bounded memory needs no vector-DB dep (mirrors P14-store). Refactored `select_context`'s redact→bound→budget back half into a shared `build_bundle` so the semantic and keyword paths apply the IDENTICAL redaction/bounding (behavior unchanged — existing tests green). Live text→vector embedding via the net helper = `TODO(B3-embed-live)`; approximate-NN index = `TODO(B3-ann)`. **Memory stays never-authority** (inv 2/7/11): red-team proves a hostile doc ranked as the nearest neighbor is still inert + redacted (secret gone) + bounded — semantic ranking changes only WHICH observation surfaces, never its (non-)authority. 5 tests. No new deps; `crustcore-index` is a sidecar (not in nano). No §7.3 contract files touched. | `claude/b3-vector-memory` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB nano (412.0 KiB, 51.5%; index sidecar) | Enforces 7 (retrieved docs untrusted, never authority), 2 (redact-then-bound before visibility — shared `build_bundle`), 11/§6.5 (bounded fragments/bundle; brute-force NN over bounded set); memory is retrieval not authority — none weakened |
| 2026-06-21 | v0.3 B4-sandbox-tiers | Implement tier-aware backend selection (B4.3) in `crustcore-sandbox`: made `ExecutionTier` `Ord` (variant order = isolation strength), added `SandboxBackend::provided_tier()` (default `Sandboxed`/Tier-2; microVM/Windows backends override), and `select_backend(required, &[backends])` — picks the least-over-isolating backend whose `provided_tier` MEETS `required`, else **refuses** (`NoBackend`); a Tier-3 task with only Tier-2 bwrap is refused, never downgraded (formalizes the hardcoded `docs/sandbox.md` §3 rule, inv 9). `run_command` now routes through `select_backend` — behavior unchanged (the existing `hostile_tier_is_refused_without_microvm` test still passes), and the Firecracker Tier-3 (`TODO(B4-firecracker-live)`) + Windows-native (`TODO(B4-windows-live)`) backends drop in by appending to the list + overriding `provided_tier`. 2 new tests (mock backends: meets-or-refuses-without-downgrade; prefers-least-over-isolation). **No new deps**; the VM/OS backend implementations + the `docs/sandbox.md` (§7.3 contract) update they require remain DEFERRED (separate serialized PR when they land). forbidden-deps confirms no VM/Windows dep in nano (+16 bytes, nano 412.0 KiB). No §7.3 contract files touched. | `claude/b4-sandbox-tiers` (PR) | Maintainer agent (Architect/Implementer) | +16 B nano (412.0 KiB, 51.5%; sandbox is in nano but pure-`process`) | Enforces 9 (every execution under an explicit sandbox; refuse-if-no-backend, never downgrade — now structural via `select_backend`), 19/20 (no VM/Windows dep in nano — forbidden-deps); none weakened |
| 2026-06-21 | v0.3 B5-autoloop | Implement the self-improvement loop runner (B5.1/B5.2) in `crustcore-daemon::selfimprove`: `run_cycle(proposal, changed_paths, &dyn EvalRunner)` drives the gated cycle end to end over the complete P15 core — run the proposal's evals via an `EvalRunner` seam (live: sandboxed P11-exec workers + real eval suite, `TODO(B5-autoloop-live)`; CI mock — a failed eval yields no `EvalRef`), require BOTH a demonstration and a regression guard (`ReadyProposal::prepare`), then contract-gate the changed paths (`plan_self_pr`). Returns only a decision: `CycleOutcome::DraftReady` (a DRAFT self-PR intent), `BlockedForMaintainer` (contract-touch → maintainer), or `NotReady` (evidence-free). **No kernel mutation, no self-merge** (inv 18): `CycleOutcome` has no Merged/Applied variant (structural), `ProposalTarget` still can't express weakening a guardrail, evidence-free can't advance, contract-touch is blocked. 3 tests (full-evidence→draft-only; evidence-free→can't-advance; contract-touch→blocked) — the silent-weakening/self-merge red-team. Live evals/PRs + multi-repo (B5.3) + hosted executor (B5.4) remain `TODO(B5-autoloop-live)`. No new deps (daemon-local). No §7.3 contract files touched. | `claude/b5-autoloop` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB nano (412.0 KiB, 51.5%; daemon sidecar) | Enforces 18 (self-improvement via PRs/evals, no live kernel mutation; no self-merge — `CycleOutcome` tops out at a draft), 13-analogue (evidence-gated advance via `ReadyProposal`), contract-gate (silent weakening blocked); none weakened |
| 2026-06-21 | v0.3 B6-release-infra | Implement reproducible builds (B6.2) in `xtask`: the nano build runs under a deterministic env (`reproducible_env` — `--remap-path-prefix` strips the workspace path + cargo home + rustup sysroot, `SOURCE_DATE_EPOCH=0`, `CARGO_INCREMENTAL=0`) which, with the `nano` profile (codegen-units=1/lto=fat/strip/panic=abort) + pinned `rust-toolchain.toml`, makes the build deterministic. New `cargo xtask reproduce` builds nano twice into independent target dirs + asserts the SHA-256 digests match — **ran it, it passed**. `nano_build` refactored to `nano_build_into(Option<&Path>)` so size-check/release/reproduce all measure the SAME reproducible binary; `run_env` added for env-bearing builds. `docs/releasing.md` §9 added. **Review: 8 found, 4 confirmed+fixed** — all the same overclaim (`reproduce` proves SAME-MACHINE determinism, not cross-machine "anyone can rebuild"): fixed by adding the rustup/sysroot remap (a real cross-machine variance source I'd missed) + rewriting §9 to honestly bound the claim (cross-machine bit-identity still needs a `1.x.y` toolchain-version pin — `stable` is a channel, not a pin — and the same target triple), reconciled with §2. No new deps; nano steady at 412.0 KiB (remap leaves the stripped binary size unchanged). **B6.1 (signed GH Actions release workflow) + B6.3 (cargo-bloat/fuzz CI jobs) edit `.github/workflows/**` — irreversible/CI-credentialed, MAINTAINER-OWNED (§6.3), not agent-wired; B6.4 TUI/packaging are separate non-nano artifacts.** No §7.3 contract files touched. **Final Track B phase.** | `claude/b6-release-infra` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB nano (412.0 KiB, 51.5%; xtask is build tooling, not linked) | Enforces auditability (reproducible bytes — verify, don't trust the signer), 19 (size gate measures the same reproducible binary); respects §6.3 (workflow/signing irreversible steps left to the maintainer); none weakened |
| 2026-06-21 | v0.4 Track C (C1–C7) | Add **Track C (compose & adopt)** — the RIG/ADK-Rust ergonomics track — to `docs/roadmap-v0.2.md`: seven fully-specified phases (C1-providers unified multi-modal provider registry; C2-toolmacro `#[crust_tool]` macro; C3-flow `crustcore-flow` typed workflow graph; C4-session session/artifact service; C5-rag `crustcore-index-rag`; C6-telemetry OTel/GenAI export; C7-devui `crustcore-dev` loopback UI), each with the full per-phase template (tasks + owned globs, deferral boundary, contract-file impact, adversarial-review dimensions, parallelization, risks, DoD, nano size impact), plus Track C front matter (intro, dependency waves C-1/C-2/C-3, cross-cutting principles, v0.4 DoD, out-of-scope) and four front-matter splices. **Drafted by a multi-agent workflow (8× design + adversarial review + synthesis), integrated by the supervisor**; review corrected real symbol inaccuracies (`crustcore-index::embed::Embedder` per B3; public `run_verify` not private `run_verify_with`; string-bound non-`Clone` `Tainted<T>`; `AuthorizedUser::approve` as sole `Approved<T>` minter; host-`MacKey` `ReceiptChain::mint`). Documentation/planning only — no code; reconciled with P7-live/B3/B6/P11-exec. Every Track C surface is a non-nano sidecar/feature-gated pack with zero nano impact, consumes existing contracts unchanged, defaults fail-safe, and cannot become a side-effect/completion/user-comms path. | `claude/polish-pass` (docs/planning) | Maintainer agent (supervisor + worker fleet) | n/a (docs only) | References 1–14, 16, 19, 20 (ergonomics must not widen the trust boundary); none weakened |
| 2026-06-21 | v0.4 C1-providers | Generalize `crustcore-net` completion routing into a unified multi-modal capability registry adding **embedding + rerank** without touching the frozen P7-live `Provider`/`Engine`/`select_candidates`/`apply_budget`/`run_reliable`/`BudgetLedger`. **Additive** `embeddings`/`rerank`/`embedding_dims` (default-off) flow through `ModelCard` (net) **and** `ModelInfo` (netproto) via `ModelCard::to_info` — completion routing byte-for-byte unchanged; conservative-off enforced at both the config parse and the wire decode (inv 17). New `modality.rs`: sibling `EmbedProvider`/`RerankProvider` traits + value types `EmbeddingRequest`/`Response` (bounded by `MAX_BATCH`) + `RerankRequest`/`Response` (bounded by `MAX_DOCS`), `select_candidates_for` (capability-gated, fail-closed) + `EmbedEngine`/`RerankEngine` sharing the **single** `BudgetLedger` across all three modalities (inv 11). Live adapters `embed.rs` (`/v1/embeddings`) + `rerank.rs` (Cohere/Jina + OpenAI `/v1/rerank`) over the `HttpClient` boundary (CI-tested via `ReplayClient`), per-call credential resolution (never stored), status-only `map_status_error`, and **rerank indices/scores treated as untrusted — out-of-range/duplicate dropped, non-finite sanitized, never propagated raw** (inv 7). New bounded wire variants `Request::Embed`/`Rerank` + `Response::Embedding`/`Ranking` + `NetHelper::embed`/`rerank` + a `MultiModalEngine`/`serve` that routes all three; deterministic `MockEmbedProvider`/`MockRerankProvider` + `default_mock_multimodal_engine` so the default/CI build links nothing new (the `UreqClient` path stays `live`-gated). Red-team `tests/redteam_c1_modality.rs` (10 tests) covers dims (a)-(g): credential never leaks through any embed/rerank error/garbage path, no panic/over-read, indices can't corrupt selection, capability-missing fails closed, omission can't flip a capability on, failing embedder emits no partial output. `docs/model-routing.md` §1.2 added; B3-vector-memory named as the `EmbedProvider` consumer. No new deps; `crustcore-net`/`-netproto`/`docs/model-routing.md` not §7.3 contract files; `forbidden-deps` + `size-check` green (nano 412.0 KiB, zero delta). | `claude/track-c-implementation` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB nano (412.0 KiB, 51.5%; net/netproto sidecars, live behind `live`) | Enforces 1-3 (credential per-call, never stored/logged/in sandbox env), 7 (provider bytes untrusted — bounded, no-panic, rerank indices clamped), 11 (one shared budget ledger; `MAX_BATCH`/`MAX_DOCS`/dims caps), 17 (capability default-off at config + wire decode, fail-closed routing), 19/20 (zero nano delta; live HTTP behind `live`); none weakened |
| 2026-06-21 | v0.4 C5-rag (C5.1–C5.8) | Add `crustcore-index-rag`, a NEW optional OFF-NANO pack that generalizes B3-vector-memory into a composable RAG layer WITHOUT widening the trust boundary (memory is never authority). Modules: `store` (pluggable `VectorStore` adapter trait — `upsert`/`nearest(query, k, floor)`/`delete`/namespace, **retrieval-only, grants nothing**; `ChunkMeta { path, byte_span, symbol, source: MemorySource, redact_required }` is a **pure data tag with NO capability/approval field** so memory-as-authority is unrepresentable; `k` capped to `MAX_NEAREST_K`, returned hits to `MAX_STORE_HITS`); `store::local` (DEFAULT dependency-free backend over `crustcore-index`'s in-memory set, reusing `crustcore_index::embed::cosine` verbatim, preserving `VectorMemory` semantics — positively-similar only, descending score with deterministic insertion-order ties — plus an explicit floor; persistence = `TODO(C5-persist)`, off-by-default `persist` feature); `store::mock` (`MockVectorStore` for CI, can return oversized payloads / NaN-inf / forged-duplicate `ChunkId`s to test the planner's guards); `store::qdrant`+`store::lancedb` (thin adapters, each behind its OWN off-by-default cargo feature, auth via `crustcore_secrets::CredentialProxy` only — key never to model/sandbox env; real client `TODO(C5-<backend>-live)`); `chunk` (bounded line-oriented `Chunker` with overlap, **defaults to whole-line, bounded, deny-large** — every fragment `<= MAX_CHUNK_BYTES`, giant lines split at UTF-8 boundaries, per-file/per-call fan-out capped, `redact_required=true`+`symbol=None` defaults); `chunk::symbol` (symbol-aware metadata via the EXISTING `crustcore_index::CodeIntel`/`GrepCodeIntel` — aligns boundaries to symbol spans, tags `ChunkMeta.symbol`; **conservative line-chunk fallback is the DEFAULT** when symbol info is absent [fail-closed]; malformed/inverted/OOB spans sanitized; tree-sitter `TODO(C5-ast)` behind off-by-default `ast`); `plan` (`QueryPlanner` trust chokepoint — embed the bounded query via the B3-owned `crustcore_index::embed::Embedder`, bounded `RetrievalPlan { namespace, k (capped), floor }`, run store NN, dedup forged ids, then push every hit through the EXISTING `semantic_select` redact-then-bound boundary [`Redactor` + `MAX_CONTEXT_*` caps] → a `ContextBundle` of inert provenance-tagged fragments; store score NOT trusted, `semantic_select` re-ranks by cosine so a NaN/forged score can't reorder/smuggle); `index` (`index_repo` — chunk→embed→upsert, all bounded, **write-to-store only**: returns an opaque `IndexedContent` resolver, no content to model context; live indexer reads via confined paths). Reused verbatim (never re-implemented): `Embedder`/`HashEmbedder`/`cosine`/`VectorMemory`/`semantic_select`/`build_bundle`/`CodeIntel`/`GrepCodeIntel` + `crustcore_secrets::{Redactor, CredentialProxy}`. Seams: `TODO(B3-embed-live)` (`live`), `TODO(C5-ast)` (`ast`), `TODO(C5-persist)` (`persist`), `TODO(C5-<backend>-live)` (`qdrant`/`lancedb`). 24 deterministic CI tests (13 unit + 5 `rag.rs` + 6 `redteam_rag.rs`): fragment bounding incl. giant-line/multibyte; ast-off line-chunk fallback always exercised; symbol alignment to `CodeIntel` spans; local backend matches `VectorMemory`; planner caps `k`+floor+redacts+bounds; precision@1 eval over a canned corpus meets a 3/4 floor; deterministic across runs. **Red-team:** the B3 `sk-VECSENTINEL` hostile chunk ranked nearest stays inert+redacted+provenance-tagged with no `Approved<T>` path — through the planner over BOTH local backend AND `MockVectorStore`; a malicious backend (10k oversized hits + NaN/inf/negative scores + forged duplicate ids) does not bypass bounding or panic; missing classification fails closed; indexing write-to-store only. Dims (a)–(g) covered. Workspace `Cargo.toml` touched additively only (1 member + 1 internal path dep). Default build links zero third-party crates; `forbidden-deps` green (`crustcore-index-rag` + store SDKs absent from nano graph); nano unchanged (zero delta). | `claude/track-c-implementation` (PR) | Maintainer agent (Architect/Implementer) | n/a (412.0 KiB, 51.5%; non-nano pack; store SDKs/`ast`/`live`/`persist` feature-gated, off nano graph) | Enforces 3 (store-backend creds via `CredentialProxy` only, never model/sandbox env), 7 (indexed content untrusted — a hostile chunk stays inert data), 11 (bounded everything — chunk/query/`k`/hits/files/chunks + the `MAX_CONTEXT_*` bundle caps), 20 (external-store SDKs + `ast`/`live` feature-gated, zero nano linkage); plus memory-never-authority by construction (no path from `ChunkMeta`/fragment to `Approved<T>`/capability — red-team (a)); none weakened |
| 2026-06-21 | v0.4 C6-telemetry (C6T.1–C6T.8) | Add `crustcore-telemetry`, a NEW non-nano sidecar crate that projects CrustCore's already-authoritative audit trail (hash-chained `crustcore-eventlog` + MAC-chained `crustcore-receipts`) into OTel/GenAI-semconv spans & metrics — a READ-ONLY projection that mints nothing, mutates no state, and is never authoritative (the event log stays the single source of truth; a deleted/altered span can't affect a verdict/budget/`VerifiedPatch`). Modules: `project` (`EventProjector` — pure, sync, SDK-free mapper from a borrowed `FrameMeta` + joined `ToolReceipt` to a neutral `SpanModel`/`MetricSample` IR; deterministic, idempotent, reads typed fields not payload); `semconv` (the `EventKind`→span/metric table — model frames → `gen_ai.*` with `gen_ai.system=crustcore` + operation [conservative, no model name/usage from untrusted output, inv 17]; `ToolCall*`+receipt → `crustcore.tool.*` with receipt hashes/MAC/ids only [never values, inv 10]; `Patch*` → `crustcore.verify.*`; budget deltas → `crustcore.budget.<axis>` metrics; **NAMES from the closed `EventKind`/`BudgetAxis` enums via exhaustive `match`, never payload** [inv 6, 7]); `redact` (the SOLE emission chokepoint — every attr value + metric label through `Redactor::redact`, then `MAX_ATTR_LEN`/`MAX_ATTRS` bounding [after redaction, drop-with-marker], `redact_frame` is the only IR→exporter path); `export` (`Exporter` trait consuming ONLY post-redaction IR, `InMemoryExporter` CI default, `OtlpExporter` behind `otlp` feature, real socket `TODO(C6-otlp-live)`); `auth` (`OtlpEndpointAuth` holds only a `SecretHandle`; `otlp`-gated `inject` resolves the bearer per-request via `SecretBroker`→`ApprovedSecretView`→`CredentialProxy::bearer`, never env/span/model-visible [inv 1]); `run` (`run`/`run_log` driver — range-filtered frames, receipt↔log join via P5-join's `verify_against_log` [consumed not re-implemented], project→redact→export, `batch_bound`/`sample_rate` bounded, Internal/`Redacted` frames emit only kind+seq, `enabled=false` default fail-closed); `config` (opt-in, default OFF, in-memory exporter, loopback collector, bounded batch). 43 deterministic CI tests (29 unit + 10 integration + 4 red-team) over synthetic `EventLog`+receipt fixtures: span-name/attr mapping, count/length bounding, Internal+`Redacted` emit no payload-derived attrs, read-only (log bytes/head unchanged, idempotent), forged receipt seq doesn't bind, **C6T.7 leak-canary** (sentinel `sk-LEAKCANARY-7f3a` in payloads + a `Tainted<T>` frame + a `Redacted` frame → NO sentinel in any span attr/metric label/span name/metric name, `would_leak` false on every emitted string). Adversarial dims (a)–(g) covered. Workspace `Cargo.toml` touched additively only (1 member + 1 internal path dep). Default build links zero third-party crates; `forbidden-deps` green (telemetry/OTel/Tokio/HTTP absent from nano graph); `size-check` green (nano 412.0 KiB, zero delta). | `claude/track-c-implementation` (PR) | Maintainer agent (Architect/Implementer) | n/a (412.0 KiB, 51.5%; non-nano sidecar; OTel/OTLP SDK behind `otlp`, off nano graph) | Enforces 1 (OTLP endpoint credential broker-mediated per-request, never env/span/model-visible), 2/3 (every attr/label through `Redactor` at the single chokepoint; `Tainted<T>` dropped not declassified; leak-canary asserts names+values), 7 (frame payload untrusted — span/metric names from the closed `EventKind` enum only), 11 (`MAX_ATTRS`/`MAX_ATTR_LEN`/`batch_bound` caps, drop-with-marker), 20 (OTel SDK feature-gated, zero nano linkage); plus read-only/never-authority (6, 13 — no path mints a receipt/budget/`VerifiedPatch`); none weakened |
| 2026-06-21 | v0.4 C4-session (C4.1–C4.7) | Add `crustcore-session`, a NEW non-nano crate giving the daemon/`crustcore-flow`/dev-UI an application-level session model as a redacted, verify-or-refuse **VIEW over the hash-chained event log — never a competing store** (the event log stays the single source of truth). Modules: `id` (opaque `SessionId`/`ConversationId`); `view` (borrowing `SessionView` indexing an `EventLog` by `task_id`/`job_id`/`seq` range via `EventFrame`/`iter`, plus `ConversationView` over turn frames — never copies the chain, exposes no completion/integration method); `snapshot` (`Snapshot { at_seq, head_hash, turns }` projected up to a `seq`, including ONLY `Visibility::ModelVisible` frames — Internal/unclassified excluded FAIL-CLOSED via a positive match — redactor-per-field, structurally no `SecretMaterial`/`Tainted<T>` field [inv 3], `Serialize` for disk persistence with serde, reloaded snapshot UNTRUSTED until `verify_against` re-checks `head_hash` via `verify_to_head`); `resume` (`resume`/`resume_to_head` gate on `EventLog::verify`/`verify_to_head` AND `crustcore_receipts::join::verify_against_log`, returning a view only when `is_intact()` AND `is_joined()`, else `ResumeRefused` carrying the exact `BreakReason`/`JoinBreak`; mutates no kernel state [inv 13, 18]); `lease` (re-derives lease/heartbeat/cancellation/recovery from `JobLeased`/`TaskKilled`/`TaskFailed` frames, ASSERTS ownership via `owned_by`, surfaces kill/cancel [inv 12]); `artifact` (opaque `ArtifactHandle(ArtifactId)`, contents NEVER inlined, `BoundedArtifact` capped accessor for trusted code only [inv 20]); `compact` (`CompactionPolicy` keep-last-N/summarize/drop-bulk redact-then-bound, `MAX_*` caps mirroring `crustcore-index`, never-authority `ModelVisibleText`, default = most restrictive [inv 7, 11]); `service` (`SessionService` open/snapshot/resume/compact/list, strictly READ/DERIVE/VERIFY-ONLY — no `Approved<T>`/`VerifiedPatch`/capability/side-effect method, enforced by construction since the crate doesn't depend on `crustcore-backend`/`-policy`; completion stays solely `verify::run_verify`, stated as an explicit non-goal). Serde bridges for the external std-only `crustcore-types` ids live in a sidecar-local `serde_compat` module so serde stays off the nano graph. 64 deterministic CI tests (41 unit + 14 integration + 9 red-team) over synthetic + a committed on-disk fixture (`fixtures/clean_session.cclog`, `examples/gen_fixture.rs`): snapshot round-trip + `head_hash` re-verify; fail-closed visibility; every event-log tamper class + every forged-receipt `JoinBreak` → exact `ResumeRefused`; compaction within caps; artifact opacity; red-team (a)–(h). Workspace `Cargo.toml` touched additively only (1 member + 1 internal path dep). `cargo xtask forbidden-deps` green; nano untouched (no `crustcore-session`/serde in the nano graph). | `claude/track-c-implementation` (PR) | Maintainer agent (Architect/Implementer) | n/a (412.0 KiB, 51.5%; non-nano sidecar; serde/serde_json off the nano graph) | Enforces 3 (no secret in snapshot — structural, redactor-per-field), 7 (untrusted history is data; compacted history never-authority), 11 (bounded compaction/artifact reads), 12 (lease/heartbeat/cancellation/recovery re-derived, asserted not claimed), 13 (session never completes/integrates/mints a VerifiedPatch), 18 (resume reconstructs a view, mutates no kernel state), 20 (artifacts by opaque handle, contents never inlined); none weakened |
| 2026-06-21 | v0.4 C3-flow (C3.1–C3.8) | Add `crustcore-flow`, a NEW non-nano sidecar crate giving a typed, deterministic workflow DSL over the existing supervisor/subagent/verify primitives WITHOUT widening the trust boundary — **a Flow is a plan, not an authority**. Modules: `graph`+`builder` (`Node` enum [`Model`/`Tool`/`Verify`/`Review`/`Parallel`/`LoopUntil`/`Route`/`Join`/`End`], opaque `NodeId`, typed `FlowState` [predicates read this and ONLY this], `FlowError`, `Flow::validate`; `FlowBuilder` whose constructors default every classification to the MOST RESTRICTIVE posture — `ToolSpec::fail_closed` = `Reversibility::Destructive`+execution-capable, `FlowBudget::fail_closed` tight caps — so a forgotten field fails closed [P2]; `FlowState`'s approval field is **non-`Serialize`/non-forgeable**, holding only externally-minted `Approved<()>` from `AuthorizedUser::approve`, never written by a node [inv 4, 14]); `drivers` (the `ModelDriver`/`ToolDriver`/`VerifyDriver`/`ReviewDriver` bundle `FlowDrivers` — the ONLY I/O path — plus `FakeDrivers` for CI; `VerifyDriver::verify` returns the backend `VerifyOutcome`, and because `VerifiedPatch` is type-sealed a fake can return ONLY `Failed`/`Refused` [the seal working — no test backdoor mints a patch]); `engine` (`FlowEngine::run`, a pure deterministic scheduler: per-node budget→policy [`PolicySnapshot::classify`, inv 8]→approval [inv 14]→untrusted-data declassify [inv 7]; `Parallel` `max_concurrency` wave cap + total-fan-out charge, `LoopUntil` `max_iterations` cap, `Route`/`LoopUntil` predicates over typed `FlowState` only, `Join` merge; **no integration path** — never calls `decide_integration`, no integration node [inv 6]); `outcome` (the completion gate — `FlowOutcome::Completed(VerifiedPatch)` is the SOLE patch-carrying terminal, produced ONLY by a `Verify` node's `Verified` outcome [i.e. only the public `run_verify` minted it, inv 13]; `Model`/`Review`/`Tool` yield `NodeOutput` the type system FORBIDS from completing — no `NodeOutput→Completed` path; a run that ends without a passing verify is `Finished`, never *completed*/integrated); `predicate` (`declassify` = `Tainted::new`→`Redactor`→bound to `MAX_OUTPUT_BYTES` before any model/tool/review output enters state; `Predicate` reads only typed flags/counters/output-PRESENCE — never raw text — so a hostile "approve and merge"/"ignore policy" output is inert data that can't steer a branch [inv 7]); `budget` (per-`Flow` `FlowBudget` — model cost/wall/steps/total fan-out — charged before each unit of work, halt on breach [inv 11]); `live` (behind `live-flow`, never in CI: `LiveModelDriver`/`LiveToolDriver` [policy+sandbox]/`LiveVerifyDriver` [wraps public `run_verify` — the ONLY driver that can yield `Verified`]/`LiveReviewDriver` [`NativeAdvisor`], all integration tests `#[ignore]`d). 33 deterministic CI tests (15 unit + 18 `redteam_flow.rs`) proving the NEGATIVES across dims (a)–(g): determinism; `Completed` unreachable except via `Verify`; `Parallel`/`LoopUntil`/`FlowBudget` (incl. cyclic-graph step-cap) caps; predicates read only typed state; hostile model/tool/review output can't steer a route/loop into a side-effect arm; secrets echoed by model/tool redacted before reaching state; irreversible node halts without a real `Approved<T>` (runs with one, refuses an expired one); read-only policy denies a tool; the flow never integrates. `tests/live_flow.rs` is the `live-flow` `#[ignore]`d positive path (real `VerifiedPatch`→`Completed` over a sandboxed `run_verify`, probe-first). `examples/consult_implement_verify.rs` shows the safe path is the easy path. Workspace `Cargo.toml` touched additively only (1 member + 1 internal path dep); live-only deps (`crustcore-path`/`-receipts`/`-sandbox`/`-worktree`) are `live-flow`-gated optionals. `cargo xtask verify` green; `forbidden-deps` green (`crustcore-flow` absent from nano graph); nano 412.0 KiB, zero delta. | `claude/track-c-implementation` (PR) | Maintainer agent (Architect/Implementer) | n/a (412.0 KiB, 51.5%; non-nano sidecar; live drivers `live-flow`-gated, off nano graph) | Enforces 13 (`Completed`/`VerifiedPatch` reachable only via a `Verify` node's public `run_verify`; no node fabricates evidence — type-sealed), 4/14 (irreversible nodes need a non-forgeable `Approved<T>`; no node mints/forges one; `FlowState` approval field non-`Serialize`), 7 (untrusted node output `Tainted`+redacted+bounded before a predicate; predicates read typed state only), 8/9 (tool nodes pass `classify`; execution-capable ones pass a sandbox profile live), 5/6 (advisory model/review output never reaches the user, flow never integrates — `decide_integration` stays the supervisor's authority), 11 (per-`Parallel` fan-out cap, per-`LoopUntil` iteration cap, per-`Flow` budget); none weakened |
| 2026-06-21 | v0.4 C7-devui (C7.1–C7.7) | Add `crustcore-dev`, a NEW non-nano crate (also intended as `crustcore-daemon serve`) serving a **loopback-only, read-only-by-default local developer/inspection UI** built fail-safe so it CANNOT become a back door. **Core/`serve` split:** a PURE deterministic CORE (default features — no axum/tokio/hyper) holding ALL the security logic and exercised in CI over a `MockDevBackend`, plus a thin `serve` feature that wires the real axum/hyper loopback server (axum/tokio are OPTIONAL deps enabled only by `serve`; the default build and the nano graph link none). Modules: `backend` (the `DevBackend` decoupling trait split into TWO disjoint capability traits — `ReadOnlyBackend` [inspector/replay/provider/MCP/flow/session view models, every method borrows, none mints/writes/appends/verifies] and `MutatingBackend` [the single side-effecting op]; a read handler gets `&dyn ReadOnlyBackend` with NO method returning a `MutatingBackend`, so reaching a side effect from a read view is a COMPILE ERROR — proven by a `compile_fail` doctest; `MockDevBackend` the CI fake, flat redacted view models carrying no live/secret types); `request`/`route_class` (transport-agnostic `DevRequest` with every untrusted field length-bounded+validated and unknown verbs rejected at the door [inv 7]; `RouteClass` ReadOnly/Mutating split + route table with assets/ws registered so auth covers them); `auth` (per-launch 256-bit `BearerToken` [OS-CSPRNG in `serve`], required on EVERY route, constant-time compared, redacted in `Debug`, never in a response/log); `config` (loopback `127.0.0.1` default; off-loopback incl. `0.0.0.0`/`::` is an explicit WARNED opt-in via `bind_host(..,acknowledge_exposure=true)` else fails closed; mutation off unless explicitly unlocked); `views::inspector`/`replay` (read-only over `EventLog::inspect`/`verify`/`iter` + P5-join `verify_against_log`/`FrameRef`; reports `Intact`/`Broken`, respects `visibility`/`redaction_state`, inlines no payload, artifacts by id); `views::provider` (renders `ModelCardView`/usage metadata only — never a key, redactor on every field; live probe/complete via the spawned net helper is `TODO(C7-serve-live)`); `views::mcp` (gate decisions from `gateway_check`/`tool_policies` + manifest-drift — NEVER server self-description); `views::flow` (loads a C3 `Flow` and SIMULATES single-stepping with a no-op driver — dispatches no `Action`, appends no frame, never reaches `run_verify`, mints no `VerifiedPatch`); `views::approvals` (surfaces pending approvals read-only); `mutation` (the approval/mutation gate + the single request-dispatch chokepoint auth→loopback→classify→read-vs-gated-mutate; a resolution is dispatched into the EXISTING `crustcore_daemon::telegram::ApprovalEngine` where `AuthorizedUser::approve` is the sole `Approved<T>` minter — the UI never constructs an `Approved<T>` and a resolution is operation-bound [op-hash] so it can't approve a different op than shown; mutating routes refuse without the launch flag); `serve`/`serve_entry` (feature-gated axum loopback server mapping HTTP→the core `route` chokepoint, plus the `crustcore-daemon serve` alias entry — alias enabled here, daemon-CLI wiring noted as a follow-up since editing the daemon's tree was out of scope this pass). 65 deterministic CI tests (46 unit + 18 `redteam_devui.rs` + 1 `compile_fail` doctest) over `MockDevBackend` — no axum/net/secrets — covering adversarial dims (a)–(g). Workspace `Cargo.toml` touched additively only (1 member + 1 internal path dep). `cargo xtask forbidden-deps` green (`crustcore-dev`/axum/tokio/hyper absent from the nano graph); nano 412.0 KiB, zero delta. | `claude/track-c-implementation` (PR) | Maintainer agent (Architect/Implementer) | n/a (412.0 KiB, 51.5%; non-nano sidecar; web stack `serve`-gated, off nano graph) | Enforces 4/14 (UI never mints `Approved<T>`; resolutions dispatched into the existing operation-bound `AuthorizedUser::approve` engine, op-hash binds the resolution, mutating routes off by default), 7 (all browser input bounded+validated; server/MCP/repo/graph content untrusted), 8 (`RouteClass`/two-trait split makes a side effect from a read view a compile error), 9/13 (read paths never reach `run_verify`/mint a `VerifiedPatch`; flow debugger only simulates), 15/16 (no free-text path to model/user — typed views only), 20 (web stack feature-gated, zero nano linkage); none weakened |
| 2026-06-21 | v0.4 C2-toolmacro (C2.1–C2.8) | Add the `#[crust_tool]` tool-authoring macro as two NEW non-nano crates that consume the policy/secrets/receipts/types contracts UNCHANGED — making the safe path the easy path (P2). **`crustcore-toolkit`** (std-only, zero new third-party runtime deps) holds the real safety logic so it is testable without the macro: `CrustTool` trait, `ToolOutcome { visible: ModelVisibleText, .. }` (the ONLY visible channel — sole constructor `Redactor::to_model_visible`), `ToolSchema`/`SchemaType` (`is_concrete()` rules out `Any`), bounded `ToolArgs`, `ToolError` (`Input/OutputTooLarge`), and the host-side `finalize`/`HostTool::emit` doing the fixed order **redact → bound (refuse-on-overrun) → mint receipt over the EXACT shown bytes** (HOST owns the `MacKey`/`ReceiptChain`, passed by `&mut`; generated code never holds a key, calls `mint`, or names `Approved`/`AuthorizedUser`). **`crustcore-tool-macro`** (proc-macro; `syn`/`quote`/`proc-macro2` BUILD-TIME ONLY) derives the schema from the typed signature (String/ints/bool/`Option<T>`/`Vec<T>`; UNSUPPORTED type = HARD COMPILE ERROR, never `Any`), defaults `default_reversibility()` to the most restrictive `Destructive` unless explicitly downgraded (unknown value = hard error), wires `invoke` through the toolkit `finalize`, and emits a per-tool `#[cfg(test)]` safety fixture. Tests are the gate (`toolkit/tests/safe_path.rs` 9 + unit 4; `macro/tests/generated_tool.rs` 8 + 8 generated fixtures = 16); `compile_fail`/trybuild bypass tests (`tests/compile_fail.rs` + `tests/ui/*` — unsupported type, unknown reversibility, self-authorize symbol, missing host, non-Result return) are gated behind a `trybuild` feature and OFF in default `cargo test --workspace`. **C2.7 migration of a live pack tool DEFERRED (approved scoping)** to keep blast radius small — representative end-to-end examples ship instead (`toolkit/examples/safe_tool.rs`, `macro/examples/crust_tool_demo.rs`). Workspace `Cargo.toml` gained 2 members + 2 internal path deps (additive). `ReceiptParams` fields used exactly: `task_id`/`job_id`/`tool_call_id`/`tool_name`/`args`/`result`(redacted+bounded)/`artifacts`/`event_seq`. `forbidden-deps` + `size-check` green; nano 412.0 KiB, zero delta (no toolkit/macro/syn/quote/proc-macro2 in the nano graph). | `claude/track-c-implementation` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB nano (412.0 KiB, 51.5%; both crates non-nano; proc-macro deps build-only) | Enforces 2/10 (every model-visible result redacted-then-receipted; `ModelVisibleText`-only channel; receipt binds the final bytes), 11 (bounded I/O, refuse-on-overrun), 4/8 (generated code routes the decision through `classify`, never inlines it, never constructs `Approved<T>`), 1/3 (host-owned `MacKey`, no secret in visible output), 7 (args untrusted), 19/20 (zero nano delta; proc-macro deps build-time only); none weakened |

---

## Release history

_No releases yet. CrustCore v0.1 targets the definition of done in
[`ROADMAP.md` §22](./ROADMAP.md) and [`CLAUDE.md` §2.2](./CLAUDE.md)._

<!--
Template for a future release section:

## [0.1.0] - YYYY-MM-DD

### Added
### Changed
### Fixed
### Security

### Agent Log
| Date | Phase/Task | Change | PR / Branch | Agent / Role | Nano Δ | Invariants |
| --- | --- | --- | --- | --- | --- | --- |
-->
