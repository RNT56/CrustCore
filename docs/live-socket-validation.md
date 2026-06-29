# docs/live-socket-validation.md — Live-Socket Validation Runbook

> **Status:** maintainer-ready checklist. The tests catalogued here already exist
> in the tree behind `#[ignore]`; this document is the *map* of what each one
> needs to run for real. It is **documentation, not code** — nothing here changes
> the trust boundary, and every entry stays green-by-default in CI because the
> socket-touching half is `#[ignore]`d.

CrustCore's CI gate proves the **decision cores** of every capability: the
mapping, framing, redaction, bounding, and policy logic all run socket-free and
deterministic on every PR. What CI *cannot* run is the irreducible last inch —
a real provider key, a GitHub App, a sandbox backend, a vector DB, an OTLP
collector, a Telegram token. Each of those inches is sealed behind one
`#[ignore]`d "live" test and a `TODO(*-live)` marker.

This runbook enumerates every such seam so that *validating CrustCore against
real infrastructure is systematic rather than exploratory*. For each seam it
records: the feature gate + test name, the irreducible socket it exercises, the
CI-testable core that already passes, prerequisites, the exact validation
command, success criteria, and risk/difficulty.

A CI lint (`scripts/validate_live_socket_runbook.sh`, wired as
`cargo xtask runbook-check`) greps the tree for every `#[ignore = "…"]` test and
every `TODO(*-live)` tag and **fails if one is missing from this file**, so the
runbook cannot silently go stale.

---

## Quick start

```sh
# The cores — every PR runs these; no infra, fully deterministic, must be green:
cargo test --workspace
cargo xtask verify          # fmt + clippy + tests + forbidden-deps + size gate + runbook-check

# A single live seam — supply the infra it names, then run it with --ignored:
CRUSTCORE_<VAR>=… cargo test -p <crate> --features live <test_name> -- --ignored --nocapture

# Confirm what is still gated (lists every ignored test without running it):
cargo test --workspace -- --list --ignored
```

> **Trust rules while validating (unchanged from the cores):** secrets enter
> only through the broker / env, never argv or logs (invariants 1–3); a live run
> still completes a task *only* from a `VerifiedPatch` (invariant 13); irreversible
> actions still need an `Approved<…>` token (invariant 14). A live test that would
> require relaxing any of these is a bug in the test, not the kernel.

---

## Validation matrix

| Test | Cat. | Feature | Section | CI core status | Difficulty |
| --- | --- | --- | --- | --- | --- |
| `live_smoke` (net live_adapters) | A | `live` | [A.1](#a1) | mock multimodal engine ✓ | easy (provider key) |
| `live_advisor_round_trip_smoke` | A | `live` | [A.2](#a2) | `NativeAdvisor` over injected fn ✓ | medium (helper + key) |
| `net_embedder_over_a_spawned_sidecar` | A/D | — | [A.3](#a3) | deterministic hash embedder ✓ | medium (embed provider) |
| `live_installation_token_smoke` (net) | B | `live` | [B.1](#b1) | JWT assembly + argv parse ✓ | medium (App key) |
| `live_installation_token_smoke` (daemon) | B | `live` | [B.1](#b1) | `mint_installation_token` glue ✓ | medium (App key) |
| `app_onboarding_live_smoke` | B | `live` | [B.1](#b1) | redirect→cap→register→approve→config core ✓ | medium (App install) |
| `gh_live` | B | `live` | [B.2](#b2) | canned-REST request rendering ✓ | easy (PAT) |
| `live_serve_webhooks_once_round_trip` | B | `live` | [B.3](#b3) | HMAC verify + bound + dedup ✓ | medium (port + POST) |
| `live_draft_pr_post_smoke` | B/F | `live` | [B.4](#b4) | eval→contract gate→`draft_pr_request` ✓ | hard (patch+approval+token) |
| `cred_proxy_live_push_smoke` | B | — | [B.5](#b5) | argv-parse + validate_push + cred-request authorize ✓ | hard (token+repo+worktree) |
| `draft_pr_live_post_smoke` | B | `live` | [B.6](#b6) | `pr_intent_to_create_request` mapping + non-2xx typed errors ✓ | medium (token+repo) |
| `ci_monitor_live_poll_smoke` | B | — | [B.8](#b8) | `aggregate_check_runs`/`monitor_decision`/`repair_task_goal` ✓ | medium (PR with checks) |
| `live_evidence_render_append_smoke` | B | — | [B.7](#b7) | `to_markdown`/`to_json` bounded evidence render ✓ | medium (draft PR + token) |
| `live_worktree_executor_accepts_only_verifier_evidence` | C | `live` | [C.1](#c1) | scheduler/budget/verifier-owned accept ✓ | medium (sandbox+git) |
| `run_one_task_completes_only_on_verifier_evidence` | C | `live` | [C.2](#c2) | task lifecycle decision core ✓ | medium (sandbox+git) |
| `live_verify_node_completes_only_on_a_real_verified_patch` | C | — | [C.3](#c3) | flow graph w/ mock verify driver ✓ | medium (sandbox+git) |
| `live_bundle_still_enforces_the_approval_gate` | C | — | [C.3](#c3) | approval-gated bundle core ✓ | medium (sandbox+git) |
| `live_grep_lines_on_this_repo` | C | — | [C.4](#c4) | arg build + output parse ✓ | easy (git repo) |
| `live_list_files_on_this_repo` | C | — | [C.4](#c4) | arg build + output parse ✓ | easy (git repo) |
| `live_parse_test_manifest_reads_a_real_manifest` | C | — | [C.5](#c5) | pure `parse_test_manifest` over text ✓ | easy (a repo file) |
| `live_executor_wire_smoke` | C | — | [C.6](#c6) | `plan_task`/`finalize_task` route+gate cores ✓ | hard (sandbox+repo) |
| `live_insert_query_delete_roundtrip` (lancedb) | D | — | [D.1](#d1) | in-memory store roundtrip ✓ | medium (LanceDB) |
| `live_upsert_search_delete_roundtrip` (qdrant) | D | — | [D.2](#d2) | in-memory store roundtrip ✓ | easy (docker qdrant) |
| `live_post_to_loopback_collector` | D | — | [D.3](#d3) | OTLP/GenAI payload assembly ✓ | easy (docker otel) |
| `live_post_with_broker_bearer` | D | — | [D.3](#d3) | payload + broker-bearer wiring ✓ | medium (otel + secret) |
| `http_round_trips_against_a_live_server` | E | — | [E.1](#e1) | JSON-RPC framing + trust rules ✓ | medium (MCP server) |
| `stdio_round_trips_a_framed_response` | E | — | [E.2](#e2) | stdio framing ✓ | easy (POSIX shell) |
| `live_get_updates_smoke` | F | `live` | [F.1](#f1) | `RestTelegram` shaping + redaction ✓ | easy (bot token) |
| `live_telegram_round_trip_smoke` | F | `live` | [F.2](#f2) | runtime-channel decision logic ✓ | easy (bot token) |
| `live_ws_sse_emits_a_snapshot` | F | — | [F.3](#f3) | snapshot serialize + `ws_stream` ✓ | easy (loopback port) |

---

## A. Model / provider keys

<a id="a1"></a>
### A.1 — `live_smoke` — real provider transport
- **Test:** `crustcore-net/tests/live_adapters.rs::live_smoke`, feature `live`.
- **Socket:** HTTPS to a real provider (Anthropic / OpenAI / compatible).
- **CI core (passing):** the mock multimodal engine
  (`crustcore_net::default_mock_multimodal_engine`) round-trips chat / embed /
  rerank with the same request/response shaping and redaction.
- **Prereq:** a provider key in env (e.g. `ANTHROPIC_API_KEY` / `OPENAI_API_KEY`)
  and a `--providers <config.json>` that names it; outbound network.
- **Run:** `cargo test -p crustcore-net --features live --test live_adapters live_smoke -- --ignored --nocapture`
- **Success:** a non-empty completion returns; no key bytes appear in any log
  line (grep the `--nocapture` output for the key — must be absent).
- **Risk:** cost (real tokens); a flaky provider. Difficulty: **easy**.

<a id="a2"></a>
### A.2 — `live_advisor_round_trip_smoke` — advisor over the spawned net helper
- **Test:** `crustcore-daemon/src/advisor.rs::live_advisor_round_trip_smoke`, feature `live`. Seam tag `TODO(P12-native-live)`.
- **Socket:** the spawned `crustcore-net` helper process + a provider behind it.
- **CI core (passing):** `NativeAdvisor` over an injected `consult` fn —
  advisory-not-policy preserved, untrusted model text redacted before it informs
  any decision.
- **Prereq:** the net helper discoverable (`CRUSTCORE_NET_HELPER=<path>` or
  `crustcore-net` on `PATH`), a provider key, and `--providers`.
- **Run:** `cargo test -p crustcore-daemon --features live advisor::tests::live_advisor_round_trip_smoke -- --ignored --nocapture`
- **Success:** the advisor returns a routed suggestion; the response is treated as
  advice (no side effect, no approval) — confirm the decision path still gates on
  policy. **Difficulty: medium.**

<a id="a3"></a>
### A.3 — `net_embedder_over_a_spawned_sidecar` — embeddings over the sidecar
- **Test:** `crustcore-index/src/embed.rs::net_embedder_over_a_spawned_sidecar`. Seam tag `TODO(B3-embed-live)`.
- **Socket:** a spawned `crustcore-net` sidecar with a *live embedding provider*.
- **CI core (passing):** the deterministic hash embedder produces stable vectors
  through the same `EmbedProvider` contract.
- **Prereq:** net helper + an embedding-capable provider key + `--providers`.
- **Run:** `cargo test -p crustcore-index net_embedder_over_a_spawned_sidecar -- --ignored --nocapture`
- **Success:** vectors of the expected dimension return for a batch; cross-listed
  in [D](#d-vector--embedding--telemetry) because it also feeds the vector stores.
  **Difficulty: medium.**

---

## B. GitHub (App credentials · REST · webhook)

<a id="b1"></a>
### B.1 — `live_installation_token_smoke` — App → installation token mint
- **Tests:** `crustcore-net/src/githubapp.rs::live_installation_token_smoke` and
  `crustcore-daemon/src/github.rs::live_installation_token_smoke`, feature `live`.
  Seam tag `TODO(B2-gh-app-live)`.
- **Socket:** GitHub's App-JWT → installation-token endpoint over HTTPS.
- **CI core (passing):** JWT assembly, the git credential-helper argv parser
  (`github::parse_push_argv`), and token-shape handling — all socket-free.
- **Prereq:** a GitHub App private key (PEM) provisioned **through the broker**
  (never argv), the App id, and an installation id on a test repo.
- **Run:** `cargo test -p crustcore-net --features live githubapp::tests::live_installation_token_smoke -- --ignored --nocapture`
  (and the daemon-side variant analogously).
- **Success:** a short-lived installation token is minted and is usable for a
  scoped REST call; the PEM never appears in logs. **Difficulty: medium.**
- **Onboarding (A.1) — `app_onboarding_live_smoke`** (`crustcore-daemon/src/onboarding.rs`,
  feature `live`, seam tag `TODO(app-onboarding-live)`): the full install path —
  capture the redirect, confirm `GET /app/installations/{id}`, register the repo,
  mint the `Approved<GitHubWriteCap>`, then mint the installation token. CI core:
  `cap_from_redirect` / `onboard` / `TokenLease::needs_refresh` / `load_profile` all
  pass socket-free. Prereq: a registered test App + `CRUSTCORE_GH_APP_ID`,
  `CRUSTCORE_GH_APP_KEY_PEM`, `CRUSTCORE_GH_INSTALLATION_ID`, `CRUSTCORE_GH_REPO`.
  Run: `cargo test -p crustcore-daemon --features live onboarding::tests::app_onboarding_live_smoke -- --ignored --nocapture`.
  Success: the test repo registers and a `ghs_…` token mints; the PEM never appears
  in output. **Difficulty: medium.**

<a id="b2"></a>
### B.2 — `gh_live` — GitHub REST (branch / PR create)
- **Test:** `crustcore-net/tests/github_rest.rs::gh_live`, feature `live`.
- **Socket:** GitHub REST v3 (create ref / create pull).
- **CI core (passing):** canned-REST request rendering for the same operations
  (the `golden_issue_to_pr_flow` path renders `CreatePrRequest` through fixtures).
- **Prereq:** a real GitHub token (PAT or the minted installation token from B.1)
  scoped to a throwaway test repo.
- **Run:** `cargo test -p crustcore-net --features live --test github_rest gh_live -- --ignored --nocapture`
- **Success:** a branch + **draft** PR appear on the test repo. **Difficulty: easy.**

<a id="b3"></a>
### B.3 — `live_serve_webhooks_once_round_trip` — webhook listener
- **Test:** `crustcore-daemon/src/webhook.rs::live_serve_webhooks_once_round_trip`, feature `live`. Seam tag `TODO(B2-webhook-live)`.
- **Socket:** a bound TCP listener + an external HTTP POST.
- **CI core (passing):** HMAC-SHA256 **constant-time** signature verification, the
  size bound (`oversized_body_is_rejected_before_hashing`), and replay-dedup →
  a redacted, bounded `GitHubEnvelope`.
- **Prereq:** a free loopback port, a webhook signing secret, and a POST source
  (a real GitHub webhook or `curl` with a correctly computed signature).
- **Run:** `cargo test -p crustcore-daemon --features live webhook::tests::live_serve_webhooks_once_round_trip -- --ignored --nocapture`
- **Success:** a correctly signed POST yields one `GitHubEnvelope`; a wrong
  signature is rejected before hashing. **Difficulty: medium.**

<a id="b4"></a>
### B.4 — `live_draft_pr_post_smoke` — self-improvement draft PR POST
- **Test:** `crustcore-daemon/src/selfimprove.rs::live_draft_pr_post_smoke`, feature `live`. Seam tag `TODO(B5-autoloop-live)`.
- **Socket:** the GitHub PR-create POST (the last inch of the self-improvement loop).
- **CI core (passing):** eval-run → evidence-gate → contract-gate →
  `draft_pr_request` — **no self-merge, no kernel mutation** (invariant 18).
- **Prereq:** a minted `VerifiedPatch` + an `Approved<…>` token + a GitHub token;
  a test repo.
- **Run:** `cargo test -p crustcore-daemon --features live selfimprove::tests::live_draft_pr_post_smoke -- --ignored --nocapture`
- **Success:** a **draft** self-PR opens *only* when the patch is verified and the
  contract gate passes; never auto-merges. Cross-listed in [F](#f-runtime--loops).
  **Difficulty: hard.**

---

<a id="b5"></a>
### B.5 — `cred_proxy_live_push_smoke` — credential-proxy branch push (A.2)
- **Test:** `crustcore-daemon/src/github.rs::tests::cred_proxy_live_push_smoke`. Seam tag `TODO(cred-proxy-live)`.
- **Socket:** the credential-helper **subprocess exec** + a real `git push` to GitHub.
- **CI core (passing):** `parse_push_argv` (every force spelling) + `validate_push`
  (refspec smuggling, multi-ref, protected branches) + `parse_credential_request` +
  `authorize_credential` (https/github.com/registered-repo only) +
  `credential_helper_response` (`x-access-token` + token) + `confining_git_config`
  (reset-then-set-only-ours, `useHttpPath`).
- **Prereq:** a registered test repo + a minted installation token + a worktree with a
  verified branch under the `crustcore/` prefix.
- **Run:** `cargo test -p crustcore-daemon github::tests::cred_proxy_live_push_smoke -- --ignored --nocapture`
- **Success:** the branch pushes; the token **never** appears in the worker/verifier
  env, argv, or logs (it reaches `git` only over the helper pipe); an out-of-prefix or
  protected-branch push is rejected. **Difficulty: hard.**

<a id="b6"></a>
### B.6 — `draft_pr_live_post_smoke` — real draft PR creation (A.3)
- **Test:** `crustcore-daemon/src/github.rs::tests::draft_pr_live_post_smoke`, feature `live`. Seam tag `TODO(draft-pr-live)`.
- **Socket:** the real `POST /repos/{owner}/{repo}/pulls` that opens the draft PR.
- **CI core (passing):** `pr_intent_to_create_request` maps a `PrIntent` (minted by
  `open_pr` *only* from a `VerifiedPatch` + valid approval) onto `CreatePrRequest`,
  carrying the **verifier-evidence body verbatim** (no `self_claimed_done`) and
  `draft = true`; the net layer already maps non-2xx (401/404/422) to typed
  `GitHubError` (never a fake success).
- **Prereq:** a registered test repo + a minted token + a pushed verified branch.
- **Run:** `cargo test -p crustcore-daemon --features live github::tests::draft_pr_live_post_smoke -- --ignored --nocapture`
- **Success:** a **draft** PR opens with the verifier-evidence body + "human review
  required" notice and no secrets/self-claims; an existing head → 422 surfaces, never
  a fake success. **Difficulty: medium.**

<a id="b8"></a>
### B.8 — `ci_monitor_live_poll_smoke` — CI monitor → bounded repair (A.4)
- **Test:** `crustcore-daemon/src/github.rs::tests::ci_monitor_live_poll_smoke`. Seam tag `TODO(ci-monitor-live)`.
- **Socket:** the real check-runs polling loop (`RestGitHub::check_state`) with backoff.
- **CI core (passing):** `aggregate_check_runs` (failure-dominates, empty/any-pending →
  Pending), `monitor_decision` (Pending→Wait / Passed→Green / Failed→budget-bounded
  `repair_decision`), and `repair_task_goal` (bounded, untrusted-check-name failure
  context). The decision uses *aggregated state*, never untrusted CI log text (invariant
  7); repair is bounded by the budget (invariant 11); CrustCore decides repair, not a
  model/comment (invariant 4).
- **Prereq:** a real PR with check-runs + a GitHub token.
- **Run:** `cargo test -p crustcore-daemon github::tests::ci_monitor_live_poll_smoke -- --ignored --nocapture`
- **Success:** failing checks under budget → a repair task spawns; at the cap →
  `StopExhausted`; no unbounded looping. **Difficulty: medium.**
<a id="b7"></a>
### B.7 — `live_evidence_render_append_smoke` — evidence body append (C.3)
- **Test:** `crustcore-daemon/src/product.rs::tests::live_evidence_render_append_smoke`. Seam tag `TODO(P3-live-evidence-render)`.
- **Socket:** the GitHub edit-PR-body call that appends the rendered evidence markdown.
- **CI core (passing):** `EvidenceBundle::to_markdown` (bounded per the export caps, with
  the 🔴 human-review notice + per-list overflow notes) and `to_json` (the stable
  `crustcore.evidence_bundle.v1` schema) — no unbounded dump (invariant 11), every
  fitting receipt included (invariant 10), notes/risks pre-redacted (invariant 2).
- **Prereq:** a real draft PR + a GitHub token.
- **Run:** `cargo test -p crustcore-daemon product::tests::live_evidence_render_append_smoke -- --ignored --nocapture`
- **Success:** the draft PR body shows the bounded evidence markdown + the review
  notice; no secrets/self-claims. **Difficulty: medium.**

## C. Sandbox backend (`bubblewrap` / `sandbox-exec`) + git

<a id="c1"></a>
### C.1 — `live_worktree_executor_accepts_only_verifier_evidence`
- **Test:** `crustcore-daemon/src/exec.rs::live_worktree_executor_accepts_only_verifier_evidence`, feature `live`. Seam tag `TODO(P11-exec-live)`.
- **Socket:** a real sandbox backend + a git worktree.
- **CI core (passing):** the subagent scheduler, budget enforcement, blackboard,
  no-user-channel rule, and **verifier-owned acceptance** over the
  `SubagentExecutor` trait — all with a fake executor.
- **Prereq:** `bubblewrap` (Linux) or `sandbox-exec` (macOS) installed; a git repo.
- **Run:** `cargo test -p crustcore-daemon --features live exec::tests::live_worktree_executor_accepts_only_verifier_evidence -- --ignored --nocapture`
- **Success:** the executor accepts a candidate **only** when the in-sandbox
  verify exits zero (mints a `VerifiedPatch`); rejects otherwise. **Difficulty: medium.**

<a id="c2"></a>
### C.2 — `run_one_task_completes_only_on_verifier_evidence`
- **Test:** `crustcore-daemon/src/task.rs::run_one_task_completes_only_on_verifier_evidence`, feature `live`.
- **Socket:** a sandbox backend + a git repo worktree.
- **CI core (passing):** the task lifecycle decision core (lease / heartbeat /
  budget / cancel) with a stub verify.
- **Prereq:** sandbox backend + git repo.
- **Run:** `cargo test -p crustcore-daemon --features live task::tests::run_one_task_completes_only_on_verifier_evidence -- --ignored --nocapture`
- **Success:** the task reaches `Completed` **only** through verifier evidence.
  **Difficulty: medium.**

<a id="c3"></a>
### C.3 — flow live verify + approval gate
- **Tests:** `crustcore-flow/tests/live_flow.rs::live_verify_node_completes_only_on_a_real_verified_patch`
  and `::live_bundle_still_enforces_the_approval_gate`.
- **Socket:** a functional sandbox backend + git.
- **CI core (passing):** the typed workflow graph with a mock verify driver, and
  the approval-gated bundle.
- **Prereq:** sandbox backend + git repo.
- **Run:** `cargo test -p crustcore-flow --test live_flow -- --ignored --nocapture`
- **Success:** the verify node completes only on a real `VerifiedPatch`, and the
  bundle still refuses to act without the approval token. **Difficulty: medium.**

<a id="c4"></a>
### C.4 — `live_grep_lines_on_this_repo` / `live_list_files_on_this_repo`
- **Tests:** `crustcore-index/src/exec.rs::live_grep_lines_on_this_repo`,
  `::live_list_files_on_this_repo`. Seam tag `TODO(P14-exec)`.
- **Socket:** a real `git` on `PATH` against a real repo.
- **CI core (passing):** argument construction + output parsing on fixtures.
- **Prereq:** run from inside a git repo with `git` available.
- **Run:** `cargo test -p crustcore-index exec::tests::live_grep_lines_on_this_repo -- --ignored --nocapture`
  (and `live_list_files_on_this_repo`).
- **Success:** grep/list return real repo lines/paths, bounded. **Difficulty: easy.**

<a id="c5"></a>
### C.5 — `live_parse_test_manifest_reads_a_real_manifest` (B.1 test-graph)
- **Test:** `crustcore-daemon/src/product.rs::tests::live_parse_test_manifest_reads_a_real_manifest`. Seam tag `TODO(P2-live-graph)`.
- **Socket:** a single filesystem read of a real test manifest
  (`pytest.ini` / `jest.config.js` / `.cargo/config.toml`).
- **CI core (passing):** `parse_test_manifest(kind, text)` is **pure** — it parses
  provided text into bounded group hints; the verifier `TestGraph`
  (`from_signals_and_changed_paths` / `command_order`) is built entirely from path
  strings + repo signals, no filesystem. This is the only filesystem inch in B.1.
- **Prereq:** `CRUSTCORE_TEST_MANIFEST=<path>` to a real manifest in a repo.
- **Run:** `CRUSTCORE_TEST_MANIFEST=pytest.ini cargo test -p crustcore-daemon product::tests::live_parse_test_manifest_reads_a_real_manifest -- --ignored --nocapture`
- **Success:** the pure parser runs over real bytes (groups may be empty). The
  graph never grants authority — gates inform, only the verifier completes
  (invariant 13). **Difficulty: easy.**

---

<a id="c6"></a>
### C.6 — `live_executor_wire_smoke` — end-to-end task loop (D.1)
- **Test:** `crustcore-daemon/src/task_loop.rs::tests::live_executor_wire_smoke`. Seam tag `TODO(P3-live-executor-wire)`.
- **Socket:** a real sandbox backend + a git repo worktree + a configured executor —
  the full pipeline route → `run_fanout`/`run_subagent` → verify → finalize → draft PR.
- **CI core (passing):** `plan_task` (routing → `ExecutionPlan`) and `finalize_task`
  (verifier result + advisory verdicts → terminal `TaskOutcome`) are pure and fully
  CI-tested over the routing/review cores; the executor (`run_subagent`/`run_fanout`)
  is already CI-tested over a mock `SubagentExecutor`.
- **Prereq:** `bubblewrap`/`sandbox-exec` + a git repo + a configured executor (Codex/
  Claude Code/external command).
- **Run:** `cargo test -p crustcore-daemon --features live task_loop::tests::live_executor_wire_smoke -- --ignored --nocapture`
- **Success:** a routed task runs in a sandboxed worktree, the verifier accepts a
  candidate (`VerifiedPatch`), the advisory gate clears, and a draft PR is proposed —
  integration only after a verifier pass (invariant 13). **Difficulty: hard.**

## D. Vector / embedding / telemetry

<a id="d1"></a>
### D.1 — `live_insert_query_delete_roundtrip` (LanceDB)
- **Test:** `crustcore-index-rag/src/store/lancedb.rs::live_insert_query_delete_roundtrip`. Seam tag `TODO(C5-lancedb-live)`.
- **Socket:** a running LanceDB remote endpoint.
- **CI core (passing):** the in-memory store performs the same insert/query/delete
  roundtrip through the store trait.
- **Prereq:** a reachable LanceDB endpoint (env-configured URL).
- **Run:** `cargo test -p crustcore-index-rag store::lancedb::tests::live_insert_query_delete_roundtrip -- --ignored --nocapture`
- **Success:** vectors insert, the nearest-neighbour query returns them, delete
  removes them. **Difficulty: medium.**

<a id="d2"></a>
### D.2 — `live_upsert_search_delete_roundtrip` (Qdrant)
- **Test:** `crustcore-index-rag/src/store/qdrant.rs::live_upsert_search_delete_roundtrip`. Seam tag `TODO(C5-qdrant-live)`.
- **Socket:** Qdrant on `127.0.0.1:6333`.
- **CI core (passing):** the in-memory store roundtrip.
- **Prereq:** `docker run -p 6333:6333 qdrant/qdrant`.
- **Run:** `cargo test -p crustcore-index-rag store::qdrant::tests::live_upsert_search_delete_roundtrip -- --ignored --nocapture`
- **Success:** upsert → search → delete roundtrips against the live collection.
  **Difficulty: easy.**

<a id="d3"></a>
### D.3 — OTLP export (`live_post_to_loopback_collector`, `live_post_with_broker_bearer`)
- **Tests:** `crustcore-telemetry/src/export/otlp.rs::live_post_to_loopback_collector`,
  `::live_post_with_broker_bearer`. Seam tag `TODO(C6-otlp-live)`.
- **Socket:** an OTLP/HTTP collector on `127.0.0.1:4318` (the second also needs a
  broker-issued bearer secret).
- **CI core (passing):** OTLP/GenAI payload assembly + bounding, socket-free.
- **Prereq:** `docker run -p 4318:4318 otel/opentelemetry-collector`; for the
  bearer variant, a broker secret.
- **Run:** `cargo test -p crustcore-telemetry export::otlp::tests::live_post_to_loopback_collector -- --ignored --nocapture`
  (and `live_post_with_broker_bearer`).
- **Success:** the collector accepts the spans; the bearer secret never appears in
  logs. **Difficulty: easy / medium.**

---

## E. MCP & discovery

<a id="e1"></a>
### E.1 — `http_round_trips_against_a_live_server`
- **Test:** `crustcore-mcp/src/transport.rs::http_round_trips_against_a_live_server`. Seam tag `TODO(B1-mcp-modes-live)`.
- **Socket:** a running MCP HTTP server at `$CRUSTCORE_MCP_HTTP_URL`.
- **CI core (passing):** JSON-RPC framing + the MCP-output-is-untrusted trust
  rules (invariant 7).
- **Prereq:** an MCP server reachable at `CRUSTCORE_MCP_HTTP_URL`.
- **Run:** `CRUSTCORE_MCP_HTTP_URL=http://127.0.0.1:PORT cargo test -p crustcore-mcp transport::tests::http_round_trips_against_a_live_server -- --ignored --nocapture`
- **Success:** a tools/list (or equivalent) round-trips; output is treated as
  untrusted data. **Difficulty: medium.**

<a id="e2"></a>
### E.2 — `stdio_round_trips_a_framed_response`
- **Test:** `crustcore-mcp/src/transport.rs::stdio_round_trips_a_framed_response`.
- **Socket:** a spawned subprocess (POSIX shell + `cat`).
- **CI core (passing):** stdio length-prefixed framing.
- **Prereq:** a POSIX shell (any Unix).
- **Run:** `cargo test -p crustcore-mcp transport::tests::stdio_round_trips_a_framed_response -- --ignored --nocapture`
- **Success:** a framed JSON-RPC response round-trips over the pipe. **Difficulty: easy.**

---

## F. Runtime & loops

<a id="f1"></a>
### F.1 — `live_get_updates_smoke` (Telegram transport)
- **Test:** `crustcore-net/src/telegram.rs::live_get_updates_smoke`, feature `live`. Seam tag `TODO(P9-net-live)`.
- **Socket:** the Telegram Bot API (`getUpdates`) over the network.
- **CI core (passing):** `RestTelegram` request shaping + token redaction (the
  token rides only in the URL path, never a log line).
- **Prereq:** a real bot token (`CRUSTCORE_TELEGRAM_TOKEN` or config).
- **Run:** `cargo test -p crustcore-net --features live telegram::tests::live_get_updates_smoke -- --ignored --nocapture`
- **Success:** `getUpdates` returns; the token never appears in output. **Difficulty: easy.**

<a id="f2"></a>
### F.2 — `live_telegram_round_trip_smoke` (runtime channel)
- **Test:** `crustcore-daemon/src/telegram.rs::live_telegram_round_trip_smoke`, feature `live`. Seam tag `TODO(P9-net-live)`.
- **Socket:** Telegram token + network through the daemon runtime channel.
- **CI core (passing):** the runtime-channel decision logic (queue / steer / nonce
  approvals) with a fake API.
- **Prereq:** a bot token + a chat id to message.
- **Run:** `cargo test -p crustcore-daemon --features live telegram::tests::live_telegram_round_trip_smoke -- --ignored --nocapture`
- **Success:** an inbound update becomes a redacted `Event::UserTurn`; an outbound
  reply is delivered through the authorized channel (invariant 15). **Difficulty: easy.**

<a id="f3"></a>
### F.3 — `live_ws_sse_emits_a_snapshot` (dev-UI serve)
- **Test:** `crustcore-dev/src/serve.rs::live_ws_sse_emits_a_snapshot`. Seam tag `TODO(C7-serve-live)`.
- **Socket:** a real loopback TCP socket + an SSE HTTP client.
- **CI core (passing):** snapshot serialization + the `ws_stream` framing test.
- **Prereq:** a free loopback port (the dev UI is loopback-only by posture).
- **Run:** `cargo test -p crustcore-dev serve::tests::live_ws_sse_emits_a_snapshot -- --ignored --nocapture`
- **Success:** an SSE client receives a task snapshot frame. **Difficulty: easy.**

> The **chat front door** and the **self-improvement loop** are runtime loops too;
> their live inches are covered by [F.2](#f2)/[A.2](#a2) (model + channel) and
> [B.4](#b4) (the draft-PR POST) respectively.

---

## Seam tags without a dedicated smoke test

A few `TODO(*-live)` markers gate seams that have **no single named test** because
they require maintainer-only or not-yet-built infrastructure. They are tracked
here so the lint stays honest and the maintainer knows what is deliberately
deferred:

| Tag | Seam | Why no smoke test yet |
| --- | --- | --- |
| `TODO(P8-store-live)` | encrypted secret vault persistence | needs a provisioned vault/keystore; secret-handling is maintainer-owned |
| `TODO(P10-net-live)` | GitHub task/PR loop + multi-repo driver | lands with the daemon runtime entry point (roadmap-v0.6 A.4/F.3) |
| `TODO(B4-firecracker-live)` | Firecracker microVM sandbox tier | **maintainer/infra-only** — requires a microVM host; out of scope for autonomous agents |
| `TODO(B4-windows-live)` | Windows native sandbox backend | **maintainer/infra-only** — requires a Windows host; CrustCore currently targets Linux/macOS |

---

## The runbook lint (`scripts/validate_live_socket_runbook.sh`)

The lint enforces this contract:

1. Every `#[ignore = "…"]` test in `crates/**` — its function name must appear in
   this file.
2. Every distinct `TODO(*-live)` tag in `crates/**` — must appear in this file.

It is run as `cargo xtask runbook-check` and is part of `cargo xtask verify`, so a
new live seam that is added without a runbook entry **fails CI**. To add a seam:
write the `#[ignore]`d test + `TODO(*-live)` marker, then add its row to the
[validation matrix](#validation-matrix) and a section entry above.

```sh
# Run the lint directly:
bash scripts/validate_live_socket_runbook.sh
# or via the gate:
cargo xtask runbook-check
```
