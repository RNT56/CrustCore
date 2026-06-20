# CrustCore v0.2+ Roadmap — Track A (light it up) & Track B (expand)

The v0.1 trusted core is **done and merged**: every capability pack already ships a std-only, fully-tested, transport-agnostic *decision core*, nano is **412.0 KiB** (51.5% of the 800 kB gate), and ~300 workspace tests pass green under `cargo xtask verify`. **Track A ("light it up")** wires real live I/O — model providers, Telegram, GitHub, MCP, subagent execution, native secret stores — onto those already-verified cores *without re-litigating the routing, policy, budget, or verifier logic they encode*. **Track B ("expand")** then adds net-new surfaces once the lit-up core is proven end-to-end. This plan is authored to be executed by the **same parallel multi-worker supervisor/worker model the project itself implements** (CLAUDE.md §7): one supervisor integrates, a fleet of workers drafts patches in isolated worktrees, and only a `VerifiedPatch` ever ships.

## How to read this

This document has two layers. The **front matter** you are reading now — the dependency graph, the parallel execution model, the cross-cutting best practices, the v0.2 definition of done, and the milestone slices — is the contract every per-phase plan inherits; read it first and hold it in memory before opening any phase. The **per-phase detail sections** (P7-live, P8-store, P9-net, P10-net, P11-exec, P12-native, P13-net, P14-live, P5-join, and the Track B phases) are appended after this front matter and each follow the same shape: goal, leverage, prerequisites, a numbered task list with owned file globs, deferral boundary (CI-testable core vs live-gated part), contract-file impact, test/verify strategy, parallel-worker split, risks, definition-of-done checklist, and nano size impact. When a per-phase section and this front matter ever disagree, this front matter and the CLAUDE.md contract win.

## Dependency graph & execution waves

Every Track A phase has a **deterministic core already merged** in v0.1; its v0.2 work is the live-I/O layer plus any net-new surface. The waves below are derived purely from the *unmet* prerequisites of that live layer — a phase joins the earliest wave in which all of its prerequisites have landed. Phases inside a wave own disjoint file globs and run concurrently.

**Cross-cutting credential dependency (read first).** The secret broker (`crustcore-secrets`: `SecretBroker`, `ApprovedSecretView`, `CredentialProxy`, `Redactor`, `Tainted<T>`) **already exists and is a contract crate** — every live phase *consumes* it unchanged to get credentials to tools (never to the model, never to the sandbox env; invariants 1–3). What does *not* yet exist is at-rest native storage: **P8-store** adds OS keychains / encrypted-file vaults behind the existing `SecretStore` trait. Crucially, the broker's `InMemoryStore` plus an operator-supplied vault file is **enough to feed live credentials in dev and in the live-gated integration paths today** — so P8-store is a *hardening* dependency for production at-rest secrets, **not a hard blocker** for the wire adapters in P7-live / P9-net / P10-net / P13-net. Those phases can develop against `InMemoryStore` and adopt native backends as they land.

| Wave | Phases (run concurrently) | Why this wave | Unblocks |
| --- | --- | --- | --- |
| **Wave 1** | **P7-live** (live model providers in spawned `crustcore-net`), **P8-store** (native keychain/vault behind `SecretStore`), **P10-net** (GitHub REST: auth, branch push via credential proxy, draft-PR), **P5-join** (worktree/verify-loop refinements & integration-worktree join helpers) | All four depend only on v0.1 cores that are merged: the net engine, the secrets contract, the worktree/verify loop, and the backend contract. None depends on another *live* phase. P8-store and P5-join are pure-local (no creds/net beyond an OS keychain), so they can land earliest of all. | P7-live → P12-native + Track B (B3 agentic flows); P10-net → the issue→PR **golden task**; P8-store → production at-rest secrets for every other live phase |
| **Wave 2** | **P9-net** (Telegram Bot API long-poll + sendMessage loop), **P11-exec** (subagent execution + integration-worktree verify), **P13-net** (MCP JSON-RPC transport + gateway), **P14-live** (tree-sitter / persistent memory) | P9-net needs the live net helper transport pattern proven by P7-live; P11-exec needs the net protocol + a mock helper (Wave 1) and the worktree join helpers (P5-join); P13-net needs the gateway's credential path (broker) and the net transport pattern; P14-live needs the index core only. | P9-net → operable runtime human channel (invariant 15); P11-exec → P12-native (shared paused-executor boundary) and multi-agent self-improvement; P13-net → code-mode tool surface |
| **Wave 3** | **P12-native** (native advisor/executor live calls), **Track B** surfaces (B1…Bn — net-new expansion: e.g. richer providers, webhook server, additional sandbox backends) | P12-native needs live model calls (P7-live) and the subagent execution boundary (P11-exec); Track B expands only after the lit-up core runs end-to-end. | v0.3 |

Notes on the critical path: **P7-live is the single highest-leverage unlock** — it turns every model-consuming phase (advisor/executor, subagent supervisor, self-improvement evals) from canned-text mocks into real frontier-model calls, while the trust story is preserved structurally (the key never leaves the trusted helper process; the model output is still only a `BackendResult` candidate that must become a `VerifiedPatch`). **P10-net is the unlock for the issue→PR golden task** — the end-to-end demonstration that a `VerifiedPatch` becomes a draft PR. **P5-join and P8-store are deliberately early** because they are local-only and de-risk Wave 2's integration and credential paths.

## Parallel multi-worker execution model

This plan is executed by the **exact supervisor/worker model CrustCore itself implements** (CLAUDE.md §7; `crates/crustcore-daemon/src/supervisor.rs` — the `AgentRegistry`, `Role`, budget-enforcing `Scheduler`, `Blackboard`, and `decide_integration`). Use it literally.

**Exactly one supervisor per build session.** Only the supervisor may: talk to the user, request approval, integrate patches / merge branches, push branches, open PRs, resolve secret handles for tools, spawn workers, and commit durable project state (`CHANGELOG.md`, contract docs). The supervisor is the only actor that holds authority — mirroring the runtime rule that only CrustCore authorizes, verifies, persists, exposes, or integrates.

**A worker fleet explores, drafts, and produces patches — never authority.** Each worker runs in its **own isolated git worktree** on a per-task branch `claude/<phase>-<slug>`, edits only the file globs assigned to it, runs its verifier in a sandbox, and reports a **structured result** (what changed, files touched, tests run, risks, open questions, and its proposed changelog lines) back to the supervisor via the blackboard. Workers never talk to the user (invariant 5), never edit each other's files, and never merge.

**Partition by disjoint owned file globs.** Two workers must never own overlapping paths; the supervisor assigns disjoint directories/crates up front. Each phase's detail section lists the globs it owns precisely so the supervisor can fan out without collision.

**Contract-file changes are serialized.** The contract files (CLAUDE.md, AGENTS.md, INVARIANTS.md, THREAT_MODEL.md, SECURITY.md, `docs/policy.md`, `docs/secrets.md`, `docs/sandbox.md`, `docs/backend-contract.md`, `crustcore-kernel/src/event.rs`, `crustcore-kernel/src/action.rs`, `crustcore-policy/src/decision.rs`, `crustcore-secrets/src/lib.rs`, `Cargo.toml`, `Cargo.lock`) are **never edited in parallel**. A phase that needs a contract change stops and routes it through a dedicated, maintainer-approved, single-PR serialized task *before* the dependent work — it does not bundle the change into unrelated work.

**Per-phase loop (every worker, every phase):**

```text
read the contract doc(s) for the phase
  -> implement the CI-testable deterministic core in the right crate
  -> launch a multi-agent adversarial review (each finding independently refuted)
  -> fix confirmed findings with regression tests
  -> cargo xtask verify GREEN (fmt, clippy -D warnings, tests, forbidden-deps, nano size gate)
  -> branch claude/<phase>-<slug>  (one task = one branch = one PR; declare owned globs)
  -> PR -> CI -> supervisor integrates -> merge
```

**Bounded budgets and concurrency.** Every spawned worker has wall-time, output-size, token/cost, and a concurrency cap (the `Scheduler`'s `max_concurrent`). Runaway fan-out is a modeled threat (budget exhaustion); keep concurrency bounded and purposeful. **One changelog writer at integration time:** workers report their changelog lines; the supervisor writes the consolidated `[Unreleased]` entries to avoid `CHANGELOG.md` merge conflicts.

**Worked example — fanning out Wave 1.** The supervisor opens Wave 1 by first landing the one serialized contract sub-PR it requires (the `Cargo.toml` workspace-dependency pins for P7-live's `tokio`/HTTP/TLS stack and P8-store's keychain crates — reviewed and merged alone). Then it spawns four workers on disjoint globs:

- **Worker A (P7-live):** owns `crates/crustcore-net/**` and `docs/model-routing.md`; implements the live `Provider` impls + Tokio/HTTP/TLS transport behind the existing `Engine`, gated behind a `live` feature; deterministic replay tests in CI, live calls behind `#[ignore]`.
- **Worker B (P8-store):** owns `crates/crustcore-secrets/src/store/**` (new backend module) and `docs/secrets.md` (serialized — routed as its own sub-PR); implements OS-keychain + encrypted-vault `SecretStore` impls behind the existing trait.
- **Worker C (P10-net):** owns `crates/crustcore-net/src/github/**` and `docs/github.md`; implements GitHub REST auth, branch push via the credential proxy, and draft-PR creation; mock-server contract tests in CI, live calls `#[ignore]`.
- **Worker D (P5-join):** owns `crates/crustcore-worktree/**` and `crates/crustcore-backend/src/verify*`; refines the integration-worktree join / verify-loop helpers; fully CI-testable on the local filesystem.

Workers A and C both touch `crustcore-net` but **own disjoint subtrees** (`crustcore-net/src/{lib,provider}` vs `crustcore-net/src/github`), so they do not collide; the supervisor confirms the partition before fan-out. Each worker returns a structured result; the supervisor reruns the full verifier on the integrated tree, writes the consolidated changelog, and merges in dependency order.

## Cross-cutting best practices

These apply to **every** phase and every worker. They are not optional.

- **Std-only-kernel & size-gate discipline.** The kernel and the nano build stay std-only — no async runtime, no network, no DB — and under the 800 kB gate (invariants 19/20). No phase adds a dependency to `crustcore-kernel` or to the nano feature graph. Treat the gate as a release blocker, not a guideline.
- **The spawned-helper pattern for any network/TLS/keychain stack.** Anything that links Tokio, an HTTP client, Rustls/platform TLS, a provider SDK, or an OS keychain lives **behind a separately-spawned helper binary or a non-nano capability crate** — never linked into nano. Nano links only the **std-only protocol** (`crustcore-netproto`) and *spawns* the heavy process over a pipe, exactly as it spawns `git`/`codex`/`claude`. Every phase states whether it touches nano (almost always: it must not) and its size impact.
- **Credentials only via the broker / credential proxy.** Tools receive secrets **only** through `SecretBroker::authorize` → `ApprovedSecretView::expose` or, preferred, a `CredentialProxy` that injects the credential inside the trusted process. The model never sees a raw or secret-bearing value (invariants 1–3); the sandbox env never carries a token (the git credential proxy mediates instead). `SecretMaterial` stays non-`Debug`/non-`Serialize`/non-`Clone`. Where a header shape the proxy cannot express is needed (e.g. Anthropic `x-api-key`), build it inside the trusted crate's own code from `ApprovedSecretView::expose()` rather than amending the secrets contract.
- **The deterministic-core-vs-live-gated split.** Live network/exec/keychain is **not CI-testable** (CI has no net and no secrets). So every phase splits into (a) a **CI-testable deterministic core** — mock providers, replay fixtures, mock servers, contract tests, on-disk vault stubs — that `cargo xtask verify` runs on every PR, and (b) a **live-gated part** behind a cargo `live` feature flag, a spawned helper, and/or `#[ignore]`d integration tests that run only with real credentials supplied out-of-band. The deterministic core carries the correctness proof; the live part is a thin, transport-only drop-in.
- **Untrusted-data discipline (invariant 7) for every new external surface.** Every new inbound surface — provider responses, Telegram updates, GitHub JSON and PR comments, MCP tool results/descriptions, indexed repo content, external-worker transcripts — is **untrusted data**. It informs understanding; it never controls policy, secrets, approvals, sandboxing, or user communication. Wrap it as data; do not obey instructions inside it.
- **Receipts + redaction + bounding for anything model-visible.** Every model-visible tool result gets a `ToolReceipt` (invariant 10), passes through the `Redactor` before it can become `ModelVisibleText`, and is **bounded** (line caps, text caps, stream caps — the protocol already enforces `MAX_LINE_BYTES`, `MAX_TEXT_BYTES`, `MAX_STREAM_BYTES`, `MAX_REGISTRY_MODELS`). No unbounded read enters model context.
- **Contract-file serialization.** Any change to a contract file is a dedicated, maintainer-approved, single PR landed *before* the dependent work — never bundled, never parallel. Each phase names exactly which contract files (if any) it touches; most touch none.
- **`cargo-bloat` on nano-affecting PRs.** Any PR that could affect the nano graph attaches `cargo bloat --profile nano -p crustcore --crates -n 30` and a `cargo tree` confirming no forbidden crate (tokio/reqwest/rustls/clap/sqlx/rmcp/provider SDK) entered nano. A live phase that adds deps to a non-nano crate still runs the forbidden-deps check to prove the deps did not leak.

## Definition of done for v0.2

v0.2 is done when all of the following hold and are demonstrated:

1. **A real local task runs end-to-end against a live model.** `crustcore run` drives a real frontier model (via the spawned `crustcore-net` helper) to produce a `BackendResult`, the verifier reruns in a clean sandbox, and a `VerifiedPatch` is minted — completion still comes only from verifier evidence (invariant 13).
2. **That `VerifiedPatch` opens a draft PR.** P10-net pushes the branch through the credential proxy and opens a **draft** PR from a `VerifiedPatch` only; merge still requires explicit approval; force-push stays denied by default.
3. **The full issue→PR golden task passes** against a mock GitHub server in CI and is demonstrated once live.
4. **Secrets come from a native store.** P8-store provides OS keychain / encrypted vault behind `SecretStore`; the broker resolves live credentials from it; no secret is serializable/debuggable/clonable or model-visible, and the redaction red-team fixtures pass.
5. **Telegram is operable as the default human channel** (invariant 15): allowlisted chat control, queue/steer, nonce-bound approvals, status — driven live through the net helper, with the model unable to send arbitrary Telegram text directly.
6. **Subagent execution works end-to-end** (P11-exec): the supervisor spawns real subagents in isolated worktrees, integrates only a verified merge, and every privilege is bound to the registry role, not a self-asserted claim.
7. **MCP tools call live through the gateway** (P13-net) with policy checks, receipts, redaction, and untrusted-data handling; unused servers cost zero model context.
8. **Nano is still under budget.** `crustcore-nano` remains < 800 kB stripped; the CI size gate is green; no live phase leaked an HTTP/TLS/keychain/provider stack into the nano graph (`cargo tree`/`cargo bloat` attached to each nano-touching PR).
9. **Every new external surface has a red-team fixture.** New prompt-injection, credential-exfil, fake-tool-result, MCP-hidden-instruction, and PR-comment-injection fixtures are added (or un-ignored) and pass; the existing red-team suite stays green.
10. **`cargo xtask verify` is green** across the workspace and the changelog records each phase's change, phase id, PR, owning role, size impact, and invariants touched.

## Suggested milestone slices

- **v0.2.0 — "first live patch & PR":** **P7-live + P10-net + P8-store**. The minimal slice that satisfies the headline DoD criteria 1–4: a live model produces a verified patch, it opens a draft PR through the credential proxy, and secrets come from a native store. This is the proof that the v0.1 trust story holds under real I/O end-to-end.
- **v0.2.x — "operable runtime & parallel orchestration":** **P9-net** (Telegram operable), **P13-net** (MCP live), **P11-exec** (subagent execution + integration verify), **P12-native** (native advisor/executor), **P14-live** (tree-sitter / persistent memory), **P5-join** (worktree/verify-loop join refinements). Lights up the remaining runtime surfaces and multi-agent orchestration on top of the v0.2.0 base.
- **v0.3 — Track B (expand):** the net-new surfaces — additional providers and meta-provider paths, the optional webhook server, further sandbox backends (Firecracker / container hardening), richer code intelligence, and broader multi-repo orchestration — built only after the lit-up Track A core is proven end-to-end and under budget.

---

## Track A — detailed phase plans (light it up)

### P7-live — Live model providers (OpenAI / Anthropic / OpenRouter / local OpenAI-compatible) in the spawned crustcore-net helper  _(Track A)_

**Goal.** Replace the deterministic MockProvider stand-in with real credentialed HTTP `Provider` adapters for OpenAI, Anthropic, OpenRouter, and local OpenAI-compatible endpoints (Ollama/vLLM/LM Studio), living entirely inside the *spawned* `crustcore-net` helper binary. The already-tested routing engine (dynamic registry/probe, Router/Budget/Reliable meta-providers, streaming sink, budget ledger) stays byte-for-byte unchanged: a live `Provider` drops into the existing `Vec<Box<dyn Provider>>` without touching routing logic. Credentials reach the outbound request only via the Phase-8 secret broker's credential-proxy pattern (`CredentialProxy::bearer` → `HeaderInjection`), never the model, never the sandbox env, never nano. Nano continues to link only `crustcore-netproto` (std-only) and spawn the helper over a pipe, so the 800 kB size gate and forbidden-deps gate stay green with zero nano size delta.

**Leverage.** Unblocks every model-consuming capability above it: the advisor/executor loop (docs/advisor-executor.md), subagent supervisor (P11), self-improvement evals (P15), and any role-driven routing become real instead of echoing canned text. It is the single seam that turns CrustCore from a verifier harness driven by mocks into one that can actually call a frontier model to produce patches — while preserving the entire trust story: completion is still verifier-owned (a model's output is just a BackendResult candidate; only a VerifiedPatch ships, invariant 13), and the no-secret-to-model guarantee (invariants 1-3) is enforced structurally because the key never leaves the trusted helper process. Because the engine is transport-agnostic, this is a high-value/low-blast-radius drop-in: the routing/budget/fallback correctness already proven by the workspace test suite is reused, not re-litigated.

**Prerequisites:** P8-store / Phase 8 secret broker (DONE — crustcore-secrets ships SecretBroker, ApprovedSecretView, CredentialProxy::bearer, HeaderInjection, Redactor; this phase consumes them, it does not build them), Phase 7 engine (DONE — Provider trait, Engine, select_candidates/apply_budget/run_reliable, serve loop, crustcore-netproto wire protocol), Native OS keychain backends (P8-store TODO) are NOT a hard prerequisite: the broker's InMemoryStore + an operator-supplied vault file is enough to feed live creds in the integration path; keychain backends improve at-rest storage but do not block the wire adapters

**Tasks**

| Task | What | Owns |
|---|---|---|
| `P7L.1` | Add the gated HTTP/TLS transport layer to crustcore-net (deps + feature flag) — Introduce a `live` feature on crustcore-net that pulls a minimal blocking HTTP client + TLS (recommend `ureq` + `rustls` so we keep a single blocking call site matching the SYNC `Provider::complete` signature, avoiding a Tokio runtime per request; if streaming SSE forces async, contain a single `tokio` current-thread runtime BEHIND the helper binary only). All such deps are declared under `[features] live = [...]` and `[dependencies] tokio = { optional = true } ...` so a default `cargo build -p crustcore-net` (used by the workspace build + the mock helper) links NONE of them. Add a `transport` module exposing a tiny `HttpClient` trait (`fn post_json(&self, url, headers: &[(&str,&[u8])], body: &[u8], on_sse_line: &mut dyn FnMut(&str)) -> Result<HttpResponse, TransportError>`) with a real impl behind `#[cfg(feature="live")]` and a `ReplayClient` (canned-response) impl always compiled for tests. cargo-bloat is irrelevant to nano here (crustcore-net is a sidecar) but attach `cargo tree -p crustcore-net --features live` to the PR to show the heavy stack is confined. | `crates/crustcore-net/Cargo.toml, crates/crustcore-net/src/transport/**` |
| `P7L.2` | Define the provider-config + credential-resolution boundary the helper reads at startup — The helper must learn which providers to instantiate, their base URLs/model allowlists, and WHICH secret handle authenticates each — without ever embedding a raw key. Add a `config` module: a `ProviderConfig { id, kind: ProviderKind, base_url, secret_handle_label, model_allowlist, default_cost_micros }` parsed from a small operator-supplied config file path passed as a helper arg (e.g. `crustcore-net --providers /path/cfg`). Crucially, config carries only the `secret://<label>` handle, never bytes (docs/secrets.md §3.2). The helper resolves the actual key by constructing a `SecretBroker` over a store the OPERATOR populates (InMemoryStore seeded from a vault/keychain in the live path) and minting a one-shot `ApprovedSecretView` → `CredentialProxy::bearer` per request. Define `CredentialSource` trait abstracting 'give me a HeaderInjection for label X right now' so adapters never see SecretMaterial. Local-endpoint providers may have no secret (handle absent → no Authorization header). | `crates/crustcore-net/src/config.rs, crates/crustcore-net/src/credsource.rs` |
| `P7L.3` | Implement the OpenAI-compatible adapter (serves OpenAI, OpenRouter, and local endpoints) — One adapter shape covers OpenAI, OpenRouter, and local OpenAI-compatible (Ollama/vLLM/LM Studio) since they share the `/v1/chat/completions` + `/v1/models` API; only base_url, auth header, and optional extra headers (OpenRouter's `HTTP-Referer`/`X-Title`) differ. Implement `OpenAiProvider` impl of `Provider`: `probe()` GETs `/v1/models` and maps to `ModelCard`s (health = endpoint reachable + model listed; tools/structured/streaming/context filled from a capability table keyed by model id with safe conservative defaults when unknown — invariant 17, discovered not hard-coded as permanent truth); `complete()` POSTs `/v1/chat/completions` with `stream: req.stream`, parses SSE `data:` lines on the success path ONLY (emit chunks via `sink` exactly like MockProvider, so a provider that will fail emits nothing — preserving the no-partial-leak property the engine's tests assert), accumulates the full text, and fills `Usage` from the provider's `usage` block (or estimates if absent). Map HTTP 429/5xx/timeout → `ProviderError::Unavailable` (drives Reliable fallback), 400 context-length → `ProviderError::Capability`, everything else → `ProviderError::Other`. Auth header comes from `CredentialSource`, never inlined. All HTTP goes through the P7L.1 `HttpClient` trait so the adapter is testable with `ReplayClient`. | `crates/crustcore-net/src/providers/openai.rs, crates/crustcore-net/src/providers/mod.rs` |
| `P7L.4` | Implement the Anthropic Messages-API adapter — Anthropic differs from the OpenAI shape: `POST /v1/messages`, `x-api-key` + `anthropic-version` headers (not Bearer), a `system` top-level field, `content` blocks, and SSE event types (`content_block_delta` with `text_delta`, `message_delta` carrying output usage). Implement `AnthropicProvider` impl of `Provider` mirroring P7L.3's contract: success-path-only streaming via `sink`, `Usage` from `message_start`/`message_delta` usage fields, the same `ProviderError` mapping (`overloaded_error`/429/5xx → Unavailable, context overflow → Capability). `probe()` has no live `/models` list historically, so model availability comes from the configured allowlist plus a lightweight reachability check; cards are still dynamic (a model removed from the allowlist or an unreachable endpoint drops out — invariant 17), never a permanent hard-coded table. Auth via `CredentialSource` producing an `x-api-key` HeaderInjection variant (extend `CredentialProxy` usage; if `bearer()` is too narrow, add the header construction in this crate's trusted code using `ApprovedSecretView::expose` directly — NOT a contract-file change, it lives in crustcore-net). | `crates/crustcore-net/src/providers/anthropic.rs` |
| `P7L.5` | Wire a live engine builder + helper CLI without disturbing the mock default — Add `pub fn live_engine(cfg: &[ProviderConfig], creds: &dyn CredentialSource) -> Engine` (behind `#[cfg(feature="live")]`) that instantiates the configured adapters and returns the SAME `Engine` type the mock path uses — proving the drop-in. Update `src/bin/helper.rs`: with no args (or `--mock`) keep `default_mock_engine()` (so CI, the existing subprocess integration test, and offline `crustcore doctor` are unchanged); with `--providers <path>` and the `live` feature, build `live_engine`. The `serve()` loop, protocol, and streaming sink are untouched. Per-request flow: helper receives `Request::Complete` → engine routes → adapter asks `CredentialSource` for a fresh one-shot HeaderInjection → HTTP call → chunks stream back over the existing protocol. Redact every outbound diagnostic (stderr, error strings) through the broker's `Redactor` before it leaves the process (invariant 2): the helper's stderr is inherited by the parent, so a leaked key there would reach logs. | `crates/crustcore-net/src/engine_live.rs, crates/crustcore-net/src/bin/helper.rs` |
| `P7L.6` | Replay/contract test suite for every adapter (the CI-testable core) — Capture sanitized real response fixtures (SSE streams + error bodies) for OpenAI, OpenRouter, local, and Anthropic into `tests/fixtures/` (NO secrets, NO real org data). Drive each adapter through `ReplayClient` to assert: streaming chunks concatenate to the final text; `Usage` parsing; error-status → correct `ProviderError` variant; non-UTF8/truncated/garbage SSE is handled without panic (no-panic); a failure emits ZERO chunks to the sink (fallback-safety property the engine relies on); `probe()` builds dynamic cards and a removed model drops out. Add an engine-level replay test: a `ReplayClient`-backed OpenAI provider that returns 429 then an Anthropic provider that succeeds proves `run_reliable` falls back across REAL adapters, not just mocks. These run with `--features live` in CI but make NO network calls (ReplayClient). | `crates/crustcore-net/tests/providers_replay.rs, crates/crustcore-net/tests/fixtures/**` |
| `P7L.7` | Live, ignored integration tests gated on real credentials — Add `#[ignore]` integration tests (run only with `--features live --ignored` and env-provided real keys via the operator's broker/vault, NEVER committed) that hit each provider's real endpoint with a trivial cheap prompt and assert a non-empty completion + usage + that the helper's own stderr/stdout contain no substring of the supplied key (a runtime leak canary complementing the structural guarantee). Document the run recipe in a test-module doc comment, not in CI. These are the ONLY part of the phase that needs net+secrets and they never run in CI. | `crates/crustcore-net/tests/providers_live.rs` |
| `P7L.8` | Secret-leak red-team fixture for the new model-transport surface (invariant 1-3, new-surface rule) — Per docs/secrets.md §10 'New-surface rule', the new outbound surface adds its own leak-matrix row: a sentinel key registered with the broker's Redactor, routed through the live adapter's error/diagnostic paths (a forced 401 'invalid key sk-SENTINEL...' body, a panic-inducing malformed SSE, a timeout), must come out absent/redacted in: the helper's stderr, the `Response::Error` reason sent over the protocol to the parent, and any `Tainted` log line. Add this as a deterministic ReplayClient-driven fixture under tests/redteam (un-ignored, CI-run) since it needs no network — the sentinel is injected via the fixture, not a real provider. Assert `Redactor::would_leak` is false on every model-visible/log-visible string the helper can emit. | `tests/redteam/net_model_transport_leak.rs, crates/crustcore-net/tests/leak_canary.rs` |
| `P7L.9` | Docs, changelog, and forbidden-deps gate extension — Update docs/model-routing.md §7 status block from 'wire adapters deferred (TODO(P7-live))' to 'live adapters implemented behind the `live` feature; engine unchanged; mock default preserved' and document the config-file + credential-source flow and the SYNC-vs-SSE transport decision. Update crustcore-net's lib.rs module doc (remove the TODO(P7-live) language for adapters, keep the boundary statement). Extend xtask `forbidden-deps`: add an assertion that the DEFAULT (non-live) crustcore-net build links no tokio/rustls/ureq, so the heavy stack is provably confined to the `live` feature and can never leak into the default helper or the workspace build. Add a CHANGELOG `[Unreleased]` entry (Added: live providers; size impact: n/a (sidecar, nano unaffected); invariants verified: 1-3, 11, 17, 20). NOTE: docs/model-routing.md and docs/secrets.md are NOT in the contract-file list; CLAUDE.md/INVARIANTS.md/docs/policy.md/docs/sandbox.md/crustcore-secrets/src/lib.rs are — and this phase touches NONE of them. | `docs/model-routing.md, crates/crustcore-net/src/lib.rs, xtask/src/main.rs, CHANGELOG.md` |

**Deferral boundary.** CI-TESTABLE CORE (no net, no secrets, runs every PR): the `HttpClient`/`ReplayClient` abstraction; all four adapter parse/map/stream/error paths driven by sanitized canned fixtures; engine-level cross-adapter fallback over ReplayClient; the config + credential-source wiring with an InMemoryStore-backed broker and a SENTINEL key; the secret-leak red-team fixture (sentinel forced through error/panic/timeout paths via ReplayClient — needs no real provider); no-panic/garbage-SSE handling. LIVE-GATED (needs real creds + network, NEVER in CI): only P7L.7 — `#[ignore]`d integration tests behind `--features live --ignored` that hit real OpenAI/Anthropic/OpenRouter/local endpoints with operator-supplied keys, asserting real completions and a runtime no-leak canary. GATING MECHANISM is three-layered: (1) a `live` cargo feature so the HTTP/TLS deps and live_engine are not even compiled by default; (2) `#[ignore]` on the network tests so even `cargo test --features live` skips them unless `--ignored` is passed; (3) the helper binary defaults to `default_mock_engine()` so the spawned-helper integration test and `crustcore doctor` stay offline and deterministic. The live path is reached only by an operator passing `--providers <cfg>` to a `live`-built helper with a populated broker.

**Contract-file impact.** NONE of the serialized contract files are touched. crustcore-secrets/src/lib.rs is a contract file and is CONSUMED unchanged (CredentialProxy::bearer, ApprovedSecretView::expose, Redactor are used as-is); if Anthropic's `x-api-key` header cannot be expressed via the existing `CredentialProxy::bearer`, the header is built inside crustcore-net's own trusted code from `ApprovedSecretView::expose()` rather than by editing crustcore-secrets — so no contract change is required. event.rs/action.rs/policy/decision.rs/sandbox.md/policy.md/Cargo.lock-as-contract are untouched. The only edited shared/root files are docs/model-routing.md (NOT a contract file), xtask/src/main.rs, CHANGELOG.md, and the root Cargo.toml workspace.dependencies table IF a new optional dep needs a workspace pin — Cargo.toml IS a contract file, so adding `ureq`/`rustls`/`tokio` workspace pins must be a small, serialized, maintainer-approved sub-PR done first (P7L.1's dep additions). Flag this explicitly: the dependency-admission step is the one serialized gate in this phase.

**Test / verify strategy.** UNIT/CONTRACT (every PR, --features live, no network via ReplayClient): per-adapter streaming-concatenation, Usage parsing, HTTP-status → ProviderError mapping, success-path-only chunk emission, dynamic-probe card construction + de-listing, no-panic on malformed/truncated/non-UTF8 SSE; engine-level real-adapter fallback (429 then success); config parse + handle-only (no bytes) assertion. RED-TEAM (CI, deterministic): the new model-transport leak fixture — sentinel key forced through 401-body/panic/timeout paths must be absent/redacted in stderr, protocol Error reason, and Tainted logs; assert Redactor::would_leak == false on all emittable strings; reuse the existing secret-leak S-matrix posture (docs/secrets.md §10). LIVE (manual only): P7L.7 ignored tests + runtime leak canary. ADVERSARIAL-REVIEW DIMENSIONS to fan out independently (each finding independently refuted per the project loop): (a) partial-output leakage on fallback — does any error path emit chunks first?; (b) secret reachability — can the key reach stderr, the protocol, a panic message, a Tainted Debug, or an env var anywhere?; (c) unbounded/DoS — can a hostile provider stream force unbounded allocation or hang past timeout/size caps?; (d) trait-purity — did the engine/protocol change at all (it must not)?; (e) feature-confinement — does the DEFAULT build link any HTTP/TLS crate (forbidden-deps must catch it)?; (f) capability-truth — is any model availability hard-coded as permanent rather than probed (invariant 17)?; (g) untrusted-content — is a provider's response treated as data and never as policy/instructions (invariant 7)? VERIFY: `cargo xtask verify` green (fmt, clippy -D warnings, workspace tests, nano size gate unchanged, extended forbidden-deps), plus `cargo test -p crustcore-net --features live` (excluding ignored).

**Parallelization.** Partition by disjoint globs so workers never collide. Worker A (transport+config+creds foundation, blocks others): P7L.1 (Cargo.toml/transport) → P7L.2 (config.rs/credsource.rs) — must land first since adapters depend on HttpClient + CredentialSource traits; the Cargo.toml dependency-pin sub-PR is the serialized gate inside A. Worker B: P7L.3 (providers/openai.rs + providers/mod.rs) — OpenAI/OpenRouter/local. Worker C: P7L.4 (providers/anthropic.rs). Workers B and C run fully in parallel on disjoint files once A's traits exist. Worker D: P7L.6 + P7L.8 (tests/providers_replay.rs, tests/fixtures, tests/redteam/*, tests/leak_canary.rs) — owns all test/fixture globs, can scaffold ReplayClient fixtures against A's trait in parallel with B/C, finalizing once adapters land. Worker E (integration, runs at the end, owns the wiring + shared-file edits): P7L.5 (engine_live.rs/helper.rs), P7L.7 (providers_live.rs), P7L.9 (docs/model-routing.md, lib.rs, xtask, CHANGELOG) — the supervisor integrates here, edits the shared xtask/docs/changelog exactly once (per CLAUDE.md §7.2 one-changelog-writer), reruns full verify, and produces the merge. No two workers own overlapping files; providers/mod.rs is owned solely by B and B coordinates exporting C's module via a one-line add the supervisor folds in at integration to avoid a shared-file race.

**Best practices.** Engine is sacred: do NOT modify select_candidates / apply_budget / run_reliable / Engine / serve / the Provider trait signature. A live provider is a new impl of the existing trait; if you feel the urge to change the trait, stop — the whole leverage of this phase is the drop-in.; Streaming must emit chunks to `sink` ONLY on the success path, exactly as MockProvider does. A provider that is going to return Err must have emitted zero chunks, or run_reliable's fallback leaks partial output from a failed provider (the engine's tests assert this; preserve it).; The key is resolved per-request via a one-shot ApprovedSecretView → HeaderInjection, consumed immediately, never stored on the adapter struct. Adapters hold a `&dyn CredentialSource`, never SecretMaterial, never a String key.; Treat every byte from a provider as untrusted data (invariant 7): bound the response size (reuse MAX_STREAM_BYTES posture), never let a malformed SSE stream allocate unboundedly or panic, and run all provider output through the Redactor before it touches stderr or the protocol error channel.; Model capability/availability is discovered, not asserted as permanent (invariant 17): cards come from /v1/models + a conservative capability table or the operator allowlist; an unreachable endpoint or de-listed model simply stops appearing.; Keep the SYNC Provider::complete contract. Prefer a blocking HTTP client (ureq+rustls) so there is no async infection; if SSE forces async, contain exactly one current-thread Tokio runtime inside the helper binary and never expose a Future across the Provider boundary.; Every heavy dep is `optional = true` and behind `features.live`; the default build (workspace + mock helper + CI) must link none of them — enforced by the extended forbidden-deps gate.

**Risks.** Async infection: if SSE streaming pushes you toward Tokio/reqwest, the SYNC Provider::complete signature forces either a blocking client (ureq) or a contained runtime; picking reqwest+full-tokio bloats the sidecar and risks a Future leaking across the trait. Mitigation: mandate ureq+rustls first; only contain a current-thread runtime if a blocking SSE client proves inadequate.; Secret leak via stderr: the helper's stderr is inherited by the parent (SpawnedHelper sets stderr=inherit), so a key echoed in a panic/error reaches parent logs. Mitigation: redact ALL diagnostics through the broker Redactor before emission; the leak-canary fixture (P7L.8) is a release blocker.; Fallback partial-output leak: a live adapter that streams some chunks then errors would leak a failed provider's output before run_reliable advances. Mitigation: buffer-then-flush or strictly emit-on-success-only, asserted by a dedicated replay test.; Capability drift / hard-coding (invariant 17): an unknown model's tools/context filled from a stale table misroutes. Mitigation: conservative safe defaults + dynamic /v1/models probe; never assert permanent availability.; Dependency-admission gate (Cargo.toml is a contract file): adding ureq/rustls/tokio workspace pins is a serialized maintainer-approved step; skipping it stalls the phase. Mitigation: land the dep sub-PR first.; Forbidden-deps false sense of safety: the existing gate checks the `net` feature of crustcore (the caller), not the DEFAULT crustcore-net helper build; without extending it, a heavy dep could sneak into the non-live helper. Mitigation: P7L.9 extends the gate to assert default crustcore-net links no HTTP/TLS.; Provider response as injection vector (invariant 7): a model/provider returning crafted text must never be interpreted as policy/approval/tool-instructions by downstream consumers; this phase must treat completions strictly as bounded untrusted data and rely on the kernel/policy layer above for any action gating.

**Definition of done.**
- All four adapters (OpenAI, OpenRouter, local OpenAI-compatible, Anthropic) implement the existing `Provider` trait with NO change to the trait, Engine, or protocol.
- Default `cargo build` (workspace) and the default/mock helper link zero HTTP/TLS crates; the extended xtask forbidden-deps gate proves it and `cargo xtask verify` is green.
- Nano size unchanged (sidecar-only change): size gate green, nano still ~412.0 KiB, cargo tree shows nano links only crustcore-netproto.
- Replay/contract tests cover streaming concat, usage parsing, error→ProviderError mapping, success-path-only chunk emission, dynamic probe, and no-panic on malformed SSE — all running in CI with --features live and zero network.
- Engine-level cross-adapter fallback (429→success) passes over real adapters via ReplayClient, proving the engine is genuinely transport-agnostic.
- The new model-transport secret-leak red-team fixture passes: a sentinel key forced through error/panic/timeout paths is absent/redacted in stderr, the protocol Error reason, and Tainted logs (would_leak == false everywhere).
- Credentials reach requests ONLY via one-shot ApprovedSecretView→HeaderInjection; no adapter stores a key; live integration tests' runtime canary confirms no key substring in helper output.
- Live `#[ignore]` integration tests exist, are documented, and are confirmed runnable with real creds out-of-band; they never run in CI.
- Multi-agent adversarial review completed with every confirmed finding fixed + a regression test; docs/model-routing.md status updated; CHANGELOG [Unreleased] entry added; one branch / one PR per task with declared owned globs.

**Nano size impact.** Zero. All work is confined to the spawned `crustcore-net` helper crate and its `live`-gated dependencies; nano links only `crustcore-netproto` (std-only) and reaches the transport by spawning the helper over a pipe — exactly as today. No new crate enters nano's dependency tree, so the 800 kB size gate and the forbidden-deps gate stay green with nano at ~412.0 KiB (51.5% of budget). cargo-bloat on nano is unaffected; the only size growth is the (non-flagship) crustcore-net sidecar binary, which has a 3-8 MB budget and is never the size claim. The PR attaches `cargo tree -p crustcore --features net` (proves no HTTP/TLS in the caller) and `cargo tree -p crustcore-net --features live` (proves the heavy stack is confined to the sidecar's live feature) rather than a nano cargo-bloat delta.

---

### P8-store — Native secret stores (OS keychain + encrypted-file vault)  _(Track A)_

**Goal.** Provide real at-rest `SecretStore` backends behind the trait that already lives in `crustcore-secrets` — a macOS Keychain backend, a Linux Secret Service / encrypted-file vault backend, and (later) a Windows DPAPI backend — so the `SecretBroker` resolves live credentials from durable storage instead of the dev-only `InMemoryStore`. The critical constraint: **`crustcore-secrets` is a nano dependency** (nano links it for `SecretMaterial`/`Redactor`/`ModelVisibleText`), so every backend must be **feature-gated and absent from the nano build**. The trait crate's default build stays std-only; backends (FFI to keychains, an AEAD for the vault) live behind `#[cfg(feature = …)]` and never enter nano's dependency graph.

**Leverage.** Turns the dev-only in-memory broker into production-grade secret storage and is the at-rest half of the no-secret-to-model story (invariants 1–3): the model and the sandbox env still never see a key; now the key also lives encrypted on disk or in the OS keychain rather than seeded into a process. Every live phase (P7-live, P9-net, P10-net, P13-net) consumes it through the unchanged broker API, so it hardens all of them at once.

**Prerequisites:** Phase 8 broker core (DONE — `SecretStore` trait, `SecretBroker`, `ApprovedSecretView`, `CredentialProxy`, `Redactor`, zeroize-on-drop). None are live or blocking — this is local-only and can land in Wave 1.

**Tasks**

| Task | What | Owns |
|---|---|---|
| `P8S.1` | Backend module + feature flags, dep-clean by construction. Add a `store` submodule with cargo features `vault-file`, `macos-keychain`, `linux-keyring`; declare every heavy dep (`aes-gcm`/`chacha20poly1305`, `security-framework`, `secret-service`) `optional = true` so the **default** `crustcore-secrets` build (and the nano build) links none. Extend `xtask forbidden-deps` to assert the nano graph links no crypto/keychain crate. | `crates/crustcore-secrets/src/store/mod.rs, crates/crustcore-secrets/Cargo.toml, xtask/src/main.rs` |
| `P8S.2` | Encrypted-file vault (fully CI-testable). An `EncryptedVault` `SecretStore` impl: a passphrase-derived key (Argon2/scrypt KDF) over an audited AEAD; secrets sealed at rest, opened into a `SecretMaterial` that scrubs on drop; the plaintext never touches `Debug`/`Serialize`/disk. Deterministic round-trip + tamper tests run in CI on a temp file. | `crates/crustcore-secrets/src/store/vault.rs` |
| `P8S.3` | macOS Keychain backend (OS-gated). `KeychainStore` over `security-framework`; isolated, justified `unsafe`/FFI with a written rationale per CLAUDE.md §6.5; compiled only under `#[cfg(target_os = "macos")] + feature`. | `crates/crustcore-secrets/src/store/macos.rs` |
| `P8S.4` | Linux Secret Service backend (OS-gated). `SecretServiceStore` over D-Bus/libsecret; or fall back to the file vault where no keyring daemon exists; `#[cfg(target_os = "linux")] + feature`. | `crates/crustcore-secrets/src/store/linux.rs` |
| `P8S.5` | Property + red-team tests for at-rest confidentiality. Round-trip, scrub-on-drop (black_box-guarded), no-plaintext-at-rest (the on-disk bytes never contain the secret), and the existing secret-leak matrix extended to cover the store path. | `crates/crustcore-secrets/tests/store_redteam.rs` |
| `P8S.6` | Contract-doc update (serialized). Reflect the storage backends in `docs/secrets.md` §3 and the `crustcore-secrets` module doc. **Both are contract surfaces — routed as a dedicated maintainer-approved sub-PR**, landed before dependents adopt native stores. | `docs/secrets.md, crates/crustcore-secrets/src/lib.rs` |

**Deferral boundary.** CI-TESTABLE: the encrypted-file vault end to end (KDF + AEAD over a temp file, round-trip, tamper, scrub-on-drop, no-plaintext-at-rest) and all the trait wiring. OS-GATED (not in CI): the macOS Keychain and Linux Secret Service backends — compiled per-OS behind a feature, exercised by `#[ignore]`d integration tests that need a real keyring session. The broker keeps working with `InMemoryStore` for everything else, so no live phase is blocked.

**Contract-file impact.** **TWO contract files** — `crustcore-secrets/src/lib.rs` (adds the `store` module + feature plumbing) and `docs/secrets.md` (documents storage). Both go through a single serialized, maintainer-approved PR per §7.3, landed before dependent phases adopt native stores. The `SecretStore` *trait* is unchanged (backends implement the existing contract), which keeps the blast radius to additive module + features. `Cargo.toml` gains optional workspace deps (also serialized).

**Test / verify strategy.** Unit: vault KDF+AEAD round-trip, tamper-detect, scrub-on-drop, on-disk-bytes-never-contain-secret; broker resolves a credential from each store via the unchanged API. Red-team: extend the secret-leak matrix to the store path (a sealed secret is never `Debug`/`Serialize`/log-visible; `Redactor::would_leak == false`). Adversarial-review dimensions: (a) any plaintext path to disk/log/`Debug`?; (b) is the AEAD/KDF choice audited (no hand-rolled crypto for confidentiality)?; (c) does any backend dep leak into nano (forbidden-deps must catch it)?; (d) is `unsafe`/FFI isolated, justified, and tested?; (e) is the at-rest key zeroized on drop? `cargo xtask verify` green with the extended forbidden-deps gate.

**Parallelization.** P8S.1 (features + module skeleton, the serialized `Cargo.toml`/contract-lib gate) lands first. Then Worker A owns `store/vault.rs` + tests (the CI-testable core, highest value); Worker B owns `store/macos.rs`; Worker C owns `store/linux.rs` — disjoint files. The `docs/secrets.md` + `lib.rs` contract edits (P8S.6) are the integrator's serialized step.

**Best practices.** Never hand-roll confidentiality crypto — use an audited AEAD + a memory-hard KDF behind a feature; Keep `SecretMaterial` non-`Debug`/`Serialize`/`Clone` and zeroizing across every backend; The default (and nano) build links zero crypto/keychain crates — feature-gate ruthlessly and prove it with forbidden-deps; Isolate and justify every line of FFI/`unsafe` per §6.5; A backend opens a secret into a one-shot view, never a long-lived plaintext `String`.

**Risks.** Contract-file change (serialized — do not bundle); Hand-rolled crypto is a footgun (mandate an audited AEAD); FFI/`unsafe` for keychains needs isolation + justification; A backend dep leaking into nano would blow the size/forbidden-deps gate — the feature-gating + extended gate is a release blocker.

**Definition of done.**
- Encrypted-file vault round-trips, tamper-detects, scrubs on drop, and never writes plaintext — all proven in CI.
- macOS + Linux backends compile per-OS behind features with isolated/justified FFI and `#[ignore]`d integration coverage.
- The default and nano builds link zero crypto/keychain crates; the extended forbidden-deps gate proves it; nano size unchanged.
- `SecretMaterial` invariants (no `Debug`/`Serialize`/`Clone`, zeroize-on-drop) hold across all backends; secret-leak red-team green.
- `docs/secrets.md` + `crustcore-secrets/src/lib.rs` updated via a serialized maintainer-approved PR; `cargo xtask verify` green.

**Nano size impact.** Zero, by construction. All backends are feature-gated off in the nano build; nano keeps linking only the std-only trust types (`SecretMaterial`/`Redactor`/`ModelVisibleText`). The extended forbidden-deps gate asserts no crypto/keychain crate enters the nano graph; the size gate stays green at ~412.0 KiB.

---

### P9-net — Telegram Bot API loop (long-poll + send)  _(Track A)_

**Goal.** Wire the live Telegram Bot API (`getUpdates` long-poll + `sendMessage`) on top of the finished `crustcore-daemon::telegram` core (allowlist, dedupe, normalization, command routing, queue/steer, nonce-bound approvals, the typed→redacted `OutboundRenderer`). Raw updates flow into the existing `normalize → InboundEnvelope → Deduper` pipeline; outbound goes only through `OutboundRenderer` (typed → redacted `ModelVisibleText`, never raw model text). The bot token is resolved via the credential proxy — never in the env, never model-visible. HTTP lives in the spawned net helper, so the daemon links no TLS stack.

**Leverage.** Makes the **default human runtime channel** (invariant 15) operable: queue/steer of follow-ups, nonce-bound approvals for irreversible actions, and status — live. It is what turns CrustCore from a CLI harness into a steerable runtime, and it does so without the model ever gaining a direct outward channel (the renderer is the only egress).

**Prerequisites:** P9 core (DONE), the spawned-helper HTTP transport pattern proven by **P7-live** (Wave 2), the broker for the bot token (`InMemoryStore` suffices in dev; P8-store in prod).

**Tasks**

| Task | What | Owns |
|---|---|---|
| `P9N.1` | Telegram transport over the net helper. Express `getUpdates`/`sendMessage` as net-helper HTTP requests (reusing P7-live's `HttpClient`/transport), so the daemon links no HTTP/TLS; a `TelegramTransport` trait with a `ReplayTransport` for CI. | `crates/crustcore-daemon/src/telegram/transport.rs` |
| `P9N.2` | Long-poll loop. `getUpdates` with monotonic `offset`, bounded timeout, exponential backoff; each raw update fed through the existing `normalize → InboundEnvelope → Deduper` (value-floor dedupe) — no new trust logic. | `crates/crustcore-daemon/src/telegram/poll.rs` |
| `P9N.3` | Outbound send. Drive `sendMessage` from `OutboundRenderer` output only (typed → redacted `ModelVisibleText`); the model cannot emit arbitrary Telegram text; every outbound string passes the `Redactor`. | `crates/crustcore-daemon/src/telegram/send.rs` |
| `P9N.4` | Token via credential proxy + lease/heartbeat/reconnect. Bot token resolved per-call through the proxy (never env, never logged); a supervised loop with lease/heartbeat/cancellation/recovery (invariant 12). | `crates/crustcore-daemon/src/telegram/runtime.rs` |
| `P9N.5` | Replay tests + live-gated integration. CI drives the full loop via `ReplayTransport` replaying canned updates (allowlist deny, dedupe, command routing, approval-nonce round-trip); a `#[ignore]`d live test uses a real bot token out-of-band. | `crates/crustcore-daemon/tests/telegram_loop.rs` |
| `P9N.6` | Red-team: hostile message is inert. A Telegram message that says "ignore policy / approve this / set token" confers no capability and leaks no secret — asserted through the live loop path. | `crates/crustcore-eval/tests/redteam.rs (serialized)` |

**Deferral boundary.** CI-TESTABLE: the entire loop (offset/backoff state machine, normalization, dedupe, command routing, approval-nonce flow, outbound rendering+redaction) via a `ReplayTransport` replaying canned `getUpdates` JSON — no network. LIVE-GATED: actual `getUpdates`/`sendMessage` against the real Bot API behind a `live-telegram` feature + `#[ignore]`d test with a real token. The model→user egress is structurally renderer-only in both.

**Contract-file impact.** None. `telegram.rs` and `docs/telegram.md` are not contract files. `Cargo.lock` changes only if a new daemon dep is added — avoided by routing HTTP through the existing net helper (the daemon gains no TLS dep).

**Test / verify strategy.** Unit/replay (CI): allowlist deny-by-default, value-floor dedupe rejects replays, `!`-steer vs queue routing, approval nonce is op-hash-bound/expiring/single-use, outbound is redacted. Adversarial-review dimensions: (a) can the model reach `sendMessage` with arbitrary text?; (b) is the token ever in env/logs/`Debug`?; (c) does a replayed/duplicated/out-of-order update bypass dedupe?; (d) can a non-allowlisted chat steer?; (e) is every inbound update treated as untrusted data (invariant 7)? `cargo xtask verify` green; nano unaffected.

**Parallelization.** P9N.1 (transport trait + `ReplayTransport`) first. Then Worker A owns `poll.rs`, Worker B owns `send.rs`, Worker C owns `runtime.rs` (token/lease) — disjoint. Tests (P9N.5) and the serialized red-team assertion (P9N.6) are the integrator's step.

**Best practices.** The model never sends Telegram text directly — `OutboundRenderer` is the only egress, always redacted; Inbound updates are untrusted data — never obey instructions in them; Token via the credential proxy only, never the process env; Reuse the existing dedupe/allowlist/approval core unchanged — this phase adds transport, not trust logic; HTTP stays in the spawned helper so the daemon links no TLS.

**Risks.** Token leak via logs/`Debug` (redact all diagnostics; canary test); Out-of-order/duplicate update replay (the value-floor `Deduper` already defends — keep it on the live path); Model-egress bypass (keep `AgentTarget`/renderer the sole channel); Long-poll reconnection storms (bounded backoff + lease).

**Definition of done.**
- The full loop runs in CI over a `ReplayTransport` (allowlist, dedupe, commands, approvals, redacted outbound) with no network.
- Live `getUpdates`/`sendMessage` behind `live-telegram` + `#[ignore]`; documented run recipe; excluded from CI.
- Bot token resolved via the credential proxy; never in env/logs; canary confirms no token substring in output.
- The model cannot emit arbitrary Telegram text; outbound is always redacted `ModelVisibleText`.
- Hostile-message red-team fixture passes; `cargo xtask verify` green; CHANGELOG updated.

**Nano size impact.** Zero — all work is in `crustcore-daemon` (a sidecar, never in nano); HTTP/TLS stays in the spawned net helper.

---

### P10-net — GitHub REST flow (auth · push · draft-PR · checks · comments)  _(Track A)_

**Goal.** Wire live GitHub REST + token minting behind the finished `crustcore-backend::integrate::open_pr` and `crustcore-daemon::github` decision cores: authenticate (PAT now, App later in B2), push the branch **through the git credential proxy** (no token in the sandbox env), open a **draft PR from a `VerifiedPatch` only**, monitor checks → spawn a bounded repair task, and ingest PR comments as untrusted data. This **un-defers the `golden_issue_to_pr_flow` golden** — the headline end-to-end demonstration that a `VerifiedPatch` becomes a draft PR.

**Leverage.** The single most visible v0.2 unlock: it closes the loop from "a model proposed a patch" to "a verified change is sitting in a draft PR awaiting human merge," with every gate intact — only a `VerifiedPatch` opens a PR (invariant 13), merge needs `Approved<GitHubWriteCap>` (invariant 14), force-push is denied by default, and the multi-refspec `validate_push` (the bug a prior review caught) guards every ref.

**Prerequisites:** P10 core (DONE — `open_pr`, `RepoRegistry`, `validate_push`, `decide_merge`, `repair_decision`, `ingest_comment`), the broker for the token (`InMemoryStore` in dev), P5/verify for the `VerifiedPatch`. Pairs naturally with **P7-live** (so a real model produces the patch) but is independently developable against a fixture patch.

**Tasks**

| Task | What | Owns |
|---|---|---|
| `P10N.1` | GitHub REST client in the net helper. `create-ref`/`create-pull` (draft)/`get-check-runs`/`create-comment` as net-helper HTTP calls (reusing P7-live transport); a `GitHubApi` trait with a `MockGitHub` server impl for CI. | `crates/crustcore-net/src/github/**` |
| `P10N.2` | Branch push via the git credential proxy. Push through the Phase-8 `CredentialProxy` git-credential-helper shim so the token is injected by the trusted process, never placed in the sandbox env; reuse the structured multi-refspec `validate_push` (force-push/protected/out-of-prefix/host denied). | `crates/crustcore-net/src/github/push.rs` |
| `P10N.3` | Live `open_pr`. Make `open_pr(VerifiedPatch, Approved<GitHubWriteCap>)` actually call REST, building the PR body from verifier evidence (`format_pr_body`), never from a model's self-claim; draft only. | `crates/crustcore-backend/src/integrate.rs (live arm)` |
| `P10N.4` | Checks → repair loop. Poll check runs; on failure feed the bounded `repair_decision` to spawn a repair task; never auto-merge; surface status to Telegram. | `crates/crustcore-daemon/src/github/checks.rs` |
| `P10N.5` | Comment ingestion (untrusted). Wire `ingest_comment` to live comments; a PR comment is data — it never grants capability, approves, or reveals a secret. | `crates/crustcore-daemon/src/github/comments.rs` |
| `P10N.6` | Un-ignore the issue→PR golden. Drive the full flow against `MockGitHub` in CI; add an `#[ignore]`d live variant against a real throwaway repo. | `crates/crustcore-eval/tests/golden.rs` |
| `P10N.7` | Red-team through the live path. The existing `issue_comment_says_ignore_policy` fixture asserted through the live ingest/decide path; a push-smuggling attempt (multi-refspec) is rejected. | `crates/crustcore-eval/tests/redteam.rs (serialized)` |

**Deferral boundary.** CI-TESTABLE: the entire flow against a `MockGitHub` server — auth header shape, ref/PR/comment payloads, `validate_push` over every refspec, `decide_merge` ask-always, `repair_decision`, `ingest_comment` redaction, and the **golden issue→PR task end to end with no network**. The git-push proxy is tested against a local bare repo. LIVE-GATED: real REST against a throwaway repo behind a `live-github` feature + `#[ignore]`d test with a real token.

**Contract-file impact.** None. `integrate.rs`, `github.rs`, and `docs/github.md` are not contract files; the type-13/14 gates (`VerifiedPatch` by value, `Approved<GitHubWriteCap>`) are reused unchanged. `Cargo.lock` only if the net helper gains a dep (HTTP already there from P7-live).

**Test / verify strategy.** Unit/contract (CI, `MockGitHub`): draft-only PR creation, `format_pr_body` from evidence not self-claim, multi-refspec `validate_push` denials, ask-always merge, repair loop, comment redaction; the golden issue→PR passes. Adversarial-review dimensions: (a) can a non-`VerifiedPatch` open a PR?; (b) can merge proceed without `Approved`?; (c) can any refspec smuggle a force/protected update past `validate_push`?; (d) does the token ever reach the sandbox env or a log?; (e) is a PR comment ever treated as an instruction (invariant 7)?; (f) does the PR body ever contain a model self-claim instead of verifier evidence? `cargo xtask verify` green; nano unaffected.

**Parallelization.** P10N.1 (REST client trait + `MockGitHub`) first. Worker A owns `github/push.rs` (credential-proxy push), Worker B owns the `integrate.rs` live arm (P10N.3), Worker C owns `daemon/github/{checks,comments}.rs` (P10N.4/.5) — disjoint. The golden + red-team (P10N.6/.7, shared eval files) are the integrator's serialized step.

**Best practices.** Only a `VerifiedPatch` (by value) opens a PR, always draft; the PR body is verifier evidence, never a model self-claim; The token is injected by the credential proxy inside the trusted process — never the sandbox env, never a log; Validate **every** refspec on push (the structured `PushRequest`), force-push denied by default; PR comments and GitHub JSON are untrusted data — they inform, never authorize; Merge is always ask (invariant 14) — the agent never self-merges.

**Risks.** Refspec smuggling on push (reuse the structured multi-refspec `validate_push`; red-team it); Token leaking into the sandbox env or CI logs (credential-proxy injection + canary); A model self-claim leaking into the PR body (build the body from evidence only); Comment-as-instruction injection (invariant-7 wrapping; red-team fixture).

**Definition of done.**
- Draft PR opens from a `VerifiedPatch` + `Approved<GitHubWriteCap>` only; merge stays ask; force-push denied; every refspec validated.
- The issue→PR golden passes in CI against `MockGitHub`; an `#[ignore]`d live variant is documented and runs out-of-band.
- The branch push injects the token via the credential proxy; never in env/logs (canary confirms).
- PR comments ingested as untrusted data; the redaction + comment-injection red-team fixtures pass.
- `cargo xtask verify` green; CHANGELOG updated with phase id, PR, invariants (1, 7, 8, 13, 14).

**Nano size impact.** Zero — `integrate` is dead-code-eliminated in nano and the daemon/net-helper are sidecars; HTTP stays in the spawned helper.

---

### P11-exec — Subagent execution + integration-worktree verify  _(Track A)_

**Goal.** Make the std-only supervisor core in crates/crustcore-daemon/src/supervisor.rs drive real subagent executions and integrate only verified patches. Two halves: an ExecutionDriver that runs each subagent (native model roles via the spawned crustcore-net helper; external-worker roles via crustcore-backend::worker) each in its own throwaway worktree under registry-bound privilege, budgets, and blackboard reporting; and an integration-worktree step that merges candidate patches into one integration worktree, reruns the full verifier in a clean sandbox via crustcore-backend::verify::run_verify, and gates the merge on decide_integration so parallel worktrees merge only after a VerifiedPatch is minted. Lands entirely in the daemon (non-nano), filling the existing TODO(P11-exec) seams.

**Leverage.** Turns the tested supervisor decision core (registry, roles, budgets/scheduler, blackboard, decide_integration) into a working parallel orchestrator. Today the supervisor can decide who may integrate but cannot run a single subagent or produce an integration; P11-exec fills exactly that execution gap, the runtime embodiment of CLAUDE.md section 7. It unblocks P12 advisor/executor (same paused-executor boundary) and any multi-subagent self-improvement loop (P15), proving end-to-end that models propose while only CrustCore integrates, with every privilege bound to the registry and every merge gated on verifier evidence.

**Prerequisites:** P5 WorktreeManager + verify loop (run_verify, sole VerifiedPatch minter) - DONE, P6 external backend contract + run_external_worker + guard/diff/confinement - DONE, P7 net sidecar protocol (crustcore-netproto + spawned crustcore-net helper) - core DONE; P11-exec needs only the protocol plus a mock helper for CI, P11.1-P11.6 supervisor decision core - DONE; P11-exec fills its TODO(P11-exec) seams, Phase 8 secret broker - needed only for LIVE git-with-credentials paths; the secrets:none worker path needs nothing from it

**Tasks**

| Task | What | Owns |
|---|---|---|
| `P11x.1` | Wire daemon deps + ExecutionDriver trait — Add crustcore-backend and crustcore-worktree as deps of crustcore-daemon (non-nano; attach cargo tree for nano showing neither appears). Define a transport-agnostic ExecutionDriver trait in a new supervisor::exec module: run(spec: &AgentSpec, input: &SubagentInput) -> Result<SubagentOutcome, ExecError>. SubagentInput carries the registry-resolved Role, the per-subagent WorktreeRoot, the bounded untrusted goal/context (invariant 7), and the AgentBudget. The driver is the only thing that performs I/O; scheduling/blackboard/integration stay the pure core. Parameterize over the driver as run_verify_with/run_external_worker_with do, so CI injects a fake driver and live transports drop in behind a feature flag. Must NOT mint VerifiedPatch and must NOT add a User-addressable channel. | `crates/crustcore-daemon/Cargo.toml, crates/crustcore-daemon/src/supervisor/exec.rs (new), crates/crustcore-daemon/src/supervisor.rs -> supervisor/mod.rs` |
| `P11x.2` | Per-subagent worktree provisioning + registry-bound privilege — Each subagent gets its OWN disposable worktree via WorktreeManager::create_for keyed per AgentId (CLAUDE.md 7.4). Privilege is read from AgentRegistry by the message from id, NEVER the self-asserted AgentMessage.from_role (doc says display-only). Add reconcile(&AgentRegistry, &AgentMessage) -> Option<Role>; unknown agent => non-privileged, never Supervisor. CapabilityRequest is actioned only after reconcile, and only the registry-Supervisor may integrate/push/resolve secrets. Teardown each worktree on finish (Scheduler::finish + WorktreeManager::remove) on all exit paths. | `crates/crustcore-daemon/src/supervisor/exec.rs, crates/crustcore-daemon/src/supervisor/privilege.rs (new)` |
| `P11x.3` | Native model-backed subagent driver over the spawned net helper — ExecutionDriver for native roles (Planner/Researcher/RepoAnalyst/Architect/Implementer/Tester/Reviewer/SecurityAuditor) talking to the model transport via crustcore-netproto NetHelper probe+complete against the SPAWNED crustcore-net helper, never linking a model/HTTP stack into the daemon. Compacts a bounded prompt (untrusted context wrapped as data, invariant 7), meters tokens/output/wall against AgentBudget via AgentUsage::charge (refuse-on-overrun), and turns the model reply into structured blackboard AgentMessages, never direct user output. An Implementer writes its patch into ITS worktree; the patch is content-addressed from the worktree, never the model claim. Real model calls live-gated behind a live-subagents feature; CI uses a deterministic mock NetHelper. | `crates/crustcore-daemon/src/supervisor/native_driver.rs (new)` |
| `P11x.4` | External-worker subagent driver reusing run_external_worker — ExecutionDriver for ExternalCodex/ExternalClaudeCode/ExternalCommand roles delegating to crustcore_backend::worker::run_external_worker with WorkerInput::for_task, inheriting unchanged secrets:none/network:deny, the guard manifest out-of-root rejection, worktree diff extraction, path confinement, and sensitive-file classification. Maps WorkerProduct into a PatchProposal message + an UnverifiedPatch for integration; completes nothing. self_claimed_done/DONE_MARKER stay advisory (invariant 6). Mostly glue over already-tested backend/src/worker.rs. | `crates/crustcore-daemon/src/supervisor/external_driver.rs (new)` |
| `P11x.5` | Integration-worktree merge + full-verifier rerun gated on decide_integration — P11.6 proper: a fresh integration worktree via WorktreeManager::create_for, apply the candidate via the hardened git_apply wrapper (filter/textconv neutralized, no RCE), rerun the FULL user verify command in a clean sandbox through crustcore_backend::verify::run_verify. Per docs/backend-contract.md 4.2 ordering: collect blocking verdicts, call decide_integration(verdicts, verified = run_verify produced VerifiedPatch). Merge proceeds ONLY on IntegrationDecision::Integrate (all blocking approve AND a VerifiedPatch minted). NotVerified/BlockedBy/MissingReview abort and emit a PatchRejected-style event. Conflict on apply => reject candidate, surface a Risk, never force. | `crates/crustcore-daemon/src/supervisor/integration.rs (new)` |
| `P11x.6` | Bounded parallel fan-out loop: scheduler + budgets + blackboard drain — Bounded run loop: dispatch SubagentInputs to the Scheduler (try_spawn => ConcurrencyCap honored), run each via its ExecutionDriver selected by registry Role, accumulate AgentUsage per agent and refuse the breaching charge, drain blackboard messages for Supervisor + BroadcastToTeam, feed verdicts/patch proposals to integration. Caps: max concurrent subagents, per-subagent budget, and a global fan-out cap so a runaway planner cannot spawn unbounded children (CLAUDE.md 7.5). Deterministic given a fixed driver, so fully CI-testable with fakes. | `crates/crustcore-daemon/src/supervisor/run_loop.rs (new)` |
| `P11x.7` | Live-gated integration test + red-team fixture through the supervisor — Ignored/feature-gated integration test (live-subagents) running the external-worker driver end-to-end with a real codex/claude binary + real sandbox, asserting a failing-verify candidate is NOT integrated and a passing one is. Route the existing red-team scenario external worker writes outside the worktree THROUGH the supervisor driver path. Add a deterministic CI test that a subagent whose from_role claims Supervisor but whose registry id is non-supervisor CANNOT integrate/push/resolve secrets. | `crates/crustcore-daemon/tests/supervisor_exec.rs (new), crates/crustcore-eval/tests/redteam.rs (supervisor-path assertions only, serialized), tests/redteam/README.md` |

**Deferral boundary.** CI-testable deterministic core (no net/secrets): the ExecutionDriver trait and fake-driver-injected run loop; per-subagent worktree provisioning/teardown (real local git, gracefully skipped when git is absent as in existing worktree/worker tests); registry-bound privilege reconciliation; integration-worktree merge + decide_integration gating with a verify seam executor (as in verify.rs seam tests); budget/scheduler/fan-out enforcement; mapping WorkerProduct to blackboard messages; a mock NetHelper replaying a canned model transcript for the native driver. Live-gated (real creds/net/binaries, NOT in CI): real model calls through the spawned crustcore-net helper to live providers (depends on P7-live + Phase 8 broker) and real codex/claude subprocess execution. Gating: a live-subagents cargo feature on crustcore-daemon (off by default, off in cargo xtask verify) plus #[ignore] tests in crates/crustcore-daemon/tests/supervisor_exec.rs that run only with the feature + binaries present. CI exercises the native driver solely via the mock NetHelper. The integration-worktree real-sandbox arm runs only when a functional bubblewrap is present (probe-first, same pattern as golden_fix_failing_test_gates_completion).

**Contract-file impact.** Zero contract files in the core implementation. supervisor.rs is not a contract file (only kernel event.rs/action.rs, policy decision.rs, secrets lib.rs, the named docs, and Cargo.toml/Cargo.lock are). Two caveats: (1) Cargo.lock WILL change because crustcore-daemon gains crustcore-backend/crustcore-worktree deps; Cargo.lock is a contract file, so that bump is a serialized, maintainer-approved change (no new third-party deps - both are existing workspace crates, so the lock delta is internal-only; attach the diff). The workspace Cargo.toml does not need editing (deps go in the daemon's own manifest). (2) Reflecting the new execution semantics in docs/maintainer-agent.md or docs/advisor-executor.md section 6 is a SEPARATE serialized docs PR, not bundled here. No change to backend-contract.md, policy.md, secrets.md, sandbox.md, or kernel/secrets source: P11-exec consumes those contracts, it does not amend them.

**Test / verify strategy.** Unit (deterministic, every platform): fake-driver run loop produces expected blackboard messages and respects concurrency/budget caps; AgentUsage charge refuses each axis; privilege reconciliation returns the registry role and never elevates a spoofed from_role to Supervisor; integration-worktree merge uses a verify seam to assert Integrate only when all blocking approve AND a VerifiedPatch is minted, and that NotVerified/BlockedBy/MissingReview abort with no integration; git_apply conflict rejects the candidate. Reuse the executor-seam pattern from verify.rs/worker.rs so positive and negative paths run in CI without an OS sandbox. Adversarial-review dimensions (each finding independently refuted): (a) can a subagent reach the user or mint an approval? (b) does any code read from_role for privilege instead of the registry? (c) can an unverified/self-claimed patch reach integrate/complete/open_pr? (d) can a worker/model write outside its worktree and survive to integration? (e) is every model reply/transcript bounded and treated as data? (f) can fan-out or budget be bypassed (saturating math, missing charge, unbounded children)? (g) does a panicking/timed-out subagent leak a worktree or a slot? (h) does the native driver ever link or inherit a credential/env into the model call? Red-team fixtures: route external worker writes outside the worktree through the supervisor driver (assert OutOfRootWrite before integration); add a deterministic spoofed from_role=Supervisor assertion. cargo xtask verify (fmt, clippy -D warnings, workspace tests, nano size gate unchanged, nano forbidden-deps unaffected) must be green; attach cargo tree proving backend/worktree do not enter the nano build.

**Parallelization.** Land P11x.1 first (trait + Cargo deps + supervisor/mod.rs split) as a small serialized prerequisite, then fan out across disjoint new files: Worker A owns supervisor/exec.rs + supervisor/privilege.rs (P11x.1/.2); Worker B owns supervisor/native_driver.rs (P11x.3); Worker C owns supervisor/external_driver.rs (P11x.4); Worker D owns supervisor/integration.rs + supervisor/run_loop.rs (P11x.5/.6). Disjoint globs, no overlapping edits. Two shared touch-points are serialized: supervisor/mod.rs re-exports (the integrator wires them at merge time) and crates/crustcore-eval/tests/redteam.rs (assertions added in one dedicated commit, not in parallel, since redteam.rs is shared). The Cargo.lock bump is the integrator's serialized step. decide_integration stays untouched, so no contention there.

**Best practices.** Privilege is read from AgentRegistry by from id, NEVER the self-asserted AgentMessage.from_role. Reconcile every actionable message; unknown agent is non-privileged, never Supervisor.; Keep AgentTarget with no User variant - the no-direct-user-channel guarantee (invariant 5) stays structural. Drivers post only to the blackboard; the supervisor alone holds the outward channel.; Never link a model/HTTP/TLS or codex/claude stack into the daemon. Native model calls go through crustcore-netproto to the spawned crustcore-net helper; external workers are spawned subprocesses (invariants 19/20 posture, keeps the supervisor auditable).; Trust the worktree, not the worker/model: candidate patches are content-addressed and diffed from the worktree via the hardened git wrappers, never a self-reported diff (reuse worker.rs).; Each subagent gets its own disposable worktree; merge only into the integration worktree, only after run_verify mints a VerifiedPatch. Never force-apply; a failed git_apply rejects the candidate and surfaces a Risk.; VerifiedPatch is minted in exactly one place (verify::run_verify). Integration code calls it, never reconstructs or fakes it; integrate/complete accept VerifiedPatch by value.; Budgets enforced via AgentUsage::charge (refuse-on-overrun) plus Scheduler concurrency cap plus a global fan-out cap. Every axis bounded; runaway fan-out is a named threat.; All model replies and worker transcripts are untrusted data (invariant 7): wrapped, bounded (BoundedText/MAX_* caps), never interpreted as instructions.; Parameterize every I/O boundary over an injected executor/driver (mirroring run_verify_with/run_external_worker_with) so trust-critical logic is unit-tested deterministically, with live transports behind a feature flag.

**Risks.** Cargo.lock (contract file) changes when the daemon gains backend/worktree deps. Mitigation: serialized, maintainer-approved lock bump; cargo tree confirms the nano graph is unchanged (existing workspace crates, no new third-party deps).; Privilege confusion: self-asserted AgentMessage.from_role is a spoofing vector. Mitigation: reconcile against the registry by id for every actionable message; regression test that a spoofed from_role=Supervisor cannot integrate/push/resolve secrets.; VerifiedPatch bypass: integration code could fabricate verifier evidence. Mitigation: call verify::run_verify as the sole minter; integrate/complete take VerifiedPatch by value; adversarial dimension (c).; Worktree/slot leaks from a panicking/timed-out/budget-killed subagent. Mitigation: RAII-style teardown (finish + remove) on all exit paths; test the leak-free property.; Heavy-stack creep: pulling tokio/HTTP into the daemon for model calls. Mitigation: native driver talks only via crustcore-netproto to the spawned helper; forbid model/HTTP deps in the daemon manifest.; Confinement regressions if the external glue re-implements confinement instead of reusing run_external_worker. Mitigation: delegate wholesale to backend::worker; route the out-of-root red-team fixture through the supervisor path.; Untrusted-context injection from a malicious goal/repo file/model reply. Mitigation: invariant-7 wrapping + bounding of all context and replies; the supervisor never treats blackboard payloads as instructions.; Fan-out exhaustion from recursive subagent spawning. Mitigation: a global fan-out cap in addition to the per-batch concurrency cap; deterministic test of the cap.

**Definition of done.**
- crustcore-daemon depends on crustcore-backend + crustcore-worktree; cargo tree shows neither enters the nano build; Cargo.lock bump approved (no new third-party deps).
- ExecutionDriver trait + native_driver (mock NetHelper in CI) + external_driver (run_external_worker) + integration-worktree merge + bounded run loop implemented in supervisor/ submodules.
- Each subagent runs in its own disposable worktree; worktrees and concurrency slots torn down on every exit path (no leaks).
- Privilege bound to AgentRegistry by id; a spoofed from_role=Supervisor cannot integrate/push/resolve secrets (regression test passes).
- Parallel worktrees merge ONLY when decide_integration returns Integrate (all blocking reviewer/security/tester approve AND run_verify minted a VerifiedPatch); NotVerified/BlockedBy/MissingReview abort with no integration.
- VerifiedPatch minted solely by verify::run_verify; no fabricated-evidence path; integrate/complete take VerifiedPatch by value.
- Budgets enforced (AgentUsage::charge refuse-on-overrun, Scheduler cap, global fan-out cap) with deterministic tests.
- external worker writes outside the worktree red-team scenario asserted THROUGH the supervisor driver path; spoofed from_role assertion added.
- Live model/codex/claude paths behind the live-subagents feature + #[ignore], excluded from cargo xtask verify; CI uses fakes/mocks only.
- cargo xtask verify green (fmt, clippy -D warnings, workspace tests, nano size gate, forbidden-deps); CHANGELOG.md [Unreleased] updated with phase id P11-exec, branch, invariants touched (5,6,7,9,11,13), size impact n/a.

**Nano size impact.** Zero. All work lands in crustcore-daemon, a non-nano capability pack never linked into crustcore-nano. The two new daemon deps (crustcore-backend, crustcore-worktree) are existing workspace crates already absent from nano's dependency graph; verify with cargo tree -p crustcore --no-default-features --features nano and confirm cargo xtask size-check is unchanged from 412.0 KiB. Native model calls use the spawned crustcore-net helper via the std-only crustcore-netproto protocol, so no model/HTTP/TLS stack is linked near nano. No nano-affecting change, so no cargo-bloat delta is required for the size gate (attach the cargo tree as evidence the budget is untouched).

---

### P12-native — Native provider advisor (live second-model consult)  _(Track A)_

**Goal.** Replace the deterministic `SimulatedAdvisor` with a `NativeAdvisor` that routes a compacted `Consultation` through the spawned net helper to a real model and returns an advisory `AdvisorNote`. The load-bearing property is preserved **structurally**: advisor output is advisory, not policy — there is no path from an `AdvisorNote` to an `Approved<T>` or a capability, the advisor cannot reach the user, and the typed gates still decide what is permitted.

**Leverage.** Gives the executor a real higher-reasoning second opinion at the high-leverage moments the trigger set already defines (architecture decisions, large patches, dependency/workflow changes, security risk, before a GitHub push) — without ceding any authority. It is a judgment upgrade, not a policy change.

**Prerequisites:** P12 core (DONE — `AdvisorMode`, trigger set, `Consultation`, `Advisor` trait, `should_consult` budget control), **P7-live** (real model calls), and the **P11-exec** paused-executor boundary (shared seam).

**Tasks**

| Task | What | Owns |
|---|---|---|
| `P12N.1` | `NativeAdvisor` impl of the `Advisor` trait. Calls the spawned net helper (via `crustcore-netproto`) in the advisor role; no model/HTTP stack linked into the daemon. | `crates/crustcore-daemon/src/advisor/native.rs` |
| `P12N.2` | Compacted, bounded, untrusted-wrapped prompt. Render `Consultation` → a bounded prompt; the situation context is untrusted data (invariant 7), bounded by `MAX_*` caps. | `crates/crustcore-daemon/src/advisor/prompt.rs` |
| `P12N.3` | Reply → advisory `AdvisorNote` only. Parse the model reply into an `AdvisorNote`; it carries no capability, mints no approval; `should_consult` budget control unchanged. | `crates/crustcore-daemon/src/advisor/native.rs` |
| `P12N.4` | Mock-NetHelper CI test + structural guard. Deterministic CI test via a canned NetHelper; keep the existing structural test that advisor-proceed still leaves `decide_merge` at `RequiresApproval`. | `crates/crustcore-daemon/tests/advisor_native.rs` |
| `P12N.5` | Live-gated integration. `#[ignore]`d test against a real model behind `live-advisor`. | `crates/crustcore-daemon/tests/advisor_live.rs` |

**Deferral boundary.** CI-TESTABLE: trigger selection, consultation compaction, prompt bounding, reply→`AdvisorNote` mapping, the advisory-not-policy structural guard — all via a mock NetHelper replaying a canned advisor transcript. LIVE-GATED: real model consults behind `live-advisor` + `#[ignore]`.

**Contract-file impact.** None.

**Test / verify strategy.** Unit: advisor-proceed grants nothing (no `Approved<T>`, `decide_merge` stays `RequiresApproval`); budget caps consults; reply is bounded/untrusted. Adversarial-review dimensions: (a) any `AdvisorNote`→capability/approval path?; (b) can the advisor reach the user?; (c) is the consultation context bounded + treated as data?; (d) does the daemon link a model/HTTP stack? `cargo xtask verify` green.

**Parallelization.** Small phase — Worker A owns `advisor/native.rs` + `advisor/prompt.rs`; tests are the integrator's step. Shares the net-helper transport with P7-live (no file overlap).

**Best practices.** Advisory-not-policy stays structural — no `AdvisorNote`→`Approved<T>`; The advisor cannot message the user; Consultation context is bounded, untrusted data; Native calls go through the spawned helper — no model stack in the daemon; Budget every consult (`should_consult`).

**Risks.** Authority creep (keep the no-capability path structural; test it); Unbounded consult context (bound it); Heavy-stack creep into the daemon (helper-only).

**Definition of done.**
- `NativeAdvisor` returns advisory notes via the net helper; advisory-not-policy guard passes (no approval/capability path).
- CI runs the advisor over a mock NetHelper; live behind `live-advisor` + `#[ignore]`.
- Daemon links no model/HTTP stack; `cargo xtask verify` green; CHANGELOG updated.

**Nano size impact.** Zero (daemon sidecar; helper-mediated model calls).

---

### P13-net — MCP JSON-RPC transport + sandboxed code-mode exec  _(Track A)_

**Goal.** Add the live MCP JSON-RPC transport (stdio for local servers, HTTP via the net helper for remote) and sandboxed code-mode stub execution **under the existing gateway** — `gateway_check` (policy from `tool_policies`, never the server's self-description), `filter_result` (redact + bound + receipt), the registry with manifest-drift detection, and `generate_stubs` (only used tools). Server auth is broker-mediated; stub execution runs in the sandbox.

**Leverage.** Turns the tested MCP trust core into real tool access: external MCP servers become small, policy-checked, receipted, redacted typed APIs, with credentials injected at the gateway (never the model, never the sandbox) and only used tool stubs entering model context (invariant 20).

**Prerequisites:** P13 core (DONE — registry, `gateway_check`, `filter_result`, `generate_stubs`), the broker for `BrokerSecret` server auth, **P7-live** transport pattern (for HTTP MCP), and the **sandbox** for stub execution.

**Tasks**

| Task | What | Owns |
|---|---|---|
| `P13N.1` | JSON-RPC client (initialize · tools/list · tools/call). Over stdio (spawned local server) and HTTP (net helper); an `McpTransport` trait with a `MockMcp` peer for CI. | `crates/crustcore-mcp/src/transport/**` |
| `P13N.2` | Live manifest hash → drift gate. Compute the live tool-surface hash and feed `gateway_check` drift detection (a changed surface re-gates). | `crates/crustcore-mcp/src/manifest.rs` |
| `P13N.3` | Broker secret injection at the gateway. `BrokerSecret` → credential proxy at call time; the key never reaches the model or the sandbox env. | `crates/crustcore-mcp/src/gateway_live.rs` |
| `P13N.4` | Sandboxed code-mode stub execution. Run `generate_stubs` programmatic calls in the sandbox (refuse-if-no-backend); results go through `filter_result`. | `crates/crustcore-mcp/src/codemode.rs` |
| `P13N.5` | Mock-server CI tests + live-gated integration. Full gateway flow against `MockMcp`; `#[ignore]`d live test against a real MCP server. | `crates/crustcore-mcp/tests/mcp_live.rs` |
| `P13N.6` | Red-team through the live path. `mcp_hidden_instructions_are_inert` asserted across the live transport: hidden instructions/secrets in tool output/descriptions stay inert + redacted. | `crates/crustcore-eval/tests/redteam.rs (serialized)` |

**Deferral boundary.** CI-TESTABLE: the whole gateway path (decision from `tool_policies`, drift detection, redact+bound+receipt, stub generation, untrusted-output handling) against a `MockMcp` peer replaying canned `tools/list`/`tools/call`. LIVE-GATED: real stdio/HTTP transport behind `live-mcp` + `#[ignore]`; sandboxed stub exec gated on a functional bubblewrap (probe-first).

**Contract-file impact.** None (`crustcore-mcp` is not a contract crate).

**Test / verify strategy.** Unit/contract (CI): gateway decision unaffected by server self-description, drift re-gates, output redacted+bounded+receipted, only used tools get stubs. Adversarial-review dimensions: (a) can a server's description/output influence the gate?; (b) can it leak a secret past `filter_result`?; (c) does manifest drift actually re-gate?; (d) does stub exec ever run unsandboxed?; (e) is server auth ever model/sandbox-visible? `cargo xtask verify` green.

**Parallelization.** P13N.1 (transport trait + `MockMcp`) first. Worker A owns `manifest.rs`, Worker B owns `gateway_live.rs` (auth injection), Worker C owns `codemode.rs` (sandboxed exec) — disjoint. Tests + red-team are the integrator's step.

**Best practices.** The gate decides from `tool_policies`, never the server's self-description; All MCP output is untrusted data — redact + bound + receipt before model visibility; Server credentials injected at the gateway via the broker — never the model or the sandbox env; Stub execution is sandboxed (refuse-if-no-backend); Only used tool stubs enter model context (invariant 20).

**Risks.** Hidden-instruction injection via tool output/description (keep the gate text-blind; red-team); Secret leak in tool output (`filter_result` redaction; canary); Manifest drift not re-gating (compute + compare live hash); Unsandboxed stub exec (refuse-if-no-backend).

**Definition of done.**
- Live stdio + HTTP MCP transport under the existing gateway; CI runs the full flow over `MockMcp`.
- Manifest drift re-gates; output redacted+bounded+receipted; only used stubs in context.
- Server auth broker-mediated; never model/sandbox-visible; stub exec sandboxed.
- `mcp_hidden_instructions_are_inert` passes through the live path; `cargo xtask verify` green.

**Nano size impact.** Zero (`crustcore-mcp` pack; HTTP via the spawned helper).

---

### P14-live — Live repo map/grep + persistent memory + AST code-intel  _(Track A)_

**Goal.** Wire the live backends behind the existing `crustcore-index` traits: a `RepoMap` source from confined `git ls-files`, a `GrepCodeIntel` over confined `git grep -n`, a persistent `MemoryStore` backend (SQLite/redb), and a tree-sitter/LSP `CodeIntel`. **Memory stays never-authority** — every fragment remains redacted, bounded, provenance-tagged data with no path to `Approved<T>`. SQLite/tree-sitter are feature-gated and never enter nano (the index pack is already off-nano).

**Leverage.** Turns the deterministic retrieval/compaction core into real repo memory and code intelligence: better context capsules from a live repo, persistent failure/convention memory across runs, and symbol-accurate lookups — all still inert, redacted, never-authority data.

**Prerequisites:** P14 core (DONE — `RepoMap::from_paths`, `select_context`, `GrepCodeIntel`, `MemoryStore`), runner/sandbox for confined git exec. (Embedding-backed semantic retrieval is **B3**, not here.)

**Tasks**

| Task | What | Owns |
|---|---|---|
| `P14L.1` | Live repo map via confined `git ls-files`. Feed `RepoMap::from_paths` from a worktree-confined `git ls-files` (hardened git wrapper / runner); no file contents read. | `crates/crustcore-index/src/live/repomap.rs` |
| `P14L.2` | Live grep code-intel via confined `git grep -n`. `GrepCodeIntel` backed by confined `git grep`; bounded `SymbolRef`s. | `crates/crustcore-index/src/live/grep.rs` |
| `P14L.3` | Persistent `MemoryStore` (feature-gated). SQLite (`rusqlite`) or `redb` backend behind a `persist` feature; preserves the in-memory query semantics; never in nano. | `crates/crustcore-index/src/live/store_sqlite.rs` |
| `P14L.4` | tree-sitter `CodeIntel` (feature-gated). Symbol/AST lookups behind an `ast` feature; conservative fallbacks. | `crates/crustcore-index/src/live/treesitter.rs` |
| `P14L.5` | Memory-never-authority preserved. Live fragments still flow through redact-then-bound `select_context`; provenance-tagged; no capability path. | `crates/crustcore-index/src/lib.rs (wiring)` |
| `P14L.6` | Tests. Live git over a local temp repo (skip if no git); persistent-store round-trip; tree-sitter behind feature; the memory-as-authority red-team stays green. | `crates/crustcore-index/tests/live.rs` |

**Deferral boundary.** CI-TESTABLE: the pure transforms already are; live `git ls-files`/`git grep` tested against a local temp repo (gracefully skipped if git absent, like the worktree tests); persistent-store round-trip on a temp DB. FEATURE-GATED: SQLite/redb and tree-sitter behind `persist`/`ast` features — present in the index pack, never in nano. LIVE: none needs network; this is all local exec.

**Contract-file impact.** None (`crustcore-index` is not a contract crate).

**Test / verify strategy.** Unit: live repo map/grep over a temp repo match expected; persistent store round-trips and survives reopen; `select_context` still redacts+bounds; the `memory_says_authorized_is_inert` red-team stays green. Adversarial-review dimensions: (a) does the live git exec stay worktree-confined (no escape)?; (b) can any memory entry become authority?; (c) is model-visible context still redacted+bounded?; (d) do SQLite/tree-sitter leak into nano? `cargo xtask verify` green.

**Parallelization.** Worker A owns `live/repomap.rs` + `live/grep.rs` (confined git exec); Worker B owns `live/store_sqlite.rs` (persist); Worker C owns `live/treesitter.rs` (ast) — disjoint, each behind its own feature. Wiring + tests are the integrator's step.

**Best practices.** Live git runs through the hardened, worktree-confined wrappers — never raw shell; Memory stays never-authority — redacted, bounded, provenance-tagged, no capability path; SQLite/tree-sitter feature-gated, never in nano; Reuse the in-memory query semantics as the persistent contract; Bound every retrieved fragment.

**Risks.** Confinement escape via live git args (reuse the hardened wrappers; red-team); Heavy deps leaking into nano (feature-gate + forbidden-deps); Memory drifting toward authority (keep the structural guard + test).

**Definition of done.**
- Live repo map + grep over confined git work on a temp repo (skip-if-no-git); persistent store round-trips behind `persist`; tree-sitter behind `ast`.
- `select_context` still redacts+bounds; memory-as-authority red-team green.
- SQLite/tree-sitter never enter nano (forbidden-deps proves it); `cargo xtask verify` green.

**Nano size impact.** Zero — `crustcore-index` is never linked into nano; persistent/AST backends are additionally feature-gated within the pack.

---

### P5-join — Receipt ↔ event-log join (`verify_against_log`)  _(Track A)_

**Goal.** Implement the long-standing `TODO(P5)` in `crustcore-receipts`: cross-check that each receipt's `event_seq` resolves to a real, consistent frame in the hash-chained event log, and wire that check into `crustcore inspect`. This closes the last seam in the audit story — today a receipt is MAC-bound in isolation; after this, it is provably tied to a specific logged event.

**Leverage.** Completes the "I can replay what happened" promise: a verifier can confirm not just that the receipt chain and the event log are each internally intact, but that they *agree* — every model-visible tool result is anchored to an actual `ToolCall*` frame at its claimed sequence. Small, all-local, high audit value; deliberately landed early (Wave 1) because it de-risks nothing-else and needs no creds/net.

**Prerequisites:** P2 event log + receipts (DONE). None live — fully CI-testable.

**Tasks**

| Task | What | Owns |
|---|---|---|
| `P5J.1` | `verify_against_log(&ReceiptChain, &EventLog) -> JoinStatus`. For each receipt, resolve its `event_seq` to a frame and assert kind/id consistency (a `ToolCallCompleted`-class frame at that seq with matching task/job/tool-call ids); report the first mismatch. | `crates/crustcore-receipts/src/join.rs` |
| `P5J.2` | Wire into `crustcore inspect`. `inspect` cross-verifies receipts↔log when both are present and reports JOINED/BROKEN alongside the chain status. | `crates/crustcore/src/main.rs (inspect)` |
| `P5J.3` | Tamper tests. A receipt pointing at a missing/wrong-seq/wrong-kind frame is detected; the happy path joins cleanly. | `crates/crustcore-receipts/tests/join.rs` |
| `P5J.4` | Doc refresh. Update `docs/receipts.md` §6 and the module doc to describe the join (not a contract file). | `docs/receipts.md, crates/crustcore-receipts/src/lib.rs` |

**Deferral boundary.** Fully CI-testable — no net, no secrets, no exec. The easiest, all-local phase; nothing is deferred.

**Contract-file impact.** None. `crustcore-receipts/src/lib.rs` and `crustcore-eventlog/src/lib.rs` are not contract files (only the kernel `event.rs`/`action.rs`, policy `decision.rs`, and secrets `lib.rs` are); `docs/receipts.md` is not contract.

**Test / verify strategy.** Unit: a consistent receipt+log pair joins; a receipt with a missing/mismatched `event_seq` or wrong frame kind is detected; `inspect` reports the join. Adversarial-review dimensions: (a) can a forged receipt point at an unrelated frame and pass?; (b) does the join handle a truncated/partial log without panic?; (c) is the cross-check order-independent and deterministic? `cargo xtask verify` green.

**Parallelization.** Single small worker owns `receipts/src/join.rs` + tests; the `inspect` wiring (shared `main.rs`) and the `docs/receipts.md` refresh are the integrator's step. No fan-out needed.

**Best practices.** The join is read-only verification — it mints nothing and changes no state; Deterministic, order-independent, no-panic on a truncated log; Reuse the existing decode/verify primitives; Report the first mismatch with its frame index, like the chain verifier.

**Risks.** A forged receipt slipping past a weak consistency check (assert kind + all ids, not just seq presence); Panic on a malformed/truncated log (reuse the hardened decoder; fuzz it).

**Definition of done.**
- `verify_against_log` detects missing/mismatched/wrong-kind receipt→frame links and joins a consistent pair; tamper tests pass.
- `crustcore inspect` reports the receipt↔log join; no-panic on truncated input.
- `docs/receipts.md` refreshed; `cargo xtask verify` green; nano size delta minimal and within budget.

**Nano size impact.** Minimal — the join code links into nano via `inspect` (receipts + eventlog are already nano deps), adding a small, std-only verification routine. Well within the ~388 KiB of headroom; the size gate stays green. Attach a `cargo bloat` line if the delta is non-trivial.

---

## Track B — detailed surface plans (expand)

### B1-mcp-modes — Full MCP server + client modes (beyond the gateway)  _(Track B)_

**Goal.** Extend `crustcore-mcp` from gateway-only to the full triad: an **MCP server** that exposes selected CrustCore capabilities to other MCP clients (policy-gated, receipted, redacted), a complete **client** experience (registry UX, discovery), and full **code-mode** programmatic tool calling. Every exposed tool is policy-checked and bounded; nothing exposes secrets, approvals, or the kernel.

**Leverage.** Lets CrustCore both consume *and* be consumed in the MCP ecosystem — e.g. another agent can call CrustCore's verifier or inspect tools through a typed, audited surface — without widening the trust boundary.

**Prerequisites:** **P13-net** (live MCP transport under the gateway). Builds on its `McpTransport`.

**Tasks**

| Task | What | Owns |
|---|---|---|
| `B1.1` | MCP server: expose a curated tool set (e.g. verify, inspect) behind policy + receipts + redaction; never expose secrets/approvals/kernel internals. | `crates/crustcore-mcp/src/server/**` |
| `B1.2` | Server transport (stdio + HTTP) reusing the P13 transport; untrusted inbound requests as data. | `crates/crustcore-mcp/src/server/transport.rs` |
| `B1.3` | Full client/registry UX: discovery, admission flow, per-repo scoping. | `crates/crustcore-mcp/src/client/**` |
| `B1.4` | Mock-peer CI tests + live-gated integration; red-team: a hostile client cannot escalate. | `crates/crustcore-mcp/tests/server.rs` |

**Deferral boundary.** Server/client protocol + policy logic CI-testable with mock peers; live transport behind a feature + `#[ignore]`d tests.

**Contract-file impact.** None. **Nano size impact.** Zero (mcp pack).

**Test / verify strategy.** Exposed tools are policy-gated/receipted/redacted; a hostile inbound request is untrusted data and grants nothing; adversarial dimensions: capability escalation, secret exposure, unbounded output. `cargo xtask verify` green.

**Parallelization.** Worker A owns `server/**`, Worker B owns `client/**` — disjoint. **Definition of done.** Server exposes only curated, policy-gated, receipted tools; client/registry UX complete; mock-peer CI green; hostile-client red-team passes.

---

### B2-gh-app — Full GitHub App flow + hardened webhook server  _(Track B)_

**Goal.** Move from PAT/credential-proxy auth to a proper **GitHub App** (JWT-signed installation tokens, minted via the broker) and add a **hardened inbound webhook server** that turns untrusted GitHub payloads into kernel events (`GitHubEnvelope → Event::GitHubObserved`) with signature verification and strict bounding. The webhook server is a separate hardened sidecar — never nano.

**Leverage.** Production GitHub posture: fine-grained, revocable installation permissions instead of a broad PAT, and event-driven reactivity (issues, PR updates, check completions) instead of polling.

**Prerequisites:** **P10-net** (GitHub REST). Reuses its REST client + credential proxy.

**Tasks**

| Task | What | Owns |
|---|---|---|
| `B2.1` | App auth: JWT signing + installation-token minting via the broker (key never model/sandbox-visible). | `crates/crustcore-net/src/github/app.rs` |
| `B2.2` | Webhook server: a hardened HTTP listener (separate process), HMAC signature verification, bounded payloads → `GitHubEnvelope`. | `crates/crustcore-daemon/src/webhook/**` |
| `B2.3` | Payload → event mapping; everything inbound is untrusted data (invariant 7). | `crates/crustcore-daemon/src/webhook/map.rs` |
| `B2.4` | Mock-signed-payload CI tests + live-gated App install; red-team: forged/replayed/oversized payloads rejected. | `crates/crustcore-daemon/tests/webhook.rs` |

**Deferral boundary.** JWT/token logic + signature verification + payload parsing CI-testable with fixtures; live App + public webhook endpoint behind a feature + manual setup.

**Contract-file impact.** None (auth/webhook code is not contract). The webhook listener is a new sidecar; never nano. **Nano size impact.** Zero.

**Test / verify strategy.** Signature verification rejects forged/replayed/oversized payloads; tokens never reach env/logs; payloads are bounded untrusted data. Adversarial dimensions: signature bypass, replay, payload injection, token leak. `cargo xtask verify` green.

**Parallelization.** Worker A owns `github/app.rs` (auth), Worker B owns `webhook/**` (server) — disjoint. **Definition of done.** App installation tokens minted via the broker; webhook verifies HMAC + bounds payloads + maps to events; forged/replayed/oversized payloads rejected (red-team); no token leak.

---

### B3-vector-memory — Embeddings / vector memory + richer code intelligence  _(Track B)_

**Goal.** Add embedding-backed semantic retrieval and a vector store to `crustcore-index`, plus richer code intelligence, on top of P14-live's persistent memory — **still memory-is-never-authority, redacted and bounded**. Embedding calls route through the spawned net helper (an embedding provider); the vector store is feature-gated within the pack and never enters nano.

**Leverage.** Semantic recall (vs. keyword overlap) makes the small context capsules markedly more relevant — the model gets the *right* prior observations, not just lexically-matching ones — while every fragment stays inert, redacted, provenance-tagged data.

**Prerequisites:** **P7-live** (embedding calls via the net helper) and **P14-live** (persistent store).

**Tasks**

| Task | What | Owns |
|---|---|---|
| `B3.1` | Embedding provider over the net helper (reuse P7-live transport); bounded inputs. | `crates/crustcore-index/src/embed/**` |
| `B3.2` | Vector store (feature-gated) + nearest-neighbor retrieval; deterministic over canned embeddings in CI. | `crates/crustcore-index/src/embed/store.rs` |
| `B3.3` | Semantic `select_context`: rank by embedding similarity, still redact-then-bound, still never-authority. | `crates/crustcore-index/src/embed/select.rs` |
| `B3.4` | Retrieval-quality eval + red-team (a hostile embedded doc is inert). | `crates/crustcore-index/tests/semantic.rs` |

**Deferral boundary.** Ranking/store/select logic CI-testable with canned embedding vectors; live embedding calls behind a feature + `#[ignore]`d tests.

**Contract-file impact.** None. **Nano size impact.** Zero (index pack; vector store feature-gated).

**Test / verify strategy.** Semantic select still redacts+bounds and stays never-authority; retrieval is deterministic over fixtures; adversarial dimensions: hostile-doc-as-authority, secret in an embedded doc, unbounded context. `cargo xtask verify` green.

**Parallelization.** Worker A owns `embed/store.rs` + `embed/select.rs`; Worker B owns `embed/**` provider — disjoint. **Definition of done.** Semantic retrieval improves capsule relevance over fixtures; memory stays never-authority + redacted + bounded; embeddings via the helper behind a feature; red-team green.

---

### B4-sandbox-tiers — Firecracker/microVM Tier-3 + Windows native sandbox  _(Track B)_

**Goal.** Add stronger and broader execution backends behind the existing `SandboxBackend` trait: a **Tier-3 microVM** (Firecracker) backend for hostile-code isolation, and a **Windows-native** backend (job objects / AppContainer), keeping the refuse-if-no-backend posture. Heavy/OS-specific backends are feature-gated and absent from nano. `docs/sandbox.md` is a contract file — changes are serialized.

**Leverage.** Raises the execution-isolation ceiling (microVM for untrusted code) and broadens platform reach (Windows) without weakening the v0.1 Linux bubblewrap default — strictly additive backends behind one trait.

**Prerequisites:** P4 sandbox core (DONE). Independent of the other phases.

**Tasks**

| Task | What | Owns |
|---|---|---|
| `B4.1` | Firecracker Tier-3 backend: VM lifecycle, minimal rootfs, deny-all egress, bounded resources; `#[cfg]` + feature. | `crates/crustcore-sandbox/src/backends/firecracker.rs` |
| `B4.2` | Windows-native backend: job objects / AppContainer confinement, env sanitation; `#[cfg(windows)]` + feature. | `crates/crustcore-sandbox/src/backends/windows.rs` |
| `B4.3` | Tier selection + refuse-if-no-backend across the new tiers; backend order. | `crates/crustcore-sandbox/src/lib.rs (selection)` |
| `B4.4` | `docs/sandbox.md` update (CONTRACT — serialized) + red-team: an escape attempt fails under each backend. | `docs/sandbox.md, crates/crustcore-sandbox/tests/backends.rs` |

**Deferral boundary.** Backend selection + profile/refusal logic CI-testable; actual VM/Windows execution behind features + OS-gated `#[ignore]`d tests (CI has no Firecracker/Windows).

**Contract-file impact.** **`docs/sandbox.md`** is a §7.3 contract file — serialized, maintainer-approved. **Nano size impact.** Zero — new backends are feature-gated off in nano; bubblewrap stays the default; the forbidden-deps gate proves no VM/Windows dep enters nano. (The bubblewrap backend stays std-only `process`.)

**Test / verify strategy.** Selection picks the strongest available tier and refuses when none; profile/env sanitation preserved; adversarial dimensions: egress escape, FS escape, env leak, resource exhaustion per backend. `cargo xtask verify` green with the extended forbidden-deps gate.

**Parallelization.** Worker A owns `backends/firecracker.rs`, Worker B owns `backends/windows.rs`, Worker C owns selection — disjoint; the `docs/sandbox.md` contract edit is the integrator's serialized step. **Definition of done.** Firecracker + Windows backends behind features with OS-gated tests; refuse-if-no-backend preserved; no VM/Windows dep in nano; escape red-team passes; `docs/sandbox.md` updated via serialized PR.

---

### B5-autoloop — Live self-improvement loop + multi-repo orchestration  _(Track B)_

**Goal.** Run the PR/eval-gated self-improvement loop (`crustcore-daemon::selfimprove`) **end to end** — classify → propose → generate evals → self-PR → contract-gate → human merge — using real evals and real PRs, **still with no live kernel mutation and the contract-file gate enforced** (invariant 18). Add multi-repo task orchestration across the supervisor, and an optional provider-hosted code-execution executor as a `CodingBackend`.

**Leverage.** Closes the highest-order loop: CrustCore proposing its own improvements as gated, evidence-backed, human-merged PRs — and operating across more than one repository — while the structural guarantees (no live mutation, type-sealed `ReadyProposal`, contract-gate flags any guardrail touch) hold exactly as built.

**Prerequisites:** **P7-live** (real eval/model runs), **P10-net** (real PRs), **P11-exec** (subagent orchestration), P15 self-improvement core (DONE).

**Tasks**

| Task | What | Owns |
|---|---|---|
| `B5.1` | Drive the loop with real evals: a proposal advances only with `Demonstrates`+`GuardsRegression` evals actually run (via P11-exec workers); contract-gate enforced. | `crates/crustcore-daemon/src/selfimprove/runner.rs` |
| `B5.2` | Real self-PR via P10-net (draft only, never self-merge); contract-touching PRs blocked pending maintainer. | `crates/crustcore-daemon/src/selfimprove/pr.rs` |
| `B5.3` | Multi-repo orchestration: task routing across a `RepoRegistry` set; per-repo confinement + budgets. | `crates/crustcore-daemon/src/multirepo.rs` |
| `B5.4` | Optional provider-hosted executor as a `CodingBackend` (sandbox-equivalent guarantees); red-team: a proposal cannot weaken a guardrail or self-merge. | `crates/crustcore-backend/src/hosted.rs` |

**Deferral boundary.** The gate/proposal/eval-requirement logic is CI-tested (P15 done); the *live* loop (real evals, real PRs, multi-repo) behind a `live-autoloop` feature + the live providers/GitHub, run out-of-band.

**Contract-file impact.** None (`selfimprove` is not contract). **Nano size impact.** Zero (daemon sidecar).

**Test / verify strategy.** No live kernel mutation (structural); a contract-touching self-PR is blocked; an evidence-free proposal cannot advance; self-PRs are draft + never self-merge. Adversarial dimensions: silent weakening, self-merge, memory-as-authority, multi-repo confinement escape, budget exhaustion. `cargo xtask verify` green.

**Parallelization.** Worker A owns `selfimprove/runner.rs` + `selfimprove/pr.rs`; Worker B owns `multirepo.rs`; Worker C owns `backend/hosted.rs` — disjoint. **Definition of done.** The loop runs end-to-end behind `live-autoloop` with the contract-gate + no-live-mutation guarantees intact; multi-repo tasks stay confined + budgeted; self-PRs are draft-only; silent-weakening + self-merge red-team passes.

---

### B6-release-infra — Signed CI releases · reproducible builds · fuzz/bloat CI · TUI · packaging  _(Track B)_

**Goal.** Productionize delivery on top of the existing `cargo xtask release` + `docs/releasing.md`: a **signed GitHub Actions release job** (build → `xtask release` → sign `SHA256SUMS` → upload), **bit-reproducible builds**, **`cargo-bloat` + fuzz CI jobs**, an optional **rich TUI** (a separate non-nano binary), and **package publishing** (crates.io / Homebrew). The release workflow + signing key are **irreversible, maintainer-owned** steps (CLAUDE.md §6.3) — tooling is wired; the keyed/irreversible actions are not agent-performed.

**Leverage.** Turns "releasable" into "released, signed, auditable, and installable" — the operational maturity layer — while keeping the irreversible bits under explicit human control.

**Prerequisites:** Phase 16 release tooling (DONE — `cargo xtask release`, `SHA256SUMS`, `docs/releasing.md`, installer). Independent of Track A.

**Tasks**

| Task | What | Owns |
|---|---|---|
| `B6.1` | Signed GH Actions release workflow (build → `xtask release` → sign → upload). **Irreversible/CI-credentialed — maintainer-authored, serialized.** | `.github/workflows/release.yml` |
| `B6.2` | Bit-reproducible builds: pinned toolchain, `--remap-path-prefix`, `SOURCE_DATE_EPOCH`; verify the digest reproduces. | `xtask/src/main.rs, rust-toolchain.toml` |
| `B6.3` | CI hardening jobs: `cargo-bloat` report + a fuzz job (the existing no-panic fuzzers) in CI. | `.github/workflows/ci.yml` |
| `B6.4` | Optional rich TUI (separate non-nano binary) + package publishing (crates.io/Homebrew). | `crates/crustcore-tui/** (new), packaging/**` |

**Deferral boundary.** Reproducible-build flags + bloat/fuzz jobs are CI-testable. The signed release workflow + signing key are **irreversible, maintainer-owned** (not agent-wired). The TUI is a separate optional binary; packaging is a release-time action.

**Contract-file impact.** Editing `.github/workflows/**` is an **irreversible** action (§6.3) — maintainer-owned, serialized. **Nano size impact.** Zero — the TUI/packaging are separate, non-nano artifacts.

**Test / verify strategy.** Reproducible build produces a matching digest across two runs; bloat/fuzz jobs run in CI; the release workflow is reviewed by a maintainer before merge. `cargo xtask verify` green; the size gate stays green.

**Parallelization.** Worker A owns the reproducible-build flags (B6.2) + CI hardening (B6.3); Worker B owns the TUI/packaging (B6.4). The release workflow (B6.1) is a **maintainer-authored serialized PR**, not a worker task. **Definition of done.** Builds reproduce a matching digest; bloat/fuzz jobs run in CI; the signed release workflow is maintainer-merged and produces signed, checksummed artifacts; optional TUI + packaging ship as separate non-nano artifacts; nano stays under budget.
