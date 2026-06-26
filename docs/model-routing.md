# docs/model-routing.md — Providers and Model Routing

> **Purpose:** specify how CrustCore discovers providers and models, routes
> requests by role and constraint, composes meta-providers for reliability and
> cost control, accounts for budget — and how it does all this without nano ever
> linking an HTTP/TLS stack.

**Source of truth:** [`ROADMAP.md` §13.1–§13.2](../ROADMAP.md) (providers,
router, meta-providers), [`ROADMAP.md` §18 Phase 7](../ROADMAP.md)
(tasks/acceptance), [`ROADMAP.md` §2.2](../ROADMAP.md) (`crustcore-net`).
**Governs / governed by:** invariants **17, 11, 20** in
[`INVARIANTS.md`](../INVARIANTS.md).
**Siblings:** [`advisor-executor.md`](./advisor-executor.md),
[`mcp.md`](./mcp.md), [`telegram.md`](./telegram.md), [`github.md`](./github.md).

---

## 1. Providers are discovered, not hard-coded

Invariant **17**: *model/provider names are config and capability-probed, not
permanent assumptions.* Model availability changes constantly; a hard-coded
"this model exists / supports tools / has N context" rots and misroutes. CrustCore
**probes** providers and keeps a **dynamic local registry** of what each one
actually offers ([`ROADMAP.md` §13.1](../ROADMAP.md), invariant 17 enforcement).

Supported providers through configuration / capability discovery:

```text
OpenAI
Anthropic
OpenRouter
local OpenAI-compatible endpoints (Ollama / vLLM / LM Studio)
```

The local OpenAI-compatible family matters for privacy and the local-fallback
path (§4): the same adapter shape serves any endpoint that speaks the
OpenAI-compatible API.

### 1.1 The capability probe and registry

At startup / on demand, the net sidecar probes each configured provider and
records, per model: available? context length, tool/function-call support,
structured-output support, streaming support, rate limits, health. This local
registry is the **source of truth for routing** — not a baked-in table. Phase 7
acceptance: *"Model registry is dynamic."*

Edge cases:

- A model that disappears from a provider drops out of the registry on the next
  probe; routing stops selecting it instead of failing requests against a dead
  name.
- A newly added model appears without a code change — discovery, not a release.
- Probe results are cached with a TTL; health is refreshed so a degraded provider
  is detected and routed around.

### 1.2 Multi-modal capability registry (completion · embedding · rerank)

The registry is **one shape across modalities** (Track C `C1-providers`). The same
`ModelCard` carries the completion capabilities above *plus* three additive,
**default-off** capability flags:

```text
embeddings     : bool   (default off)  — model can serve /v1/embeddings
rerank         : bool   (default off)  — model can serve /v1/rerank
embedding_dims : u32    (default 0)    — vector dimensionality (0 = unknown)
```

These flags flow through **both** records: the `ModelCard` in `crustcore-net` and
its wire mirror `ModelInfo` in the std-only `crustcore-netproto`, via the existing
`ModelCard::to_info` mapping — so the probe surfaces capability across the spawned-
helper boundary. They are **additive only**: the completion fields, their ordering,
and the completion `to_info` mapping are byte-identical, so completion routing is
unchanged.

Conservative-off is enforced at **both** layers (invariant 17 — a forgotten
capability classification fails closed, never on by omission):

- **Config parse** (`config.rs`): `embeddings`/`rerank` default `false`,
  `embedding_dims` defaults `0` — unlike `streaming`, which defaults `true`.
- **Wire decode** (`crustcore-netproto`): a `model` line lacking the new keys decodes
  to `embeddings=false`/`rerank=false`/`embedding_dims=0`.

Completion, embedding, and rerank compose under the **same** abstraction:

```text
Provider        + Engine        + select_candidates  (completion — frozen P7-live)
EmbedProvider   + EmbedEngine   + select_candidates_for(Embedding, ..)
RerankProvider  + RerankEngine  + select_candidates_for(Rerank, ..)
```

`EmbedProvider`/`RerankProvider` are **sibling** sync traits mirroring `Provider`'s
`id`/`probe`/call shape exactly; the per-modality engines reuse the same
hard-constraint-then-role-order filter (gating on `card.embeddings`/`card.rerank` and
`embedding_dims`), the same `run_reliable`-shaped fallback, and the **same single
`BudgetLedger` instance** — one per-task ceiling is honored across all three
modalities, not split three ways (invariant 11). A request with no capability-matching
model **fails closed** with a typed `NoModelForConstraints` error rather than silently
routing to a completion-only model.

The trust boundary is exactly where P7-live put it. Credentials still resolve
**per call** through the `CredentialSource`/`AuthHeader` adapter (never stored on the
embed/rerank adapters, never carried into the sandbox/helper env — invariants 1–3).
Every provider byte stays untrusted and bounded: embedding batches are capped by
`MAX_BATCH`, documents by `MAX_DOCS`, dimensions by `MAX_EMBEDDING_DIMS`; non-finite
floats are sanitized to `0.0`; and **rerank indices are validated against the request's
document count — out-of-range and duplicate indices are dropped, never propagated raw
into downstream selection** (invariants 7, 11). Error paths reuse `map_status_error`,
so a non-2xx maps to a status-only `ProviderError` and never echoes a response body
that could carry a credential.

The wire protocol gains additive, bounded variants — `Request::Embed`/`Request::Rerank`
and `Response::Embedding`/`Response::Ranking` — alongside `complete`/`probe`; the
`serve` loop routes them through the new engines, and `NetHelper` gains `embed`/`rerank`
client methods (bounded, single-shot, like `complete`).

**Consumer relationship.** `C1-providers` is the **producer** that `B3-vector-memory`
consumes: B3's "embedding provider over the net helper" is exactly this crate's
net-side `crustcore-net::EmbedProvider` routed by this registry, which becomes the live
backend fulfilling B3's *consumer-side* `crustcore-index::embed::Embedder` trait. The
two are deliberately distinct — `C1` owns the routed *provider* trait in
`crustcore-net`; B3 owns the *consumer* trait in `crustcore-index` and builds **on**
this registry rather than beside it. Rerank likewise unblocks rerank-assisted context
selection in `crustcore-index::select_context` without that crate ever linking HTTP/TLS.

All of this lives in the non-nano sidecar; the live sockets stay behind the existing
`live` feature and the default/CI build links nothing new (invariants 19, 20 — see §6).

---

## 2. Model roles

Routing is **role-driven**. Example roles ([`ROADMAP.md` §13.1](../ROADMAP.md)):

```text
high reasoning / advisor : strongest available model
implementation           : strong coding model
review / security        : high-reasoning model
research / summarization  : cheaper, fast model
local fallback           : local endpoint
```

A role is an *abstract requirement*, resolved against the dynamic registry at
request time — "give me the strongest available reasoning model that supports
tools and fits the budget," not "use model X." The advisor role here is the one
consumed by [`advisor-executor.md`](./advisor-executor.md).

---

## 3. The provider router

The router selects a concrete provider+model for a request from these inputs
([`ROADMAP.md` §13.2](../ROADMAP.md)):

```text
role
required capabilities      (tools, structured output, context length, ...)
privacy policy             (e.g. must stay local / must not leave a boundary)
cost budget
latency target
context length
tool support
structured output support
provider health
rate limits
```

The router consults the dynamic registry (§1.1) to find candidates that satisfy
the hard constraints (capabilities, privacy, context length, tool/structured-
output support) and then orders them by the soft objectives (cost, latency,
health). A request that no available model can satisfy fails explicitly with a
typed reason rather than silently downgrading past a hard constraint (e.g. a
privacy-must-stay-local request never routes to a remote provider).

---

## 4. Meta-providers

CrustCore composes routing behavior from **meta-provider behaviors** — each adds one
policy ([`ROADMAP.md` §13.2](../ROADMAP.md)). They are realized as **composable
functions over the candidate list** (not wrapper structs), so they compose by
sequencing: `Engine::complete` runs Router → Budget → Reliable
(`select_candidates` → `apply_budget` → `run_reliable`). Two further behaviors are
**opt-in engine methods**: `LocalFallbackProvider` (`ensure_local_fallback`, via
`Engine::complete_with_local_fallback`) reorders the already-filtered candidates so a
local model is tried *last* — a true last-resort degrade; `FusionProvider`
(`run_fusion`, via `Engine::fusion_panel`) runs the strongest *n* candidates and
returns each result as a panel for the caller (e.g. the advisor) to fuse.

| Meta-provider | Behavior | Primary concern |
| --- | --- | --- |
| `ReliableProvider` | **Fallback chain** — try providers in order until one succeeds | availability |
| `RouterProvider` | **Hint/role-based routing** — pick a provider by role + registry | correctness of selection |
| `BudgetProvider` | **Cost ceiling** — refuse/route-down when a budget would be exceeded | invariant 11 (budget) |
| `LocalFallbackProvider` | **Degrade to a local model** when remote is unavailable/over-budget/privacy-bound | resilience + privacy |
| `FusionProvider` | **Deliberate multi-model path** for high-risk planning/review | quality on high-risk steps |

Notes and edge cases:

- **`ReliableProvider`** must fail *safely*: a provider error triggers the next
  in the chain, but it never silently violates a hard constraint (e.g. it does
  not fall back to a remote provider for a privacy-local request). Phase 7
  acceptance: *"Provider failures fallback safely."*
- **`BudgetProvider`** enforces invariant 11 at the routing layer: when a request
  would breach the task's cost/token budget, it refuses or degrades to a cheaper
  model rather than blowing the budget. This pairs with the kernel's
  budget-exhaustion state ([`ROADMAP.md` §18 Phase 1](../ROADMAP.md)).
- **`FusionProvider`** is reserved for *high-risk* planning/review steps where the
  cost of a deliberate multi-model path is justified — not the default for every
  call (cost discipline).
- **`LocalFallbackProvider`** is the privacy/offline safety net: when remote is
  down, over budget, or disallowed by privacy policy, it degrades to a local
  OpenAI-compatible endpoint.

---

## 5. Budget accounting

Every model request is metered (invariant 11; [`ROADMAP.md` §13.2,
§18 P7.7](../ROADMAP.md)). The net sidecar records, per request and aggregated
per task/job:

```text
provider + model used
input / output tokens
estimated / actual cost
latency
fallbacks taken (which providers were tried)
```

These feed the budget record on each task (invariant 11). When a budget would be
exceeded, `BudgetProvider` (§4) intervenes; when it *is* exceeded, the kernel's
budget-exhaustion state pauses the task ([`telegram.md` §2](./telegram.md)
`/budget` surfaces this to the user). Budget accounting is also part of the
audit story: routing decisions and costs are observable, not hidden.

---

## 6. Where it lives — nano links no HTTP/TLS

All of this lives in **`crustcore-net`** (Tokio, minimal HTTP client, Rustls or
platform TLS, provider adapters — [`ROADMAP.md` §2.2](../ROADMAP.md)). The kernel
and nano **do not link** any of it (invariants 19, 20;
[`CLAUDE.md` §5.1](../CLAUDE.md)).

Phase 7 acceptance is explicit: ***"Nano can call net helper without linking
HTTP/TLS."*** Nano invokes the net sidecar as an **external command / helper
protocol** ([`ROADMAP.md` §2.1, §7.1](../ROADMAP.md)) — the same way it invokes
`git`, `codex`, or `claude`. The sub-800kB binary never embeds Tokio, Reqwest,
Rustls, or a provider SDK.

```text
nano  --(local helper protocol over pipe/socket)-->  crustcore-net
                                                       -> router / meta-providers
                                                       -> provider adapters (HTTP/TLS)
                                                       -> OpenAI / Anthropic / OpenRouter / local
```

| Concern | Crate | In nano? |
| --- | --- | --- |
| HTTP/TLS, provider adapters, router, meta-providers, budget metering | `crustcore-net` | No |
| Local helper protocol client (request/response shape) | nano | Yes (protocol only, no HTTP/TLS) |

---

## 7. Phase 7 tasks and acceptance

From [`ROADMAP.md` §18 Phase 7](../ROADMAP.md):

```text
P7.1 Define local helper protocol.
P7.2 Implement provider request/response models.
P7.3 Implement streaming support.
P7.4 Implement provider health/capability probe.
P7.5 Implement reliable fallback provider.
P7.6 Implement hint-based router provider.
P7.7 Implement budget accounting.
```

**Acceptance criteria:**

```text
Nano can call net helper without linking HTTP/TLS.   -> §6
Provider failures fallback safely.                   -> §4 (ReliableProvider)
Model registry is dynamic.                            -> §1.1
```

**Status (Phase 7 + P7-live implemented).** The protocol (`crustcore-netproto`,
std-only), the routing engine (`crustcore-net`: dynamic registry/probe,
Router/Budget/Reliable meta-providers, streaming, budget accounting), the helper
binary, and the spawn-based caller are implemented and tested. The concrete
**live wire adapters** — OpenAI/OpenRouter/local (`OpenAiProvider`) and Anthropic
(`AnthropicProvider`) — are now implemented over an [`HttpClient`] transport
boundary (`crustcore-net::transport`). Their parse / map / stream / error logic is
**fully tested in CI with a canned `ReplayClient`** (no network): streaming
concatenation, usage parsing, status→`ProviderError` mapping, success-path-only chunk
emission, no-panic on malformed SSE, and an engine-level cross-adapter fallback over
*real* adapters. The real HTTP/TLS socket (`UreqClient`, `ureq` + rustls) is gated
behind the **`live`** cargo feature so the default build — workspace, CI, and the
spawned mock helper — links no HTTP/TLS stack (asserted by `xtask forbidden-deps`).
Credentials are resolved per call via a `CredentialSource` (broker-backed in the live
helper) and never reach the model, a log, or the sandbox env (invariants 1–3); a
secret-leak red-team fixture proves a sentinel key cannot surface in the completion
text or a routed error even when the provider echoes it. The engine is unchanged — a
live `Provider` is a pure drop-in. **What remains live-gated** (real network + a real
key, never in CI): the `#[ignore]`d `live_smoke` integration test, run out-of-band
against a real endpoint with a `live`-built helper.

### 7.1 Testing notes

- **Dynamic registry (invariant 17):** router tests run against a *mutable* registry
  — a model removed mid-session is no longer selected; a model added appears
  without a code change; no permanent hard-coded availability.
- **Safe fallback:** `ReliableProvider` advances on provider-down; it never
  crosses a hard constraint (privacy-local never falls back to remote;
  tool-required never falls back to a non-tool model).
- **Budget (invariant 11):** `BudgetProvider` refuses/degrades at the ceiling;
  exhaustion pauses the task; `/budget` reflects real accounting.
- **Helper boundary (invariant 20):** `cargo tree` / `cargo bloat` confirm nano
  links no HTTP/TLS/provider crates; the helper protocol round-trips over the
  pipe/socket without nano importing Tokio.
- **Streaming:** progress streams to the runtime channel as visible summaries,
  not raw hidden CoT ([`telegram.md` §7](./telegram.md)).
