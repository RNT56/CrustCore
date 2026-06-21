// SPDX-License-Identifier: Apache-2.0
//! Network/provider sidecar engine (`ROADMAP.md` §2.2, §13; `docs/model-routing.md`;
//! Phase 7, tasks P7.2–P7.7).
//!
//! This crate is where the model-transport logic lives so the nano binary never
//! has to. Nano (the `net` feature of `crustcore`) talks to the **helper binary**
//! (`src/bin/helper.rs`) over the std-only local protocol (`crustcore-netproto`),
//! never by linking this crate — so the sub-800kB binary embeds no HTTP/TLS
//! (invariants 19, 20; `docs/model-routing.md` §6).
//!
//! What is implemented (deterministic, no network, fully tested):
//! - a [`Provider`] trait (the provider-agnostic request/response model — P7.2),
//! - a **dynamic registry** built by probing providers (invariant 17 — P7.4),
//! - the three meta-provider behaviors — [`select_candidates`] (RouterProvider,
//!   P7.6), [`apply_budget`] (BudgetProvider, P7.7), [`run_reliable`]
//!   (ReliableProvider fallback, P7.5) — composed by [`Engine::complete`],
//! - **streaming** chunks through a sink (P7.3),
//! - **budget accounting** ([`BudgetLedger`], P7.7),
//! - the [`serve`] loop the helper binary runs.
//!
//! Live providers (P7-live): the concrete OpenAI/OpenRouter/local + Anthropic wire
//! adapters ([`providers`]) are implemented over an [`HttpClient`](transport::HttpClient)
//! transport boundary. Their parse/map/stream logic is **fully tested in CI** with a
//! canned [`ReplayClient`](transport::ReplayClient) — no network; the real HTTP/TLS
//! socket (`UreqClient`) is gated behind the **`live`** cargo feature so the default
//! build (and the workspace/CI build) links no HTTP stack, and the helper defaults to
//! [`default_mock_engine`]. Credentials are resolved per call via a
//! [`CredentialSource`](credsource::CredentialSource) (broker-backed in the live
//! helper) and never reach the model, a log, or the sandbox env (invariants 1–3). The
//! adapters are drop-ins: they implement the same [`Provider`] trait the router,
//! registry, and budget logic already route over, unchanged.
#![forbid(unsafe_code)]

pub mod config;
pub mod credsource;
pub mod embed;
pub mod github;
pub mod modality;
pub mod providers;
pub mod rerank;
pub mod transport;

use std::io::{BufRead, Write};

use crustcore_netproto::{
    read_request, write_response, CompleteRequest, Final, ModelInfo, ProtoError, Request, Response,
    Role, Usage, MAX_TEXT_BYTES,
};
use crustcore_types::BoundedText;

/// One model a provider currently offers (a registry entry — `docs/model-routing.md`
/// §1.1). Probed live, never hard-coded (invariant 17).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelCard {
    /// Model id within its provider.
    pub model: String,
    /// Whether the provider reports it healthy right now (degraded → not selected).
    pub healthy: bool,
    /// Context length in tokens.
    pub context: u32,
    /// Tool/function-call support.
    pub tools: bool,
    /// Structured-output support.
    pub structured: bool,
    /// Streaming support.
    pub streaming: bool,
    /// Rough cost in micros per 1000 output tokens (for budget ordering/ceiling).
    pub cost_per_1k_micros: u64,
    /// Whether this model runs on a local endpoint (privacy / `local_only` routing).
    pub local: bool,
    /// Embedding support (additive, default off — Track C C1-providers). A model
    /// that does not declare it is never selected for an embedding request
    /// (invariant 17: capability fails closed, never on by omission).
    pub embeddings: bool,
    /// Rerank support (additive, default off — Track C C1-providers). Fails closed
    /// the same way `embeddings` does.
    pub rerank: bool,
    /// Embedding dimensionality, or `0` when unknown / not an embedding model
    /// (additive, default `0` — Track C C1-providers).
    pub embedding_dims: u32,
}

impl ModelCard {
    fn to_info(&self, provider: &str) -> ModelInfo {
        ModelInfo {
            provider: provider.to_string(),
            model: self.model.clone(),
            healthy: self.healthy,
            context: self.context,
            tools: self.tools,
            structured: self.structured,
            streaming: self.streaming,
            cost_per_1k_micros: self.cost_per_1k_micros,
            // Additive capability fields (Track C C1-providers); the completion
            // mapping above is byte-identical, these are appended only.
            embeddings: self.embeddings,
            rerank: self.rerank,
            embedding_dims: self.embedding_dims,
        }
    }

    /// Upper-bound cost estimate for a request that asks for `max_tokens` output.
    fn est_cost_micros(&self, max_tokens: u32) -> u64 {
        self.cost_per_1k_micros
            .saturating_mul(u64::from(max_tokens))
            / 1000
    }
}

/// What a provider returns from a successful completion.
#[derive(Debug, Clone)]
pub struct Completion {
    /// The full completion text.
    pub text: String,
    /// Token/cost usage actually incurred.
    pub usage: Usage,
}

/// Why a provider failed a single request (drives [`run_reliable`] fallback).
#[derive(Debug, Clone)]
pub enum ProviderError {
    /// The provider/model is currently unavailable (down, rate-limited, timeout).
    Unavailable(String),
    /// The request exceeds a capability of this model (e.g. context).
    Capability(String),
    /// Any other failure.
    Other(String),
}

impl core::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProviderError::Unavailable(e) => write!(f, "unavailable: {e}"),
            ProviderError::Capability(e) => write!(f, "capability: {e}"),
            ProviderError::Other(e) => write!(f, "{e}"),
        }
    }
}

/// A coding/model provider. Live providers (OpenAI/Anthropic/…) implement this over an
/// HTTP transport ([`providers`], behind the `live` feature); [`MockProvider`] does so
/// deterministically for tests and the default helper.
pub trait Provider {
    /// Stable provider id (e.g. `openai`, `mock-remote`).
    fn id(&self) -> &str;

    /// The models this provider currently offers — probed **live**, so a model
    /// that disappears simply stops being returned (invariant 17).
    fn probe(&self) -> Vec<ModelCard>;

    /// Runs a completion for `model`. Streaming providers deliver incremental text
    /// to `sink` **only on the success path** (a provider that is going to fail
    /// must emit no chunks, so a fallback does not leak partial output). Returns
    /// the full text + usage, or a typed error that triggers fallback.
    ///
    /// # Errors
    /// [`ProviderError`] if the provider could not serve the request.
    fn complete(
        &self,
        model: &str,
        req: &CompleteRequest,
        sink: &mut dyn FnMut(&str),
    ) -> Result<Completion, ProviderError>;
}

/// Why routing failed, as a typed reason surfaced to the caller as
/// [`Response::Error`] (a failed request never looks like success).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteError {
    /// No registered model satisfies the hard constraints (capabilities/privacy/
    /// context). Routing fails explicitly rather than downgrading past a hard
    /// constraint (`docs/model-routing.md` §3).
    NoModelForConstraints(String),
    /// Models satisfy the constraints, but none fits the cost ceiling
    /// (BudgetProvider; invariant 11).
    OverBudget(String),
    /// Every candidate that satisfied the constraints failed at request time
    /// (ReliableProvider exhausted the chain).
    AllProvidersFailed(String),
}

impl RouteError {
    /// The human-readable reason for the wire [`Response::Error`].
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            RouteError::NoModelForConstraints(s) => format!("no model satisfies constraints: {s}"),
            RouteError::OverBudget(s) => format!("over budget: {s}"),
            RouteError::AllProvidersFailed(s) => format!("all providers failed: {s}"),
        }
    }
}

/// A routing candidate: which provider + model, with its probed card.
#[derive(Debug, Clone)]
pub struct Candidate {
    /// Index into the engine's provider list.
    pub provider_idx: usize,
    /// The provider id (for diagnostics/fallback records).
    pub provider_id: String,
    /// The chosen model card.
    pub card: ModelCard,
}

/// Aggregate budget accounting across requests (invariant 11;
/// `docs/model-routing.md` §5). Feeds the kernel's per-task budget record.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BudgetLedger {
    /// Completed requests.
    pub requests: u64,
    /// Total input tokens billed.
    pub input_tokens: u64,
    /// Total output tokens billed.
    pub output_tokens: u64,
    /// Total cost in micros.
    pub cost_micros: u64,
    /// Total fallbacks taken (providers tried that failed before a success).
    pub fallbacks: u64,
}

/// The routing engine: a set of providers + accounting. `complete` composes the
/// meta-provider behaviors in the documented order
/// (Budget ∘ Router ∘ Reliable; `docs/model-routing.md` §4).
pub struct Engine {
    providers: Vec<Box<dyn Provider>>,
    ledger: BudgetLedger,
}

impl Engine {
    /// Builds an engine over the given providers (order is the registry order).
    #[must_use]
    pub fn new(providers: Vec<Box<dyn Provider>>) -> Self {
        Engine {
            providers,
            ledger: BudgetLedger::default(),
        }
    }

    /// The current dynamic registry: a live probe of every provider. A model that
    /// a provider stops offering simply drops out (invariant 17).
    #[must_use]
    pub fn registry(&self) -> Vec<(String, ModelCard)> {
        let mut out = Vec::new();
        for p in &self.providers {
            let id = p.id().to_string();
            for card in p.probe() {
                out.push((id.clone(), card));
            }
        }
        out
    }

    /// The aggregate budget ledger.
    #[must_use]
    pub fn ledger(&self) -> &BudgetLedger {
        &self.ledger
    }

    /// Mutable access to the aggregate budget ledger, so embedding/rerank engines can
    /// accumulate into the **same** ledger as completion — one per-task ceiling across
    /// all three modalities (invariant 11; Track C C1-providers). The completion path
    /// (`complete`) is unchanged; this only exposes the existing ledger for the
    /// unified multi-modal engine to share.
    pub fn ledger_mut(&mut self) -> &mut BudgetLedger {
        &mut self.ledger
    }

    /// Routes and runs a completion, streaming chunks to `sink`. Composes the
    /// meta-providers: Router selects constraint-satisfying candidates, Budget
    /// drops unaffordable ones, Reliable tries them in order until one succeeds.
    ///
    /// # Errors
    /// [`RouteError`] if no model satisfies the constraints, none fits the budget,
    /// or every candidate failed.
    pub fn complete(
        &mut self,
        req: &CompleteRequest,
        sink: &mut dyn FnMut(&str),
    ) -> Result<Final, RouteError> {
        let registry = self.registry_indexed();
        let candidates = select_candidates(&registry, req)?;
        let candidates = apply_budget(candidates, req)?;
        let fin = run_reliable(&self.providers, candidates, req, sink)?;
        // Account on success (invariant 11).
        // Saturating accumulation — monotonic counters never wrap (matching the
        // kernel's convention for `next_approval`/event-seq/lease counters).
        self.ledger.requests = self.ledger.requests.saturating_add(1);
        self.ledger.input_tokens = self
            .ledger
            .input_tokens
            .saturating_add(u64::from(fin.usage.input_tokens));
        self.ledger.output_tokens = self
            .ledger
            .output_tokens
            .saturating_add(u64::from(fin.usage.output_tokens));
        self.ledger.cost_micros = self
            .ledger
            .cost_micros
            .saturating_add(fin.usage.cost_micros);
        self.ledger.fallbacks = self
            .ledger
            .fallbacks
            .saturating_add(fin.fallbacks.len() as u64);
        Ok(fin)
    }

    fn registry_indexed(&self) -> Vec<Candidate> {
        let mut out = Vec::new();
        for (idx, p) in self.providers.iter().enumerate() {
            let id = p.id().to_string();
            for card in p.probe() {
                out.push(Candidate {
                    provider_idx: idx,
                    provider_id: id.clone(),
                    card,
                });
            }
        }
        out
    }
}

/// **RouterProvider** (P7.6): from the live registry, keep only candidates that
/// satisfy every *hard* constraint (healthy, tools, context, privacy), then order
/// by the role's *soft* objective (strongest-first for reasoning roles, cheapest-
/// first for research). Returns [`RouteError::NoModelForConstraints`] if none
/// qualify — never downgrading past a hard constraint (`docs/model-routing.md` §3).
///
/// # Errors
/// [`RouteError::NoModelForConstraints`] when nothing satisfies the constraints.
pub fn select_candidates(
    registry: &[Candidate],
    req: &CompleteRequest,
) -> Result<Vec<Candidate>, RouteError> {
    let mut kept: Vec<Candidate> = registry
        .iter()
        .filter(|c| {
            let m = &c.card;
            m.healthy
                && (!req.require.tools || m.tools)
                && m.context >= req.require.min_context
                && (!req.require.local_only || m.local)
        })
        .cloned()
        .collect();

    if kept.is_empty() {
        let mut why = Vec::new();
        if req.require.tools {
            why.push("tools");
        }
        if req.require.local_only {
            why.push("local-only");
        }
        if req.require.min_context > 0 {
            why.push("min-context");
        }
        let detail = if why.is_empty() {
            "no healthy model".to_string()
        } else {
            format!("requires {}", why.join("+"))
        };
        return Err(RouteError::NoModelForConstraints(detail));
    }

    // Soft ordering by role. Stable so equal keys keep registry order.
    match req.role {
        Role::Advisor | Role::Review => {
            // Strongest first: more context, then cheaper as a tie-break.
            kept.sort_by(|a, b| {
                b.card
                    .context
                    .cmp(&a.card.context)
                    .then(a.card.cost_per_1k_micros.cmp(&b.card.cost_per_1k_micros))
            });
        }
        Role::Research => {
            // Cheapest first.
            kept.sort_by_key(|c| c.card.cost_per_1k_micros);
        }
        Role::LocalFallback => {
            // Prefer local, then cheapest.
            kept.sort_by(|a, b| {
                b.card
                    .local
                    .cmp(&a.card.local)
                    .then(a.card.cost_per_1k_micros.cmp(&b.card.cost_per_1k_micros))
            });
        }
        Role::Implementation => {
            // Cheapest that is capable, then more context as a tie-break.
            kept.sort_by(|a, b| {
                a.card
                    .cost_per_1k_micros
                    .cmp(&b.card.cost_per_1k_micros)
                    .then(b.card.context.cmp(&a.card.context))
            });
        }
    }
    Ok(kept)
}

/// **BudgetProvider** (P7.7): drop candidates whose estimated cost exceeds the
/// request's ceiling (`max_cost_micros`; 0 = unlimited). Refuses rather than
/// breaching the budget (invariant 11).
///
/// # Errors
/// [`RouteError::OverBudget`] if every candidate would exceed the ceiling.
pub fn apply_budget(
    candidates: Vec<Candidate>,
    req: &CompleteRequest,
) -> Result<Vec<Candidate>, RouteError> {
    if req.max_cost_micros == 0 {
        return Ok(candidates);
    }
    let affordable: Vec<Candidate> = candidates
        .into_iter()
        .filter(|c| c.card.est_cost_micros(req.max_tokens) <= req.max_cost_micros)
        .collect();
    if affordable.is_empty() {
        return Err(RouteError::OverBudget(format!(
            "ceiling {} micros too low for {} output tokens",
            req.max_cost_micros, req.max_tokens
        )));
    }
    Ok(affordable)
}

/// **ReliableProvider** (P7.5): try candidates in order until one succeeds,
/// recording the providers that failed first as the fallback path. It never
/// crosses a hard constraint because the candidate list was already filtered by
/// [`select_candidates`]/[`apply_budget`] (`docs/model-routing.md` §4).
///
/// # Errors
/// [`RouteError::AllProvidersFailed`] if every candidate errored.
pub fn run_reliable(
    providers: &[Box<dyn Provider>],
    candidates: Vec<Candidate>,
    req: &CompleteRequest,
    sink: &mut dyn FnMut(&str),
) -> Result<Final, RouteError> {
    let mut fallbacks: Vec<String> = Vec::new();
    let mut last_err = String::from("no candidates");
    for cand in candidates {
        let provider = &providers[cand.provider_idx];
        match provider.complete(&cand.card.model, req, sink) {
            Ok(c) => {
                return Ok(Final {
                    text: BoundedText::truncated(c.text, MAX_TEXT_BYTES),
                    provider: cand.provider_id,
                    model: cand.card.model,
                    usage: c.usage,
                    fallbacks,
                });
            }
            Err(e) => {
                last_err = format!("{}: {e}", cand.provider_id);
                fallbacks.push(cand.provider_id);
            }
        }
    }
    Err(RouteError::AllProvidersFailed(last_err))
}

/// The sidecar request loop: read [`Request`]s from `r`, drive `engine`, write
/// [`Response`]s to `w`. Runs until clean EOF on `r`. This is what the helper
/// binary runs over stdin/stdout (std blocking I/O — no async runtime needed for
/// a single-in-flight request/response helper).
///
/// This entry point serves the **completion** path only (the frozen P7 engine). An
/// [`Request::Embed`]/[`Request::Rerank`] received here fails closed with a typed
/// [`Response::Error`] (this engine has no embedding/rerank registry). To serve all
/// three modalities, use [`MultiModalEngine::serve`].
///
/// # Errors
/// [`ProtoError`] on a transport/decode failure (a failed *routing* is reported
/// in-band as [`Response::Error`], not as an `Err` here).
pub fn serve<R: BufRead, W: Write>(
    engine: &mut Engine,
    r: &mut R,
    w: &mut W,
) -> Result<(), ProtoError> {
    while let Some(req) = read_request(r)? {
        serve_one(engine, None, None, req, w)?;
    }
    Ok(())
}

/// Routes a single request through the completion `engine` and (optionally) the
/// embedding/rerank engines, writing the response(s) to `w`. The embed/rerank engines
/// accumulate into the completion engine's **single shared** ledger (invariant 11).
/// When an embed/rerank engine is absent, that modality fails closed.
fn serve_one<W: Write>(
    engine: &mut Engine,
    embed: Option<&modality::EmbedEngine>,
    rerank: Option<&modality::RerankEngine>,
    req: Request,
    w: &mut W,
) -> Result<(), ProtoError> {
    match req {
        Request::Probe => {
            // The unified registry: completion models, then embedding, then rerank.
            // Capability flags ride on each card via `to_info` (default off for
            // completion-only cards), so the probe surfaces capability across the
            // helper boundary (Track C C1-providers).
            for (pid, card) in engine.registry() {
                write_response(w, &Response::Model(card.to_info(&pid)))?;
            }
            if let Some(e) = embed {
                for (pid, card) in e.registry() {
                    write_response(w, &Response::Model(card.to_info(&pid)))?;
                }
            }
            if let Some(rr) = rerank {
                for (pid, card) in rr.registry() {
                    write_response(w, &Response::Model(card.to_info(&pid)))?;
                }
            }
            write_response(w, &Response::RegistryEnd)?;
        }
        Request::Complete(c) => {
            let stream = c.stream;
            // Stream chunks to `w` during the call; the closure's borrow of `w`
            // is scoped to this block so `w` is free again for the Final/Error.
            let result = {
                let writer = &mut *w;
                let mut sink = |t: &str| {
                    if stream {
                        let _ = write_response(
                            writer,
                            &Response::Chunk(BoundedText::truncated(t, MAX_TEXT_BYTES)),
                        );
                    }
                };
                engine.complete(&c, &mut sink)
            };
            match result {
                Ok(fin) => write_response(w, &Response::Final(fin))?,
                Err(e) => write_response(w, &Response::Error(e.reason()))?,
            }
        }
        Request::Embed(e) => {
            let resp = match embed {
                None => Response::Error(
                    RouteError::NoModelForConstraints("requires embeddings".into()).reason(),
                ),
                Some(engine_e) => {
                    let mreq = modality::EmbeddingRequest::new(e.role, e.inputs, e.max_cost_micros);
                    match engine_e.embed(&mreq, engine.ledger_mut()) {
                        Ok((resp, fallbacks, provider, model)) => {
                            Response::Embedding(crustcore_netproto::EmbeddingResult {
                                vectors: resp.vectors,
                                usage: resp.usage,
                                provider,
                                model,
                                fallbacks,
                            })
                        }
                        Err(err) => Response::Error(err.reason()),
                    }
                }
            };
            write_response(w, &resp)?;
        }
        Request::Rerank(r) => {
            let resp = match rerank {
                None => Response::Error(
                    RouteError::NoModelForConstraints("requires rerank".into()).reason(),
                ),
                Some(engine_r) => {
                    let mreq = modality::RerankRequest::new(
                        r.role,
                        r.query,
                        r.documents,
                        r.max_cost_micros,
                    );
                    match engine_r.rerank(&mreq, engine.ledger_mut()) {
                        Ok((resp, fallbacks, provider, model)) => {
                            // usize → u32 for the wire (indices are bounded by MAX_DOCS).
                            let ranking = resp
                                .ranking
                                .into_iter()
                                .map(|(i, s)| (i as u32, s))
                                .collect();
                            Response::Ranking(crustcore_netproto::RankingResult {
                                ranking,
                                usage: resp.usage,
                                provider,
                                model,
                                fallbacks,
                            })
                        }
                        Err(err) => Response::Error(err.reason()),
                    }
                }
            };
            write_response(w, &resp)?;
        }
    }
    Ok(())
}

/// The unified multi-modal sidecar engine (Track C C1-providers): the frozen
/// completion [`Engine`] plus optional [`EmbedEngine`](modality::EmbedEngine) and
/// [`RerankEngine`](modality::RerankEngine). All three meter through the completion
/// engine's **single** [`BudgetLedger`] (invariant 11). The probe surfaces every
/// modality's capability via the additive `ModelInfo` flags.
pub struct MultiModalEngine {
    completion: Engine,
    embed: Option<modality::EmbedEngine>,
    rerank: Option<modality::RerankEngine>,
}

impl MultiModalEngine {
    /// Builds a multi-modal engine. Pass `None` for a modality the helper does not
    /// serve — requests for it then fail closed with a typed error.
    #[must_use]
    pub fn new(
        completion: Engine,
        embed: Option<modality::EmbedEngine>,
        rerank: Option<modality::RerankEngine>,
    ) -> Self {
        MultiModalEngine {
            completion,
            embed,
            rerank,
        }
    }

    /// A completion-only engine (embedding/rerank absent → fail closed).
    #[must_use]
    pub fn completion_only(completion: Engine) -> Self {
        MultiModalEngine::new(completion, None, None)
    }

    /// The shared budget ledger (accumulated across all three modalities).
    #[must_use]
    pub fn ledger(&self) -> &BudgetLedger {
        self.completion.ledger()
    }

    /// The sidecar request loop over all three modalities. Runs until clean EOF.
    ///
    /// # Errors
    /// [`ProtoError`] on a transport/decode failure (a failed *routing* is reported
    /// in-band as [`Response::Error`], not as an `Err`).
    pub fn serve<R: BufRead, W: Write>(&mut self, r: &mut R, w: &mut W) -> Result<(), ProtoError> {
        while let Some(req) = read_request(r)? {
            serve_one(
                &mut self.completion,
                self.embed.as_ref(),
                self.rerank.as_ref(),
                req,
                w,
            )?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Mock provider + default engine (no network; deterministic)
// ---------------------------------------------------------------------------

/// How a [`MockProvider`] behaves on `complete` (deterministic, for tests and the
/// default helper until live providers land).
#[derive(Debug, Clone)]
pub enum MockBehavior {
    /// Succeed: echo a canned answer derived from the prompt (streamed in chunks).
    Echo,
    /// Always fail with this reason (to exercise fallback).
    AlwaysFail(String),
}

/// A deterministic in-process provider standing in for a live one.
pub struct MockProvider {
    id: String,
    cards: Vec<ModelCard>,
    behavior: MockBehavior,
}

impl MockProvider {
    /// Builds a mock provider with an id, a set of model cards, and a behavior.
    #[must_use]
    pub fn new(id: impl Into<String>, cards: Vec<ModelCard>, behavior: MockBehavior) -> Self {
        MockProvider {
            id: id.into(),
            cards,
            behavior,
        }
    }
}

/// Rough token estimate (~4 chars/token), for mock usage accounting.
fn est_tokens(s: &str) -> u32 {
    (s.len() / 4 + 1) as u32
}

impl Provider for MockProvider {
    fn id(&self) -> &str {
        &self.id
    }

    fn probe(&self) -> Vec<ModelCard> {
        self.cards.clone()
    }

    fn complete(
        &self,
        model: &str,
        req: &CompleteRequest,
        sink: &mut dyn FnMut(&str),
    ) -> Result<Completion, ProviderError> {
        if let MockBehavior::AlwaysFail(reason) = &self.behavior {
            // Fail BEFORE emitting any chunk, so fallback leaks no partial output.
            return Err(ProviderError::Unavailable(reason.clone()));
        }
        let answer = format!("[{}/{}] {}", self.id, model, req.prompt.as_str());
        // Stream in a few chunks to exercise the streaming path.
        let step = (answer.len() / 3).max(1);
        let mut i = 0;
        while i < answer.len() {
            let mut end = (i + step).min(answer.len());
            while end < answer.len() && !answer.is_char_boundary(end) {
                end += 1;
            }
            sink(&answer[i..end]);
            i = end;
        }
        let output_tokens = est_tokens(&answer);
        let input_tokens = est_tokens(req.prompt.as_str()) + est_tokens(req.system.as_str());
        let card_cost = self
            .cards
            .iter()
            .find(|c| c.model == model)
            .map_or(0, |c| c.cost_per_1k_micros);
        let cost_micros = card_cost.saturating_mul(u64::from(output_tokens)) / 1000;
        Ok(Completion {
            text: answer,
            usage: Usage {
                input_tokens,
                output_tokens,
                cost_micros,
            },
        })
    }
}

/// A default engine for the helper binary: deterministic mock providers that make
/// the dynamic registry, routing, fallback, and budget behaviors observable
/// **without any network**. The live counterpart — credentialed HTTP adapters over the
/// secret broker — is [`live_engine`] / [`build_live_engine`], behind the `live` feature.
#[must_use]
pub fn default_mock_engine() -> Engine {
    let remote_strong = ModelCard {
        model: "strong-1".into(),
        healthy: true,
        context: 128_000,
        tools: true,
        structured: true,
        streaming: true,
        cost_per_1k_micros: 15_000,
        local: false,
        embeddings: false,
        rerank: false,
        embedding_dims: 0,
    };
    let remote_fast = ModelCard {
        model: "fast-1".into(),
        healthy: true,
        context: 32_000,
        tools: true,
        structured: true,
        streaming: true,
        cost_per_1k_micros: 1_000,
        local: false,
        embeddings: false,
        rerank: false,
        embedding_dims: 0,
    };
    let local_small = ModelCard {
        model: "local-1".into(),
        healthy: true,
        context: 16_000,
        tools: false,
        structured: false,
        streaming: true,
        cost_per_1k_micros: 0,
        local: true,
        embeddings: false,
        rerank: false,
        embedding_dims: 0,
    };
    Engine::new(vec![
        Box::new(MockProvider::new(
            "mock-remote",
            vec![remote_strong, remote_fast],
            MockBehavior::Echo,
        )),
        Box::new(MockProvider::new(
            "mock-local",
            vec![local_small],
            MockBehavior::Echo,
        )),
    ])
}

/// A default **multi-modal** engine for the helper binary: the deterministic mock
/// completion providers plus deterministic mock embedding + rerank providers (no
/// network). This keeps the default/CI build linking nothing new while making the
/// embedding and rerank routing/fallback/budget behaviors observable. The live
/// counterpart is [`live_multimodal_engine`] (behind the `live` feature).
#[must_use]
pub fn default_mock_multimodal_engine() -> MultiModalEngine {
    use modality::{
        EmbedEngine, MockEmbedBehavior, MockEmbedProvider, MockRerankBehavior, MockRerankProvider,
        RerankEngine,
    };

    let embed_card = ModelCard {
        model: "mock-embed-1".into(),
        healthy: true,
        context: 8192,
        tools: false,
        structured: false,
        streaming: false,
        cost_per_1k_micros: 100,
        local: false,
        embeddings: true,
        rerank: false,
        embedding_dims: 8,
    };
    let rerank_card = ModelCard {
        model: "mock-rerank-1".into(),
        healthy: true,
        context: 8192,
        tools: false,
        structured: false,
        streaming: false,
        cost_per_1k_micros: 50,
        local: false,
        embeddings: false,
        rerank: true,
        embedding_dims: 0,
    };

    let embed = EmbedEngine::new(vec![Box::new(MockEmbedProvider::new(
        "mock-embed",
        vec![embed_card],
        MockEmbedBehavior::Echo,
    ))]);
    let rerank = RerankEngine::new(vec![Box::new(MockRerankProvider::new(
        "mock-rerank",
        vec![rerank_card],
        MockRerankBehavior::Echo,
    ))]);

    MultiModalEngine::new(default_mock_engine(), Some(embed), Some(rerank))
}

/// Builds a **live** [`Engine`] from a provider config + credential source using the
/// real `UreqClient` HTTP transport (`live` feature). It returns the *same* `Engine`
/// type the mock path uses — the live providers are pure drop-ins, so the
/// router/registry/budget logic is reused unchanged. The credential source is
/// broker-backed in the helper; the key never reaches the model or the sandbox env.
#[cfg(feature = "live")]
#[must_use]
pub fn live_engine(
    configs: &[config::ProviderConfig],
    creds: std::rc::Rc<dyn credsource::CredentialSource>,
) -> Engine {
    let http: std::rc::Rc<dyn transport::HttpClient> =
        std::rc::Rc::new(transport::UreqClient::new());
    Engine::new(providers::build_providers(configs, http, creds))
}

/// Builds a **live** [`MultiModalEngine`] from a provider config + credential source
/// using the real `UreqClient` HTTP transport (`live` feature). Completion, embedding,
/// and rerank adapters share one `UreqClient` and one [`CredentialSource`]; the
/// completion engine's single [`BudgetLedger`] meters all three (invariant 11). An
/// embedding/rerank engine is omitted (fails closed) when no configured model declares
/// that capability — capability is configured, never assumed (invariant 17).
#[cfg(feature = "live")]
#[must_use]
pub fn live_multimodal_engine(
    configs: &[config::ProviderConfig],
    creds: std::rc::Rc<dyn credsource::CredentialSource>,
) -> MultiModalEngine {
    let http: std::rc::Rc<dyn transport::HttpClient> =
        std::rc::Rc::new(transport::UreqClient::new());

    let completion = Engine::new(providers::build_providers(
        configs,
        http.clone(),
        creds.clone(),
    ));

    let embedders = embed::build_embed_providers(configs, http.clone(), creds.clone());
    let embed = if embedders.is_empty() {
        None
    } else {
        Some(modality::EmbedEngine::new(embedders))
    };

    let rerankers = rerank::build_rerankers(configs, http, creds);
    let rerank = if rerankers.is_empty() {
        None
    } else {
        Some(modality::RerankEngine::new(rerankers))
    };

    MultiModalEngine::new(completion, embed, rerank)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crustcore_netproto::Require;

    fn req(role: Role, prompt: &str) -> CompleteRequest {
        CompleteRequest {
            role,
            system: BoundedText::truncated("", MAX_TEXT_BYTES),
            prompt: BoundedText::truncated(prompt, MAX_TEXT_BYTES),
            max_tokens: 64,
            stream: true,
            max_cost_micros: 0,
            require: Require::default(),
        }
    }

    fn card(
        model: &str,
        ctx: u32,
        cost: u64,
        tools: bool,
        local: bool,
        healthy: bool,
    ) -> ModelCard {
        ModelCard {
            model: model.into(),
            healthy,
            context: ctx,
            tools,
            structured: false,
            streaming: true,
            cost_per_1k_micros: cost,
            local,
            embeddings: false,
            rerank: false,
            embedding_dims: 0,
        }
    }

    fn cand(idx: usize, id: &str, card: ModelCard) -> Candidate {
        Candidate {
            provider_idx: idx,
            provider_id: id.into(),
            card,
        }
    }

    // ---- Router (select_candidates) ----

    #[test]
    fn router_filters_hard_constraints_and_orders_by_role() {
        let reg = vec![
            cand(0, "p", card("cheap", 8000, 1000, false, false, true)),
            cand(0, "p", card("strong", 128000, 9000, true, false, true)),
            cand(0, "p", card("down", 64000, 500, true, false, false)),
        ];
        // Advisor wants the strongest (most context) first; unhealthy "down" dropped.
        let out = select_candidates(&reg, &req(Role::Advisor, "x")).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].card.model, "strong");
        // Research wants the cheapest first.
        let out = select_candidates(&reg, &req(Role::Research, "x")).unwrap();
        assert_eq!(out[0].card.model, "cheap");
    }

    #[test]
    fn router_enforces_tools_local_and_context_constraints() {
        let reg = vec![
            cand(
                0,
                "remote",
                card("remote-notools", 8000, 1000, false, false, true),
            ),
            cand(1, "local", card("local-tools", 8000, 0, true, true, true)),
        ];
        // tools required -> only the tool-capable model qualifies.
        let mut r = req(Role::Implementation, "x");
        r.require.tools = true;
        assert_eq!(select_candidates(&reg, &r).unwrap().len(), 1);
        // local_only -> never routes to the remote model.
        let mut r = req(Role::Implementation, "x");
        r.require.local_only = true;
        let out = select_candidates(&reg, &r).unwrap();
        assert!(out.iter().all(|c| c.card.local));
        // An impossible min_context fails explicitly (no silent downgrade).
        let mut r = req(Role::Implementation, "x");
        r.require.min_context = 1_000_000;
        assert!(matches!(
            select_candidates(&reg, &r),
            Err(RouteError::NoModelForConstraints(_))
        ));
    }

    // ---- Budget ----

    #[test]
    fn budget_drops_unaffordable_and_errors_when_none_fit() {
        let reg = vec![cand(
            0,
            "p",
            card("pricey", 8000, 100_000, false, false, true),
        )];
        let mut r = req(Role::Implementation, "x");
        r.max_tokens = 1000;
        r.max_cost_micros = 1; // way too low: est 100_000 micros
        let cands = select_candidates(&reg, &r).unwrap();
        assert!(matches!(
            apply_budget(cands, &r),
            Err(RouteError::OverBudget(_))
        ));
        // With a generous ceiling it passes.
        r.max_cost_micros = 1_000_000;
        let cands = select_candidates(&reg, &r).unwrap();
        assert_eq!(apply_budget(cands, &r).unwrap().len(), 1);
    }

    // ---- Reliable (fallback) ----

    #[test]
    fn reliable_falls_back_past_failing_providers_safely() {
        let providers: Vec<Box<dyn Provider>> = vec![
            Box::new(MockProvider::new(
                "down",
                vec![card("m", 8000, 1000, false, false, true)],
                MockBehavior::AlwaysFail("503".into()),
            )),
            Box::new(MockProvider::new(
                "up",
                vec![card("m", 8000, 1000, false, false, true)],
                MockBehavior::Echo,
            )),
        ];
        let candidates = vec![
            cand(0, "down", card("m", 8000, 1000, false, false, true)),
            cand(1, "up", card("m", 8000, 1000, false, false, true)),
        ];
        let mut chunks = String::new();
        let mut sink = |t: &str| chunks.push_str(t);
        let fin = run_reliable(
            &providers,
            candidates,
            &req(Role::Implementation, "hi"),
            &mut sink,
        )
        .unwrap();
        assert_eq!(fin.provider, "up");
        assert_eq!(fin.fallbacks, vec!["down"]);
        // The failing provider streamed nothing; only the successful output is seen.
        assert!(chunks.contains("[up/m] hi"));
        assert!(!chunks.contains("down"));
    }

    #[test]
    fn reliable_errors_when_all_fail() {
        let providers: Vec<Box<dyn Provider>> = vec![Box::new(MockProvider::new(
            "down",
            vec![card("m", 8000, 1000, false, false, true)],
            MockBehavior::AlwaysFail("boom".into()),
        ))];
        let candidates = vec![cand(0, "down", card("m", 8000, 1000, false, false, true))];
        let mut sink = |_: &str| {};
        assert!(matches!(
            run_reliable(
                &providers,
                candidates,
                &req(Role::Implementation, "x"),
                &mut sink
            ),
            Err(RouteError::AllProvidersFailed(_))
        ));
    }

    // ---- Dynamic registry + accounting (invariants 17, 11) ----

    #[test]
    fn registry_is_dynamic_and_routes_strongest_for_advisor() {
        let mut engine = default_mock_engine();
        assert!(engine.registry().iter().any(|(_, c)| c.model == "strong-1"));
        let mut sink = |_: &str| {};
        let fin = engine
            .complete(&req(Role::Advisor, "plan"), &mut sink)
            .unwrap();
        assert_eq!(fin.model, "strong-1");
        assert_eq!(engine.ledger().requests, 1);
        assert!(engine.ledger().output_tokens > 0);
    }

    #[test]
    fn local_only_request_never_routes_remote() {
        let mut engine = default_mock_engine();
        let mut r = req(Role::Implementation, "secret");
        r.require.local_only = true;
        let mut sink = |_: &str| {};
        let fin = engine.complete(&r, &mut sink).unwrap();
        assert_eq!(fin.provider, "mock-local");
    }

    // ---- End-to-end over the protocol (caller <-> serve), in-process pipe ----

    #[test]
    fn end_to_end_probe_and_complete_over_the_protocol() {
        use std::io::{BufReader, Cursor};

        // Drive `serve` with a canned request stream and capture its responses,
        // then parse them with the caller-side decoder — the full wire round-trip
        // without spawning a process.
        let mut input = Vec::new();
        input.extend_from_slice(crustcore_netproto::encode_request(&Request::Probe).as_bytes());
        input.push(b'\n');
        input.extend_from_slice(
            crustcore_netproto::encode_request(&Request::Complete(req(Role::Advisor, "hello")))
                .as_bytes(),
        );
        input.push(b'\n');

        let mut engine = default_mock_engine();
        let mut reader = BufReader::new(Cursor::new(input));
        let mut out: Vec<u8> = Vec::new();
        serve(&mut engine, &mut reader, &mut out).unwrap();

        let mut resp = BufReader::new(Cursor::new(out));
        // Probe responses: models until RegistryEnd.
        let mut models = Vec::new();
        loop {
            match crustcore_netproto::read_response(&mut resp)
                .unwrap()
                .unwrap()
            {
                Response::Model(m) => models.push(m),
                Response::RegistryEnd => break,
                other => panic!("unexpected {other:?}"),
            }
        }
        assert!(models.iter().any(|m| m.model == "strong-1"));
        // Complete responses: chunks then final.
        let mut streamed = String::new();
        let fin = loop {
            match crustcore_netproto::read_response(&mut resp)
                .unwrap()
                .unwrap()
            {
                Response::Chunk(t) => streamed.push_str(t.as_str()),
                Response::Final(f) => break f,
                other => panic!("unexpected {other:?}"),
            }
        };
        assert_eq!(fin.model, "strong-1");
        // Streamed chunks concatenate to the final text.
        assert_eq!(fin.text.as_str(), streamed);
        assert!(fin.text.as_str().contains("hello"));
    }

    // ---- Track C C1-providers: multi-modal serve over the protocol ----

    #[test]
    fn multimodal_serve_routes_embed_and_rerank_and_meters_one_ledger() {
        use crustcore_netproto::{EmbedRequest, RerankRequest};
        use std::io::{BufReader, Cursor};

        // Drive the multi-modal serve loop with embed + rerank requests and parse the
        // responses with the caller-side decoder — the full wire round-trip.
        let mut input = Vec::new();
        input.extend_from_slice(
            crustcore_netproto::encode_request(&Request::Embed(EmbedRequest {
                role: Role::Research,
                inputs: vec!["alpha".into(), "beta".into()],
                max_cost_micros: 0,
            }))
            .as_bytes(),
        );
        input.push(b'\n');
        input.extend_from_slice(
            crustcore_netproto::encode_request(&Request::Rerank(RerankRequest {
                role: Role::Review,
                query: "q".into(),
                documents: vec!["short".into(), "longer document".into()],
                max_cost_micros: 0,
            }))
            .as_bytes(),
        );
        input.push(b'\n');

        let mut engine = default_mock_multimodal_engine();
        let mut reader = BufReader::new(Cursor::new(input));
        let mut out: Vec<u8> = Vec::new();
        engine.serve(&mut reader, &mut out).unwrap();

        let mut resp = BufReader::new(Cursor::new(out));
        // First: an embedding result with two vectors.
        match crustcore_netproto::read_response(&mut resp)
            .unwrap()
            .unwrap()
        {
            Response::Embedding(e) => {
                assert_eq!(e.vectors.len(), 2);
                assert!(e.vectors.iter().all(|v| !v.is_empty()));
                assert_eq!(e.provider, "mock-embed");
            }
            other => panic!("expected Embedding, got {other:?}"),
        }
        // Second: a ranking result with two in-range entries.
        match crustcore_netproto::read_response(&mut resp)
            .unwrap()
            .unwrap()
        {
            Response::Ranking(r) => {
                assert_eq!(r.ranking.len(), 2);
                assert!(r.ranking.iter().all(|(i, _)| *i < 2));
            }
            other => panic!("expected Ranking, got {other:?}"),
        }

        // ONE shared ledger accumulated both requests (invariant 11).
        assert_eq!(engine.ledger().requests, 2);
    }

    #[test]
    fn multimodal_probe_surfaces_capability_flags() {
        use std::io::{BufReader, Cursor};

        let mut input = Vec::new();
        input.extend_from_slice(crustcore_netproto::encode_request(&Request::Probe).as_bytes());
        input.push(b'\n');

        let mut engine = default_mock_multimodal_engine();
        let mut reader = BufReader::new(Cursor::new(input));
        let mut out: Vec<u8> = Vec::new();
        engine.serve(&mut reader, &mut out).unwrap();

        let mut resp = BufReader::new(Cursor::new(out));
        let mut models = Vec::new();
        loop {
            match crustcore_netproto::read_response(&mut resp)
                .unwrap()
                .unwrap()
            {
                Response::Model(m) => models.push(m),
                Response::RegistryEnd => break,
                other => panic!("unexpected {other:?}"),
            }
        }
        // The probe surfaces completion-only, embedding, and rerank models with their
        // additive capability flags (default off for completion-only ones).
        assert!(models
            .iter()
            .any(|m| m.model == "strong-1" && !m.embeddings && !m.rerank));
        assert!(models.iter().any(|m| m.embeddings && m.embedding_dims == 8));
        assert!(models.iter().any(|m| m.rerank));
    }

    #[test]
    fn embed_request_fails_closed_when_no_embed_engine() {
        use crustcore_netproto::EmbedRequest;
        use std::io::{BufReader, Cursor};

        // A completion-only multi-modal engine: an embed request must fail closed
        // with a typed error, never route to a completion model (invariant 17).
        let mut input = Vec::new();
        input.extend_from_slice(
            crustcore_netproto::encode_request(&Request::Embed(EmbedRequest {
                role: Role::Research,
                inputs: vec!["x".into()],
                max_cost_micros: 0,
            }))
            .as_bytes(),
        );
        input.push(b'\n');

        let mut engine = MultiModalEngine::completion_only(default_mock_engine());
        let mut reader = BufReader::new(Cursor::new(input));
        let mut out: Vec<u8> = Vec::new();
        engine.serve(&mut reader, &mut out).unwrap();

        let mut resp = BufReader::new(Cursor::new(out));
        match crustcore_netproto::read_response(&mut resp)
            .unwrap()
            .unwrap()
        {
            Response::Error(e) => assert!(e.contains("embeddings")),
            other => panic!("expected Error, got {other:?}"),
        }
        // Nothing was metered (no capable engine ran).
        assert_eq!(engine.ledger().requests, 0);
    }
}
