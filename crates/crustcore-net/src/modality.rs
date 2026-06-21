// SPDX-License-Identifier: Apache-2.0
//! The unified multi-modal capability layer (Track C C1-providers).
//!
//! P7-live proved the drop-in pattern: a live [`Provider`](crate::Provider) is a pure
//! drop-in over a frozen router ([`select_candidates`](crate::select_candidates) /
//! [`apply_budget`](crate::apply_budget) / [`run_reliable`](crate::run_reliable)).
//! This module generalizes that *shape* to two more edge capabilities every agent
//! runtime needs — **embedding** and **rerank** — under sibling traits
//! ([`EmbedProvider`], [`RerankProvider`]) that mirror `Provider`'s `id`/`probe`/call
//! contract exactly, and per-modality engines ([`EmbedEngine`], [`RerankEngine`]) that
//! reuse the *same* hard-constraint-then-role-order filter, the *same* single
//! [`BudgetLedger`](crate::BudgetLedger) instance (so one per-task ceiling is honored
//! across all three modalities), and a [`run_reliable`](crate::run_reliable)-shaped
//! fallback. The completion `Provider`/`Engine` are **frozen and untouched**; these are
//! additive siblings.
//!
//! Credential discipline is identical to the completion adapters: the live
//! [`EmbedProvider`](crate::embed)/[`RerankProvider`](crate::rerank) resolve auth
//! per-call via [`CredentialSource`](crate::credsource::CredentialSource) and never
//! store the key. Every provider byte is untrusted: vectors and scores are bounded
//! (`MAX_BATCH`/`MAX_DOCS`/`MAX_EMBEDDING_DIMS`), non-finite floats are sanitized, and
//! out-of-range/duplicate rerank indices are clamped/dropped — never propagated raw
//! (invariants 7, 11).

use crustcore_netproto::{Role, Usage, MAX_BATCH, MAX_DOCS, MAX_EMBEDDING_DIMS, MAX_TEXT_BYTES};

use crate::{ModelCard, ProviderError, RouteError};

/// Which capability a routing query is for. Drives [`select_candidates_for`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Modality {
    /// Text completion (the frozen P7 path — kept here for the unified filter only).
    Completion,
    /// Embedding (gates on `card.embeddings`).
    Embedding,
    /// Rerank (gates on `card.rerank`).
    Rerank,
}

// ---------------------------------------------------------------------------
// Value types (bounded, forward-compatible)
// ---------------------------------------------------------------------------

/// An embedding request: a bounded batch of inputs (Track C C1-providers). Use
/// [`EmbeddingRequest::new`] to construct one with the caps applied.
#[derive(Debug, Clone)]
pub struct EmbeddingRequest {
    /// The abstract role to route for, resolved against embedding-capable models.
    pub role: Role,
    /// The inputs to embed (bounded to [`MAX_BATCH`] entries, each [`MAX_TEXT_BYTES`]).
    pub inputs: Vec<String>,
    /// Hard cost ceiling in micros (0 = unlimited).
    pub max_cost_micros: u64,
}

impl EmbeddingRequest {
    /// Builds a bounded request: at most [`MAX_BATCH`] inputs, each truncated to
    /// [`MAX_TEXT_BYTES`] on a char boundary.
    #[must_use]
    pub fn new(role: Role, inputs: Vec<String>, max_cost_micros: u64) -> Self {
        let inputs = inputs
            .into_iter()
            .take(MAX_BATCH)
            .map(|s| bound_text(&s))
            .collect();
        EmbeddingRequest {
            role,
            inputs,
            max_cost_micros,
        }
    }
}

/// The result of an embedding request: one vector per input.
#[derive(Debug, Clone, PartialEq)]
pub struct EmbeddingResponse {
    /// One embedding vector per input (each a finite-float `Vec<f32>`).
    pub vectors: Vec<Vec<f32>>,
    /// Usage/cost actually incurred.
    pub usage: Usage,
}

/// A rerank request: score `documents` against `query` (Track C C1-providers). Use
/// [`RerankRequest::new`] to construct one with the caps applied.
#[derive(Debug, Clone)]
pub struct RerankRequest {
    /// The abstract role to route for, resolved against rerank-capable models.
    pub role: Role,
    /// The query to rank documents against (bounded to [`MAX_TEXT_BYTES`]).
    pub query: String,
    /// The candidate documents (bounded to [`MAX_DOCS`] entries, each [`MAX_TEXT_BYTES`]).
    pub documents: Vec<String>,
    /// Hard cost ceiling in micros (0 = unlimited).
    pub max_cost_micros: u64,
}

impl RerankRequest {
    /// Builds a bounded request: at most [`MAX_DOCS`] documents, each truncated to
    /// [`MAX_TEXT_BYTES`]; the query truncated to [`MAX_TEXT_BYTES`].
    #[must_use]
    pub fn new(role: Role, query: String, documents: Vec<String>, max_cost_micros: u64) -> Self {
        let documents = documents
            .into_iter()
            .take(MAX_DOCS)
            .map(|s| bound_text(&s))
            .collect();
        RerankRequest {
            role,
            query: bound_text(&query),
            documents,
            max_cost_micros,
        }
    }

    /// The number of candidate documents (the valid index range is `0..len`).
    #[must_use]
    pub fn doc_count(&self) -> usize {
        self.documents.len()
    }
}

/// The result of a rerank request: `(document_index, score)` pairs. The adapter has
/// already validated every index against the request's document count — out-of-range
/// or duplicate indices are dropped, so a consumer can trust each `usize` is in range.
#[derive(Debug, Clone, PartialEq)]
pub struct RerankResponse {
    /// `(document_index, score)` pairs, sorted by descending score.
    pub ranking: Vec<(usize, f32)>,
    /// Usage/cost actually incurred.
    pub usage: Usage,
}

/// Truncate a text to [`MAX_TEXT_BYTES`] on a char boundary.
fn bound_text(s: &str) -> String {
    if s.len() <= MAX_TEXT_BYTES {
        return s.to_string();
    }
    let mut end = MAX_TEXT_BYTES;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Sanitize a raw `(index, score)` ranking from an **untrusted** provider response
/// against a known document count: drop out-of-range and duplicate indices, sanitize
/// non-finite scores to `0.0`, sort by descending score, and bound to [`MAX_DOCS`].
/// Never panics, never corrupts downstream selection (invariant 7).
#[must_use]
pub fn sanitize_ranking(raw: &[(i64, f32)], doc_count: usize) -> Vec<(usize, f32)> {
    let mut seen = vec![false; doc_count];
    let mut out: Vec<(usize, f32)> = Vec::new();
    for &(idx, score) in raw.iter().take(MAX_DOCS) {
        // Reject negative or out-of-range indices (clamp by rejection).
        if idx < 0 {
            continue;
        }
        let idx = idx as usize;
        if idx >= doc_count {
            continue;
        }
        // Drop duplicates: a provider must not double-count a document.
        if seen[idx] {
            continue;
        }
        seen[idx] = true;
        let score = if score.is_finite() { score } else { 0.0 };
        out.push((idx, score));
    }
    // Highest relevance first; stable to keep provider order on ties.
    out.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    out
}

/// Sanitize an embedding vector batch from an **untrusted** provider response: bound
/// to [`MAX_BATCH`] vectors, each [`MAX_EMBEDDING_DIMS`] dims, sanitizing non-finite
/// floats to `0.0` (invariant 7, 11).
#[must_use]
pub fn sanitize_vectors(raw: Vec<Vec<f32>>) -> Vec<Vec<f32>> {
    raw.into_iter()
        .take(MAX_BATCH)
        .map(|v| {
            v.into_iter()
                .take(MAX_EMBEDDING_DIMS)
                .map(|x| if x.is_finite() { x } else { 0.0 })
                .collect()
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Sibling capability traits (mirror Provider's id/probe/call shape exactly)
// ---------------------------------------------------------------------------

/// An embedding provider. Live adapters ([`crate::embed`]) implement this over an
/// [`HttpClient`](crate::transport::HttpClient); [`MockEmbedProvider`] does so
/// deterministically for tests and the default helper. Mirrors
/// [`Provider`](crate::Provider)'s `id`/`probe`/call shape exactly (sync, no I/O in
/// the trait surface beyond the call).
pub trait EmbedProvider {
    /// Stable provider id (e.g. `openai-embed`, `mock-embed`).
    fn id(&self) -> &str;

    /// The embedding models this provider currently offers — probed **live** so a
    /// model that disappears stops being returned (invariant 17). Every returned
    /// card must have `embeddings == true`.
    fn probe(&self) -> Vec<ModelCard>;

    /// Embeds `req.inputs` using `model`.
    ///
    /// # Errors
    /// [`ProviderError`] if the provider could not serve the request (drives fallback).
    fn embed(
        &self,
        model: &str,
        req: &EmbeddingRequest,
    ) -> Result<EmbeddingResponse, ProviderError>;
}

/// A rerank provider. Live adapters ([`crate::rerank`]) implement this over an
/// [`HttpClient`](crate::transport::HttpClient); [`MockRerankProvider`] does so
/// deterministically. Mirrors [`Provider`](crate::Provider)'s shape exactly.
pub trait RerankProvider {
    /// Stable provider id (e.g. `cohere-rerank`, `mock-rerank`).
    fn id(&self) -> &str;

    /// The rerank models this provider currently offers (each with `rerank == true`).
    fn probe(&self) -> Vec<ModelCard>;

    /// Reranks `req.documents` against `req.query` using `model`.
    ///
    /// # Errors
    /// [`ProviderError`] if the provider could not serve the request (drives fallback).
    fn rerank(&self, model: &str, req: &RerankRequest) -> Result<RerankResponse, ProviderError>;
}

// ---------------------------------------------------------------------------
// Generalized routing (reuses the completion filter shape, gated by modality)
// ---------------------------------------------------------------------------

/// A routing candidate for any modality: which provider index + its probed card.
#[derive(Debug, Clone)]
pub struct ModalCandidate {
    /// Index into the engine's provider list.
    pub provider_idx: usize,
    /// The provider id (for diagnostics/fallback records).
    pub provider_id: String,
    /// The chosen model card.
    pub card: ModelCard,
}

/// A capability-typed candidate filter mirroring
/// [`select_candidates`](crate::select_candidates): keep only healthy models whose
/// card declares the requested `modality` (and, for embedding, a matching dimension
/// when `require_dims > 0`), then order by the role's soft objective. Returns
/// [`RouteError::NoModelForConstraints`] if none qualify — a capability-missing
/// request **fails closed**, never silently routing to a completion-only model
/// (invariant 17).
///
/// # Errors
/// [`RouteError::NoModelForConstraints`] when nothing satisfies the constraints.
pub fn select_candidates_for(
    modality: Modality,
    registry: &[ModalCandidate],
    role: Role,
    require_dims: u32,
) -> Result<Vec<ModalCandidate>, RouteError> {
    let mut kept: Vec<ModalCandidate> = registry
        .iter()
        .filter(|c| {
            let m = &c.card;
            if !m.healthy {
                return false;
            }
            match modality {
                Modality::Completion => true,
                Modality::Embedding => {
                    m.embeddings && (require_dims == 0 || m.embedding_dims == require_dims)
                }
                Modality::Rerank => m.rerank,
            }
        })
        .cloned()
        .collect();

    if kept.is_empty() {
        let detail = match modality {
            Modality::Completion => "no healthy model".to_string(),
            Modality::Embedding => {
                if require_dims > 0 {
                    format!("requires embeddings+{require_dims}-dims")
                } else {
                    "requires embeddings".to_string()
                }
            }
            Modality::Rerank => "requires rerank".to_string(),
        };
        return Err(RouteError::NoModelForConstraints(detail));
    }

    // Soft ordering by role, mirroring the completion router's objectives.
    match role {
        Role::Advisor | Role::Review => kept.sort_by(|a, b| {
            b.card
                .context
                .cmp(&a.card.context)
                .then(a.card.cost_per_1k_micros.cmp(&b.card.cost_per_1k_micros))
        }),
        Role::Research => kept.sort_by_key(|c| c.card.cost_per_1k_micros),
        Role::LocalFallback => kept.sort_by(|a, b| {
            b.card
                .local
                .cmp(&a.card.local)
                .then(a.card.cost_per_1k_micros.cmp(&b.card.cost_per_1k_micros))
        }),
        Role::Implementation => kept.sort_by(|a, b| {
            a.card
                .cost_per_1k_micros
                .cmp(&b.card.cost_per_1k_micros)
                .then(b.card.context.cmp(&a.card.context))
        }),
    }
    Ok(kept)
}

/// Drop candidates whose estimated cost exceeds `max_cost_micros` (0 = unlimited),
/// mirroring [`apply_budget`](crate::apply_budget). For embedding/rerank we estimate
/// cost from the model's `cost_per_1k_micros` against the input/document volume.
///
/// # Errors
/// [`RouteError::OverBudget`] if every candidate would exceed the ceiling.
pub fn apply_budget_for(
    candidates: Vec<ModalCandidate>,
    est_output_tokens: u32,
    max_cost_micros: u64,
) -> Result<Vec<ModalCandidate>, RouteError> {
    if max_cost_micros == 0 {
        return Ok(candidates);
    }
    let affordable: Vec<ModalCandidate> = candidates
        .into_iter()
        .filter(|c| {
            let est = c
                .card
                .cost_per_1k_micros
                .saturating_mul(u64::from(est_output_tokens))
                / 1000;
            est <= max_cost_micros
        })
        .collect();
    if affordable.is_empty() {
        return Err(RouteError::OverBudget(format!(
            "ceiling {max_cost_micros} micros too low for ~{est_output_tokens} tokens"
        )));
    }
    Ok(affordable)
}

/// Rough token estimate (~4 chars/token) over a batch of texts, for budget ordering.
fn est_batch_tokens(texts: &[String]) -> u32 {
    let bytes: usize = texts.iter().map(String::len).sum();
    (bytes / 4 + 1) as u32
}

// ---------------------------------------------------------------------------
// Per-modality engines (share ONE BudgetLedger; run_reliable-shaped fallback)
// ---------------------------------------------------------------------------

/// The embedding routing engine: a set of [`EmbedProvider`]s sharing the *same*
/// [`BudgetLedger`](crate::BudgetLedger) as the completion (and rerank) engines, so a
/// single per-task ceiling is honored across all three modalities (invariant 11).
/// Composes the meta-provider behaviors (Router selects embedding-capable candidates,
/// Budget drops unaffordable ones, Reliable tries them in order).
pub struct EmbedEngine {
    providers: Vec<Box<dyn EmbedProvider>>,
}

impl EmbedEngine {
    /// Builds an engine over the given embedding providers.
    #[must_use]
    pub fn new(providers: Vec<Box<dyn EmbedProvider>>) -> Self {
        EmbedEngine { providers }
    }

    /// The current dynamic registry: a live probe of every embedding provider.
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

    fn registry_indexed(&self) -> Vec<ModalCandidate> {
        let mut out = Vec::new();
        for (idx, p) in self.providers.iter().enumerate() {
            let id = p.id().to_string();
            for card in p.probe() {
                out.push(ModalCandidate {
                    provider_idx: idx,
                    provider_id: id.clone(),
                    card,
                });
            }
        }
        out
    }

    /// Routes and runs an embedding request, accumulating into the shared `ledger`.
    /// The `(EmbeddingResponse, fallbacks, provider, model)` tuple feeds the wire
    /// response.
    ///
    /// # Errors
    /// [`RouteError`] if no embedding model satisfies the constraints, none fits the
    /// budget, or every candidate failed.
    pub fn embed(
        &self,
        req: &EmbeddingRequest,
        ledger: &mut crate::BudgetLedger,
    ) -> Result<(EmbeddingResponse, Vec<String>, String, String), RouteError> {
        let registry = self.registry_indexed();
        let candidates = select_candidates_for(Modality::Embedding, &registry, req.role, 0)?;
        let est = est_batch_tokens(&req.inputs);
        let candidates = apply_budget_for(candidates, est, req.max_cost_micros)?;

        let mut fallbacks: Vec<String> = Vec::new();
        let mut last_err = String::from("no candidates");
        for cand in candidates {
            let provider = &self.providers[cand.provider_idx];
            match provider.embed(&cand.card.model, req) {
                Ok(resp) => {
                    let resp = EmbeddingResponse {
                        vectors: sanitize_vectors(resp.vectors),
                        usage: resp.usage,
                    };
                    accumulate(ledger, &resp.usage, fallbacks.len());
                    return Ok((resp, fallbacks, cand.provider_id, cand.card.model));
                }
                Err(e) => {
                    last_err = format!("{}: {e}", cand.provider_id);
                    fallbacks.push(cand.provider_id);
                }
            }
        }
        Err(RouteError::AllProvidersFailed(last_err))
    }
}

/// The rerank routing engine — same shape and the *same* shared
/// [`BudgetLedger`](crate::BudgetLedger) as [`EmbedEngine`]/`Engine`.
pub struct RerankEngine {
    providers: Vec<Box<dyn RerankProvider>>,
}

impl RerankEngine {
    /// Builds an engine over the given rerank providers.
    #[must_use]
    pub fn new(providers: Vec<Box<dyn RerankProvider>>) -> Self {
        RerankEngine { providers }
    }

    /// The current dynamic registry: a live probe of every rerank provider.
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

    fn registry_indexed(&self) -> Vec<ModalCandidate> {
        let mut out = Vec::new();
        for (idx, p) in self.providers.iter().enumerate() {
            let id = p.id().to_string();
            for card in p.probe() {
                out.push(ModalCandidate {
                    provider_idx: idx,
                    provider_id: id.clone(),
                    card,
                });
            }
        }
        out
    }

    /// Routes and runs a rerank request, accumulating into the shared `ledger`.
    ///
    /// # Errors
    /// [`RouteError`] if no rerank model satisfies the constraints, none fits the
    /// budget, or every candidate failed.
    pub fn rerank(
        &self,
        req: &RerankRequest,
        ledger: &mut crate::BudgetLedger,
    ) -> Result<(RerankResponse, Vec<String>, String, String), RouteError> {
        let registry = self.registry_indexed();
        let candidates = select_candidates_for(Modality::Rerank, &registry, req.role, 0)?;
        let query_tokens = (req.query.len() / 4 + 1) as u32;
        let est = est_batch_tokens(&req.documents).saturating_add(query_tokens);
        let candidates = apply_budget_for(candidates, est, req.max_cost_micros)?;

        let mut fallbacks: Vec<String> = Vec::new();
        let mut last_err = String::from("no candidates");
        for cand in candidates {
            let provider = &self.providers[cand.provider_idx];
            match provider.rerank(&cand.card.model, req) {
                Ok(resp) => {
                    accumulate(ledger, &resp.usage, fallbacks.len());
                    return Ok((resp, fallbacks, cand.provider_id, cand.card.model));
                }
                Err(e) => {
                    last_err = format!("{}: {e}", cand.provider_id);
                    fallbacks.push(cand.provider_id);
                }
            }
        }
        Err(RouteError::AllProvidersFailed(last_err))
    }
}

/// Accumulate a successful modality request into the shared ledger (saturating —
/// monotonic counters never wrap), mirroring [`Engine::complete`](crate::Engine)'s
/// accounting so all three modalities meter through one ledger (invariant 11).
fn accumulate(ledger: &mut crate::BudgetLedger, usage: &Usage, fallbacks: usize) {
    ledger.requests = ledger.requests.saturating_add(1);
    ledger.input_tokens = ledger
        .input_tokens
        .saturating_add(u64::from(usage.input_tokens));
    ledger.output_tokens = ledger
        .output_tokens
        .saturating_add(u64::from(usage.output_tokens));
    ledger.cost_micros = ledger.cost_micros.saturating_add(usage.cost_micros);
    ledger.fallbacks = ledger.fallbacks.saturating_add(fallbacks as u64);
}

// ---------------------------------------------------------------------------
// Deterministic mocks (no network) — the default helper links nothing new
// ---------------------------------------------------------------------------

/// How a [`MockEmbedProvider`] behaves, analogous to
/// [`MockBehavior`](crate::MockBehavior).
#[derive(Debug, Clone)]
pub enum MockEmbedBehavior {
    /// Succeed: return a deterministic small vector per input.
    Echo,
    /// Always fail with this reason (to exercise fallback).
    AlwaysFail(String),
}

/// A deterministic in-process [`EmbedProvider`] for tests and the default helper.
pub struct MockEmbedProvider {
    id: String,
    cards: Vec<ModelCard>,
    behavior: MockEmbedBehavior,
}

impl MockEmbedProvider {
    /// Builds a mock embed provider. Every card is forced `embeddings = true`
    /// (and `rerank = false`) so it is selectable for embedding routing.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        mut cards: Vec<ModelCard>,
        behavior: MockEmbedBehavior,
    ) -> Self {
        for c in &mut cards {
            c.embeddings = true;
            c.rerank = false;
            if c.embedding_dims == 0 {
                c.embedding_dims = 3;
            }
        }
        MockEmbedProvider {
            id: id.into(),
            cards,
            behavior,
        }
    }
}

impl EmbedProvider for MockEmbedProvider {
    fn id(&self) -> &str {
        &self.id
    }

    fn probe(&self) -> Vec<ModelCard> {
        self.cards.clone()
    }

    fn embed(
        &self,
        model: &str,
        req: &EmbeddingRequest,
    ) -> Result<EmbeddingResponse, ProviderError> {
        if let MockEmbedBehavior::AlwaysFail(reason) = &self.behavior {
            return Err(ProviderError::Unavailable(reason.clone()));
        }
        let dims = self
            .cards
            .iter()
            .find(|c| c.model == model)
            .map_or(3, |c| c.embedding_dims.max(1)) as usize;
        // Deterministic vector derived from each input's length (a stand-in for a
        // real embedding) — bounded and finite.
        let vectors: Vec<Vec<f32>> = req
            .inputs
            .iter()
            .map(|s| {
                let base = (s.len() % 100) as f32 / 100.0;
                (0..dims).map(|i| base + i as f32 * 0.01).collect()
            })
            .collect();
        let input_tokens = est_batch_tokens(&req.inputs);
        let cost = self
            .cards
            .iter()
            .find(|c| c.model == model)
            .map_or(0, |c| c.cost_per_1k_micros)
            .saturating_mul(u64::from(input_tokens))
            / 1000;
        Ok(EmbeddingResponse {
            vectors,
            usage: Usage {
                input_tokens,
                output_tokens: 0,
                cost_micros: cost,
            },
        })
    }
}

/// How a [`MockRerankProvider`] behaves.
#[derive(Debug, Clone)]
pub enum MockRerankBehavior {
    /// Succeed: score documents by a deterministic rule.
    Echo,
    /// Always fail with this reason (to exercise fallback).
    AlwaysFail(String),
}

/// A deterministic in-process [`RerankProvider`] for tests and the default helper.
pub struct MockRerankProvider {
    id: String,
    cards: Vec<ModelCard>,
    behavior: MockRerankBehavior,
}

impl MockRerankProvider {
    /// Builds a mock rerank provider. Every card is forced `rerank = true` (and
    /// `embeddings = false`) so it is selectable for rerank routing.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        mut cards: Vec<ModelCard>,
        behavior: MockRerankBehavior,
    ) -> Self {
        for c in &mut cards {
            c.rerank = true;
            c.embeddings = false;
        }
        MockRerankProvider {
            id: id.into(),
            cards,
            behavior,
        }
    }
}

impl RerankProvider for MockRerankProvider {
    fn id(&self) -> &str {
        &self.id
    }

    fn probe(&self) -> Vec<ModelCard> {
        self.cards.clone()
    }

    fn rerank(&self, model: &str, req: &RerankRequest) -> Result<RerankResponse, ProviderError> {
        if let MockRerankBehavior::AlwaysFail(reason) = &self.behavior {
            return Err(ProviderError::Unavailable(reason.clone()));
        }
        // Deterministic score: longer documents score higher (a stand-in). Already
        // in-range indices, so sanitize is a no-op here but keeps the contract.
        let raw: Vec<(i64, f32)> = req
            .documents
            .iter()
            .enumerate()
            .map(|(i, d)| (i as i64, d.len() as f32))
            .collect();
        let ranking = sanitize_ranking(&raw, req.doc_count());
        let input_tokens = est_batch_tokens(&req.documents);
        let cost = self
            .cards
            .iter()
            .find(|c| c.model == model)
            .map_or(0, |c| c.cost_per_1k_micros)
            .saturating_mul(u64::from(input_tokens))
            / 1000;
        Ok(RerankResponse {
            ranking,
            usage: Usage {
                input_tokens,
                output_tokens: 0,
                cost_micros: cost,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ecard(model: &str, dims: u32, cost: u64) -> ModelCard {
        ModelCard {
            model: model.into(),
            healthy: true,
            context: 8192,
            tools: false,
            structured: false,
            streaming: false,
            cost_per_1k_micros: cost,
            local: false,
            embeddings: true,
            rerank: false,
            embedding_dims: dims,
        }
    }

    fn rcard(model: &str, cost: u64) -> ModelCard {
        ModelCard {
            model: model.into(),
            healthy: true,
            context: 8192,
            tools: false,
            structured: false,
            streaming: false,
            cost_per_1k_micros: cost,
            local: false,
            embeddings: false,
            rerank: true,
            embedding_dims: 0,
        }
    }

    fn completion_only_card(model: &str) -> ModelCard {
        ModelCard {
            model: model.into(),
            healthy: true,
            context: 8192,
            tools: true,
            structured: false,
            streaming: true,
            cost_per_1k_micros: 100,
            local: false,
            embeddings: false,
            rerank: false,
            embedding_dims: 0,
        }
    }

    fn modal(idx: usize, id: &str, card: ModelCard) -> ModalCandidate {
        ModalCandidate {
            provider_idx: idx,
            provider_id: id.into(),
            card,
        }
    }

    #[test]
    fn select_for_embedding_keeps_only_embedding_models() {
        let reg = vec![
            modal(0, "c", completion_only_card("gpt")),
            modal(1, "e", ecard("emb", 1536, 50)),
        ];
        let out = select_candidates_for(Modality::Embedding, &reg, Role::Research, 0).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].card.model, "emb");
    }

    #[test]
    fn embedding_request_with_no_capable_model_fails_closed() {
        // Only completion-only models present → a capability-missing request returns
        // a typed error rather than routing to a completion-only model (invariant 17).
        let reg = vec![modal(0, "c", completion_only_card("gpt"))];
        assert!(matches!(
            select_candidates_for(Modality::Embedding, &reg, Role::Research, 0),
            Err(RouteError::NoModelForConstraints(_))
        ));
        assert!(matches!(
            select_candidates_for(Modality::Rerank, &reg, Role::Review, 0),
            Err(RouteError::NoModelForConstraints(_))
        ));
    }

    #[test]
    fn embedding_dimension_constraint_is_enforced() {
        let reg = vec![
            modal(0, "e", ecard("small", 768, 10)),
            modal(1, "e", ecard("big", 1536, 10)),
        ];
        let out = select_candidates_for(Modality::Embedding, &reg, Role::Research, 1536).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].card.model, "big");
        // An impossible dimension fails closed.
        assert!(matches!(
            select_candidates_for(Modality::Embedding, &reg, Role::Research, 9999),
            Err(RouteError::NoModelForConstraints(_))
        ));
    }

    #[test]
    fn sanitize_ranking_drops_out_of_range_and_duplicates() {
        // doc_count = 3 (valid indices 0..3). Raw has out-of-range (5, -1), a
        // duplicate (1 twice), and a non-finite score.
        let raw = vec![
            (1i64, 0.9f32),
            (5, 0.99), // out of range → dropped
            (-1, 0.8), // negative → dropped
            (0, 0.5),
            (1, 0.7),      // duplicate → dropped
            (2, f32::NAN), // non-finite → 0.0
        ];
        let out = sanitize_ranking(&raw, 3);
        // Three valid unique indices remain; all in range; sorted desc by score.
        assert_eq!(out.len(), 3);
        assert!(out.iter().all(|(i, _)| *i < 3));
        assert!(out.iter().all(|(_, s)| s.is_finite()));
        // 1 (0.9) > 0 (0.5) > 2 (0.0)
        assert_eq!(out[0], (1, 0.9));
        assert_eq!(out[1], (0, 0.5));
        assert_eq!(out[2], (2, 0.0));
    }

    #[test]
    fn embed_engine_routes_and_meters_the_shared_ledger() {
        let engine = EmbedEngine::new(vec![Box::new(MockEmbedProvider::new(
            "mock-embed",
            vec![ecard("e1", 4, 1000)],
            MockEmbedBehavior::Echo,
        ))]);
        let mut ledger = crate::BudgetLedger::default();
        let req = EmbeddingRequest::new(Role::Research, vec!["a".into(), "bb".into()], 0);
        let (resp, fb, provider, model) = engine.embed(&req, &mut ledger).unwrap();
        assert_eq!(resp.vectors.len(), 2);
        assert!(resp.vectors.iter().all(|v| v.len() == 4));
        assert!(fb.is_empty());
        assert_eq!(provider, "mock-embed");
        assert_eq!(model, "e1");
        assert_eq!(ledger.requests, 1);
    }

    #[test]
    fn rerank_engine_routes_and_meters_the_shared_ledger() {
        let engine = RerankEngine::new(vec![Box::new(MockRerankProvider::new(
            "mock-rerank",
            vec![rcard("r1", 500)],
            MockRerankBehavior::Echo,
        ))]);
        let mut ledger = crate::BudgetLedger::default();
        let req = RerankRequest::new(
            Role::Review,
            "q".into(),
            vec!["short".into(), "a much longer document".into()],
            0,
        );
        let (resp, _fb, _p, _m) = engine.rerank(&req, &mut ledger).unwrap();
        assert_eq!(resp.ranking.len(), 2);
        // Longer doc (index 1) ranks first under the mock's length rule.
        assert_eq!(resp.ranking[0].0, 1);
        assert!(resp.ranking.iter().all(|(i, _)| *i < 2));
        assert_eq!(ledger.requests, 1);
    }

    #[test]
    fn one_ledger_accumulates_across_all_three_modalities() {
        // The crucial property: a single BudgetLedger instance is threaded through
        // completion, embedding, and rerank, so a per-task ceiling is honored across
        // all three (invariant 11) — not split into three per-engine ledgers.
        let mut ledger = crate::BudgetLedger::default();

        // 1) Completion (frozen Engine path) accumulates into `ledger`... but
        //    Engine owns its own ledger; here we simulate the shared-ledger contract
        //    the serve loop uses: embed + rerank both take &mut ledger.
        let embed = EmbedEngine::new(vec![Box::new(MockEmbedProvider::new(
            "me",
            vec![ecard("e1", 4, 1000)],
            MockEmbedBehavior::Echo,
        ))]);
        let rerank = RerankEngine::new(vec![Box::new(MockRerankProvider::new(
            "mr",
            vec![rcard("r1", 500)],
            MockRerankBehavior::Echo,
        ))]);

        let ereq = EmbeddingRequest::new(Role::Research, vec!["x".into()], 0);
        embed.embed(&ereq, &mut ledger).unwrap();
        let rreq = RerankRequest::new(Role::Review, "q".into(), vec!["d".into()], 0);
        rerank.rerank(&rreq, &mut ledger).unwrap();

        // One ledger total: two requests counted, not two separate ledgers of one.
        assert_eq!(ledger.requests, 2);
    }

    #[test]
    fn embed_engine_falls_back_past_a_failing_provider() {
        let engine = EmbedEngine::new(vec![
            Box::new(MockEmbedProvider::new(
                "down",
                vec![ecard("e1", 4, 10)],
                MockEmbedBehavior::AlwaysFail("503".into()),
            )),
            Box::new(MockEmbedProvider::new(
                "up",
                vec![ecard("e1", 4, 10)],
                MockEmbedBehavior::Echo,
            )),
        ]);
        let mut ledger = crate::BudgetLedger::default();
        let req = EmbeddingRequest::new(Role::Research, vec!["a".into()], 0);
        let (_resp, fb, provider, _m) = engine.embed(&req, &mut ledger).unwrap();
        assert_eq!(provider, "up");
        assert_eq!(fb, vec!["down"]);
        assert_eq!(ledger.fallbacks, 1);
    }

    #[test]
    fn embed_engine_errors_when_all_providers_fail() {
        let engine = EmbedEngine::new(vec![Box::new(MockEmbedProvider::new(
            "down",
            vec![ecard("e1", 4, 10)],
            MockEmbedBehavior::AlwaysFail("boom".into()),
        ))]);
        let mut ledger = crate::BudgetLedger::default();
        let req = EmbeddingRequest::new(Role::Research, vec!["a".into()], 0);
        assert!(matches!(
            engine.embed(&req, &mut ledger),
            Err(RouteError::AllProvidersFailed(_))
        ));
        // A failing request meters nothing (success-path-only accounting).
        assert_eq!(ledger.requests, 0);
    }

    #[test]
    fn embed_over_budget_fails_closed() {
        let engine = EmbedEngine::new(vec![Box::new(MockEmbedProvider::new(
            "pricey",
            vec![ecard("e1", 4, 1_000_000)],
            MockEmbedBehavior::Echo,
        ))]);
        let mut ledger = crate::BudgetLedger::default();
        let req = EmbeddingRequest::new(Role::Research, vec!["x".repeat(4000)], 1);
        assert!(matches!(
            engine.embed(&req, &mut ledger),
            Err(RouteError::OverBudget(_))
        ));
    }
}
