// SPDX-License-Identifier: Apache-2.0
//! The [`QueryPlanner`] (C5.6): turn a query into a **bounded** retrieval plan, run the
//! store NN, then push every hit through the **existing** redact-then-bound pipeline
//! ([`crustcore_index::embed::semantic_select`] + [`crustcore_secrets::Redactor`] + the
//! `MAX_CONTEXT_*` caps), emitting a [`ContextBundle`] of inert, provenance-tagged
//! fragments.
//!
//! **This is the trust chokepoint.** Defaults are read-only, redact-by-default,
//! bounded-by-default. Memory is never authority: the planner returns a
//! [`crustcore_index::ContextBundle`] — pure `ModelVisibleText` fragments — and there is
//! deliberately **no** path from a hit to an `Approved<T>` or a capability (dimension (a)).
//! Adding or swapping a backend changes only *which* fragments surface, never their
//! (non-)authority, redaction, or bounding (dimensions (b), (g)).

use crustcore_index::embed::{semantic_select, Embedder};
use crustcore_index::{ContextBundle, ContextCandidate, MemoryKind, MemorySource};
use crustcore_secrets::Redactor;
use crustcore_types::BoundedText;

use crate::store::{ChunkId, ChunkMeta, VectorStore, MAX_NEAREST_K, MAX_STORE_HITS};

/// Maximum bytes of a query string the planner will embed (bounded input; invariant 11).
pub const MAX_QUERY_BYTES: usize = 4 * 1024;

/// A bounded retrieval plan. Every field is capped/normalized on construction so a caller
/// (or an upstream model) cannot widen the fan-in or disable redaction.
#[derive(Debug, Clone)]
pub struct RetrievalPlan {
    /// Store namespace to query.
    pub namespace: String,
    /// Top-`k`, capped to [`MAX_NEAREST_K`].
    pub k: usize,
    /// Similarity floor in `[0, 1]` (negative floors are clamped to 0 — the store already
    /// drops non-positive similarities).
    pub floor: f32,
}

impl RetrievalPlan {
    /// Builds a plan with the safe, bounded defaults applied: `k` capped to
    /// [`MAX_NEAREST_K`], `floor` clamped to `[0, 1]`.
    #[must_use]
    pub fn new(namespace: impl Into<String>, k: usize, floor: f32) -> Self {
        RetrievalPlan {
            namespace: namespace.into(),
            k: k.clamp(1, MAX_NEAREST_K),
            floor: if floor.is_finite() {
                floor.clamp(0.0, 1.0)
            } else {
                0.0
            },
        }
    }
}

/// Resolves a retrieved [`ChunkId`] to its raw content + embedding, so the planner can
/// build a [`ContextCandidate`] and re-apply the shared redact-then-bound ranking. The
/// indexer (`index.rs`) populates the backing store from which this resolves; content is
/// untrusted data and is redacted by the planner before it can be model-visible.
pub trait ChunkResolver {
    /// The raw (untrusted, un-redacted) content for `id`, plus its embedding, if known.
    /// Returns `None` for an unknown/forged id — so a hostile backend returning a forged
    /// `ChunkId` simply yields no fragment (dimension (c)).
    fn resolve(&self, id: &ChunkId) -> Option<(String, Vec<f32>)>;
}

/// The query planner. Holds an embedder (the dev/CI [`HashEmbedder`] or a live one behind
/// `live`) and a redactor; runs the bounded plan and returns a redacted+bounded bundle.
pub struct QueryPlanner<'a, E: Embedder> {
    embedder: &'a E,
    redactor: &'a Redactor,
}

impl<'a, E: Embedder> QueryPlanner<'a, E> {
    /// A planner over `embedder` and `redactor`. The redactor seals the model boundary;
    /// the embedder produces the query vector.
    pub fn new(embedder: &'a E, redactor: &'a Redactor) -> Self {
        QueryPlanner { embedder, redactor }
    }

    /// Runs `plan` against `store`, resolving content via `resolver`, and returns a
    /// **redacted, bounded** [`ContextBundle`].
    ///
    /// Steps (every one bounded / fail-safe):
    /// 1. Truncate the query to [`MAX_QUERY_BYTES`] and embed it.
    /// 2. Ask the store for `min(plan.k, MAX_NEAREST_K)` nearest at `plan.floor`.
    /// 3. Truncate the returned hits to [`MAX_STORE_HITS`] and **deduplicate forged
    ///    `ChunkId`s** (a hostile backend cannot inflate the candidate set).
    /// 4. Resolve each hit's content+embedding; skip unresolvable/forged ids.
    /// 5. Hand the candidates to [`semantic_select`], which **redacts then bounds** every
    ///    fragment under the `MAX_CONTEXT_*` caps — the identical boundary every other
    ///    `crustcore-index` retrieval path uses. The store score is not trusted for
    ///    ranking; `semantic_select` re-ranks by cosine to the query embedding (so a
    ///    NaN/forged store score cannot reorder or smuggle a fragment).
    ///
    /// The returned fragments are inert `ModelVisibleText` tagged with provenance — never
    /// authority.
    pub fn run<S: VectorStore + ?Sized, R: ChunkResolver + ?Sized>(
        &self,
        query: &str,
        plan: &RetrievalPlan,
        store: &mut S,
        resolver: &R,
    ) -> ContextBundle {
        // 1. Bounded query embedding.
        let bounded_query = BoundedText::truncated(query, MAX_QUERY_BYTES);
        let query_embedding = self.embedder.embed(bounded_query.as_str());

        // 2. Scope + query the store with a capped k and clamped floor.
        store.set_namespace(&plan.namespace);
        let k = plan.k.clamp(1, MAX_NEAREST_K);
        let mut hits = store.nearest(&query_embedding, k, plan.floor);

        // 3. Bound the returned hit count and dedup forged duplicate ChunkIds. We keep the
        //    first occurrence of each id (stable) so a backend cannot amplify one chunk.
        hits.truncate(MAX_STORE_HITS);
        let mut seen = std::collections::BTreeSet::new();
        hits.retain(|(id, _, _)| seen.insert(id.clone()));

        // 4. Resolve content; build candidates with their embeddings for re-ranking. We
        //    OWN the content strings (resolved) so `ContextCandidate<'_>` can borrow them.
        let resolved: Vec<(String, ChunkMeta, Vec<f32>)> = hits
            .into_iter()
            .filter_map(|(id, _score, meta)| {
                resolver
                    .resolve(&id)
                    .map(|(content, emb)| (content, meta, emb))
            })
            .collect();

        let candidates: Vec<(ContextCandidate<'_>, Vec<f32>)> = resolved
            .iter()
            .map(|(content, meta, emb)| {
                (
                    ContextCandidate {
                        source: meta.source,
                        kind: source_to_kind(meta.source),
                        text: content.as_str(),
                    },
                    emb.clone(),
                )
            })
            .collect();

        // 5. The shared redact-then-bound boundary. `semantic_select` re-ranks by cosine to
        //    the query embedding and applies `build_bundle` (redact FIRST, then bound under
        //    MAX_CONTEXT_FRAGMENTS / MAX_CONTEXT_BUNDLE / MAX_FRAGMENT_BYTES). Every emitted
        //    fragment is `ModelVisibleText` — inert, redacted, provenance-tagged data.
        semantic_select(&query_embedding, &candidates, self.redactor)
    }
}

/// Maps chunk provenance to the nearest [`MemoryKind`] for the bundle fragment. Chunks are
/// repo/file-derived prior observations; this is provenance bookkeeping only, never trust.
fn source_to_kind(source: MemorySource) -> MemoryKind {
    match source {
        MemorySource::RepoFile => MemoryKind::Convention,
        MemorySource::ToolObservation => MemoryKind::CommandMemory,
        MemorySource::PriorRun => MemoryKind::CommandMemory,
        MemorySource::UserNote => MemoryKind::Convention,
    }
}
