// SPDX-License-Identifier: Apache-2.0
//! A CI [`MockVectorStore`] (C5.3): a controllable peer backend used to prove the planner
//! and the redact-then-bound boundary hold against an **adversarial** store.
//!
//! Unlike [`LocalVectorStore`](super::local::LocalVectorStore), the mock can be told to
//! misbehave the way a hostile or buggy external backend might (adversarial dimension
//! (c)): return more hits than `k`, emit `NaN`/`inf`/negative scores, or forge duplicate
//! [`ChunkId`]s. The planner must still bound, sanitize, and redact every hit — so the
//! mock is the fixture that forces those guarantees.

use super::{ByteSpan, ChunkId, ChunkMeta, VectorStore, DEFAULT_NAMESPACE};
use crustcore_index::MemorySource;

/// A canned hit the mock returns from `nearest`.
#[derive(Debug, Clone)]
pub struct MockHit {
    /// The id to return.
    pub id: ChunkId,
    /// The score to return (may be `NaN`/`inf`/negative to exercise sanitization).
    pub score: f32,
    /// The metadata to return.
    pub meta: ChunkMeta,
}

impl MockHit {
    /// A hit with safe-default metadata (`redact_required = true`, no symbol).
    #[must_use]
    pub fn new(id: impl Into<String>, score: f32, path: impl Into<String>) -> Self {
        MockHit {
            id: ChunkId::new(id),
            score,
            meta: ChunkMeta::new(path, ByteSpan::new(0, 0), MemorySource::RepoFile),
        }
    }
}

/// A controllable store for CI. By default it behaves like a normal store (it records
/// upserts and returns them filtered by the positive-similarity + floor gate using a
/// caller-supplied score). With [`with_canned_hits`](Self::with_canned_hits) it instead
/// returns a fixed, possibly-adversarial hit list verbatim — letting a test prove the
/// planner survives an oversized / NaN-scored / forged-duplicate payload.
#[derive(Debug, Default)]
pub struct MockVectorStore {
    upserted: Vec<(ChunkId, Vec<f32>, ChunkMeta)>,
    canned: Option<Vec<MockHit>>,
    namespace: String,
}

impl MockVectorStore {
    /// An empty mock in the default namespace, behaving like a real store.
    #[must_use]
    pub fn new() -> Self {
        MockVectorStore {
            upserted: Vec::new(),
            canned: None,
            namespace: DEFAULT_NAMESPACE.to_string(),
        }
    }

    /// Forces `nearest` to return `hits` verbatim (ignoring the query) — the adversarial
    /// mode. The list is returned UNFILTERED and UNBOUNDED on purpose, so the planner's
    /// own capping/sanitization/redaction is what must hold (dimension (c)).
    #[must_use]
    pub fn with_canned_hits(mut self, hits: Vec<MockHit>) -> Self {
        self.canned = Some(hits);
        self
    }

    /// The chunks recorded by `upsert` (for assertions).
    #[must_use]
    pub fn upserted(&self) -> &[(ChunkId, Vec<f32>, ChunkMeta)] {
        &self.upserted
    }
}

impl VectorStore for MockVectorStore {
    fn upsert(&mut self, items: Vec<(ChunkId, Vec<f32>, ChunkMeta)>) {
        self.upserted.extend(items);
    }

    fn nearest(&self, query: &[f32], k: usize, floor: f32) -> Vec<(ChunkId, f32, ChunkMeta)> {
        // Adversarial mode: return canned hits verbatim, unbounded and unsanitized, so the
        // planner is the thing under test.
        if let Some(hits) = &self.canned {
            return hits
                .iter()
                .map(|h| (h.id.clone(), h.score, h.meta.clone()))
                .collect();
        }
        // Normal mode: score upserted chunks honestly via the shared cosine and apply the
        // same positive-similarity + floor gate the local backend uses.
        use crustcore_index::embed::cosine;
        let effective_floor = floor.max(0.0);
        let mut scored: Vec<(f32, usize)> = self
            .upserted
            .iter()
            .enumerate()
            .map(|(i, (_, emb, _))| (cosine(query, emb), i))
            .filter(|(s, _)| *s > 0.0 && *s >= effective_floor)
            .collect();
        scored.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(&b.1)));
        scored
            .into_iter()
            .take(k)
            .map(|(s, i)| {
                let (id, _, meta) = &self.upserted[i];
                (id.clone(), s, meta.clone())
            })
            .collect()
    }

    fn delete(&mut self, id: &ChunkId) {
        self.upserted.retain(|(i, _, _)| i != id);
    }

    fn set_namespace(&mut self, namespace: &str) {
        self.namespace = namespace.to_string();
    }

    fn namespace(&self) -> &str {
        &self.namespace
    }

    fn len(&self) -> usize {
        self.upserted.len()
    }
}
