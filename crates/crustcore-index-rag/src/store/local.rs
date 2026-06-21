// SPDX-License-Identifier: Apache-2.0
//! The default, **dependency-free** local vector-store backend (C5.2).
//!
//! It is a thin namespaced wrapper over the same brute-force cosine nearest-neighbor scan
//! that [`crustcore_index::embed::VectorMemory`] performs, reusing
//! [`crustcore_index::embed::cosine`] verbatim (no re-implemented ranking). It preserves
//! `VectorMemory`'s query semantics exactly: only **positively-similar** hits, sorted by
//! descending score with **insertion-order tie-breaks** (deterministic). A `floor` is an
//! additional lower bound on top of the positive-similarity filter.
//!
//! Persistence is the `TODO(C5-persist)` seam (behind the off-by-default `persist`
//! feature, reusing `crustcore-index`'s dependency-free snapshot); the default path is
//! purely in-memory and dependency-free.

use std::collections::BTreeMap;

use crustcore_index::embed::cosine;

use super::{ChunkId, ChunkMeta, VectorStore, DEFAULT_NAMESPACE};

/// One stored chunk: its embedding, metadata, and a monotonic insertion sequence used
/// for deterministic tie-breaking (mirrors `VectorMemory`'s insertion-order ties).
#[derive(Debug, Clone)]
struct Stored {
    embedding: Vec<f32>,
    meta: ChunkMeta,
    seq: u64,
}

/// The dependency-free default backend. Chunks are partitioned by namespace; within a
/// namespace an upsert replaces by [`ChunkId`] (idempotent).
#[derive(Debug)]
pub struct LocalVectorStore {
    namespaces: BTreeMap<String, BTreeMap<ChunkId, Stored>>,
    namespace: String,
    next_seq: u64,
}

impl Default for LocalVectorStore {
    fn default() -> Self {
        LocalVectorStore::new()
    }
}

impl LocalVectorStore {
    /// An empty store scoped to the default namespace.
    #[must_use]
    pub fn new() -> Self {
        LocalVectorStore {
            namespaces: BTreeMap::new(),
            namespace: DEFAULT_NAMESPACE.to_string(),
            next_seq: 0,
        }
    }

    fn active(&self) -> Option<&BTreeMap<ChunkId, Stored>> {
        self.namespaces.get(&self.namespace)
    }
}

impl VectorStore for LocalVectorStore {
    fn upsert(&mut self, items: Vec<(ChunkId, Vec<f32>, ChunkMeta)>) {
        let ns = self.namespaces.entry(self.namespace.clone()).or_default();
        for (id, embedding, meta) in items {
            let seq = self.next_seq;
            self.next_seq += 1;
            // Idempotent on ChunkId: a duplicate/forged id REPLACES rather than
            // double-counts, so a backend caller cannot inflate the set with forged dupes.
            ns.insert(
                id,
                Stored {
                    embedding,
                    meta,
                    seq,
                },
            );
        }
    }

    fn nearest(&self, query: &[f32], k: usize, floor: f32) -> Vec<(ChunkId, f32, ChunkMeta)> {
        let Some(ns) = self.active() else {
            return Vec::new();
        };
        // Score every stored chunk; keep only positively-similar AND >= floor (same
        // positive-similarity gate as VectorMemory, plus the explicit floor). `cosine`
        // already sanitizes (finite-or-0, length-mismatch -> 0), so a NaN/inf embedding
        // cannot poison the ranking.
        let effective_floor = floor.max(0.0);
        let mut scored: Vec<(f32, u64, &ChunkId, &Stored)> = ns
            .iter()
            .map(|(id, s)| (cosine(query, &s.embedding), s.seq, id, s))
            .filter(|(score, _, _, _)| *score > 0.0 && *score >= effective_floor)
            .collect();
        // Descending score; ties resolve by ascending insertion seq (deterministic),
        // exactly like VectorMemory's `then(a.1.cmp(&b.1))` on the original index.
        scored.sort_by(|a, b| b.0.total_cmp(&a.0).then(a.1.cmp(&b.1)));
        scored
            .into_iter()
            .take(k)
            .map(|(score, _, id, s)| (id.clone(), score, s.meta.clone()))
            .collect()
    }

    fn delete(&mut self, id: &ChunkId) {
        if let Some(ns) = self.namespaces.get_mut(&self.namespace) {
            ns.remove(id);
        }
    }

    fn set_namespace(&mut self, namespace: &str) {
        self.namespace = namespace.to_string();
    }

    fn namespace(&self) -> &str {
        &self.namespace
    }

    fn len(&self) -> usize {
        self.active().map_or(0, BTreeMap::len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crustcore_index::embed::{Embedder, HashEmbedder, VectorMemory};
    use crustcore_index::{MemoryEntry, MemoryKind, MemorySource};
    use crustcore_types::BoundedText;

    use crate::store::ByteSpan;

    fn meta(path: &str) -> ChunkMeta {
        ChunkMeta::new(path, ByteSpan::new(0, 0), MemorySource::RepoFile)
    }

    #[test]
    fn local_backend_matches_vector_memory_semantics() {
        let e = HashEmbedder;
        // Same corpus into both a raw VectorMemory and the local backend.
        let docs = [
            ("verify", "cargo xtask verify fmt clippy test"),
            ("clippy", "clippy lints mistakes"),
            ("revenue", "quarterly revenue projections"),
        ];
        let mut vm = VectorMemory::new();
        let mut store = LocalVectorStore::new();
        for (key, text) in docs {
            vm.put(
                MemoryEntry {
                    kind: MemoryKind::CommandMemory,
                    key: BoundedText::truncated(key, 256),
                    value: BoundedText::truncated(text, 256),
                    source: MemorySource::ToolObservation,
                },
                e.embed(text),
            );
            store.upsert(vec![(ChunkId::new(key), e.embed(text), meta(key))]);
        }
        let q = e.embed("run cargo verify with clippy");
        let vm_hits: Vec<&str> = vm.nearest(&q, 5).iter().map(|m| m.key.as_str()).collect();
        let store_hits: Vec<String> = store
            .nearest(&q, 5, 0.0)
            .into_iter()
            .map(|(id, _, _)| id.0)
            .collect();
        // Same ranked set + order (positively-similar only, deterministic ties).
        assert_eq!(vm_hits, store_hits);
        // Top hit is the dominant match.
        assert_eq!(store_hits[0], "verify");
    }

    #[test]
    fn floor_and_positive_similarity_are_applied() {
        let e = HashEmbedder;
        let mut store = LocalVectorStore::new();
        let a_text = "alpha beta gamma";
        store.upsert(vec![(ChunkId::new("a"), e.embed(a_text), meta("a"))]);
        // A deterministically-orthogonal doc: a zero vector never scores positively
        // (cosine returns 0 for a zero vector), so it is always excluded regardless of
        // HashEmbedder bucket collisions.
        store.upsert(vec![(
            ChunkId::new("orthogonal"),
            vec![0.0; crustcore_index::embed::EMBED_DIM],
            meta("orthogonal"),
        )]);
        let q = e.embed("alpha beta");
        // The floor is an effective lower bound: every returned hit is >= the floor.
        let mid = store.nearest(&q, 5, 0.05);
        assert!(mid.iter().all(|(_, s, _)| *s >= 0.05));
        // Floor 0 keeps positively-similar only; the zero-vector doc is always excluded.
        let low = store.nearest(&q, 5, 0.0);
        assert!(low.iter().all(|(_, s, _)| *s > 0.0));
        assert!(low.iter().any(|(id, _, _)| id.0 == "a"));
        assert!(
            !low.iter().any(|(id, _, _)| id.0 == "orthogonal"),
            "a zero-vector (non-positive) hit must be excluded"
        );
        // A floor above any achievable score yields nothing (no panic).
        assert!(store.nearest(&q, 5, 1.001).is_empty());
    }

    #[test]
    fn upsert_is_idempotent_on_chunk_id() {
        let e = HashEmbedder;
        let mut store = LocalVectorStore::new();
        store.upsert(vec![(ChunkId::new("x"), e.embed("one"), meta("x"))]);
        store.upsert(vec![(ChunkId::new("x"), e.embed("two"), meta("x"))]);
        assert_eq!(store.len(), 1, "duplicate id replaces, not duplicates");
        store.delete(&ChunkId::new("x"));
        assert!(store.is_empty());
    }

    #[test]
    fn namespaces_partition_retrieval() {
        let e = HashEmbedder;
        let mut store = LocalVectorStore::new();
        store.set_namespace("ns1");
        store.upsert(vec![(ChunkId::new("a"), e.embed("hello world"), meta("a"))]);
        store.set_namespace("ns2");
        assert_eq!(store.len(), 0);
        let q = e.embed("hello");
        assert!(store.nearest(&q, 5, 0.0).is_empty());
        store.set_namespace("ns1");
        assert_eq!(store.len(), 1);
        assert!(!store.nearest(&q, 5, 0.0).is_empty());
    }

    #[test]
    fn nan_inf_embeddings_do_not_panic_or_rank() {
        let e = HashEmbedder;
        let mut store = LocalVectorStore::new();
        // A poisoned embedding (NaN/inf) cannot rank: cosine sanitizes finite-or-0.
        store.upsert(vec![(
            ChunkId::new("poison"),
            vec![f32::NAN, f32::INFINITY, f32::NEG_INFINITY],
            meta("poison"),
        )]);
        store.upsert(vec![(ChunkId::new("ok"), e.embed("alpha"), meta("ok"))]);
        let q = e.embed("alpha");
        let hits = store.nearest(&q, 5, 0.0);
        assert!(hits.iter().all(|(_, s, _)| s.is_finite() && *s > 0.0));
        assert!(!hits.iter().any(|(id, _, _)| id.0 == "poison"));
    }
}
