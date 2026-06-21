// SPDX-License-Identifier: Apache-2.0
//! The indexing entry point (C5.8): `index_repo` — chunk -> embed -> upsert, all bounded.
//!
//! **Write-to-store only.** No chunk content enters model context here; indexing only
//! writes embeddings + pure-data [`ChunkMeta`] tags into the [`VectorStore`]. The live
//! indexer reads file content via **confined paths** (the same path confinement the rest
//! of CrustCore uses); this function takes already-read in-memory `(path, content)` so the
//! deterministic core is fully CI-testable (dimension (e)).
//!
//! Bounded everything (invariant 11): the chunker caps each fragment to
//! [`MAX_CHUNK_BYTES`](crate::chunk::MAX_CHUNK_BYTES) and the per-file fan-out; this
//! function additionally caps the total number of files and total chunks indexed in one
//! call, so a hostile/huge repo cannot blow up the store.

use std::collections::BTreeMap;

use crustcore_index::embed::Embedder;
use crustcore_index::MemorySource;

use crate::chunk::Chunker;
use crate::plan::ChunkResolver;
use crate::store::{ChunkId, VectorStore};

/// Maximum files indexed in one `index_repo` call (bounded fan-in).
pub const MAX_INDEX_FILES: usize = 64 * 1024;

/// Maximum total chunks upserted in one `index_repo` call (bounded; deny-large).
pub const MAX_INDEX_CHUNKS: usize = 256 * 1024;

/// The default in-memory [`ChunkResolver`]: records each indexed chunk's raw content and
/// embedding so the planner can resolve a retrieved [`ChunkId`] back to a candidate. It is
/// produced by [`index_repo`] alongside the store upserts. Content held here is untrusted
/// data; the planner redacts it before any model visibility.
#[derive(Debug, Default)]
pub struct IndexedContent {
    by_id: BTreeMap<ChunkId, (String, Vec<f32>)>,
}

impl IndexedContent {
    /// An empty resolver.
    #[must_use]
    pub fn new() -> Self {
        IndexedContent {
            by_id: BTreeMap::new(),
        }
    }

    /// Number of resolvable chunks.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// Whether empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
}

impl ChunkResolver for IndexedContent {
    fn resolve(&self, id: &ChunkId) -> Option<(String, Vec<f32>)> {
        self.by_id.get(id).cloned()
    }
}

/// Chunks each `(path, content)`, embeds every chunk, and upserts `(ChunkId, embedding,
/// ChunkMeta)` into `store` — **write-to-store only**, no content returned to a caller for
/// model context. Returns an [`IndexedContent`] resolver for later planner retrieval.
///
/// All bounded: at most [`MAX_INDEX_FILES`] files and [`MAX_INDEX_CHUNKS`] chunks; each
/// chunk is bounded by the [`Chunker`]. `source` tags every chunk's provenance (typically
/// [`MemorySource::RepoFile`]); `redact_required` defaults to `true` on every chunk.
pub fn index_repo<E: Embedder, S: VectorStore + ?Sized>(
    files: &[(&str, &str)],
    chunker: &Chunker,
    embedder: &E,
    store: &mut S,
    source: MemorySource,
) -> IndexedContent {
    let mut resolver = IndexedContent::new();
    let mut total_chunks = 0usize;
    let mut batch = Vec::new();

    for &(path, content) in files.iter().take(MAX_INDEX_FILES) {
        for chunk in chunker.chunk(path, content, source) {
            if total_chunks >= MAX_INDEX_CHUNKS {
                break;
            }
            total_chunks += 1;
            let embedding = embedder.embed(&chunk.content);
            resolver
                .by_id
                .insert(chunk.id.clone(), (chunk.content.clone(), embedding.clone()));
            batch.push((chunk.id, embedding, chunk.meta));
        }
        if total_chunks >= MAX_INDEX_CHUNKS {
            break;
        }
    }
    store.upsert(batch);
    resolver
}
