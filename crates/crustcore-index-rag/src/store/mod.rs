// SPDX-License-Identifier: Apache-2.0
//! The pluggable [`VectorStore`] adapter trait and the pure-data [`ChunkMeta`] tag
//! (C5.1).
//!
//! A [`VectorStore`] is **retrieval only** — exactly like
//! [`crustcore_index::embed::VectorMemory`], it grants *nothing*. Swapping the local
//! backend for Qdrant/LanceDB changes only *where* vectors live and *which* fragments
//! surface — never their (non-)authority, never their redaction, never their bounding.
//! Every method returns inert, provenance-tagged data; there is deliberately no method
//! that mints an `Approved<T>`, a capability, or any token (memory is never authority).

use crustcore_index::MemorySource;

/// Maximum top-`k` any backend may be asked for. A planner/caller request is capped to
/// this regardless of what it asks (bounded fan-in; invariant 11). A malicious backend
/// that *returns* more than asked is additionally truncated by the planner.
pub const MAX_NEAREST_K: usize = 64;

/// Maximum number of hits the planner will accept from a single `nearest` call before
/// truncation, independent of `k`. Defends against a hostile/buggy backend that ignores
/// `k` and returns an oversized payload (adversarial dimension (c)).
pub const MAX_STORE_HITS: usize = 256;

/// An opaque, bounded identifier for a stored chunk. It is just data — a stable handle a
/// backend uses for upsert/delete and returns from `nearest`. Cloning/equality let a
/// caller deduplicate forged duplicates; it confers no authority.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChunkId(pub String);

impl ChunkId {
    /// Wraps a string id (bounded by the caller's chunker, which derives it from a
    /// confined path + byte span).
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        ChunkId(id.into())
    }

    /// The id as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A byte span `[start, end)` within a source file. Pure metadata; carries no contents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteSpan {
    /// Inclusive start byte offset.
    pub start: usize,
    /// Exclusive end byte offset.
    pub end: usize,
}

impl ByteSpan {
    /// A span `[start, end)`. `end` is clamped to be `>= start` so the length is never
    /// negative (a buggy/hostile caller cannot produce an inverted span).
    #[must_use]
    pub fn new(start: usize, end: usize) -> Self {
        ByteSpan {
            start,
            end: end.max(start),
        }
    }

    /// The span length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Whether the span is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.end == self.start
    }
}

/// Pure-data metadata attached to a chunk. **This is a tag, not a token**: it has no
/// capability field, no approval field, and no method that turns a chunk into authority
/// (memory is never authority; the type system makes the dangerous state unrepresentable
/// — adversarial dimension (a)). It only records *where* the chunk came from and whether
/// its content must be redacted before it can be model-visible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkMeta {
    /// Repo-relative source path (untrusted; provenance only).
    pub path: String,
    /// Byte span of the chunk within the file.
    pub byte_span: ByteSpan,
    /// Enclosing symbol name when symbol info was available; `None` falls back to a
    /// bounded line-chunk (the conservative default).
    pub symbol: Option<String>,
    /// Where this chunk came from — provenance, never trust (invariant 7).
    pub source: MemorySource,
    /// Whether the chunk's content must pass the redactor before model visibility.
    /// **Defaults to `true`** everywhere a chunk is created (fail-safe; dimension (d)).
    pub redact_required: bool,
}

impl ChunkMeta {
    /// A chunk tag with the **safe defaults**: `redact_required = true` and no symbol
    /// (line-chunk fallback). Callers narrow from here; a forgotten field stays safe.
    #[must_use]
    pub fn new(path: impl Into<String>, byte_span: ByteSpan, source: MemorySource) -> Self {
        ChunkMeta {
            path: path.into(),
            byte_span,
            symbol: None,
            source,
            redact_required: true,
        }
    }

    /// Sets the enclosing symbol (builder style); leaves `redact_required` untouched.
    #[must_use]
    pub fn with_symbol(mut self, symbol: impl Into<String>) -> Self {
        self.symbol = Some(symbol.into());
        self
    }
}

/// A pluggable vector-store adapter. **Retrieval only — grants nothing.**
///
/// Backends: the dependency-free [`local::LocalVectorStore`] (default), the CI
/// [`mock::MockVectorStore`], and the feature-gated external adapters
/// ([`qdrant`]/[`lancedb`], each `TODO(C5-<backend>-live)`). The planner applies the
/// redact-then-bound boundary to **every** backend's hits identically, so adding a
/// backend never changes the trust posture (dimensions (b), (g)).
pub trait VectorStore {
    /// Inserts (or replaces) chunks under the active namespace. Each entry is
    /// `(id, embedding, meta)`. Idempotent on `ChunkId`. The embedding dimension is the
    /// embedder's; mismatched dims simply score 0 at query time (see
    /// [`crustcore_index::embed::cosine`]).
    fn upsert(&mut self, items: Vec<(ChunkId, Vec<f32>, ChunkMeta)>);

    /// The top-`k` nearest chunks to `query` by cosine similarity, keeping only hits at
    /// or above `floor` and (like [`crustcore_index::embed::VectorMemory::nearest`])
    /// only positively-similar ones. Returns `(id, score, meta)`. `k` is the caller's
    /// request; the planner additionally caps it to [`MAX_NEAREST_K`] and truncates the
    /// returned vec to [`MAX_STORE_HITS`], so a backend cannot widen the fan-in.
    fn nearest(&self, query: &[f32], k: usize, floor: f32) -> Vec<(ChunkId, f32, ChunkMeta)>;

    /// Removes a chunk by id from the active namespace. A no-op if absent.
    fn delete(&mut self, id: &ChunkId);

    /// Scopes subsequent `upsert`/`nearest`/`delete` to `namespace`. Namespacing is a
    /// retrieval partition, not a trust boundary — it confers no authority.
    fn set_namespace(&mut self, namespace: &str);

    /// The active namespace.
    fn namespace(&self) -> &str;

    /// Number of chunks in the active namespace (bounded; for tests/inspection).
    fn len(&self) -> usize;

    /// Whether the active namespace is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The default namespace when none is set.
pub const DEFAULT_NAMESPACE: &str = "default";

pub mod local;
pub mod mock;

#[cfg(feature = "qdrant")]
pub mod qdrant;

#[cfg(feature = "lancedb")]
pub mod lancedb;
