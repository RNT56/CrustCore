// SPDX-License-Identifier: Apache-2.0
//! # crustcore-index-rag — a composable RAG layer (C5-rag)
//!
//! An **optional, off-nano** pack that generalizes B3-vector-memory into a composable RAG
//! surface: a pluggable [`VectorStore`] adapter trait, a bounded repo [`Chunker`],
//! symbol-aware chunk metadata, a bounded [`QueryPlanner`], and an [`index_repo`] entry
//! point — **without widening the trust boundary**.
//!
//! ## Memory is never authority
//!
//! Everything this crate retrieves is an *untrusted prior observation* (invariant 7),
//! offered to the model only as small, **redacted** (invariant 2), **bounded**
//! (invariant 11), provenance-tagged context. Structurally there is **no path** from a
//! [`store::ChunkMeta`] or a retrieved fragment to an `Approved<T>`, a capability, or any
//! token: the planner emits a [`crustcore_index::ContextBundle`] of pure
//! `ModelVisibleText` fragments, exactly like [`crustcore_index::select_context`] /
//! [`crustcore_index::embed::semantic_select`]. Swapping the local backend for
//! Qdrant/LanceDB changes only *where* vectors live and *which* fragments surface — never
//! their (non-)authority, redaction, or bounding.
//!
//! ## What is reused vs. what is a seam
//!
//! Reused verbatim (never re-implemented): the [`crustcore_index::embed::Embedder`] trait,
//! the dependency-free [`HashEmbedder`](crustcore_index::embed::HashEmbedder),
//! [`cosine`](crustcore_index::embed::cosine),
//! [`VectorMemory`](crustcore_index::embed::VectorMemory) semantics,
//! [`semantic_select`](crustcore_index::embed::semantic_select)'s redact-then-bound
//! boundary, the [`CodeIntel`](crustcore_index::CodeIntel) trait +
//! [`GrepCodeIntel`](crustcore_index::GrepCodeIntel), and
//! [`crustcore_secrets::Redactor`]/[`CredentialProxy`](crustcore_secrets::CredentialProxy).
//!
//! Off-by-default feature seams (absent from CI / nano):
//! - `live` — live text->vector embedding via B3's net-helper seam (`TODO(B3-embed-live)`).
//! - `ast` — tree-sitter/AST symbol spans (C5-ast; implemented for Rust via
//!   `chunk::ast::ast_symbol_spans` / `Chunker::chunk_with_ast_symbols`). The default
//!   (feature off) remains the conservative grep/line-chunk fallback, and any parse failure
//!   degrades to it; more grammars are an additive follow-on.
//! - `persist` — a persistent local store snapshot ([`LocalVectorStore::save`] /
//!   [`LocalVectorStore::load`]): a dependency-free, versioned, bounded, panic-free,
//!   fail-closed "CCRG" frame, mirroring [`crustcore_index::MemoryStore`]'s snapshot.
//! - `qdrant` / `lancedb` — external store backends, each `TODO(C5-<backend>-live)`, with
//!   auth flowing only via [`CredentialProxy`](crustcore_secrets::CredentialProxy).
//!
//! ## Bounded everything
//!
//! Queries ([`plan::MAX_QUERY_BYTES`]), chunk size ([`chunk::MAX_CHUNK_BYTES`]), top-`k`
//! ([`store::MAX_NEAREST_K`]), returned hits ([`store::MAX_STORE_HITS`]), per-call files /
//! chunks ([`index::MAX_INDEX_FILES`] / [`index::MAX_INDEX_CHUNKS`]), and the bundle caps
//! inherited from `crustcore-index` — none unbounded.
#![forbid(unsafe_code)]

pub mod chunk;
pub mod index;
pub mod plan;
pub mod store;

// Re-exports for the common surface.
pub use chunk::symbol::{symbol_spans_from_intel, SymbolSpan};
pub use chunk::{Chunk, Chunker, MAX_CHUNK_BYTES};
pub use index::{index_repo, IndexedContent};
pub use plan::{ChunkResolver, QueryPlanner, RetrievalPlan, MAX_QUERY_BYTES};
pub use store::local::LocalVectorStore;
pub use store::mock::{MockHit, MockVectorStore};
pub use store::{ByteSpan, ChunkId, ChunkMeta, VectorStore, MAX_NEAREST_K, MAX_STORE_HITS};

#[cfg(feature = "persist")]
pub use store::local::SnapshotError;

#[cfg(feature = "qdrant")]
pub use store::qdrant::{QdrantConfig, QdrantVectorStore};

#[cfg(feature = "lancedb")]
pub use store::lancedb::{LanceDbConfig, LanceDbVectorStore};
