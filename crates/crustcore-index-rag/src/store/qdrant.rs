// SPDX-License-Identifier: Apache-2.0
//! Qdrant vector-store backend (C5.3) — behind the off-by-default `qdrant` feature.
//!
//! This is a thin [`VectorStore`](super::VectorStore) adapter. The **real network client
//! is `TODO(C5-qdrant-live)`** (the live HTTP/gRPC transport, like B3's
//! `TODO(B3-embed-live)`, routes through a spawned helper, never linking an HTTP/TLS stack
//! into a CI build). The deterministic core is exercised by
//! [`MockVectorStore`](super::mock::MockVectorStore); this stub exists so the feature
//! compiles and the credential-flow contract is fixed.
//!
//! **Credential flow (invariants 1, 3; dimension (f)):** any Qdrant API key resolves
//! ONLY through [`crustcore_secrets::CredentialProxy`] — the live client injects the key
//! as an outbound header at send time and never reads it from the sandbox env, never
//! places it in a span/log, and never makes it model-visible. The key bytes never enter
//! this process's model-visible surface.

use super::{ChunkId, ChunkMeta, VectorStore, DEFAULT_NAMESPACE};

/// Configuration for the Qdrant backend. Holds only non-secret connection metadata; the
/// API key is resolved via the broker/`CredentialProxy` at request time, never stored here.
#[derive(Debug, Clone)]
pub struct QdrantConfig {
    /// Collection (namespace) name.
    pub collection: String,
    /// Loopback/remote endpoint (non-secret).
    pub endpoint: String,
}

/// A thin Qdrant adapter. `TODO(C5-qdrant-live)`: wire the spawned helper transport and
/// per-request `CredentialProxy` header injection. Until then the methods are inert.
#[derive(Debug)]
pub struct QdrantVectorStore {
    #[allow(dead_code)] // consumed by the live transport (TODO(C5-qdrant-live)).
    config: QdrantConfig,
    namespace: String,
}

impl QdrantVectorStore {
    /// Builds an adapter from non-secret config. No network or credential access happens
    /// here; the live transport is `TODO(C5-qdrant-live)`.
    #[must_use]
    pub fn new(config: QdrantConfig) -> Self {
        let namespace = config.collection.clone();
        QdrantVectorStore { config, namespace }
    }
}

impl VectorStore for QdrantVectorStore {
    fn upsert(&mut self, _items: Vec<(ChunkId, Vec<f32>, ChunkMeta)>) {
        // TODO(C5-qdrant-live): POST points to the collection via the spawned helper,
        // injecting auth via CredentialProxy.
    }

    fn nearest(&self, _query: &[f32], _k: usize, _floor: f32) -> Vec<(ChunkId, f32, ChunkMeta)> {
        // TODO(C5-qdrant-live): query the collection; the planner redact-then-bounds the
        // result identically to every other backend.
        Vec::new()
    }

    fn delete(&mut self, _id: &ChunkId) {
        // TODO(C5-qdrant-live): delete points by id.
    }

    fn set_namespace(&mut self, namespace: &str) {
        self.namespace = namespace.to_string();
    }

    fn namespace(&self) -> &str {
        if self.namespace.is_empty() {
            DEFAULT_NAMESPACE
        } else {
            &self.namespace
        }
    }

    fn len(&self) -> usize {
        0
    }
}
