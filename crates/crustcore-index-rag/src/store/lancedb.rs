// SPDX-License-Identifier: Apache-2.0
//! LanceDB vector-store backend (C5.3) — behind the off-by-default `lancedb` feature.
//!
//! A thin [`VectorStore`](super::VectorStore) adapter; the **real client is
//! `TODO(C5-lancedb-live)`**. The deterministic core is exercised by
//! [`MockVectorStore`](super::mock::MockVectorStore). Any credential resolves only through
//! [`crustcore_secrets::CredentialProxy`] (never the sandbox env, never model-visible;
//! invariants 1, 3, dimension (f)).

use super::{ChunkId, ChunkMeta, VectorStore, DEFAULT_NAMESPACE};

/// Configuration for the LanceDB backend (non-secret connection metadata only).
#[derive(Debug, Clone)]
pub struct LanceDbConfig {
    /// Table (namespace) name.
    pub table: String,
    /// Dataset URI (non-secret).
    pub uri: String,
}

/// A thin LanceDB adapter. `TODO(C5-lancedb-live)`: wire the live client + per-request
/// `CredentialProxy` auth. Until then the methods are inert.
#[derive(Debug)]
pub struct LanceDbVectorStore {
    #[allow(dead_code)] // consumed by the live transport (TODO(C5-lancedb-live)).
    config: LanceDbConfig,
    namespace: String,
}

impl LanceDbVectorStore {
    /// Builds an adapter from non-secret config. No network/credential access here.
    #[must_use]
    pub fn new(config: LanceDbConfig) -> Self {
        let namespace = config.table.clone();
        LanceDbVectorStore { config, namespace }
    }
}

impl VectorStore for LanceDbVectorStore {
    fn upsert(&mut self, _items: Vec<(ChunkId, Vec<f32>, ChunkMeta)>) {
        // TODO(C5-lancedb-live): add rows via the live client / spawned helper.
    }

    fn nearest(&self, _query: &[f32], _k: usize, _floor: f32) -> Vec<(ChunkId, f32, ChunkMeta)> {
        // TODO(C5-lancedb-live): vector search; the planner redact-then-bounds the result.
        Vec::new()
    }

    fn delete(&mut self, _id: &ChunkId) {
        // TODO(C5-lancedb-live): delete row by id.
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
