// SPDX-License-Identifier: Apache-2.0
//! Optional repo memory / code intelligence (`ROADMAP.md` §16; Phase 14).
//!
//! Repo summaries, symbol graphs, and failure/convention memory live here, fully
//! optional and never linked into nano (invariant 20). **Memory is never
//! authority** — it is retrieved as context and marked as prior observation
//! (`docs/self-improvement.md`).
//!
//! Status: Phase 0 scaffold (std only). Stores and indexers land in Phase 14
//! (`TODO(P14.*)`).
#![forbid(unsafe_code)]

/// Kinds of memory this crate can retrieve (as untrusted prior observations).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryKind {
    /// Repository summary capsule.
    RepoSummary,
    /// Test/build command memory.
    CommandMemory,
    /// Convention memory.
    Convention,
    /// Failure-classifier memory.
    Failure,
}
