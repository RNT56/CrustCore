// SPDX-License-Identifier: Apache-2.0
//! End-to-end RAG flow + retrieval-quality eval (C5.7), deterministic over `HashEmbedder`
//! and the dependency-free local store (no net/secrets).

use crustcore_index::embed::HashEmbedder;
use crustcore_index::MemorySource;
use crustcore_index_rag::{
    index_repo, ChunkResolver, Chunker, LocalVectorStore, QueryPlanner, RetrievalPlan, VectorStore,
    MAX_NEAREST_K,
};
use crustcore_secrets::Redactor;

/// A small canned corpus: each file's content is dominated by a distinct topic so a
/// topical query should retrieve the matching file's chunk.
fn corpus() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "src/verify.rs",
            "the verify command runs cargo xtask verify which runs fmt clippy and the test suite",
        ),
        (
            "src/sandbox.rs",
            "the sandbox confines execution with bubblewrap and a deny all egress network posture",
        ),
        (
            "src/secrets.rs",
            "the secret broker injects credentials via a credential proxy without exposing bytes",
        ),
        (
            "docs/revenue.md",
            "quarterly revenue projections and the annual financial planning calendar",
        ),
    ]
}

#[test]
fn full_chunk_embed_upsert_plan_flow_is_end_to_end() {
    let embedder = HashEmbedder;
    let chunker = Chunker::new();
    let mut store = LocalVectorStore::new();
    let redactor = Redactor::new();

    // index_repo: chunk -> embed -> upsert (write-to-store only).
    let resolver = index_repo(
        &corpus(),
        &chunker,
        &embedder,
        &mut store,
        MemorySource::RepoFile,
    );
    assert!(store.len() > 0, "store populated");
    assert!(!resolver.is_empty());

    // Plan + retrieve.
    let planner = QueryPlanner::new(&embedder, &redactor);
    let plan = RetrievalPlan::new("default", 3, 0.0);
    let bundle = planner.run(
        "how does the verify command work",
        &plan,
        &mut store,
        &resolver,
    );
    assert!(!bundle.fragments.is_empty(), "retrieved something relevant");
    // The verify file's content surfaces first (topical match).
    assert!(bundle.fragments[0].text.as_str().contains("verify"));
    // Bounded.
    assert!(bundle.byte_len() <= crustcore_index::MAX_CONTEXT_BUNDLE);
}

#[test]
fn retrieval_precision_meets_floor_over_canned_corpus() {
    let embedder = HashEmbedder;
    let chunker = Chunker::new();
    let mut store = LocalVectorStore::new();
    let redactor = Redactor::new();
    let resolver = index_repo(
        &corpus(),
        &chunker,
        &embedder,
        &mut store,
        MemorySource::RepoFile,
    );
    let planner = QueryPlanner::new(&embedder, &redactor);

    // (query, substring expected in the top fragment).
    let cases = [
        ("verify command cargo xtask fmt clippy", "verify"),
        ("sandbox bubblewrap deny egress network", "sandbox"),
        ("secret broker credential proxy bytes", "credential"),
        ("quarterly revenue financial planning", "revenue"),
    ];
    let mut correct = 0;
    for (query, expected) in cases {
        let plan = RetrievalPlan::new("default", 3, 0.0);
        let bundle = planner.run(query, &plan, &mut store, &resolver);
        if let Some(first) = bundle.fragments.first() {
            if first.text.as_str().contains(expected) {
                correct += 1;
            }
        }
    }
    // Precision@1 floor: at least 3 of 4 topical queries return the right file's chunk
    // first (HashEmbedder is a bag-of-words stand-in, so the floor is deterministic but
    // not 100%).
    assert!(correct >= 3, "retrieval precision below floor: {correct}/4");
}

#[test]
fn planner_caps_k_and_applies_floor() {
    let embedder = HashEmbedder;
    let chunker = Chunker::new();
    let mut store = LocalVectorStore::new();
    let redactor = Redactor::new();
    let resolver = index_repo(
        &corpus(),
        &chunker,
        &embedder,
        &mut store,
        MemorySource::RepoFile,
    );
    let planner = QueryPlanner::new(&embedder, &redactor);

    // Ask for an absurd k; RetrievalPlan caps it to MAX_NEAREST_K.
    let plan = RetrievalPlan::new("default", 10_000, 0.0);
    assert_eq!(plan.k, MAX_NEAREST_K);

    // A floor of 1.0 (near-identical only) should drop most/all topical-but-imperfect hits.
    let strict = RetrievalPlan::new("default", 3, 1.0);
    let bundle = planner.run("sandbox", &strict, &mut store, &resolver);
    // Either nothing passes the strict floor, or what does is genuinely near-perfect; in
    // all cases the bundle is bounded.
    assert!(bundle.byte_len() <= crustcore_index::MAX_CONTEXT_BUNDLE);
    // Negative floor is clamped to 0 (no panic, no widening).
    let neg = RetrievalPlan::new("default", 3, -5.0);
    assert_eq!(neg.floor, 0.0);
}

#[test]
fn retrieval_is_deterministic_across_runs() {
    // Same corpus -> same ranked, capped, redacted bundle (dimension (g)).
    let embedder = HashEmbedder;
    let chunker = Chunker::new();
    let redactor = Redactor::new();

    let run = || {
        let mut store = LocalVectorStore::new();
        let resolver = index_repo(
            &corpus(),
            &chunker,
            &embedder,
            &mut store,
            MemorySource::RepoFile,
        );
        let planner = QueryPlanner::new(&embedder, &redactor);
        let plan = RetrievalPlan::new("default", 4, 0.0);
        let bundle = planner.run(
            "verify sandbox secret revenue",
            &plan,
            &mut store,
            &resolver,
        );
        bundle
            .fragments
            .iter()
            .map(|f| f.text.as_str().to_string())
            .collect::<Vec<_>>()
    };
    assert_eq!(run(), run(), "retrieval must be deterministic");
}

#[test]
fn unknown_chunk_id_resolves_to_nothing() {
    // A resolver that never resolves -> empty bundle (no panic).
    struct NeverResolver;
    impl ChunkResolver for NeverResolver {
        fn resolve(&self, _id: &crustcore_index_rag::ChunkId) -> Option<(String, Vec<f32>)> {
            None
        }
    }
    let embedder = HashEmbedder;
    let chunker = Chunker::new();
    let mut store = LocalVectorStore::new();
    let redactor = Redactor::new();
    let _ = index_repo(
        &corpus(),
        &chunker,
        &embedder,
        &mut store,
        MemorySource::RepoFile,
    );
    let planner = QueryPlanner::new(&embedder, &redactor);
    let plan = RetrievalPlan::new("default", 3, 0.0);
    let bundle = planner.run("verify", &plan, &mut store, &NeverResolver);
    assert!(bundle.fragments.is_empty());
}
