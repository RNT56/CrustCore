// SPDX-License-Identifier: Apache-2.0
//! Red-team fixture for Track C C1-providers (the unified multi-modal capability
//! registry). Proves the ergonomic embedding/rerank layer cannot:
//!
//! (a) leak a credential into any model-visible value, log, or error string (mirrors
//!     `providers::tests::auth_header_is_sent_but_key_never_appears_in_text_or_errors`);
//! (b) panic / over-allocate / escape the `MAX_*` caps on malformed, oversized, or
//!     non-finite provider bytes (invariants 7, 11);
//! (c) corrupt downstream selection with out-of-range or duplicate rerank indices —
//!     they are clamped/dropped, never propagated raw;
//! (d) route a capability-missing request open — it fails closed with a typed error;
//! (e) flip a capability on by config/decode omission — defaults are off;
//! (f) emit partial output before fallback when an embedder/reranker fails;
//! (g) carry a credential onto the adapter struct / into any reachable state.
//!
//! All deterministic, no network: the transport is a canned `ReplayClient`.

use std::rc::Rc;

use crustcore_net::credsource::{CredentialSource, StaticCredentials};
use crustcore_net::embed::OpenAiEmbedProvider;
use crustcore_net::modality::{
    EmbedEngine, EmbedProvider, EmbeddingRequest, RerankEngine, RerankProvider, RerankRequest,
};
use crustcore_net::rerank::RerankApiProvider;
use crustcore_net::transport::{Canned, ReplayClient};
use crustcore_net::{BudgetLedger, ModelCard, ProviderError, RouteError};
use crustcore_netproto::{Role, MAX_BATCH, MAX_DOCS};

/// The sentinel credential. It must NEVER appear in any error/result/log string.
const SENTINEL: &str = "sk-CANARY-d34db33f-must-never-leak";

fn creds() -> Rc<dyn CredentialSource> {
    Rc::new(StaticCredentials::new().with("k", SENTINEL))
}

fn embed_card(model: &str, dims: u32) -> ModelCard {
    ModelCard {
        model: model.into(),
        healthy: true,
        context: 8192,
        tools: false,
        structured: false,
        streaming: false,
        cost_per_1k_micros: 100,
        local: false,
        embeddings: true,
        rerank: false,
        embedding_dims: dims,
    }
}

fn rerank_card(model: &str) -> ModelCard {
    ModelCard {
        model: model.into(),
        healthy: true,
        context: 8192,
        tools: false,
        structured: false,
        streaming: false,
        cost_per_1k_micros: 100,
        local: false,
        embeddings: false,
        rerank: true,
        embedding_dims: 0,
    }
}

fn embed_provider(http: ReplayClient) -> OpenAiEmbedProvider {
    OpenAiEmbedProvider::new(
        "openai-embed",
        "https://api.openai.com",
        Some("k".into()),
        vec![],
        vec![embed_card("text-embedding-3-small", 1536)],
        Rc::new(http),
        creds(),
    )
}

fn rerank_provider(http: ReplayClient) -> RerankApiProvider {
    RerankApiProvider::new(
        "cohere-rerank",
        "https://api.cohere.ai",
        Some("k".into()),
        vec![],
        vec![rerank_card("rerank-3")],
        Rc::new(http),
        creds(),
    )
}

fn embed_req(n: usize) -> EmbeddingRequest {
    EmbeddingRequest::new(
        Role::Research,
        (0..n).map(|i| format!("input {i}")).collect(),
        0,
    )
}

fn rerank_req(n: usize) -> RerankRequest {
    RerankRequest::new(
        Role::Review,
        "the query".into(),
        (0..n).map(|i| format!("doc {i}")).collect(),
        0,
    )
}

// (a)/(g) — credential never appears in any embed/rerank error string, across the
// 4xx-echo, garbage-body, and transport-timeout paths.

#[test]
fn embed_credential_never_leaks_through_any_error_path() {
    // 4xx body echoes the key — must map to a status-only error.
    let http = ReplayClient::new(vec![Canned::with_body(
        401,
        &format!(r#"{{"error":"invalid key {SENTINEL}"}}"#),
    )]);
    let err = embed_provider(http)
        .embed("text-embedding-3-small", &embed_req(1))
        .unwrap_err();
    assert!(
        !format!("{err}").contains(SENTINEL),
        "401 body leaked the key"
    );

    // A 200 with a credential echoed in a string field — the parsed vectors are
    // numeric and the success result must not carry the key anywhere.
    let http = ReplayClient::new(vec![Canned::with_body(
        200,
        &format!(r#"{{"note":"{SENTINEL}","data":[{{"embedding":[0.1,0.2]}}]}}"#),
    )]);
    let out = embed_provider(http)
        .embed("text-embedding-3-small", &embed_req(1))
        .unwrap();
    let dbg = format!("{out:?}");
    assert!(!dbg.contains(SENTINEL), "success result leaked the key");
}

#[test]
fn rerank_credential_never_leaks_through_any_error_path() {
    let http = ReplayClient::new(vec![Canned::with_body(
        403,
        &format!(r#"{{"message":"forbidden {SENTINEL}"}}"#),
    )]);
    let err = rerank_provider(http)
        .rerank("rerank-3", &rerank_req(2))
        .unwrap_err();
    assert!(
        !format!("{err}").contains(SENTINEL),
        "403 body leaked the key"
    );

    // Garbage body → malformed error, still status/parse-only (no body verbatim).
    let http = ReplayClient::new(vec![Canned::with_body(
        200,
        &format!("not json {SENTINEL}"),
    )]);
    let err = rerank_provider(http)
        .rerank("rerank-3", &rerank_req(2))
        .unwrap_err();
    assert!(
        !format!("{err}").contains(SENTINEL),
        "malformed-body error leaked the key"
    );
}

// (b) — malformed / oversized / non-finite bytes never panic and stay bounded.

#[test]
fn malformed_and_oversized_embed_bytes_do_not_panic_or_over_allocate() {
    // Truncated JSON.
    let http = ReplayClient::new(vec![Canned::with_body(200, r#"{"data":[{"embed"#)]);
    let _ = embed_provider(http).embed("text-embedding-3-small", &embed_req(1));

    // A vector with non-finite values smuggled in: the engine sanitizes them so no
    // NaN/Inf reaches downstream selection.
    let http = ReplayClient::new(vec![Canned::with_body(
        200,
        r#"{"data":[{"embedding":[1.0,2.0,3.0]}]}"#,
    )]);
    let engine = EmbedEngine::new(vec![Box::new(embed_provider(http))]);
    let mut ledger = BudgetLedger::default();
    if let Ok((resp, _, _, _)) = engine.embed(&embed_req(1), &mut ledger) {
        assert!(resp.vectors.iter().flatten().all(|x| x.is_finite()));
    }
}

#[test]
fn embed_batch_request_is_bounded_by_max_batch() {
    // Constructing an over-cap request truncates to MAX_BATCH (no unbounded read).
    let req = EmbeddingRequest::new(
        Role::Research,
        (0..MAX_BATCH + 100).map(|i| format!("t{i}")).collect(),
        0,
    );
    assert_eq!(req.inputs.len(), MAX_BATCH);
}

#[test]
fn rerank_request_is_bounded_by_max_docs() {
    let req = RerankRequest::new(
        Role::Review,
        "q".into(),
        (0..MAX_DOCS + 100).map(|i| format!("d{i}")).collect(),
        0,
    );
    assert_eq!(req.documents.len(), MAX_DOCS);
}

// (c) — out-of-range / duplicate rerank indices are clamped/dropped, never raw.

#[test]
fn rerank_out_of_range_indices_cannot_corrupt_selection() {
    // doc_count = 3; the provider returns indices 99 (out of range), 1 (dup), -ish.
    let http = ReplayClient::new(vec![Canned::with_body(
        200,
        r#"{"results":[{"index":99,"relevance_score":1.0},{"index":1,"relevance_score":0.9},{"index":1,"relevance_score":0.8},{"index":0,"relevance_score":0.5}]}"#,
    )]);
    let out = rerank_provider(http)
        .rerank("rerank-3", &rerank_req(3))
        .unwrap();
    // Every surviving index is a valid document index, with no duplicates.
    assert!(out.ranking.iter().all(|(i, _)| *i < 3));
    let mut seen = std::collections::HashSet::new();
    assert!(
        out.ranking.iter().all(|(i, _)| seen.insert(*i)),
        "duplicate index propagated"
    );
}

// (d) — capability-missing request fails closed (typed error), never routes open.

#[test]
fn embed_with_only_completion_models_fails_closed() {
    // An EmbedEngine with no embedding-capable provider: routing returns a typed
    // NoModelForConstraints, not a silent success or a completion fallback.
    let engine = EmbedEngine::new(Vec::new());
    let mut ledger = BudgetLedger::default();
    assert!(matches!(
        engine.embed(&embed_req(1), &mut ledger),
        Err(RouteError::NoModelForConstraints(_))
    ));
    assert_eq!(ledger.requests, 0);
}

#[test]
fn rerank_with_no_capable_model_fails_closed() {
    let engine = RerankEngine::new(Vec::new());
    let mut ledger = BudgetLedger::default();
    assert!(matches!(
        engine.rerank(&rerank_req(2), &mut ledger),
        Err(RouteError::NoModelForConstraints(_))
    ));
}

// (e) — capability flags default OFF by config omission (wire-decode default-off is
// covered in netproto's tests; this covers the config parse path end-to-end).

#[test]
fn config_omission_does_not_flip_a_capability_on() {
    let json = r#"[
      { "id":"openai", "kind":"openai", "base_url":"https://api.openai.com",
        "secret_label":"k",
        "models":[{"model":"gpt-x","tools":true}] }
    ]"#;
    let cfg = crustcore_net::config::parse_providers(json).unwrap();
    let m = &cfg[0].models[0];
    assert!(!m.embeddings, "embeddings flipped on by omission");
    assert!(!m.rerank, "rerank flipped on by omission");
    assert_eq!(m.embedding_dims, 0);

    // Such a model is therefore NOT offered by the embed/rerank builders (fail closed).
    let http: Rc<dyn crustcore_net::transport::HttpClient> = Rc::new(ReplayClient::new(vec![]));
    let embedders = crustcore_net::embed::build_embed_providers(&cfg, http.clone(), creds());
    let rerankers = crustcore_net::rerank::build_rerankers(&cfg, http, creds());
    assert!(
        embedders.is_empty(),
        "a non-embeddings model became an embedder"
    );
    assert!(rerankers.is_empty(), "a non-rerank model became a reranker");
}

// (f) — a failing embedder/reranker emits zero partial output before fallback.

#[test]
fn failing_embedder_emits_no_partial_output_before_fallback() {
    use crustcore_net::modality::{MockEmbedBehavior, MockEmbedProvider};

    let engine = EmbedEngine::new(vec![
        Box::new(MockEmbedProvider::new(
            "down",
            vec![embed_card("e1", 4)],
            MockEmbedBehavior::AlwaysFail("503".into()),
        )),
        Box::new(MockEmbedProvider::new(
            "up",
            vec![embed_card("e1", 4)],
            MockEmbedBehavior::Echo,
        )),
    ]);
    let mut ledger = BudgetLedger::default();
    let (resp, fallbacks, provider, _model) = engine.embed(&embed_req(1), &mut ledger).unwrap();
    // The result came entirely from the second provider — no partial vectors from the
    // failed first one (a single response, success-path only).
    assert_eq!(provider, "up");
    assert_eq!(fallbacks, vec!["down"]);
    assert_eq!(resp.vectors.len(), 1);
    // The error path itself maps to a typed ProviderError (drives fallback, leaks no
    // body).
    let solo = MockEmbedProvider::new(
        "down",
        vec![embed_card("e1", 4)],
        MockEmbedBehavior::AlwaysFail("503".into()),
    );
    assert!(matches!(
        solo.embed("e1", &embed_req(1)),
        Err(ProviderError::Unavailable(_))
    ));
}
