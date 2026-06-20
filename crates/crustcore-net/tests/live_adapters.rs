// SPDX-License-Identifier: Apache-2.0
//! Integration tests for the live provider adapters (P7-live), driven by a canned
//! `ReplayClient` — **no network**, so they run in CI. They prove two things the unit
//! tests cannot on their own: (1) the *Engine* routes and falls back across the
//! **real** adapters (not just mocks), so the engine is genuinely transport-agnostic;
//! and (2) a provider's credential cannot leak into any string the helper can emit
//! (the secret-leak red-team for the new model-transport surface).

use std::rc::Rc;

use crustcore_net::config::parse_providers;
use crustcore_net::credsource::{CredentialSource, StaticCredentials};
use crustcore_net::providers::build_providers;
use crustcore_net::transport::{Canned, HttpClient, ReplayClient};
use crustcore_net::Engine;
use crustcore_netproto::{CompleteRequest, Require, Role, MAX_TEXT_BYTES};
use crustcore_types::BoundedText;

fn req(prompt: &str) -> CompleteRequest {
    CompleteRequest {
        role: Role::Implementation,
        system: BoundedText::truncated("", MAX_TEXT_BYTES),
        prompt: BoundedText::truncated(prompt, MAX_TEXT_BYTES),
        max_tokens: 64,
        stream: true,
        max_cost_micros: 0,
        require: Require::default(),
    }
}

fn two_provider_config() -> String {
    // Two OpenAI-compatible providers, each one model, equal cost → registry order.
    r#"[
      { "id":"p1", "kind":"openai", "base_url":"https://a.example", "secret_label":"k",
        "models":[{"model":"m","context":128000,"tools":false,"streaming":true,"cost_per_1k_micros":1000}] },
      { "id":"p2", "kind":"openai", "base_url":"https://b.example", "secret_label":"k",
        "models":[{"model":"m","context":128000,"tools":false,"streaming":true,"cost_per_1k_micros":1000}] }
    ]"#
    .to_string()
}

#[test]
fn engine_falls_back_across_real_adapters() {
    // The shared transport replays: p1 gets a 429 (Unavailable), p2 succeeds.
    let http: Rc<dyn HttpClient> = Rc::new(ReplayClient::new(vec![
        Canned::with_body(429, "rate limited"),
        Canned::streaming(&[r#"data: {"choices":[{"delta":{"content":"recovered"}}]}"#]),
    ]));
    let creds: Rc<dyn CredentialSource> = Rc::new(StaticCredentials::new().with("k", "sk-x"));
    let configs = parse_providers(&two_provider_config()).unwrap();
    let mut engine = Engine::new(build_providers(&configs, http, creds));

    let mut streamed = String::new();
    let fin = engine
        .complete(&req("hi"), &mut |c| streamed.push_str(c))
        .unwrap();

    // Routed to p2 after p1 failed — fallback works across the REAL adapters.
    assert_eq!(fin.provider, "p2");
    assert_eq!(fin.fallbacks, vec!["p1".to_string()]);
    assert_eq!(fin.text.as_str(), "recovered");
    // The failed provider streamed nothing (no partial-output leak on fallback).
    assert_eq!(streamed, "recovered");
    // Accounting recorded the fallback.
    assert_eq!(engine.ledger().fallbacks, 1);
}

/// Red-team (P7-live, model-transport surface): a provider's credential must never
/// surface in any model-visible or log-visible string the helper can emit — not in
/// the completion text, and not in a `ProviderError` even when the provider's own
/// error body echoes the key back. The adapter maps errors to a **status-only**
/// reason and never inlines the provider body, so the sentinel stays contained.
#[test]
fn provider_credential_never_leaks_into_output_or_errors() {
    let sentinel = "sk-LEAKCANARY-7f3a";

    // Success path: the key authenticates the request but never appears in the text.
    let http: Rc<dyn HttpClient> = Rc::new(ReplayClient::new(vec![Canned::streaming(&[
        r#"data: {"choices":[{"delta":{"content":"all good"}}]}"#,
    ])]));
    let creds: Rc<dyn CredentialSource> = Rc::new(StaticCredentials::new().with("k", sentinel));
    let configs = parse_providers(
        r#"[{ "id":"p","kind":"openai","base_url":"https://x.example","secret_label":"k",
              "models":[{"model":"m","context":8000,"streaming":true}] }]"#,
    )
    .unwrap();
    let mut engine = Engine::new(build_providers(&configs, http, creds.clone()));
    let fin = engine.complete(&req("hi"), &mut |_| {}).unwrap();
    assert!(!fin.text.as_str().contains(sentinel));
    assert!(!fin.provider.contains(sentinel));

    // Error path: a 401 whose body echoes the key must not surface it in the routed
    // error reason (the engine returns AllProvidersFailed with the mapped reason).
    let http: Rc<dyn HttpClient> = Rc::new(ReplayClient::new(vec![Canned::with_body(
        401,
        &format!(r#"{{"error":"invalid api key {sentinel}"}}"#),
    )]));
    let mut engine = Engine::new(build_providers(&configs, http, creds));
    let routed = engine.complete(&req("hi"), &mut |_| {});
    let reason = match routed {
        Ok(_) => panic!("a 401 must not succeed"),
        Err(e) => e.reason(),
    };
    assert!(
        !reason.contains(sentinel),
        "the credential leaked into the routed error reason: {reason}"
    );
    assert!(!reason.contains("LEAKCANARY"));
}

/// A documented, `#[ignore]`d live integration test — it hits a real provider and is
/// the **only** part of P7-live that needs network + a real key, so it never runs in
/// CI. Run it out-of-band with a `live`-built helper and an operator-supplied key:
/// `CRUSTCORE_NET_LIVE_KEY=sk-... cargo test -p crustcore-net --features live --ignored live_smoke`.
#[test]
#[ignore = "live: needs --features live + a real provider key (network); run manually"]
fn live_smoke() {
    // Intentionally minimal: documents the run recipe. The live transport (UreqClient)
    // only compiles under `--features live`; a real assertion would build a live_engine
    // from a config pointing at a real endpoint and assert a non-empty completion plus
    // a runtime check that the key never appears in the helper's stdout/stderr.
}
