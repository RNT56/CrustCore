// SPDX-License-Identifier: Apache-2.0
//! Red-team fixture (`C7.7`): proves the dev UI ergonomic layer cannot become a back
//! door. Each test maps to one of the adversarial-review dimensions (a)–(g) from
//! `docs/roadmap-v0.2.md` §C7. The whole fixture runs over `MockDevBackend` — no
//! axum/net/secrets — so it is deterministic and part of every PR.
//!
//! (a) Bind/exposure  — no off-loopback default; `0.0.0.0` never silent.
//! (b) Auth           — required on EVERY route (assets/ws included); token absent from responses.
//! (c) Read-only      — a read view never reaches a mutating method / verifier / VerifiedPatch.
//! (d) Approval bypass— UI cannot self-mint `Approved<T>` or approve a different operation.
//! (e) Secret leak    — no handler emits a secret-bearing value (redactor on every render).
//! (f) Untrusted input— headers/queries/bodies bounded + validated; unknown verbs rejected.
//! (g) Second channel — no free-text path to the model or user.

use crustcore_dev::backend::{DevBackend, MockDevBackend, ModelCardView, ReadOnlyBackend};
use crustcore_dev::config::{ConfigError, DevConfig, LOOPBACK};
use crustcore_dev::request::{DevRequest, RequestError, Status};
use crustcore_dev::route_class::{RouteClass, ROUTES};
use crustcore_dev::{route, Authenticator, BearerToken};
use crustcore_eventlog::{EventLog, FrameMeta, RedactionState};
use crustcore_kernel::event::EventKind;
use crustcore_kernel::Visibility;
use crustcore_secrets::Redactor;
use crustcore_types::{TaskId, Timestamp};

use std::net::{IpAddr, Ipv4Addr};

const SENTINEL: &str = "sk-DEADBEEF-TOPSECRET-CANARY";

fn token() -> BearerToken {
    BearerToken::from_bytes([42u8; crustcore_dev::auth::TOKEN_BYTES])
}

fn bearer_header() -> Vec<(String, String)> {
    vec![(
        "Authorization".to_string(),
        format!("Bearer {}", token().reveal_once()),
    )]
}

fn get(path: &str, headers: Vec<(String, String)>) -> DevRequest {
    DevRequest::new("GET", path, headers, [], Vec::new()).unwrap()
}

/// A backend seeded with a sentinel secret in the redactor and a redacted log frame, so
/// the leak tests have something to catch.
fn seeded_backend() -> MockDevBackend {
    let mut redactor = Redactor::new();
    redactor.register("canary", SENTINEL.as_bytes());

    let mut log = EventLog::new();
    log.append(
        &FrameMeta::new(1, EventKind::TaskCreated).task(TaskId(1)),
        b"created",
    );
    // A secret-bearing, redacted, model-visible frame — must never have its payload shown.
    log.append(
        &FrameMeta::new(2, EventKind::ModelOutputReceived)
            .task(TaskId(1))
            .visibility(Visibility::ModelVisible)
            .redaction(RedactionState::Redacted),
        SENTINEL.as_bytes(),
    );

    let cards = vec![ModelCardView {
        // Even if a credential ever leaked into a card field, the redactor scrubs it.
        provider: format!("provider-{SENTINEL}"),
        model: "model-x".to_string(),
        healthy: true,
        context: 100_000,
        tools: true,
        cost_per_1k_micros: 1_000,
    }];

    MockDevBackend::new()
        .with_log(log)
        .with_redactor(redactor)
        .with_provider_cards(cards)
}

// ---------------------------------------------------------------------------
// SPA serving (C7-devui) — `/` and `/assets` serve the real embedded inspector,
// the route table is unchanged (exactly 9 read + 1 mutating), and the SPA routes
// keep the same auth/read posture as every other route.
// ---------------------------------------------------------------------------

#[test]
fn root_serves_the_spa_with_title_marker() {
    let auth = Authenticator::new(token());
    let cfg = DevConfig::default();
    let mut backend = seeded_backend();
    let resp = route(&mut backend, &auth, &cfg, &get("/", bearer_header()));
    assert_eq!(resp.status, Status::Ok);
    assert!(resp.body.contains("<title>CrustCore Inspector</title>"));
    assert!(resp.body.contains("<!DOCTYPE html>"));
    assert_ne!(resp.body, "ok", "the `/` placeholder must be replaced");
}

#[test]
fn assets_serves_the_stylesheet_bytes() {
    let auth = Authenticator::new(token());
    let cfg = DevConfig::default();
    let mut backend = seeded_backend();
    let resp = route(&mut backend, &auth, &cfg, &get("/assets", bearer_header()));
    assert_eq!(resp.status, Status::Ok);
    assert_eq!(resp.body, crustcore_dev::INSPECTOR_CSS);
}

#[test]
fn route_table_is_unchanged_ten_read_and_one_mutating() {
    // The SPA reuses the existing read routes; it adds none. The table stays exactly the
    // ten read GET routes (`/`, `/assets`, `/ws`, `/inspector`, `/replay`, `/provider`,
    // `/mcp`, `/flow`, `/sessions`, `/approvals`) plus the single mutating POST.
    let read = ROUTES
        .iter()
        .filter(|r| r.class == RouteClass::ReadOnly)
        .count();
    let mutating = ROUTES
        .iter()
        .filter(|r| r.class == RouteClass::Mutating)
        .count();
    assert_eq!(read, 10, "exactly ten read routes");
    assert_eq!(mutating, 1, "exactly one mutating route");
    assert_eq!(ROUTES.len(), 11);
}

// ---------------------------------------------------------------------------
// (a) Bind / exposure
// ---------------------------------------------------------------------------

#[test]
fn a_default_bind_is_loopback() {
    let cfg = DevConfig::default();
    assert!(cfg.host().is_loopback());
    assert_eq!(cfg.host(), LOOPBACK);
    assert!(!cfg.is_off_loopback());
    assert!(cfg.exposure_warning().is_none());
}

#[test]
fn a_wildcard_bind_is_never_a_silent_default() {
    let wildcard = IpAddr::V4(Ipv4Addr::UNSPECIFIED); // 0.0.0.0
                                                      // Off-loopback without explicit acknowledgement fails closed.
    assert_eq!(
        DevConfig::default().bind_host(wildcard, false).unwrap_err(),
        ConfigError::OffLoopbackNotAcknowledged(wildcard)
    );
    // With acknowledgement it is allowed BUT loudly warned (never silent).
    let cfg = DevConfig::default().bind_host(wildcard, true).unwrap();
    assert!(cfg.is_off_loopback());
    assert!(cfg.exposure_warning().is_some());
}

#[test]
fn a_non_loopback_peer_is_rejected_even_with_a_valid_token() {
    let auth = Authenticator::new(token());
    let cfg = DevConfig::default();
    let mut backend = seeded_backend();
    // A valid token, but the peer is not loopback.
    let req = get("/inspector", bearer_header()).with_peer_loopback(false);
    let resp = route(&mut backend, &auth, &cfg, &req);
    assert_eq!(resp.status, Status::Forbidden);
}

// ---------------------------------------------------------------------------
// (b) Auth on every route
// ---------------------------------------------------------------------------

#[test]
fn b_every_route_requires_auth_including_assets_and_ws() {
    let auth = Authenticator::new(token());
    let cfg = DevConfig::default();
    for spec in ROUTES {
        let mut backend = seeded_backend();
        // No Authorization header at all.
        let body = if spec.class == RouteClass::Mutating {
            b"approval_id=1&decision=approve&op_hash=".to_vec()
        } else {
            Vec::new()
        };
        let verb = match spec.method {
            crustcore_dev::request::Method::Get => "GET",
            crustcore_dev::request::Method::Post => "POST",
        };
        let req = DevRequest::new(verb, spec.path, [], [], body).unwrap();
        let resp = route(&mut backend, &auth, &cfg, &req);
        assert_eq!(
            resp.status,
            Status::Unauthorized,
            "route {} ({:?}) must require auth",
            spec.path,
            spec.method
        );
    }
}

#[test]
fn b_bad_token_is_unauthorized_on_every_route() {
    let auth = Authenticator::new(token());
    let cfg = DevConfig::default();
    let wrong = BearerToken::from_bytes([0u8; crustcore_dev::auth::TOKEN_BYTES]);
    let bad = vec![(
        "Authorization".to_string(),
        format!("Bearer {}", wrong.reveal_once()),
    )];
    for spec in ROUTES.iter().filter(|r| r.class == RouteClass::ReadOnly) {
        let mut backend = seeded_backend();
        let resp = route(&mut backend, &auth, &cfg, &get(spec.path, bad.clone()));
        assert_eq!(resp.status, Status::Unauthorized, "route {}", spec.path);
    }
}

#[test]
fn b_token_never_appears_in_any_response_body() {
    let auth = Authenticator::new(token());
    let cfg = DevConfig::default();
    let revealed = token().reveal_once();
    for spec in ROUTES.iter().filter(|r| r.class == RouteClass::ReadOnly) {
        let mut backend = seeded_backend();
        let resp = route(&mut backend, &auth, &cfg, &get(spec.path, bearer_header()));
        assert!(
            !resp.body.contains(&revealed),
            "token leaked into response for {}",
            spec.path
        );
    }
}

// ---------------------------------------------------------------------------
// (c) Read-only / verifier integrity
// ---------------------------------------------------------------------------

#[test]
fn c_read_routes_perform_no_side_effect_on_the_log() {
    let auth = Authenticator::new(token());
    let cfg = DevConfig::default();
    let mut backend = seeded_backend();
    let before = backend.log().bytes().to_vec();
    let before_head = backend.log().head_hash();

    for spec in ROUTES.iter().filter(|r| r.class == RouteClass::ReadOnly) {
        let _ = route(&mut backend, &auth, &cfg, &get(spec.path, bearer_header()));
    }

    // No read view mutated the log (no append, no mint, no write).
    assert_eq!(backend.log().bytes(), before.as_slice());
    assert_eq!(backend.log().head_hash(), before_head);
}

#[test]
fn c_flow_simulation_never_completes_or_mints_a_verified_patch() {
    use crustcore_flow::builder::FlowBuilder;
    let mut b = FlowBuilder::new();
    let model = b.reserve();
    let verify = b.reserve();
    let end = b.reserve();
    b.entry(model)
        .model(model, "p", "out", verify)
        .verify(verify, end)
        .end(end);
    let flow = b.build().unwrap();

    let backend = MockDevBackend::new().with_flow(flow);
    let ro: &dyn ReadOnlyBackend = backend.read_only();

    // Stepping every node: none reports a completed/VerifiedPatch outcome. `finished` is
    // reached only structurally (verify/end), and the FlowStepView carries NO patch — it
    // structurally cannot (there is no Completed variant in the view).
    for node in 0..3u32 {
        if let Some(step) = ro.flow_step(node) {
            // The verify step explicitly states it mints no VerifiedPatch.
            if step.kind == "verify" {
                assert!(step.note.contains("mints no VerifiedPatch"));
            }
        }
    }
    // The graph rendering is inert: nodes/edges only.
    let g = ro.flow_graph();
    assert_eq!(g.nodes.len(), 3);
}

#[test]
fn c_a_read_route_cannot_reach_a_mutating_method_type_level() {
    // STRUCTURAL: a ReadOnlyBackend trait object exposes only read methods. There is no
    // method on `&dyn ReadOnlyBackend` that returns a MutatingBackend. The following lines
    // compile (reads); a `.dispatch_resolution(..)` call on `ro` would NOT compile — the
    // type system, not a runtime guard, forbids it (dimension (c)).
    let backend = seeded_backend();
    let ro: &dyn ReadOnlyBackend = backend.read_only();
    let _ = ro.run_inspector();
    let _ = ro.replay();
    let _ = ro.provider_cards();
    let _ = ro.mcp_servers();
    let _ = ro.sessions();
    let _ = ro.pending_approvals();
    // ro.dispatch_resolution(..) // <- would be a compile error: no such method.
}

// ---------------------------------------------------------------------------
// (d) Approval bypass
// ---------------------------------------------------------------------------

#[test]
fn d_mutating_route_is_off_by_default() {
    let auth = Authenticator::new(token());
    let cfg = DevConfig::default(); // mutation disabled
    let mut backend = seeded_backend().with_allowlisted_chat(123);
    let op_hash = backend.request_approval(5, "op", "summary", Timestamp::from_millis(10_000));
    let body = format!("approval_id=5&decision=approve&op_hash={op_hash}");
    let req = DevRequest::new(
        "POST",
        "/approvals/resolve",
        bearer_header(),
        [],
        body.into_bytes(),
    )
    .unwrap();
    let resp = route(&mut backend, &auth, &cfg, &req);
    assert_eq!(resp.status, Status::Forbidden);
    assert!(resp.body.contains("disabled"));
}

#[test]
fn d_cannot_approve_a_different_operation_than_shown() {
    let auth = Authenticator::new(token());
    let cfg = DevConfig::default().enable_mutation();
    let mut backend = seeded_backend()
        .with_allowlisted_chat(123)
        .at_time(Timestamp::from_millis(0));
    let _shown = backend.request_approval(5, "op-A", "Operation A", Timestamp::from_millis(10_000));
    // A different op-hash than the surfaced operation.
    let wrong = "ab".repeat(32);
    let body = format!("approval_id=5&decision=approve&op_hash={wrong}");
    let req = DevRequest::new(
        "POST",
        "/approvals/resolve",
        bearer_header(),
        [],
        body.into_bytes(),
    )
    .unwrap();
    let resp = route(&mut backend, &auth, &cfg, &req);
    // Operation-bound: the engine rejects the mismatch; nothing is approved.
    assert_eq!(resp.status, Status::Conflict);
    assert!(resp.body.contains("operation mismatch"));
}

#[test]
fn d_non_allowlisted_identity_cannot_resolve() {
    let auth = Authenticator::new(token());
    let cfg = DevConfig::default().enable_mutation();
    // Deny-all allowlist (the default): no chat is an AuthorizedUser, so no Approved<T>.
    let mut backend = seeded_backend().at_time(Timestamp::from_millis(0));
    let op_hash = backend.request_approval(5, "op", "summary", Timestamp::from_millis(10_000));
    let body = format!("approval_id=5&decision=approve&op_hash={op_hash}");
    let req = DevRequest::new(
        "POST",
        "/approvals/resolve",
        bearer_header(),
        [],
        body.into_bytes(),
    )
    .unwrap();
    let resp = route(&mut backend, &auth, &cfg, &req);
    assert_eq!(resp.status, Status::Conflict);
    assert!(resp.body.contains("not allowlisted"));
}

// ---------------------------------------------------------------------------
// (e) Secret leak
// ---------------------------------------------------------------------------

#[test]
fn e_no_handler_emits_the_sentinel_secret() {
    let auth = Authenticator::new(token());
    let cfg = DevConfig::default();
    for spec in ROUTES.iter().filter(|r| r.class == RouteClass::ReadOnly) {
        let mut backend = seeded_backend();
        let resp = route(&mut backend, &auth, &cfg, &get(spec.path, bearer_header()));
        assert!(
            !resp.body.contains(SENTINEL),
            "sentinel secret leaked via {}",
            spec.path
        );
    }
}

#[test]
fn e_redacted_frame_payload_is_never_inlined_in_replay() {
    let backend = seeded_backend();
    let view = backend.read_only().replay();
    // The replay view exposes per-frame metadata (redacted flag) but never the bytes.
    let redacted_row = view
        .rows
        .iter()
        .find(|r| r.redacted)
        .expect("a redacted row");
    assert!(redacted_row.model_visible);
    // The rendered debug of the whole view contains no sentinel.
    assert!(!format!("{view:?}").contains(SENTINEL));
}

// ---------------------------------------------------------------------------
// (f) Untrusted input
// ---------------------------------------------------------------------------

#[test]
fn f_unknown_verbs_are_rejected() {
    for verb in ["PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT"] {
        assert_eq!(
            DevRequest::new(verb, "/", [], [], Vec::new()).unwrap_err(),
            RequestError::UnknownVerb
        );
    }
}

#[test]
fn f_oversized_untrusted_fields_are_rejected_at_the_door() {
    use crustcore_dev::request::{MAX_BODY_BYTES, MAX_HEADER_BYTES, MAX_PATH_BYTES};
    assert!(matches!(
        DevRequest::new("GET", "x".repeat(MAX_PATH_BYTES + 1), [], [], Vec::new()),
        Err(RequestError::PathTooLong)
    ));
    assert!(matches!(
        DevRequest::new(
            "GET",
            "/",
            [("k".to_string(), "v".repeat(MAX_HEADER_BYTES + 1))],
            [],
            Vec::new()
        ),
        Err(RequestError::HeaderTooLarge)
    ));
    assert!(matches!(
        DevRequest::new("GET", "/", [], [], vec![0u8; MAX_BODY_BYTES + 1]),
        Err(RequestError::BodyTooLarge)
    ));
}

#[test]
fn f_malformed_resolution_body_is_rejected() {
    let auth = Authenticator::new(token());
    let cfg = DevConfig::default().enable_mutation();
    let mut backend = seeded_backend().with_allowlisted_chat(123);
    // Garbage body: no valid op-bound resolution.
    let req = DevRequest::new(
        "POST",
        "/approvals/resolve",
        bearer_header(),
        [],
        b"garbage=1".to_vec(),
    )
    .unwrap();
    let resp = route(&mut backend, &auth, &cfg, &req);
    assert_eq!(resp.status, Status::BadRequest);
}

// ---------------------------------------------------------------------------
// (g) Second-chat-channel drift
// ---------------------------------------------------------------------------

#[test]
fn g_no_free_text_path_to_model_or_user() {
    // STRUCTURAL: the read-only surface offers only typed views — there is no
    // `send_to_model(text)` / `send_to_user(text)` method anywhere. The only POST route is
    // the typed approval resolution (op-bound), not free text routed to a model/user. We
    // assert the route table contains no chat/message/send-style route.
    for spec in ROUTES {
        let p = spec.path;
        assert!(
            !p.contains("chat")
                && !p.contains("message")
                && !p.contains("send")
                && !p.contains("prompt"),
            "route {p} looks like a chat channel — invariants 15/16"
        );
    }
    // And the one mutating route is exactly the typed approval resolution.
    let mutating: Vec<_> = ROUTES
        .iter()
        .filter(|r| r.class == RouteClass::Mutating)
        .collect();
    assert_eq!(mutating.len(), 1);
    assert_eq!(mutating[0].path, "/approvals/resolve");
}
