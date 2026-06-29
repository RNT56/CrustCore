// SPDX-License-Identifier: Apache-2.0
//! The approval/mutation gate + the request router (`C7.6`, dimensions (c)/(d)).
//!
//! The *only* UI-triggerable irreversible action is forwarding a normal
//! `/approve`-equivalent resolution. It goes through the **identical typed approval path**
//! as Telegram/CLI: the UI surfaces an [`ApprovalView`](crate::backend::ApprovalView) and
//! dispatches the resolution to the supervisor's existing
//! [`ApprovalEngine`](crustcore_daemon::telegram::ApprovalEngine), where
//! `AuthorizedUser::approve` is the sole `Approved<T>` minter. The UI **cannot** mint an
//! `Approved<T>` itself, and a resolution is *operation-bound* (op-hash) so it cannot
//! approve a different operation than the one shown.
//!
//! Mutating routes are unreachable unless:
//!   1. the launch flag [`DevConfig::enable_mutation`](crate::config::DevConfig::enable_mutation)
//!      unlocks the route class, **and**
//!   2. the request presents a valid operation-bound token (approval id + op-hash).
//!
//! The [`route`] function is the single dispatch chokepoint: it applies auth at the root
//! (every route), enforces loopback, classifies the route, and routes a read to the
//! read-only backend (which has no mutating method) or a mutation through this gate.

use crate::auth::{AuthOutcome, Authenticator};
use crate::backend::{DevBackend, DispatchResult, ReadOnlyBackend};
use crate::config::DevConfig;
use crate::request::{DevRequest, DevResponse, Method, Status};
use crate::route_class::{lookup, RouteClass};

/// Why a mutation was refused before reaching the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MutationError {
    /// Mutating routes are not unlocked (the launch flag is off — the default).
    MutationDisabled,
    /// The request body did not parse into a valid operation-bound resolution.
    MalformedResolution,
    /// The presented op-hash was not a 64-char hex string (cannot bind to an operation).
    BadOpHash,
}

impl core::fmt::Display for MutationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            MutationError::MutationDisabled => "mutating routes are disabled",
            MutationError::MalformedResolution => "malformed approval resolution",
            MutationError::BadOpHash => "operation hash missing or malformed",
        };
        f.write_str(s)
    }
}

impl std::error::Error for MutationError {}

/// A parsed, operation-bound approval resolution from the UI. The op-hash binds the
/// resolution to the *specific* operation surfaced (the engine rejects a mismatch), so it
/// can never approve a different operation than the one shown (dimension (d)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalDispatch {
    /// The approval id being resolved.
    pub approval_id: u128,
    /// Approve (`true`) or deny (`false`).
    pub approve: bool,
    /// The op-hash (hex) the resolution is bound to.
    pub op_hash_hex: String,
}

impl ApprovalDispatch {
    /// Parse a bounded control body of the form `approval_id=<u128>&decision=<approve|deny>&op_hash=<hex>`.
    /// Untrusted input: every field is validated; malformed input is rejected (invariant 7).
    pub fn parse(body: &[u8]) -> Result<ApprovalDispatch, MutationError> {
        let text = std::str::from_utf8(body).map_err(|_| MutationError::MalformedResolution)?;
        let mut approval_id: Option<u128> = None;
        let mut approve: Option<bool> = None;
        let mut op_hash_hex: Option<String> = None;

        for pair in text.split('&') {
            let Some((k, v)) = pair.split_once('=') else {
                continue;
            };
            match k {
                "approval_id" => approval_id = v.parse::<u128>().ok(),
                "decision" => {
                    approve = match v {
                        "approve" => Some(true),
                        "deny" => Some(false),
                        _ => None,
                    }
                }
                // Bound: a 64-char hex string (32 bytes). Reject anything else.
                "op_hash" if v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()) => {
                    op_hash_hex = Some(v.to_ascii_lowercase());
                }
                _ => {}
            }
        }

        let approval_id = approval_id.ok_or(MutationError::MalformedResolution)?;
        let approve = approve.ok_or(MutationError::MalformedResolution)?;
        let op_hash_hex = op_hash_hex.ok_or(MutationError::BadOpHash)?;
        Ok(ApprovalDispatch {
            approval_id,
            approve,
            op_hash_hex,
        })
    }
}

/// The mutation gate: enforces the launch flag, then forwards an operation-bound
/// resolution into the backend's mutating surface (which dispatches into the real
/// approval engine). It never constructs an `Approved<T>`.
pub struct MutationGate<'cfg> {
    config: &'cfg DevConfig,
}

impl<'cfg> MutationGate<'cfg> {
    /// A gate bound to the launch config.
    #[must_use]
    pub fn new(config: &'cfg DevConfig) -> Self {
        MutationGate { config }
    }

    /// Dispatch a parsed resolution. Refuses with [`MutationError::MutationDisabled`] when
    /// the launch flag is off (the default). When unlocked, forwards to the mutating
    /// backend, which performs the genuine operation-bound resolution. The op-hash binds
    /// the resolution; the engine rejects a mismatch.
    pub fn dispatch<B: DevBackend>(
        &self,
        backend: &mut B,
        dispatch: &ApprovalDispatch,
    ) -> Result<DispatchResult, MutationError> {
        if !self.config.mutation_enabled() {
            return Err(MutationError::MutationDisabled);
        }
        Ok(backend.mutating().dispatch_resolution(
            dispatch.approval_id,
            dispatch.approve,
            &dispatch.op_hash_hex,
        ))
    }
}

/// The single request-dispatch chokepoint. Applies, in order:
///   1. **Auth on every route** (dimension (b)) — bearer token required first.
///   2. **Loopback** (dimension (a)) — a non-loopback peer is rejected.
///   3. **Route classification** — unknown route -> 404.
///   4. **Read vs mutate** (dimension (c)) — a read route is served from the
///      *read-only* backend (no mutating method reachable); the one mutating route goes
///      through [`MutationGate`] (launch flag + operation-bound token).
///
/// Returns a [`DevResponse`] with an already-redacted, bounded body.
pub fn route<B: DevBackend>(
    backend: &mut B,
    auth: &Authenticator,
    config: &DevConfig,
    req: &DevRequest,
) -> DevResponse {
    // 1. Auth FIRST — before any handler, for every route class (assets/ws included).
    match auth.authenticate(req) {
        AuthOutcome::Authorized => {}
        AuthOutcome::MissingToken | AuthOutcome::BadToken => {
            return DevResponse::error(Status::Unauthorized, "unauthorized");
        }
    }

    // 2. Loopback — a non-loopback peer is rejected even with a valid token.
    if !req.peer_is_loopback() {
        return DevResponse::error(Status::Forbidden, "non-loopback peer rejected");
    }

    // 3. Classify.
    let Some(spec) = lookup(req.method(), req.path()) else {
        return DevResponse::error(Status::NotFound, "no such route");
    };

    match spec.class {
        RouteClass::ReadOnly => handle_read(backend.read_only(), req),
        RouteClass::Mutating => handle_mutate(backend, config, req),
    }
}

/// Dispatch a read request to the appropriate read-only view handler. The handler is
/// handed `&dyn ReadOnlyBackend` — it cannot reach a mutating method (dimension (c)).
fn handle_read(backend: &dyn ReadOnlyBackend, req: &DevRequest) -> DevResponse {
    let body = match req.path() {
        // The single-page inspector: the page itself at `/` and its stylesheet at
        // `/assets`, both embedded (dependency-free) and served through this same read
        // mechanism — auth + loopback still apply, no posture change. The `serve` layer
        // tags `/` as `text/html` and `/assets` as `text/css`.
        "/" => crate::assets::INSPECTOR_HTML.to_string(),
        "/assets" => crate::assets::INSPECTOR_CSS.to_string(),
        "/ws" => {
            // Read route, authenticated like every other. Live snapshot streaming over a
            // websocket is not yet wired; the SPA polls the typed read endpoints instead.
            // Real streaming is `TODO(C7-serve-live)` and drops in behind this same route.
            "{\"streaming\":false,\"note\":\"websocket snapshot streaming not yet wired; \
             poll the read endpoints\"}"
                .to_string()
        }
        "/inspector" => format!("{:?}", backend.run_inspector()),
        "/replay" => format!("{:?}", backend.replay()),
        "/provider" => format!("{:?}", backend.provider_cards()),
        "/mcp" => format!("{:?}", backend.mcp_servers()),
        "/flow" => format!("{:?}", backend.flow_graph()),
        "/sessions" => format!("{:?}", backend.sessions()),
        "/approvals" => format!("{:?}", crate::views::approvals::render(backend)),
        "/cockpit" => format!("{:?}", crate::views::cockpit::build_cockpit(backend)),
        _ => return DevResponse::error(Status::NotFound, "no such read view"),
    };
    DevResponse::ok(body)
}

/// Dispatch the single mutating route. Launch flag + operation-bound token enforced.
fn handle_mutate<B: DevBackend>(
    backend: &mut B,
    config: &DevConfig,
    req: &DevRequest,
) -> DevResponse {
    // The mutating route is only `/approvals/resolve` (POST).
    if req.method() != Method::Post || req.path() != "/approvals/resolve" {
        return DevResponse::error(Status::NotFound, "no such mutating route");
    }

    let dispatch = match ApprovalDispatch::parse(req.body()) {
        Ok(d) => d,
        Err(MutationError::BadOpHash) => {
            return DevResponse::error(Status::BadRequest, "operation hash missing/malformed")
        }
        Err(_) => return DevResponse::error(Status::BadRequest, "malformed resolution"),
    };

    let gate = MutationGate::new(config);
    match gate.dispatch(backend, &dispatch) {
        Err(MutationError::MutationDisabled) => {
            DevResponse::error(Status::Forbidden, "mutating routes are disabled")
        }
        Err(e) => DevResponse::error(Status::BadRequest, e.to_string()),
        Ok(DispatchResult::Approved { approval_id }) => {
            DevResponse::ok(format!("approved:{approval_id}"))
        }
        Ok(DispatchResult::Denied { approval_id }) => {
            DevResponse::ok(format!("denied:{approval_id}"))
        }
        Ok(DispatchResult::Rejected { reason }) => DevResponse::error(Status::Conflict, reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{BearerToken, TOKEN_BYTES};
    use crate::backend::MockDevBackend;
    use crustcore_types::Timestamp;

    fn token() -> BearerToken {
        BearerToken::from_bytes([3u8; TOKEN_BYTES])
    }

    fn authed(method: &str, path: &str, body: Vec<u8>) -> DevRequest {
        let bearer = format!("Bearer {}", token().reveal_once());
        DevRequest::new(
            method,
            path,
            [("Authorization".to_string(), bearer)],
            [],
            body,
        )
        .unwrap()
    }

    #[test]
    fn root_serves_the_spa_html() {
        let config = DevConfig::default();
        let auth = Authenticator::new(token());
        let mut mock = MockDevBackend::new();
        let resp = route(&mut mock, &auth, &config, &authed("GET", "/", Vec::new()));
        assert_eq!(resp.status, Status::Ok);
        // The real SPA, not the old "ok" placeholder.
        assert!(resp.body.contains("<title>CrustCore Inspector</title>"));
        assert!(resp.body.contains("<!DOCTYPE html>"));
        assert_ne!(resp.body, "ok");
    }

    #[test]
    fn assets_serves_the_stylesheet() {
        let config = DevConfig::default();
        let auth = Authenticator::new(token());
        let mut mock = MockDevBackend::new();
        let resp = route(
            &mut mock,
            &auth,
            &config,
            &authed("GET", "/assets", Vec::new()),
        );
        assert_eq!(resp.status, Status::Ok);
        assert_eq!(resp.body, crate::assets::INSPECTOR_CSS);
        assert!(resp.body.contains("CrustCore dev UI styles"));
    }

    #[test]
    fn cockpit_route_renders_a_bounded_read_only_frame() {
        // E.1 serve route: an authed GET /cockpit is classified ReadOnly and renders the
        // cockpit frame from the read-model — no mutation, no minting.
        let config = DevConfig::default(); // mutation OFF by default
        let auth = Authenticator::new(token());
        let mut mock = MockDevBackend::new();
        let resp = route(
            &mut mock,
            &auth,
            &config,
            &authed("GET", "/cockpit", Vec::new()),
        );
        assert_eq!(resp.status, Status::Ok);
        assert!(resp.body.contains("CockpitView"), "got: {}", resp.body);
        assert!(resp.body.contains("chain_intact"));
    }

    #[test]
    fn cockpit_route_rejects_a_post_as_not_a_mutating_route() {
        // The cockpit is read-only: a POST to it is not the one mutating route.
        let config = DevConfig::default();
        let auth = Authenticator::new(token());
        let mut mock = MockDevBackend::new();
        let resp = route(
            &mut mock,
            &auth,
            &config,
            &authed("POST", "/cockpit", Vec::new()),
        );
        assert_eq!(resp.status, Status::NotFound);
    }

    #[test]
    fn ws_is_a_documented_non_streaming_read_route() {
        let config = DevConfig::default();
        let auth = Authenticator::new(token());
        let mut mock = MockDevBackend::new();
        let resp = route(&mut mock, &auth, &config, &authed("GET", "/ws", Vec::new()));
        assert_eq!(resp.status, Status::Ok);
        assert!(resp.body.contains("streaming"));
        // No secret/token leak; it is a static, harmless note.
        assert_ne!(resp.body, "ok");
    }

    #[test]
    fn spa_routes_still_require_auth() {
        let config = DevConfig::default();
        let auth = Authenticator::new(token());
        let mut mock = MockDevBackend::new();
        for path in ["/", "/assets", "/ws"] {
            // No Authorization header => unauthorized, exactly like every other route.
            let req = DevRequest::new("GET", path, [], [], Vec::new()).unwrap();
            let resp = route(&mut mock, &auth, &config, &req);
            assert_eq!(resp.status, Status::Unauthorized, "path {path}");
        }
    }

    #[test]
    fn parses_a_valid_resolution() {
        let body = format!("approval_id=7&decision=approve&op_hash={}", "ab".repeat(32));
        let d = ApprovalDispatch::parse(body.as_bytes()).unwrap();
        assert_eq!(d.approval_id, 7);
        assert!(d.approve);
        assert_eq!(d.op_hash_hex.len(), 64);
    }

    #[test]
    fn rejects_malformed_or_short_op_hash() {
        assert_eq!(
            ApprovalDispatch::parse(b"approval_id=1&decision=approve&op_hash=abcd").unwrap_err(),
            MutationError::BadOpHash
        );
        assert_eq!(
            ApprovalDispatch::parse(b"approval_id=1&decision=maybe").unwrap_err(),
            MutationError::MalformedResolution
        );
    }

    #[test]
    fn mutating_route_refused_without_launch_flag() {
        // Default config: mutation disabled.
        let config = DevConfig::default();
        let auth = Authenticator::new(token());
        let mut mock = MockDevBackend::new().with_allowlisted_chat(123);
        let op_hash =
            mock.request_approval(7, "op-A", "Operation A", Timestamp::from_millis(10_000));
        let body = format!("approval_id=7&decision=approve&op_hash={op_hash}");
        let resp = route(
            &mut mock,
            &auth,
            &config,
            &authed("POST", "/approvals/resolve", body.into_bytes()),
        );
        assert_eq!(resp.status, Status::Forbidden);
        assert!(resp.body.contains("disabled"));
    }

    #[test]
    fn mutating_route_with_flag_and_matching_op_hash_approves() {
        let config = DevConfig::default().enable_mutation();
        let auth = Authenticator::new(token());
        let mut mock = MockDevBackend::new()
            .with_allowlisted_chat(123)
            .at_time(Timestamp::from_millis(0));
        let op_hash =
            mock.request_approval(7, "op-A", "Operation A", Timestamp::from_millis(10_000));
        let body = format!("approval_id=7&decision=approve&op_hash={op_hash}");
        let resp = route(
            &mut mock,
            &auth,
            &config,
            &authed("POST", "/approvals/resolve", body.into_bytes()),
        );
        assert_eq!(resp.status, Status::Ok, "body was {}", resp.body);
        assert!(resp.body.contains("approved:7"));
    }

    #[test]
    fn mismatched_op_hash_cannot_approve_a_different_op() {
        let config = DevConfig::default().enable_mutation();
        let auth = Authenticator::new(token());
        let mut mock = MockDevBackend::new()
            .with_allowlisted_chat(123)
            .at_time(Timestamp::from_millis(0));
        let _real = mock.request_approval(7, "op-A", "Operation A", Timestamp::from_millis(10_000));
        // Present a DIFFERENT op-hash than the surfaced operation.
        let wrong = "cd".repeat(32);
        let body = format!("approval_id=7&decision=approve&op_hash={wrong}");
        let resp = route(
            &mut mock,
            &auth,
            &config,
            &authed("POST", "/approvals/resolve", body.into_bytes()),
        );
        // The engine rejects the op-mismatch; the UI surfaces a conflict, mints nothing.
        assert_eq!(resp.status, Status::Conflict);
        assert!(resp.body.contains("operation mismatch"));
    }
}
