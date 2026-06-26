// SPDX-License-Identifier: Apache-2.0
//! The real loopback HTTP server (`C7.1`, behind the `serve` feature).
//!
//! This is the **only** module that links the heavy web stack (`axum`/`hyper`/`tokio`).
//! It is feature-gated and absent from the default build; the deterministic core is
//! tested without it. The server's sole job is to map an inbound HTTP request onto a
//! [`DevRequest`](crate::request::DevRequest) and call the core
//! [`route`](crate::mutation::route) chokepoint — it adds **no** policy of its own: auth,
//! loopback, route-classification, and the read/mutate split all live in the core and are
//! CI-tested over `MockDevBackend`.
//!
//! The embedded single-page inspector ([`crate::assets`]) is served through this layer at
//! `/` (HTML) and `/assets` (CSS), tagged with the right `Content-Type` in
//! [`into_response`]. Real provider/MCP/spawned-helper wiring (a `DevBackend` impl backed
//! by a live event log, the spawned `crustcore-net` helper, and the P13-net MCP transport)
//! and live `/ws` snapshot streaming remain `TODO(C7-serve-live)` — they drop in behind
//! this same `route` call with the core unchanged.

use std::io::Read;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::{ConnectInfo, RawQuery, State};
use axum::http::{HeaderMap, Method as HttpMethod, StatusCode, Uri};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;

use crate::auth::{Authenticator, BearerToken, TOKEN_BYTES};
use crate::backend::DevBackend;
use crate::config::DevConfig;
use crate::request::{DevRequest, DevResponse, Status};

/// Shared server state: the backend (behind a mutex so the one mutating route can take
/// `&mut`), the authenticator, and the launch config.
struct DevState<B: DevBackend + Send> {
    backend: Mutex<B>,
    auth: Authenticator,
    config: DevConfig,
}

/// Mint a fresh per-launch bearer token from the OS CSPRNG (`/dev/urandom`, std-only —
/// no extra dependency, matching the nano binary's randomness source). The token is
/// returned so the launcher can print it once; it is never logged here.
#[must_use]
pub fn mint_launch_token() -> BearerToken {
    let mut buf = [0u8; TOKEN_BYTES];
    // Best-effort fill from the OS CSPRNG. On the rare failure we still return a token,
    // but the caller-visible randomness is the OS source on every supported platform.
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = f.read_exact(&mut buf);
    }
    BearerToken::from_bytes(buf)
}

/// Builds the axum router. Every route is registered here so the root-level handler
/// applies auth + loopback + classification uniformly (assets and the ws route included).
fn router<B: DevBackend + Send + 'static>(state: Arc<DevState<B>>) -> Router {
    // A single catch-all per method funnels into the core `route` chokepoint; the core's
    // route table (`route_class::ROUTES`) is the authority on what exists and its class.
    Router::new()
        .route("/", get(dispatch::<B>))
        .route("/assets", get(dispatch::<B>))
        .route("/ws", get(dispatch::<B>))
        .route("/inspector", get(dispatch::<B>))
        .route("/replay", get(dispatch::<B>))
        .route("/provider", get(dispatch::<B>))
        .route("/mcp", get(dispatch::<B>))
        .route("/flow", get(dispatch::<B>))
        .route("/sessions", get(dispatch::<B>))
        .route("/approvals", get(dispatch::<B>))
        .route("/approvals/resolve", post(dispatch::<B>))
        .with_state(state)
}

/// The single axum handler: translate HTTP → `DevRequest`, call the core, translate back.
async fn dispatch<B: DevBackend + Send + 'static>(
    State(state): State<Arc<DevState<B>>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: HttpMethod,
    uri: Uri,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
    body: Bytes,
) -> Response {
    // Collect headers (lossy-decoded values; the core re-bounds them).
    let hdrs: Vec<(String, String)> = headers
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|s| (k.as_str().to_string(), s.to_string()))
        })
        .collect();

    // Decode the query string into params (best-effort; the core re-bounds).
    let query: Vec<(String, String)> = raw_query.as_deref().map(parse_query).unwrap_or_default();

    let dev_req = match DevRequest::new(
        method.as_str(),
        uri.path().to_string(),
        hdrs,
        query,
        body.to_vec(),
    ) {
        Ok(r) => r.with_peer_loopback(peer.ip().is_loopback()),
        Err(e) => {
            return into_response(
                uri.path(),
                DevResponse::error(Status::BadRequest, e.to_string()),
            )
        }
    };

    // The core does ALL the security work. `&mut` is taken only here, under the lock; the
    // core hands a read route the read-only surface and the one mutating route the gate.
    let resp = {
        let mut backend = state.backend.lock().expect("backend mutex poisoned");
        crate::mutation::route(&mut *backend, &state.auth, &state.config, &dev_req)
    };
    into_response(uri.path(), resp)
}

/// Map a core [`DevResponse`] onto an HTTP response, tagging the embedded single-page
/// inspector with the right `Content-Type` (the core carries only a body string). Only the
/// static SPA routes get a non-default type; every typed view stays `text/plain`.
fn into_response(path: &str, resp: DevResponse) -> Response {
    let code =
        StatusCode::from_u16(resp.status.code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let content_type = if resp.status == Status::Ok {
        match path {
            "/" => "text/html; charset=utf-8",
            "/assets" => "text/css; charset=utf-8",
            "/ws" => "application/json; charset=utf-8",
            _ => "text/plain; charset=utf-8",
        }
    } else {
        "text/plain; charset=utf-8"
    };
    let mut http = Response::new(axum::body::Body::from(resp.body));
    *http.status_mut() = code;
    http.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static(content_type),
    );
    http
}

fn parse_query(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter_map(|p| p.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Run the loopback dev server to completion. Binds the configured host:port (loopback by
/// default), prints the launch token once and any off-loopback exposure warning, and
/// serves until shut down. The backend is provided by the caller (the `serve` entry wires
/// a live one; `TODO(C7-serve-live)`).
///
/// # Errors
/// Returns an `std::io::Error` if the socket cannot be bound or the server fails.
pub async fn serve<B: DevBackend + Send + 'static>(
    backend: B,
    config: DevConfig,
    token: BearerToken,
) -> std::io::Result<()> {
    // Print the token ONCE to the launching terminal (never to a log sink).
    println!(
        "crustcore-dev: bearer token (present as `Authorization: Bearer <token>`):\n  {}",
        token.reveal_once()
    );
    if let Some(warn) = config.exposure_warning() {
        eprintln!("{warn}");
    }

    let addr = SocketAddr::new(config.host(), config.port_num());
    let auth = Authenticator::new(token);
    let state = Arc::new(DevState {
        backend: Mutex::new(backend),
        auth,
        config,
    });

    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("crustcore-dev: listening on http://{addr}");
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
}
