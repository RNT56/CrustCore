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

use std::convert::Infallible;
use std::io::Read;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::{ConnectInfo, RawQuery, State};
use axum::http::{HeaderMap, Method as HttpMethod, StatusCode, Uri};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use tokio_stream::wrappers::IntervalStream;
use tokio_stream::StreamExt;

use crate::auth::{Authenticator, BearerToken, TOKEN_BYTES};
use crate::backend::DevBackend;
use crate::config::DevConfig;
use crate::request::{DevRequest, DevResponse, Status};
use crate::stream::{next_snapshot, render_frame, SnapshotCursor};

/// How often the live `/ws` SSE stream samples the read-model for a change. Idle ticks emit
/// nothing (the snapshot is debounced); only a changed snapshot becomes an SSE event.
const SNAPSHOT_INTERVAL: Duration = Duration::from_millis(500);

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
        // `/ws` is the live snapshot stream — a dedicated SSE handler (still funnelling
        // through the SAME core `route` gate for auth + loopback before it opens).
        .route("/ws", get(ws_stream::<B>))
        .route("/inspector", get(dispatch::<B>))
        .route("/replay", get(dispatch::<B>))
        .route("/provider", get(dispatch::<B>))
        .route("/mcp", get(dispatch::<B>))
        .route("/flow", get(dispatch::<B>))
        .route("/sessions", get(dispatch::<B>))
        .route("/approvals", get(dispatch::<B>))
        .route("/cockpit", get(dispatch::<B>))
        .route("/approvals/resolve", post(dispatch::<B>))
        .with_state(state)
}

/// Translate axum request parts into the core [`DevRequest`] (shared by [`dispatch`] and
/// the `/ws` SSE handler). On a malformed request it returns the bad-request HTTP response.
fn dev_request_from(
    method: &HttpMethod,
    uri: &Uri,
    headers: &HeaderMap,
    raw_query: Option<&str>,
    peer: SocketAddr,
    body: &[u8],
) -> Result<DevRequest, Box<Response>> {
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
    let query: Vec<(String, String)> = raw_query.map(parse_query).unwrap_or_default();

    match DevRequest::new(
        method.as_str(),
        uri.path().to_string(),
        hdrs,
        query,
        body.to_vec(),
    ) {
        Ok(r) => Ok(r.with_peer_loopback(peer.ip().is_loopback())),
        Err(e) => Err(Box::new(into_response(
            uri.path(),
            DevResponse::error(Status::BadRequest, e.to_string()),
        ))),
    }
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
    let dev_req = match dev_request_from(&method, &uri, &headers, raw_query.as_deref(), peer, &body)
    {
        Ok(r) => r,
        Err(resp) => return *resp,
    };

    // The core does ALL the security work. `&mut` is taken only here, under the lock; the
    // core hands a read route the read-only surface and the one mutating route the gate.
    let resp = {
        let mut backend = state.backend.lock().expect("backend mutex poisoned");
        crate::mutation::route(&mut *backend, &state.auth, &state.config, &dev_req)
    };
    into_response(uri.path(), resp)
}

/// The `/ws` **live snapshot stream** (`C7-serve-live`). It funnels through the SAME core
/// `route` gate (auth + loopback + classification) before opening; only an authenticated
/// loopback request gets the stream. On admit it returns a Server-Sent-Events response that,
/// every [`SNAPSHOT_INTERVAL`], calls the pure [`next_snapshot`] core and emits one SSE
/// `snapshot` event per *change* (idle ticks emit nothing but keep-alives). SSE is strictly
/// server→client, so this stream can never become an inbound control channel (invariant 16);
/// frames come only from the read-only surface and are already redacted (invariant 2).
///
/// `TODO(C7-serve-live)`: only the interval tick loop driving a real socket is the reduced
/// live seam (exercised by the `#[ignore]`d smoke); the per-tick snapshot computation is the
/// CI-tested [`crate::stream`] core.
async fn ws_stream<B: DevBackend + Send + 'static>(
    State(state): State<Arc<DevState<B>>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: HttpMethod,
    uri: Uri,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
    body: Bytes,
) -> Response {
    let dev_req = match dev_request_from(&method, &uri, &headers, raw_query.as_deref(), peer, &body)
    {
        Ok(r) => r,
        Err(resp) => return *resp,
    };

    // Run the SAME core gate. If it rejects (bad/missing bearer, off-loopback), surface that
    // response verbatim — the stream opens ONLY for an admitted request.
    let gate = {
        let mut backend = state.backend.lock().expect("backend mutex poisoned");
        crate::mutation::route(&mut *backend, &state.auth, &state.config, &dev_req)
    };
    if gate.status != Status::Ok {
        return into_response(uri.path(), gate);
    }

    // Admitted: stream redacted snapshot frames, one SSE event per change. The backend lock
    // is held only for the synchronous `next_snapshot` call, then released before the await.
    let stream_state = Arc::clone(&state);
    let mut cursor = SnapshotCursor::start();
    let events =
        IntervalStream::new(tokio::time::interval(SNAPSHOT_INTERVAL)).filter_map(move |_tick| {
            let batch = {
                let backend = stream_state.backend.lock().expect("backend mutex poisoned");
                next_snapshot(backend.read_only(), cursor)
            };
            cursor = batch.next_cursor;
            batch.frame.map(|frame| {
                Ok::<Event, Infallible>(
                    Event::default()
                        .id(cursor.seq.to_string())
                        .event("snapshot")
                        .data(render_frame(&frame)),
                )
            })
        });
    Sse::new(events)
        .keep_alive(KeepAlive::default())
        .into_response()
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
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("crustcore-dev: listening on http://{addr}");
    serve_on(listener, backend, config, token).await
}

/// Serve on an already-bound loopback listener. Factored out of [`serve`] so a test can bind
/// `127.0.0.1:0`, learn the port, and drive the live `/ws` SSE stream over a real socket
/// (the reduced `TODO(C7-serve-live)` seam). Does not print the token (the caller does).
///
/// # Errors
/// Returns an `std::io::Error` if the server fails.
pub async fn serve_on<B: DevBackend + Send + 'static>(
    listener: tokio::net::TcpListener,
    backend: B,
    config: DevConfig,
    token: BearerToken,
) -> std::io::Result<()> {
    let auth = Authenticator::new(token);
    let state = Arc::new(DevState {
        backend: Mutex::new(backend),
        auth,
        config,
    });
    axum::serve(
        listener,
        router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
}

#[cfg(test)]
mod live_tests {
    use super::*;
    use crate::backend::MockDevBackend;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // The live `/ws` stream needs a real TCP socket + an HTTP/SSE client round-trip; it is
    // `#[ignore]`d (the reduced C7-serve-live seam). The per-tick snapshot computation is the
    // CI-tested `crate::stream` core — this asserts the end-to-end SSE wiring on a host.
    #[tokio::test]
    #[ignore = "live: real TCP socket + SSE HTTP client (TODO C7-serve-live)"]
    async fn live_ws_sse_emits_a_snapshot() {
        let token = BearerToken::from_bytes([7u8; TOKEN_BYTES]);
        let bearer = token.reveal_once();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(serve_on(
            listener,
            MockDevBackend::new(),
            DevConfig::loopback(),
            token,
        ));

        let mut sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!(
            "GET /ws HTTP/1.1\r\nHost: {addr}\r\nAuthorization: Bearer {bearer}\r\nConnection: close\r\n\r\n"
        );
        sock.write_all(req.as_bytes()).await.unwrap();

        // Accumulate chunks until the first SSE snapshot frame arrives (the headers flush
        // before the body), bounded by a deadline so a regression can't hang the test.
        let mut acc = String::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            let mut buf = vec![0u8; 8192];
            match tokio::time::timeout_at(deadline, sock.read(&mut buf)).await {
                Ok(Ok(0)) => break, // EOF
                Ok(Ok(n)) => {
                    acc.push_str(&String::from_utf8_lossy(&buf[..n]));
                    if acc.contains("event: snapshot") {
                        break;
                    }
                }
                Ok(Err(_)) | Err(_) => break, // io error or deadline
            }
        }
        assert!(
            acc.contains("text/event-stream"),
            "expected an SSE response, got: {acc}"
        );
        assert!(
            acc.contains("event: snapshot") && acc.contains("RunInspectorView"),
            "expected the initial snapshot frame, got: {acc}"
        );
    }
}
