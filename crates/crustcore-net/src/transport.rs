// SPDX-License-Identifier: Apache-2.0
//! HTTP transport boundary for live providers (P7-live).
//!
//! The provider adapters ([`crate::providers`]) never touch a socket directly —
//! they go through the [`HttpClient`] trait. This keeps the adapters' parse / map /
//! stream logic **fully testable in CI with no network** via [`ReplayClient`] (canned
//! responses), while the real, network-bearing [`UreqClient`] lives behind the
//! `live` cargo feature and is the only thing that links an HTTP/TLS stack.
//!
//! **No-partial-leak invariant.** On a **non-2xx** response the `on_line` streaming
//! callback is **never** invoked — the error body is returned in
//! [`HttpResponse::body`] instead. So a request that is going to fail emits nothing
//! downstream, preserving the engine's fallback-safety property (a failed provider
//! must not leak partial output before the next one is tried).

use std::fmt;

/// The outcome of an HTTP call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// The HTTP status code.
    pub status: u16,
    /// The response body. For a **2xx streaming** POST the body lines were already
    /// delivered via `on_line` and this is empty; for a **non-2xx** response (or a
    /// GET) it holds the full body, bounded to [`MAX_BODY_BYTES`].
    pub body: String,
}

impl HttpResponse {
    /// Whether the status is 2xx.
    #[must_use]
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// A transport-level failure (distinct from an HTTP error *status*, which is a
/// successful round-trip with a non-2xx [`HttpResponse`]). These map to
/// [`crate::ProviderError::Unavailable`] so they drive fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// The request timed out.
    Timeout,
    /// Could not connect / DNS / TLS handshake failure.
    Connect(String),
    /// An I/O error reading the response.
    Io(String),
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Timeout => write!(f, "request timed out"),
            TransportError::Connect(e) => write!(f, "connect failed: {e}"),
            TransportError::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

/// Cap on bytes read from any single response (bounded — a hostile/huge response
/// can never force unbounded allocation; §6.5). Mirrors the protocol stream cap.
pub const MAX_BODY_BYTES: usize = crustcore_netproto::MAX_STREAM_BYTES;

/// The HTTP transport a live provider adapter speaks. Synchronous and blocking to
/// match the sync `Provider::complete` contract (no async runtime needed).
pub trait HttpClient {
    /// POST `body` (a JSON request) to `url` with `headers`. On a **2xx** response,
    /// each response body line is delivered to `on_line` (SSE streaming) and the
    /// returned [`HttpResponse::body`] is empty. On a **non-2xx** response, `on_line`
    /// is **not** called and the (bounded) error body is returned. Total bytes read
    /// are bounded by [`MAX_BODY_BYTES`].
    ///
    /// # Errors
    /// [`TransportError`] on a connect/timeout/io failure (not on an HTTP error
    /// status, which is a successful round-trip with a non-2xx response).
    fn post_lines(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
        on_line: &mut dyn FnMut(&str),
    ) -> Result<HttpResponse, TransportError>;

    /// GET `url` (e.g. `/v1/models` for a probe). Returns status + bounded body.
    ///
    /// # Errors
    /// [`TransportError`] on a transport failure.
    fn get(&self, url: &str, headers: &[(String, String)]) -> Result<HttpResponse, TransportError>;

    /// POST `body` to `url`, returning the **full** (bounded) response body for any
    /// status — for non-streaming JSON APIs (e.g. GitHub REST). Unlike
    /// [`HttpClient::post_lines`] it never streams; the response is the whole body.
    ///
    /// # Errors
    /// [`TransportError`] on a transport failure.
    fn post_json(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<HttpResponse, TransportError>;
}

// ---------------------------------------------------------------------------
// ReplayClient — canned responses, always compiled (the CI-testable transport)
// ---------------------------------------------------------------------------

/// One canned HTTP exchange for [`ReplayClient`].
#[derive(Debug, Clone)]
pub struct Canned {
    /// The HTTP status to report.
    pub status: u16,
    /// Body lines delivered via `on_line` on a 2xx POST (e.g. SSE `data:` lines).
    pub lines: Vec<String>,
    /// The full body returned for a GET, or for a non-2xx POST error.
    pub body: String,
}

impl Canned {
    /// A 2xx streaming response delivering `lines`.
    #[must_use]
    pub fn streaming(lines: &[&str]) -> Self {
        Canned {
            status: 200,
            lines: lines.iter().map(|s| (*s).to_string()).collect(),
            body: String::new(),
        }
    }

    /// A non-streaming response with a status + body (a GET result or an error).
    #[must_use]
    pub fn with_body(status: u16, body: &str) -> Self {
        Canned {
            status,
            lines: Vec::new(),
            body: body.to_string(),
        }
    }
}

/// A deterministic [`HttpClient`] that replays a fixed sequence of [`Canned`]
/// responses — the transport used by the provider replay tests and the secret-leak
/// red-team fixture. Makes **no** network calls, so it runs in CI.
pub struct ReplayClient {
    responses: std::cell::RefCell<std::collections::VecDeque<Canned>>,
}

impl ReplayClient {
    /// A client that will replay `responses` in order.
    #[must_use]
    pub fn new(responses: Vec<Canned>) -> Self {
        ReplayClient {
            responses: std::cell::RefCell::new(responses.into_iter().collect()),
        }
    }

    fn next(&self) -> Result<Canned, TransportError> {
        self.responses
            .borrow_mut()
            .pop_front()
            .ok_or_else(|| TransportError::Io("replay exhausted".into()))
    }
}

impl HttpClient for ReplayClient {
    fn post_lines(
        &self,
        _url: &str,
        _headers: &[(String, String)],
        _body: &[u8],
        on_line: &mut dyn FnMut(&str),
    ) -> Result<HttpResponse, TransportError> {
        let canned = self.next()?;
        if (200..300).contains(&canned.status) {
            // 2xx: stream the lines, bounded; the body stays empty.
            let mut sent = 0usize;
            for line in &canned.lines {
                sent = sent.saturating_add(line.len());
                if sent > MAX_BODY_BYTES {
                    break;
                }
                on_line(line);
            }
            Ok(HttpResponse {
                status: canned.status,
                body: String::new(),
            })
        } else {
            // Non-2xx: on_line is NEVER called; the error body is returned.
            Ok(HttpResponse {
                status: canned.status,
                body: bound(&canned.body),
            })
        }
    }

    fn get(
        &self,
        _url: &str,
        _headers: &[(String, String)],
    ) -> Result<HttpResponse, TransportError> {
        let canned = self.next()?;
        Ok(HttpResponse {
            status: canned.status,
            body: bound(&canned.body),
        })
    }

    fn post_json(
        &self,
        _url: &str,
        _headers: &[(String, String)],
        _body: &[u8],
    ) -> Result<HttpResponse, TransportError> {
        let canned = self.next()?;
        Ok(HttpResponse {
            status: canned.status,
            body: bound(&canned.body),
        })
    }
}

/// Truncates a body to [`MAX_BODY_BYTES`] on a char boundary (bounded everything).
fn bound(s: &str) -> String {
    if s.len() <= MAX_BODY_BYTES {
        return s.to_string();
    }
    let mut end = MAX_BODY_BYTES;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

// ---------------------------------------------------------------------------
// UreqClient — the real HTTP/TLS transport (live feature only)
// ---------------------------------------------------------------------------

/// The real blocking HTTP client (`ureq` + rustls), behind the `live` feature so the
/// default build links no HTTP/TLS stack. This is the **only** code that opens a
/// socket; all parse/map/stream logic above it is transport-agnostic and CI-tested.
#[cfg(feature = "live")]
pub struct UreqClient {
    agent: ureq::Agent,
}

#[cfg(feature = "live")]
impl Default for UreqClient {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "live")]
impl UreqClient {
    /// A client with a bounded request timeout.
    #[must_use]
    pub fn new() -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(120))
            .build();
        UreqClient { agent }
    }

    fn read_bounded(reader: impl std::io::Read, on_line: &mut dyn FnMut(&str)) {
        use std::io::BufRead;
        let mut sent = 0usize;
        let mut buf = std::io::BufReader::new(reader.take(MAX_BODY_BYTES as u64));
        let mut line = String::new();
        loop {
            line.clear();
            match buf.read_line(&mut line) {
                Ok(0) => break,
                Ok(n) => {
                    sent = sent.saturating_add(n);
                    if sent > MAX_BODY_BYTES {
                        break;
                    }
                    on_line(line.trim_end_matches(['\n', '\r']));
                }
                Err(_) => break,
            }
        }
    }
}

#[cfg(feature = "live")]
impl HttpClient for UreqClient {
    fn post_lines(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
        on_line: &mut dyn FnMut(&str),
    ) -> Result<HttpResponse, TransportError> {
        let mut req = self.agent.post(url);
        for (k, v) in headers {
            req = req.set(k, v);
        }
        match req.send_bytes(body) {
            Ok(resp) => {
                let status = resp.status();
                if (200..300).contains(&status) {
                    Self::read_bounded(resp.into_reader(), on_line);
                    Ok(HttpResponse {
                        status,
                        body: String::new(),
                    })
                } else {
                    let body = resp.into_string().unwrap_or_default();
                    Ok(HttpResponse {
                        status,
                        body: bound(&body),
                    })
                }
            }
            // ureq surfaces a non-2xx as Err(Status); that is still a round-trip.
            Err(ureq::Error::Status(status, resp)) => {
                let body = resp.into_string().unwrap_or_default();
                Ok(HttpResponse {
                    status,
                    body: bound(&body),
                })
            }
            Err(ureq::Error::Transport(t)) => {
                let kind = t.kind();
                let msg = t.to_string();
                if matches!(kind, ureq::ErrorKind::Io) && msg.contains("timed out") {
                    Err(TransportError::Timeout)
                } else {
                    Err(TransportError::Connect(msg))
                }
            }
        }
    }

    fn get(&self, url: &str, headers: &[(String, String)]) -> Result<HttpResponse, TransportError> {
        let mut req = self.agent.get(url);
        for (k, v) in headers {
            req = req.set(k, v);
        }
        match req.call() {
            Ok(resp) => {
                let status = resp.status();
                let body = resp.into_string().unwrap_or_default();
                Ok(HttpResponse {
                    status,
                    body: bound(&body),
                })
            }
            Err(ureq::Error::Status(status, resp)) => {
                let body = resp.into_string().unwrap_or_default();
                Ok(HttpResponse {
                    status,
                    body: bound(&body),
                })
            }
            Err(ureq::Error::Transport(t)) => Err(TransportError::Connect(t.to_string())),
        }
    }

    fn post_json(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<HttpResponse, TransportError> {
        let mut req = self.agent.post(url);
        for (k, v) in headers {
            req = req.set(k, v);
        }
        match req.send_bytes(body) {
            Ok(resp) => {
                let status = resp.status();
                let body = resp.into_string().unwrap_or_default();
                Ok(HttpResponse {
                    status,
                    body: bound(&body),
                })
            }
            Err(ureq::Error::Status(status, resp)) => {
                let body = resp.into_string().unwrap_or_default();
                Ok(HttpResponse {
                    status,
                    body: bound(&body),
                })
            }
            Err(ureq::Error::Transport(t)) => Err(TransportError::Connect(t.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_streams_2xx_lines_and_returns_error_body_for_non_2xx() {
        let client = ReplayClient::new(vec![
            Canned::streaming(&["data: a", "data: b"]),
            Canned::with_body(429, "rate limited"),
        ]);

        // 2xx: lines delivered via on_line, body empty.
        let mut got = Vec::new();
        let resp = client
            .post_lines("u", &[], b"{}", &mut |l| got.push(l.to_string()))
            .unwrap();
        assert!(resp.is_success());
        assert_eq!(got, vec!["data: a", "data: b"]);
        assert!(resp.body.is_empty());

        // non-2xx: on_line NOT called, error body returned.
        let mut called = false;
        let resp = client
            .post_lines("u", &[], b"{}", &mut |_| called = true)
            .unwrap();
        assert_eq!(resp.status, 429);
        assert_eq!(resp.body, "rate limited");
        assert!(!called, "a non-2xx response must not stream any line");
    }

    #[test]
    fn replay_exhaustion_is_an_error_not_a_panic() {
        let client = ReplayClient::new(vec![]);
        assert_eq!(
            client.get("u", &[]).unwrap_err(),
            TransportError::Io("replay exhausted".into())
        );
    }
}
