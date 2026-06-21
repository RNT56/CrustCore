// SPDX-License-Identifier: Apache-2.0
//! Transport-agnostic request/response types (`C7.1`/`C7.2`).
//!
//! [`DevRequest`] is a parsed `{ method, path, headers, query, body }`. It is the
//! single shape every core handler consumes, so the whole handler surface is exercised
//! in CI without `axum`/`hyper` (the `serve` feature maps real HTTP onto this type).
//!
//! Everything in a `DevRequest` is **untrusted** (invariant 7). Construction is
//! length-bounded and validates the verb; an over-long header/query/body or an unknown
//! verb is rejected at the door, before any handler runs.

use std::collections::BTreeMap;

/// Max bytes for any single header value (untrusted; invariant 7).
pub const MAX_HEADER_BYTES: usize = 8 * 1024;
/// Max number of headers we will hold for one request.
pub const MAX_HEADERS: usize = 64;
/// Max bytes for the request path.
pub const MAX_PATH_BYTES: usize = 4 * 1024;
/// Max bytes for the raw query string.
pub const MAX_QUERY_BYTES: usize = 8 * 1024;
/// Max bytes for the request body (the UI posts only small typed control payloads).
pub const MAX_BODY_BYTES: usize = 64 * 1024;
/// Max number of decoded query parameters.
pub const MAX_QUERY_PARAMS: usize = 64;

/// The HTTP method, restricted to the verbs the dev UI accepts. Anything else is an
/// unknown verb and is rejected (invariant 7 — reject unknown verbs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// Read requests (assets, inspector, replay, provider/MCP/flow views).
    Get,
    /// Control requests (approval resolutions); always `Mutating`-classed.
    Post,
}

impl Method {
    /// Parses a method string case-insensitively. Returns `None` for any verb the
    /// dev UI does not serve (PUT/DELETE/PATCH/HEAD/OPTIONS/TRACE/CONNECT/garbage).
    #[must_use]
    pub fn parse(s: &str) -> Option<Method> {
        match s.to_ascii_uppercase().as_str() {
            "GET" => Some(Method::Get),
            "POST" => Some(Method::Post),
            _ => None,
        }
    }
}

/// Why a [`DevRequest`] failed to construct (rejected at the door).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestError {
    /// The verb is not one the dev UI serves.
    UnknownVerb,
    /// The path exceeded [`MAX_PATH_BYTES`].
    PathTooLong,
    /// The query string exceeded [`MAX_QUERY_BYTES`] (or too many params).
    QueryTooLarge,
    /// A header value exceeded [`MAX_HEADER_BYTES`] (or too many headers).
    HeaderTooLarge,
    /// The body exceeded [`MAX_BODY_BYTES`].
    BodyTooLarge,
}

impl core::fmt::Display for RequestError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            RequestError::UnknownVerb => "unknown HTTP verb",
            RequestError::PathTooLong => "request path too long",
            RequestError::QueryTooLarge => "query string too large",
            RequestError::HeaderTooLarge => "header value too large",
            RequestError::BodyTooLarge => "request body too large",
        };
        f.write_str(s)
    }
}

impl std::error::Error for RequestError {}

/// A parsed, bounded, validated inbound request. The single shape every core handler
/// consumes. All fields are **untrusted data** (invariant 7).
#[derive(Debug, Clone)]
pub struct DevRequest {
    method: Method,
    path: String,
    /// Lowercased header name -> value (already length-checked).
    headers: BTreeMap<String, String>,
    /// Decoded query parameters (already length-checked).
    query: BTreeMap<String, String>,
    /// The raw body bytes (already length-checked).
    body: Vec<u8>,
    /// Whether the peer is a loopback address. The `serve` layer sets this from the
    /// socket; the core treats a non-loopback peer as a hard reject (dimension (a)).
    peer_is_loopback: bool,
}

impl DevRequest {
    /// Builds a bounded, validated request. Returns [`RequestError`] if any field is
    /// over budget or the verb is unknown. The peer is assumed loopback unless set
    /// otherwise via [`DevRequest::with_peer_loopback`].
    pub fn new(
        method: &str,
        path: impl Into<String>,
        headers: impl IntoIterator<Item = (String, String)>,
        query: impl IntoIterator<Item = (String, String)>,
        body: Vec<u8>,
    ) -> Result<DevRequest, RequestError> {
        let method = Method::parse(method).ok_or(RequestError::UnknownVerb)?;

        let path = path.into();
        if path.len() > MAX_PATH_BYTES {
            return Err(RequestError::PathTooLong);
        }

        let mut hmap = BTreeMap::new();
        for (k, v) in headers {
            if hmap.len() >= MAX_HEADERS {
                return Err(RequestError::HeaderTooLarge);
            }
            if k.len() > MAX_HEADER_BYTES || v.len() > MAX_HEADER_BYTES {
                return Err(RequestError::HeaderTooLarge);
            }
            hmap.insert(k.to_ascii_lowercase(), v);
        }

        let mut qmap = BTreeMap::new();
        let mut qbytes = 0usize;
        for (k, v) in query {
            if qmap.len() >= MAX_QUERY_PARAMS {
                return Err(RequestError::QueryTooLarge);
            }
            qbytes = qbytes.saturating_add(k.len()).saturating_add(v.len());
            if qbytes > MAX_QUERY_BYTES {
                return Err(RequestError::QueryTooLarge);
            }
            qmap.insert(k, v);
        }

        if body.len() > MAX_BODY_BYTES {
            return Err(RequestError::BodyTooLarge);
        }

        Ok(DevRequest {
            method,
            path,
            headers: hmap,
            query: qmap,
            body,
            peer_is_loopback: true,
        })
    }

    /// Marks whether the peer socket is a loopback address. The `serve` layer sets this
    /// from the accepted connection; the core rejects non-loopback peers (dimension (a)).
    #[must_use]
    pub fn with_peer_loopback(mut self, is_loopback: bool) -> Self {
        self.peer_is_loopback = is_loopback;
        self
    }

    /// The request method.
    #[must_use]
    pub fn method(&self) -> Method {
        self.method
    }

    /// The request path.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// A header value by (case-insensitive) name.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    /// A query parameter by name.
    #[must_use]
    pub fn query(&self, name: &str) -> Option<&str> {
        self.query.get(name).map(String::as_str)
    }

    /// The raw (bounded) body bytes.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Whether the peer is a loopback address.
    #[must_use]
    pub fn peer_is_loopback(&self) -> bool {
        self.peer_is_loopback
    }
}

/// A coarse status for a [`DevResponse`], mirroring the HTTP statuses the dev UI emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// 200 — handled.
    Ok,
    /// 400 — malformed/invalid request.
    BadRequest,
    /// 401 — missing/invalid bearer token.
    Unauthorized,
    /// 403 — non-loopback peer, or a mutating route reached without the launch flag.
    Forbidden,
    /// 404 — no such route.
    NotFound,
    /// 409 — an operation-bound conflict (e.g. op-hash mismatch on an approval).
    Conflict,
}

impl Status {
    /// The numeric HTTP code, for the `serve` mapping.
    #[must_use]
    pub fn code(self) -> u16 {
        match self {
            Status::Ok => 200,
            Status::BadRequest => 400,
            Status::Unauthorized => 401,
            Status::Forbidden => 403,
            Status::NotFound => 404,
            Status::Conflict => 409,
        }
    }
}

/// A handler's response: a status plus an already-redacted, bounded body. The body is
/// always render-safe — handlers pass every user-visible string through
/// [`crustcore_secrets::Redactor`] before it reaches here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevResponse {
    /// The response status.
    pub status: Status,
    /// The (redacted, bounded) response body.
    pub body: String,
}

impl DevResponse {
    /// A 200 response with `body`.
    #[must_use]
    pub fn ok(body: impl Into<String>) -> Self {
        DevResponse {
            status: Status::Ok,
            body: body.into(),
        }
    }

    /// An error response with `status` and a short message.
    #[must_use]
    pub fn error(status: Status, message: impl Into<String>) -> Self {
        DevResponse {
            status,
            body: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_verbs() {
        for verb in [
            "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "CONNECT", "ZZ",
        ] {
            assert_eq!(
                DevRequest::new(verb, "/", [], [], Vec::new()).unwrap_err(),
                RequestError::UnknownVerb
            );
        }
        assert!(DevRequest::new("get", "/", [], [], Vec::new()).is_ok());
        assert!(DevRequest::new("POST", "/", [], [], Vec::new()).is_ok());
    }

    #[test]
    fn bounds_every_untrusted_field() {
        let long = "x".repeat(MAX_PATH_BYTES + 1);
        assert_eq!(
            DevRequest::new("GET", long, [], [], Vec::new()).unwrap_err(),
            RequestError::PathTooLong
        );

        let big_header = [("k".to_string(), "v".repeat(MAX_HEADER_BYTES + 1))];
        assert_eq!(
            DevRequest::new("GET", "/", big_header, [], Vec::new()).unwrap_err(),
            RequestError::HeaderTooLarge
        );

        let big_body = vec![0u8; MAX_BODY_BYTES + 1];
        assert_eq!(
            DevRequest::new("GET", "/", [], [], big_body).unwrap_err(),
            RequestError::BodyTooLarge
        );

        let big_query = [("q".to_string(), "v".repeat(MAX_QUERY_BYTES + 1))];
        assert_eq!(
            DevRequest::new("GET", "/", [], big_query, Vec::new()).unwrap_err(),
            RequestError::QueryTooLarge
        );
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        let req = DevRequest::new(
            "GET",
            "/",
            [("Authorization".to_string(), "Bearer xyz".to_string())],
            [],
            Vec::new(),
        )
        .unwrap();
        assert_eq!(req.header("authorization"), Some("Bearer xyz"));
        assert_eq!(req.header("AUTHORIZATION"), Some("Bearer xyz"));
    }

    #[test]
    fn loopback_defaults_true_and_is_settable() {
        let req = DevRequest::new("GET", "/", [], [], Vec::new()).unwrap();
        assert!(req.peer_is_loopback());
        let off = req.with_peer_loopback(false);
        assert!(!off.peer_is_loopback());
    }
}
