// SPDX-License-Identifier: Apache-2.0
//! Bearer-token authentication (`C7.2`, dimension (b)).
//!
//! A per-launch [`BearerToken`] is generated once, printed to the launching terminal
//! ([`BearerToken::reveal_once`]), and required on **every** route — assets and the
//! websocket route class included. The comparison is constant-time. The token is never
//! written into a [`crate::DevResponse`] body and its `Debug` is redacted, so it cannot
//! leak into a log line.

use std::fmt;

use crustcore_types::hex_val;

/// Number of random bytes in a launch token (256 bits).
pub const TOKEN_BYTES: usize = 32;

/// A per-launch bearer token. Generated once at launch and required on every request.
///
/// `Debug` is deliberately opaque so a token can never land in a log line via a derived
/// `{:?}`. The raw value is revealed exactly once, to the launching terminal, via
/// [`BearerToken::reveal_once`]; everywhere else only the constant-time
/// [`BearerToken::matches`] is exposed.
#[derive(Clone, PartialEq, Eq)]
pub struct BearerToken {
    bytes: [u8; TOKEN_BYTES],
}

impl fmt::Debug for BearerToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never render the token (dimension (b): absent from logs/responses).
        f.write_str("BearerToken(<redacted>)")
    }
}

impl BearerToken {
    /// Builds a token from raw bytes (e.g. read from a launcher-provided source). The
    /// `serve` entry point fills these from a CSPRNG; the deterministic core takes them
    /// as given so handler tests are reproducible.
    #[must_use]
    pub fn from_bytes(bytes: [u8; TOKEN_BYTES]) -> Self {
        BearerToken { bytes }
    }

    /// Reveals the hex-encoded token **once**, for printing to the launching terminal.
    /// This is the only path that exposes the value; callers must print it to the
    /// operator and never persist it.
    #[must_use]
    pub fn reveal_once(&self) -> String {
        let mut s = String::with_capacity(TOKEN_BYTES * 2);
        for b in &self.bytes {
            use core::fmt::Write as _;
            let _ = write!(s, "{b:02x}");
        }
        s
    }

    /// Constant-time comparison against a presented hex token. Decodes `presented` as
    /// hex and compares all bytes without early exit, so timing cannot reveal a prefix
    /// match. A wrong length or non-hex input returns `false`.
    #[must_use]
    pub fn matches(&self, presented: &str) -> bool {
        let Some(decoded) = decode_hex(presented) else {
            // Still do a fixed-cost compare against ourselves to avoid leaking, via
            // timing, whether the *length/format* was the failure vs the value.
            let _ = ct_eq(&self.bytes, &self.bytes);
            return false;
        };
        if decoded.len() != TOKEN_BYTES {
            return false;
        }
        ct_eq(&self.bytes, &decoded)
    }
}

/// Constant-time byte-slice equality. Compares every byte; no early return.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_val(bytes[i])?;
        let lo = hex_val(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

/// The result of authenticating a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthOutcome {
    /// The bearer token matched — the request may proceed to dispatch.
    Authorized,
    /// No `Authorization` header, or a non-`Bearer` scheme.
    MissingToken,
    /// A `Bearer` token was presented but did not match.
    BadToken,
}

impl AuthOutcome {
    /// Whether the request is authorized.
    #[must_use]
    pub fn is_authorized(self) -> bool {
        matches!(self, AuthOutcome::Authorized)
    }
}

/// Authenticates inbound requests against the launch token. Applied at the router root,
/// so it covers **every** route class (assets and websockets included).
#[derive(Clone)]
pub struct Authenticator {
    token: BearerToken,
}

impl fmt::Debug for Authenticator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Authenticator(<token redacted>)")
    }
}

impl Authenticator {
    /// An authenticator for the launch token.
    #[must_use]
    pub fn new(token: BearerToken) -> Self {
        Authenticator { token }
    }

    /// Authenticates a request from its `Authorization: Bearer <hex>` header. A missing
    /// header, a non-`Bearer` scheme, or a non-matching token all fail.
    #[must_use]
    pub fn authenticate(&self, req: &crate::request::DevRequest) -> AuthOutcome {
        let Some(header) = req.header("authorization") else {
            return AuthOutcome::MissingToken;
        };
        let Some(rest) = header
            .strip_prefix("Bearer ")
            .or_else(|| header.strip_prefix("bearer "))
        else {
            return AuthOutcome::MissingToken;
        };
        if self.token.matches(rest.trim()) {
            AuthOutcome::Authorized
        } else {
            AuthOutcome::BadToken
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::DevRequest;

    fn token() -> BearerToken {
        BearerToken::from_bytes([7u8; TOKEN_BYTES])
    }

    fn req_with_auth(value: Option<&str>) -> DevRequest {
        let headers: Vec<(String, String)> = value
            .map(|v| vec![("Authorization".to_string(), v.to_string())])
            .unwrap_or_default();
        DevRequest::new("GET", "/inspector", headers, [], Vec::new()).unwrap()
    }

    #[test]
    fn correct_token_authorizes() {
        let t = token();
        let auth = Authenticator::new(t.clone());
        let presented = format!("Bearer {}", t.reveal_once());
        assert_eq!(
            auth.authenticate(&req_with_auth(Some(&presented))),
            AuthOutcome::Authorized
        );
    }

    #[test]
    fn missing_header_is_missing_token() {
        let auth = Authenticator::new(token());
        assert_eq!(
            auth.authenticate(&req_with_auth(None)),
            AuthOutcome::MissingToken
        );
    }

    #[test]
    fn non_bearer_scheme_is_missing_token() {
        let auth = Authenticator::new(token());
        assert_eq!(
            auth.authenticate(&req_with_auth(Some("Basic abc"))),
            AuthOutcome::MissingToken
        );
    }

    #[test]
    fn wrong_token_is_bad_token() {
        let auth = Authenticator::new(token());
        let wrong = BearerToken::from_bytes([9u8; TOKEN_BYTES]);
        let presented = format!("Bearer {}", wrong.reveal_once());
        assert_eq!(
            auth.authenticate(&req_with_auth(Some(&presented))),
            AuthOutcome::BadToken
        );
    }

    #[test]
    fn malformed_hex_and_wrong_length_reject() {
        let t = token();
        assert!(!t.matches("not-hex"));
        assert!(!t.matches("abcd")); // valid hex, wrong length
        assert!(!t.matches("")); // empty
        assert!(!t.matches(&"f".repeat(63))); // odd length
    }

    #[test]
    fn token_never_renders_in_debug() {
        let dbg = format!("{:?}", token());
        assert!(dbg.contains("redacted"));
        // The raw hex must not appear.
        assert!(!dbg.contains(&token().reveal_once()));
        let auth_dbg = format!("{:?}", Authenticator::new(token()));
        assert!(!auth_dbg.contains(&token().reveal_once()));
    }

    #[test]
    fn constant_time_compare_is_correct() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}
