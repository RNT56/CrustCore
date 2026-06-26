// SPDX-License-Identifier: Apache-2.0
//! The embedded single-page inspector assets (`C7-devui`).
//!
//! The dev UI ships a small, **dependency-free** single-page app: one HTML page with
//! inline vanilla JS plus one stylesheet, both embedded at compile time via
//! [`include_str!`] — no CDN, no framework, no network, no extra crate. The page is the
//! human surface over the existing typed read endpoints (`/inspector`, `/replay`,
//! `/provider`, `/mcp`, `/flow`, `/sessions`, `/approvals`): its JS `fetch()`es each one
//! with the per-launch bearer token in an `Authorization` header (matching [`crate::auth`],
//! which is header-only) and renders the already-redacted bodies.
//!
//! Serving these is purely a **read** concern: `/` returns [`INSPECTOR_HTML`] and `/assets`
//! returns [`INSPECTOR_CSS`], both through the same read-route mechanism as every other
//! view (auth + loopback still apply — no posture change). The token is deliberately
//! **not** embedded in the served bytes (it must never appear in a response body); the page
//! takes it from the URL fragment or a paste box client-side.

/// The single-page inspector HTML (inline CSS link + inline vanilla JS). Served at `/`.
pub const INSPECTOR_HTML: &str = include_str!("assets/inspector.html");

/// The inspector stylesheet. Served at `/assets`.
pub const INSPECTOR_CSS: &str = include_str!("assets/inspector.css");

/// A marker present in [`INSPECTOR_HTML`] (`<title>CrustCore Inspector</title>`) that the
/// core tests assert on, so `/` is verified to serve the real SPA rather than a placeholder.
pub const TITLE_MARKER: &str = "CrustCore Inspector";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_is_the_real_spa() {
        assert!(INSPECTOR_HTML.contains("<!DOCTYPE html>"));
        assert!(INSPECTOR_HTML.contains(TITLE_MARKER));
        // It references the split stylesheet asset and surfaces every read endpoint.
        assert!(INSPECTOR_HTML.contains("href=\"/assets\""));
        for path in [
            "/inspector",
            "/replay",
            "/provider",
            "/mcp",
            "/flow",
            "/sessions",
            "/approvals",
        ] {
            assert!(INSPECTOR_HTML.contains(path), "SPA should surface {path}");
        }
        // It authenticates fetches with the bearer header (never weakens auth).
        assert!(INSPECTOR_HTML.contains("Authorization"));
        assert!(INSPECTOR_HTML.contains("Bearer "));
    }

    #[test]
    fn css_is_non_empty_stylesheet() {
        assert!(INSPECTOR_CSS.contains("CrustCore dev UI styles"));
        assert!(!INSPECTOR_CSS.trim().is_empty());
    }

    #[test]
    fn assets_embed_no_concrete_token_value() {
        // The served bytes are static; the page reads the token from the fragment / a
        // paste box at runtime — no concrete 64-hex token can be baked into the HTML.
        // (The strings `token`/`Bearer ` legitimately appear in the fetch/parse code.)
        let lower = INSPECTOR_HTML.to_ascii_lowercase();
        let has_baked_token = lower
            .split_whitespace()
            .any(|w| w.len() == 64 && w.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(
            !has_baked_token,
            "a concrete bearer-token-shaped value is embedded in the SPA"
        );
    }
}
