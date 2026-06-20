// SPDX-License-Identifier: Apache-2.0
//! Credential boundary for live providers (P7-live; invariants 1–3).
//!
//! A live adapter must authenticate an outbound request **without** ever storing the
//! key on its struct or letting it reach the model, a log, or the sandbox env. It
//! holds a [`CredentialSource`] and a secret-handle label, and asks for a freshly
//! assembled [`AuthHeader`] *per request*; it never sees the underlying bytes after
//! the header is built.
//!
//! In the live helper, [`CredentialSource`] is backed by the Phase-8 secret broker
//! (`crustcore-secrets`: `CredentialProxy` / one-shot `ApprovedSecretView`), so the
//! key is resolved from a vault/keychain at call time and dropped immediately. Tests
//! and simple operator setups use [`StaticCredentials`]. This crate deliberately does
//! not link `crustcore-secrets` — the broker-backed source is a thin wrapper the
//! operator constructs and passes in — keeping the model-transport sidecar's
//! dependency surface minimal.

use std::fmt;

/// Which header style a provider uses to carry its credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthStyle {
    /// `Authorization: Bearer <key>` (OpenAI, OpenRouter, most OpenAI-compatible).
    Bearer,
    /// `x-api-key: <key>` (Anthropic).
    XApiKey,
}

/// An assembled authentication header. The **value carries a secret**, so this type
/// has a redacting [`Debug`], is not `Clone`/`Serialize`, and is meant to be built
/// just before a request and consumed into it — never logged or stored.
pub struct AuthHeader {
    /// The header name (e.g. `Authorization` or `x-api-key`).
    pub name: &'static str,
    /// The header value (secret-bearing).
    pub value: String,
}

impl fmt::Debug for AuthHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the secret-bearing value (invariant 2).
        write!(f, "AuthHeader {{ name: {:?}, value: *** }}", self.name)
    }
}

/// Resolves a provider's auth header by its secret-handle label, at call time. The
/// adapter asks for a fresh header per request and never holds the key.
pub trait CredentialSource {
    /// The auth header for `label` in the given `style`, or `None` if no credential
    /// is configured for that label (a local endpoint needs none → no auth header).
    fn header_for(&self, label: &str, style: AuthStyle) -> Option<AuthHeader>;
}

/// A simple in-process [`CredentialSource`] mapping handle labels to key strings —
/// used by tests and by the `#[ignore]`d live integration tests (seeded from an
/// operator-supplied key, never committed). The keys are held in a non-`Debug` map
/// so they are not printed.
#[derive(Default)]
pub struct StaticCredentials {
    keys: std::collections::BTreeMap<String, String>,
}

impl fmt::Debug for StaticCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Do not print the keys; only how many labels are configured.
        write!(f, "StaticCredentials {{ labels: {} }}", self.keys.len())
    }
}

impl StaticCredentials {
    /// An empty credential source.
    #[must_use]
    pub fn new() -> Self {
        StaticCredentials::default()
    }

    /// Registers `key` under `label`. The key is never logged or exposed except as
    /// an assembled header in [`CredentialSource::header_for`].
    #[must_use]
    pub fn with(mut self, label: &str, key: &str) -> Self {
        self.keys.insert(label.to_string(), key.to_string());
        self
    }
}

impl CredentialSource for StaticCredentials {
    fn header_for(&self, label: &str, style: AuthStyle) -> Option<AuthHeader> {
        let key = self.keys.get(label)?;
        Some(match style {
            AuthStyle::Bearer => AuthHeader {
                name: "Authorization",
                value: format!("Bearer {key}"),
            },
            AuthStyle::XApiKey => AuthHeader {
                name: "x-api-key",
                value: key.clone(),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_credentials_build_the_right_header_style() {
        let creds = StaticCredentials::new()
            .with("openai", "sk-abc")
            .with("anthropic", "sk-ant-xyz");

        let bearer = creds.header_for("openai", AuthStyle::Bearer).unwrap();
        assert_eq!(bearer.name, "Authorization");
        assert_eq!(bearer.value, "Bearer sk-abc");

        let xkey = creds.header_for("anthropic", AuthStyle::XApiKey).unwrap();
        assert_eq!(xkey.name, "x-api-key");
        assert_eq!(xkey.value, "sk-ant-xyz");

        // An unknown label yields no header (a local endpoint needs none).
        assert!(creds.header_for("nope", AuthStyle::Bearer).is_none());
    }

    #[test]
    fn auth_header_and_store_debug_never_print_the_secret() {
        let creds = StaticCredentials::new().with("openai", "sk-SECRET");
        let header = creds.header_for("openai", AuthStyle::Bearer).unwrap();
        assert!(!format!("{header:?}").contains("sk-SECRET"));
        assert!(format!("{header:?}").contains("***"));
        assert!(!format!("{creds:?}").contains("sk-SECRET"));
    }
}
