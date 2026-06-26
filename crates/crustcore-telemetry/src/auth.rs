// SPDX-License-Identifier: Apache-2.0
//! Broker-mediated OTLP endpoint auth (C6T.5) — a seam, live path behind `otlp`.
//!
//! If a collector requires a bearer/header, it is resolved **only** through the
//! secret broker ([`crustcore_secrets::SecretBroker`] →
//! [`crustcore_secrets::ApprovedSecretView`] →
//! [`crustcore_secrets::CredentialProxy::bearer`]) at send time, per request. The
//! credential is **never** read from an environment variable, **never** placed in a
//! span attribute or metric label, and **never** model-visible (invariant 1). The
//! exporter process holds only a [`crustcore_secrets::SecretHandle`] (an id + label),
//! not the bytes.
//!
//! The deterministic projection core needs no secrets, so the auth *config* is a
//! simple, non-secret descriptor that lives in the default build; the actual broker
//! call + header injection compiles only under the `otlp` feature, alongside the real
//! exporter, which wires the returned [`crustcore_secrets::HeaderInjection`] straight
//! into the outbound POST. Only the live socket smoke is `TODO(C6-otlp-live)`.

use crustcore_secrets::SecretHandle;

/// How the OTLP exporter authenticates to its collector. This is **non-secret
/// config**: it names *which* broker-held secret to use (by handle), never the value.
#[derive(Debug, Clone, Default)]
pub enum OtlpEndpointAuth {
    /// No authentication (the default; appropriate for a loopback collector).
    #[default]
    None,
    /// A bearer token resolved at send time from the broker via this handle. The
    /// bytes never live here — only the handle (id + label).
    BrokerBearer(SecretHandle),
}

impl OtlpEndpointAuth {
    /// No-auth (loopback default).
    #[must_use]
    pub fn none() -> Self {
        OtlpEndpointAuth::None
    }

    /// Authenticate with a broker-held bearer token, referenced by `handle`.
    #[must_use]
    pub fn broker_bearer(handle: SecretHandle) -> Self {
        OtlpEndpointAuth::BrokerBearer(handle)
    }

    /// Whether this config requires a credential at send time.
    #[must_use]
    pub fn requires_credential(&self) -> bool {
        matches!(self, OtlpEndpointAuth::BrokerBearer(_))
    }
}

/// The live, broker-mediated injection path. Compiled only with the `otlp` feature
/// (it is exercised against a real collector out-of-band; the deterministic core
/// never reaches it).
#[cfg(feature = "otlp")]
mod live {
    use super::OtlpEndpointAuth;
    use crustcore_secrets::{
        BrokerError, CredentialProxy, HeaderInjection, SecretBroker, SecretStore, ViewError,
    };
    use crustcore_types::{ApprovalId, Timestamp};

    /// Why per-request endpoint auth could not be produced.
    #[derive(Debug)]
    pub enum AuthError {
        /// No credential is configured (the `None` variant) — caller should send
        /// without an auth header.
        NoCredentialConfigured,
        /// The broker could not mint a view for the configured handle.
        Broker(BrokerError),
        /// The minted view was consumed or expired before injection.
        View(ViewError),
    }

    impl OtlpEndpointAuth {
        /// Resolves the per-request `Authorization` header through the broker.
        ///
        /// The token is materialized only inside a one-shot
        /// [`crustcore_secrets::ApprovedSecretView`] and immediately moved into a
        /// non-model-visible [`HeaderInjection`]; it never enters env, a span, or
        /// model context (invariant 1). The returned injection is wired into the
        /// exporter's outbound POST headers by [`crate::export::otlp::OtlpExporter::send`];
        /// only the live socket smoke against a real collector is `TODO(C6-otlp-live)`.
        ///
        /// # Errors
        /// [`AuthError`] if no credential is configured, the broker refuses, or the
        /// view is consumed/expired.
        pub fn inject<S: SecretStore>(
            &self,
            broker: &SecretBroker<S>,
            approval_id: ApprovalId,
            now: Timestamp,
            ttl_millis: u64,
        ) -> Result<HeaderInjection, AuthError> {
            let handle = match self {
                OtlpEndpointAuth::None => return Err(AuthError::NoCredentialConfigured),
                OtlpEndpointAuth::BrokerBearer(h) => h,
            };
            let view = broker
                .authorize(handle.id, approval_id, now, ttl_millis)
                .map_err(AuthError::Broker)?;
            CredentialProxy::bearer(&view, now, handle.label.as_str()).map_err(AuthError::View)
        }
    }
}

#[cfg(feature = "otlp")]
pub use live::AuthError;

#[cfg(test)]
mod tests {
    use super::*;
    use crustcore_types::{BoundedText, SecretId};

    fn handle() -> SecretHandle {
        SecretHandle {
            id: SecretId(1),
            label: BoundedText::new("otlp-collector-token").unwrap(),
        }
    }

    #[test]
    fn default_is_none_and_needs_no_credential() {
        let a = OtlpEndpointAuth::default();
        assert!(matches!(a, OtlpEndpointAuth::None));
        assert!(!a.requires_credential());
    }

    #[test]
    fn broker_bearer_holds_only_a_handle_not_bytes() {
        let a = OtlpEndpointAuth::broker_bearer(handle());
        assert!(a.requires_credential());
        // The Debug form carries the (non-secret) label only — no value (the value
        // never enters this type).
        let dbg = format!("{a:?}");
        assert!(dbg.contains("otlp-collector-token"));
    }
}
