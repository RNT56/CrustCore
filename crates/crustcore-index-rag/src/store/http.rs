// SPDX-License-Identifier: Apache-2.0
//! Shared HTTP plumbing for the external vector-store backends (C5-qdrant-live /
//! C5-lancedb-live) — compiled only when the `qdrant` **or** `lancedb` feature is on.
//!
//! Both adapters are *thin* [`VectorStore`](super::VectorStore) clients over a small,
//! blocking [`ureq`] agent (the same client `crustcore-net`/`crustcore-telemetry` use —
//! NOT a second Tokio/TLS runtime; invariants 19, 20). This module holds what they share:
//!
//! - the agent builder + bounded request timeout,
//! - the **broker-mediated auth seam** ([`EndpointAuth`]): any API key is resolved per
//!   request through [`crustcore_secrets::CredentialProxy`] at send time and wired
//!   straight into an outbound header — never read from env, never logged, never
//!   model-visible (invariants 1, 3; `docs/secrets.md` §6),
//! - response bounding + score sanitization helpers,
//! - the [`StoreSendError`] type (carries no secret material).
//!
//! Trust posture is unchanged from the inert stub: the store is **retrieval only** and its
//! scores are **not trusted** — [`crate::plan::QueryPlanner`] re-ranks every hit by cosine
//! to the query embedding and redact-then-bounds it. These helpers therefore only need to
//! be *safe* (bounded, panic-free, non-finite-scrubbed), not *authoritative*.

use super::{ChunkId, MAX_STORE_HITS};

/// Bounded request timeout for a live POST/PUT (mirrors `crustcore-net` / the OTLP
/// exporter). A store that hangs cannot stall the planner indefinitely.
const REQUEST_TIMEOUT_SECS: u64 = 30;

/// A parsed search hit from an external store: an opaque id + a raw score. The score is
/// sanitized to finite-or-`0.0` here as defense in depth, but it is **not trusted for
/// ranking** — the planner re-ranks by cosine to the query embedding (`plan.rs`), so a
/// hostile/NaN store score cannot reorder or smuggle a fragment. Carries no content.
#[derive(Debug, Clone, PartialEq)]
pub struct StoreHit {
    /// The store's id for the chunk (used to resolve content via the planner's resolver;
    /// a forged/unknown id simply yields no fragment).
    pub id: ChunkId,
    /// The store-reported similarity, already sanitized to finite-or-`0.0`. Advisory only.
    pub score: f32,
}

/// Sanitizes a store-reported score to a finite value (`NaN`/`±inf` → `0.0`). Defense in
/// depth: the planner re-ranks anyway, so this only guarantees we never *carry* a
/// non-finite score out of the adapter.
#[must_use]
pub fn sanitize_score(score: f32) -> f32 {
    if score.is_finite() {
        score
    } else {
        0.0
    }
}

/// Caps a parsed hit list to [`MAX_STORE_HITS`] (a hostile/buggy store that ignores the
/// requested `limit` cannot return an oversized payload). The planner additionally
/// truncates + dedups, but bounding here keeps the adapter's own allocation bounded.
pub fn bound_hits(mut hits: Vec<StoreHit>) -> Vec<StoreHit> {
    hits.truncate(MAX_STORE_HITS);
    hits
}

/// Builds the shared blocking [`ureq`] agent with the bounded timeout.
#[must_use]
pub fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .build()
}

/// How an external store authenticates. **Non-secret config**: it names *which*
/// broker-held secret to use (by [`crustcore_secrets::SecretHandle`]) and *how* to frame
/// it, never the value. The bytes are resolved per request through the broker at send
/// time and never live in this type.
///
/// Two outbound schemes are supported, matching the two stores' native conventions:
/// - [`BrokerBearer`](EndpointAuth::BrokerBearer): `Authorization: Bearer <token>`, minted
///   through the canonical [`crustcore_secrets::CredentialProxy::bearer`] path (LanceDB
///   Cloud uses this).
/// - [`BrokerHeader`](EndpointAuth::BrokerHeader): a bespoke `header_name: <token>` (Qdrant
///   Cloud's native scheme is `api-key: <token>`). The token is read **once** from a
///   one-shot [`crustcore_secrets::ApprovedSecretView`] and set straight onto the
///   `ureq` request — never into a `String`, log, span, or model-visible surface.
#[derive(Debug, Clone, Default)]
pub enum EndpointAuth {
    /// No authentication (the default; appropriate for a loopback dev store).
    #[default]
    None,
    /// An `Authorization: Bearer <token>` header resolved at send time from the broker
    /// via this handle (e.g. LanceDB Cloud).
    BrokerBearer(crustcore_secrets::SecretHandle),
    /// A bespoke header (e.g. Qdrant's `api-key: <token>`) resolved at send time from the
    /// broker via this handle. The header *name* is non-secret config; the *value* is the
    /// broker-held token, read once and set directly onto the outbound request.
    BrokerHeader {
        /// The non-secret outbound header name (e.g. `api-key`).
        header_name: String,
        /// The handle naming the broker-held token (id + label; never the bytes).
        handle: crustcore_secrets::SecretHandle,
    },
}

/// The per-request authorization context threaded into every broker-mediated store call:
/// the broker to resolve the credential through, the approval authorizing this use, the
/// current time, and the view's TTL. Grouping these keeps the `*_with_broker` signatures
/// small and makes the "credential resolved per request through the broker" contract one
/// argument. Holds **no** secret bytes — only a `&SecretBroker` and plain ids/time.
pub struct BrokerAuth<'b, S: crustcore_secrets::SecretStore> {
    /// The broker that mints the one-shot credential view at send time.
    pub broker: &'b crustcore_secrets::SecretBroker<S>,
    /// The approval authorizing this credential use.
    pub approval_id: crustcore_types::ApprovalId,
    /// The current time (for view minting + expiry).
    pub now: crustcore_types::Timestamp,
    /// How long the minted view is valid, in milliseconds.
    pub ttl_millis: u64,
}

impl<'b, S: crustcore_secrets::SecretStore> BrokerAuth<'b, S> {
    /// Builds the context from its parts.
    #[must_use]
    pub fn new(
        broker: &'b crustcore_secrets::SecretBroker<S>,
        approval_id: crustcore_types::ApprovalId,
        now: crustcore_types::Timestamp,
        ttl_millis: u64,
    ) -> Self {
        BrokerAuth {
            broker,
            approval_id,
            now,
            ttl_millis,
        }
    }
}

impl EndpointAuth {
    /// No-auth (loopback default).
    #[must_use]
    pub fn none() -> Self {
        EndpointAuth::None
    }

    /// `Authorization: Bearer <token>` from the broker-held secret `handle`.
    #[must_use]
    pub fn bearer(handle: crustcore_secrets::SecretHandle) -> Self {
        EndpointAuth::BrokerBearer(handle)
    }

    /// A custom `header_name: <token>` from the broker-held secret `handle` (Qdrant's
    /// convention is `api-key`).
    #[must_use]
    pub fn header(header_name: impl Into<String>, handle: crustcore_secrets::SecretHandle) -> Self {
        EndpointAuth::BrokerHeader {
            header_name: header_name.into(),
            handle,
        }
    }

    /// Whether this config requires a credential at send time.
    #[must_use]
    pub fn requires_credential(&self) -> bool {
        !matches!(self, EndpointAuth::None)
    }
}

/// Resolves `auth` through the broker **only** and applies the resulting header to `req`.
///
/// The credential is materialized solely inside a one-shot
/// [`crustcore_secrets::ApprovedSecretView`] and read **once** — for the bearer scheme via
/// the canonical [`crustcore_secrets::CredentialProxy::bearer`] →
/// [`crustcore_secrets::HeaderInjection::reveal`], and for the custom-header scheme via
/// [`crustcore_secrets::ApprovedSecretView::expose`] straight onto the request header. In
/// neither case does the token enter env, a `String`, a log, a span, or model context
/// (invariants 1, 3). [`EndpointAuth::None`] returns `req` unchanged (loopback dev store).
///
/// # Errors
/// [`StoreSendError::Auth`] if the broker refuses, the minted view is consumed/expired, or
/// the token is not header-safe UTF-8.
pub fn apply_auth<S: crustcore_secrets::SecretStore>(
    req: ureq::Request,
    auth: &EndpointAuth,
    ctx: &BrokerAuth<'_, S>,
) -> Result<ureq::Request, StoreSendError> {
    match auth {
        EndpointAuth::None => Ok(req),
        EndpointAuth::BrokerBearer(handle) => {
            let view = ctx
                .broker
                .authorize(handle.id, ctx.approval_id, ctx.now, ctx.ttl_millis)
                .map_err(|_| StoreSendError::Auth)?;
            // Canonical bearer path: the token is moved into a non-model-visible
            // HeaderInjection, read once here, never into a String/log.
            let inj =
                crustcore_secrets::CredentialProxy::bearer(&view, ctx.now, handle.label.as_str())
                    .map_err(|_| StoreSendError::Auth)?;
            let value = std::str::from_utf8(inj.reveal()).map_err(|_| StoreSendError::Auth)?;
            Ok(req.set(inj.header_name(), value))
        }
        EndpointAuth::BrokerHeader {
            header_name,
            handle,
        } => {
            let view = ctx
                .broker
                .authorize(handle.id, ctx.approval_id, ctx.now, ctx.ttl_millis)
                .map_err(|_| StoreSendError::Auth)?;
            // Custom-header path (e.g. Qdrant `api-key`): expose the one-shot view's bytes
            // ONCE and set them directly as the header value. The bytes never enter a
            // String we keep, a log, or model context; `set` copies into ureq's internal
            // header map for this single request only.
            let token = view.expose(ctx.now).map_err(|_| StoreSendError::Auth)?;
            let value = std::str::from_utf8(token).map_err(|_| StoreSendError::Auth)?;
            Ok(req.set(header_name, value))
        }
    }
}

/// Why a live store request failed. Carries **no secret material**: the `Transport` string
/// is `ureq`'s connection diagnostic, never the request body or the auth header.
#[derive(Debug)]
pub enum StoreSendError {
    /// The request body could not be serialized.
    Serialize,
    /// The broker refused, or the minted view was consumed/expired, when resolving the
    /// per-request auth header. (No secret bytes are included.)
    Auth,
    /// The HTTP transport failed to reach the store.
    Transport(String),
    /// The store returned a non-2xx status (the round-trip succeeded but the store
    /// rejected the request). The body is intentionally not carried.
    Status(u16),
    /// The store's response body could not be parsed into the expected shape.
    BadResponse,
}

impl core::fmt::Display for StoreSendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StoreSendError::Serialize => write!(f, "vector-store request serialization failed"),
            StoreSendError::Auth => write!(f, "vector-store endpoint auth could not be resolved"),
            StoreSendError::Transport(m) => write!(f, "vector-store transport error: {m}"),
            StoreSendError::Status(s) => write!(f, "vector-store returned status {s}"),
            StoreSendError::BadResponse => write!(f, "vector-store response was malformed"),
        }
    }
}

impl std::error::Error for StoreSendError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crustcore_secrets::SecretHandle;
    use crustcore_types::{BoundedText, SecretId};

    fn handle() -> SecretHandle {
        SecretHandle {
            id: SecretId(1),
            label: BoundedText::new("store-api-key").unwrap(),
        }
    }

    #[test]
    fn sanitize_score_scrubs_nonfinite() {
        assert_eq!(sanitize_score(0.7), 0.7);
        assert_eq!(sanitize_score(f32::NAN), 0.0);
        assert_eq!(sanitize_score(f32::INFINITY), 0.0);
        assert_eq!(sanitize_score(f32::NEG_INFINITY), 0.0);
    }

    #[test]
    fn bound_hits_caps_at_max() {
        let many: Vec<StoreHit> = (0..(MAX_STORE_HITS + 50))
            .map(|i| StoreHit {
                id: ChunkId::new(format!("id-{i}")),
                score: 0.5,
            })
            .collect();
        assert_eq!(bound_hits(many).len(), MAX_STORE_HITS);
    }

    #[test]
    fn auth_none_requires_no_credential() {
        let a = EndpointAuth::none();
        assert!(!a.requires_credential());
    }

    #[test]
    fn auth_variants_hold_only_a_handle_not_bytes() {
        let bearer = EndpointAuth::bearer(handle());
        assert!(bearer.requires_credential());
        let header = EndpointAuth::header("api-key", handle());
        assert!(header.requires_credential());
        // The Debug form carries only the (non-secret) label — the value never enters
        // these types (there is no field for it).
        assert!(format!("{bearer:?}").contains("store-api-key"));
        assert!(format!("{header:?}").contains("store-api-key"));
    }

    #[test]
    fn bearer_auth_resolves_through_broker_without_exposing_to_model() {
        // Exercise the canonical bearer minting path directly (the same one apply_auth
        // uses) to prove the token is broker-mediated and never model-visible.
        let mut store = crustcore_secrets::InMemoryStore::new();
        store.insert(SecretId(1), "store-api-key", b"sk-SENTINELxyz".to_vec());
        let broker = crustcore_secrets::SecretBroker::new(store);
        let view = broker
            .authorize(
                SecretId(1),
                crustcore_types::ApprovalId(1),
                crustcore_types::Timestamp::from_millis(1000),
                5_000,
            )
            .unwrap();
        let inj = crustcore_secrets::CredentialProxy::bearer(
            &view,
            crustcore_types::Timestamp::from_millis(1001),
            "store-api-key",
        )
        .unwrap();
        // Trusted outbound code can read the real header bytes...
        assert_eq!(inj.reveal(), b"Bearer sk-SENTINELxyz");
        assert_eq!(inj.header_name(), "Authorization");
        // ...but the model-/log-safe rendering never contains the token.
        assert!(!inj.redacted().contains("SENTINEL"));
    }
}
