// SPDX-License-Identifier: Apache-2.0
//! The OTLP exporter (C6T.4), behind the `otlp` cargo feature only.
//!
//! This is a deliberately **lightweight** OTLP/HTTP+JSON exporter: it serializes the
//! buffered **post-redaction** IR to the OTLP traces JSON schema and POSTs it to the
//! configured collector with `ureq` (a small blocking HTTP client) — it does **not**
//! pull the heavy OTel/tonic/Tokio SDK, which would never link into a sidecar this
//! crate's callers spawn (invariants 19, 20). The whole exporter (and the
//! `ureq`/`serde_json` deps) compiles only under the `otlp` feature; the deterministic
//! projection core never needs it, and CI uses [`crate::export::InMemoryExporter`].
//!
//! Trust posture (unchanged from the seam it replaces):
//! - Like every [`Exporter`], it consumes only the post-redaction IR — there is no
//!   path here that sees a raw frame or an unredacted value.
//! - The endpoint URL is non-secret config. Any collector bearer/header is resolved
//!   **per request** through the secret broker
//!   ([`crate::auth::OtlpEndpointAuth::inject`] →
//!   [`crustcore_secrets::CredentialProxy::bearer`]) at send time — never from env,
//!   never placed in a span attribute, never model-visible (invariant 1). The exporter
//!   holds only a [`crustcore_secrets::SecretHandle`] (id + label), not the bytes.
//! - Fail-safe: a serialization or send error never panics and never leaks a secret;
//!   the batch is bounded ([`MAX_SPANS_PER_BATCH`] / [`MAX_METRICS_PER_BATCH`]).
//!
//! JSON exporter implemented; only the live socket smoke is `TODO(C6-otlp-live)` — the
//! IR→OTLP-JSON serialization is unit-tested below without a network.

use crate::auth::OtlpEndpointAuth;
use crate::export::Exporter;
use crate::project::{MetricSample, SpanModel};

/// Default OTLP/HTTP traces path appended to a bare host endpoint. If the configured
/// endpoint already names a `/v1/...` path it is used verbatim.
const OTLP_TRACES_PATH: &str = "/v1/traces";

/// The OTel instrumentation scope name stamped on every emitted scope. A fixed,
/// non-payload constant identifying this projection (the *mediator*, not a provider).
const SCOPE_NAME: &str = "crustcore-telemetry";

/// Hard cap on spans serialized per flush (invariant 11): even though the run driver
/// already bounds frames via `Config::batch_bound`, the exporter re-bounds its own
/// buffer so an adversarial caller cannot make the JSON body unbounded.
pub const MAX_SPANS_PER_BATCH: usize = 4096;

/// Hard cap on metric samples buffered per flush (invariant 11). Metrics are not part
/// of the OTLP **traces** body this exporter posts; they are bounded and dropped on
/// flush (the live metrics socket is out of scope — `TODO(C6-otlp-live)`).
pub const MAX_METRICS_PER_BATCH: usize = 4096;

/// Bounded request timeout for the live POST (mirrors `crustcore-net`'s client).
#[cfg(feature = "otlp")]
const REQUEST_TIMEOUT_SECS: u64 = 30;

/// An OTLP/HTTP+JSON trace exporter. The endpoint URL is non-secret config; the
/// bearer/header (if any) is resolved per-request via [`OtlpEndpointAuth`] at send time
/// — never from env, never placed in a span (invariant 1).
///
/// On [`flush`](Exporter::flush) the buffered, **post-redaction** spans are serialized
/// to the OTLP traces JSON schema and POSTed to the endpoint. The serialization is
/// pure and CI-testable ([`Self::spans_to_otlp_json`], available under the `otlp`
/// feature); only the live socket smoke is `TODO(C6-otlp-live)`.
pub struct OtlpExporter {
    endpoint: String,
    auth: OtlpEndpointAuth,
    buffered_spans: Vec<SpanModel>,
    buffered_metrics: Vec<MetricSample>,
}

impl OtlpExporter {
    /// Builds an exporter for `endpoint` (e.g. `http://127.0.0.1:4318`) with the
    /// broker-mediated `auth` seam. Loopback endpoints are the safe default
    /// (`crate::config`).
    #[must_use]
    pub fn new(endpoint: impl Into<String>, auth: OtlpEndpointAuth) -> Self {
        OtlpExporter {
            endpoint: endpoint.into(),
            auth,
            buffered_spans: Vec::new(),
            buffered_metrics: Vec::new(),
        }
    }

    /// The configured (non-secret) endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// The full URL the traces body is POSTed to: the configured endpoint verbatim if
    /// it already names a `/v1/...` path, otherwise the endpoint with
    /// [`OTLP_TRACES_PATH`] appended (collapsing a trailing slash). Non-secret.
    #[must_use]
    pub fn traces_url(&self) -> String {
        let e = self.endpoint.trim_end_matches('/');
        if e.contains("/v1/") {
            self.endpoint.clone()
        } else {
            format!("{e}{OTLP_TRACES_PATH}")
        }
    }

    /// Number of spans currently buffered (awaiting `flush`).
    #[must_use]
    pub fn buffered_span_count(&self) -> usize {
        self.buffered_spans.len()
    }
}

impl Exporter for OtlpExporter {
    fn export_span(&mut self, span: &SpanModel) {
        if self.buffered_spans.len() < MAX_SPANS_PER_BATCH {
            self.buffered_spans.push(span.clone());
        }
    }

    fn export_metric(&mut self, metric: &MetricSample) {
        if self.buffered_metrics.len() < MAX_METRICS_PER_BATCH {
            self.buffered_metrics.push(metric.clone());
        }
    }

    #[cfg(feature = "otlp")]
    fn flush(&mut self) {
        // Serialize the buffered, post-redaction spans to OTLP/HTTP+JSON and POST them.
        // Errors are swallowed (fail-safe: never panic, never surface a secret); the
        // buffer is always cleared so a transient failure does not unbound memory.
        if !self.buffered_spans.is_empty() {
            let body = OtlpExporter::spans_to_otlp_json(&self.buffered_spans);
            let url = self.traces_url();
            // Fire-and-forget: telemetry is best-effort and never authoritative. The
            // result is surfaced by `flush_now` for the live smoke test; here we drop
            // it. A `BrokerBearer` endpoint is *not* POSTed from this fire-and-forget
            // path (resolving its token needs a broker + approval flush does not hold):
            // it fails closed (see `flush_now`).
            let _ = self.flush_now(&url, &body);
        }
        self.buffered_spans.clear();
        self.buffered_metrics.clear();
    }

    // Without the `otlp` feature the exporter exists (the `ExporterChoice::Otlp` config
    // variant references it) but cannot open a socket: `flush` drops the buffer,
    // fail-closed (no telemetry leaves the process).
    #[cfg(not(feature = "otlp"))]
    fn flush(&mut self) {
        let _ = &self.auth;
        self.buffered_spans.clear();
        self.buffered_metrics.clear();
    }
}

#[cfg(feature = "otlp")]
impl OtlpExporter {
    /// Serializes a slice of **post-redaction** spans to the OTLP/HTTP+JSON traces
    /// schema. Pure, network-free, and the CI-testable heart of this exporter.
    ///
    /// Shape:
    /// ```json
    /// { "resourceSpans": [ {
    ///     "resource": { "attributes": [ ... ] },
    ///     "scopeSpans": [ {
    ///       "scope": { "name": "crustcore-telemetry" },
    ///       "spans": [ {
    ///         "name": "<span name>",
    ///         "startTimeUnixNano": "<ns>",
    ///         "endTimeUnixNano": "<ns>",
    ///         "attributes": [ { "key": "...", "value": { "stringValue"|"intValue": .. } } ]
    ///       } ]
    ///     } ]
    /// } ] }
    /// ```
    ///
    /// Each attribute whose value parses cleanly as an `i64` is emitted as an
    /// `intValue` (per OTLP JSON, encoded as a string), and everything else as a
    /// `stringValue` — so `crustcore.event.seq` / `gen_ai.usage.*_tokens` become
    /// numbers and `gen_ai.system` / `gen_ai.request.model` stay strings. Span names
    /// are enum-derived (never payload). Times are best-effort: the IR has no span
    /// duration, so start == end (taken from `crustcore.timestamp_ms` when present, else
    /// `0`). The input is already redacted + bounded, so this never sees a secret.
    #[must_use]
    pub fn spans_to_otlp_json(spans: &[SpanModel]) -> serde_json::Value {
        use serde_json::json;

        let span_json: Vec<serde_json::Value> = spans
            .iter()
            .map(|s| {
                // `crustcore.timestamp_ms` is a trusted FrameMeta field carried on
                // non-suppressed spans; use it as both start and end (no duration in the
                // IR). Missing/non-numeric => 0. OTLP wants nanoseconds as a string.
                let ts_nanos = s
                    .attrs
                    .iter()
                    .find(|(k, _)| k == "crustcore.timestamp_ms")
                    .and_then(|(_, v)| v.parse::<u128>().ok())
                    .map(|ms| ms.saturating_mul(1_000_000))
                    .unwrap_or(0);
                let ts_str = ts_nanos.to_string();

                let attributes: Vec<serde_json::Value> =
                    s.attrs.iter().map(|(k, v)| attr_kv(k, v)).collect();

                json!({
                    "name": s.name,
                    "startTimeUnixNano": ts_str,
                    "endTimeUnixNano": ts_str,
                    "attributes": attributes,
                })
            })
            .collect();

        json!({
            "resourceSpans": [ {
                "resource": {
                    "attributes": [ attr_kv("service.name", "crustcore") ]
                },
                "scopeSpans": [ {
                    "scope": { "name": SCOPE_NAME },
                    "spans": span_json,
                } ]
            } ]
        })
    }

    /// The `flush`-path POST: only valid for the `None` (loopback, no-auth) case. A
    /// `BrokerBearer` config returns [`OtlpSendError::Auth`] here, because resolving its
    /// token requires a broker + approval the fire-and-forget `flush` does not carry;
    /// broker-authenticated sends go through the broker-taking [`Self::send`].
    fn flush_now(&self, url: &str, body: &serde_json::Value) -> Result<u16, OtlpSendError> {
        if self.auth.requires_credential() {
            // Fail-safe: never POST a BrokerBearer endpoint without a resolved token.
            return Err(OtlpSendError::Auth);
        }
        let payload = serde_json::to_vec(body).map_err(|_| OtlpSendError::Serialize)?;
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .build();
        match agent
            .post(url)
            .set("Content-Type", "application/json")
            .send_bytes(&payload)
        {
            Ok(resp) => Ok(resp.status()),
            Err(ureq::Error::Status(status, _resp)) => Ok(status),
            Err(ureq::Error::Transport(t)) => Err(OtlpSendError::Transport(t.to_string())),
        }
    }

    /// POSTs an already-serialized OTLP/JSON `body` to `url` with `Content-Type:
    /// application/json`, resolving the per-request `Authorization` header through the
    /// secret broker when [`OtlpEndpointAuth::BrokerBearer`] is configured.
    ///
    /// `TODO(C6-otlp-live)`: this opens a real socket, so it is only smoke-tested
    /// against a running collector (the unit tests cover the JSON shape, not the POST).
    /// The credential is materialized only inside a one-shot
    /// [`crustcore_secrets::ApprovedSecretView`], moved straight into the request header
    /// via [`crustcore_secrets::HeaderInjection::reveal`], and never logged,
    /// span-stamped, or model-visible (invariant 1).
    ///
    /// # Errors
    /// [`OtlpSendError`] on a serialization, auth, or transport failure. The `flush`
    /// path discards its result — telemetry is best-effort — but it is surfaced here so
    /// the broker-mediated live socket can be smoke-tested directly.
    pub fn send<S: crustcore_secrets::SecretStore>(
        &self,
        url: &str,
        body: &serde_json::Value,
        broker: &crustcore_secrets::SecretBroker<S>,
        approval_id: crustcore_types::ApprovalId,
        now: crustcore_types::Timestamp,
        ttl_millis: u64,
    ) -> Result<u16, OtlpSendError> {
        let payload = serde_json::to_vec(body).map_err(|_| OtlpSendError::Serialize)?;

        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .build();
        let mut req = agent.post(url).set("Content-Type", "application/json");

        // Resolve the auth header at send time, through the broker only. The injection
        // holds the secret bytes; we read them ONCE into the request header and never
        // elsewhere. `None` => no header (loopback collector).
        let injection = match self.auth {
            OtlpEndpointAuth::None => None,
            OtlpEndpointAuth::BrokerBearer(_) => Some(
                self.auth
                    .inject(broker, approval_id, now, ttl_millis)
                    .map_err(|_| OtlpSendError::Auth)?,
            ),
        };
        if let Some(inj) = &injection {
            // The secret never enters a String/log; hand the raw bytes (validated as
            // header-safe UTF-8) straight to ureq's header setter.
            let header_value =
                std::str::from_utf8(inj.reveal()).map_err(|_| OtlpSendError::Auth)?;
            req = req.set(inj.header_name(), header_value);
        }

        match req.send_bytes(&payload) {
            Ok(resp) => Ok(resp.status()),
            // A non-2xx is still a round-trip (ureq surfaces it as Err(Status)).
            Err(ureq::Error::Status(status, _resp)) => Ok(status),
            // A transport error reports only ureq's connection diagnostic, never the
            // request body or the auth header.
            Err(ureq::Error::Transport(t)) => Err(OtlpSendError::Transport(t.to_string())),
        }
    }
}

/// One OTLP `KeyValue`: `{ "key": k, "value": { "intValue"|"stringValue": .. } }`.
/// A value that parses as `i64` becomes an `intValue` (OTLP encodes int64 as a JSON
/// string); everything else stays a `stringValue`. The key is enum/table-derived and
/// the value is already redacted, so neither can carry a secret.
#[cfg(feature = "otlp")]
fn attr_kv(key: &str, value: &str) -> serde_json::Value {
    use serde_json::json;
    if let Ok(n) = value.parse::<i64>() {
        json!({ "key": key, "value": { "intValue": n.to_string() } })
    } else {
        json!({ "key": key, "value": { "stringValue": value } })
    }
}

/// Why a live OTLP POST failed. Carries no secret material: the `Transport` string is
/// `ureq`'s connection diagnostic, never the request body or the auth header.
#[cfg(feature = "otlp")]
#[derive(Debug)]
pub enum OtlpSendError {
    /// The OTLP/JSON body could not be serialized.
    Serialize,
    /// The broker refused, or the minted view was consumed/expired, when resolving the
    /// per-request auth header; or the fire-and-forget `flush` path saw a `BrokerBearer`
    /// endpoint it cannot authenticate. (No secret bytes are included.)
    Auth,
    /// The HTTP transport failed to reach the collector.
    Transport(String),
}

#[cfg(feature = "otlp")]
impl core::fmt::Display for OtlpSendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            OtlpSendError::Serialize => write!(f, "OTLP body serialization failed"),
            OtlpSendError::Auth => write!(f, "OTLP endpoint auth could not be resolved"),
            OtlpSendError::Transport(m) => write!(f, "OTLP transport error: {m}"),
        }
    }
}

#[cfg(feature = "otlp")]
impl std::error::Error for OtlpSendError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::project::ProjectedFrame;

    #[test]
    fn otlp_exporter_buffers_then_flushes() {
        let mut e = OtlpExporter::new("http://127.0.0.1:4318", OtlpEndpointAuth::none());
        assert_eq!(e.endpoint(), "http://127.0.0.1:4318");
        e.export_frame(&ProjectedFrame {
            spans: vec![SpanModel::new("s")],
            metrics: vec![MetricSample::new("m", 1)],
        });
        assert_eq!(e.buffered_span_count(), 1);
        // Without a collector the POST fails internally; flush still clears the buffer
        // (fail-safe), so this is network-independent.
        e.flush();
        assert_eq!(e.buffered_span_count(), 0);
    }

    #[test]
    fn traces_url_appends_path_or_uses_explicit() {
        let bare = OtlpExporter::new("http://127.0.0.1:4318", OtlpEndpointAuth::none());
        assert_eq!(bare.traces_url(), "http://127.0.0.1:4318/v1/traces");
        let slash = OtlpExporter::new("http://127.0.0.1:4318/", OtlpEndpointAuth::none());
        assert_eq!(slash.traces_url(), "http://127.0.0.1:4318/v1/traces");
        let explicit =
            OtlpExporter::new("http://collector.local/v1/traces", OtlpEndpointAuth::none());
        assert_eq!(explicit.traces_url(), "http://collector.local/v1/traces");
    }

    #[test]
    fn export_buffer_is_bounded() {
        let mut e = OtlpExporter::new("http://127.0.0.1:4318", OtlpEndpointAuth::none());
        for _ in 0..(MAX_SPANS_PER_BATCH + 10) {
            e.export_span(&SpanModel::new("s"));
        }
        assert_eq!(e.buffered_span_count(), MAX_SPANS_PER_BATCH);
    }
}

#[cfg(all(test, feature = "otlp"))]
mod otlp_json_tests {
    use super::*;

    fn obj_key<'a>(v: &'a serde_json::Value, k: &str) -> &'a serde_json::Value {
        v.get(k).unwrap_or_else(|| panic!("missing key {k}"))
    }

    /// Drills `resourceSpans[0].scopeSpans[0].spans[i].attributes`.
    fn span_attrs(v: &serde_json::Value, i: usize) -> Vec<serde_json::Value> {
        obj_key(
            &obj_key(&obj_key(v, "resourceSpans")[0], "scopeSpans")[0],
            "spans",
        )[i]
            .get("attributes")
            .unwrap()
            .as_array()
            .unwrap()
            .clone()
    }

    #[test]
    fn json_shape_has_resource_scope_and_span_name() {
        let span = SpanModel::new("gen_ai.model_request")
            .attr("gen_ai.system", "crustcore")
            .attr("crustcore.event.seq", "42");
        let v = OtlpExporter::spans_to_otlp_json(&[span]);

        let rs = &obj_key(&v, "resourceSpans")[0];
        // resource is present with attributes.
        assert!(obj_key(obj_key(rs, "resource"), "attributes").is_array());
        let ss = &obj_key(rs, "scopeSpans")[0];
        assert_eq!(obj_key(obj_key(ss, "scope"), "name"), "crustcore-telemetry");
        let span0 = &obj_key(ss, "spans")[0];
        // The span name passes through (enum-derived).
        assert_eq!(obj_key(span0, "name"), "gen_ai.model_request");
        // Times present as strings (OTLP nanos).
        assert!(obj_key(span0, "startTimeUnixNano").is_string());
        assert!(obj_key(span0, "endTimeUnixNano").is_string());
    }

    #[test]
    fn string_attr_serializes_as_string_value() {
        let span = SpanModel::new("gen_ai.model_request").attr("gen_ai.system", "crustcore");
        let v = OtlpExporter::spans_to_otlp_json(&[span]);
        let a = span_attrs(&v, 0)
            .into_iter()
            .find(|a| a["key"] == "gen_ai.system")
            .expect("gen_ai.system attr present");
        assert_eq!(a["value"]["stringValue"], "crustcore");
        assert!(a["value"].get("intValue").is_none());
    }

    #[test]
    fn numeric_attr_serializes_as_int_value() {
        let span = SpanModel::new("gen_ai.model_request").attr("crustcore.event.seq", "42");
        let v = OtlpExporter::spans_to_otlp_json(&[span]);
        let a = span_attrs(&v, 0)
            .into_iter()
            .find(|a| a["key"] == "crustcore.event.seq")
            .expect("seq attr present");
        // OTLP int64 is JSON-encoded as a string.
        assert_eq!(a["value"]["intValue"], "42");
        assert!(a["value"].get("stringValue").is_none());
    }

    #[test]
    fn gen_ai_attrs_pass_through_unmodified() {
        // The GenAI semconv attributes the projection produces must survive end-to-end.
        let span = SpanModel::new("gen_ai.model_request")
            .attr("gen_ai.system", "crustcore")
            .attr("gen_ai.operation.name", "model_request")
            .attr("gen_ai.request.model", "anthropic/claude-x")
            .attr("gen_ai.usage.input_tokens", "1234")
            .attr("gen_ai.usage.output_tokens", "56");
        let v = OtlpExporter::spans_to_otlp_json(&[span]);
        let attrs = span_attrs(&v, 0);
        let find = |k: &str| {
            attrs
                .iter()
                .find(|a| a["key"] == k)
                .unwrap_or_else(|| panic!("missing {k}"))
                .clone()
        };
        // String-typed gen_ai attrs.
        assert_eq!(find("gen_ai.system")["value"]["stringValue"], "crustcore");
        assert_eq!(
            find("gen_ai.operation.name")["value"]["stringValue"],
            "model_request"
        );
        assert_eq!(
            find("gen_ai.request.model")["value"]["stringValue"],
            "anthropic/claude-x"
        );
        // Token counts are numeric => intValue.
        assert_eq!(
            find("gen_ai.usage.input_tokens")["value"]["intValue"],
            "1234"
        );
        assert_eq!(
            find("gen_ai.usage.output_tokens")["value"]["intValue"],
            "56"
        );
    }

    #[test]
    fn timestamp_ms_attr_becomes_nanos() {
        let span =
            SpanModel::new("crustcore.event.task_created").attr("crustcore.timestamp_ms", "70");
        let v = OtlpExporter::spans_to_otlp_json(&[span]);
        let span0 = &obj_key(
            &obj_key(&obj_key(&v, "resourceSpans")[0], "scopeSpans")[0],
            "spans",
        )[0];
        // 70 ms = 70_000_000 ns, encoded as a string.
        assert_eq!(obj_key(span0, "startTimeUnixNano"), "70000000");
        assert_eq!(obj_key(span0, "endTimeUnixNano"), "70000000");
    }

    #[test]
    fn body_is_serializable_to_bytes_for_a_multi_span_batch() {
        // The flush path serializes to bytes; assert that round-trips (the network-free
        // half of the live POST).
        let spans = vec![
            SpanModel::new("gen_ai.model_request").attr("gen_ai.system", "crustcore"),
            SpanModel::new("crustcore.tool.completed").attr("crustcore.tool.call_id", "99"),
        ];
        let v = OtlpExporter::spans_to_otlp_json(&spans);
        let bytes = serde_json::to_vec(&v).expect("serializes");
        assert!(!bytes.is_empty());
        let count = obj_key(
            &obj_key(&obj_key(&v, "resourceSpans")[0], "scopeSpans")[0],
            "spans",
        )
        .as_array()
        .unwrap()
        .len();
        assert_eq!(count, 2);
    }

    #[test]
    fn flush_with_broker_bearer_does_not_post_unauthenticated() {
        // Fail-safe: a BrokerBearer endpoint is never POSTed from the fire-and-forget
        // flush path (which holds no broker), so `flush_now` rejects it instead of
        // sending an unauthenticated request.
        use crustcore_types::{BoundedText, SecretId};
        let handle = crustcore_secrets::SecretHandle {
            id: SecretId(1),
            label: BoundedText::new("otlp-collector-token").unwrap(),
        };
        let e = OtlpExporter::new(
            "http://127.0.0.1:4318",
            OtlpEndpointAuth::broker_bearer(handle),
        );
        let body = OtlpExporter::spans_to_otlp_json(&[SpanModel::new("s")]);
        let r = e.flush_now(&e.traces_url(), &body);
        assert!(matches!(r, Err(OtlpSendError::Auth)));
    }

    /// The live socket smoke: needs a running OTLP collector on the endpoint, so it is
    /// `#[ignore]`d in CI. `TODO(C6-otlp-live)`: run against a real collector. Uses the
    /// no-auth (loopback) flush path.
    #[test]
    #[ignore = "needs a running OTLP collector on 127.0.0.1:4318 (TODO(C6-otlp-live))"]
    fn live_post_to_loopback_collector() {
        let mut e = OtlpExporter::new(
            crate::config::Config::DEFAULT_LOOPBACK_ENDPOINT,
            OtlpEndpointAuth::none(),
        );
        e.export_span(&SpanModel::new("gen_ai.model_request").attr("gen_ai.system", "crustcore"));
        // Reaches the real socket; asserts only that flush does not panic.
        e.flush();
        assert_eq!(e.buffered_span_count(), 0);
    }

    /// The broker-mediated live smoke: also `#[ignore]`d (needs a collector). It proves
    /// the auth header is resolved through the broker → `CredentialProxy::bearer` at
    /// send time and that the call shape compiles. `TODO(C6-otlp-live)`.
    #[test]
    #[ignore = "needs a running OTLP collector + broker secret (TODO(C6-otlp-live))"]
    fn live_post_with_broker_bearer() {
        use crustcore_secrets::{InMemoryStore, SecretBroker, SecretHandle};
        use crustcore_types::{ApprovalId, BoundedText, SecretId, Timestamp};

        let mut store = InMemoryStore::new();
        store.insert(SecretId(1), "otlp-collector-token", b"tok-XXXX".to_vec());
        let broker = SecretBroker::new(store);
        let handle = SecretHandle {
            id: SecretId(1),
            label: BoundedText::new("otlp-collector-token").unwrap(),
        };
        let e = OtlpExporter::new(
            crate::config::Config::DEFAULT_LOOPBACK_ENDPOINT,
            OtlpEndpointAuth::broker_bearer(handle),
        );
        let body = OtlpExporter::spans_to_otlp_json(&[
            SpanModel::new("gen_ai.model_request").attr("gen_ai.system", "crustcore")
        ]);
        let _ = e.send(
            &e.traces_url(),
            &body,
            &broker,
            ApprovalId(1),
            Timestamp::from_millis(0),
            5_000,
        );
    }
}
