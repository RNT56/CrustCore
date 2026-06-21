// SPDX-License-Identifier: Apache-2.0
//! The OTLP exporter (C6T.4), behind the `otlp` cargo feature only.
//!
//! The real OTel/OTLP SDK is heavy (Tokio/HTTP/protobuf) and runs spawned/sidecar —
//! **never linked into nano** (invariants 19, 20). This module is the seam where it
//! plugs in. The live socket is `TODO(C6-otlp-live)`: today it ships a minimal,
//! dependency-free stub that buffers the post-redaction IR and, on `flush`, would
//! hand it to the SDK over the broker-authenticated endpoint
//! ([`crate::auth::OtlpEndpointAuth`]). The deterministic projection core does not
//! need this exporter; CI uses [`crate::export::InMemoryExporter`].
//!
//! Like every [`Exporter`], it consumes only the post-redaction IR — there is no
//! path here that sees a raw frame or a secret value (the endpoint credential is
//! resolved per-request via the broker, never stored in a span).

use crate::auth::OtlpEndpointAuth;
use crate::export::Exporter;
use crate::project::{MetricSample, SpanModel};

/// An OTLP/HTTP exporter. The endpoint URL is non-secret config; the bearer/header
/// (if any) is resolved per-request via [`OtlpEndpointAuth`] at send time — never
/// from env, never placed in a span (invariant 1).
///
/// `TODO(C6-otlp-live)`: replace the in-process buffer with the real OTLP SDK
/// transport. The buffer keeps the type usable and testable behind the feature
/// without pulling the heavy stack into the default build.
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

    /// Number of spans currently buffered (awaiting `flush`).
    #[must_use]
    pub fn buffered_span_count(&self) -> usize {
        self.buffered_spans.len()
    }
}

impl Exporter for OtlpExporter {
    fn export_span(&mut self, span: &SpanModel) {
        self.buffered_spans.push(span.clone());
    }

    fn export_metric(&mut self, metric: &MetricSample) {
        self.buffered_metrics.push(metric.clone());
    }

    fn flush(&mut self) {
        // TODO(C6-otlp-live): resolve the per-request auth header via
        // `self.auth.inject(...)` and POST the OTLP payload to `self.endpoint`
        // through the OTel SDK / spawned helper. Until then, dropping the buffer is
        // the fail-closed behavior (no telemetry leaves the process).
        let _ = &self.auth;
        self.buffered_spans.clear();
        self.buffered_metrics.clear();
    }
}

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
        e.flush();
        assert_eq!(e.buffered_span_count(), 0);
    }
}
