// SPDX-License-Identifier: Apache-2.0
//! The mandatory redaction + bounding gate (C6T.3) — the **sole emission
//! chokepoint** from the pre-redaction IR to any exporter.
//!
//! Nothing in this crate may hand a [`SpanModel`]/[`MetricSample`] to an exporter
//! except via [`redact_frame`]. It does three things, in order, to **every**
//! attribute value and metric-label value:
//!
//! 1. **Redact.** Run the value through [`crustcore_secrets::Redactor::redact`],
//!    which scrubs every registered secret (invariants 1–3). A secret in a span is a
//!    release-blocker leak; this is the one place that guarantees it cannot happen.
//! 2. **Bound the value.** Truncate to [`MAX_ATTR_LEN`] bytes (char-boundary safe).
//!    We bound *after* redaction so truncation can never split a half-redacted
//!    secret and leak a fragment.
//! 3. **Bound the count.** Keep at most [`MAX_ATTRS`] attributes/labels per span or
//!    metric; the rest are **dropped** (never silently merged), and a single
//!    `crustcore.telemetry.attrs_dropped` marker records how many — so an adversarial
//!    log with thousands of attributes cannot blow the exporter (invariant 11).
//!
//! Span and metric *names* are **not** redacted — they come only from the closed
//! [`crustcore_kernel::EventKind`] enum (see [`crate::semconv`]) and are never
//! payload-derived, so there is nothing secret to scrub. (The leak-canary test in
//! `tests/` still asserts no sentinel appears in any name, as defense in depth.)

use crustcore_secrets::Redactor;

use crate::project::{MetricSample, ProjectedFrame, SpanModel};

/// Maximum bytes for a single redacted attribute value / metric-label value.
/// Bounded *after* redaction (invariant 11; bounded-everything).
pub const MAX_ATTR_LEN: usize = 1024;

/// Maximum number of attributes per span (or labels per metric) that may be
/// emitted. Excess are dropped, with a count marker added.
pub const MAX_ATTRS: usize = 64;

/// The marker attribute/label recording how many entries were dropped by the
/// [`MAX_ATTRS`] bound (so the truncation is itself observable).
pub const DROPPED_MARKER_KEY: &str = "crustcore.telemetry.attrs_dropped";

/// Truncates `s` to at most [`MAX_ATTR_LEN`] bytes on a char boundary. Applied
/// only to already-redacted text, so it can never split a secret.
fn bound_value(s: String) -> String {
    if s.len() <= MAX_ATTR_LEN {
        return s;
    }
    let mut end = MAX_ATTR_LEN;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = s;
    out.truncate(end);
    out
}

/// Redacts + bounds one list of `(key, value)` pairs. The key is left as-is (keys
/// come from constant attribute-name tables, never payload), the value is redacted
/// and length-bounded, and the list is count-bounded with a dropped-count marker.
fn redact_pairs(pairs: &[(String, String)], redactor: &Redactor) -> Vec<(String, String)> {
    let total = pairs.len();
    let keep = total.min(MAX_ATTRS);
    let mut out: Vec<(String, String)> = Vec::with_capacity(keep + 1);
    for (k, v) in pairs.iter().take(keep) {
        let redacted = redactor.redact(v);
        out.push((k.clone(), bound_value(redacted)));
    }
    if total > keep {
        out.push((DROPPED_MARKER_KEY.to_string(), (total - keep).to_string()));
    }
    out
}

/// Redacts + bounds a single span. The name is untouched (enum-derived); every
/// attribute value is passed through the redactor and bounded.
#[must_use]
pub fn redact_span(span: &SpanModel, redactor: &Redactor) -> SpanModel {
    SpanModel {
        name: span.name.clone(),
        attrs: redact_pairs(&span.attrs, redactor),
    }
}

/// Redacts + bounds a single metric sample. The name and numeric value are
/// untouched (numbers carry no secret text); every label value is redacted and
/// bounded.
#[must_use]
pub fn redact_metric(metric: &MetricSample, redactor: &Redactor) -> MetricSample {
    MetricSample {
        name: metric.name.clone(),
        value: metric.value,
        labels: redact_pairs(&metric.labels, redactor),
    }
}

/// The single chokepoint: redacts + bounds an entire [`ProjectedFrame`]. The
/// returned IR is the **only** form an exporter may consume.
#[must_use]
pub fn redact_frame(frame: &ProjectedFrame, redactor: &Redactor) -> ProjectedFrame {
    ProjectedFrame {
        spans: frame
            .spans
            .iter()
            .map(|s| redact_span(s, redactor))
            .collect(),
        metrics: frame
            .metrics
            .iter()
            .map(|m| redact_metric(m, redactor))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redactor_with(secret: &str) -> Redactor {
        let mut r = Redactor::new();
        r.register("model-key", secret.as_bytes());
        r
    }

    #[test]
    fn attribute_value_is_redacted() {
        let r = redactor_with("sk-SENTINEL");
        let span =
            SpanModel::new("gen_ai.model_request").attr("note", "calling with sk-SENTINEL now");
        let out = redact_span(&span, &r);
        let v = &out.attrs[0].1;
        assert!(!v.contains("sk-SENTINEL"), "secret survived: {v}");
        assert!(v.contains("[REDACTED:model-key]"));
        assert!(!r.would_leak(v));
    }

    #[test]
    fn metric_label_is_redacted() {
        let r = redactor_with("sk-SENTINEL");
        let m = MetricSample::new("crustcore.budget.tokens", 10).label("ctx", "sk-SENTINEL");
        let out = redact_metric(&m, &r);
        assert!(!out.labels[0].1.contains("sk-SENTINEL"));
        // The numeric value is preserved.
        assert_eq!(out.value, 10);
    }

    #[test]
    fn value_length_is_bounded_after_redaction() {
        let r = Redactor::new();
        let long = "x".repeat(MAX_ATTR_LEN * 3);
        let span = SpanModel::new("crustcore.event.task_created").attr("k", long);
        let out = redact_span(&span, &r);
        assert!(out.attrs[0].1.len() <= MAX_ATTR_LEN);
    }

    #[test]
    fn truncation_on_char_boundary_does_not_panic() {
        let r = Redactor::new();
        // Multi-byte chars right at the boundary.
        let s = "é".repeat(MAX_ATTR_LEN); // 2 bytes each
        let span = SpanModel::new("crustcore.event.task_created").attr("k", s);
        let out = redact_span(&span, &r);
        assert!(out.attrs[0].1.len() <= MAX_ATTR_LEN);
        // Still valid UTF-8 (Rust String guarantees it, but assert the bound held).
        assert!(out.attrs[0].1.is_char_boundary(out.attrs[0].1.len()));
    }

    #[test]
    fn attribute_count_is_bounded_with_marker() {
        let r = Redactor::new();
        let mut span = SpanModel::new("crustcore.event.task_created");
        for i in 0..(MAX_ATTRS + 50) {
            span = span.attr(format!("k{i}"), "v");
        }
        let out = redact_span(&span, &r);
        // Kept <= MAX_ATTRS real attrs, plus exactly one dropped marker.
        assert_eq!(out.attrs.len(), MAX_ATTRS + 1);
        let marker = out
            .attrs
            .iter()
            .find(|(k, _)| k == DROPPED_MARKER_KEY)
            .expect("dropped marker present");
        assert_eq!(marker.1, "50");
    }

    #[test]
    fn no_marker_when_under_the_cap() {
        let r = Redactor::new();
        let span = SpanModel::new("x").attr("a", "1").attr("b", "2");
        let out = redact_span(&span, &r);
        assert_eq!(out.attrs.len(), 2);
        assert!(!out.attrs.iter().any(|(k, _)| k == DROPPED_MARKER_KEY));
    }

    #[test]
    fn redact_frame_covers_spans_and_metrics() {
        let r = redactor_with("sk-SENTINEL");
        let frame = ProjectedFrame {
            spans: vec![SpanModel::new("s").attr("a", "x sk-SENTINEL")],
            metrics: vec![MetricSample::new("m", 1).label("l", "y sk-SENTINEL")],
        };
        let out = redact_frame(&frame, &r);
        assert!(!out.spans[0].attrs[0].1.contains("sk-SENTINEL"));
        assert!(!out.metrics[0].labels[0].1.contains("sk-SENTINEL"));
    }
}
