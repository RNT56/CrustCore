// SPDX-License-Identifier: Apache-2.0
//! Exporters (C6T.4): the sink for the **post-redaction** IR.
//!
//! An [`Exporter`] consumes only [`SpanModel`]/[`MetricSample`] values that have
//! already passed [`crate::redact`] — it never sees a raw `FrameRef` or a
//! pre-redaction IR. This keeps the redaction chokepoint structurally enforced: the
//! exporter trait's input type is the post-redaction IR, so there is no method that
//! could accept unredacted data.
//!
//! Two exporters ship:
//! - [`InMemoryExporter`] — the CI default. It captures every emitted span/metric so
//!   tests can assert span shape, names, bounding, and (crucially) that no secret
//!   sentinel ever reaches it.
//! - [`otlp::OtlpExporter`] — behind the `otlp` cargo feature. The OTLP/HTTP+JSON
//!   exporter is implemented (IR→JSON serialization + a `ureq` POST); only the live
//!   socket smoke is `TODO(C6-otlp-live)`. The deterministic core never needs it.

#[cfg(feature = "otlp")]
pub mod otlp;

use crate::project::{MetricSample, ProjectedFrame, SpanModel};

/// A span or metric that an exporter received. Used by [`InMemoryExporter`] so
/// tests can assert exactly what was emitted, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Emitted {
    /// A redacted span.
    Span(SpanModel),
    /// A redacted metric sample.
    Metric(MetricSample),
}

/// A sink for **already-redacted** telemetry. Implementors must treat the input as
/// final (it has passed the [`crate::redact`] chokepoint) and must never widen it
/// back to a frame/payload.
///
/// `export_frame` has a default impl that fans a [`ProjectedFrame`] out to
/// [`export_span`](Exporter::export_span) / [`export_metric`](Exporter::export_metric)
/// in order, so implementors only need the two primitive methods.
pub trait Exporter {
    /// Exports one redacted span.
    fn export_span(&mut self, span: &SpanModel);

    /// Exports one redacted metric sample.
    fn export_metric(&mut self, metric: &MetricSample);

    /// Exports a whole redacted frame (spans then metrics, in order).
    fn export_frame(&mut self, frame: &ProjectedFrame) {
        for s in &frame.spans {
            self.export_span(s);
        }
        for m in &frame.metrics {
            self.export_metric(m);
        }
    }

    /// Flushes any buffered telemetry. The in-memory exporter is a no-op; the OTLP
    /// exporter would flush its batch to the collector here.
    fn flush(&mut self) {}
}

/// The CI default exporter: records every emitted span/metric in order for
/// assertions. Holds no network/SDK state.
#[derive(Debug, Default, Clone)]
pub struct InMemoryExporter {
    emitted: Vec<Emitted>,
}

impl InMemoryExporter {
    /// A new, empty in-memory exporter.
    #[must_use]
    pub fn new() -> Self {
        InMemoryExporter {
            emitted: Vec::new(),
        }
    }

    /// Everything emitted so far, in order.
    #[must_use]
    pub fn emitted(&self) -> &[Emitted] {
        &self.emitted
    }

    /// Only the spans emitted, in order.
    #[must_use]
    pub fn spans(&self) -> Vec<&SpanModel> {
        self.emitted
            .iter()
            .filter_map(|e| match e {
                Emitted::Span(s) => Some(s),
                Emitted::Metric(_) => None,
            })
            .collect()
    }

    /// Only the metrics emitted, in order.
    #[must_use]
    pub fn metrics(&self) -> Vec<&MetricSample> {
        self.emitted
            .iter()
            .filter_map(|e| match e {
                Emitted::Metric(m) => Some(m),
                Emitted::Span(_) => None,
            })
            .collect()
    }

    /// Every string an exporter could surface: span/metric names plus all
    /// attribute/label keys and values. The leak-canary test scans this for a
    /// sentinel, so it must cover *every* emitted string.
    #[must_use]
    pub fn all_strings(&self) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::new();
        for e in &self.emitted {
            match e {
                Emitted::Span(s) => {
                    out.push(s.name.as_str());
                    for (k, v) in &s.attrs {
                        out.push(k.as_str());
                        out.push(v.as_str());
                    }
                }
                Emitted::Metric(m) => {
                    out.push(m.name.as_str());
                    for (k, v) in &m.labels {
                        out.push(k.as_str());
                        out.push(v.as_str());
                    }
                }
            }
        }
        out
    }
}

impl Exporter for InMemoryExporter {
    fn export_span(&mut self, span: &SpanModel) {
        self.emitted.push(Emitted::Span(span.clone()));
    }

    fn export_metric(&mut self, metric: &MetricSample) {
        self.emitted.push(Emitted::Metric(metric.clone()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_exporter_records_in_order() {
        let mut e = InMemoryExporter::new();
        let frame = ProjectedFrame {
            spans: vec![SpanModel::new("s1"), SpanModel::new("s2")],
            metrics: vec![MetricSample::new("m1", 1)],
        };
        e.export_frame(&frame);
        assert_eq!(e.spans().len(), 2);
        assert_eq!(e.metrics().len(), 1);
        assert_eq!(e.emitted().len(), 3);
        // Spans before metrics (default fan-out order).
        assert!(matches!(e.emitted()[0], Emitted::Span(_)));
        assert!(matches!(e.emitted()[2], Emitted::Metric(_)));
    }

    #[test]
    fn all_strings_covers_names_keys_and_values() {
        let mut e = InMemoryExporter::new();
        e.export_span(&SpanModel::new("the.name").attr("the.key", "the value"));
        e.export_metric(&MetricSample::new("m.name", 9).label("lk", "lv"));
        let s = e.all_strings();
        assert!(s.contains(&"the.name"));
        assert!(s.contains(&"the.key"));
        assert!(s.contains(&"the value"));
        assert!(s.contains(&"m.name"));
        assert!(s.contains(&"lk"));
        assert!(s.contains(&"lv"));
    }
}
