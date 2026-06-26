// SPDX-License-Identifier: Apache-2.0
//! The neutral, SDK-free telemetry IR and the pure [`EventProjector`] (C6T.1).
//!
//! [`EventProjector::project`] is a **pure, synchronous, deterministic** mapper
//! from a borrowed event-log frame (+ its joined [`crustcore_receipts::ToolReceipt`]
//! when present) to a [`ProjectedFrame`] holding zero or more [`SpanModel`]s and
//! [`MetricSample`]s. It performs **no I/O**, depends on **no OTel SDK**, mutates
//! nothing (its inputs are borrowed), and is idempotent — projecting the same input
//! twice yields equal output.
//!
//! Crucially, the projector does **not** decode arbitrary frame payloads (which are
//! untrusted data, invariant 7). It maps from typed [`FrameMeta`] header fields and
//! the (MAC-bound) receipt fields only. Span/metric *names* come solely from
//! [`semconv`], which keys off the closed [`crustcore_kernel::EventKind`] enum.
//!
//! This module produces the **pre-redaction** IR. Nothing here is safe to export
//! until it passes [`crate::redact`], the sole emission chokepoint.

use crustcore_eventlog::FrameMeta;
use crustcore_receipts::ToolReceipt;

use crate::semconv;
use crate::usage::RecordedUsage;

/// A span in the neutral IR: a name (from the closed [`crustcore_kernel::EventKind`]
/// enum) and a bounded list of key/value attributes. Values here are
/// **pre-redaction**; they must pass [`crate::redact`] before export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpanModel {
    /// The span name (e.g. `gen_ai.model_request`, `crustcore.tool.completed`).
    /// Derived only from the event kind — never from payload.
    pub name: String,
    /// Attribute key/value pairs (pre-redaction).
    pub attrs: Vec<(String, String)>,
}

impl SpanModel {
    /// A span with `name` and no attributes.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        SpanModel {
            name: name.into(),
            attrs: Vec::new(),
        }
    }

    /// Adds a `(key, value)` attribute (builder style).
    #[must_use]
    pub fn attr(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attrs.push((key.into(), value.into()));
        self
    }
}

/// A metric sample in the neutral IR: a name (from the closed
/// [`crustcore_kernel::EventKind`] enum), a `u64` value, and bounded labels.
/// Label *values* are **pre-redaction**; they must pass [`crate::redact`] before
/// export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricSample {
    /// The metric name (e.g. `crustcore.budget.wall_millis`). Derived only from
    /// the event kind / budget axis — never from payload.
    pub name: String,
    /// The metric value.
    pub value: u64,
    /// Label key/value pairs (pre-redaction).
    pub labels: Vec<(String, String)>,
}

impl MetricSample {
    /// A metric `name = value` with no labels.
    #[must_use]
    pub fn new(name: impl Into<String>, value: u64) -> Self {
        MetricSample {
            name: name.into(),
            value,
            labels: Vec::new(),
        }
    }

    /// Adds a `(key, value)` label (builder style).
    #[must_use]
    pub fn label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.labels.push((key.into(), value.into()));
        self
    }
}

/// The IR produced for one frame: the spans and metrics it projects to. May be
/// empty (e.g. a kind we do not map to telemetry).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectedFrame {
    /// Spans derived from this frame (pre-redaction).
    pub spans: Vec<SpanModel>,
    /// Metric samples derived from this frame (pre-redaction).
    pub metrics: Vec<MetricSample>,
}

impl ProjectedFrame {
    /// Whether this projection produced nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.spans.is_empty() && self.metrics.is_empty()
    }
}

/// A pure, deterministic, SDK-free mapper from audit frames to the telemetry IR.
///
/// Stateless and zero-sized: construct with [`EventProjector::new`] (or
/// [`Default`]). `project` borrows its inputs and never mutates state, so it is
/// trivially idempotent and read-only (invariant 6/13: telemetry mints nothing).
#[derive(Debug, Clone, Copy, Default)]
pub struct EventProjector;

impl EventProjector {
    /// A new projector.
    #[must_use]
    pub fn new() -> Self {
        EventProjector
    }

    /// Projects one frame (+ its joined receipt, if any) to the IR, with no
    /// recorded GenAI usage. Equivalent to [`project_with_usage`] with `usage =
    /// None`; kept for callers that have no model-usage carrier.
    ///
    /// [`project_with_usage`]: EventProjector::project_with_usage
    #[must_use]
    pub fn project(&self, meta: &FrameMeta, receipt: Option<&ToolReceipt>) -> ProjectedFrame {
        self.project_with_usage(meta, receipt, None)
    }

    /// Projects one frame (+ its joined receipt + trusted recorded usage) to the IR.
    ///
    /// The mapping is delegated entirely to [`semconv`]: the span/metric *names*
    /// derive only from `meta.kind` (the closed [`crustcore_kernel::EventKind`]
    /// enum), and attributes come only from typed [`FrameMeta`] / [`ToolReceipt`]
    /// fields and the trusted [`RecordedUsage`] carrier — never from the (untrusted)
    /// payload. `receipt` is honored only for a `ToolCallCompleted` frame, and
    /// `usage` only for the model-frame kinds; for every other kind each is ignored
    /// (a forged receipt or usage cannot inject attributes onto an unrelated span).
    /// An absent `usage` emits no model/usage attributes (no fabricated tokens).
    ///
    /// This is **pre-redaction** IR; callers must run it through [`crate::redact`]
    /// before handing it to an exporter.
    #[must_use]
    pub fn project_with_usage(
        &self,
        meta: &FrameMeta,
        receipt: Option<&ToolReceipt>,
        usage: Option<&RecordedUsage>,
    ) -> ProjectedFrame {
        semconv::project_frame(meta, receipt, usage)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crustcore_kernel::{Actor, EventKind, Visibility};
    use crustcore_types::{EventSeq, TaskId, Timestamp};

    fn meta(seq: u64, kind: EventKind) -> FrameMeta {
        FrameMeta::new(seq, kind)
            .task(TaskId(1))
            .actor(Actor::Adapter)
            .visibility(Visibility::ModelVisible)
            .timestamp(Timestamp::from_millis(seq * 10))
    }

    #[test]
    fn projector_is_zero_sized_and_default() {
        assert_eq!(std::mem::size_of::<EventProjector>(), 0);
        let _: EventProjector = Default::default();
    }

    #[test]
    fn project_is_idempotent_and_borrows_only() {
        let p = EventProjector::new();
        let m = meta(3, EventKind::ModelRequestStarted);
        let a = p.project(&m, None);
        let b = p.project(&m, None);
        assert_eq!(a, b, "projection must be deterministic / idempotent");
        // The input is untouched (borrowed): re-projecting still works.
        assert_eq!(p.project(&m, None), a);
        assert_eq!(m.seq, EventSeq(3));
    }

    #[test]
    fn span_and_metric_builders_accumulate() {
        let s = SpanModel::new("x").attr("a", "1").attr("b", "2");
        assert_eq!(s.attrs.len(), 2);
        let mm = MetricSample::new("m", 7).label("k", "v");
        assert_eq!(mm.value, 7);
        assert_eq!(mm.labels.len(), 1);
    }
}
