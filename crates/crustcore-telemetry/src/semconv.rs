// SPDX-License-Identifier: Apache-2.0
//! The GenAI-semantic-convention mapping table (C6T.2): the closed
//! [`EventKind`] enum → span name + attribute set, and the budget projection.
//!
//! ## Invariant: names come only from the enum
//!
//! Every span name and metric name in this module is a **compile-time constant**
//! chosen by an exhaustive `match` on [`EventKind`]. No name is ever derived from
//! frame payload (untrusted data, invariant 7) or from any model output — so a
//! crafted payload cannot inject a span/metric name that downstream tooling might
//! mis-trust as authoritative (invariants 6, 7). Because the `match` is exhaustive,
//! adding a new `EventKind` forces a decision here rather than silently defaulting.
//!
//! ## Span families
//!
//! | Frame kind(s)                                    | Span/metric name(s)               |
//! |--------------------------------------------------|-----------------------------------|
//! | `ModelRequestStarted`                            | `gen_ai.model_request`            |
//! | `ModelOutputReceived`                            | `gen_ai.model_response`           |
//! | `ToolCallStarted`                                | `crustcore.tool.started`          |
//! | `ToolCallCompleted` (+ joined receipt)           | `crustcore.tool.completed`        |
//! | `PatchProposed`                                  | `crustcore.verify.proposed`       |
//! | `PatchVerified`                                  | `crustcore.verify.verified`       |
//! | `PatchRejected`                                  | `crustcore.verify.rejected`       |
//! | `JobLeased`                                      | `crustcore.budget.lease` (metric) |
//! | every other kind                                 | `crustcore.event.<kind>` (generic)|
//!
//! ## Attributes are typed, not payload
//!
//! Attributes are sourced only from [`FrameMeta`] header fields (`seq`, `actor`,
//! `task_id`, `job_id`, `timestamp`, `kind`) and, for the tool-completed span, from
//! the MAC-bound [`ToolReceipt`] (tool-name hash, args hash, result hash, MAC,
//! tool-call id, event seq) — never from the payload bytes. GenAI `gen_ai.*` model
//! attributes (system/model/usage) are intentionally **conservative**: `FrameMeta`
//! does not carry the `ModelCard` capability metadata or token usage, and free-text
//! model output is untrusted (invariant 17), so we emit only the typed audit facts
//! (`gen_ai.operation.name`, `gen_ai.system`, and the audit ids). A live wiring that
//! threads recorded `ModelCard`/usage metadata into these spans is a follow-up
//! (`TODO(C6-genai-usage)`); it must come from recorded capability metadata, never
//! from model output.
//!
//! All values produced here are **pre-redaction**: they pass through
//! [`crate::redact`] (the sole emission chokepoint) before any exporter sees them.

use crustcore_eventlog::{FrameMeta, RedactionState};
use crustcore_kernel::{EventKind, Visibility};
use crustcore_receipts::ToolReceipt;
use crustcore_types::BudgetAxis;

use crate::project::{MetricSample, ProjectedFrame, SpanModel};

/// The OTel `gen_ai.system` value for CrustCore-mediated model calls. A fixed
/// constant (not payload-derived): it identifies the *mediator*, not the provider.
pub const GEN_AI_SYSTEM: &str = "crustcore";

/// Returns the span/metric **name** for an [`EventKind`]. This is the single
/// authoritative name map and is keyed *only* by the enum (invariants 6, 7).
///
/// Exhaustive by construction: a new `EventKind` will not compile until it is
/// mapped, so no kind silently falls through to an unstable name.
#[must_use]
pub fn span_name(kind: EventKind) -> &'static str {
    match kind {
        EventKind::ModelRequestStarted => "gen_ai.model_request",
        EventKind::ModelOutputReceived => "gen_ai.model_response",
        EventKind::ToolCallStarted => "crustcore.tool.started",
        EventKind::ToolCallCompleted => "crustcore.tool.completed",
        EventKind::PatchProposed => "crustcore.verify.proposed",
        EventKind::PatchVerified => "crustcore.verify.verified",
        EventKind::PatchRejected => "crustcore.verify.rejected",
        EventKind::JobLeased => "crustcore.budget.lease",
        // Every remaining kind projects to a stable generic event span, named from
        // the enum's canonical lowercase token (still NOT payload-derived).
        EventKind::TaskCreated => "crustcore.event.task_created",
        EventKind::TaskPlanned => "crustcore.event.task_planned",
        EventKind::JobQueued => "crustcore.event.job_queued",
        EventKind::ToolCallRequested => "crustcore.event.tool_call_requested",
        EventKind::ToolCallApproved => "crustcore.event.tool_call_approved",
        EventKind::ToolCallDenied => "crustcore.event.tool_call_denied",
        EventKind::SandboxStarted => "crustcore.event.sandbox_started",
        EventKind::CommandStarted => "crustcore.event.command_started",
        EventKind::CommandOutputCaptured => "crustcore.event.command_output_captured",
        EventKind::CommandCompleted => "crustcore.event.command_completed",
        EventKind::ApprovalRequested => "crustcore.event.approval_requested",
        EventKind::ApprovalResolved => "crustcore.event.approval_resolved",
        EventKind::UserMessageQueued => "crustcore.event.user_message_queued",
        EventKind::UserSteerReceived => "crustcore.event.user_steer_received",
        EventKind::GitHubOperationRequested => "crustcore.event.github_operation_requested",
        EventKind::GitHubOperationCompleted => "crustcore.event.github_operation_completed",
        EventKind::SecretRequested => "crustcore.event.secret_requested",
        EventKind::SecretHandleStored => "crustcore.event.secret_handle_stored",
        EventKind::RiskDetected => "crustcore.event.risk_detected",
        EventKind::TaskCompleted => "crustcore.event.task_completed",
        EventKind::TaskFailed => "crustcore.event.task_failed",
        EventKind::TaskKilled => "crustcore.event.task_killed",
    }
}

/// The metric name for a budget axis. Constant per axis; never payload-derived.
#[must_use]
pub fn budget_metric_name(axis: BudgetAxis) -> &'static str {
    match axis {
        BudgetAxis::WallMillis => "crustcore.budget.wall_millis",
        BudgetAxis::CpuMillis => "crustcore.budget.cpu_millis",
        BudgetAxis::MemoryBytes => "crustcore.budget.memory_bytes",
        BudgetAxis::DiskBytes => "crustcore.budget.disk_bytes",
        BudgetAxis::OutputBytes => "crustcore.budget.output_bytes",
        BudgetAxis::Tokens => "crustcore.budget.tokens",
        BudgetAxis::ModelCostMicros => "crustcore.budget.model_cost_micros",
        BudgetAxis::SubagentCount => "crustcore.budget.subagent_count",
    }
}

/// Projects a [`crustcore_types::BudgetDelta`] (what an event consumed) to one
/// [`MetricSample`] per non-zero axis, labelled by task/job. `FrameMeta` does not
/// carry budget data (consumption lives on the in-memory `Event`, not the logged
/// frame), so this is the seam a caller uses when it *holds* the delta — e.g. an
/// adapter projecting a `JobLeased`/budget-bearing event. Names come only from the
/// closed [`BudgetAxis`] table (never payload); values are integer counts (no secret
/// text, but they still pass [`crate::redact`] for the labels at the chokepoint).
#[must_use]
pub fn budget_samples(
    delta: &crustcore_types::BudgetDelta,
    task_id: Option<crustcore_types::TaskId>,
    job_id: Option<crustcore_types::JobId>,
) -> Vec<MetricSample> {
    let mut out = Vec::new();
    for axis in BudgetAxis::ALL {
        let amount = delta.amount(axis);
        if amount == 0 {
            continue;
        }
        let mut sample = MetricSample::new(budget_metric_name(axis), amount);
        if let Some(t) = task_id {
            sample = sample.label("crustcore.task_id", t.0.to_string());
        }
        if let Some(j) = job_id {
            sample = sample.label("crustcore.job_id", j.0.to_string());
        }
        out.push(sample);
    }
    out
}

/// Lowercase-hex of the first `n` bytes of a hash, for a compact, non-secret span
/// attribute (a full 32-byte hex is allowed too; receipts carry only hashes/MACs,
/// never values — invariant 10). `n` is clamped to the array length.
fn hex_prefix(bytes: &[u8; 32], n: usize) -> String {
    let n = n.min(bytes.len());
    let mut s = String::with_capacity(n * 2);
    for b in &bytes[..n] {
        use core::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// The audit attributes every span carries — sourced only from typed [`FrameMeta`]
/// header fields, never from payload. These identify *where in the authoritative
/// log* the span came from, so a consumer can always go back to the real evidence.
fn base_attrs(meta: &FrameMeta) -> Vec<(String, String)> {
    let mut attrs = vec![
        (
            "crustcore.event.kind".to_string(),
            format!("{:?}", meta.kind),
        ),
        ("crustcore.event.seq".to_string(), meta.seq.0.to_string()),
        ("crustcore.actor".to_string(), format!("{:?}", meta.actor)),
        (
            "crustcore.timestamp_ms".to_string(),
            meta.timestamp.as_millis().to_string(),
        ),
    ];
    if let Some(t) = meta.task_id {
        attrs.push(("crustcore.task_id".to_string(), t.0.to_string()));
    }
    if let Some(j) = meta.job_id {
        attrs.push(("crustcore.job_id".to_string(), j.0.to_string()));
    }
    attrs
}

/// Whether a frame's payload-derived attributes must be suppressed. An
/// `Internal`-visibility frame or a `Redacted` frame projects to **kind + seq
/// only** (no payload-derived attributes), honoring the log's own gates
/// (`docs/event-log.md` §8; invariants 2, 3). Note: nothing in this crate reads the
/// payload bytes anyway, but receipt-derived attributes (hashes/MAC) and the GenAI
/// operation hints are gated here for defense in depth.
#[must_use]
pub fn payload_derived_suppressed(meta: &FrameMeta) -> bool {
    meta.visibility == Visibility::Internal || meta.redaction == RedactionState::Redacted
}

/// The minimal "kind + seq only" span used when payload-derived attributes are
/// suppressed (Internal / Redacted frames). It still carries no payload.
fn minimal_span(meta: &FrameMeta) -> SpanModel {
    SpanModel {
        name: span_name(meta.kind).to_string(),
        attrs: vec![
            (
                "crustcore.event.kind".to_string(),
                format!("{:?}", meta.kind),
            ),
            ("crustcore.event.seq".to_string(), meta.seq.0.to_string()),
        ],
    }
}

/// Projects one frame (+ joined receipt) to the IR. The single mapping entry point
/// used by [`crate::project::EventProjector`].
#[must_use]
pub fn project_frame(meta: &FrameMeta, receipt: Option<&ToolReceipt>) -> ProjectedFrame {
    // Visibility/redaction gate (C6T.6 / dimension (d)): Internal or Redacted frames
    // emit only kind+seq — no actor, no ids, no receipt hashes, no GenAI hints.
    if payload_derived_suppressed(meta) {
        return ProjectedFrame {
            spans: vec![minimal_span(meta)],
            metrics: Vec::new(),
        };
    }

    let name = span_name(meta.kind);
    let mut span = SpanModel {
        name: name.to_string(),
        attrs: base_attrs(meta),
    };

    match meta.kind {
        EventKind::ModelRequestStarted | EventKind::ModelOutputReceived => {
            // GenAI semconv: the operation + the *mediator* system. Deliberately
            // conservative — no model name/usage from untrusted output (invariant 17).
            let op = if meta.kind == EventKind::ModelRequestStarted {
                "model_request"
            } else {
                "model_response"
            };
            span.attrs
                .push(("gen_ai.operation.name".to_string(), op.to_string()));
            span.attrs
                .push(("gen_ai.system".to_string(), GEN_AI_SYSTEM.to_string()));
        }
        EventKind::ToolCallCompleted => {
            // Bind the span to its receipt via P5-join (consumed, not re-implemented).
            // Receipts carry only hashes/ids/MAC — never values (invariant 10), so
            // these attributes are safe and prove the tool result is the real one.
            if let Some(r) = receipt {
                span.attrs.push((
                    "crustcore.tool.call_id".to_string(),
                    r.tool_call_id.0.to_string(),
                ));
                span.attrs.push((
                    "crustcore.tool.name_hash".to_string(),
                    hex_prefix(&r.tool_name_hash, 32),
                ));
                span.attrs.push((
                    "crustcore.tool.args_hash".to_string(),
                    hex_prefix(&r.args_hash, 32),
                ));
                span.attrs.push((
                    "crustcore.tool.result_hash".to_string(),
                    hex_prefix(&r.result_hash, 32),
                ));
                span.attrs
                    .push(("crustcore.tool.mac".to_string(), hex_prefix(&r.mac, 32)));
                span.attrs.push((
                    "crustcore.tool.receipt_event_seq".to_string(),
                    r.event_seq.0.to_string(),
                ));
                span.attrs.push((
                    "crustcore.tool.artifact_count".to_string(),
                    r.artifact_hashes.len().to_string(),
                ));
            } else {
                // No receipt joined: record the absence honestly. A model-visible
                // "tool completed" with no receipt is exactly the case invariant 10
                // guards — downstream can flag it.
                span.attrs
                    .push(("crustcore.tool.receipt".to_string(), "absent".to_string()));
            }
        }
        EventKind::PatchVerified => {
            span.attrs.push((
                "crustcore.verify.outcome".to_string(),
                "verified".to_string(),
            ));
        }
        EventKind::PatchRejected => {
            span.attrs.push((
                "crustcore.verify.outcome".to_string(),
                "rejected".to_string(),
            ));
        }
        EventKind::PatchProposed => {
            span.attrs.push((
                "crustcore.verify.outcome".to_string(),
                "proposed".to_string(),
            ));
        }
        _ => {}
    }

    ProjectedFrame {
        spans: vec![span],
        metrics: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crustcore_kernel::Actor;
    use crustcore_receipts::{MacKey, ReceiptChain, ReceiptParams};
    use crustcore_types::{EventSeq, JobId, TaskId, Timestamp, ToolCallId};

    fn meta(kind: EventKind) -> FrameMeta {
        FrameMeta::new(7, kind)
            .task(TaskId(2))
            .job(JobId(3))
            .actor(Actor::Adapter)
            .visibility(Visibility::ModelVisible)
            .timestamp(Timestamp::from_millis(70))
    }

    #[test]
    fn every_kind_has_a_stable_name_keyed_by_the_enum() {
        // The name map is total over the closed enum and prefixed by family.
        for kind in EventKind::ALL {
            let n = span_name(kind);
            assert!(
                n.starts_with("gen_ai.") || n.starts_with("crustcore."),
                "{kind:?} -> {n} has an unexpected prefix"
            );
            // Names are stable per kind.
            assert_eq!(span_name(kind), n);
        }
    }

    #[test]
    fn model_frames_map_to_genai_spans() {
        let pf = project_frame(&meta(EventKind::ModelRequestStarted), None);
        assert_eq!(pf.spans.len(), 1);
        let s = &pf.spans[0];
        assert_eq!(s.name, "gen_ai.model_request");
        assert!(s
            .attrs
            .iter()
            .any(|(k, v)| k == "gen_ai.system" && v == GEN_AI_SYSTEM));
        assert!(s
            .attrs
            .iter()
            .any(|(k, v)| k == "gen_ai.operation.name" && v == "model_request"));
    }

    #[test]
    fn tool_completed_binds_receipt_hashes_not_values() {
        let mut chain = ReceiptChain::new(MacKey::new([5u8; 32]));
        let r = chain.mint(&ReceiptParams {
            task_id: TaskId(2),
            job_id: JobId(3),
            tool_call_id: ToolCallId(99),
            tool_name: b"run_command",
            args: b"cargo test",
            result: b"ok",
            artifacts: &[],
            event_seq: EventSeq(7),
        });
        let pf = project_frame(&meta(EventKind::ToolCallCompleted), Some(&r));
        let s = &pf.spans[0];
        assert_eq!(s.name, "crustcore.tool.completed");
        // The result hash is present; the raw result ("ok") is not.
        assert!(s
            .attrs
            .iter()
            .any(|(k, _)| k == "crustcore.tool.result_hash"));
        assert!(s.attrs.iter().any(|(k, _)| k == "crustcore.tool.mac"));
        assert!(!s.attrs.iter().any(|(_, v)| v == "ok"));
        assert!(!s.attrs.iter().any(|(_, v)| v == "run_command"));
    }

    #[test]
    fn tool_completed_without_receipt_records_absence() {
        let pf = project_frame(&meta(EventKind::ToolCallCompleted), None);
        let s = &pf.spans[0];
        assert!(s
            .attrs
            .iter()
            .any(|(k, v)| k == "crustcore.tool.receipt" && v == "absent"));
    }

    #[test]
    fn verify_frames_carry_the_outcome() {
        for (kind, want) in [
            (EventKind::PatchVerified, "verified"),
            (EventKind::PatchRejected, "rejected"),
            (EventKind::PatchProposed, "proposed"),
        ] {
            let pf = project_frame(&meta(kind), None);
            let s = &pf.spans[0];
            assert!(s
                .attrs
                .iter()
                .any(|(k, v)| k == "crustcore.verify.outcome" && v == want));
        }
    }

    #[test]
    fn internal_or_redacted_frame_emits_only_kind_and_seq() {
        // Internal visibility.
        let internal = FrameMeta::new(7, EventKind::ModelOutputReceived)
            .task(TaskId(2))
            .visibility(Visibility::Internal);
        let pf = project_frame(&internal, None);
        assert_eq!(pf.spans.len(), 1);
        let s = &pf.spans[0];
        assert_eq!(s.attrs.len(), 2);
        assert!(s.attrs.iter().any(|(k, _)| k == "crustcore.event.kind"));
        assert!(s.attrs.iter().any(|(k, _)| k == "crustcore.event.seq"));
        // No actor / ids / GenAI hints leak through.
        assert!(!s.attrs.iter().any(|(k, _)| k == "crustcore.task_id"));
        assert!(!s.attrs.iter().any(|(k, _)| k == "gen_ai.system"));

        // Redacted state — even with model-visible visibility.
        let redacted = FrameMeta::new(7, EventKind::ToolCallCompleted)
            .task(TaskId(2))
            .visibility(Visibility::ModelVisible)
            .redaction(RedactionState::Redacted);
        let pf = project_frame(&redacted, None);
        assert_eq!(pf.spans[0].attrs.len(), 2);
        assert!(!pf.spans[0]
            .attrs
            .iter()
            .any(|(k, _)| k == "crustcore.tool.result_hash"));
    }

    #[test]
    fn budget_metric_names_are_per_axis_constants() {
        for axis in BudgetAxis::ALL {
            assert!(budget_metric_name(axis).starts_with("crustcore.budget."));
        }
    }

    #[test]
    fn budget_samples_emit_one_metric_per_nonzero_axis() {
        use crustcore_types::BudgetDelta;
        let delta = BudgetDelta::of(BudgetAxis::Tokens, 120).with(BudgetAxis::WallMillis, 5);
        let samples = budget_samples(&delta, Some(TaskId(4)), Some(JobId(5)));
        assert_eq!(samples.len(), 2);
        assert!(samples
            .iter()
            .any(|m| m.name == "crustcore.budget.tokens" && m.value == 120));
        assert!(samples
            .iter()
            .any(|m| m.name == "crustcore.budget.wall_millis" && m.value == 5));
        // Labels carry only ids, never payload.
        assert!(samples[0]
            .labels
            .iter()
            .any(|(k, _)| k == "crustcore.task_id"));
        // A zero delta yields nothing.
        assert!(budget_samples(&BudgetDelta::none(), None, None).is_empty());
    }
}
