// SPDX-License-Identifier: Apache-2.0
//! The run driver (C6T.6): walk a bounded frame range, join receipts, project,
//! redact, and feed the chosen exporter.
//!
//! The driver is the glue, but it adds **no** authority: it reads the log, reads
//! receipts, and emits redacted telemetry. It mints nothing, advances no budget,
//! and never reaches `verify::run_verify` (invariants 6, 13).
//!
//! Two entry points:
//! - [`run`] — the low-level driver over a caller-supplied slice of [`FrameInput`]
//!   (each a typed [`FrameMeta`] + its optional joined [`ToolReceipt`]). This is the
//!   CI-testable core: deterministic, no I/O.
//! - [`run_log`] — the convenience driver over an [`crustcore_eventlog::EventLog`] +
//!   a receipt slice. It range-filters frames in-crate, builds the join via
//!   [`crustcore_receipts::join::verify_against_log`] (P5-join, consumed not
//!   re-implemented), and respects each frame's visibility/redaction.
//!
//! Both honor [`Config`]: disabled = emit nothing (fail-closed); `sample_rate`
//! thins frames; `batch_bound` caps how many frames are processed (invariant 11).

use crustcore_eventlog::{EventLog, FrameMeta};
use crustcore_receipts::join::{verify_against_log, FrameRef};
use crustcore_receipts::ToolReceipt;
use crustcore_secrets::Redactor;

use crate::config::Config;
use crate::export::Exporter;
use crate::project::EventProjector;
use crate::redact::redact_frame;
use crate::semconv;

/// One unit of input for the low-level [`run`] driver: a typed frame header plus the
/// [`ToolReceipt`] it joins to (if any). Decoupled from the on-disk log so the core
/// is testable without constructing a full `EventLog`.
#[derive(Debug, Clone)]
pub struct FrameInput {
    /// The frame's typed header (kind/seq/ids/visibility/redaction/actor/time).
    pub meta: FrameMeta,
    /// The joined receipt for a `ToolCallCompleted` frame, if one was bound.
    pub receipt: Option<ToolReceipt>,
}

impl FrameInput {
    /// A frame with no joined receipt.
    #[must_use]
    pub fn new(meta: FrameMeta) -> Self {
        FrameInput {
            meta,
            receipt: None,
        }
    }

    /// A frame with a joined receipt.
    #[must_use]
    pub fn with_receipt(meta: FrameMeta, receipt: ToolReceipt) -> Self {
        FrameInput {
            meta,
            receipt: Some(receipt),
        }
    }
}

/// What a telemetry run did. Read-only accounting — it mints nothing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RunReport {
    /// Frames considered (after the `batch_bound` cap).
    pub frames_seen: u64,
    /// Frames actually projected (after sampling).
    pub frames_projected: u64,
    /// Spans emitted to the exporter.
    pub spans_emitted: u64,
    /// Metric samples emitted to the exporter.
    pub metrics_emitted: u64,
}

/// The low-level driver: project → redact → export each input frame, in order.
///
/// If `config.enabled` is false, nothing is emitted (fail-closed). Otherwise every
/// `sample_rate`-th frame (up to `batch_bound`) is projected, redacted through
/// `redactor` (the sole emission chokepoint), and handed to `exporter`. The exporter
/// is flushed at the end. Returns a [`RunReport`].
pub fn run<E: Exporter>(
    frames: &[FrameInput],
    config: &Config,
    redactor: &Redactor,
    exporter: &mut E,
) -> RunReport {
    let mut report = RunReport::default();
    if !config.enabled {
        return report;
    }
    let projector = EventProjector::new();
    let rate = config.effective_sample_rate() as u64;

    for (i, input) in frames.iter().take(config.batch_bound).enumerate() {
        report.frames_seen += 1;
        // Deterministic sampling on frame index (no clock, no RNG).
        if (i as u64) % rate != 0 {
            continue;
        }
        // Project (pre-redaction), then redact at the single chokepoint.
        let projected = projector.project(&input.meta, input.receipt.as_ref());
        if projected.is_empty() {
            continue;
        }
        let redacted = redact_frame(&projected, redactor);
        report.spans_emitted += redacted.spans.len() as u64;
        report.metrics_emitted += redacted.metrics.len() as u64;
        report.frames_projected += 1;
        exporter.export_frame(&redacted);
    }
    exporter.flush();
    report
}

/// The convenience driver over an [`EventLog`] + receipts.
///
/// Decodes the log's frames in `[seq_lo, seq_hi]` (inclusive), builds the receipt↔log
/// join via [`verify_against_log`] (P5-join), pairs each `ToolCallCompleted` frame
/// with its receipt, and drives [`run`]. Receipts that do not join cleanly are simply
/// not bound to a span (the projection records the absence honestly — invariant 10);
/// telemetry never asserts a join that the audit layer did not confirm.
///
/// Range filtering and `batch_bound` keep the work bounded over an arbitrarily large
/// log (invariant 11).
pub fn run_log<E: Exporter>(
    log: &EventLog,
    receipts: &[ToolReceipt],
    seq_lo: u64,
    seq_hi: u64,
    config: &Config,
    redactor: &Redactor,
    exporter: &mut E,
) -> RunReport {
    if !config.enabled {
        return RunReport::default();
    }

    // Build FrameRefs for the whole log so the receipt join sees every frame, then
    // confirm the join (read-only). We only *bind* a receipt to a span if the join
    // confirms it resolves to a real ToolCallCompleted frame for the same task/job.
    let frame_refs: Vec<FrameRef> = log
        .iter()
        .map(|d| FrameRef {
            seq: d.frame.seq,
            tool_completed: d.frame.kind == crustcore_kernel::EventKind::ToolCallCompleted,
            task_id: d.frame.task_id,
            job_id: d.frame.job_id,
        })
        .collect();
    let join_ok = verify_against_log(receipts, &frame_refs).is_joined();

    // Index receipts by the seq they anchor to (first occurrence wins, like the join).
    let mut receipt_by_seq: std::collections::BTreeMap<u64, &ToolReceipt> =
        std::collections::BTreeMap::new();
    if join_ok {
        for r in receipts {
            receipt_by_seq.entry(r.event_seq.0).or_insert(r);
        }
    }

    // Range-filter the frames and build typed inputs. We reconstruct a FrameMeta from
    // each decoded EventFrame's header fields (the projector reads typed metadata, not
    // payload bytes).
    let mut inputs: Vec<FrameInput> = Vec::new();
    for d in log.iter() {
        let f = &d.frame;
        if f.seq.0 < seq_lo || f.seq.0 > seq_hi {
            continue;
        }
        let mut meta = FrameMeta::new(f.seq.0, f.kind)
            .actor(f.actor)
            .visibility(f.visibility)
            .redaction(f.redaction)
            .timestamp(f.timestamp);
        if let Some(t) = f.task_id {
            meta = meta.task(t);
        }
        if let Some(j) = f.job_id {
            meta = meta.job(j);
        }
        let receipt = if f.kind == crustcore_kernel::EventKind::ToolCallCompleted {
            receipt_by_seq.get(&f.seq.0).map(|r| (*r).clone())
        } else {
            None
        };
        inputs.push(FrameInput { meta, receipt });
    }

    run(&inputs, config, redactor, exporter)
}

/// Re-export of the budget helpers so callers building budget samples from
/// `BudgetDelta` data use the same authoritative name table.
pub use semconv::{budget_metric_name, budget_samples};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::export::InMemoryExporter;
    use crustcore_kernel::{Actor, EventKind, Visibility};
    use crustcore_types::{TaskId, Timestamp};

    fn frame(seq: u64, kind: EventKind) -> FrameInput {
        FrameInput::new(
            FrameMeta::new(seq, kind)
                .task(TaskId(1))
                .actor(Actor::Adapter)
                .visibility(Visibility::ModelVisible)
                .timestamp(Timestamp::from_millis(seq * 10)),
        )
    }

    #[test]
    fn disabled_config_emits_nothing() {
        let frames = vec![frame(1, EventKind::ModelRequestStarted)];
        let mut exp = InMemoryExporter::new();
        let report = run(&frames, &Config::default(), &Redactor::new(), &mut exp);
        assert_eq!(report, RunReport::default());
        assert!(exp.emitted().is_empty());
    }

    #[test]
    fn enabled_config_projects_and_exports() {
        let frames = vec![
            frame(1, EventKind::ModelRequestStarted),
            frame(2, EventKind::ToolCallStarted),
        ];
        let mut exp = InMemoryExporter::new();
        let report = run(
            &frames,
            &Config::enabled_in_memory(),
            &Redactor::new(),
            &mut exp,
        );
        assert_eq!(report.frames_seen, 2);
        assert_eq!(report.frames_projected, 2);
        assert_eq!(report.spans_emitted, 2);
        assert_eq!(exp.spans().len(), 2);
    }

    #[test]
    fn batch_bound_caps_frames_processed() {
        let frames: Vec<FrameInput> = (1..=10)
            .map(|s| frame(s, EventKind::ModelRequestStarted))
            .collect();
        let cfg = Config {
            batch_bound: 3,
            ..Config::enabled_in_memory()
        };
        let mut exp = InMemoryExporter::new();
        let report = run(&frames, &cfg, &Redactor::new(), &mut exp);
        assert_eq!(report.frames_seen, 3);
    }

    #[test]
    fn sample_rate_thins_frames_deterministically() {
        let frames: Vec<FrameInput> = (0..6)
            .map(|s| frame(s + 1, EventKind::ModelRequestStarted))
            .collect();
        let cfg = Config {
            sample_rate: 2,
            ..Config::enabled_in_memory()
        };
        let mut exp = InMemoryExporter::new();
        let report = run(&frames, &cfg, &Redactor::new(), &mut exp);
        // indices 0,2,4 sampled => 3 frames.
        assert_eq!(report.frames_projected, 3);
    }
}
