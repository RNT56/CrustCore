// SPDX-License-Identifier: Apache-2.0
//! Replay viewer (`C7.3`). Read-only over the append-only hash-chained log.
//!
//! Reuses `EventLog::verify` + `iter` (the same walk that backs `export_jsonl`) and the
//! receipt↔log join `verify_against_log`/`FrameRef` (P5-join). It reports
//! `ChainStatus::Intact`/`Broken`, surfaces per-frame `visibility`/`redaction_state`, and
//! **mints nothing, writes nothing, appends no frame** — payloads are never inlined;
//! artifacts are referenced by `ArtifactId` only.

use crate::backend::{ReplayRow, ReplayView};
use crustcore_eventlog::{EventLog, RedactionState};
use crustcore_kernel::Visibility;
use crustcore_receipts::join::{verify_against_log, FrameRef};
use crustcore_receipts::ToolReceipt;

/// Render the replay view over the log + (optional) receipts. Pure read.
#[must_use]
pub fn render(log: &EventLog, receipts: &[ToolReceipt]) -> ReplayView {
    // 1. Full hash-chain verification — the single source of truth for Intact/Broken.
    let chain = log.verify();

    // 2. Per-frame rows. We walk the *decodable* frames and tag each with its
    //    visibility/redaction state. We never inline the payload bytes (invariant 7);
    //    a redacted (secret-bearing) frame is flagged and its bytes withheld.
    let mut rows = Vec::new();
    let mut frame_refs = Vec::new();
    for decoded in log.iter() {
        let f = &decoded.frame;
        rows.push(ReplayRow {
            seq: f.seq,
            kind: format!("{:?}", f.kind), // closed-enum name, never untrusted text
            model_visible: f.visibility == Visibility::ModelVisible,
            redacted: f.redaction == RedactionState::Redacted,
            // Artifacts are referenced by id only — never inlined. The payload bytes
            // (which the replay view never exposes) would carry any artifact handle, so
            // we expose none here directly; the row carries the metadata the UI shows.
            artifact: None,
        });
        // Build the minimal FrameRef the join needs (P5-join), tagging tool-completion
        // frames so a receipt can only anchor to a real completed tool call.
        frame_refs.push(FrameRef {
            seq: f.seq,
            tool_completed: f.kind == crustcore_kernel::EventKind::ToolCallCompleted,
            task_id: f.task_id,
            job_id: f.job_id,
        });
    }

    // 3. Receipt↔log join (only when receipts are present).
    let join = if receipts.is_empty() {
        None
    } else {
        Some(verify_against_log(receipts, &frame_refs))
    };

    ReplayView { chain, join, rows }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crustcore_eventlog::{ChainStatus, FrameMeta};
    use crustcore_kernel::event::EventKind;
    use crustcore_types::TaskId;

    fn intact_log() -> EventLog {
        let mut log = EventLog::new();
        log.append(
            &FrameMeta::new(1, EventKind::TaskCreated).task(TaskId(1)),
            b"a",
        );
        log.append(
            &FrameMeta::new(2, EventKind::ToolCallCompleted).task(TaskId(1)),
            b"b",
        );
        log
    }

    #[test]
    fn reports_intact_for_a_good_log() {
        let log = intact_log();
        let view = render(&log, &[]);
        assert!(matches!(view.chain, ChainStatus::Intact { frames: 2 }));
        assert_eq!(view.rows.len(), 2);
        assert!(view.join.is_none());
    }

    #[test]
    fn reports_broken_for_a_tampered_log() {
        let mut log = intact_log();
        // Tamper: flip a byte in the raw representation, then reload.
        let mut bytes = log.bytes().to_vec();
        // Flip a payload byte well inside the first frame (the redaction byte / payload).
        let idx = bytes.len() / 3;
        bytes[idx] ^= 0xFF;
        log = EventLog::from_bytes(bytes);
        let view = render(&log, &[]);
        assert!(
            matches!(view.chain, ChainStatus::Broken { .. }),
            "tampered log must report Broken, got {:?}",
            view.chain
        );
    }

    #[test]
    fn redaction_and_visibility_are_surfaced_not_inlined() {
        let mut log = EventLog::new();
        log.append(
            &FrameMeta::new(1, EventKind::ModelOutputReceived)
                .task(TaskId(1))
                .visibility(Visibility::ModelVisible)
                .redaction(RedactionState::Redacted),
            b"secret-bearing",
        );
        let view = render(&log, &[]);
        let row = &view.rows[0];
        assert!(row.model_visible);
        assert!(row.redacted);
        // The payload bytes are never present on the row — only metadata + id.
        assert!(row.artifact.is_none());
    }

    #[test]
    fn render_is_read_only() {
        let log = intact_log();
        let before = log.bytes().to_vec();
        let _ = render(&log, &[]);
        assert_eq!(log.bytes(), before.as_slice());
    }
}
