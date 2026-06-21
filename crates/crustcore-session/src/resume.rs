// SPDX-License-Identifier: Apache-2.0
//! Resumable runs — verify-or-refuse (C4.3; invariants 7, 13, 18).
//!
//! [`resume`] reconstructs a [`SessionView`] for a run **only after** the log and
//! its receipts both verify:
//!
//! 1. [`EventLog::verify`] (or [`EventLog::verify_to_head`] against a persisted
//!    head via [`resume_to_head`]) must report
//!    [`ChainStatus::is_intact`](crustcore_eventlog::ChainStatus::is_intact); and
//! 2. [`crustcore_receipts::join::verify_against_log`] over the session's receipts
//!    must report [`JoinStatus::is_joined`](crustcore_receipts::join::JoinStatus::is_joined).
//!
//! If either fails, [`resume`] returns [`ResumeRefused`] carrying the exact break
//! reason — a tampered or broken log **refuses to resume** rather than silently
//! reconstructing a corrupted view (invariant 7). Resume reconstructs a *view*: it
//! mutates no kernel state, completes nothing, and integrates nothing
//! (invariants 13, 18).

use crustcore_eventlog::{BreakReason, ChainStatus, EventLog};
use crustcore_receipts::join::{verify_against_log, JoinBreak, JoinStatus};
use crustcore_receipts::ToolReceipt;

use crate::id::SessionId;
use crate::view::{frame_refs, SessionView};

/// Why a resume was refused. Carries the exact verifier break so the caller can
/// log/report which integrity check failed. No `ResumeRefused` is recoverable to a
/// view — a refused resume yields no [`SessionView`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeRefused {
    /// The event-log chain failed to verify.
    LogBroken {
        /// The frame index where verification failed.
        frame_index: u64,
        /// Why the chain broke.
        reason: BreakReason,
    },
    /// A persisted head anchor did not match the live log (clean trailing-frame
    /// removal / fork). This is a distinguished case of a broken log surfaced via
    /// [`resume_to_head`].
    HeadMismatch,
    /// The receipt ↔ log join failed.
    ReceiptJoinBroken {
        /// The index of the failing receipt.
        index: u64,
        /// Why the receipt did not join.
        reason: JoinBreak,
    },
}

impl core::fmt::Display for ResumeRefused {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ResumeRefused::LogBroken {
                frame_index,
                reason,
            } => write!(
                f,
                "resume refused: log broken at frame {frame_index}: {reason}"
            ),
            ResumeRefused::HeadMismatch => {
                write!(f, "resume refused: persisted head does not match live log")
            }
            ResumeRefused::ReceiptJoinBroken { index, reason } => {
                write!(
                    f,
                    "resume refused: receipt {index} did not join the log ({reason:?})"
                )
            }
        }
    }
}

impl std::error::Error for ResumeRefused {}

/// Resumes `session` over `log`, cross-checking `receipts`. Proceeds only when the
/// chain `is_intact()` **and** every receipt `is_joined()`. Returns a borrowing
/// [`SessionView`] on success, else [`ResumeRefused`].
///
/// The returned view borrows `log`: resume reconstructs a read-only view and
/// mutates no state (invariants 13, 18).
///
/// # Errors
/// [`ResumeRefused`] if the log fails [`EventLog::verify`] or the receipts fail
/// [`verify_against_log`].
pub fn resume<'log>(
    log: &'log EventLog,
    session: SessionId,
    receipts: &[ToolReceipt],
) -> Result<SessionView<'log>, ResumeRefused> {
    check_join(log, receipts)?;
    match log.verify() {
        ChainStatus::Intact { .. } => Ok(SessionView::new(log, session)),
        ChainStatus::Broken {
            frame_index,
            reason,
        } => Err(log_break(frame_index, reason)),
    }
}

/// Like [`resume`], but anchors the chain to a persisted `expected_head` via
/// [`EventLog::verify_to_head`] — detecting clean trailing-frame removal that bare
/// [`resume`] cannot. Use this when resuming from a persisted snapshot whose
/// `head_hash` is the anchor.
///
/// # Errors
/// [`ResumeRefused`] if the anchored verify or the receipt join fails.
pub fn resume_to_head<'log>(
    log: &'log EventLog,
    session: SessionId,
    receipts: &[ToolReceipt],
    expected_head: [u8; 32],
) -> Result<SessionView<'log>, ResumeRefused> {
    check_join(log, receipts)?;
    match log.verify_to_head(expected_head) {
        ChainStatus::Intact { .. } => Ok(SessionView::new(log, session)),
        ChainStatus::Broken {
            frame_index,
            reason,
        } => Err(log_break(frame_index, reason)),
    }
}

/// Runs the receipt ↔ log join and maps a break to [`ResumeRefused`]. Shared by
/// both resume paths so the join is never skipped.
fn check_join(log: &EventLog, receipts: &[ToolReceipt]) -> Result<(), ResumeRefused> {
    let refs = frame_refs(log);
    match verify_against_log(receipts, &refs) {
        JoinStatus::Joined { .. } => Ok(()),
        JoinStatus::Broken { index, reason } => {
            Err(ResumeRefused::ReceiptJoinBroken { index, reason })
        }
    }
}

fn log_break(frame_index: u64, reason: BreakReason) -> ResumeRefused {
    if reason == BreakReason::HeadMismatch {
        ResumeRefused::HeadMismatch
    } else {
        ResumeRefused::LogBroken {
            frame_index,
            reason,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crustcore_eventlog::{EventLog, FrameMeta};
    use crustcore_kernel::{Actor, EventKind, Visibility};
    use crustcore_receipts::{MacKey, ReceiptChain, ReceiptParams};
    use crustcore_types::{EventSeq, JobId, TaskId, ToolCallId};

    // Builds a clean log: a ToolCallCompleted frame at the receipt's seq plus a
    // model turn, all under task 1 / job 10.
    fn clean_log() -> EventLog {
        let mut log = EventLog::new();
        log.append(
            &FrameMeta::new(1, EventKind::TaskCreated).task(TaskId(1)),
            b"created",
        );
        log.append(
            &FrameMeta::new(2, EventKind::ToolCallCompleted)
                .task(TaskId(1))
                .job(JobId(10))
                .actor(Actor::Adapter),
            b"tool done",
        );
        log.append(
            &FrameMeta::new(3, EventKind::ModelOutputReceived)
                .task(TaskId(1))
                .job(JobId(10))
                .actor(Actor::Model)
                .visibility(Visibility::ModelVisible),
            b"reply",
        );
        log
    }

    fn receipt_at(seq: u64, task: u128, job: u128) -> ToolReceipt {
        let mut chain = ReceiptChain::new(MacKey::new([3u8; 32]));
        chain.mint(&ReceiptParams {
            task_id: TaskId(task),
            job_id: JobId(job),
            tool_call_id: ToolCallId(u128::from(seq)),
            tool_name: b"run_command",
            args: b"cargo test",
            result: b"tool done",
            artifacts: &[],
            event_seq: EventSeq(seq),
        })
    }

    #[test]
    fn clean_log_with_joined_receipts_resumes() {
        let log = clean_log();
        let receipts = vec![receipt_at(2, 1, 10)];
        let view = resume(&log, SessionId::new(TaskId(1)), &receipts).unwrap();
        assert_eq!(view.task_id(), TaskId(1));
        // The view is read-only; it merely re-derives from the borrowed log.
        assert_eq!(view.frame_count(), 3);
    }

    #[test]
    fn resume_with_no_receipts_joins_vacuously() {
        let log = clean_log();
        assert!(resume(&log, SessionId::new(TaskId(1)), &[]).is_ok());
    }

    // --- event-log tamper classes each yield the exact refusal ---

    #[test]
    fn flipped_payload_refuses() {
        let mut log = clean_log();
        let pos = log
            .bytes()
            .windows(7)
            .position(|w| w == b"created")
            .unwrap();
        let mut bytes = log.bytes().to_vec();
        bytes[pos] ^= 0xff;
        log = EventLog::from_bytes(bytes);
        let err = resume(&log, SessionId::new(TaskId(1)), &[]).unwrap_err();
        assert!(matches!(
            err,
            ResumeRefused::LogBroken {
                reason: BreakReason::PayloadHashMismatch,
                ..
            }
        ));
    }

    #[test]
    fn deleted_frame_refuses() {
        // Splice the raw log bytes to drop the middle frame: keep frame 0, skip
        // frame 1, keep frame 2. The kept frame-2's stored prev_hash then no longer
        // matches frame-0's frame_hash, so the chain breaks with PrevHashMismatch.
        let full = clean_log();
        let bytes = full.bytes();
        // Learn frame byte-lengths by building single-frame logs identical to each
        // appended frame (the eventlog does not expose offsets).
        let mut f0 = EventLog::new();
        f0.append(
            &FrameMeta::new(1, EventKind::TaskCreated).task(TaskId(1)),
            b"created",
        );
        let len0 = f0.bytes().len();
        let mut f1 = EventLog::new();
        f1.append(
            &FrameMeta::new(2, EventKind::ToolCallCompleted)
                .task(TaskId(1))
                .job(JobId(10))
                .actor(Actor::Adapter),
            b"tool done",
        );
        let len1 = f1.bytes().len();
        let mut spliced = Vec::new();
        spliced.extend_from_slice(&bytes[0..len0]); // frame 0
        spliced.extend_from_slice(&bytes[len0 + len1..]); // frame 2 (skip frame 1)
        let tampered = EventLog::from_bytes(spliced);
        let err = resume(&tampered, SessionId::new(TaskId(1)), &[]).unwrap_err();
        assert!(matches!(
            err,
            ResumeRefused::LogBroken {
                reason: BreakReason::PrevHashMismatch,
                ..
            }
        ));
    }

    #[test]
    fn truncated_frame_refuses() {
        let full = clean_log();
        let mut bytes = full.bytes().to_vec();
        bytes.truncate(bytes.len() - 10);
        let log = EventLog::from_bytes(bytes);
        let err = resume(&log, SessionId::new(TaskId(1)), &[]).unwrap_err();
        assert!(matches!(
            err,
            ResumeRefused::LogBroken {
                reason: BreakReason::Truncated,
                ..
            }
        ));
    }

    #[test]
    fn clean_trailing_removal_refuses_only_under_head_anchor() {
        let full = clean_log();
        let expected_head = full.head_hash();
        // Drop the last frame cleanly: rebuild a 2-frame prefix log.
        let mut prefix = EventLog::new();
        prefix.append(
            &FrameMeta::new(1, EventKind::TaskCreated).task(TaskId(1)),
            b"created",
        );
        prefix.append(
            &FrameMeta::new(2, EventKind::ToolCallCompleted)
                .task(TaskId(1))
                .job(JobId(10))
                .actor(Actor::Adapter),
            b"tool done",
        );
        // Bare resume: the 2-frame prefix is internally consistent → resumes.
        assert!(resume(&prefix, SessionId::new(TaskId(1)), &[]).is_ok());
        // Anchored resume against the full head: refused as HeadMismatch.
        let err =
            resume_to_head(&prefix, SessionId::new(TaskId(1)), &[], expected_head).unwrap_err();
        assert_eq!(err, ResumeRefused::HeadMismatch);
    }

    // --- forged-receipt join-break classes each yield the exact refusal ---

    #[test]
    fn forged_receipt_no_frame_at_seq_refuses() {
        let log = clean_log();
        let receipts = vec![receipt_at(99, 1, 10)]; // no frame at seq 99
        let err = resume(&log, SessionId::new(TaskId(1)), &receipts).unwrap_err();
        assert!(matches!(
            err,
            ResumeRefused::ReceiptJoinBroken {
                reason: JoinBreak::NoFrameAtSeq,
                ..
            }
        ));
    }

    #[test]
    fn forged_receipt_not_a_tool_completion_refuses() {
        let log = clean_log();
        // Anchor a receipt at seq 3 (ModelOutputReceived, not a tool completion).
        let receipts = vec![receipt_at(3, 1, 10)];
        let err = resume(&log, SessionId::new(TaskId(1)), &receipts).unwrap_err();
        assert!(matches!(
            err,
            ResumeRefused::ReceiptJoinBroken {
                reason: JoinBreak::NotAToolCompletion,
                ..
            }
        ));
    }

    #[test]
    fn forged_receipt_task_mismatch_refuses() {
        let log = clean_log();
        let receipts = vec![receipt_at(2, 999, 10)]; // wrong task
        let err = resume(&log, SessionId::new(TaskId(1)), &receipts).unwrap_err();
        assert!(matches!(
            err,
            ResumeRefused::ReceiptJoinBroken {
                reason: JoinBreak::TaskMismatch,
                ..
            }
        ));
    }

    #[test]
    fn forged_receipt_job_mismatch_refuses() {
        let log = clean_log();
        let receipts = vec![receipt_at(2, 1, 999)]; // wrong job
        let err = resume(&log, SessionId::new(TaskId(1)), &receipts).unwrap_err();
        assert!(matches!(
            err,
            ResumeRefused::ReceiptJoinBroken {
                reason: JoinBreak::JobMismatch,
                ..
            }
        ));
    }
}
