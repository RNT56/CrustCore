// SPDX-License-Identifier: Apache-2.0
//! Receipt ↔ event-log join (`ROADMAP.md` §7.4; `docs/receipts.md` §6).
//!
//! A [`ToolReceipt`](crate::ToolReceipt) is MAC-bound and chained, so it cannot be
//! forged or reordered *in isolation*. But a receipt also claims an `event_seq` —
//! the event-log frame the tool result corresponds to. This module closes that last
//! audit seam: it cross-checks that every receipt's `event_seq` resolves to a real,
//! consistent `ToolCallCompleted` frame in the log, so a receipt is provably tied to
//! a logged event rather than merely being self-consistent.
//!
//! To keep `crustcore-receipts` dependency-light (it links into nano and must stay
//! tiny), the join does **not** depend on the event-log crate. The caller — which
//! holds the `EventLog` — extracts a minimal, log-agnostic [`FrameRef`] per frame
//! and passes them in. The cross-check is pure, deterministic, allocation-light, and
//! panic-free for any input.

use crate::ToolReceipt;
use crustcore_types::{EventSeq, JobId, TaskId};

/// A minimal, log-agnostic summary of one event-log frame — just enough to
/// cross-check a receipt against the log without coupling this crate to the
/// event-log representation. The caller builds these from its `EventLog` (one per
/// frame), setting [`FrameRef::tool_completed`] from `frame.kind ==
/// EventKind::ToolCallCompleted`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameRef {
    /// The frame's sequence number.
    pub seq: EventSeq,
    /// Whether this frame records a **completed** tool call — the only kind a
    /// receipt may anchor to.
    pub tool_completed: bool,
    /// The frame's owning task, if any.
    pub task_id: Option<TaskId>,
    /// The frame's owning job, if any.
    pub job_id: Option<JobId>,
}

/// Why a receipt failed to join to the event log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinBreak {
    /// No frame in the log has the receipt's `event_seq`.
    NoFrameAtSeq,
    /// The frame at the receipt's `event_seq` is not a completed tool call — the
    /// receipt anchors to a non-tool-completion event (or a forged seq).
    NotAToolCompletion,
    /// The frame's task does not match the receipt's task.
    TaskMismatch,
    /// The frame's job does not match the receipt's job.
    JobMismatch,
}

/// The outcome of joining a receipt chain to the event log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinStatus {
    /// Every receipt resolved to a consistent `ToolCallCompleted` frame.
    Joined {
        /// Number of receipts joined.
        count: u64,
    },
    /// A receipt did not join; reports its index and the reason.
    Broken {
        /// Index of the failing receipt.
        index: u64,
        /// What went wrong.
        reason: JoinBreak,
    },
}

impl JoinStatus {
    /// Whether every receipt joined to the log.
    #[must_use]
    pub fn is_joined(self) -> bool {
        matches!(self, JoinStatus::Joined { .. })
    }
}

/// Cross-checks every receipt against the event log: each receipt's `event_seq`
/// must resolve to a frame that **(a)** exists, **(b)** is a completed tool call,
/// and **(c)** carries the same task and job. Returns the first failing receipt's
/// index + reason, else [`JoinStatus::Joined`].
///
/// `frames` need not be sorted. A verified event log has strictly-monotonic seqs so
/// duplicates are not expected; if a seq appears twice, the **first** occurrence
/// wins (deterministic). This is read-only verification — it mints nothing and
/// mutates no state — and never panics.
#[must_use]
pub fn verify_against_log(receipts: &[ToolReceipt], frames: &[FrameRef]) -> JoinStatus {
    use std::collections::BTreeMap;

    let mut by_seq: BTreeMap<u64, FrameRef> = BTreeMap::new();
    for f in frames {
        by_seq.entry(f.seq.0).or_insert(*f);
    }

    for (i, r) in receipts.iter().enumerate() {
        let index = i as u64;
        let Some(frame) = by_seq.get(&r.event_seq.0) else {
            return JoinStatus::Broken {
                index,
                reason: JoinBreak::NoFrameAtSeq,
            };
        };
        if !frame.tool_completed {
            return JoinStatus::Broken {
                index,
                reason: JoinBreak::NotAToolCompletion,
            };
        }
        if frame.task_id != Some(r.task_id) {
            return JoinStatus::Broken {
                index,
                reason: JoinBreak::TaskMismatch,
            };
        }
        if frame.job_id != Some(r.job_id) {
            return JoinStatus::Broken {
                index,
                reason: JoinBreak::JobMismatch,
            };
        }
    }

    JoinStatus::Joined {
        count: receipts.len() as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MacKey, ReceiptChain, ReceiptParams};
    use crustcore_types::ToolCallId;

    fn receipt(seq: u64, task: u128, job: u128) -> ToolReceipt {
        // Mint a real receipt anchored to `seq` via the crate's own API.
        let mut chain = ReceiptChain::new(MacKey::new([9u8; 32]));
        chain.mint(&ReceiptParams {
            task_id: TaskId(task),
            job_id: JobId(job),
            tool_call_id: ToolCallId(u128::from(seq)),
            tool_name: b"run_command",
            args: b"cargo test",
            result: b"ok",
            artifacts: &[],
            event_seq: EventSeq(seq),
        })
    }

    fn completed(seq: u64, task: u128, job: u128) -> FrameRef {
        FrameRef {
            seq: EventSeq(seq),
            tool_completed: true,
            task_id: Some(TaskId(task)),
            job_id: Some(JobId(job)),
        }
    }

    #[test]
    fn consistent_receipts_join() {
        let receipts = vec![receipt(2, 1, 1), receipt(5, 1, 1)];
        // Frames at the receipts' seqs (plus an unrelated non-tool frame).
        let frames = vec![
            FrameRef {
                seq: EventSeq(1),
                tool_completed: false,
                task_id: Some(TaskId(1)),
                job_id: None,
            },
            completed(2, 1, 1),
            completed(5, 1, 1),
        ];
        assert_eq!(
            verify_against_log(&receipts, &frames),
            JoinStatus::Joined { count: 2 }
        );
        // Frame order does not matter.
        let shuffled = vec![completed(5, 1, 1), completed(2, 1, 1)];
        assert!(verify_against_log(&receipts, &shuffled).is_joined());
    }

    #[test]
    fn missing_frame_is_detected() {
        let receipts = vec![receipt(2, 1, 1)];
        let frames = vec![completed(3, 1, 1)]; // no frame at seq 2
        assert_eq!(
            verify_against_log(&receipts, &frames),
            JoinStatus::Broken {
                index: 0,
                reason: JoinBreak::NoFrameAtSeq,
            }
        );
        // Empty log: also no frame.
        assert!(matches!(
            verify_against_log(&receipts, &[]),
            JoinStatus::Broken {
                reason: JoinBreak::NoFrameAtSeq,
                ..
            }
        ));
    }

    #[test]
    fn anchoring_to_a_non_tool_frame_is_detected() {
        let receipts = vec![receipt(2, 1, 1)];
        // A frame exists at seq 2, but it is not a tool completion.
        let frames = vec![FrameRef {
            seq: EventSeq(2),
            tool_completed: false,
            task_id: Some(TaskId(1)),
            job_id: Some(JobId(1)),
        }];
        assert_eq!(
            verify_against_log(&receipts, &frames),
            JoinStatus::Broken {
                index: 0,
                reason: JoinBreak::NotAToolCompletion,
            }
        );
    }

    #[test]
    fn task_and_job_mismatch_are_detected() {
        let receipts = vec![receipt(2, 1, 1)];
        // Right seq + tool completion, but the frame belongs to a different task.
        assert_eq!(
            verify_against_log(&receipts, &[completed(2, 999, 1)]),
            JoinStatus::Broken {
                index: 0,
                reason: JoinBreak::TaskMismatch,
            }
        );
        // Right task, wrong job.
        assert_eq!(
            verify_against_log(&receipts, &[completed(2, 1, 999)]),
            JoinStatus::Broken {
                index: 0,
                reason: JoinBreak::JobMismatch,
            }
        );
        // A frame whose ids are absent (None) cannot match a receipt's ids.
        assert!(matches!(
            verify_against_log(
                &receipts,
                &[FrameRef {
                    seq: EventSeq(2),
                    tool_completed: true,
                    task_id: None,
                    job_id: None,
                }]
            ),
            JoinStatus::Broken {
                reason: JoinBreak::TaskMismatch,
                ..
            }
        ));
    }

    #[test]
    fn reports_the_first_failing_receipt_index() {
        // First receipt joins; the second has no frame.
        let receipts = vec![receipt(2, 1, 1), receipt(9, 1, 1)];
        assert_eq!(
            verify_against_log(&receipts, &[completed(2, 1, 1)]),
            JoinStatus::Broken {
                index: 1,
                reason: JoinBreak::NoFrameAtSeq,
            }
        );
    }

    #[test]
    fn empty_receipts_join_vacuously() {
        assert_eq!(
            verify_against_log(&[], &[completed(2, 1, 1)]),
            JoinStatus::Joined { count: 0 }
        );
    }
}
