// SPDX-License-Identifier: Apache-2.0
//! The typed identity + view layer (C4.1).
//!
//! A [`SessionView`] **borrows** an [`EventLog`] and indexes the frames bound to
//! one session's [`TaskId`], optionally narrowed to a [`JobId`] and/or a `seq`
//! range. It never copies the chain into a second mutable store: it holds a
//! `&EventLog` and re-derives everything on demand via [`EventLog::iter`]. A
//! [`ConversationView`] is the same borrow narrowed to the user/model/tool turn
//! frames (`UserMessageQueued` / `ModelOutputReceived` / `ToolCallCompleted`).
//!
//! Neither type exposes a completion, integration, approval, or side-effect
//! method — by construction (invariants 13, 18). The view is read-only: every
//! accessor returns derived data, never a mutation handle.

use crustcore_eventlog::{DecodedFrame, EventLog};
use crustcore_kernel::EventKind;
use crustcore_receipts::join::FrameRef;
use crustcore_types::{EventSeq, JobId, TaskId};

use crate::id::SessionId;

/// An inclusive `seq` range filter for a view (`[start, end]`). Either bound may
/// be open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SeqRange {
    /// Inclusive lower bound, if any.
    pub start: Option<EventSeq>,
    /// Inclusive upper bound, if any.
    pub end: Option<EventSeq>,
}

impl SeqRange {
    /// The unbounded range (every seq).
    #[must_use]
    pub const fn all() -> Self {
        SeqRange {
            start: None,
            end: None,
        }
    }

    /// A range bounded above (inclusive) by `seq` — the "up to and including a
    /// snapshot point" filter.
    #[must_use]
    pub const fn up_to(seq: EventSeq) -> Self {
        SeqRange {
            start: None,
            end: Some(seq),
        }
    }

    /// Whether `seq` is inside the range.
    #[must_use]
    pub fn contains(self, seq: EventSeq) -> bool {
        self.start.is_none_or(|s| seq.0 >= s.0) && self.end.is_none_or(|e| seq.0 <= e.0)
    }
}

/// A read-only, borrowing index over the frames of one session.
///
/// Holds a `&EventLog` (the single source of truth) plus the session identity and
/// an optional job/seq narrowing. It exposes only derived reads — never a
/// completion, integration, approval, or mutation method (invariants 13, 18).
#[derive(Debug, Clone, Copy)]
pub struct SessionView<'log> {
    log: &'log EventLog,
    session: SessionId,
    job: Option<JobId>,
    range: SeqRange,
}

impl<'log> SessionView<'log> {
    /// Builds a view over every frame of `session` in `log`.
    #[must_use]
    pub fn new(log: &'log EventLog, session: SessionId) -> Self {
        SessionView {
            log,
            session,
            job: None,
            range: SeqRange::all(),
        }
    }

    /// Narrows the view to one job.
    #[must_use]
    pub fn with_job(mut self, job: JobId) -> Self {
        self.job = Some(job);
        self
    }

    /// Narrows the view to a `seq` range.
    #[must_use]
    pub fn with_range(mut self, range: SeqRange) -> Self {
        self.range = range;
        self
    }

    /// The session this view indexes.
    #[must_use]
    pub fn session(&self) -> SessionId {
        self.session
    }

    /// The task this view indexes (the session's task).
    #[must_use]
    pub fn task_id(&self) -> TaskId {
        self.session.task_id()
    }

    /// The job narrowing, if any.
    #[must_use]
    pub fn job(&self) -> Option<JobId> {
        self.job
    }

    /// The seq range narrowing.
    #[must_use]
    pub fn range(&self) -> SeqRange {
        self.range
    }

    /// The underlying log (read-only).
    #[must_use]
    pub fn log(&self) -> &'log EventLog {
        self.log
    }

    /// Whether a decoded frame belongs to this view (task + job + range match).
    fn selects(&self, frame: &crustcore_eventlog::EventFrame) -> bool {
        frame.task_id == Some(self.session.task_id())
            && self.job.is_none_or(|j| frame.job_id == Some(j))
            && self.range.contains(frame.seq)
    }

    /// Iterates the decoded frames of this session, in chain order. The chain is
    /// re-decoded from the borrowed log each call — no second store is kept.
    pub fn frames(&self) -> impl Iterator<Item = DecodedFrame<'log>> + '_ {
        self.log.iter().filter(move |d| self.selects(&d.frame))
    }

    /// Number of frames in this view.
    #[must_use]
    pub fn frame_count(&self) -> u64 {
        self.frames().count() as u64
    }

    /// The highest `seq` in this view, if any (the view's head seq).
    #[must_use]
    pub fn head_seq(&self) -> Option<EventSeq> {
        self.frames().map(|d| d.frame.seq).max_by_key(|s| s.0)
    }

    /// A [`ConversationView`] narrowed to this session's turn frames.
    #[must_use]
    pub fn conversation(&self) -> ConversationView<'log> {
        ConversationView { inner: *self }
    }

    /// Builds the log-agnostic [`FrameRef`] list for **the whole log** (not just
    /// this session) — the resume-time receipt↔log cross-check
    /// ([`crustcore_receipts::join::verify_against_log`]) must see every frame so a
    /// receipt anchoring outside this session's frames still resolves (and is
    /// caught as a task/job mismatch rather than a spurious `NoFrameAtSeq`).
    #[must_use]
    pub fn frame_refs(&self) -> Vec<FrameRef> {
        frame_refs(self.log)
    }
}

/// Builds a [`FrameRef`] per frame of `log`, marking `tool_completed` from
/// `kind == ToolCallCompleted`. The single helper both [`SessionView`] and resume
/// use, so the join always sees the same view of the log.
#[must_use]
pub fn frame_refs(log: &EventLog) -> Vec<FrameRef> {
    log.iter()
        .map(|d| FrameRef {
            seq: d.frame.seq,
            tool_completed: d.frame.kind == EventKind::ToolCallCompleted,
            task_id: d.frame.task_id,
            job_id: d.frame.job_id,
        })
        .collect()
}

/// Whether `kind` is a conversation turn frame (user / model / tool result).
#[must_use]
pub fn is_turn_kind(kind: EventKind) -> bool {
    matches!(
        kind,
        EventKind::UserMessageQueued
            | EventKind::UserSteerReceived
            | EventKind::ModelOutputReceived
            | EventKind::ToolCallCompleted
    )
}

/// A read-only view over the conversation turn frames of a session.
///
/// Wraps a [`SessionView`] and yields only the user/model/tool frames in chain
/// order. Like [`SessionView`], it exposes no completion/integration method.
#[derive(Debug, Clone, Copy)]
pub struct ConversationView<'log> {
    inner: SessionView<'log>,
}

impl<'log> ConversationView<'log> {
    /// The session this conversation belongs to.
    #[must_use]
    pub fn session(&self) -> SessionId {
        self.inner.session()
    }

    /// Iterates the turn frames in chain order.
    pub fn turns(&self) -> impl Iterator<Item = DecodedFrame<'log>> + '_ {
        self.inner.frames().filter(|d| is_turn_kind(d.frame.kind))
    }

    /// Number of turn frames.
    #[must_use]
    pub fn turn_count(&self) -> u64 {
        self.turns().count() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crustcore_eventlog::FrameMeta;
    use crustcore_kernel::{Actor, Visibility};

    fn log_with_session() -> EventLog {
        let mut log = EventLog::new();
        // Task 1, job 10: a small run.
        log.append(
            &FrameMeta::new(1, EventKind::TaskCreated).task(TaskId(1)),
            b"created",
        );
        log.append(
            &FrameMeta::new(2, EventKind::UserMessageQueued)
                .task(TaskId(1))
                .job(JobId(10))
                .actor(Actor::User)
                .visibility(Visibility::ModelVisible),
            b"hello",
        );
        log.append(
            &FrameMeta::new(3, EventKind::ModelOutputReceived)
                .task(TaskId(1))
                .job(JobId(10))
                .actor(Actor::Model)
                .visibility(Visibility::ModelVisible),
            b"hi back",
        );
        // A different task's frame must be excluded.
        log.append(
            &FrameMeta::new(4, EventKind::UserMessageQueued)
                .task(TaskId(2))
                .actor(Actor::User),
            b"other task",
        );
        log
    }

    #[test]
    fn view_selects_only_its_session_frames() {
        let log = log_with_session();
        let view = SessionView::new(&log, SessionId::new(TaskId(1)));
        assert_eq!(view.frame_count(), 3);
        assert_eq!(view.head_seq(), Some(EventSeq(3)));
        for d in view.frames() {
            assert_eq!(d.frame.task_id, Some(TaskId(1)));
        }
    }

    #[test]
    fn job_and_range_narrow_the_view() {
        let log = log_with_session();
        let view = SessionView::new(&log, SessionId::new(TaskId(1))).with_job(JobId(10));
        assert_eq!(view.frame_count(), 2);

        let ranged = SessionView::new(&log, SessionId::new(TaskId(1)))
            .with_range(SeqRange::up_to(EventSeq(2)));
        assert_eq!(ranged.frame_count(), 2); // seq 1 and 2
    }

    #[test]
    fn conversation_view_yields_only_turn_frames() {
        let log = log_with_session();
        let conv = SessionView::new(&log, SessionId::new(TaskId(1))).conversation();
        // seq 2 (user) and seq 3 (model); seq 1 (TaskCreated) is not a turn.
        assert_eq!(conv.turn_count(), 2);
    }

    #[test]
    fn frame_refs_cover_the_whole_log_with_tool_completed_flag() {
        let mut log = EventLog::new();
        log.append(
            &FrameMeta::new(1, EventKind::ToolCallCompleted)
                .task(TaskId(1))
                .job(JobId(10)),
            b"done",
        );
        log.append(
            &FrameMeta::new(2, EventKind::ModelOutputReceived).task(TaskId(1)),
            b"x",
        );
        let view = SessionView::new(&log, SessionId::new(TaskId(1)));
        let refs = view.frame_refs();
        assert_eq!(refs.len(), 2);
        assert!(refs[0].tool_completed);
        assert!(!refs[1].tool_completed);
    }
}
