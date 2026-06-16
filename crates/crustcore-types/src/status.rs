// SPDX-License-Identifier: Apache-2.0
//! Task/job status enums and reversibility (`ROADMAP.md` §7.2, §8.4).
//!
//! The valid *transitions* between these states are owned by the kernel state
//! machine (`crustcore-kernel`); see invariant-style property tests added in
//! Phase 1 (`ROADMAP.md` §18, task P1.2/P1.6).

/// Lifecycle of a task.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TaskStatus {
    Created,
    Queued,
    Planning,
    Running,
    AwaitingApproval,
    Blocked,
    Retrying,
    Integrating,
    AwaitingUserReview,
    Completed,
    Failed,
    Killed,
    Archived,
}

/// Lifecycle of a job (one execution attempt). Every long-running job carries
/// lease/heartbeat/cancellation/recovery state (invariant 12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JobStatus {
    Queued,
    Leased,
    Running,
    HeartbeatMissing,
    Retrying,
    Completed,
    Failed,
    Killed,
    Expired,
}

/// Lifecycle of an approval request (invariants 4, 14). Created `Pending` when
/// policy asks for human approval; resolved by an authorized user only. See
/// `crustcore-kernel`'s approval flow and [`docs/policy.md`] §4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApprovalStatus {
    /// Awaiting an authorized user's decision.
    Pending,
    /// Approved by an authorized user.
    Approved,
    /// Denied by an authorized user.
    Denied,
    /// The approval window elapsed before a decision was applied.
    Expired,
}

impl ApprovalStatus {
    /// Whether the approval has reached a final decision (no further resolution
    /// applies; re-delivered resolutions are idempotent no-ops).
    #[must_use]
    pub const fn is_resolved(self) -> bool {
        matches!(
            self,
            ApprovalStatus::Approved | ApprovalStatus::Denied | ApprovalStatus::Expired
        )
    }
}

/// An authorized user's decision on a pending approval. The kernel acts on this
/// only when the carrying event's actor is the user (invariant 4); a model can
/// never originate an effective resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApprovalResolution {
    /// Permit the bound operation.
    Approve,
    /// Reject the bound operation.
    Deny,
}

/// How undoable an action is. Drives which operations require an approval token
/// (invariant 14). See `crustcore-policy` and [`docs/policy.md`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reversibility {
    /// Fully undoable (edit, build, test, local commit, worktree ops).
    Reversible,
    /// Undoable but requires explicit cleanup.
    ReversibleWithCleanup,
    /// Not undoable (merge, deploy, publish, force-push).
    Irreversible,
    /// Not undoable and data-destroying.
    Destructive,
}

impl TaskStatus {
    /// Terminal states emit no further tool actions (Phase 1 acceptance:
    /// killed tasks do not emit new tool actions).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            TaskStatus::Completed | TaskStatus::Failed | TaskStatus::Killed | TaskStatus::Archived
        )
    }
}

impl JobStatus {
    /// Terminal job states. A terminal job absorbs further events (at most an
    /// audit append), mirroring [`TaskStatus::is_terminal`] (invariant 12).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            JobStatus::Completed | JobStatus::Failed | JobStatus::Killed | JobStatus::Expired
        )
    }
}

impl Reversibility {
    /// Whether an action with this reversibility requires an approval token
    /// before it may be emitted (invariant 14).
    #[must_use]
    pub const fn requires_approval(self) -> bool {
        matches!(
            self,
            Reversibility::Irreversible | Reversibility::Destructive
        )
    }
}
