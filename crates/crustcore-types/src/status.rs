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
