// SPDX-License-Identifier: Apache-2.0
//! Kernel state: compact arenas and the **pure, total** transition tables.
//!
//! State lives in `Vec`-of-records arenas (not `HashMap`/`BTreeMap`): a plain
//! `Vec` is the smallest storage, is cache-friendly, and — crucially —
//! preserves deterministic insertion-order iteration so replay and golden tests
//! are reproducible (`docs/architecture.md` §2.1). Lookups are linear scans,
//! which is fine at kernel cardinality (one user session, bounded by the
//! subagent-count budget, invariant 11); a sorted-`Vec` + binary search is the
//! documented next step only if cardinality is later shown to grow.
//!
//! The policy/lease-independent core of the state machine is expressed as two
//! pure functions — [`task_next`] and [`job_next`] — that map `(status, kind)` to
//! a transition. They are exhaustive over [`EventKind`] (no wildcard), so adding
//! an event kind is a compile error until the table and its property tests are
//! updated. Context-sensitive transitions (policy classification, budget
//! exhaustion, approval resolution, lease/expiry) are layered on top in
//! [`crate::kernel`].

use crustcore_types::{
    ApprovalId, ApprovalStatus, Budget, BudgetAxis, EventSeq, JobId, JobStatus, LeaseOwner, TaskId,
    TaskStatus, Timestamp, ToolCallId,
};

use crate::event::EventKind;

/// Default job lease lifetime, milliseconds. A lease not refreshed within this
/// window (measured against event-carried time, never a clock) expires
/// (invariant 12).
pub(crate) const LEASE_TTL_MS: u64 = 60_000;

/// Maximum number of ready jobs drained (and therefore model requests emitted)
/// per step. Keeps the action fan-out bounded (`docs/architecture.md` §2.3).
pub(crate) const READY_DRAIN_MAX: usize = 1;

/// Why a task is in `Blocked`, so `crustcore inspect` (and tests) can tell a
/// budget pause from a policy denial or a detected risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockReason {
    /// A budget axis was exhausted (invariant 11).
    BudgetExhausted(BudgetAxis),
    /// Policy denied a proposed side effect (invariant 8).
    PolicyDenied,
    /// An authorized user denied an approval (invariant 14).
    ApprovalDenied,
    /// A pending approval expired before it was resolved (invariant 14;
    /// `docs/policy.md` §4.1). The task pauses (resumable by a user steer)
    /// rather than stranding in `AwaitingApproval`.
    ApprovalExpired,
    /// A risk was detected (untrusted-input or contradictory-state defense).
    RiskDetected,
}

/// A task's record in the arena. Budget is co-located so the exhaustion check is
/// a single record read on the hot path (invariant 11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TaskEntry {
    pub id: TaskId,
    pub status: TaskStatus,
    pub budget: Budget,
    pub last_event: EventSeq,
    pub awaiting: Option<ApprovalId>,
    pub block_reason: Option<BlockReason>,
}

impl TaskEntry {
    pub(crate) fn new(id: TaskId, budget: Budget, seq: EventSeq) -> Self {
        TaskEntry {
            id,
            status: TaskStatus::Created,
            budget,
            last_event: seq,
            awaiting: None,
            block_reason: None,
        }
    }
}

/// The lease state of a job (invariant 12). Timing is compared against
/// event-carried [`Timestamp`]s; the kernel never reads a wall clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LeaseState {
    pub owner: Option<LeaseOwner>,
    pub expires_at: Timestamp,
    pub heartbeat_at: Timestamp,
}

impl LeaseState {
    pub(crate) fn unleased() -> Self {
        LeaseState {
            owner: None,
            expires_at: Timestamp::EPOCH,
            heartbeat_at: Timestamp::EPOCH,
        }
    }

    /// Grants/refreshes the lease at `now`, extending expiry by the TTL.
    pub(crate) fn refresh(&mut self, owner: Option<LeaseOwner>, now: Timestamp) {
        self.owner = owner;
        self.heartbeat_at = now;
        self.expires_at = Timestamp::from_millis(now.as_millis().saturating_add(LEASE_TTL_MS));
    }

    /// Whether `now` is strictly past the lease expiry.
    pub(crate) fn is_expired_at(&self, now: Timestamp) -> bool {
        now > self.expires_at
    }
}

/// A job's record in the arena.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct JobEntry {
    pub id: JobId,
    pub task: TaskId,
    pub status: JobStatus,
    pub lease: LeaseState,
    pub last_event: EventSeq,
}

impl JobEntry {
    pub(crate) fn new(id: JobId, task: TaskId, seq: EventSeq) -> Self {
        JobEntry {
            id,
            task,
            status: JobStatus::Queued,
            lease: LeaseState::unleased(),
            last_event: seq,
        }
    }
}

/// The exact operation an approval is bound to. Derived from kernel-assigned ids
/// (never a model-controlled string) so an approval cannot be retargeted to a
/// different operation (invariant 14; defeats the misleading-approval red-team).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ApprovalOp {
    pub tool_call_id: Option<ToolCallId>,
}

impl ApprovalOp {
    /// Whether `tool_call_id` names the same operation this approval is bound to.
    /// An unbound op (`None` on either side) is **never** satisfiable: a
    /// resolution must positively name the exact operation it authorizes, so a
    /// missing id cannot be silently matched (invariant 14; the kernel also
    /// refuses to mint a `None`-bound approval in the first place).
    pub(crate) fn matches(&self, tool_call_id: Option<ToolCallId>) -> bool {
        match (self.tool_call_id, tool_call_id) {
            (Some(bound), Some(given)) => bound == given,
            _ => false,
        }
    }
}

/// A pending/resolved approval's record in the arena.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ApprovalEntry {
    pub id: ApprovalId,
    pub task: TaskId,
    pub job: Option<JobId>,
    pub status: ApprovalStatus,
    pub op: ApprovalOp,
    pub expires_at: Timestamp,
}

/// The result of a pure transition function: stay put or move to a new status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TaskTransition {
    /// No status change (no-op + audit).
    Stay,
    /// Move to a new status.
    Move(TaskStatus),
}

/// The result of a pure job transition function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JobTransition {
    /// No status change.
    Stay,
    /// Move to a new status.
    Move(JobStatus),
}

/// The pure, total task transition table for **policy/lease-independent** event
/// kinds. Terminal statuses are absorbing (always `Stay`). Context-sensitive
/// kinds (`ToolCallRequested`, `GitHubOperationRequested`, `ApprovalResolved`)
/// return `Stay` here; their real transitions are decided in [`crate::kernel`]
/// with the extra context (policy decision, actor, approval entry). Budget
/// exhaustion is likewise handled in the kernel before this is consulted.
#[must_use]
pub(crate) fn task_next(status: TaskStatus, kind: EventKind) -> TaskTransition {
    use EventKind as K;
    use TaskStatus as S;

    if status.is_terminal() {
        return TaskTransition::Stay;
    }

    match kind {
        // Creation is handled by the kernel (the only task creator); re-create is
        // a no-op here.
        K::TaskCreated => TaskTransition::Stay,
        K::TaskPlanned => match status {
            S::Created => TaskTransition::Move(S::Planning),
            _ => TaskTransition::Stay,
        },
        K::JobQueued => match status {
            S::Created | S::Planning | S::Retrying => TaskTransition::Move(S::Queued),
            _ => TaskTransition::Stay,
        },
        K::JobLeased => match status {
            S::Queued | S::Planning => TaskTransition::Move(S::Running),
            _ => TaskTransition::Stay,
        },
        K::ModelRequestStarted => match status {
            S::Planning | S::Queued => TaskTransition::Move(S::Running),
            _ => TaskTransition::Stay,
        },
        // Bookkeeping / job-level / budget-bearing — no task status change here.
        K::ModelOutputReceived
        | K::ToolCallApproved
        | K::ToolCallDenied
        | K::ToolCallStarted
        | K::SandboxStarted
        | K::CommandStarted
        | K::CommandOutputCaptured
        | K::CommandCompleted
        | K::ToolCallCompleted
        | K::PatchProposed
        | K::UserMessageQueued
        | K::SecretRequested
        | K::SecretHandleStored => TaskTransition::Stay,
        // Policy-classified in the kernel.
        K::ToolCallRequested | K::GitHubOperationRequested => TaskTransition::Stay,
        // Resolved in the kernel (actor + approval-entry context).
        K::ApprovalResolved => TaskTransition::Stay,
        K::PatchVerified => match status {
            S::Running => TaskTransition::Move(S::Integrating),
            _ => TaskTransition::Stay,
        },
        K::PatchRejected => match status {
            S::Running | S::Blocked => TaskTransition::Move(S::Retrying),
            _ => TaskTransition::Stay,
        },
        // `AwaitingApproval` is entered **only** by the kernel when it mints an
        // approval in `classify_request` (with a real pending `awaiting` id). An
        // inbound `ApprovalRequested` event is an echo/audit and must NOT move the
        // task — otherwise an untrusted actor could park a task in
        // `AwaitingApproval` with no pending approval (a liveness trap).
        K::ApprovalRequested => TaskTransition::Stay,
        K::UserSteerReceived => match status {
            S::Blocked | S::AwaitingUserReview => TaskTransition::Move(S::Running),
            _ => TaskTransition::Stay,
        },
        K::GitHubOperationCompleted => match status {
            S::Integrating => TaskTransition::Move(S::AwaitingUserReview),
            _ => TaskTransition::Stay,
        },
        K::RiskDetected => TaskTransition::Move(S::Blocked),
        K::TaskCompleted => TaskTransition::Move(S::Completed),
        K::TaskFailed => TaskTransition::Move(S::Failed),
        K::TaskKilled => TaskTransition::Move(S::Killed),
    }
}

/// The pure, total job transition table for kind-driven transitions. Timing
/// transitions (`Expired`, `HeartbeatMissing`) are computed in [`crate::kernel`]
/// from event-carried timestamps and are not produced here. Terminal job
/// statuses are absorbing.
#[must_use]
pub(crate) fn job_next(status: JobStatus, kind: EventKind) -> JobTransition {
    use EventKind as K;
    use JobStatus as S;

    if status.is_terminal() {
        return JobTransition::Stay;
    }

    match kind {
        K::JobQueued => match status {
            S::Retrying => JobTransition::Move(S::Queued),
            _ => JobTransition::Stay,
        },
        K::JobLeased => match status {
            S::Queued => JobTransition::Move(S::Leased),
            _ => JobTransition::Stay,
        },
        K::ModelRequestStarted | K::ToolCallStarted | K::CommandStarted | K::SandboxStarted => {
            match status {
                S::Leased | S::HeartbeatMissing => JobTransition::Move(S::Running),
                _ => JobTransition::Stay,
            }
        }
        K::CommandOutputCaptured => match status {
            // Output is proof of life; recover a quiet job.
            S::HeartbeatMissing => JobTransition::Move(S::Running),
            _ => JobTransition::Stay,
        },
        K::CommandCompleted | K::ToolCallCompleted => match status {
            S::Running | S::Leased => JobTransition::Move(S::Completed),
            _ => JobTransition::Stay,
        },
        K::TaskKilled => JobTransition::Move(S::Killed),
        K::TaskFailed => JobTransition::Move(S::Failed),
        // Not job-state-changing on their own.
        K::TaskCreated
        | K::TaskPlanned
        | K::ModelOutputReceived
        | K::ToolCallRequested
        | K::ToolCallApproved
        | K::ToolCallDenied
        | K::PatchProposed
        | K::PatchVerified
        | K::PatchRejected
        | K::ApprovalRequested
        | K::ApprovalResolved
        | K::UserMessageQueued
        | K::UserSteerReceived
        | K::GitHubOperationRequested
        | K::GitHubOperationCompleted
        | K::SecretRequested
        | K::SecretHandleStored
        | K::RiskDetected
        | K::TaskCompleted => JobTransition::Stay,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_TASK_STATUSES: [TaskStatus; 13] = [
        TaskStatus::Created,
        TaskStatus::Queued,
        TaskStatus::Planning,
        TaskStatus::Running,
        TaskStatus::AwaitingApproval,
        TaskStatus::Blocked,
        TaskStatus::Retrying,
        TaskStatus::Integrating,
        TaskStatus::AwaitingUserReview,
        TaskStatus::Completed,
        TaskStatus::Failed,
        TaskStatus::Killed,
        TaskStatus::Archived,
    ];

    const ALL_JOB_STATUSES: [JobStatus; 9] = [
        JobStatus::Queued,
        JobStatus::Leased,
        JobStatus::Running,
        JobStatus::HeartbeatMissing,
        JobStatus::Retrying,
        JobStatus::Completed,
        JobStatus::Failed,
        JobStatus::Killed,
        JobStatus::Expired,
    ];

    /// The hand-maintained legal successor set per non-terminal task status — the
    /// reference table the pure transition function must never violate (P1.6).
    /// Self-moves (e.g. `RiskDetected` on an already-`Blocked` task) are allowed.
    fn legal_task_successors(from: TaskStatus) -> &'static [TaskStatus] {
        use TaskStatus as S;
        match from {
            S::Created => &[
                S::Planning,
                S::Queued,
                S::Blocked,
                S::Completed,
                S::Failed,
                S::Killed,
            ],
            S::Planning => &[
                S::Queued,
                S::Running,
                S::Blocked,
                S::Completed,
                S::Failed,
                S::Killed,
            ],
            S::Queued => &[S::Running, S::Blocked, S::Completed, S::Failed, S::Killed],
            S::Running => &[
                S::AwaitingApproval,
                S::Integrating,
                S::Retrying,
                S::Blocked,
                S::Completed,
                S::Failed,
                S::Killed,
            ],
            S::AwaitingApproval => &[S::Blocked, S::Completed, S::Failed, S::Killed],
            S::Blocked => &[S::Running, S::Retrying, S::Completed, S::Failed, S::Killed],
            S::Retrying => &[S::Queued, S::Blocked, S::Completed, S::Failed, S::Killed],
            S::Integrating => &[
                S::AwaitingUserReview,
                S::Blocked,
                S::Completed,
                S::Failed,
                S::Killed,
            ],
            S::AwaitingUserReview => &[S::Running, S::Blocked, S::Completed, S::Failed, S::Killed],
            // Terminal: no successors (absorbing).
            S::Completed | S::Failed | S::Killed | S::Archived => &[],
        }
    }

    fn legal_job_successors(from: JobStatus) -> &'static [JobStatus] {
        use JobStatus as S;
        match from {
            S::Queued => &[S::Leased, S::Killed, S::Failed],
            S::Leased => &[S::Running, S::Completed, S::Killed, S::Failed],
            S::Running => &[S::Completed, S::Killed, S::Failed],
            S::HeartbeatMissing => &[S::Running, S::Killed, S::Failed],
            S::Retrying => &[S::Queued, S::Killed, S::Failed],
            S::Completed | S::Failed | S::Killed | S::Expired => &[],
        }
    }

    // P1.6: no impossible task transition occurs, for every (status, kind).
    #[test]
    fn task_transitions_are_total_and_legal() {
        for status in ALL_TASK_STATUSES {
            for kind in EventKind::ALL {
                match task_next(status, kind) {
                    TaskTransition::Stay => {}
                    TaskTransition::Move(to) => {
                        assert!(
                            to == status || legal_task_successors(status).contains(&to),
                            "illegal task edge {status:?} --{kind:?}--> {to:?}"
                        );
                    }
                }
            }
        }
    }

    // P1.6: no impossible job transition occurs, for every (status, kind).
    #[test]
    fn job_transitions_are_total_and_legal() {
        for status in ALL_JOB_STATUSES {
            for kind in EventKind::ALL {
                match job_next(status, kind) {
                    JobTransition::Stay => {}
                    JobTransition::Move(to) => {
                        assert!(
                            to == status || legal_job_successors(status).contains(&to),
                            "illegal job edge {status:?} --{kind:?}--> {to:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn terminal_task_statuses_are_absorbing() {
        for status in ALL_TASK_STATUSES.into_iter().filter(|s| s.is_terminal()) {
            for kind in EventKind::ALL {
                assert_eq!(
                    task_next(status, kind),
                    TaskTransition::Stay,
                    "terminal {status:?} moved on {kind:?}"
                );
            }
        }
    }

    #[test]
    fn terminal_job_statuses_are_absorbing() {
        for status in ALL_JOB_STATUSES.into_iter().filter(|s| s.is_terminal()) {
            for kind in EventKind::ALL {
                assert_eq!(
                    job_next(status, kind),
                    JobTransition::Stay,
                    "terminal job {status:?} moved on {kind:?}"
                );
            }
        }
    }

    // Archived is only reachable via internal archival, never an event; and the
    // timing-only job statuses are never produced by the kind-driven table.
    #[test]
    fn events_never_reach_clock_or_archival_only_states() {
        for status in ALL_TASK_STATUSES {
            for kind in EventKind::ALL {
                assert_ne!(
                    task_next(status, kind),
                    TaskTransition::Move(TaskStatus::Archived),
                    "{status:?} --{kind:?}--> Archived must not be event-driven"
                );
            }
        }
        for status in ALL_JOB_STATUSES {
            for kind in EventKind::ALL {
                let t = job_next(status, kind);
                assert_ne!(t, JobTransition::Move(JobStatus::Expired));
                assert_ne!(t, JobTransition::Move(JobStatus::HeartbeatMissing));
            }
        }
    }

    // The safety edges every active task must honor.
    #[test]
    fn kill_and_risk_edges_hold_for_active_tasks() {
        for status in ALL_TASK_STATUSES.into_iter().filter(|s| !s.is_terminal()) {
            assert_eq!(
                task_next(status, EventKind::TaskKilled),
                TaskTransition::Move(TaskStatus::Killed)
            );
            assert_eq!(
                task_next(status, EventKind::RiskDetected),
                TaskTransition::Move(TaskStatus::Blocked)
            );
        }
    }
}
