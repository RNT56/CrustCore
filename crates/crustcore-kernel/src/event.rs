// SPDX-License-Identifier: Apache-2.0
//! Kernel events (`ROADMAP.md` §7.3). **CONTRACT FILE** — changes are serialized
//! and reviewed (CLAUDE.md §7.3).
//!
//! Every meaningful state change is an event. Adapters build these from external
//! inputs; the kernel consumes them deterministically. The on-disk encoding of
//! events is owned by `crustcore-eventlog` (the hash-chained frame format); this
//! `Event` is the in-memory envelope `Kernel::step` consumes.
//!
//! Fields beyond the kind/ids are the typed inputs the Phase 1 transition table
//! reads, each justified:
//! - `seq` — the adapter-assigned monotonic sequence used for the kernel's
//!   idempotency frontier (`docs/architecture.md` §2.3). `EventSeq::FIRST` (0) is
//!   the "unsequenced" sentinel for kernel-internal events.
//! - `timestamp` — event-carried time so the kernel evaluates lease/heartbeat,
//!   approval expiry, and wall budgets **without reading a clock** (determinism).
//! - `reversibility` — what a proposed side effect would cost, so policy can
//!   classify it (invariant 8). A side-effecting request with no reversibility is
//!   treated fail-safe as requiring approval.
//! - `approval_id` / `tool_call_id` — kernel-assigned ids that bind an approval
//!   to exactly one operation (invariant 14; defeats wrong-operation replay).
//! - `resolution` — an authorized user's approve/deny decision (invariant 4).
//! - `budget_delta` — what this event consumed, folded into the task budget
//!   (invariant 11).

use crustcore_types::{
    ApprovalId, ApprovalResolution, Budget, BudgetDelta, EventSeq, JobId, LeaseOwner,
    Reversibility, TaskId, Timestamp, ToolCallId,
};

/// The kind of a kernel event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventKind {
    TaskCreated,
    TaskPlanned,
    JobQueued,
    JobLeased,
    ModelRequestStarted,
    ModelOutputReceived,
    ToolCallRequested,
    ToolCallApproved,
    ToolCallDenied,
    ToolCallStarted,
    ToolCallCompleted,
    SandboxStarted,
    CommandStarted,
    CommandOutputCaptured,
    CommandCompleted,
    PatchProposed,
    PatchVerified,
    PatchRejected,
    ApprovalRequested,
    ApprovalResolved,
    UserMessageQueued,
    UserSteerReceived,
    GitHubOperationRequested,
    GitHubOperationCompleted,
    SecretRequested,
    SecretHandleStored,
    RiskDetected,
    TaskCompleted,
    TaskFailed,
    TaskKilled,
}

impl EventKind {
    /// Every event kind, in declaration order. Used by the kernel's exhaustive
    /// transition property tests so adding a kind forces a table+test update.
    pub const ALL: [EventKind; 30] = [
        EventKind::TaskCreated,
        EventKind::TaskPlanned,
        EventKind::JobQueued,
        EventKind::JobLeased,
        EventKind::ModelRequestStarted,
        EventKind::ModelOutputReceived,
        EventKind::ToolCallRequested,
        EventKind::ToolCallApproved,
        EventKind::ToolCallDenied,
        EventKind::ToolCallStarted,
        EventKind::ToolCallCompleted,
        EventKind::SandboxStarted,
        EventKind::CommandStarted,
        EventKind::CommandOutputCaptured,
        EventKind::CommandCompleted,
        EventKind::PatchProposed,
        EventKind::PatchVerified,
        EventKind::PatchRejected,
        EventKind::ApprovalRequested,
        EventKind::ApprovalResolved,
        EventKind::UserMessageQueued,
        EventKind::UserSteerReceived,
        EventKind::GitHubOperationRequested,
        EventKind::GitHubOperationCompleted,
        EventKind::SecretRequested,
        EventKind::SecretHandleStored,
        EventKind::RiskDetected,
        EventKind::TaskCompleted,
        EventKind::TaskFailed,
        EventKind::TaskKilled,
    ];
}

/// Who/what originated an event. Used for trust attribution and the event log's
/// `actor` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Actor {
    /// The trusted kernel itself.
    Kernel,
    /// An authorized human (e.g. via Telegram approval).
    User,
    /// A model/provider (untrusted).
    Model,
    /// A subagent worker (untrusted).
    Subagent,
    /// An external worker such as Codex/Claude Code (untrusted).
    ExternalWorker,
    /// A boundary adapter (Telegram/GitHub/MCP/net).
    Adapter,
}

impl Actor {
    /// Every actor, in declaration order (used by exhaustive tests).
    pub const ALL: [Actor; 6] = [
        Actor::Kernel,
        Actor::User,
        Actor::Model,
        Actor::Subagent,
        Actor::ExternalWorker,
        Actor::Adapter,
    ];
}

/// Whether an event's payload may be shown to a model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Visibility {
    /// May be included in model context (subject to redaction).
    ModelVisible,
    /// Internal only; never shown to a model.
    Internal,
}

/// An event delivered to [`super::Kernel::step`].
///
/// Construct with [`Event::internal`] / [`Event::inbound`] and refine with the
/// `with_*` builders; fields are public for adapters and tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// The kind of state change.
    pub kind: EventKind,
    /// The adapter-assigned sequence number (`EventSeq::FIRST` = unsequenced).
    pub seq: EventSeq,
    /// Event-carried time (epoch for unsequenced internal events).
    pub timestamp: Timestamp,
    /// The task this event pertains to, if any.
    pub task_id: Option<TaskId>,
    /// The job this event pertains to, if any.
    pub job_id: Option<JobId>,
    /// Who originated it.
    pub actor: Actor,
    /// Whether the payload is model-visible.
    pub visibility: Visibility,
    /// Reversibility of a proposed side effect (for `ToolCallRequested` /
    /// `GitHubOperationRequested`). `None` on such a request is treated fail-safe
    /// as requiring approval.
    pub reversibility: Option<Reversibility>,
    /// The approval this event references (e.g. on `ApprovalResolved`).
    pub approval_id: Option<ApprovalId>,
    /// The tool call this event binds to (operation binding for approvals).
    pub tool_call_id: Option<ToolCallId>,
    /// An authorized user's decision (on `ApprovalResolved`).
    pub resolution: Option<ApprovalResolution>,
    /// What this event consumed, folded into the task budget (invariant 11).
    pub budget_delta: Option<BudgetDelta>,
    /// The budget *limits* a task is seeded with (on `TaskCreated`; `None` =
    /// unlimited). Distinct from `budget_delta`, which is consumption.
    pub budget: Option<Budget>,
    /// The lease holder for a job event (on `JobLeased` it sets the owner; on a
    /// later job event a mismatch marks it stale — invariant 12).
    pub lease_owner: Option<LeaseOwner>,
}

impl Event {
    /// Builds a minimal kernel-originated internal event of `kind`: unsequenced
    /// (`EventSeq::FIRST`), epoch timestamp, `Actor::Kernel`, `Internal`
    /// visibility, no ids/payload.
    #[must_use]
    pub fn internal(kind: EventKind) -> Self {
        Event::base(kind, Actor::Kernel, Visibility::Internal)
    }

    /// Builds a sequenced inbound event of `kind` from `actor` with sequence
    /// `seq`, model-visible by default (adapters refine with `with_*`).
    #[must_use]
    pub fn inbound(kind: EventKind, seq: EventSeq, actor: Actor) -> Self {
        Event::base(kind, actor, Visibility::ModelVisible).with_seq(seq)
    }

    fn base(kind: EventKind, actor: Actor, visibility: Visibility) -> Self {
        Event {
            kind,
            seq: EventSeq::FIRST,
            timestamp: Timestamp::EPOCH,
            task_id: None,
            job_id: None,
            actor,
            visibility,
            reversibility: None,
            approval_id: None,
            tool_call_id: None,
            resolution: None,
            budget_delta: None,
            budget: None,
            lease_owner: None,
        }
    }

    /// Sets the sequence number.
    #[must_use]
    pub fn with_seq(mut self, seq: EventSeq) -> Self {
        self.seq = seq;
        self
    }

    /// Sets the event-carried timestamp.
    #[must_use]
    pub fn with_timestamp(mut self, timestamp: Timestamp) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Binds the event to a task.
    #[must_use]
    pub fn with_task(mut self, task_id: TaskId) -> Self {
        self.task_id = Some(task_id);
        self
    }

    /// Binds the event to a job.
    #[must_use]
    pub fn with_job(mut self, job_id: JobId) -> Self {
        self.job_id = Some(job_id);
        self
    }

    /// Sets the payload visibility.
    #[must_use]
    pub fn with_visibility(mut self, visibility: Visibility) -> Self {
        self.visibility = visibility;
        self
    }

    /// Sets the reversibility of a proposed side effect.
    #[must_use]
    pub fn with_reversibility(mut self, reversibility: Reversibility) -> Self {
        self.reversibility = Some(reversibility);
        self
    }

    /// References an approval.
    #[must_use]
    pub fn with_approval(mut self, approval_id: ApprovalId) -> Self {
        self.approval_id = Some(approval_id);
        self
    }

    /// Binds the event to a tool call.
    #[must_use]
    pub fn with_tool_call(mut self, tool_call_id: ToolCallId) -> Self {
        self.tool_call_id = Some(tool_call_id);
        self
    }

    /// Sets an approve/deny resolution.
    #[must_use]
    pub fn with_resolution(mut self, resolution: ApprovalResolution) -> Self {
        self.resolution = Some(resolution);
        self
    }

    /// Sets the budget consumption for this event.
    #[must_use]
    pub fn with_budget_delta(mut self, delta: BudgetDelta) -> Self {
        self.budget_delta = Some(delta);
        self
    }

    /// Seeds the task budget limits (use on `TaskCreated`).
    #[must_use]
    pub fn with_budget(mut self, budget: Budget) -> Self {
        self.budget = Some(budget);
        self
    }

    /// Sets the lease owner for a job event.
    #[must_use]
    pub fn with_lease_owner(mut self, owner: LeaseOwner) -> Self {
        self.lease_owner = Some(owner);
        self
    }
}
