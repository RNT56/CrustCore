// SPDX-License-Identifier: Apache-2.0
//! Kernel events (`ROADMAP.md` §7.3). **CONTRACT FILE** — changes are serialized
//! and reviewed (CLAUDE.md §7.3).
//!
//! Every meaningful state change is an event. Adapters build these from external
//! inputs; the kernel consumes them deterministically. The on-disk encoding of
//! events is owned by `crustcore-eventlog` (the hash-chained frame format).

use crustcore_types::{JobId, TaskId};

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
/// TODO(P1.1): carry a typed payload per kind and the originating event seq.
/// The scaffold keeps the envelope minimal but real.
#[derive(Debug, Clone)]
pub struct Event {
    /// The kind of state change.
    pub kind: EventKind,
    /// The task this event pertains to, if any.
    pub task_id: Option<TaskId>,
    /// The job this event pertains to, if any.
    pub job_id: Option<JobId>,
    /// Who originated it.
    pub actor: Actor,
    /// Whether the payload is model-visible.
    pub visibility: Visibility,
}

impl Event {
    /// Builds a minimal kernel-originated internal event of `kind`.
    #[must_use]
    pub fn internal(kind: EventKind) -> Self {
        Event {
            kind,
            task_id: None,
            job_id: None,
            actor: Actor::Kernel,
            visibility: Visibility::Internal,
        }
    }
}
