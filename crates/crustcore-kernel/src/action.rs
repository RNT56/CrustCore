// SPDX-License-Identifier: Apache-2.0
//! Kernel actions (`ROADMAP.md` §5.2). **CONTRACT FILE** — changes are
//! serialized and reviewed (CLAUDE.md §7.3).
//!
//! Actions are the *only* way the kernel asks the outside world to do anything.
//! The kernel emits them; adapters execute them. The kernel never performs a
//! side effect directly (invariant 8). Killed/terminal tasks emit no further
//! tool actions (Phase 1 acceptance).

use crustcore_types::{ApprovalId, JobId, TaskId};

/// A bounded instruction from the kernel to an adapter.
///
/// TODO(P1.3): flesh out variants with typed payloads (tool spec, command spec,
/// approval prompt, model request) and keep the list bounded
/// (`SmallVec<[Action; 4]>` once `smallvec` is admitted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Append an event to the hash-chained log (`crustcore-eventlog`).
    AppendEvent {
        /// The task the event belongs to, if any.
        task_id: Option<TaskId>,
    },
    /// Ask a model adapter to produce output for a job.
    RequestModel {
        /// The job awaiting model output.
        job_id: JobId,
    },
    /// Request a tool call be executed by an adapter (after policy allowed it).
    RunTool {
        /// The job the tool runs under.
        job_id: JobId,
    },
    /// Ask the user (via Telegram) to approve an irreversible action
    /// (invariant 14).
    RequestApproval {
        /// The pending approval.
        approval_id: ApprovalId,
    },
    /// Notify that a task reached a terminal state.
    TaskFinished {
        /// The finished task.
        task_id: TaskId,
    },
    /// No operation (e.g. an event that requires no outward action).
    Noop,
}
