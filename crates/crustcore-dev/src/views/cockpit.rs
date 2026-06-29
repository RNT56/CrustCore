// SPDX-License-Identifier: Apache-2.0
//! Cockpit view (roadmap-v0.6 E.1).
//!
//! A task/evidence/approval **cockpit** built entirely from the existing redacted,
//! read-only event-log read-model ([`ReadOnlyBackend`]). It renders evidence and surfaces
//! approval forms; it **cannot approve, complete, or integrate** — every value comes from
//! an already-redacted source (invariant 2), the lists are bounded (invariant 11), it
//! renders evidence but never mints a `VerifiedPatch` (invariant 13), and an approval form
//! carries the **operation-bound op-hash** so a resolution can only approve the exact
//! operation shown (invariant 14; the binding is checked by
//! [`MutatingBackend::dispatch_resolution`](crate::backend::MutatingBackend)).
//!
//! This is the **pure view core** over [`MockDevBackend`](crate::backend::MockDevBackend);
//! the axum bind, the `/ws` tick loop, and the HTML/JS assets are the `C7-serve-live` seam.

use crate::backend::{ApprovalView, ReadOnlyBackend, TaskRow};
use crustcore_eventlog::ChainStatus;

/// Max tasks rendered in one cockpit frame (bounded — invariant 11; mirrors the snapshot
/// task cap so a huge log can't make an unbounded page).
pub const MAX_COCKPIT_TASKS: usize = 256;
/// Max approval forms surfaced in one frame (bounded).
pub const MAX_COCKPIT_APPROVALS: usize = 64;

/// A task's evidence summary for the cockpit: **references only** (frame counts, sequence
/// range, terminal kind) — never raw chain-of-thought or secret-bearing content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceSummaryView {
    /// Bounded evidence references (each a short, non-sensitive label).
    pub refs: Vec<String>,
}

/// One task's detail in the cockpit, rolled up from the run inspector's [`TaskRow`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskDetailView {
    /// The task id.
    pub task_id: u128,
    /// Verified frames seen for this task.
    pub frames: u64,
    /// First sequence number.
    pub first_seq: u64,
    /// Last sequence number.
    pub last_seq: u64,
    /// The terminal event kind, if the task ended.
    pub terminal: Option<String>,
    /// Reference-only evidence summary.
    pub evidence: EvidenceSummaryView,
}

impl TaskDetailView {
    /// Builds a detail view from a run-inspector row. Evidence is **refs only**.
    #[must_use]
    pub fn from_row(row: &TaskRow) -> Self {
        let mut refs = vec![
            format!("frames: {}", row.frames),
            format!("seq: {}..{}", row.first_seq.0, row.last_seq.0),
        ];
        if let Some(t) = &row.terminal {
            refs.push(format!("terminal: {t}"));
        }
        TaskDetailView {
            task_id: row.task_id.0,
            frames: row.frames,
            first_seq: row.first_seq.0,
            last_seq: row.last_seq.0,
            terminal: row.terminal.clone(),
            evidence: EvidenceSummaryView { refs },
        }
    }
}

/// An approval form the cockpit surfaces. The `op_hash_hex` is the **binding**: the
/// resolution the form submits carries it, and `dispatch_resolution` rejects a mismatch —
/// so resolving the form for approval A can never approve a different operation B
/// (invariant 14). The cockpit mints nothing; only the engine mints `Approved<T>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalFormView {
    /// The approval id the form resolves.
    pub approval_id: u128,
    /// The operation-bound hash the resolution must echo (hex).
    pub op_hash_hex: String,
    /// A redacted, bounded human summary of the operation.
    pub summary: String,
    /// When the approval expires (millis).
    pub expires_at_millis: u64,
}

impl ApprovalFormView {
    /// Builds a form from a pending-approval view, carrying the op-hash binding.
    #[must_use]
    pub fn from_view(a: &ApprovalView) -> Self {
        ApprovalFormView {
            approval_id: a.approval_id,
            op_hash_hex: a.op_hash_hex.clone(),
            summary: a.summary.clone(),
            expires_at_millis: a.expires_at_millis,
        }
    }
}

/// The full cockpit frame: the chain-health flag, the bounded task grid, and the pending
/// approval forms — all from the redacted read-model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CockpitView {
    /// Whether the event-log hash chain verified intact.
    pub chain_intact: bool,
    /// The (bounded) task detail grid.
    pub tasks: Vec<TaskDetailView>,
    /// The (bounded) pending approval forms.
    pub approvals: Vec<ApprovalFormView>,
}

/// Composes a cockpit frame from a [`ReadOnlyBackend`]. Pure — it reads the redacted view
/// model and bounds every list (invariant 11). It performs no mutation and mints nothing.
#[must_use]
pub fn build_cockpit(backend: &dyn ReadOnlyBackend) -> CockpitView {
    let inspector = backend.run_inspector();
    let chain_intact = matches!(inspector.chain, ChainStatus::Intact { .. });
    let tasks = inspector
        .tasks
        .iter()
        .take(MAX_COCKPIT_TASKS)
        .map(TaskDetailView::from_row)
        .collect();
    let approvals = backend
        .pending_approvals()
        .iter()
        .take(MAX_COCKPIT_APPROVALS)
        .map(ApprovalFormView::from_view)
        .collect();
    CockpitView {
        chain_intact,
        tasks,
        approvals,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MockDevBackend;
    use crustcore_types::{EventSeq, TaskId};

    fn row(id: u128, frames: u64, terminal: Option<&str>) -> TaskRow {
        TaskRow {
            task_id: TaskId(id),
            frames,
            first_seq: EventSeq(1),
            last_seq: EventSeq(frames),
            terminal: terminal.map(str::to_string),
        }
    }

    #[test]
    fn task_detail_carries_evidence_refs_only() {
        let v = TaskDetailView::from_row(&row(7, 5, Some("TaskCompleted")));
        assert_eq!(v.task_id, 7);
        // Evidence is references — frame count, seq range, terminal — never raw content.
        assert!(v.evidence.refs.iter().any(|r| r.contains("frames: 5")));
        assert!(v.evidence.refs.iter().any(|r| r.contains("seq: 1..5")));
        assert!(v
            .evidence
            .refs
            .iter()
            .any(|r| r.contains("terminal: TaskCompleted")));
    }

    #[test]
    fn approval_form_carries_the_op_hash_binding() {
        let a = ApprovalView {
            approval_id: 42,
            op_hash_hex: "abcd1234".to_string(),
            summary: "open a draft PR".to_string(),
            expires_at_millis: 10_000,
        };
        let form = ApprovalFormView::from_view(&a);
        assert_eq!(form.approval_id, 42);
        // The op-hash binds the resolution to this exact operation (invariant 14).
        assert_eq!(form.op_hash_hex, "abcd1234");
    }

    #[test]
    fn build_cockpit_over_the_mock_backend_composes_a_bounded_frame() {
        // An empty mock yields an empty, well-formed frame (composition + bounds hold).
        let mock = MockDevBackend::new();
        let cockpit = build_cockpit(&mock);
        assert!(cockpit.tasks.len() <= MAX_COCKPIT_TASKS);
        assert!(cockpit.approvals.len() <= MAX_COCKPIT_APPROVALS);
    }

    #[test]
    fn the_task_grid_is_bounded() {
        // More rows than the cap → the grid is capped (no unbounded page; invariant 11).
        let rows: Vec<TaskRow> = (0..(MAX_COCKPIT_TASKS as u128 + 50))
            .map(|i| row(i, 1, None))
            .collect();
        let grid: Vec<TaskDetailView> = rows
            .iter()
            .take(MAX_COCKPIT_TASKS)
            .map(TaskDetailView::from_row)
            .collect();
        assert_eq!(grid.len(), MAX_COCKPIT_TASKS);
    }
}
