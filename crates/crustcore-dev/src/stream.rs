// SPDX-License-Identifier: Apache-2.0
//! The **pure snapshot-streaming core** for the live `/ws` stream (`C7-serve-live`).
//!
//! This module is **always compiled** — it links no axum/tokio/socket. It is the
//! deterministic engine behind the live `/ws` stream: given the read-only backend and an
//! opaque [`SnapshotCursor`], [`next_snapshot`] reads the existing read-model
//! ([`ReadOnlyBackend::run_inspector`] + [`ReadOnlyBackend::pending_approvals`]), bounds it,
//! and returns the next [`DevSnapshot`] **iff it changed** since the cursor — plus an
//! advanced cursor. The whole thing is synchronous, side-effect-free, and CI-tested over
//! `MockDevBackend` with no socket. The `serve`-gated layer ([`crate::serve`]) is the only
//! part that needs a real socket; it just calls this core on an interval and emits each
//! changed frame as an SSE event (`TODO(C7-serve-live)` is reduced to that tick loop).
//!
//! ## Why it cannot leak or mutate
//!
//! - **Read-only by type:** [`next_snapshot`] takes `&dyn ReadOnlyBackend` — never `&mut`,
//!   never [`DevBackend`](crate::backend::DevBackend) — so it structurally cannot reach the
//!   one mutating capability (dimension (c)). It mints nothing, appends no frame, and never
//!   reaches the verifier (invariant 13).
//! - **Redaction inherited:** every field of [`DevSnapshot`] is an already-redacted view
//!   model ([`RunInspectorView`]/[`ApprovalView`] are produced redacted by the views and by
//!   `request_approval`), so the rendered frame carries no raw secret (invariant 2). A
//!   leak-canary test pins this.
//! - **Bounded everything:** the approval list and task list are truncated to fixed caps so
//!   a flood of pending approvals or tasks cannot blow up a frame (invariant 11).

use crate::backend::{ApprovalView, ReadOnlyBackend, RunInspectorView};

/// Max pending approvals carried in one snapshot frame (bounded — invariant 11). A flood of
/// pending approvals cannot grow the frame past this.
pub const MAX_SNAPSHOT_APPROVALS: usize = 256;

/// Max per-task rollup rows carried in one snapshot frame (bounded — invariant 11). This is
/// **required**, not defensive: `crustcore_eventlog::EventLog::inspect` emits one task row per
/// distinct task id with **no upstream cap**, so without this an unbounded log would grow the
/// streamed frame without limit. Pinned by `tasks_are_bounded`.
pub const MAX_SNAPSHOT_TASKS: usize = 256;

/// An opaque change/pagination handle for the snapshot stream. It carries only monotone
/// signals already present in the read-model — the **total verified frame count** and the
/// **pending-approval count** — plus a monotonic emit counter (`seq`, surfaced as the SSE
/// `id:` so a reconnecting client can resume). "Has the snapshot changed?" is therefore a
/// pure comparison with **no hidden server state**.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SnapshotCursor {
    /// Total verified frames last emitted (`RunInspectorView::total_frames`).
    pub frames: u64,
    /// Pending-approval count last emitted.
    pub pending: u32,
    /// Monotonic emit counter (the SSE event id). `0` means "nothing emitted yet".
    pub seq: u64,
}

impl SnapshotCursor {
    /// The starting cursor: nothing emitted yet. The first [`next_snapshot`] from here
    /// **always** emits an initial frame (so a freshly-connected client gets the current
    /// state even if it is empty), then subsequent calls debounce on `(frames, pending)`.
    #[must_use]
    pub fn start() -> Self {
        SnapshotCursor {
            frames: 0,
            pending: 0,
            seq: 0,
        }
    }
}

impl Default for SnapshotCursor {
    fn default() -> Self {
        SnapshotCursor::start()
    }
}

/// A composite, already-redacted, already-bounded snapshot of the frequently-changing
/// runtime read-model: the run-inspector rollup plus the pending approvals. It introduces
/// no new payload bytes — every field comes from an existing redacted view model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevSnapshot {
    /// The run-inspector rollup (chain status + per-task rows; bounded).
    pub inspector: RunInspectorView,
    /// The pending approvals the UI surfaces (already redacted; **bounded** to
    /// [`MAX_SNAPSHOT_APPROVALS`] — a view, not the full set; see `pending`).
    pub approvals: Vec<ApprovalView>,
    /// The **true** total verified frame count — a change signal, not a list length. It can
    /// exceed `inspector.tasks.len()` (which is capped).
    pub frames: u64,
    /// The **true** total pending-approval count — a change signal. It may exceed
    /// `approvals.len()` (capped at [`MAX_SNAPSHOT_APPROVALS`]): the count is the real total,
    /// the list is a bounded view. It is the *pre-truncation* total **on purpose** — that
    /// way a change is still detected when the real count sits above the cap (a
    /// post-truncation count would pin at the cap and hide churn, showing stale data).
    pub pending: u32,
}

/// The result of one [`next_snapshot`] call: the next frame (only when it changed),
/// the advanced cursor, and whether anything changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotBatch {
    /// `Some` only when the snapshot changed since the incoming cursor (debounced). An idle
    /// stream therefore emits nothing but transport keep-alives.
    pub frame: Option<DevSnapshot>,
    /// The cursor to carry into the next call. `seq` advances by 1 iff a frame was emitted.
    pub next_cursor: SnapshotCursor,
    /// Whether the snapshot changed (true iff `frame` is `Some`).
    pub changed: bool,
}

/// Compute the next snapshot. **Pure, deterministic, synchronous, read-only.**
///
/// Reads the read-model, bounds it, and returns the next [`DevSnapshot`] iff it changed
/// since `cursor` (the first call — `cursor.seq == 0` — always emits an initial frame).
/// No socket, no async, no mutation, no frame append, never reaches the verifier.
#[must_use]
pub fn next_snapshot(backend: &dyn ReadOnlyBackend, cursor: SnapshotCursor) -> SnapshotBatch {
    let mut inspector = backend.run_inspector();
    let mut approvals = backend.pending_approvals();

    // Change signals are the TRUE totals, captured BEFORE bounding — so a change is detected
    // even when a total sits above its display cap (the bounded lists below would otherwise
    // hide it). `total_frames` is the real frame count; `pending` the real pending count.
    let frames = inspector.total_frames;
    let pending = approvals.len() as u32;

    // Bound the frame for display (invariant 11). REQUIRED for tasks: `EventLog::inspect` does
    // not cap the task count, so an unbounded log would otherwise blow up the frame.
    inspector.tasks.truncate(MAX_SNAPSHOT_TASKS);
    approvals.truncate(MAX_SNAPSHOT_APPROVALS);

    // Emit on the first call (initial state) or whenever a change signal moved.
    let changed = cursor.seq == 0 || frames != cursor.frames || pending != cursor.pending;
    if !changed {
        return SnapshotBatch {
            frame: None,
            next_cursor: cursor,
            changed: false,
        };
    }

    let snapshot = DevSnapshot {
        inspector,
        approvals,
        frames,
        pending,
    };
    SnapshotBatch {
        frame: Some(snapshot),
        next_cursor: SnapshotCursor {
            frames,
            pending,
            seq: cursor.seq + 1,
        },
        changed: true,
    }
}

/// Render a snapshot frame to the bytes the SSE `data:` field carries. Uses the repo's
/// `Debug`-render convention (identical to every other read route), so the stream
/// introduces no new serialization surface and inherits the view models' redaction.
#[must_use]
pub fn render_frame(frame: &DevSnapshot) -> String {
    format!("{frame:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{DevBackend, MockDevBackend};
    use crustcore_secrets::Redactor;
    use crustcore_types::Timestamp;

    #[test]
    fn initial_snapshot_is_emitted_then_debounced() {
        let mock = MockDevBackend::new();
        let ro = mock.read_only();

        // First call (seq == 0) always emits the current state — even an empty backend.
        let first = next_snapshot(ro, SnapshotCursor::start());
        assert!(first.changed);
        let frame = first.frame.expect("the initial snapshot is always emitted");
        assert_eq!(frame.frames, 0);
        assert_eq!(frame.pending, 0);
        assert_eq!(first.next_cursor.seq, 1);

        // A second call with the advanced cursor sees no change → nothing to send.
        let second = next_snapshot(ro, first.next_cursor);
        assert!(!second.changed);
        assert!(second.frame.is_none());
        assert_eq!(second.next_cursor, first.next_cursor);
    }

    #[test]
    fn a_new_pending_approval_changes_the_snapshot() {
        let mut mock = MockDevBackend::new();
        // Consume the initial emit so the cursor is past the seq==0 always-emit.
        let c0 = next_snapshot(mock.read_only(), SnapshotCursor::start()).next_cursor;

        mock.request_approval(
            7,
            "push branch x",
            "push branch x",
            Timestamp::from_millis(10_000),
        );

        let batch = next_snapshot(mock.read_only(), c0);
        assert!(batch.changed, "a new pending approval is a change");
        let frame = batch.frame.expect("changed → a frame");
        assert_eq!(frame.pending, 1);
        assert_eq!(frame.approvals.len(), 1);
        assert_eq!(batch.next_cursor.seq, c0.seq + 1);
    }

    #[test]
    fn snapshot_is_deterministic_and_read_only() {
        let mock = MockDevBackend::new();
        let ro = mock.read_only();

        // Same fixed state → identical batches (replay/determinism).
        let a = next_snapshot(ro, SnapshotCursor::start());
        let b = next_snapshot(ro, SnapshotCursor::start());
        assert_eq!(a, b);

        // Read-only: the call mutates no observable backend state.
        assert_eq!(mock.read_only().run_inspector().total_frames, 0);
        assert!(mock.read_only().pending_approvals().is_empty());
    }

    #[test]
    fn approvals_are_bounded() {
        let mut mock = MockDevBackend::new();
        // Seed more pending approvals than the cap allows.
        for i in 0..(MAX_SNAPSHOT_APPROVALS as u128 + 50) {
            mock.request_approval(i, "op", "op", Timestamp::from_millis(10_000));
        }
        let frame = next_snapshot(mock.read_only(), SnapshotCursor::start())
            .frame
            .expect("a frame");
        assert_eq!(
            frame.approvals.len(),
            MAX_SNAPSHOT_APPROVALS,
            "the approval list is truncated to the bound"
        );
    }

    #[test]
    fn tasks_are_bounded() {
        use crustcore_eventlog::{EventLog, FrameMeta};
        use crustcore_kernel::event::EventKind;
        use crustcore_types::TaskId;

        // `EventLog::inspect` emits one task row per distinct task with no upstream cap, so
        // seed more distinct tasks than the bound and assert the frame truncates the rows.
        let mut log = EventLog::new();
        for i in 0..(MAX_SNAPSHOT_TASKS as u64 + 50) {
            log.append(
                &FrameMeta::new(i + 1, EventKind::TaskCreated).task(TaskId(u128::from(i) + 1)),
                b"created",
            );
        }
        let mock = MockDevBackend::new().with_log(log);
        let frame = next_snapshot(mock.read_only(), SnapshotCursor::start())
            .frame
            .expect("a frame");
        assert_eq!(
            frame.inspector.tasks.len(),
            MAX_SNAPSHOT_TASKS,
            "the per-task rows are truncated to the bound"
        );
        // The change signal stays the TRUE total even though the row list is capped.
        assert_eq!(frame.frames, MAX_SNAPSHOT_TASKS as u64 + 50);
    }

    #[test]
    fn rendered_frame_carries_no_redacted_secret() {
        // Coverage note: the only free-text, user/secret-influenced field in a DevSnapshot is
        // `ApprovalView.summary` (redacted at `request_approval` time, backend.rs). The
        // inspector rows (`RunInspectorView`/`TaskRow`) carry only closed-enum kind names,
        // numeric ids, and chain status — no secret-capable text — and adding a String field
        // to those view models is a contract change reviewed against invariant 2. This canary
        // pins the summary path; `views::provider` has the parallel canary for model cards.
        //
        // A redactor seeded with a sentinel; an approval summary that mentions it is
        // redacted at request time, so the streamed frame must not contain the sentinel
        // (invariant 2 — the snapshot inherits the view models' redaction).
        let mut redactor = Redactor::new();
        redactor.register("api-key", b"sk-SENTINEL-SECRET");
        let mut mock = MockDevBackend::new().with_redactor(redactor);
        mock.request_approval(
            1,
            "deploy with sk-SENTINEL-SECRET",
            "deploy with sk-SENTINEL-SECRET",
            Timestamp::from_millis(10_000),
        );

        let frame = next_snapshot(mock.read_only(), SnapshotCursor::start())
            .frame
            .expect("a frame");
        let rendered = render_frame(&frame);
        assert!(
            !rendered.contains("sk-SENTINEL-SECRET"),
            "the streamed frame must not leak the sentinel secret"
        );
        assert!(
            rendered.contains("[REDACTED:api-key]"),
            "the secret should be present only as its redacted marker"
        );
    }
}
