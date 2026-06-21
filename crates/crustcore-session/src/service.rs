// SPDX-License-Identifier: Apache-2.0
//! The consumer-facing session facade (C4.7).
//!
//! [`SessionService`] is the surface the daemon, `crustcore-flow` (C3), and the
//! dev UI (C7) use to address a run by id and `open`/`snapshot`/`resume`/`compact`/
//! `list` it. It is **strictly read / derive / verify-only.**
//!
//! ## Explicit non-goal (invariants 13, 18) — stated where it is enforced
//!
//! This facade **never** completes a task, integrates a patch, opens a PR, or
//! mints a `VerifiedPatch`; completion remains solely
//! `crustcore_backend::verify::run_verify`. It exposes **no** method that returns
//! an `Approved<T>`, a capability/approval token, a `VerifiedPatch`, or any other
//! side-effect trigger. This is enforced **by construction**: every method below
//! returns a borrowing view, a derived [`Snapshot`], a derived
//! [`CompactedHistory`], or a list of ids — never an authority object — and the
//! crate does not even depend on `crustcore-backend` or `crustcore-policy`, so it
//! has no `VerifiedPatch`/`Approved<T>` type in scope to return.
//!
//! `SessionService` borrows an [`EventLog`]; it keeps no second mutable store.

use crustcore_eventlog::EventLog;
use crustcore_receipts::ToolReceipt;
use crustcore_secrets::Redactor;
use crustcore_types::EventSeq;

use crate::compact::{CompactedHistory, CompactionPolicy};
use crate::id::SessionId;
use crate::lease::LeaseView;
use crate::resume::{resume, resume_to_head, ResumeRefused};
use crate::snapshot::{Snapshot, SnapshotError};
use crate::view::SessionView;

/// A read/derive/verify-only facade over an [`EventLog`].
///
/// Holds a `&EventLog` (the single source of truth) and a `&Redactor` used for
/// every model-visible projection. It mints nothing, mutates nothing, and exposes
/// no completion/integration/approval/capability method (see the module docs).
pub struct SessionService<'a> {
    log: &'a EventLog,
    redactor: &'a Redactor,
}

impl<'a> SessionService<'a> {
    /// Builds a service over a borrowed log + redactor.
    #[must_use]
    pub fn new(log: &'a EventLog, redactor: &'a Redactor) -> Self {
        SessionService { log, redactor }
    }

    /// Opens a read-only [`SessionView`] for `session`. No verification is run —
    /// this is the cheap "index over the log" entry point; use [`resume`](Self::resume)
    /// to gate on integrity.
    #[must_use]
    pub fn open(&self, session: SessionId) -> SessionView<'a> {
        SessionView::new(self.log, session)
    }

    /// Lists the [`SessionId`]s present in the log, in first-seen order
    /// (deterministic). A session is one task; a `TaskCreated` (or any
    /// task-bearing) frame marks its presence.
    #[must_use]
    pub fn list(&self) -> Vec<SessionId> {
        let mut seen: Vec<SessionId> = Vec::new();
        for d in self.log.iter() {
            if let Some(tid) = d.frame.task_id {
                let id = SessionId::new(tid);
                if !seen.contains(&id) {
                    seen.push(id);
                }
            }
        }
        seen
    }

    /// Derives a redacted, visibility-gated [`Snapshot`] of `session` up to
    /// `at_seq`. Derive-only; mints nothing.
    ///
    /// # Errors
    /// [`SnapshotError`] if the session has no frame at or below `at_seq`.
    pub fn snapshot(
        &self,
        session: SessionId,
        at_seq: EventSeq,
    ) -> Result<Snapshot, SnapshotError> {
        Snapshot::derive(&self.open(session), at_seq, self.redactor)
    }

    /// Resumes `session`: verifies the chain and the receipt join, returning a
    /// borrowing [`SessionView`] only on success. Verify-only; mutates no state.
    ///
    /// # Errors
    /// [`ResumeRefused`] on any integrity break.
    pub fn resume(
        &self,
        session: SessionId,
        receipts: &[ToolReceipt],
    ) -> Result<SessionView<'a>, ResumeRefused> {
        resume(self.log, session, receipts)
    }

    /// Like [`resume`](Self::resume) but anchors the chain to a persisted
    /// `expected_head` (detecting clean trailing-frame removal).
    ///
    /// # Errors
    /// [`ResumeRefused`] on any integrity break.
    pub fn resume_to_head(
        &self,
        session: SessionId,
        receipts: &[ToolReceipt],
        expected_head: [u8; 32],
    ) -> Result<SessionView<'a>, ResumeRefused> {
        resume_to_head(self.log, session, receipts, expected_head)
    }

    /// Re-derives the lease/cancellation status of `session` from the log
    /// (invariant 12). Read-only.
    #[must_use]
    pub fn lease(&self, session: SessionId) -> LeaseView {
        LeaseView::derive(&self.open(session))
    }

    /// Compacts `session`'s model-visible history under `policy`, returning bounded,
    /// redacted, never-authority [`CompactedHistory`]. Derive-only.
    ///
    /// Internally snapshots up to the session head, so it inherits the same
    /// fail-closed visibility gating and per-field redaction.
    #[must_use]
    pub fn compact(&self, session: SessionId, policy: CompactionPolicy) -> CompactedHistory {
        let view = self.open(session);
        // Snapshot to the head seq; if the session is empty there is nothing to
        // compact, so return an empty compaction under the policy.
        match view.head_seq() {
            Some(head) => match Snapshot::derive(&view, head, self.redactor) {
                Ok(snap) => policy.compact(&snap.turns, self.redactor),
                Err(_) => policy.compact(&[], self.redactor),
            },
            None => policy.compact(&[], self.redactor),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crustcore_eventlog::FrameMeta;
    use crustcore_kernel::{Actor, EventKind, Visibility};
    use crustcore_types::{JobId, TaskId};

    fn multi_session_log() -> EventLog {
        let mut log = EventLog::new();
        log.append(
            &FrameMeta::new(1, EventKind::TaskCreated).task(TaskId(1)),
            b"a",
        );
        log.append(
            &FrameMeta::new(2, EventKind::ModelOutputReceived)
                .task(TaskId(1))
                .actor(Actor::Model)
                .visibility(Visibility::ModelVisible),
            b"reply one",
        );
        log.append(
            &FrameMeta::new(3, EventKind::TaskCreated).task(TaskId(2)),
            b"b",
        );
        log
    }

    #[test]
    fn list_returns_sessions_in_first_seen_order() {
        let log = multi_session_log();
        let r = Redactor::new();
        let svc = SessionService::new(&log, &r);
        assert_eq!(
            svc.list(),
            vec![SessionId::new(TaskId(1)), SessionId::new(TaskId(2))]
        );
    }

    #[test]
    fn snapshot_and_compact_are_derive_only() {
        let log = multi_session_log();
        let r = Redactor::new();
        let svc = SessionService::new(&log, &r);
        let snap = svc
            .snapshot(SessionId::new(TaskId(1)), EventSeq(2))
            .unwrap();
        assert_eq!(snap.turn_count(), 1);

        let compacted = svc.compact(SessionId::new(TaskId(1)), CompactionPolicy::keep_last_n(4));
        assert!(compacted.text.as_str().contains("reply one"));
    }

    #[test]
    fn resume_through_service_gates_on_integrity() {
        let log = multi_session_log();
        let r = Redactor::new();
        let svc = SessionService::new(&log, &r);
        // Clean log, no receipts: resumes.
        assert!(svc.resume(SessionId::new(TaskId(1)), &[]).is_ok());
    }

    #[test]
    fn lease_is_read_only_projection() {
        let mut log = EventLog::new();
        log.append(
            &FrameMeta::new(1, EventKind::JobLeased)
                .task(TaskId(1))
                .job(JobId(10))
                .actor(Actor::Adapter),
            &crate::lease::encode_lease_payload(crustcore_types::LeaseOwner(7)),
        );
        let r = Redactor::new();
        let svc = SessionService::new(&log, &r);
        let lv = svc.lease(SessionId::new(TaskId(1)));
        assert!(lv.owned_by(crustcore_types::LeaseOwner(7)));
        assert!(lv.is_live());
    }
}
