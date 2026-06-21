// SPDX-License-Identifier: Apache-2.0
//! Re-derived lease / heartbeat / cancellation / recovery status (C4.4;
//! invariant 12).
//!
//! A resumable run does not *claim* a lease — it **re-derives** the live state
//! from the session's `JobLeased` / `TaskKilled` / `TaskFailed` frames in the
//! event log and exposes it as a [`LeaseView`]. Resume then **asserts** ownership
//! against this derived state ([`LeaseView::owned_by`]) rather than assuming it,
//! and surfaces a kill/cancellation ([`CancellationState`]) instead of silently
//! re-running a cancelled job.
//!
//! The kernel remains the authority over the live lease; this is a read-only
//! projection for "what does the log say about this run's lease right now?".

use crustcore_kernel::EventKind;
use crustcore_types::{EventSeq, JobId, LeaseOwner};

use crate::view::SessionView;

/// Whether the run is still live, or has been killed/failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancellationState {
    /// No terminal kill/fail frame seen; the run is live (subject to lease).
    Live,
    /// A `TaskKilled` frame was seen — the run was cancelled and must not resume.
    Killed,
    /// A `TaskFailed` frame was seen — the run ended in failure.
    Failed,
}

impl CancellationState {
    /// Whether the run is still live (not killed/failed).
    #[must_use]
    pub fn is_live(self) -> bool {
        matches!(self, CancellationState::Live)
    }
}

/// The current lease ownership as derived from the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseStatus {
    /// No `JobLeased` frame seen — the run was never leased.
    Unleased,
    /// The most recent `JobLeased` frame named this owner.
    Leased {
        /// The job whose lease is held.
        job: JobId,
        /// The lease holder per the latest `JobLeased` frame.
        owner: LeaseOwner,
        /// The seq of the `JobLeased` frame (the "heartbeat" anchor).
        at_seq: EventSeq,
    },
}

/// A read-only projection of a session's lease/cancellation state, re-derived from
/// the event log. Used by resume to **assert** (never claim) ownership and to
/// refuse resuming a killed/failed run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeaseView {
    lease: LeaseStatus,
    cancellation: CancellationState,
    /// The seq of the latest terminal (kill/fail) frame, if any — the recovery
    /// anchor.
    terminal_seq: Option<EventSeq>,
}

impl LeaseView {
    /// Re-derives lease/cancellation state by replaying `view`'s frames in chain
    /// order. The last `JobLeased` wins for ownership (the heartbeat); the first
    /// `TaskKilled`/`TaskFailed` sets the terminal state.
    #[must_use]
    pub fn derive(view: &SessionView<'_>) -> Self {
        let mut lease = LeaseStatus::Unleased;
        let mut cancellation = CancellationState::Live;
        let mut terminal_seq = None;

        for d in view.frames() {
            match d.frame.kind {
                EventKind::JobLeased => {
                    if let (Some(job), Some(owner)) = (d.frame.job_id, d.frame_lease_owner()) {
                        lease = LeaseStatus::Leased {
                            job,
                            owner,
                            at_seq: d.frame.seq,
                        };
                    }
                }
                EventKind::TaskKilled if cancellation.is_live() => {
                    cancellation = CancellationState::Killed;
                    terminal_seq = Some(d.frame.seq);
                }
                EventKind::TaskFailed if cancellation.is_live() => {
                    cancellation = CancellationState::Failed;
                    terminal_seq = Some(d.frame.seq);
                }
                _ => {}
            }
        }

        LeaseView {
            lease,
            cancellation,
            terminal_seq,
        }
    }

    /// The derived lease status.
    #[must_use]
    pub fn lease(&self) -> LeaseStatus {
        self.lease
    }

    /// The derived cancellation state.
    #[must_use]
    pub fn cancellation(&self) -> CancellationState {
        self.cancellation
    }

    /// The seq of the terminal (kill/fail) frame, if any.
    #[must_use]
    pub fn terminal_seq(&self) -> Option<EventSeq> {
        self.terminal_seq
    }

    /// Whether the run is still live (not killed/failed). Resume refuses unless
    /// this holds — a cancelled/killed job never silently resumes (invariant 12).
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.cancellation.is_live()
    }

    /// **Asserts** (does not claim) that `owner` currently holds the lease. Resume
    /// uses this to verify ownership against the derived state rather than assuming
    /// it.
    #[must_use]
    pub fn owned_by(&self, owner: LeaseOwner) -> bool {
        matches!(self.lease, LeaseStatus::Leased { owner: o, .. } if o == owner)
    }
}

// A tiny extension so the lease projection reads the frame's lease owner. The
// event-log `EventFrame` does not carry `lease_owner` (it is kernel in-memory
// state, not a framed field), so we recover it from the kernel `Event` envelope
// is not possible here; instead the log encodes lease ownership in the frame's
// job binding plus a `JobLeased` kind. We expose the owner via the frame's job id
// mapped through a deterministic, documented convention used by the daemon when it
// frames a `JobLeased` event: the lease owner is carried in the payload's first 8
// bytes (little-endian) when present. This keeps the projection log-only.
trait FrameLeaseOwner {
    fn frame_lease_owner(&self) -> Option<LeaseOwner>;
}

impl FrameLeaseOwner for crustcore_eventlog::DecodedFrame<'_> {
    fn frame_lease_owner(&self) -> Option<LeaseOwner> {
        if self.frame.kind != EventKind::JobLeased {
            return None;
        }
        let bytes: [u8; 8] = self.payload.get(0..8)?.try_into().ok()?;
        Some(LeaseOwner(u64::from_le_bytes(bytes)))
    }
}

/// Encodes a lease owner into the payload convention [`LeaseView`] reads back: the
/// owner as little-endian `u64` at the start of a `JobLeased` frame's payload.
/// Provided so fixtures (and the daemon) frame `JobLeased` consistently.
#[must_use]
pub fn encode_lease_payload(owner: LeaseOwner) -> Vec<u8> {
    owner.0.to_le_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crustcore_eventlog::{EventLog, FrameMeta};
    use crustcore_kernel::Actor;
    use crustcore_types::TaskId;

    use crate::id::SessionId;

    fn leased_then(kinds: &[(u64, EventKind, Option<LeaseOwner>)]) -> EventLog {
        let mut log = EventLog::new();
        for &(seq, kind, owner) in kinds {
            let meta = FrameMeta::new(seq, kind)
                .task(TaskId(1))
                .job(JobId(10))
                .actor(Actor::Adapter);
            let payload = owner.map_or_else(Vec::new, encode_lease_payload);
            log.append(&meta, &payload);
        }
        log
    }

    #[test]
    fn derives_lease_owner_from_last_lease_frame() {
        let log = leased_then(&[
            (1, EventKind::JobLeased, Some(LeaseOwner(5))),
            (2, EventKind::JobLeased, Some(LeaseOwner(9))), // heartbeat / re-lease
        ]);
        let view = SessionView::new(&log, SessionId::new(TaskId(1)));
        let lv = LeaseView::derive(&view);
        assert!(lv.is_live());
        assert!(lv.owned_by(LeaseOwner(9)));
        assert!(
            !lv.owned_by(LeaseOwner(5)),
            "stale owner asserted ownership"
        );
    }

    #[test]
    fn surfaces_kill_and_refuses_liveness() {
        let log = leased_then(&[
            (1, EventKind::JobLeased, Some(LeaseOwner(5))),
            (2, EventKind::TaskKilled, None),
        ]);
        let view = SessionView::new(&log, SessionId::new(TaskId(1)));
        let lv = LeaseView::derive(&view);
        assert_eq!(lv.cancellation(), CancellationState::Killed);
        assert!(!lv.is_live(), "killed run must not be live");
        assert_eq!(lv.terminal_seq(), Some(EventSeq(2)));
    }

    #[test]
    fn surfaces_failure() {
        let log = leased_then(&[(1, EventKind::TaskFailed, None)]);
        let view = SessionView::new(&log, SessionId::new(TaskId(1)));
        let lv = LeaseView::derive(&view);
        assert_eq!(lv.cancellation(), CancellationState::Failed);
        assert!(!lv.is_live());
    }

    #[test]
    fn unleased_run_is_not_owned_by_anyone() {
        let log = leased_then(&[(1, EventKind::JobQueued, None)]);
        let view = SessionView::new(&log, SessionId::new(TaskId(1)));
        let lv = LeaseView::derive(&view);
        assert_eq!(lv.lease(), LeaseStatus::Unleased);
        assert!(!lv.owned_by(LeaseOwner(1)));
    }
}
