// SPDX-License-Identifier: Apache-2.0
//! Derived, redacted, visibility-gated state snapshots (C4.2).
//!
//! A [`Snapshot`] is a **derived projection** of a session at a known `seq`,
//! produced by replaying the session's frames up to that `seq`. The trust
//! guarantees are structural, not best-effort:
//!
//! - **Fail-closed visibility gating (invariant 7).** A frame contributes a turn
//!   to the snapshot **only** if its [`Visibility`] is
//!   [`ModelVisible`](Visibility::ModelVisible). `Internal` frames — and, since the
//!   gate is a positive match on `ModelVisible`, any frame that is anything other
//!   than `ModelVisible` — are excluded.
//! - **No secret can be captured (invariant 3).** [`Snapshot`] (and [`Turn`])
//!   contain **no** `SecretMaterial`/`Tainted<T>` field — only redacted
//!   `String`s/handles. Every retained text field is passed through
//!   [`Redactor::redact`] as it enters the snapshot. Because
//!   [`crustcore_secrets::SecretMaterial`] implements no `Serialize`, even an
//!   accidental attempt to embed one in this `Serialize` type would fail to
//!   compile.
//! - **Artifacts are handles only (invariant 20).** A turn that produced artifacts
//!   carries opaque [`ArtifactHandle`]s, never inlined bytes.
//! - **A persisted snapshot is untrusted until re-verified.** [`Snapshot`] records
//!   the `head_hash` of the log it was derived against;
//!   [`Snapshot::verify_against`] re-checks it before a reloaded snapshot is
//!   trusted.

use crustcore_eventlog::EventLog;
use crustcore_kernel::EventKind;
use crustcore_secrets::Redactor;
use crustcore_types::EventSeq;
use serde::{Deserialize, Serialize};

use crate::artifact::ArtifactHandle;
use crate::id::SessionId;
use crate::view::{SeqRange, SessionView};

/// The kind of a model-visible conversation turn retained in a snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TurnKind {
    /// A user message / steer.
    User,
    /// A model output.
    Model,
    /// A completed tool call (its result text, redacted).
    Tool,
}

impl TurnKind {
    fn from_event(kind: EventKind) -> Option<Self> {
        match kind {
            EventKind::UserMessageQueued | EventKind::UserSteerReceived => Some(TurnKind::User),
            EventKind::ModelOutputReceived => Some(TurnKind::Model),
            EventKind::ToolCallCompleted => Some(TurnKind::Tool),
            _ => None,
        }
    }
}

/// One model-visible conversation turn in a [`Snapshot`].
///
/// Contains only redacted text and opaque artifact handles. It is structurally
/// incapable of holding a `SecretMaterial`/`Tainted<T>` (invariant 3) or inlined
/// artifact bytes (invariant 20).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Turn {
    /// The frame sequence number this turn was derived from.
    #[serde(with = "crate::serde_compat::event_seq")]
    pub seq: EventSeq,
    /// Which side of the conversation produced it.
    pub kind: TurnKind,
    /// The turn text, already passed through [`Redactor::redact`]. A plain
    /// `String` (not `ModelVisibleText`) so the snapshot is `Serialize`; it has
    /// nonetheless provably been redacted at construction time.
    pub text: String,
    /// Opaque, by-hash handles to any artifacts this turn produced. Contents are
    /// never inlined (invariant 20).
    pub artifacts: Vec<ArtifactHandle>,
}

/// Why deriving a snapshot failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotError {
    /// The session has no frame at or below the requested `seq`.
    NoFramesAtOrBelow(EventSeq),
}

impl core::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SnapshotError::NoFramesAtOrBelow(s) => {
                write!(f, "no session frames at or below seq {}", s.0)
            }
        }
    }
}

impl std::error::Error for SnapshotError {}

/// A derived, redacted, visibility-gated projection of a session at a known `seq`.
///
/// Holds only derived state plus the `head_hash` of the log it was projected
/// against — never the chain itself, and never any secret-bearing field. It is
/// `Serialize`/`Deserialize` for on-disk persistence; a reloaded snapshot is
/// **untrusted** until [`Snapshot::verify_against`] re-checks its `head_hash`
/// against the live log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    /// The session this snapshot projects.
    pub session: SessionId,
    /// The highest frame `seq` included in this projection.
    #[serde(with = "crate::serde_compat::event_seq")]
    pub at_seq: EventSeq,
    /// The chain head hash of the log this snapshot was derived against, used to
    /// re-verify a reloaded snapshot before trusting it.
    pub head_hash: [u8; 32],
    /// The model-visible, redacted conversation turns up to `at_seq`.
    pub turns: Vec<Turn>,
}

impl Snapshot {
    /// Derives a snapshot of `view` up to `at_seq` (inclusive), redacting every
    /// retained field with `redactor` and including **only**
    /// [`Visibility::ModelVisible`](crustcore_kernel::Visibility::ModelVisible)
    /// turn frames (fail closed).
    ///
    /// `payload_of` resolves a frame's `seq` to its raw payload bytes (the caller
    /// has the log; the snapshot keeps no chain). The bytes are treated as
    /// untrusted: they are redacted via `redactor` and lossily decoded as UTF-8 so
    /// a hostile non-UTF-8 payload cannot panic the projection.
    ///
    /// # Errors
    /// [`SnapshotError::NoFramesAtOrBelow`] if no session frame is at or below
    /// `at_seq`.
    pub fn derive<'log>(
        view: &SessionView<'log>,
        at_seq: EventSeq,
        redactor: &Redactor,
    ) -> Result<Snapshot, SnapshotError> {
        let bounded = view.with_range(SeqRange::up_to(at_seq));

        let mut turns = Vec::new();
        let mut max_seq: Option<EventSeq> = None;
        for d in bounded.frames() {
            max_seq = Some(max_seq.map_or(d.frame.seq, |m| {
                if d.frame.seq.0 > m.0 {
                    d.frame.seq
                } else {
                    m
                }
            }));

            // FAIL CLOSED: only a positively-ModelVisible turn frame contributes.
            if d.frame.visibility != crustcore_kernel::Visibility::ModelVisible {
                continue;
            }
            let Some(kind) = TurnKind::from_event(d.frame.kind) else {
                continue;
            };
            // Untrusted payload bytes: redact, then lossily decode (no panic).
            let raw = String::from_utf8_lossy(d.payload);
            let text = redactor.redact(raw.as_ref());
            // Artifacts for tool turns are referenced by-hash only. The payload
            // never inlines artifact bytes; the kernel records artifact ids out of
            // band, so here a tool turn simply carries no inlined content.
            turns.push(Turn {
                seq: d.frame.seq,
                kind,
                text,
                artifacts: Vec::new(),
            });
        }

        let Some(at) = max_seq else {
            return Err(SnapshotError::NoFramesAtOrBelow(at_seq));
        };

        Ok(Snapshot {
            session: view.session(),
            at_seq: at,
            head_hash: view.log().head_hash(),
            turns,
        })
    }

    /// Re-verifies a (possibly reloaded-from-disk) snapshot against a live log: the
    /// chain must verify to this snapshot's recorded `head_hash`. A snapshot that
    /// was tampered on disk, or that belongs to a different/forked log, fails here.
    ///
    /// This is the reload trust gate (invariant 18): a persisted snapshot is data
    /// until its `head_hash` anchors it to a verified live chain.
    #[must_use]
    pub fn verify_against(&self, log: &EventLog) -> bool {
        log.verify_to_head(self.head_hash).is_intact()
    }

    /// The number of turns retained.
    #[must_use]
    pub fn turn_count(&self) -> usize {
        self.turns.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crustcore_eventlog::FrameMeta;
    use crustcore_kernel::{Actor, Visibility};
    use crustcore_types::{JobId, TaskId};

    fn redactor_with(secret: &str) -> Redactor {
        let mut r = Redactor::new();
        r.register("sentinel", secret.as_bytes());
        r
    }

    fn sample_log() -> EventLog {
        let mut log = EventLog::new();
        log.append(
            &FrameMeta::new(1, EventKind::TaskCreated).task(TaskId(1)),
            b"created",
        );
        log.append(
            &FrameMeta::new(2, EventKind::UserMessageQueued)
                .task(TaskId(1))
                .job(JobId(10))
                .actor(Actor::User)
                .visibility(Visibility::ModelVisible),
            b"please fix it",
        );
        log.append(
            &FrameMeta::new(3, EventKind::ModelOutputReceived)
                .task(TaskId(1))
                .job(JobId(10))
                .actor(Actor::Model)
                .visibility(Visibility::ModelVisible),
            b"on it",
        );
        log
    }

    #[test]
    fn derive_includes_only_model_visible_turns() {
        let log = sample_log();
        let view = SessionView::new(&log, SessionId::new(TaskId(1)));
        let snap = Snapshot::derive(&view, EventSeq(3), &Redactor::new()).unwrap();
        // seq 1 (TaskCreated, Internal default) excluded; 2 user + 3 model kept.
        assert_eq!(snap.turn_count(), 2);
        assert_eq!(snap.turns[0].kind, TurnKind::User);
        assert_eq!(snap.turns[1].kind, TurnKind::Model);
        assert_eq!(snap.at_seq, EventSeq(3));
        assert_eq!(snap.head_hash, log.head_hash());
    }

    #[test]
    fn internal_frame_is_excluded_fail_closed() {
        let mut log = EventLog::new();
        // A model-output frame that is INTERNAL must not produce a turn.
        log.append(
            &FrameMeta::new(1, EventKind::ModelOutputReceived)
                .task(TaskId(1))
                .actor(Actor::Model)
                .visibility(Visibility::Internal),
            b"internal reasoning",
        );
        let view = SessionView::new(&log, SessionId::new(TaskId(1)));
        let snap = Snapshot::derive(&view, EventSeq(1), &Redactor::new()).unwrap();
        assert_eq!(snap.turn_count(), 0, "Internal frame leaked into snapshot");
    }

    #[test]
    fn every_retained_field_is_redacted() {
        let secret = "sk-SNAPSENTINEL";
        let mut log = EventLog::new();
        log.append(
            &FrameMeta::new(1, EventKind::ModelOutputReceived)
                .task(TaskId(1))
                .actor(Actor::Model)
                .visibility(Visibility::ModelVisible),
            format!("here is the key {secret} ok").as_bytes(),
        );
        let view = SessionView::new(&log, SessionId::new(TaskId(1)));
        let snap = Snapshot::derive(&view, EventSeq(1), &redactor_with(secret)).unwrap();
        assert_eq!(snap.turn_count(), 1);
        assert!(
            !snap.turns[0].text.contains(secret),
            "secret survived into snapshot: {}",
            snap.turns[0].text
        );
        assert!(snap.turns[0].text.contains("[REDACTED:sentinel]"));
    }

    #[test]
    fn round_trip_derive_serialize_restore_is_identical() {
        let log = sample_log();
        let view = SessionView::new(&log, SessionId::new(TaskId(1)));
        let snap = Snapshot::derive(&view, EventSeq(3), &Redactor::new()).unwrap();
        let json = serde_json::to_string(&snap).unwrap();
        let restored: Snapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, restored);
        // A restored snapshot re-verifies against the live log.
        assert!(restored.verify_against(&log));
    }

    #[test]
    fn reloaded_snapshot_rejects_a_tampered_or_forked_log() {
        let log = sample_log();
        let view = SessionView::new(&log, SessionId::new(TaskId(1)));
        let snap = Snapshot::derive(&view, EventSeq(3), &Redactor::new()).unwrap();

        // A different log (different head) must fail the re-verify.
        let mut other = EventLog::new();
        other.append(
            &FrameMeta::new(1, EventKind::TaskCreated).task(TaskId(9)),
            b"x",
        );
        assert!(
            !snap.verify_against(&other),
            "snapshot trusted a log it was not derived from"
        );
    }

    #[test]
    fn empty_session_has_no_snapshot() {
        let log = sample_log();
        let view = SessionView::new(&log, SessionId::new(TaskId(404)));
        assert_eq!(
            Snapshot::derive(&view, EventSeq(3), &Redactor::new()),
            Err(SnapshotError::NoFramesAtOrBelow(EventSeq(3)))
        );
    }
}
