// SPDX-License-Identifier: Apache-2.0
//! Integration: snapshot round-trip, on-disk persistence, resume verify-or-refuse
//! over the full event-log tamper corpus, and the forged-receipt join-break corpus
//! (C4 test/verify strategy). Fully deterministic — no net/secrets/binaries.

mod common;

use common::*;
use crustcore_eventlog::{BreakReason, EventLog};
use crustcore_receipts::join::JoinBreak;
use crustcore_session::resume::ResumeRefused;
use crustcore_session::{resume, resume_to_head, SessionId, SessionService, Snapshot};
use crustcore_types::{EventSeq, TaskId};

fn session() -> SessionId {
    SessionId::new(TaskId(TASK))
}

#[test]
fn snapshot_round_trip_derive_serialize_restore_identical_view() {
    let log = clean_log();
    let r = redactor();
    let svc = SessionService::new(&log, &r);
    let snap = svc.snapshot(session(), EventSeq(5)).unwrap();

    // Derive → serialize → restore → identical.
    let json = serde_json::to_string(&snap).unwrap();
    let restored: Snapshot = serde_json::from_str(&json).unwrap();
    assert_eq!(snap, restored);

    // The reloaded persisted snapshot re-verifies its head_hash against the live log.
    assert!(restored.verify_against(&log));
    assert_eq!(restored.head_hash, log.head_hash());

    // The secret never enters the serialized snapshot (invariant 3 — runtime check).
    assert!(
        !json.contains(SECRET),
        "secret leaked into serialized snapshot JSON"
    );
}

#[test]
fn persisted_snapshot_survives_disk_round_trip_and_reverifies() {
    let log = clean_log();
    let r = redactor();
    let svc = SessionService::new(&log, &r);
    let snap = svc.snapshot(session(), EventSeq(5)).unwrap();

    let path = std::env::temp_dir().join(format!(
        "cc-session-snap-{}-{}.json",
        std::process::id(),
        snap.at_seq.0
    ));
    std::fs::write(&path, serde_json::to_vec(&snap).unwrap()).unwrap();

    let bytes = std::fs::read(&path).unwrap();
    let reloaded: Snapshot = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(reloaded, snap);
    // Untrusted until re-verified — and it re-verifies against the live log.
    assert!(reloaded.verify_against(&log));

    let _ = std::fs::remove_file(&path);
}

#[test]
fn clean_fixture_resumes_when_intact_and_joined() {
    let log = clean_log();
    let receipts = vec![clean_receipt()];
    let view = resume(&log, session(), &receipts).expect("clean fixture must resume");
    assert_eq!(view.task_id(), TaskId(TASK));
    assert_eq!(view.frame_count(), 5);
}

// The committed on-disk fixture (a daemon-shaped log) loads, verifies, and resumes.
// Regenerate it with `cargo run -p crustcore-session --example gen_fixture`.
#[test]
fn committed_on_disk_fixture_loads_verifies_and_resumes() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/clean_session.cclog");
    let bytes = std::fs::read(path).expect("fixture present");
    let log = EventLog::from_bytes(bytes);
    // A persisted log is untrusted until verified — and this one verifies.
    assert!(log.verify().is_intact());
    // A receipt anchored at the fixture's ToolCallCompleted frame (seq 4) joins.
    let view = resume(&log, session(), &[receipt_at(4, TASK, JOB)]).expect("fixture must resume");
    assert_eq!(view.frame_count(), 5);

    // A snapshot over the fixture is derivable and serializable.
    let r = redactor();
    let svc = SessionService::new(&log, &r);
    let snap = svc.snapshot(session(), EventSeq(5)).unwrap();
    assert!(snap.verify_against(&log));
}

// ---- event-log tamper corpus: each class returns its exact ResumeRefused ----

#[test]
fn tamper_flipped_payload_refuses_payload_hash_mismatch() {
    let mut bytes = clean_log().bytes().to_vec();
    let pos = bytes.windows(7).position(|w| w == b"created").unwrap();
    bytes[pos] ^= 0xff;
    let log = EventLog::from_bytes(bytes);
    match resume(&log, session(), &[]).unwrap_err() {
        ResumeRefused::LogBroken { reason, .. } => {
            assert_eq!(reason, BreakReason::PayloadHashMismatch);
        }
        other => panic!("expected LogBroken, got {other:?}"),
    }
}

#[test]
fn tamper_deleted_frame_refuses_prev_hash_mismatch() {
    let full = clean_log();
    let bytes = full.bytes();
    let lens = frame_lengths();
    // Drop frame index 2 (the user message at seq 3).
    let start2: usize = lens[..2].iter().sum();
    let end2 = start2 + lens[2];
    let mut spliced = Vec::new();
    spliced.extend_from_slice(&bytes[..start2]);
    spliced.extend_from_slice(&bytes[end2..]);
    let log = EventLog::from_bytes(spliced);
    match resume(&log, session(), &[]).unwrap_err() {
        ResumeRefused::LogBroken { reason, .. } => {
            assert_eq!(reason, BreakReason::PrevHashMismatch);
        }
        other => panic!("expected LogBroken, got {other:?}"),
    }
}

#[test]
fn tamper_reordered_frames_refuses() {
    let full = clean_log();
    let bytes = full.bytes();
    let lens = frame_lengths();
    let off = |i: usize| -> (usize, usize) {
        let s: usize = lens[..i].iter().sum();
        (s, s + lens[i])
    };
    // Swap frames 3 and 4 (seq 4 and seq 5).
    let (s3, e3) = off(3);
    let (s4, e4) = off(4);
    let mut spliced = Vec::new();
    spliced.extend_from_slice(&bytes[..s3]);
    spliced.extend_from_slice(&bytes[s4..e4]);
    spliced.extend_from_slice(&bytes[s3..e3]);
    let log = EventLog::from_bytes(spliced);
    assert!(
        resume(&log, session(), &[]).is_err(),
        "reordered frames must refuse to resume"
    );
}

#[test]
fn tamper_inserted_frame_refuses() {
    // Insert a duplicate of frame 0's bytes after frame 0: the inserted frame's
    // prev_hash (genesis) will not match the real frame 0's frame_hash, and its seq
    // is non-monotonic — either way the chain breaks.
    let full = clean_log();
    let bytes = full.bytes();
    let lens = frame_lengths();
    let end0 = lens[0];
    let mut spliced = Vec::new();
    spliced.extend_from_slice(&bytes[..end0]); // frame 0
    spliced.extend_from_slice(&bytes[..end0]); // frame 0 again (inserted)
    spliced.extend_from_slice(&bytes[end0..]); // rest
    let log = EventLog::from_bytes(spliced);
    assert!(
        resume(&log, session(), &[]).is_err(),
        "inserted frame must refuse to resume"
    );
}

#[test]
fn tamper_truncated_frame_refuses_truncated() {
    let full = clean_log();
    let mut bytes = full.bytes().to_vec();
    bytes.truncate(bytes.len() - 8);
    let log = EventLog::from_bytes(bytes);
    match resume(&log, session(), &[]).unwrap_err() {
        ResumeRefused::LogBroken { reason, .. } => assert_eq!(reason, BreakReason::Truncated),
        other => panic!("expected LogBroken/Truncated, got {other:?}"),
    }
}

#[test]
fn tamper_clean_trailing_removal_refuses_under_head_anchor() {
    let full = clean_log();
    let expected_head = full.head_hash();
    let bytes = full.bytes();
    let lens = frame_lengths();
    // Drop the last frame cleanly (a shorter prefix still chains).
    let keep: usize = lens[..lens.len() - 1].iter().sum();
    let prefix = EventLog::from_bytes(bytes[..keep].to_vec());

    // Bare resume cannot detect a clean trailing removal.
    assert!(resume(&prefix, session(), &[]).is_ok());
    // The anchored resume against the persisted head detects it.
    assert_eq!(
        resume_to_head(&prefix, session(), &[], expected_head).unwrap_err(),
        ResumeRefused::HeadMismatch
    );
}

// ---- forged-receipt join-break corpus ----

#[test]
fn forged_receipt_no_frame_at_seq() {
    let log = clean_log();
    let receipts = vec![receipt_at(99, TASK, JOB)];
    match resume(&log, session(), &receipts).unwrap_err() {
        ResumeRefused::ReceiptJoinBroken { reason, .. } => {
            assert_eq!(reason, JoinBreak::NoFrameAtSeq);
        }
        other => panic!("expected ReceiptJoinBroken, got {other:?}"),
    }
}

#[test]
fn forged_receipt_not_a_tool_completion() {
    let log = clean_log();
    // seq 5 is ModelOutputReceived, not a tool completion.
    let receipts = vec![receipt_at(5, TASK, JOB)];
    match resume(&log, session(), &receipts).unwrap_err() {
        ResumeRefused::ReceiptJoinBroken { reason, .. } => {
            assert_eq!(reason, JoinBreak::NotAToolCompletion);
        }
        other => panic!("expected ReceiptJoinBroken, got {other:?}"),
    }
}

#[test]
fn forged_receipt_task_mismatch() {
    let log = clean_log();
    let receipts = vec![receipt_at(4, 999, JOB)];
    match resume(&log, session(), &receipts).unwrap_err() {
        ResumeRefused::ReceiptJoinBroken { reason, .. } => {
            assert_eq!(reason, JoinBreak::TaskMismatch);
        }
        other => panic!("expected ReceiptJoinBroken, got {other:?}"),
    }
}

#[test]
fn forged_receipt_job_mismatch() {
    let log = clean_log();
    let receipts = vec![receipt_at(4, TASK, 999)];
    match resume(&log, session(), &receipts).unwrap_err() {
        ResumeRefused::ReceiptJoinBroken { reason, .. } => {
            assert_eq!(reason, JoinBreak::JobMismatch);
        }
        other => panic!("expected ReceiptJoinBroken, got {other:?}"),
    }
}
