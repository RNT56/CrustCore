// SPDX-License-Identifier: Apache-2.0
//! Append-only, hash-chained event log (`ROADMAP.md` §7.3, §16.1; Phase 2).
//!
//! The log is the audit backbone: a tampered log must be detectable, and
//! `crustcore inspect` replays and verifies the chain (`docs/event-log.md`).
//!
//! Status: Phase 0 scaffold. The frame layout is defined as a type; the binary
//! encoder/decoder, hash chaining, append/verify, JSONL export, and tamper tests
//! are implemented in Phase 2 (`TODO(P2.*)`).
#![forbid(unsafe_code)]

use crustcore_kernel::{Actor, EventKind, Visibility};
use crustcore_types::{EventSeq, JobId, TaskId, Timestamp};

/// Magic bytes at the head of every frame ("CCEL" = CrustCore Event Log).
pub const FRAME_MAGIC: [u8; 4] = *b"CCEL";

/// Current frame format version.
pub const FRAME_VERSION: u16 = 1;

/// Redaction state of an event payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RedactionState {
    /// No secret-bearing content; safe as-is.
    Clean,
    /// Contained secret-bearing content that has been redacted.
    Redacted,
}

/// One hash-chained event frame (`ROADMAP.md` §7.3).
///
/// On disk this is a compact binary layout:
/// `magic | version | seq | timestamp | task_id? | job_id? | actor | kind |
///  visibility | redaction_state | payload_len | payload_hash | prev_hash |
///  payload | frame_hash`.
#[derive(Debug, Clone)]
pub struct EventFrame {
    /// Monotonic sequence number.
    pub seq: EventSeq,
    /// When the event was recorded.
    pub timestamp: Timestamp,
    /// Owning task, if any.
    pub task_id: Option<TaskId>,
    /// Owning job, if any.
    pub job_id: Option<JobId>,
    /// Originating actor.
    pub actor: Actor,
    /// Event kind.
    pub kind: EventKind,
    /// Model visibility of the payload.
    pub visibility: Visibility,
    /// Redaction state of the payload.
    pub redaction: RedactionState,
    /// Hash of this frame's payload.
    pub payload_hash: [u8; 32],
    /// Hash of the previous frame (chains the log).
    pub prev_hash: [u8; 32],
    /// Hash over the full frame (binds all fields).
    pub frame_hash: [u8; 32],
}

/// Errors from log operations.
#[derive(Debug)]
pub enum LogError {
    /// The hash chain did not verify at the given sequence.
    ChainBroken(EventSeq),
    /// An I/O error occurred.
    Io(std::io::Error),
}

impl core::fmt::Display for LogError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LogError::ChainBroken(s) => write!(f, "event log hash chain broken at seq {}", s.0),
            LogError::Io(e) => write!(f, "event log io error: {e}"),
        }
    }
}

impl std::error::Error for LogError {}

impl From<std::io::Error> for LogError {
    fn from(e: std::io::Error) -> Self {
        LogError::Io(e)
    }
}

/// Append-only event log writer/reader.
///
/// TODO(P2.1–P2.6): encode/decode frames, maintain the running `prev_hash`,
/// verify the chain on read, export JSONL, and add tamper tests.
#[derive(Debug, Default)]
pub struct EventLog {
    last_hash: [u8; 32],
    len: u64,
}

impl EventLog {
    /// Opens (or creates) an empty in-memory log. Phase 2 adds a file backend.
    #[must_use]
    pub fn new() -> Self {
        EventLog {
            last_hash: [0u8; 32],
            len: 0,
        }
    }

    /// Number of frames appended.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the log is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The hash of the most recently appended frame (the chain head).
    #[must_use]
    pub fn head_hash(&self) -> [u8; 32] {
        self.last_hash
    }
}
