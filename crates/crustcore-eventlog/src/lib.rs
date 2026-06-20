// SPDX-License-Identifier: Apache-2.0
//! Append-only, hash-chained event log (`ROADMAP.md` §7.3, §16.1; Phase 2).
//!
//! The log is the audit backbone: a tampered log must be detectable, and
//! `crustcore inspect` replays and verifies the chain (`docs/event-log.md`).
//!
//! On-disk each event is a compact binary frame:
//! `magic | version | flags | actor | kind | visibility | redaction | seq |
//!  timestamp | task_id? | job_id? | payload_len | payload_hash | prev_hash |
//!  payload | frame_hash`. All integers are little-endian. The chain links via
//! `prev_hash` (the previous frame's `frame_hash`), so any modification,
//! reorder, insertion, deletion, or truncation of an earlier frame is detected
//! (§4 of the doc). Hashing is the vendored SHA-256 in `crustcore-types`.
//!
//! **Tamper model.** [`EventLog::verify`] is *prefix integrity*: it detects any
//! edit, reorder, mid-deletion, or insertion among the frames present. It cannot,
//! by itself, detect clean removal of trailing frames (a shorter prefix still
//! chains correctly) — that requires an out-of-band anchor of the expected head
//! hash, which [`EventLog::verify_to_head`] checks (`docs/event-log.md` §4). The
//! receipt MAC chain adds tamper-*resistance* on top (`docs/receipts.md` §6).
#![forbid(unsafe_code)]

use crustcore_kernel::{Actor, EventKind, Visibility};
use crustcore_types::{sha256, EventSeq, JobId, TaskId, Timestamp};

/// Magic bytes at the head of every frame ("CCEL" = CrustCore Event Log).
pub const FRAME_MAGIC: [u8; 4] = *b"CCEL";

/// Current frame format version.
pub const FRAME_VERSION: u16 = 1;

/// The genesis `prev_hash`: the first frame chains from all-zeros.
pub const GENESIS_PREV_HASH: [u8; 32] = [0u8; 32];

const FLAG_HAS_TASK: u8 = 0b0000_0001;
const FLAG_HAS_JOB: u8 = 0b0000_0010;

/// Redaction state of an event payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RedactionState {
    /// No secret-bearing content; safe as-is.
    Clean,
    /// Contained secret-bearing content that has been redacted.
    Redacted,
}

impl RedactionState {
    fn to_byte(self) -> u8 {
        match self {
            RedactionState::Clean => 0,
            RedactionState::Redacted => 1,
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(RedactionState::Clean),
            1 => Some(RedactionState::Redacted),
            _ => None,
        }
    }
}

fn visibility_to_byte(v: Visibility) -> u8 {
    match v {
        Visibility::ModelVisible => 0,
        Visibility::Internal => 1,
    }
}

fn visibility_from_byte(b: u8) -> Option<Visibility> {
    match b {
        0 => Some(Visibility::ModelVisible),
        1 => Some(Visibility::Internal),
        _ => None,
    }
}

fn actor_from_byte(b: u8) -> Option<Actor> {
    Actor::ALL.into_iter().find(|a| *a as u8 == b)
}

fn kind_from_byte(b: u8) -> Option<EventKind> {
    EventKind::ALL.into_iter().find(|k| *k as u8 == b)
}

/// The non-hash header fields of an event, supplied to [`EventLog::append`]. The
/// log computes `payload_hash`/`prev_hash`/`frame_hash` itself.
#[derive(Debug, Clone)]
pub struct FrameMeta {
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
}

impl FrameMeta {
    /// A frame for `seq`/`kind` defaulting to `Actor::Kernel`, `Internal`
    /// visibility, `Clean` redaction, epoch timestamp, and no ids. Refine with
    /// the builder methods.
    #[must_use]
    pub fn new(seq: u64, kind: EventKind) -> Self {
        FrameMeta {
            seq: EventSeq(seq),
            timestamp: Timestamp::EPOCH,
            task_id: None,
            job_id: None,
            actor: Actor::Kernel,
            kind,
            visibility: Visibility::Internal,
            redaction: RedactionState::Clean,
        }
    }

    /// Sets the originating actor.
    #[must_use]
    pub fn actor(mut self, actor: Actor) -> Self {
        self.actor = actor;
        self
    }

    /// Sets the payload visibility.
    #[must_use]
    pub fn visibility(mut self, visibility: Visibility) -> Self {
        self.visibility = visibility;
        self
    }

    /// Sets the redaction state.
    #[must_use]
    pub fn redaction(mut self, redaction: RedactionState) -> Self {
        self.redaction = redaction;
        self
    }

    /// Sets the event timestamp.
    #[must_use]
    pub fn timestamp(mut self, timestamp: Timestamp) -> Self {
        self.timestamp = timestamp;
        self
    }

    /// Binds the frame to a task.
    #[must_use]
    pub fn task(mut self, task_id: TaskId) -> Self {
        self.task_id = Some(task_id);
        self
    }

    /// Binds the frame to a job.
    #[must_use]
    pub fn job(mut self, job_id: JobId) -> Self {
        self.job_id = Some(job_id);
        self
    }
}

/// A decoded event frame header (the payload is returned alongside by the
/// iterator). On-disk layout is documented at the crate level.
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Why the chain failed to verify, and where.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakReason {
    /// Frame magic bytes were wrong.
    BadMagic,
    /// Frame format version was unsupported.
    BadVersion,
    /// A field discriminant (actor/kind/visibility/redaction/flags) was invalid.
    BadDiscriminant,
    /// The frame was shorter than its declared length (e.g. a crash mid-append).
    Truncated,
    /// The stored `payload_hash` did not match the payload bytes.
    PayloadHashMismatch,
    /// The stored `frame_hash` did not match the recomputed frame hash.
    FrameHashMismatch,
    /// `prev_hash` did not match the previous frame's `frame_hash`.
    PrevHashMismatch,
    /// The sequence number did not strictly increase.
    NonMonotonicSeq,
    /// The verified head did not match the expected (anchored) head — e.g.
    /// trailing frames were cleanly removed (`verify_to_head`).
    HeadMismatch,
}

impl core::fmt::Display for BreakReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            BreakReason::BadMagic => "bad frame magic",
            BreakReason::BadVersion => "unsupported frame version",
            BreakReason::BadDiscriminant => "invalid field discriminant",
            BreakReason::Truncated => "truncated/partial frame",
            BreakReason::PayloadHashMismatch => "payload hash mismatch",
            BreakReason::FrameHashMismatch => "frame hash mismatch",
            BreakReason::PrevHashMismatch => "prev-hash chain mismatch",
            BreakReason::NonMonotonicSeq => "non-monotonic sequence",
            BreakReason::HeadMismatch => "head mismatch (trailing frames removed?)",
        };
        f.write_str(s)
    }
}

/// The result of verifying the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainStatus {
    /// The chain verified end to end.
    Intact {
        /// Number of frames verified.
        frames: u64,
    },
    /// The chain broke; reports the offending frame index (0-based) and reason.
    Broken {
        /// Index of the frame where verification failed.
        frame_index: u64,
        /// What went wrong.
        reason: BreakReason,
    },
}

impl ChainStatus {
    /// Whether the chain verified end to end.
    #[must_use]
    pub fn is_intact(self) -> bool {
        matches!(self, ChainStatus::Intact { .. })
    }
}

fn encode_frame_prefix(
    meta: &FrameMeta,
    payload_len: u32,
    payload_hash: &[u8; 32],
    prev_hash: &[u8; 32],
) -> Vec<u8> {
    let mut flags = 0u8;
    if meta.task_id.is_some() {
        flags |= FLAG_HAS_TASK;
    }
    if meta.job_id.is_some() {
        flags |= FLAG_HAS_JOB;
    }

    let mut buf = Vec::with_capacity(96 + payload_len as usize);
    buf.extend_from_slice(&FRAME_MAGIC);
    buf.extend_from_slice(&FRAME_VERSION.to_le_bytes());
    buf.push(flags);
    buf.push(meta.actor as u8);
    buf.push(meta.kind as u8);
    buf.push(visibility_to_byte(meta.visibility));
    buf.push(meta.redaction.to_byte());
    buf.extend_from_slice(&meta.seq.0.to_le_bytes());
    buf.extend_from_slice(&meta.timestamp.as_millis().to_le_bytes());
    if let Some(t) = meta.task_id {
        buf.extend_from_slice(&t.0.to_le_bytes());
    }
    if let Some(j) = meta.job_id {
        buf.extend_from_slice(&j.0.to_le_bytes());
    }
    buf.extend_from_slice(&payload_len.to_le_bytes());
    buf.extend_from_slice(payload_hash);
    buf.extend_from_slice(prev_hash);
    buf
}

/// Append-only, hash-chained event log over a raw byte buffer (the real on-disk
/// representation). `append` frames and chains; `verify` walks the bytes and
/// reports the first tamper; `iter` decodes frames for inspect/export.
#[derive(Debug, Default, Clone)]
pub struct EventLog {
    bytes: Vec<u8>,
    head_hash: [u8; 32],
    count: u64,
}

impl EventLog {
    /// An empty in-memory log.
    #[must_use]
    pub fn new() -> Self {
        EventLog {
            bytes: Vec::new(),
            head_hash: GENESIS_PREV_HASH,
            count: 0,
        }
    }

    /// Loads a log from existing bytes (e.g. read from disk). This is
    /// **decode-grade** recovery only: `head_hash`/`count` reflect the longest
    /// *decodable* prefix, **not** an integrity check. Callers must run
    /// [`EventLog::verify`] (or [`EventLog::verify_to_head`]) before trusting a
    /// loaded log or extending it with [`EventLog::append`].
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let mut log = EventLog {
            bytes,
            head_hash: GENESIS_PREV_HASH,
            count: 0,
        };
        let mut prev = GENESIS_PREV_HASH;
        let mut count = 0u64;
        for decoded in log.iter() {
            prev = decoded.frame.frame_hash;
            count += 1;
        }
        log.head_hash = prev;
        log.count = count;
        log
    }

    /// Frames the event, sets `prev_hash` to the current head, computes the
    /// payload/frame hashes over the **bytes actually written**, appends the
    /// frame, and returns its `frame_hash`.
    ///
    /// Payloads must be bounded (`CLAUDE.md` §6.5); a payload exceeding
    /// `u32::MAX` bytes is a caller contract violation (`debug_assert`), and in
    /// release the frame is still written self-consistently over the truncated
    /// bytes so it cannot produce a spurious verify failure.
    pub fn append(&mut self, meta: &FrameMeta, payload: &[u8]) -> [u8; 32] {
        debug_assert!(
            payload.len() <= u32::MAX as usize,
            "event payload exceeds u32::MAX (bounded-everything violation)"
        );
        let payload_len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
        let written = &payload[..payload_len as usize];
        let payload_hash = sha256(written);
        let prev_hash = self.head_hash;

        let mut frame = encode_frame_prefix(meta, payload_len, &payload_hash, &prev_hash);
        frame.extend_from_slice(written);
        let frame_hash = sha256(&frame);
        frame.extend_from_slice(&frame_hash);

        self.bytes.extend_from_slice(&frame);
        self.head_hash = frame_hash;
        self.count += 1;
        frame_hash
    }

    /// The raw on-disk bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Number of frames appended.
    #[must_use]
    pub fn len(&self) -> u64 {
        self.count
    }

    /// Whether the log is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// The hash of the most recently appended frame (the chain head).
    #[must_use]
    pub fn head_hash(&self) -> [u8; 32] {
        self.head_hash
    }

    /// Iterates decoded frames + their payloads. Stops at the first frame that
    /// fails to *decode* (truncation/bad magic); use [`EventLog::verify`] for a
    /// full integrity check with the break reason.
    #[must_use]
    pub fn iter(&self) -> FrameIter<'_> {
        FrameIter {
            bytes: &self.bytes,
            offset: 0,
        }
    }

    /// Walks the log, fully verifying each frame, and returns the verified frames
    /// (in order) plus the overall status. Frames *before* a break are returned;
    /// the break is reported in the status. This is the single source of truth
    /// shared by [`EventLog::verify`], [`EventLog::inspect`], and
    /// [`EventLog::export_jsonl`], so they can never diverge.
    fn walk(&self) -> (Vec<(EventFrame, &[u8])>, ChainStatus) {
        let mut frames = Vec::new();
        let mut offset = 0usize;
        let mut prev_hash = GENESIS_PREV_HASH;
        let mut index = 0u64;
        let mut last_seq: Option<u64> = None;

        while offset < self.bytes.len() {
            let decoded = match decode_at(&self.bytes, offset) {
                Ok(d) => d,
                Err(reason) => {
                    return (
                        frames,
                        ChainStatus::Broken {
                            frame_index: index,
                            reason,
                        },
                    )
                }
            };
            let break_with = |reason| {
                (
                    frames.clone(),
                    ChainStatus::Broken {
                        frame_index: index,
                        reason,
                    },
                )
            };
            if sha256(decoded.payload) != decoded.frame.payload_hash {
                return break_with(BreakReason::PayloadHashMismatch);
            }
            let frame_body = &self.bytes[offset..decoded.frame_hash_offset];
            if sha256(frame_body) != decoded.frame.frame_hash {
                return break_with(BreakReason::FrameHashMismatch);
            }
            if decoded.frame.prev_hash != prev_hash {
                return break_with(BreakReason::PrevHashMismatch);
            }
            if let Some(prev_seq) = last_seq {
                if decoded.frame.seq.0 <= prev_seq {
                    return break_with(BreakReason::NonMonotonicSeq);
                }
            }

            prev_hash = decoded.frame.frame_hash;
            last_seq = Some(decoded.frame.seq.0);
            offset = decoded.next_offset;
            index += 1;
            frames.push((decoded.frame, decoded.payload));
        }

        (frames, ChainStatus::Intact { frames: index })
    }

    /// Walks the whole log, recomputing every payload/frame hash and checking the
    /// `prev_hash` links and sequence monotonicity. Reports the first break.
    ///
    /// This is *prefix integrity*; it does not detect clean removal of trailing
    /// frames (see [`EventLog::verify_to_head`]).
    #[must_use]
    pub fn verify(&self) -> ChainStatus {
        self.walk().1
    }

    /// Like [`EventLog::verify`], but also asserts the final verified frame's
    /// hash equals `expected_head` — an out-of-band anchor. This detects clean
    /// trailing-frame removal/truncation that bare `verify` cannot
    /// (`docs/event-log.md` §4). For an empty log, `expected_head` must be the
    /// genesis hash.
    #[must_use]
    pub fn verify_to_head(&self, expected_head: [u8; 32]) -> ChainStatus {
        let (frames, status) = self.walk();
        match status {
            ChainStatus::Broken { .. } => status,
            ChainStatus::Intact { frames: n } => {
                let actual_head = frames
                    .last()
                    .map_or(GENESIS_PREV_HASH, |(f, _)| f.frame_hash);
                if actual_head == expected_head {
                    ChainStatus::Intact { frames: n }
                } else {
                    ChainStatus::Broken {
                        frame_index: n,
                        reason: BreakReason::HeadMismatch,
                    }
                }
            }
        }
    }

    /// Verifies the chain and rolls up a per-task summary
    /// (`docs/event-log.md` §8). Backs `crustcore inspect`. Only verified frames
    /// contribute to the summary.
    #[must_use]
    pub fn inspect(&self) -> InspectReport {
        let (frames, status) = self.walk();
        let mut tasks: Vec<TaskSummary> = Vec::new();
        for (frame, _payload) in &frames {
            let Some(tid) = frame.task_id else {
                continue;
            };
            let seq = frame.seq;
            match tasks.iter_mut().find(|t| t.task_id == tid) {
                Some(t) => {
                    t.frames += 1;
                    t.last_seq = seq;
                    if is_terminal_kind(frame.kind) {
                        t.terminal = Some(frame.kind);
                    }
                }
                None => tasks.push(TaskSummary {
                    task_id: tid,
                    frames: 1,
                    first_seq: seq,
                    last_seq: seq,
                    terminal: is_terminal_kind(frame.kind).then_some(frame.kind),
                }),
            }
        }
        InspectReport {
            status,
            total_frames: frames.len() as u64,
            tasks,
        }
    }

    /// Renders the log as JSONL — one JSON object per **verified** frame
    /// (`docs/event-log.md` §8). It is verification-gated: a frame is emitted only
    /// after it passes the full hash-chain check, so a tampered frame (including
    /// one whose redaction byte was flipped to leak a payload) is never emitted —
    /// flipping any field breaks `frame_hash` and stops emission at that frame
    /// (invariants 2, 3, 10). Redacted payloads are shown as `"<redacted>"`,
    /// never as bytes; clean payloads are hex-encoded. No `serde_json` (forbidden
    /// in nano); emitted strings are controlled (enum names, hex, integers).
    #[must_use]
    pub fn export_jsonl(&self) -> String {
        use core::fmt::Write as _;
        let (frames, _status) = self.walk();
        let mut out = String::new();
        for (fr, payload) in &frames {
            out.push('{');
            let _ = write!(out, "\"seq\":{}", fr.seq.0);
            let _ = write!(out, ",\"timestamp\":{}", fr.timestamp.as_millis());
            match fr.task_id {
                Some(t) => {
                    let _ = write!(out, ",\"task_id\":{}", t.0);
                }
                None => out.push_str(",\"task_id\":null"),
            }
            match fr.job_id {
                Some(j) => {
                    let _ = write!(out, ",\"job_id\":{}", j.0);
                }
                None => out.push_str(",\"job_id\":null"),
            }
            let _ = write!(out, ",\"actor\":\"{:?}\"", fr.actor);
            let _ = write!(out, ",\"kind\":\"{:?}\"", fr.kind);
            let _ = write!(out, ",\"visibility\":\"{:?}\"", fr.visibility);
            let _ = write!(out, ",\"redaction\":\"{:?}\"", fr.redaction);
            out.push_str(",\"payload_hash\":\"");
            hex_into(&mut out, &fr.payload_hash);
            out.push_str("\",\"prev_hash\":\"");
            hex_into(&mut out, &fr.prev_hash);
            out.push_str("\",\"frame_hash\":\"");
            hex_into(&mut out, &fr.frame_hash);
            // Respect BOTH gates (docs/event-log.md §8, invariants 2/3): raw bytes
            // are rendered only for a `Clean` + `ModelVisible` payload. A
            // `Redacted` (secret-bearing) payload hides its bytes AND its length
            // (length can be sensitive); an `Internal` payload is withheld from
            // this surface as `<internal>` (its length is non-secret and kept for
            // debugging). The `payload_hash` always commits to the real content.
            if fr.redaction == RedactionState::Redacted {
                out.push_str(",\"payload_len\":null,\"payload\":\"<redacted>\"");
            } else if fr.visibility == Visibility::ModelVisible {
                // Clean + model-visible: safe to render bytes.
                let _ = write!(out, ",\"payload_len\":{}", payload.len());
                out.push_str(",\"payload\":\"");
                hex_into(&mut out, payload);
                out.push('"');
            } else {
                // Clean but internal: withhold bytes, keep the (non-secret) length.
                let _ = write!(out, ",\"payload_len\":{}", payload.len());
                out.push_str(",\"payload\":\"<internal>\"");
            }
            out.push_str("}\n");
        }
        out
    }
}

/// A per-task rollup for `crustcore inspect`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskSummary {
    /// The task.
    pub task_id: TaskId,
    /// Frames seen for this task.
    pub frames: u64,
    /// First sequence number seen.
    pub first_seq: EventSeq,
    /// Last sequence number seen.
    pub last_seq: EventSeq,
    /// The terminal event kind, if the task ended.
    pub terminal: Option<EventKind>,
}

/// What `crustcore inspect` reports: the chain status plus a per-task summary.
#[derive(Debug, Clone)]
pub struct InspectReport {
    /// Chain verification result.
    pub status: ChainStatus,
    /// Total verified frames.
    pub total_frames: u64,
    /// Per-task rollups, in first-seen order (deterministic).
    pub tasks: Vec<TaskSummary>,
}

impl core::fmt::Display for InspectReport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.status {
            ChainStatus::Intact { frames } => {
                writeln!(f, "event log: {frames} frame(s), chain INTACT")?;
            }
            ChainStatus::Broken {
                frame_index,
                reason,
            } => {
                writeln!(
                    f,
                    "event log: chain BROKEN at frame {frame_index}: {reason}"
                )?;
            }
        }
        if self.tasks.is_empty() {
            writeln!(f, "  (no task-scoped events)")?;
        }
        for t in &self.tasks {
            let end = match t.terminal {
                Some(k) => format!("{k:?}"),
                None => "open".to_string(),
            };
            writeln!(
                f,
                "  task {}: {} frame(s), seq {}..{}, {}",
                t.task_id.0, t.frames, t.first_seq.0, t.last_seq.0, end
            )?;
        }
        Ok(())
    }
}

fn is_terminal_kind(k: EventKind) -> bool {
    matches!(
        k,
        EventKind::TaskCompleted | EventKind::TaskFailed | EventKind::TaskKilled
    )
}

fn hex_into(out: &mut String, bytes: &[u8]) {
    use core::fmt::Write as _;
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
}

/// A decoded frame plus its payload bytes.
#[derive(Debug, Clone)]
pub struct DecodedFrame<'a> {
    /// The frame header.
    pub frame: EventFrame,
    /// The payload bytes (possibly redacted).
    pub payload: &'a [u8],
}

struct Decoded<'a> {
    frame: EventFrame,
    payload: &'a [u8],
    frame_hash_offset: usize,
    next_offset: usize,
}

fn read_array<const N: usize>(bytes: &[u8], at: usize) -> Option<[u8; N]> {
    let end = at.checked_add(N)?;
    bytes.get(at..end)?.try_into().ok()
}

fn decode_at(bytes: &[u8], start: usize) -> Result<Decoded<'_>, BreakReason> {
    let mut off = start;
    let magic = read_array::<4>(bytes, off).ok_or(BreakReason::Truncated)?;
    if magic != FRAME_MAGIC {
        return Err(BreakReason::BadMagic);
    }
    off += 4;
    let version = u16::from_le_bytes(read_array::<2>(bytes, off).ok_or(BreakReason::Truncated)?);
    if version != FRAME_VERSION {
        return Err(BreakReason::BadVersion);
    }
    off += 2;

    let flags = *bytes.get(off).ok_or(BreakReason::Truncated)?;
    off += 1;
    if flags & !(FLAG_HAS_TASK | FLAG_HAS_JOB) != 0 {
        return Err(BreakReason::BadDiscriminant);
    }
    let actor = actor_from_byte(*bytes.get(off).ok_or(BreakReason::Truncated)?)
        .ok_or(BreakReason::BadDiscriminant)?;
    off += 1;
    let kind = kind_from_byte(*bytes.get(off).ok_or(BreakReason::Truncated)?)
        .ok_or(BreakReason::BadDiscriminant)?;
    off += 1;
    let visibility = visibility_from_byte(*bytes.get(off).ok_or(BreakReason::Truncated)?)
        .ok_or(BreakReason::BadDiscriminant)?;
    off += 1;
    let redaction = RedactionState::from_byte(*bytes.get(off).ok_or(BreakReason::Truncated)?)
        .ok_or(BreakReason::BadDiscriminant)?;
    off += 1;

    let seq = EventSeq(u64::from_le_bytes(
        read_array::<8>(bytes, off).ok_or(BreakReason::Truncated)?,
    ));
    off += 8;
    let timestamp = Timestamp::from_millis(u64::from_le_bytes(
        read_array::<8>(bytes, off).ok_or(BreakReason::Truncated)?,
    ));
    off += 8;

    let task_id = if flags & FLAG_HAS_TASK != 0 {
        let v = u128::from_le_bytes(read_array::<16>(bytes, off).ok_or(BreakReason::Truncated)?);
        off += 16;
        Some(TaskId(v))
    } else {
        None
    };
    let job_id = if flags & FLAG_HAS_JOB != 0 {
        let v = u128::from_le_bytes(read_array::<16>(bytes, off).ok_or(BreakReason::Truncated)?);
        off += 16;
        Some(JobId(v))
    } else {
        None
    };

    let payload_len =
        u32::from_le_bytes(read_array::<4>(bytes, off).ok_or(BreakReason::Truncated)?) as usize;
    off += 4;
    let payload_hash = read_array::<32>(bytes, off).ok_or(BreakReason::Truncated)?;
    off += 32;
    let prev_hash = read_array::<32>(bytes, off).ok_or(BreakReason::Truncated)?;
    off += 32;

    // `payload_len` is attacker-controlled (the log file is untrusted bytes), so
    // the offset arithmetic must not overflow/panic — use a checked add.
    let payload_end = off.checked_add(payload_len).ok_or(BreakReason::Truncated)?;
    let payload = bytes.get(off..payload_end).ok_or(BreakReason::Truncated)?;
    off = payload_end;

    let frame_hash_offset = off;
    let frame_hash = read_array::<32>(bytes, off).ok_or(BreakReason::Truncated)?;
    off += 32;

    Ok(Decoded {
        frame: EventFrame {
            seq,
            timestamp,
            task_id,
            job_id,
            actor,
            kind,
            visibility,
            redaction,
            payload_hash,
            prev_hash,
            frame_hash,
        },
        payload,
        frame_hash_offset,
        next_offset: off,
    })
}

/// Iterator over decoded frames. Stops at the first undecodable frame.
pub struct FrameIter<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for FrameIter<'a> {
    type Item = DecodedFrame<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.bytes.len() {
            return None;
        }
        match decode_at(self.bytes, self.offset) {
            Ok(d) => {
                self.offset = d.next_offset;
                Some(DecodedFrame {
                    frame: d.frame,
                    payload: d.payload,
                })
            }
            Err(_) => {
                self.offset = self.bytes.len();
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(seq: u64, kind: EventKind) -> FrameMeta {
        FrameMeta::new(seq, kind)
            .task(TaskId(1))
            .actor(Actor::Adapter)
            .timestamp(Timestamp::from_millis(seq * 1000))
    }

    fn sample_log() -> EventLog {
        let mut log = EventLog::new();
        log.append(&meta(1, EventKind::TaskCreated), b"created");
        log.append(&meta(2, EventKind::JobQueued), b"queued");
        log.append(&meta(3, EventKind::ToolCallCompleted), b"done");
        log
    }

    fn spans(log: &EventLog) -> Vec<(usize, usize)> {
        let mut spans = Vec::new();
        let mut off = 0usize;
        while off < log.bytes().len() {
            let d = decode_at(log.bytes(), off).unwrap();
            spans.push((off, d.next_offset));
            off = d.next_offset;
        }
        spans
    }

    #[test]
    fn append_then_verify_is_intact() {
        let log = sample_log();
        assert_eq!(log.len(), 3);
        assert_eq!(log.verify(), ChainStatus::Intact { frames: 3 });
    }

    #[test]
    fn empty_log_is_intact() {
        let log = EventLog::new();
        assert_eq!(log.verify(), ChainStatus::Intact { frames: 0 });
        assert_eq!(
            log.verify_to_head(GENESIS_PREV_HASH),
            ChainStatus::Intact { frames: 0 }
        );
    }

    // --- Format version / migration compatibility (P16.6) ---

    #[test]
    fn frame_format_version_is_stable_and_stamped() {
        // Format-contract guard: changing either of these is a migration event, and a
        // reader/writer migration must accompany it (DoD #6, P16.6). This test exists
        // so a silent format bump trips CI.
        assert_eq!(FRAME_MAGIC, *b"CCEL");
        assert_eq!(FRAME_VERSION, 1);

        let log = sample_log();
        // Every frame is stamped with the current magic + version (LE u16) in its
        // header, and the current version round-trips intact.
        for (start, _end) in spans(&log) {
            assert_eq!(&log.bytes()[start..start + 4], &FRAME_MAGIC);
            let v = u16::from_le_bytes([log.bytes()[start + 4], log.bytes()[start + 5]]);
            assert_eq!(v, FRAME_VERSION);
        }
        assert!(EventLog::from_bytes(log.bytes().to_vec())
            .verify()
            .is_intact());
    }

    #[test]
    fn future_frame_version_is_rejected_not_misread() {
        // Forward compatibility / migration boundary (P16.6): a frame stamped with a
        // NEWER format version must be **rejected** with `BadVersion`, never silently
        // misinterpreted under the old layout. An old reader refuses a newer log rather
        // than guessing — the safe direction for an audit log.
        let log = sample_log();
        let mut bytes = log.bytes().to_vec();
        let future = FRAME_VERSION + 1;
        bytes[4..6].copy_from_slice(&future.to_le_bytes());
        match EventLog::from_bytes(bytes).verify() {
            ChainStatus::Broken {
                frame_index,
                reason,
            } => {
                assert_eq!(reason, BreakReason::BadVersion);
                assert_eq!(frame_index, 0);
            }
            ChainStatus::Intact { .. } => {
                panic!("a future frame version must not verify as intact")
            }
        }
    }

    #[test]
    fn frames_roundtrip_through_iter() {
        let log = sample_log();
        let frames: Vec<_> = log.iter().collect();
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].frame.kind, EventKind::TaskCreated);
        assert_eq!(frames[0].payload, b"created");
        assert_eq!(frames[2].payload, b"done");
        assert_eq!(frames[0].frame.prev_hash, GENESIS_PREV_HASH);
        assert_eq!(frames[1].frame.prev_hash, frames[0].frame.frame_hash);
        assert_eq!(frames[2].frame.prev_hash, frames[1].frame.frame_hash);
    }

    #[test]
    fn from_bytes_recovers_head_and_count() {
        let log = sample_log();
        let loaded = EventLog::from_bytes(log.bytes().to_vec());
        assert_eq!(loaded.len(), 3);
        assert_eq!(loaded.head_hash(), log.head_hash());
        assert!(loaded.verify().is_intact());
    }

    // --- Tamper tests (P2.6) ---

    #[test]
    fn tamper_flip_payload_byte_is_detected() {
        let mut log = sample_log();
        let pos = log
            .bytes()
            .windows(7)
            .position(|w| w == b"created")
            .expect("payload present");
        log.bytes[pos] ^= 0xff;
        match log.verify() {
            ChainStatus::Broken {
                frame_index,
                reason,
            } => {
                assert_eq!(frame_index, 0);
                assert_eq!(reason, BreakReason::PayloadHashMismatch);
            }
            other => panic!("expected break, got {other:?}"),
        }
    }

    #[test]
    fn tamper_alter_header_field_is_detected() {
        let mut log = sample_log();
        let original = log.bytes[8];
        log.bytes[8] = original.wrapping_add(1);
        match log.verify() {
            ChainStatus::Broken {
                frame_index,
                reason,
            } => {
                assert_eq!(frame_index, 0);
                assert!(matches!(
                    reason,
                    BreakReason::FrameHashMismatch | BreakReason::BadDiscriminant
                ));
            }
            other => panic!("expected break, got {other:?}"),
        }
    }

    #[test]
    fn tamper_truncated_trailing_frame_is_detected() {
        let mut log = sample_log();
        log.bytes.truncate(log.bytes.len() - 10);
        match log.verify() {
            ChainStatus::Broken { reason, .. } => assert_eq!(reason, BreakReason::Truncated),
            other => panic!("expected truncation break, got {other:?}"),
        }
    }

    #[test]
    fn tamper_deleted_frame_breaks_the_chain() {
        let log = sample_log();
        let s = spans(&log);
        let mut spliced = Vec::new();
        spliced.extend_from_slice(&log.bytes()[s[0].0..s[0].1]);
        spliced.extend_from_slice(&log.bytes()[s[2].0..s[2].1]);
        let tampered = EventLog::from_bytes(spliced);
        match tampered.verify() {
            ChainStatus::Broken {
                frame_index,
                reason,
            } => {
                assert_eq!(frame_index, 1);
                assert_eq!(reason, BreakReason::PrevHashMismatch);
            }
            other => panic!("expected chain break, got {other:?}"),
        }
    }

    #[test]
    fn tamper_reordered_frames_break_the_chain() {
        let log = sample_log();
        let s = spans(&log);
        let mut spliced = Vec::new();
        spliced.extend_from_slice(&log.bytes()[s[0].0..s[0].1]);
        spliced.extend_from_slice(&log.bytes()[s[2].0..s[2].1]);
        spliced.extend_from_slice(&log.bytes()[s[1].0..s[1].1]);
        let tampered = EventLog::from_bytes(spliced);
        assert!(!tampered.verify().is_intact());
    }

    // Clean removal of a trailing frame: bare verify still sees an intact prefix,
    // but the anchored verify_to_head detects it (docs/event-log.md §4).
    #[test]
    fn trailing_truncation_detected_only_by_anchored_verify() {
        let full = sample_log();
        let expected_head = full.head_hash();
        let s = spans(&full);
        // Drop the last whole frame.
        let prefix_bytes = full.bytes()[..s[2].0].to_vec();
        let truncated = EventLog::from_bytes(prefix_bytes);
        // Bare verify: the 2-frame prefix is internally consistent.
        assert!(truncated.verify().is_intact());
        // Anchored verify against the known full head: detected.
        match truncated.verify_to_head(expected_head) {
            ChainStatus::Broken { reason, .. } => assert_eq!(reason, BreakReason::HeadMismatch),
            other => panic!("expected head mismatch, got {other:?}"),
        }
        // And the genuine full log verifies against its head.
        assert!(full.verify_to_head(expected_head).is_intact());
    }

    #[test]
    fn inspect_reports_chain_status_and_task_summary() {
        let mut log = sample_log();
        log.append(&meta(4, EventKind::TaskCompleted), b"done");
        let report = log.inspect();
        assert!(report.status.is_intact());
        assert_eq!(report.total_frames, 4);
        assert_eq!(report.tasks.len(), 1);
        let t = &report.tasks[0];
        assert_eq!(t.task_id, TaskId(1));
        assert_eq!(t.frames, 4);
        assert_eq!(t.first_seq, EventSeq(1));
        assert_eq!(t.last_seq, EventSeq(4));
        assert_eq!(t.terminal, Some(EventKind::TaskCompleted));
        let text = format!("{report}");
        assert!(text.contains("INTACT"));
        assert!(text.contains("task 1"));
    }

    #[test]
    fn inspect_reports_a_break() {
        let mut log = sample_log();
        log.bytes.truncate(log.bytes.len() - 5);
        let report = log.inspect();
        assert!(!report.status.is_intact());
        assert!(format!("{report}").contains("BROKEN"));
    }

    #[test]
    fn export_jsonl_one_line_per_frame_and_redacts() {
        let mut log = EventLog::new();
        // A model-visible, clean payload renders its bytes as hex.
        let visible = meta(1, EventKind::ModelOutputReceived).visibility(Visibility::ModelVisible);
        log.append(&visible, b"hi");
        // A redacted payload hides its bytes AND its length.
        let m = meta(2, EventKind::ModelOutputReceived)
            .redaction(RedactionState::Redacted)
            .visibility(Visibility::ModelVisible);
        log.append(&m, b"secret-bearing");
        let jsonl = log.export_jsonl();
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"payload\":\"6869\"")); // hex of "hi"
        assert!(lines[1].contains("\"payload\":\"<redacted>\""));
        assert!(lines[1].contains("\"payload_len\":null"));
        assert!(!lines[1].contains("secret-bearing"));
    }

    // Export respects BOTH gates: an Internal payload's bytes are withheld
    // (`<internal>`) even when Clean; a Redacted payload hides its length too.
    #[test]
    fn export_withholds_internal_payload_bytes() {
        let mut log = EventLog::new();
        // meta() defaults to Internal visibility, Clean redaction.
        log.append(
            &meta(1, EventKind::CommandOutputCaptured),
            b"internal-bytes",
        );
        let jsonl = log.export_jsonl();
        assert!(jsonl.contains("\"payload\":\"<internal>\""));
        assert!(!jsonl.contains("696e7465726e616c")); // hex of "internal..."
                                                      // The non-secret length is still shown for an internal frame.
        assert!(jsonl.contains("\"payload_len\":14"));
    }

    // Export is verification-gated: flipping the redaction byte of a secret frame
    // breaks frame_hash, so the frame (and its payload) is never emitted — the
    // secret cannot be leaked by tampering the redaction flag.
    #[test]
    fn export_does_not_leak_secret_when_redaction_byte_flipped() {
        let mut log = EventLog::new();
        log.append(&meta(1, EventKind::TaskCreated), b"ok");
        let m = meta(2, EventKind::ModelOutputReceived)
            .redaction(RedactionState::Redacted)
            .visibility(Visibility::ModelVisible);
        log.append(&m, b"TOPSECRET");
        // Locate the redaction byte of the second frame (offset 10 within it).
        let s = spans(&log);
        let redaction_off = s[1].0 + 10;
        assert_eq!(log.bytes[redaction_off], RedactionState::Redacted.to_byte());
        log.bytes[redaction_off] = RedactionState::Clean.to_byte();
        // The chain is now broken at frame 1; export emits only frame 0.
        assert!(!log.verify().is_intact());
        let jsonl = log.export_jsonl();
        assert_eq!(jsonl.lines().count(), 1);
        assert!(!jsonl.contains("TOPSECRET"));
    }

    // The log file is untrusted bytes: decode/verify/inspect/export must never
    // panic, whatever the input (incl. valid-magic frames with hostile lengths).
    #[test]
    fn decoder_never_panics_on_hostile_bytes() {
        let mut lcg: u64 = 0xdead_beef_cafe_babe;
        let mut next = || {
            lcg = lcg
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            lcg
        };
        for _ in 0..3000 {
            let n = (next() % 256) as usize;
            let mut bytes = Vec::with_capacity(n + 4);
            if next() % 2 == 0 {
                bytes.extend_from_slice(&FRAME_MAGIC);
            }
            while bytes.len() < n {
                bytes.push((next() & 0xff) as u8);
            }
            let log = EventLog::from_bytes(bytes);
            let _ = log.verify();
            let _ = log.verify_to_head([0xab; 32]);
            let _ = log.inspect();
            let _ = log.export_jsonl();
            let _ = log.iter().count();
        }
    }

    // Targeted hostile `payload_len` values on an otherwise-valid frame prefix
    // must be rejected cleanly (no panic), including the u32::MAX boundary.
    #[test]
    fn hostile_payload_len_is_rejected_cleanly() {
        for bad_len in [0u32, 1, 0x7fff_ffff, 0xffff_ffff] {
            // Build a valid prefix for a task-less, job-less Internal frame, then
            // splice a hostile payload_len and a too-short body.
            let mut prefix = encode_frame_prefix(
                &FrameMeta::new(1, EventKind::TaskCreated),
                bad_len,
                &[0u8; 32],
                &GENESIS_PREV_HASH,
            );
            prefix.extend_from_slice(b"short"); // far fewer than bad_len bytes
            let log = EventLog::from_bytes(prefix);
            // Must not panic and must not falsely verify.
            assert!(!log.verify().is_intact());
            let _ = log.export_jsonl();
            let _ = log.inspect();
        }
    }

    #[test]
    fn disk_roundtrip_and_on_disk_tamper_is_detected() {
        let mut log = sample_log();
        log.append(&meta(4, EventKind::TaskCompleted), b"done");

        let path = std::env::temp_dir().join(format!(
            "cc-eventlog-{}-{}.cclog",
            std::process::id(),
            log.len()
        ));
        std::fs::write(&path, log.bytes()).unwrap();

        let loaded = EventLog::from_bytes(std::fs::read(&path).unwrap());
        assert!(loaded.verify().is_intact());
        assert_eq!(loaded.len(), 4);

        let mut corrupt = std::fs::read(&path).unwrap();
        let mid = corrupt.len() / 2;
        corrupt[mid] ^= 0xff;
        std::fs::write(&path, &corrupt).unwrap();
        let reloaded = EventLog::from_bytes(std::fs::read(&path).unwrap());
        assert!(!reloaded.verify().is_intact());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn payload_visibility_and_redaction_survive_roundtrip() {
        let mut log = EventLog::new();
        let m = FrameMeta::new(1, EventKind::ModelOutputReceived)
            .task(TaskId(9))
            .job(JobId(8))
            .actor(Actor::Model)
            .visibility(Visibility::ModelVisible)
            .redaction(RedactionState::Redacted)
            .timestamp(Timestamp::from_millis(1));
        log.append(&m, b"redacted-summary");
        let f = log.iter().next().unwrap();
        assert_eq!(f.frame.visibility, Visibility::ModelVisible);
        assert_eq!(f.frame.redaction, RedactionState::Redacted);
        assert_eq!(f.frame.task_id, Some(TaskId(9)));
        assert_eq!(f.frame.job_id, Some(JobId(8)));
        assert!(log.verify().is_intact());
    }

    // Every EventKind and Actor discriminant round-trips through the byte
    // encoding (so the `x as u8` <-> ALL.find decode mapping is stable).
    #[test]
    fn all_discriminants_roundtrip() {
        for kind in EventKind::ALL {
            assert_eq!(kind_from_byte(kind as u8), Some(kind));
        }
        for actor in Actor::ALL {
            assert_eq!(actor_from_byte(actor as u8), Some(actor));
        }
    }
}
