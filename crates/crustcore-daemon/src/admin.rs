// SPDX-License-Identifier: Apache-2.0
//! Remote admin socket protocol (roadmap-v0.6 F.2).
//!
//! An authenticated loopback / Unix socket lets an **operator** (or a paired supervising
//! agent) query status and cancel/kill tasks without Telegram. This module is the **pure
//! protocol core**: the command grammar, length-prefixed framing, nonce authentication,
//! and the dispatch that feeds the *same* owner-scoped `request_cancel` / `request_kill`
//! path the Telegram channel uses (invariant 12). It is **operator-only, never
//! model-facing** (invariant 5) — the model has no admin socket.
//!
//! The real `UnixListener` / TCP-loopback bind + I/O loop is the
//! `TODO(daemon-admin-live)` seam (`#[ignore]`d); everything here is CI-tested.

use std::io::{Read, Write};

use crustcore_types::Timestamp;

use crate::registry::{RegistrySnapshot, TaskId, TaskRegistry};
use crate::telegram::ChatId;

/// Max bytes in one admin frame's payload (bounded — invariant 11; a hostile client
/// cannot make the daemon allocate without limit).
pub const MAX_ADMIN_FRAME: usize = 64 * 1024;
/// Max rows rendered into a status response (bounded output).
pub const MAX_STATUS_ROWS: usize = 256;

/// An operator admin command. A tiny, dep-free text grammar (`verb [id]`) rather than a
/// JSON body, so the daemon core links no serializer; the framing below carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminCommand {
    /// `status` — the current task snapshot.
    Status,
    /// `detail <id>` — one task's row.
    TaskDetail(u64),
    /// `cancel <id>` — graceful cancel (owner-scoped).
    Cancel(u64),
    /// `kill <id>` — hard kill (owner-scoped).
    Kill(u64),
}

/// Parses one admin command line. Unknown verbs / missing or non-numeric ids yield
/// `None` (the caller answers `BadRequest`) — never a panic.
#[must_use]
pub fn parse_admin_command(line: &str) -> Option<AdminCommand> {
    let mut t = line.split_whitespace();
    match t.next()? {
        "status" => Some(AdminCommand::Status),
        "detail" => t.next()?.parse().ok().map(AdminCommand::TaskDetail),
        "cancel" => t.next()?.parse().ok().map(AdminCommand::Cancel),
        "kill" => t.next()?.parse().ok().map(AdminCommand::Kill),
        _ => None,
    }
}

/// The admin reply. Rendered to a bounded text payload for the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminResponse {
    /// A rendered status snapshot.
    Snapshot(String),
    /// A rendered single-task detail.
    Detail(String),
    /// The cancel/kill acted (the task was owned + active).
    Acted,
    /// The cancel/kill did not act (not owned, unknown, or already terminal).
    NotActed,
    /// The command did not parse.
    BadRequest,
    /// The nonce did not authenticate (the connection is dropped).
    Unauthorized,
}

impl AdminResponse {
    /// The bounded wire text for this response.
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            AdminResponse::Snapshot(s) | AdminResponse::Detail(s) => s.clone(),
            AdminResponse::Acted => "ok: acted".to_string(),
            AdminResponse::NotActed => "ok: no-op (not owned / unknown / terminal)".to_string(),
            AdminResponse::BadRequest => "error: bad request".to_string(),
            AdminResponse::Unauthorized => "error: unauthorized".to_string(),
        }
    }
}

/// Errors decoding a framed admin message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminError {
    /// The advertised frame length exceeds [`MAX_ADMIN_FRAME`].
    FrameTooLarge,
}

/// Length-prefixes a payload: `[len: u32 LE][payload]`.
#[must_use]
pub fn frame(payload: &[u8]) -> Vec<u8> {
    let len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// Tries to decode one frame from the front of `buf`. Returns `Ok(None)` if more bytes
/// are needed, `Ok(Some((payload, consumed)))` on a complete frame, or
/// [`AdminError::FrameTooLarge`] if the advertised length is over the bound (the caller
/// drops the connection — a hostile length can never force a huge allocation).
pub fn try_deframe(buf: &[u8]) -> Result<Option<(Vec<u8>, usize)>, AdminError> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > MAX_ADMIN_FRAME {
        return Err(AdminError::FrameTooLarge);
    }
    if buf.len() < 4 + len {
        return Ok(None);
    }
    Ok(Some((buf[4..4 + len].to_vec(), 4 + len)))
}

/// Constant-time-ish nonce comparison (no early return on the first differing byte).
/// The startup nonce (`~/.crustcore/admin.nonce`, mode 0600) must match before any
/// command is honored; a mismatch drops the connection (invariant 5).
#[must_use]
pub fn authenticate(provided: &[u8], expected: &[u8]) -> bool {
    if provided.len() != expected.len() || expected.is_empty() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in provided.iter().zip(expected) {
        diff |= a ^ b;
    }
    diff == 0
}

/// Dispatches an authenticated admin command against the registry, as `operator`. Cancel
/// and kill are **owner-scoped** — they act only on tasks owned by `operator`, the exact
/// same gate Telegram uses (invariant 12). Status/detail render a bounded snapshot.
#[must_use]
pub fn dispatch_admin(
    cmd: &AdminCommand,
    registry: &mut TaskRegistry,
    operator: ChatId,
    now: Timestamp,
) -> AdminResponse {
    match cmd {
        AdminCommand::Status => AdminResponse::Snapshot(render_snapshot(&registry.snapshot(now))),
        AdminCommand::TaskDetail(id) => match registry.snapshot(now).get(TaskId(*id)) {
            Some(row) => AdminResponse::Detail(render_row(
                row.id,
                row.chat,
                &format!("{:?}", row.phase),
                row.wall_ms,
            )),
            None => AdminResponse::NotActed,
        },
        AdminCommand::Cancel(id) => {
            if registry.request_cancel(TaskId(*id), operator) {
                AdminResponse::Acted
            } else {
                AdminResponse::NotActed
            }
        }
        AdminCommand::Kill(id) => {
            if registry.request_kill(TaskId(*id), operator) {
                AdminResponse::Acted
            } else {
                AdminResponse::NotActed
            }
        }
    }
}

fn render_snapshot(snap: &RegistrySnapshot) -> String {
    let mut out = format!("tasks: {}\n", snap.rows.len());
    for row in snap.rows.iter().take(MAX_STATUS_ROWS) {
        out.push_str(&render_row(
            row.id,
            row.chat,
            &format!("{:?}", row.phase),
            row.wall_ms,
        ));
        out.push('\n');
    }
    out
}

fn render_row(id: TaskId, chat: ChatId, phase: &str, wall_ms: u64) -> String {
    format!("task {} chat {} {} {}ms", id.0, chat.0, phase, wall_ms)
}

/// Reads one length-prefixed frame from `r`, or `None` on a clean EOF before any byte. A
/// length over [`MAX_ADMIN_FRAME`] is rejected before allocating (invariant 11).
fn read_frame<R: Read>(r: &mut R) -> std::io::Result<Option<Vec<u8>>> {
    let mut len_bytes = [0u8; 4];
    match r.read_exact(&mut len_bytes) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len > MAX_ADMIN_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "admin frame too large",
        ));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(Some(buf))
}

fn write_frame<W: Write>(w: &mut W, payload: &[u8]) -> std::io::Result<()> {
    w.write_all(&frame(payload))
}

/// Serves **one** admin request over any byte stream: read a framed nonce, then a framed
/// command, authenticate, dispatch, and write the framed response. This is the
/// **transport-agnostic** serve step — CI-tested over in-memory buffers; the real
/// `UnixListener` (mode 0600) / TCP-loopback accept loop is the thin `#[ignore]`d wrapper
/// that calls this per connection. A wrong nonce drops the connection after one
/// `Unauthorized` reply (invariant 5).
///
/// # Errors
/// An I/O error from the underlying stream (a malformed/oversized frame is an
/// `InvalidData` error; a parse failure is answered as `BadRequest`, not an error).
pub fn serve_admin_connection<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    registry: &mut TaskRegistry,
    operator: ChatId,
    expected_nonce: &[u8],
    now: Timestamp,
) -> std::io::Result<()> {
    let Some(nonce) = read_frame(reader)? else {
        return Ok(()); // connection closed before sending anything
    };
    if !authenticate(&nonce, expected_nonce) {
        return write_frame(writer, AdminResponse::Unauthorized.render().as_bytes());
    }
    let Some(cmd_bytes) = read_frame(reader)? else {
        return Ok(());
    };
    let line = String::from_utf8_lossy(&cmd_bytes);
    let response = match parse_admin_command(&line) {
        Some(cmd) => dispatch_admin(&cmd, registry, operator, now),
        None => AdminResponse::BadRequest,
    };
    write_frame(writer, response.render().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{default_task_budget, LeaseOwner};

    fn ts(ms: u64) -> Timestamp {
        Timestamp::from_millis(ms)
    }

    #[test]
    fn parses_admin_commands() {
        assert_eq!(parse_admin_command("status"), Some(AdminCommand::Status));
        assert_eq!(
            parse_admin_command("detail 5"),
            Some(AdminCommand::TaskDetail(5))
        );
        assert_eq!(
            parse_admin_command("cancel 9"),
            Some(AdminCommand::Cancel(9))
        );
        assert_eq!(parse_admin_command("kill 3"), Some(AdminCommand::Kill(3)));
        assert_eq!(parse_admin_command("frobnicate 1"), None);
        assert_eq!(parse_admin_command("cancel notanumber"), None);
        assert_eq!(parse_admin_command(""), None);
    }

    #[test]
    fn framing_round_trips_and_bounds() {
        let f = frame(b"status");
        let (payload, consumed) = try_deframe(&f).unwrap().unwrap();
        assert_eq!(payload, b"status");
        assert_eq!(consumed, f.len());
        // Partial buffer → need more.
        assert_eq!(try_deframe(&f[..2]).unwrap(), None);
        // A hostile huge length is rejected before allocating.
        let mut hostile = (MAX_ADMIN_FRAME as u32 + 1).to_le_bytes().to_vec();
        hostile.extend_from_slice(b"x");
        assert_eq!(try_deframe(&hostile), Err(AdminError::FrameTooLarge));
    }

    #[test]
    fn nonce_auth_is_exact_and_constant_length() {
        let secret = b"startup-nonce-abc";
        assert!(authenticate(secret, secret));
        assert!(!authenticate(b"startup-nonce-abd", secret));
        assert!(!authenticate(b"short", secret));
        assert!(!authenticate(b"", b"")); // empty expected never authenticates
    }

    #[test]
    fn cancel_is_owner_scoped_like_telegram() {
        let mut reg = TaskRegistry::new(4, LeaseOwner(1));
        let owner = ChatId(7);
        let other = ChatId(99);
        let id = reg.admit(owner, default_task_budget(), ts(0)).unwrap();

        // Wrong operator → no-op (owner-scoped, invariant 12).
        assert_eq!(
            dispatch_admin(&AdminCommand::Cancel(id.0), &mut reg, other, ts(1)),
            AdminResponse::NotActed
        );
        // Right operator → acts.
        assert_eq!(
            dispatch_admin(&AdminCommand::Cancel(id.0), &mut reg, owner, ts(2)),
            AdminResponse::Acted
        );
    }

    #[test]
    fn status_renders_a_bounded_snapshot() {
        let mut reg = TaskRegistry::new(4, LeaseOwner(1));
        reg.admit(ChatId(7), default_task_budget(), ts(0)).unwrap();
        let resp = dispatch_admin(&AdminCommand::Status, &mut reg, ChatId(7), ts(1));
        match resp {
            AdminResponse::Snapshot(s) => {
                assert!(s.contains("tasks: 1"));
                assert!(s.contains("chat 7"));
            }
            other => panic!("expected a snapshot, got {other:?}"),
        }
    }

    #[test]
    fn kill_unknown_task_is_a_noop() {
        let mut reg = TaskRegistry::new(4, LeaseOwner(1));
        assert_eq!(
            dispatch_admin(&AdminCommand::Kill(999), &mut reg, ChatId(7), ts(1)),
            AdminResponse::NotActed
        );
    }

    #[test]
    fn serve_connection_authenticates_then_dispatches_over_a_stream() {
        let nonce = b"startup-nonce";
        let mut reg = TaskRegistry::new(4, LeaseOwner(1));
        reg.admit(ChatId(7), default_task_budget(), ts(0)).unwrap();

        // A well-formed request: framed nonce, then framed `status`.
        let mut request = frame(nonce);
        request.extend_from_slice(&frame(b"status"));
        let mut reader = std::io::Cursor::new(request);
        let mut writer: Vec<u8> = Vec::new();
        serve_admin_connection(&mut reader, &mut writer, &mut reg, ChatId(7), nonce, ts(1))
            .unwrap();

        // The single response frame carries the snapshot.
        let (payload, _) = try_deframe(&writer).unwrap().unwrap();
        let text = String::from_utf8_lossy(&payload);
        assert!(
            text.contains("tasks: 1"),
            "expected a snapshot, got: {text}"
        );
    }

    #[test]
    fn serve_connection_drops_a_wrong_nonce() {
        let mut reg = TaskRegistry::new(4, LeaseOwner(1));
        let mut request = frame(b"wrong-nonce");
        request.extend_from_slice(&frame(b"status"));
        let mut reader = std::io::Cursor::new(request);
        let mut writer: Vec<u8> = Vec::new();
        serve_admin_connection(
            &mut reader,
            &mut writer,
            &mut reg,
            ChatId(7),
            b"real-nonce",
            ts(1),
        )
        .unwrap();
        let (payload, _) = try_deframe(&writer).unwrap().unwrap();
        assert_eq!(payload, AdminResponse::Unauthorized.render().as_bytes());
    }

    // Live seam: the real Unix/TCP-loopback listener accept loop (the bind + per-connection
    // wrapper around `serve_admin_connection`, which is CI-tested over in-memory buffers).
    #[test]
    #[ignore = "live: bind the admin Unix/TCP socket + a framed query/cancel round-trip (TODO(daemon-admin-live))"]
    fn daemon_admin_live_socket_smoke() {
        // See docs/live-socket-validation.md §F.4. Requires binding a real socket.
        panic!("live seam: run manually against a bound admin socket (see runbook §F.4)");
    }
}
