// SPDX-License-Identifier: Apache-2.0
//! Queue / steer / cancel — the runtime input state machine.
//!
//! CrustCore parity with NilCore's queue-vs-`!`-steer model, with NilCore's exact
//! hard safety rule preserved: **a steer cancels the in-flight model inference, but
//! never kills a running sandbox tool.** A steer that arrives mid-tool is buffered to
//! the next safe boundary so a container/git op is never half-applied. This is a pure,
//! deterministic state machine (no I/O), so the policy is fully testable; the live
//! channel layer wires the actual model-call cancellation token to
//! [`Disposition::SteerCancelModel`].

use std::collections::VecDeque;

use crate::truncate_on_char_boundary;

/// Bound on queued follow-up turns (bounded everything; invariant 11). Beyond this,
/// new plain messages are dropped rather than growing unboundedly.
pub const MAX_QUEUE_DEPTH: usize = 64;

/// Per-message byte bound (matches the channel normalizer).
const MAX_MESSAGE_BYTES: usize = 8 * 1024;

/// What the agent is currently doing — the only thing that distinguishes a
/// model-cancelling steer from a tool-preserving one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Activity {
    /// No model call or tool in flight (between turns / at a safe boundary).
    Idle,
    /// A model inference is streaming. A steer cancels it (preserving reasoning so
    /// far) and folds in as the next turn.
    ModelInFlight,
    /// A sandbox tool (test/build/git) is running. A steer is **buffered** to the next
    /// boundary; the tool is never cancelled by a steer (only `/cancel` or `/kill`
    /// tear down a run/tool).
    ToolRunning,
}

/// How an inbound message was classified at the channel layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InboundKind {
    /// A plain message — queued for the next safe boundary (default).
    Plain,
    /// A `!`-prefixed (or explicit `/steer`) message — steer.
    Steer,
    /// A typed `/verb` command (handled by the command dispatcher, not the loop).
    Command,
    /// `/cancel` — abort the active run (but stay in the conversation).
    Cancel,
}

/// A parsed inbound message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inbound {
    /// The classified kind.
    pub kind: InboundKind,
    /// The payload text (steer/plain text, or the command verb+args).
    pub text: String,
}

impl Inbound {
    /// Parse a raw message into a typed [`Inbound`]. `!`-prefix → steer; `/cancel` →
    /// cancel; any other `/verb` → command; everything else → plain. Bounded.
    #[must_use]
    pub fn parse(raw: &str) -> Inbound {
        let trimmed = raw.trim();
        let (kind, body) = if let Some(rest) = trimmed.strip_prefix('!') {
            (InboundKind::Steer, rest.trim())
        } else if let Some(rest) = trimmed.strip_prefix("/steer") {
            (InboundKind::Steer, rest.trim())
        } else if trimmed == "/cancel" || trimmed.starts_with("/cancel ") {
            (InboundKind::Cancel, "")
        } else if trimmed.starts_with('/') {
            (InboundKind::Command, trimmed)
        } else {
            (InboundKind::Plain, trimmed)
        };
        let mut text = body.to_string();
        truncate_on_char_boundary(&mut text, MAX_MESSAGE_BYTES);
        Inbound { kind, text }
    }
}

/// The decision the [`TurnQueue`] made for an inbound message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Queued (FIFO) for the next safe boundary.
    Queued,
    /// Steer accepted while a model call was in flight (or idle): the live layer must
    /// **cancel the in-flight model inference** (preserving reasoning) and apply the
    /// steer as the next turn.
    SteerCancelModel,
    /// Steer accepted while a **tool** was running: buffered to the next boundary; the
    /// tool is NOT cancelled.
    SteerBuffered,
    /// `/cancel` — abort the active run.
    Cancel,
    /// A typed command — routed to the command dispatcher (not this loop).
    Command,
    /// Dropped because the queue is full (bounded).
    DroppedFull,
}

/// The bounded FIFO of pending turns + steer handling. Deterministic and I/O-free.
#[derive(Debug, Default)]
pub struct TurnQueue {
    queue: VecDeque<String>,
    max: usize,
}

impl TurnQueue {
    /// A queue with the default depth bound.
    #[must_use]
    pub fn new() -> Self {
        TurnQueue {
            queue: VecDeque::new(),
            max: MAX_QUEUE_DEPTH,
        }
    }

    /// A queue with a custom depth bound (clamped to [`MAX_QUEUE_DEPTH`]).
    #[must_use]
    pub fn with_max(max: usize) -> Self {
        TurnQueue {
            queue: VecDeque::new(),
            max: max.clamp(1, MAX_QUEUE_DEPTH),
        }
    }

    /// Admit an inbound message given the current [`Activity`], applying queue side
    /// effects and returning the [`Disposition`] the caller must act on.
    ///
    /// - Plain → enqueue (FIFO) for the next boundary, or [`Disposition::DroppedFull`].
    /// - Steer + `ModelInFlight`/`Idle` → push to the **front** (next turn) and signal
    ///   [`Disposition::SteerCancelModel`].
    /// - Steer + `ToolRunning` → push to the **back** and signal
    ///   [`Disposition::SteerBuffered`] (the tool keeps running).
    /// - Cancel → [`Disposition::Cancel`] (no queue change).
    /// - Command → [`Disposition::Command`] (no queue change).
    pub fn admit(&mut self, inbound: &Inbound, activity: Activity) -> Disposition {
        match inbound.kind {
            InboundKind::Cancel => Disposition::Cancel,
            InboundKind::Command => Disposition::Command,
            InboundKind::Plain => {
                if self.queue.len() >= self.max {
                    Disposition::DroppedFull
                } else {
                    self.queue.push_back(inbound.text.clone());
                    Disposition::Queued
                }
            }
            InboundKind::Steer => match activity {
                Activity::ToolRunning => {
                    // NEVER cancel a running tool: buffer to the next boundary.
                    if self.queue.len() >= self.max {
                        Disposition::DroppedFull
                    } else {
                        self.queue.push_back(inbound.text.clone());
                        Disposition::SteerBuffered
                    }
                }
                Activity::ModelInFlight | Activity::Idle => {
                    // Cancel the in-flight model call and jump the steer to the front.
                    self.queue.push_front(inbound.text.clone());
                    Disposition::SteerCancelModel
                }
            },
        }
    }

    /// Pop the next pending turn (FIFO, modulo steer front-jumps), if any.
    pub fn pop_next(&mut self) -> Option<String> {
        self.queue.pop_front()
    }

    /// Number of pending turns.
    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Whether the queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Drop all pending turns (e.g. on `/cancel`).
    pub fn clear(&mut self) {
        self.queue.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_classifies_each_kind() {
        assert_eq!(Inbound::parse("fix the test").kind, InboundKind::Plain);
        assert_eq!(
            Inbound::parse("!stop touching auth").kind,
            InboundKind::Steer
        );
        assert_eq!(Inbound::parse("/steer focus here").kind, InboundKind::Steer);
        assert_eq!(Inbound::parse("/cancel").kind, InboundKind::Cancel);
        assert_eq!(Inbound::parse("/status").kind, InboundKind::Command);
        // Steer body strips the prefix.
        assert_eq!(Inbound::parse("!focus on the bug").text, "focus on the bug");
    }

    #[test]
    fn plain_message_queues_fifo() {
        let mut q = TurnQueue::new();
        assert_eq!(
            q.admit(&Inbound::parse("first"), Activity::Idle),
            Disposition::Queued
        );
        assert_eq!(
            q.admit(&Inbound::parse("second"), Activity::ModelInFlight),
            Disposition::Queued
        );
        assert_eq!(q.pop_next().as_deref(), Some("first"));
        assert_eq!(q.pop_next().as_deref(), Some("second"));
    }

    #[test]
    fn steer_during_model_call_cancels_and_jumps_to_front() {
        let mut q = TurnQueue::new();
        q.admit(&Inbound::parse("queued earlier"), Activity::Idle);
        let d = q.admit(&Inbound::parse("!do this instead"), Activity::ModelInFlight);
        assert_eq!(d, Disposition::SteerCancelModel);
        // The steer is the NEXT turn, ahead of the earlier queued message.
        assert_eq!(q.pop_next().as_deref(), Some("do this instead"));
        assert_eq!(q.pop_next().as_deref(), Some("queued earlier"));
    }

    #[test]
    fn steer_during_tool_run_is_buffered_never_kills_the_tool() {
        // NilCore's hard rule: a steer mid-tool must NOT cancel the tool.
        let mut q = TurnQueue::new();
        let d = q.admit(&Inbound::parse("!change approach"), Activity::ToolRunning);
        assert_eq!(d, Disposition::SteerBuffered);
        // It is buffered to the back (applied at the next boundary), not front-jumped.
        q.admit(&Inbound::parse("plain follow-up"), Activity::ToolRunning);
        assert_eq!(q.pop_next().as_deref(), Some("change approach"));
    }

    #[test]
    fn cancel_and_command_do_not_enqueue() {
        let mut q = TurnQueue::new();
        assert_eq!(
            q.admit(&Inbound::parse("/cancel"), Activity::ModelInFlight),
            Disposition::Cancel
        );
        assert_eq!(
            q.admit(&Inbound::parse("/budget"), Activity::Idle),
            Disposition::Command
        );
        assert!(q.is_empty());
    }

    #[test]
    fn queue_is_bounded() {
        let mut q = TurnQueue::with_max(2);
        assert_eq!(
            q.admit(&Inbound::parse("a"), Activity::Idle),
            Disposition::Queued
        );
        assert_eq!(
            q.admit(&Inbound::parse("b"), Activity::Idle),
            Disposition::Queued
        );
        assert_eq!(
            q.admit(&Inbound::parse("c"), Activity::Idle),
            Disposition::DroppedFull
        );
        assert_eq!(q.len(), 2);
    }
}
