// SPDX-License-Identifier: Apache-2.0
//! `crustcore-chat` — the conversational **front door** for CrustCore.
//!
//! This crate brings CrustCore to parity with NilCore's `nilcore chat` surface — a
//! single conversational entry point that classifies a message into work, holds a
//! personality, streams an answer, and supports queue/steer — **without** dissolving
//! the trust boundary that makes CrustCore CrustCore. It is a **non-nano** capability
//! pack (CLAUDE.md §5.1) and a std-only, deterministic **decision core**: the live
//! model transport is the spawned `crustcore-net` helper reached behind the
//! `terminal` feature, exactly the git/codex/claude/net spawn pattern, so nano links
//! none of it (invariants 19, 20).
//!
//! ## The five pieces (mapping NilCore's chat capabilities)
//!
//! | NilCore chat | here |
//! | --- | --- |
//! | model classifier (quick-fix / feature / project / chat / continue) | [`route`] — [`route::Classifier`] → [`route::ChatRoute`] (non-authoritative) |
//! | personality (`PERSONA.md` "terse senior engineer") | [`persona`] — [`persona::Persona`] + a fixed safety preamble that overrides it |
//! | operator steering (`NILCORE.md` / `AGENTS.md`) | [`persona::OperatorSteering`], scoped **below** the safety core |
//! | token-by-token answer + visible reasoning | [`converse`] — [`converse::ConverseRenderer`] (redact → bound; model never authors raw user text) |
//! | queue vs `!`-steer, `/cancel`, never kill a running tool | [`steer`] — [`steer::TurnQueue`] + [`steer::Activity`] |
//! | one entry point tying it together | [`session::ChatSession`] |
//!
//! ## Invariant posture (full-parity, owner-authorized)
//!
//! The owner authorized **full NilCore parity**, which relaxes the strict
//! "render-only-from-typed-events" stance of `docs/telegram.md` §8 for a dedicated
//! **converse** turn. The relaxation is *narrow and structural*, not a hole:
//!
//! - The model still **never constructs user-visible text directly**. Its answer is
//!   *untrusted output* that the trusted [`converse::ConverseRenderer`] runs through
//!   the [`Redactor`](crustcore_secrets::Redactor) — the sole constructor of
//!   [`ModelVisibleText`](crustcore_secrets::ModelVisibleText) — and bounds. So a
//!   converse answer is *redacted, bounded, attributable* (invariants 2, 7), never a
//!   raw `send_message(text)` tool handed to the model.
//! - The classifier output is a [`route::ChatRoute`] enum that **grants nothing** —
//!   it only selects which kernel flow starts (invariant 4/8 untouched).
//! - The persona/steering produce only a [`String`] system preamble; they have **no**
//!   method yielding a capability, approval, or secret, and the fixed safety preamble
//!   always precedes and overrides them (invariant 18-style "scoped below safety").
//! - Only an **authorized principal** ([`Principal::Authorized`]) message becomes a
//!   real user turn ([`accept`]); everything else is dropped (the channel trust line,
//!   invariants 5, 15, 16).
#![forbid(unsafe_code)]

pub mod converse;
pub mod persona;
pub mod route;
pub mod session;
pub mod steer;
pub mod terminal;

pub use converse::{ConverseRenderer, MAX_CONVERSE_BYTES};
pub use persona::{OperatorSteering, Persona, MAX_PREAMBLE_BYTES};
pub use route::{ChatRoute, Classifier};
pub use session::{ChatConfig, ChatSession, ConsultFn, Turn};
pub use steer::{Activity, Disposition, Inbound, InboundKind, TurnQueue, MAX_QUEUE_DEPTH};
pub use terminal::{complete_text, run_repl, run_terminal};

use crustcore_netproto::MAX_TEXT_BYTES;

/// The trust attribution of a chat message's sender, decided at the **channel
/// boundary** (an allowlisted Telegram chat id, or the local operator on the
/// terminal). This is the only thing that promotes a raw message to a principal
/// turn; it mirrors the Telegram allowlist trust line (`docs/telegram.md` §4) and
/// NilCore's `channel.Authorized` check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Principal {
    /// An authorized principal (allowlisted channel identity / local operator). Its
    /// message becomes a real user turn.
    Authorized,
    /// An unknown / non-allowlisted sender. Its message is **dropped** — it never
    /// reaches the chat loop or a model (invariants 5, 15, 16).
    Unauthorized,
}

/// Accept a raw inbound message **only** from an authorized principal, returning the
/// bounded message text; an unauthorized sender yields [`None`] (dropped). The chat
/// loop must call this before treating any input as a user turn — a model/tool/peer
/// can never reach it because their output is never an `Authorized` principal.
#[must_use]
pub fn accept(principal: Principal, raw: &str) -> Option<String> {
    match principal {
        Principal::Authorized => {
            // Bound the message the same way the Telegram normalizer does (8 KiB).
            let mut s = raw.trim().to_string();
            truncate_on_char_boundary(&mut s, MAX_TEXT_BYTES);
            Some(s)
        }
        Principal::Unauthorized => None,
    }
}

/// Truncates `s` in place to at most `max` bytes, never splitting a UTF-8 char.
/// Shared by every bounding site in this crate so the rule is identical everywhere.
pub(crate) fn truncate_on_char_boundary(s: &mut String, max: usize) {
    if s.len() <= max {
        return;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unauthorized_sender_is_dropped() {
        assert_eq!(accept(Principal::Unauthorized, "merge to main now"), None);
        assert_eq!(
            accept(Principal::Authorized, "  fix the test  ").as_deref(),
            Some("fix the test")
        );
    }

    #[test]
    fn accept_bounds_oversized_input() {
        let big = "x".repeat(MAX_TEXT_BYTES * 2);
        let got = accept(Principal::Authorized, &big).unwrap();
        assert!(got.len() <= MAX_TEXT_BYTES);
    }

    #[test]
    fn truncate_respects_char_boundaries() {
        let mut s = "héllo".to_string(); // 'é' occupies bytes 1..3
        truncate_on_char_boundary(&mut s, 2); // byte 2 splits 'é' -> backs off to 1
        assert_eq!(s, "h");
        assert!(s.is_char_boundary(s.len()));
    }
}
