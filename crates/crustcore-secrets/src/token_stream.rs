// SPDX-License-Identifier: Apache-2.0
//! Streaming token redaction (roadmap-v0.6 E.4 — feasibility prototype).
//!
//! Token-by-token chain-of-thought streaming is *only* safe if no unredacted secret can
//! reach the user mid-stream (invariants 2, 3). Naively emitting each model token would
//! leak a secret that arrives split across tokens (`ghp_` then `SECRET…`). [`TokenRedactor`]
//! makes streaming safe by **buffering to a redaction boundary**, scanning the buffer with
//! the existing [`Redactor`], and emitting only redacted chunks:
//!
//! - **Boundary = newline.** A registered secret value never contains a newline, so a
//!   secret can never straddle a newline. Emitting (and redacting) everything up to and
//!   including a newline is therefore safe — any secret in that chunk is wholly inside it.
//! - **Bounded latency via dangling-prefix retention.** A long line with no newline must
//!   still emit eventually (no unbounded buffering). When the buffer reaches `max_buffer`,
//!   the redactor retains only the longest suffix that is a *prefix of some secret*
//!   ([`Redactor::longest_dangling_prefix`]) — the start of a not-yet-finished secret —
//!   and redacts+emits everything before it. The emitted part has no partial-secret tail,
//!   so a secret straddling the buffer end is retained whole and caught when it completes.
//!
//! See `docs/cot-streaming.md` for the full analysis, constraints, and the
//! `reveal_reasoning` opt-in.

use crate::Redactor;

/// Buffers streamed tokens and yields only **fully redacted** chunks. Borrow a
/// [`Redactor`] holding the live secret set; the redactor is never mutated.
pub struct TokenRedactor<'r> {
    redactor: &'r Redactor,
    buffer: String,
    /// Force an emit once the buffer reaches this many bytes (bounds latency).
    max_buffer: usize,
}

impl<'r> TokenRedactor<'r> {
    /// Builds a streaming redactor. `max_buffer` bounds how long a boundary-free run may
    /// grow before a forced emit (latency cap).
    #[must_use]
    pub fn new(redactor: &'r Redactor, max_buffer: usize) -> Self {
        TokenRedactor {
            redactor,
            buffer: String::new(),
            max_buffer: max_buffer.max(1),
        }
    }

    /// Accepts one streamed token. Returns a redacted chunk when a newline boundary is
    /// reached, or when the buffer hits `max_buffer` (the bounded-latency forced emit);
    /// otherwise buffers and returns `None`. The returned chunk is fully redacted; any
    /// **dangling partial secret** at the tail stays buffered for the next chunk, so a
    /// secret is never split across the emit point (the start of a not-yet-complete
    /// secret is never emitted — invariants 2, 3).
    #[must_use]
    pub fn accept_token(&mut self, token: &str) -> Option<String> {
        self.buffer.push_str(token);

        // Boundary emit: flush through the last newline (a secret cannot span a newline).
        if let Some(nl) = self.buffer.rfind('\n') {
            let emit: String = self.buffer.drain(..=nl).collect();
            return Some(self.redactor.redact(&emit));
        }

        // Forced emit: the boundary-free run is too long. Retain only the longest
        // dangling needle-prefix suffix; emit (redacted) everything before it. A secret
        // straddling the buffer end is, by construction, that dangling suffix, so it is
        // retained whole — never emitted partially.
        if self.buffer.len() >= self.max_buffer {
            let d = self.redactor.longest_dangling_prefix(&self.buffer);
            let cut = self.suffix_boundary(d);
            if cut == 0 {
                // The whole buffer is a dangling partial secret — keep waiting.
                return None;
            }
            let emit: String = self.buffer.drain(..cut).collect();
            return Some(self.redactor.redact(&emit));
        }
        None
    }

    /// Flushes the buffered tail at end-of-stream, redacted. Call once the model stops.
    #[must_use]
    pub fn flush(&mut self) -> Option<String> {
        if self.buffer.is_empty() {
            return None;
        }
        let emit: String = self.buffer.drain(..).collect();
        Some(self.redactor.redact(&emit))
    }

    /// The byte offset that retains `window` bytes as a suffix, rounded **down** to a char
    /// boundary so we never split a UTF-8 sequence.
    fn suffix_boundary(&self, window: usize) -> usize {
        let len = self.buffer.len();
        let mut cut = len.saturating_sub(window);
        while cut > 0 && !self.buffer.is_char_boundary(cut) {
            cut -= 1;
        }
        cut
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redactor_with(secret: &[u8]) -> Redactor {
        let mut r = Redactor::new();
        r.register("secret", secret);
        r
    }

    /// Feeds tokens, collecting every emitted chunk + the flush; returns the full output.
    fn stream(tr: &mut TokenRedactor, tokens: &[&str]) -> String {
        let mut out = String::new();
        for t in tokens {
            if let Some(chunk) = tr.accept_token(t) {
                out.push_str(&chunk);
            }
        }
        if let Some(chunk) = tr.flush() {
            out.push_str(&chunk);
        }
        out
    }

    #[test]
    fn secret_split_across_tokens_is_caught() {
        let r = redactor_with(b"ghp_SECRETTOKEN");
        let mut tr = TokenRedactor::new(&r, 4096);
        // The secret arrives split across three tokens, then a newline.
        let out = stream(&mut tr, &["thinking ghp_", "SECRET", "TOKEN done\n"]);
        assert!(!out.contains("ghp_SECRETTOKEN"), "secret leaked: {out}");
        assert!(out.contains("thinking"));
    }

    #[test]
    fn secret_at_end_of_buffer_with_no_newline_is_retained_not_leaked() {
        let r = redactor_with(b"ghp_SECRETTOKEN");
        // Tiny max_buffer to force the no-boundary emit path.
        let mut tr = TokenRedactor::new(&r, 8);
        // No newline ever; the secret straddles the forced-emit point.
        let mut out = String::new();
        for t in ["aaaaaa ghp_SE", "CRETTOKEN bbbb"] {
            if let Some(c) = tr.accept_token(t) {
                out.push_str(&c);
            }
        }
        if let Some(c) = tr.flush() {
            out.push_str(&c);
        }
        assert!(
            !out.contains("ghp_SECRETTOKEN"),
            "secret leaked on forced emit: {out}"
        );
    }

    #[test]
    fn worst_case_no_boundary_stays_bounded() {
        let r = redactor_with(b"zzzz");
        let max = 64;
        let mut tr = TokenRedactor::new(&r, max);
        // Feed a long boundary-free run; the internal buffer must never exceed max.
        for _ in 0..1000 {
            let _ = tr.accept_token("abcdefghij"); // 10 bytes each
            assert!(
                tr.buffer.len() <= max + 10,
                "buffer grew unbounded: {}",
                tr.buffer.len()
            );
        }
    }

    #[test]
    fn non_secret_text_passes_through_unchanged() {
        let r = redactor_with(b"ghp_SECRETTOKEN");
        let mut tr = TokenRedactor::new(&r, 4096);
        let out = stream(&mut tr, &["hello world\n", "no secrets here\n"]);
        assert_eq!(out, "hello world\nno secrets here\n");
    }

    #[test]
    fn flush_emits_the_trailing_partial_line_redacted() {
        let r = redactor_with(b"ghp_TAILSECRET");
        let mut tr = TokenRedactor::new(&r, 4096);
        // No trailing newline — the tail only emits on flush.
        let out = stream(&mut tr, &["leftover ghp_TAILSECRET"]);
        assert!(!out.contains("ghp_TAILSECRET"));
        assert!(out.contains("leftover"));
    }

    #[test]
    fn empty_redactor_is_a_passthrough() {
        let r = Redactor::new();
        let mut tr = TokenRedactor::new(&r, 4096);
        assert_eq!(stream(&mut tr, &["any ", "text\n"]), "any text\n");
    }
}
