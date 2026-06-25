// SPDX-License-Identifier: Apache-2.0
//! The **converse boundary** — turning a model's (untrusted) answer into
//! model-/user-visible text.
//!
//! This is the one place full chat parity deliberately relaxes
//! `docs/telegram.md` §8's "render only from typed structured sources" stance: a
//! converse turn *is* a model-authored answer the user reads. The relaxation is kept
//! narrow and structural by routing every byte through the same boundary the rest of
//! CrustCore uses:
//!
//! - **Redact first, then bound.** The model's raw text is run through the
//!   [`Redactor`] (the sole constructor of [`ModelVisibleText`]) *before* truncation,
//!   so a secret split across the truncation point can never survive (invariant 2).
//!   Bounding re-seals the already-redacted text — redaction is a fixed point, so the
//!   re-seal cannot reintroduce a secret.
//! - **The model never holds a `send_message(text)` tool.** Trusted code (this
//!   renderer) produces the visible text; the model only *supplies* the answer string
//!   as untrusted output. So injection in repo/MCP/tool content cannot coerce a chosen
//!   string straight to the user — it is redacted, bounded, attributable (invariant 7).

use crustcore_secrets::{ModelVisibleText, Redactor};

use crate::truncate_on_char_boundary;

/// Cap on a single rendered converse answer / reasoning chunk (bounded everything).
pub const MAX_CONVERSE_BYTES: usize = 16 * 1024;

/// Renders model output for the converse channel. Borrows the host [`Redactor`]
/// (pre-loaded with every stored secret by the broker), so it cannot be constructed
/// without one — there is no "render without redacting" path.
pub struct ConverseRenderer<'r> {
    redactor: &'r Redactor,
    max_bytes: usize,
    reveal_reasoning: bool,
}

impl<'r> ConverseRenderer<'r> {
    /// A renderer over `redactor` with the default bound and reasoning hidden
    /// (deliberate, bounded summaries only — the default posture).
    #[must_use]
    pub fn new(redactor: &'r Redactor) -> Self {
        ConverseRenderer {
            redactor,
            max_bytes: MAX_CONVERSE_BYTES,
            reveal_reasoning: false,
        }
    }

    /// Override the per-render byte bound.
    #[must_use]
    pub fn with_max(mut self, max_bytes: usize) -> Self {
        self.max_bytes = max_bytes.min(MAX_CONVERSE_BYTES);
        self
    }

    /// Full-parity option: stream the model's *reasoning* text to the user (still
    /// redacted + bounded). Off by default — the default streams only the answer plus
    /// deliberate summaries, matching CrustCore's "no raw hidden CoT" posture. The
    /// owner authorized enabling this for chat parity; it remains a per-session toggle.
    #[must_use]
    pub fn reveal_reasoning(mut self, on: bool) -> Self {
        self.reveal_reasoning = on;
        self
    }

    /// Whether reasoning is revealed in this session.
    #[must_use]
    pub fn reasoning_revealed(&self) -> bool {
        self.reveal_reasoning
    }

    /// Render a model answer: **redact, then bound, then re-seal**. The result is
    /// [`ModelVisibleText`] — provably redacted, bounded, safe for the user channel.
    #[must_use]
    pub fn render_answer(&self, raw: &str) -> ModelVisibleText {
        bound_visible(self.redactor, raw, self.max_bytes)
    }

    /// Render a reasoning chunk if (and only if) reasoning is revealed this session;
    /// otherwise [`None`]. Always redacted + bounded when emitted.
    #[must_use]
    pub fn render_reasoning(&self, raw: &str) -> Option<ModelVisibleText> {
        if self.reveal_reasoning {
            Some(bound_visible(self.redactor, raw, self.max_bytes))
        } else {
            None
        }
    }
}

/// Redact `text`, bound the redacted form to `max` bytes (UTF-8 safe), then re-seal as
/// [`ModelVisibleText`]. Re-sealing is safe because [`Redactor::redact`] is a fixed
/// point on its own output (markers are never re-matched).
fn bound_visible(redactor: &Redactor, text: &str, max: usize) -> ModelVisibleText {
    let mut redacted = redactor.redact(text);
    if redacted.len() > max {
        truncate_on_char_boundary(&mut redacted, max);
    }
    redactor.to_model_visible(&redacted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crustcore_secrets::{InMemoryStore, SecretBroker};
    use crustcore_types::SecretId;

    fn broker_with_secret() -> SecretBroker<InMemoryStore> {
        let mut store = InMemoryStore::new();
        store.insert(SecretId(1), "model-key", b"sk-CHATSENTINEL".to_vec());
        SecretBroker::new(store)
    }

    #[test]
    fn answer_is_redacted_before_the_user_sees_it() {
        // RED-TEAM: the model's answer (untrusted output) tries to echo a secret. The
        // converse renderer redacts it before it becomes user-visible (invariant 2).
        let broker = broker_with_secret();
        let r = ConverseRenderer::new(broker.redactor());
        let answer = r.render_answer("Sure, the key is sk-CHATSENTINEL — use it.");
        assert!(!answer.as_str().contains("sk-CHATSENTINEL"));
        assert!(answer.as_str().contains("[REDACTED:model-key]"));
    }

    #[test]
    fn answer_is_bounded() {
        let broker = SecretBroker::new(InMemoryStore::new());
        let r = ConverseRenderer::new(broker.redactor()).with_max(32);
        let answer = r.render_answer(&"word ".repeat(1000));
        assert!(answer.as_str().len() <= 32);
    }

    #[test]
    fn secret_split_by_the_bound_still_cannot_leak() {
        // The secret straddles the truncation point. Because we redact BEFORE bounding,
        // the whole secret is already a marker; truncation can only cut the marker, not
        // expose a secret tail.
        let broker = broker_with_secret();
        // Put the secret near a small bound so truncation would land mid-secret if we
        // bounded first.
        let r = ConverseRenderer::new(broker.redactor()).with_max(20);
        let answer = r.render_answer("prefix sk-CHATSENTINEL suffix");
        assert!(!answer.as_str().contains("sk-CHATSENTINEL"));
        assert!(!answer.as_str().contains("CHATSENTINEL"));
    }

    #[test]
    fn reasoning_hidden_by_default_revealed_on_opt_in() {
        let broker = SecretBroker::new(InMemoryStore::new());
        let hidden = ConverseRenderer::new(broker.redactor());
        assert!(hidden.render_reasoning("thinking...").is_none());

        let shown = ConverseRenderer::new(broker.redactor()).reveal_reasoning(true);
        let chunk = shown.render_reasoning("thinking...").unwrap();
        assert_eq!(chunk.as_str(), "thinking...");
    }

    #[test]
    fn revealed_reasoning_is_still_redacted() {
        let broker = broker_with_secret();
        let shown = ConverseRenderer::new(broker.redactor()).reveal_reasoning(true);
        let chunk = shown
            .render_reasoning("I'll authenticate with sk-CHATSENTINEL")
            .unwrap();
        assert!(!chunk.as_str().contains("CHATSENTINEL"));
    }
}
