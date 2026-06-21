// SPDX-License-Identifier: Apache-2.0
//! Provider config tester (`C7.4`). Renders `ModelCard`/usage metadata only.
//!
//! The UI process holds **no** credential: in CI the cards come from the
//! [`MockDevBackend`](crate::backend::MockDevBackend); the real probe/complete via the
//! spawned `crustcore-net` helper is `serve`-gated (`TODO(C7-serve-live)`). Every
//! string field is passed through the [`Redactor`] before render so a sentinel needle in
//! any field is scrubbed (dimension (e)) — the view never carries a key.

use crate::backend::ModelCardView;
use crustcore_secrets::Redactor;

/// Redact and render the provider/model cards. The card fields are metadata
/// (provider/model name, capability flags, cost-per-1k micros). No field is a
/// credential; the redactor is applied defensively to the text fields.
#[must_use]
pub fn render(cards: &[ModelCardView], redactor: &Redactor) -> Vec<ModelCardView> {
    cards
        .iter()
        .map(|c| ModelCardView {
            provider: redactor.redact(&c.provider),
            model: redactor.redact(&c.model),
            healthy: c.healthy,
            context: c.context,
            tools: c.tools,
            cost_per_1k_micros: c.cost_per_1k_micros,
        })
        .collect()
}

/// The bounded prompt cap for a provider `complete` test. The live (`serve`) path issues
/// at most this many bytes to the spawned helper. Kept in sync with
/// `crustcore_netproto::MAX_TEXT_BYTES`.
pub const MAX_PROMPT_BYTES: usize = crustcore_netproto::MAX_TEXT_BYTES;

#[cfg(test)]
mod tests {
    use super::*;

    fn card(provider: &str, model: &str) -> ModelCardView {
        ModelCardView {
            provider: provider.to_string(),
            model: model.to_string(),
            healthy: true,
            context: 200_000,
            tools: true,
            cost_per_1k_micros: 3_000,
        }
    }

    #[test]
    fn renders_metadata_only() {
        let cards = vec![card("anthropic", "claude-opus")];
        let out = render(&cards, &Redactor::new());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].provider, "anthropic");
        assert_eq!(out[0].model, "claude-opus");
        assert_eq!(out[0].context, 200_000);
    }

    #[test]
    fn a_sentinel_secret_in_a_field_is_redacted() {
        // If a credential ever leaked into a card field, the redactor scrubs it.
        let mut redactor = Redactor::new();
        redactor.register("api-key", b"sk-SENTINEL-SECRET");
        let cards = vec![card("provider-sk-SENTINEL-SECRET", "model")];
        let out = render(&cards, &redactor);
        assert!(
            !out[0].provider.contains("sk-SENTINEL-SECRET"),
            "secret must not survive render"
        );
    }

    #[test]
    fn prompt_cap_matches_netproto_bound() {
        assert_eq!(MAX_PROMPT_BYTES, crustcore_netproto::MAX_TEXT_BYTES);
    }
}
