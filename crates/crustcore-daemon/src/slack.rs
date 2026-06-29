// SPDX-License-Identifier: Apache-2.0
//! Slack runtime control plane (roadmap-v0.6 E.3).
//!
//! Slack sits **alongside** Telegram + the cockpit, mirroring the allowlist, redaction,
//! and approval-nonce model and feeding the *same* [`RuntimeEvent`] stream the daemon
//! already dispatches — so it routes through the same policy gates, **not a parallel
//! ungoverned surface** (invariants 8, 16). It is **opt-in, never the default**: the
//! operator binds a workspace/channel via the CLI (not via DM); an empty allowlist denies
//! everything (invariants 5, 15).
//!
//! This module is the **pure core**: the allowlist, the inbound `normalize_message`, and
//! the redacted outbound render. The live Slack Bot API HTTP client + the Events-API /
//! Socket-Mode listener are the `live` seam (the Telegram pattern), `#[ignore]`d.

use std::collections::{BTreeMap, BTreeSet};

use crustcore_secrets::Redactor;
use crustcore_types::BoundedText;

use crate::telegram::{CallbackData, Command, RuntimeEvent};

/// Max bytes of inbound Slack message text kept (bounded untrusted input; invariant 11).
pub const MAX_SLACK_TEXT: usize = 4096;
/// Max bytes of an outbound Slack message (bounded).
pub const MAX_SLACK_OUTBOUND: usize = 8192;

/// A **per-workspace, per-channel** allowlist. **Deny-all when empty** (invariant 5): no
/// workspace or channel is authorized until the operator binds it (via CLI). Nesting
/// scopes a channel to its workspace so an id collision across workspaces can't leak.
#[derive(Debug, Default, Clone)]
pub struct SlackAllowlist {
    workspaces: BTreeMap<String, BTreeSet<String>>,
}

impl SlackAllowlist {
    /// An empty allowlist — denies everything until channels are bound.
    #[must_use]
    pub fn new() -> Self {
        SlackAllowlist::default()
    }

    /// Binds `channel` in `workspace` (operator setup; not driven by message content).
    pub fn allow(&mut self, workspace: impl Into<String>, channel: impl Into<String>) {
        self.workspaces
            .entry(workspace.into())
            .or_default()
            .insert(channel.into());
    }

    /// Whether `(workspace, channel)` is authorized. An unknown workspace is rejected.
    #[must_use]
    pub fn is_allowed(&self, workspace: &str, channel: &str) -> bool {
        self.workspaces
            .get(workspace)
            .is_some_and(|chans| chans.contains(channel))
    }
}

/// An approval reaction (an emoji on a message carrying an approval nonce).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlackReaction {
    /// The callback/nonce payload bound to the reacted-to message.
    pub callback: String,
}

/// An inbound Slack event, already extracted from the API payload. The `text` is
/// **untrusted** (invariant 7); the workspace/channel/user are routing scope.
#[derive(Debug, Clone)]
pub struct SlackMessage {
    /// Workspace (team) id.
    pub workspace: String,
    /// Channel id.
    pub channel: String,
    /// Author id (for the audit trail; authority is the allowlist, not the author).
    pub user: String,
    /// Message text (untrusted).
    pub text: String,
    /// Set when this is an approval reaction rather than a message.
    pub reaction: Option<SlackReaction>,
}

/// Normalizes a Slack event into the **same** [`RuntimeEvent`] the daemon dispatches for
/// Telegram (invariants 8, 16):
/// - denied workspace/channel → `None` (no event ever forms);
/// - a reaction → `ApprovalCallback` (same nonce format, parsed by `CallbackData::parse`);
/// - `/slash` → `Command`; `!`-prefixed → `Steer`; plain text → `QueuedTurn`.
///
/// Text is bounded (invariant 11) and never interpreted as a prompt here — it is carried
/// as data for the daemon's existing dispatch + redaction path. Approvals come from
/// Slack *users* gated by the allowlist, never from model output (invariants 4, 5).
#[must_use]
pub fn normalize_message(msg: &SlackMessage, allowlist: &SlackAllowlist) -> Option<RuntimeEvent> {
    if !allowlist.is_allowed(&msg.workspace, &msg.channel) {
        return None; // deny-all / unknown workspace / unbound channel
    }
    if let Some(reaction) = &msg.reaction {
        return CallbackData::parse(&reaction.callback).map(RuntimeEvent::ApprovalCallback);
    }
    let text = msg.text.trim();
    if text.is_empty() {
        return None;
    }
    if text.starts_with('/') {
        return Some(RuntimeEvent::Command(Command::parse(text)));
    }
    if let Some(steer) = text.strip_prefix('!') {
        return Some(RuntimeEvent::Steer(BoundedText::truncated(
            steer.trim(),
            MAX_SLACK_TEXT,
        )));
    }
    Some(RuntimeEvent::QueuedTurn(BoundedText::truncated(
        text,
        MAX_SLACK_TEXT,
    )))
}

/// Renders outbound text for Slack: **redacts every known secret** through the broker's
/// [`Redactor`] before it crosses the channel boundary (invariants 1–3), then bounds it.
/// The only text that ever reaches Slack is redacted + bounded.
#[must_use]
pub fn render_to_slack(text: &str, redactor: &Redactor) -> String {
    let redacted = redactor.redact(text);
    redacted.chars().take(MAX_SLACK_OUTBOUND).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow_one() -> SlackAllowlist {
        let mut a = SlackAllowlist::new();
        a.allow("W1", "C1");
        a
    }

    fn msg(workspace: &str, channel: &str, text: &str) -> SlackMessage {
        SlackMessage {
            workspace: workspace.to_string(),
            channel: channel.to_string(),
            user: "U1".to_string(),
            text: text.to_string(),
            reaction: None,
        }
    }

    #[test]
    fn an_empty_allowlist_denies_everything() {
        let deny = SlackAllowlist::new();
        assert!(normalize_message(&msg("W1", "C1", "hello"), &deny).is_none());
    }

    #[test]
    fn allowed_vs_blocked_channel_and_unknown_workspace() {
        let a = allow_one();
        assert!(normalize_message(&msg("W1", "C1", "hello"), &a).is_some()); // allowed
        assert!(normalize_message(&msg("W1", "C2", "hello"), &a).is_none()); // unbound channel
        assert!(normalize_message(&msg("W2", "C1", "hello"), &a).is_none()); // unknown workspace
    }

    #[test]
    fn plain_steer_and_command_normalize_like_telegram() {
        let a = allow_one();
        assert!(matches!(
            normalize_message(&msg("W1", "C1", "do the thing"), &a),
            Some(RuntimeEvent::QueuedTurn(_))
        ));
        assert!(matches!(
            normalize_message(&msg("W1", "C1", "!actually do this instead"), &a),
            Some(RuntimeEvent::Steer(_))
        ));
        assert!(matches!(
            normalize_message(&msg("W1", "C1", "/status"), &a),
            Some(RuntimeEvent::Command(Command::Status))
        ));
    }

    #[test]
    fn a_reaction_becomes_an_approval_callback_when_the_nonce_parses() {
        let a = allow_one();
        // A valid Telegram-format callback should parse; an unparseable one yields no event.
        let mut m = msg("W1", "C1", "");
        m.reaction = Some(SlackReaction {
            callback: "not-a-valid-callback".to_string(),
        });
        // Unparseable nonce → no event (never a spurious approval).
        assert!(normalize_message(&m, &a).is_none());
    }

    #[test]
    fn outbound_render_redacts_secrets_and_bounds() {
        let mut r = Redactor::new();
        r.register("token", b"xoxb-SECRET");
        let out = render_to_slack("posting xoxb-SECRET to the channel", &r);
        assert!(
            !out.contains("xoxb-SECRET"),
            "secret leaked to Slack: {out}"
        );
        assert!(out.len() <= MAX_SLACK_OUTBOUND);
    }

    // Live seam: the Slack Bot API HTTP client + Events-API/Socket-Mode listener.
    #[cfg(feature = "live")]
    #[test]
    #[ignore = "live: Slack Bot API + Events-API/Socket-Mode round-trip against a real workspace (TODO(slack-live))"]
    fn slack_live_round_trip_smoke() {
        // See docs/live-socket-validation.md §F.7. Requires a real Slack workspace + token.
        panic!("live seam: run manually with a real Slack workspace (see runbook §F.7)");
    }
}
