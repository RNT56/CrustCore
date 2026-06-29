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
//! This module is the **pure core**: the [`SlackSignature`] request verifier (the "is
//! this really from Slack" gate — HMAC-SHA256 over `v0:{ts}:{body}` + a timestamp-freshness
//! replay defense, mirroring the GitHub webhook hardening), the allowlist, the inbound
//! `normalize_message`, and the redacted outbound render. The live Slack Bot API HTTP
//! client + the Events-API / Socket-Mode listener that *delivers* a verified request are
//! the `live` seam (the Telegram pattern), `#[ignore]`d.

use std::collections::{BTreeMap, BTreeSet};

use crustcore_secrets::Redactor;
use crustcore_types::{ct_eq, hex32_decode, hmac_sha256, BoundedText};

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

/// Max accepted clock skew (seconds) for a Slack request timestamp — Slack's own
/// recommendation. A request older (or more forward-dated) than this is rejected as a
/// possible replay even if its signature is valid.
pub const SLACK_MAX_SKEW_SECS: u64 = 300;

/// Max accepted request-body size (bytes) for signature verification — bounds the work an
/// unauthenticated caller can force (invariant 11), mirroring `MAX_WEBHOOK_BODY`. Rejected
/// *before* the basestring is allocated or the HMAC is computed.
pub const MAX_SLACK_BODY: usize = 1024 * 1024;

/// Max accepted `X-Slack-Request-Timestamp` length (bytes). A unix timestamp is ~10
/// digits; anything longer is malformed and rejected before any allocation.
pub const MAX_SLACK_TIMESTAMP: usize = 32;

/// Verifies a Slack request's signature **and** timestamp freshness — the "is this really
/// from Slack" gate that runs *before* [`normalize_message`] ever sees the body.
///
/// Slack signs every request as `X-Slack-Signature: v0=HMAC_SHA256(signing_secret,
/// "v0:{timestamp}:{body}")`, with `X-Slack-Request-Timestamp: {timestamp}`. This mirrors
/// the GitHub webhook hardening: a forged or stale request **never forms a
/// [`SlackMessage`]**, so it can never reach the dispatch path (invariants 7, 8, 16). The
/// compare is constant-time (no timing oracle) and the signing secret is never logged or
/// returned. Std-only + CI-tested with signed fixtures; the only live inch is the HTTP
/// listener that *delivers* the request (the `live` Events-API/Socket-Mode seam).
pub struct SlackSignature {
    secret: Vec<u8>,
}

impl SlackSignature {
    /// Bind the verifier to a workspace's signing secret. The secret is held only to
    /// compute the HMAC; it is never serialized, logged, or returned.
    #[must_use]
    pub fn new(signing_secret: &[u8]) -> Self {
        SlackSignature {
            secret: signing_secret.to_vec(),
        }
    }

    /// Returns `true` iff `signature` (the `X-Slack-Signature` header, `v0=<hex>`) is a
    /// valid HMAC over `v0:{timestamp}:{body}` **and** the request is fresh
    /// (`|now_unix_secs - timestamp| <= `[`SLACK_MAX_SKEW_SECS`]). `timestamp` is the raw
    /// `X-Slack-Request-Timestamp` header value (used verbatim in the basestring, exactly
    /// as Slack signs it; parsed separately only for the freshness window). Untrusted
    /// input — any malformed field returns `false` (fail-closed).
    #[must_use]
    pub fn verify(
        &self,
        signature: &str,
        timestamp: &str,
        body: &[u8],
        now_unix_secs: u64,
    ) -> bool {
        // 0. Bound the untrusted inputs BEFORE any allocation or HMAC work (invariant 11):
        //    an oversized body/timestamp from an unauthenticated caller is rejected outright,
        //    so it can never force an unbounded basestring allocation or HMAC computation.
        if body.len() > MAX_SLACK_BODY || timestamp.len() > MAX_SLACK_TIMESTAMP {
            return false;
        }
        // 1. Freshness: a captured-and-replayed (or forward-dated) request is rejected even
        //    with a valid signature.
        let Ok(ts) = timestamp.parse::<u64>() else {
            return false;
        };
        if now_unix_secs.abs_diff(ts) > SLACK_MAX_SKEW_SECS {
            return false;
        }
        // 2. Signature: HMAC over the RAW basestring `v0:{timestamp}:{body}` (timestamp used
        //    verbatim, matching how Slack signs it).
        let Some(hex) = signature.strip_prefix("v0=") else {
            return false;
        };
        let Some(provided) = hex32_decode(hex) else {
            return false;
        };
        let mut base = Vec::with_capacity(3 + timestamp.len() + 1 + body.len());
        base.extend_from_slice(b"v0:");
        base.extend_from_slice(timestamp.as_bytes());
        base.push(b':');
        base.extend_from_slice(body);
        let expected = hmac_sha256(&self.secret, &base);
        ct_eq(&provided, &expected)
    }
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

    // ----- E.3: Slack request signature + freshness gate -----

    /// Lowercase-hex encode (test-only — builds a signature the way Slack would).
    fn hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    const SIGNING_SECRET: &[u8] = b"8f742231b10e8888abcd99yyyzzz85a5";

    fn valid_sig(ts: &str, body: &[u8]) -> String {
        let mut base = Vec::new();
        base.extend_from_slice(b"v0:");
        base.extend_from_slice(ts.as_bytes());
        base.push(b':');
        base.extend_from_slice(body);
        format!("v0={}", hex(&hmac_sha256(SIGNING_SECRET, &base)))
    }

    #[test]
    fn a_genuine_slack_signature_with_a_fresh_timestamp_verifies() {
        let v = SlackSignature::new(SIGNING_SECRET);
        let body = br#"{"type":"event_callback"}"#;
        let ts = "1700000000";
        // now within the skew window.
        assert!(v.verify(&valid_sig(ts, body), ts, body, 1700000010));
    }

    #[test]
    fn a_forged_signature_is_rejected() {
        let v = SlackSignature::new(SIGNING_SECRET);
        let body = br#"{"type":"event_callback"}"#;
        let ts = "1700000000";
        // Signed with the WRONG secret → no match.
        let mut base = Vec::new();
        base.extend_from_slice(b"v0:");
        base.extend_from_slice(ts.as_bytes());
        base.push(b':');
        base.extend_from_slice(body);
        let forged = format!("v0={}", hex(&hmac_sha256(b"not-the-secret", &base)));
        assert!(!v.verify(&forged, ts, body, 1700000010));
    }

    #[test]
    fn a_stale_or_forward_dated_request_is_rejected_even_if_signed() {
        let v = SlackSignature::new(SIGNING_SECRET);
        let body = br#"{"type":"event_callback"}"#;
        let ts = "1700000000";
        let sig = valid_sig(ts, body); // a genuinely valid signature...
                                       // ...but the request is 10 minutes old (> SLACK_MAX_SKEW_SECS) → replay-rejected.
        assert!(!v.verify(&sig, ts, body, 1700000000 + 600));
        // ...and a forward-dated request is likewise rejected.
        assert!(!v.verify(&sig, ts, body, 1700000000 - 600));
    }

    #[test]
    fn malformed_signature_or_timestamp_fails_closed() {
        let v = SlackSignature::new(SIGNING_SECRET);
        let body = b"{}";
        // Missing `v0=` prefix, bad hex length, non-numeric timestamp — all reject.
        assert!(!v.verify("deadbeef", "1700000000", body, 1700000000));
        assert!(!v.verify("v0=zz", "1700000000", body, 1700000000));
        assert!(!v.verify(
            &valid_sig("1700000000", body),
            "not-a-number",
            body,
            1700000000
        ));
    }

    #[test]
    fn an_oversized_body_or_timestamp_is_rejected_before_any_work() {
        let v = SlackSignature::new(SIGNING_SECRET);
        let ts = "1700000000";
        // A body past the bound is refused outright (invariant 11) — even though we never
        // even reach the signature step, fail-closed returns false.
        let huge = vec![b'x'; MAX_SLACK_BODY + 1];
        assert!(!v.verify(&valid_sig(ts, &huge), ts, &huge, 1700000005));
        // An over-long timestamp is likewise refused before allocation.
        let long_ts = "1".repeat(MAX_SLACK_TIMESTAMP + 1);
        assert!(!v.verify("v0=deadbeef", &long_ts, b"{}", 1700000005));
    }

    #[test]
    fn a_tampered_body_does_not_match_the_signature() {
        let v = SlackSignature::new(SIGNING_SECRET);
        let ts = "1700000000";
        let sig = valid_sig(ts, b"original body");
        // The signature was for a different body → reject (integrity, not just authenticity).
        assert!(!v.verify(&sig, ts, b"tampered body", 1700000005));
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
