// SPDX-License-Identifier: Apache-2.0
//! Telegram Bot API wire layer (P9-net): the live HTTP execution of the Telegram
//! runtime channel whose decision core already lives in `crustcore-daemon::telegram`
//! (allowlist, normalize, dedupe, typed commands, queue/steer routing, nonce-bound
//! approvals, the redacted `OutboundRenderer`). That module decides *whether* and
//! *what*; this executes the long-poll `getUpdates` and the `sendMessage` REST calls.
//!
//! Like the model + GitHub adapters, this client goes through the [`HttpClient`]
//! transport so its build/parse/error logic is **fully CI-testable with a canned
//! `ReplayClient`** (no network); the real socket is the `live`-gated `UreqClient`.
//! It takes **primitive** inputs (`offset`, `chat_id`, the redacted reply text) and
//! returns a net-side [`TgUpdate`] the daemon maps onto its own `RawUpdate`, so this
//! sidecar stays dependency-light and the daemon's trust-critical normalization is
//! reused unchanged.
//!
//! **Token handling (invariants 1–3).** The bot token goes in the URL *path*
//! (`https://api.telegram.org/bot<token>/getUpdates`), so it is resolved per call via
//! the [`CredentialSource`]/broker, spliced into the URL, and dropped — never stored
//! on the struct, never logged, and **never in an error body**: every failure is
//! mapped to a status-only / typed [`TgError`], exactly like the providers'
//! `map_status_error`. A non-2xx never fabricates an update or a successful send.
//!
//! Trust posture: a Telegram response is **untrusted data** (invariant 7) — only the
//! few fields the daemon needs are extracted (`update_id`, `message`/`chat`/`text`,
//! `callback_query`); nothing in a response is ever interpreted as a command. The
//! response is bounded (the transport caps bytes; the batch `limit` caps count).

use std::rc::Rc;

use crate::credsource::CredentialSource;
use crate::transport::HttpClient;

/// Default Telegram Bot API base URL.
pub const TELEGRAM_API: &str = "https://api.telegram.org";

/// The `getUpdates` long-poll timeout, in seconds. Telegram holds the connection open
/// up to this long when there are no updates (server-side long-poll). Bounded so a
/// poll cannot hang indefinitely; the `UreqClient`'s own request timeout is a wider
/// outer bound.
pub const LONG_POLL_SECS: u32 = 50;

/// The max number of updates a single `getUpdates` returns (Telegram's `limit`; max
/// 100). Bounds the batch so one poll can never return an unbounded `Vec`
/// (invariant 11) — mirrors the contract on `crustcore_daemon::telegram::TelegramApi`.
pub const UPDATE_BATCH_LIMIT: u32 = 100;

/// One update decoded from a `getUpdates` response — the net-side shape the daemon
/// maps onto its own `RawUpdate`. Everything here is **untrusted** until the daemon's
/// allowlist check; the claimed `from_username` is never used for identity.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TgUpdate {
    /// Telegram's monotonic update id (used for dedupe + offset advance).
    pub update_id: i64,
    /// The chat the update came from (the trusted identity after allowlisting).
    pub chat_id: i64,
    /// The message id (0 for a callback query without a message).
    pub message_id: i64,
    /// The sender's user id (informational).
    pub from_user_id: i64,
    /// The sender's claimed username — **untrusted**, never used for identity.
    pub from_username: Option<String>,
    /// Message text, if this update is a message.
    pub text: Option<String>,
    /// Inline-button callback payload, if this update is a callback query.
    pub callback_data: Option<String>,
}

/// Why a Telegram Bot API call failed. A non-2xx (or `ok: false`) maps here — it never
/// becomes a fake update or a fake send. The token is **never** carried in any variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TgError {
    /// 401 — the bot token is invalid/unauthorized (the daemon re-resolves it).
    Unauthorized,
    /// 429 — rate limited / flood wait.
    RateLimited,
    /// 5xx — Telegram server error.
    ServerError(u16),
    /// The API returned `ok: false` (a logical error) — carries Telegram's bounded
    /// `description`, which is Telegram-authored and never echoes the request URL/token.
    Api(String),
    /// A transport-level failure (connect/timeout/io).
    Transport(String),
    /// A 2xx whose body could not be parsed for the expected fields.
    BadResponse(String),
}

impl core::fmt::Display for TgError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TgError::Unauthorized => write!(f, "unauthorized"),
            TgError::RateLimited => write!(f, "rate limited"),
            TgError::ServerError(s) => write!(f, "server error {s}"),
            TgError::Api(m) => write!(f, "api error: {m}"),
            TgError::Transport(e) => write!(f, "transport: {e}"),
            TgError::BadResponse(m) => write!(f, "bad response: {m}"),
        }
    }
}

/// The Telegram Bot API operations the daemon's runtime loop needs. A [`RestTelegram`]
/// implements it over HTTP; a mock implements it for the daemon's tests.
pub trait TelegramBotApi {
    /// Long-poll for updates with `update_id >= offset` (Telegram advances the offset
    /// past acknowledged updates). The batch is bounded by [`UPDATE_BATCH_LIMIT`] and
    /// the wait by [`LONG_POLL_SECS`].
    ///
    /// # Errors
    /// [`TgError`] on any non-success, `ok: false`, or unparseable response.
    fn get_updates(&self, offset: i64) -> Result<Vec<TgUpdate>, TgError>;

    /// Sends `text` (already redacted/rendered upstream) to `chat_id`; returns the new
    /// message id.
    ///
    /// # Errors
    /// [`TgError`] on any non-success, `ok: false`, or unparseable response.
    fn send_message(&self, chat_id: i64, text: &str) -> Result<i64, TgError>;
}

/// The live Telegram Bot API client over an [`HttpClient`] transport + a credential
/// source. The bot token is resolved per call from `secret_label` and spliced into the
/// URL path — never held on the struct.
pub struct RestTelegram {
    base_url: String,
    secret_label: String,
    http: Rc<dyn HttpClient>,
    creds: Rc<dyn CredentialSource>,
}

impl RestTelegram {
    /// A client against `base_url` (normally [`TELEGRAM_API`]) whose bot token is the
    /// secret stored under `secret_label`.
    #[must_use]
    pub fn new(
        base_url: impl Into<String>,
        secret_label: impl Into<String>,
        http: Rc<dyn HttpClient>,
        creds: Rc<dyn CredentialSource>,
    ) -> Self {
        RestTelegram {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            secret_label: secret_label.into(),
            http,
            creds,
        }
    }

    /// Builds `https://api.telegram.org/bot<token>/<method>` for `method`, resolving
    /// the token per call. Returns `None` if no token is configured for the label —
    /// the call then fails closed (no token, no request) rather than hitting the API
    /// unauthenticated. The returned `String` is **secret-bearing** (it contains the
    /// token): it is built here, consumed by the transport call, and dropped — never
    /// logged and never placed into an error.
    fn method_url(&self, method: &str) -> Option<String> {
        let token = self.creds.bot_token(&self.secret_label)?;
        Some(format!("{}/bot{}/{method}", self.base_url, token))
    }

    /// JSON headers (no auth header — the token rides in the URL path for Telegram).
    fn headers() -> Vec<(String, String)> {
        vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ]
    }
}

/// Builds the `getUpdates` request body (testable independently of the transport):
/// the `offset`, a bounded `limit`, the long-poll `timeout`, and an `allowed_updates`
/// filter restricting deliveries to the two kinds the daemon handles.
#[must_use]
pub fn get_updates_body(offset: i64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "offset": offset,
        "limit": UPDATE_BATCH_LIMIT,
        "timeout": LONG_POLL_SECS,
        "allowed_updates": ["message", "callback_query"],
    }))
    .unwrap_or_default()
}

/// Builds the `sendMessage` request body (testable independently of the transport).
#[must_use]
pub fn send_message_body(chat_id: i64, text: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "chat_id": chat_id,
        "text": text,
    }))
    .unwrap_or_default()
}

/// Maps a non-2xx HTTP status to a typed [`TgError`]. Status-only: the provider body
/// is **never** embedded verbatim (it could, in a misconfigured proxy, echo the URL
/// and thus the token), mirroring the providers' `map_status_error`.
fn map_status(status: u16) -> TgError {
    match status {
        401 => TgError::Unauthorized,
        429 => TgError::RateLimited,
        500..=599 => TgError::ServerError(status),
        _ => TgError::Api(format!("http {status}")),
    }
}

/// Parses a Bot API envelope `{ "ok": bool, "result"|"description": ... }` from a 2xx
/// body, returning the `result` value on `ok: true` or a typed [`TgError`] on
/// `ok: false`. The `description` is Telegram-authored text (it does not echo the
/// request), bounded by the transport's body cap.
fn parse_envelope(body: &str) -> Result<serde_json::Value, TgError> {
    let v: serde_json::Value =
        serde_json::from_str(body).map_err(|e| TgError::BadResponse(e.to_string()))?;
    if v["ok"].as_bool() != Some(true) {
        let desc = v["description"].as_str().unwrap_or("ok: false").to_string();
        return Err(TgError::Api(desc));
    }
    Ok(v["result"].clone())
}

/// Decodes one Telegram `Update` JSON object into a [`TgUpdate`]. Handles both a plain
/// `message` and a `callback_query` (whose nested `message` carries the chat). Unknown
/// update kinds yield a `TgUpdate` with only `update_id` set (the daemon's normalize
/// then drops it as empty) — never a panic (invariant 7: untrusted data).
fn decode_update(u: &serde_json::Value) -> TgUpdate {
    let update_id = u["update_id"].as_i64().unwrap_or(0);

    // A callback_query carries its own `from` + nested `message` (for the chat id).
    if let Some(cq) = u.get("callback_query").filter(|c| !c.is_null()) {
        let msg = &cq["message"];
        return TgUpdate {
            update_id,
            chat_id: msg["chat"]["id"].as_i64().unwrap_or(0),
            message_id: msg["message_id"].as_i64().unwrap_or(0),
            from_user_id: cq["from"]["id"].as_i64().unwrap_or(0),
            from_username: cq["from"]["username"].as_str().map(str::to_string),
            text: None,
            callback_data: cq["data"].as_str().map(str::to_string),
        };
    }

    // Otherwise a plain message (or edited_message — we read `message` only).
    let msg = &u["message"];
    TgUpdate {
        update_id,
        chat_id: msg["chat"]["id"].as_i64().unwrap_or(0),
        message_id: msg["message_id"].as_i64().unwrap_or(0),
        from_user_id: msg["from"]["id"].as_i64().unwrap_or(0),
        from_username: msg["from"]["username"].as_str().map(str::to_string),
        text: msg["text"].as_str().map(str::to_string),
        callback_data: None,
    }
}

impl TelegramBotApi for RestTelegram {
    fn get_updates(&self, offset: i64) -> Result<Vec<TgUpdate>, TgError> {
        let url = self.method_url("getUpdates").ok_or(TgError::Unauthorized)?;
        let body = get_updates_body(offset);
        let resp = self
            .http
            .post_json(&url, &Self::headers(), &body)
            .map_err(|e| TgError::Transport(e.to_string()))?;
        if !resp.is_success() {
            return Err(map_status(resp.status));
        }
        let result = parse_envelope(&resp.body)?;
        let arr = result
            .as_array()
            .ok_or_else(|| TgError::BadResponse("result is not an array".into()))?;
        // Bound the decoded batch defensively even though `limit` already caps it.
        Ok(arr
            .iter()
            .take(UPDATE_BATCH_LIMIT as usize)
            .map(decode_update)
            .collect())
    }

    fn send_message(&self, chat_id: i64, text: &str) -> Result<i64, TgError> {
        let url = self
            .method_url("sendMessage")
            .ok_or(TgError::Unauthorized)?;
        let body = send_message_body(chat_id, text);
        let resp = self
            .http
            .post_json(&url, &Self::headers(), &body)
            .map_err(|e| TgError::Transport(e.to_string()))?;
        if !resp.is_success() {
            return Err(map_status(resp.status));
        }
        let result = parse_envelope(&resp.body)?;
        result["message_id"]
            .as_i64()
            .ok_or_else(|| TgError::BadResponse("missing message_id".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credsource::StaticCredentials;
    use crate::transport::{Canned, ReplayClient};

    fn client(responses: Vec<Canned>) -> RestTelegram {
        RestTelegram::new(
            TELEGRAM_API,
            "tg",
            Rc::new(ReplayClient::new(responses)),
            Rc::new(StaticCredentials::new().with("tg", "123456:SECRET-BOT-TOKEN")),
        )
    }

    #[test]
    fn get_updates_body_carries_offset_limit_timeout_and_filter() {
        let body = get_updates_body(42);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["offset"], 42);
        assert_eq!(v["limit"], UPDATE_BATCH_LIMIT);
        assert_eq!(v["timeout"], LONG_POLL_SECS);
        assert_eq!(v["allowed_updates"][0], "message");
        assert_eq!(v["allowed_updates"][1], "callback_query");
    }

    #[test]
    fn send_message_body_carries_chat_and_text() {
        let body = send_message_body(100, "verify PASSED");
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["chat_id"], 100);
        assert_eq!(v["text"], "verify PASSED");
    }

    #[test]
    fn get_updates_parses_message_and_callback() {
        // A canned getUpdates JSON with one text message and one callback query.
        let tg = client(vec![Canned::with_body(
            200,
            r#"{"ok":true,"result":[
                {"update_id":11,"message":{"message_id":5,"from":{"id":7,"username":"alice"},
                 "chat":{"id":100},"text":"fix the bug"}},
                {"update_id":12,"callback_query":{"id":"cb1","from":{"id":7,"username":"alice"},
                 "message":{"message_id":6,"chat":{"id":100}},"data":"ap:7:approve:00"}}
            ]}"#,
        )]);
        let updates = tg.get_updates(0).unwrap();
        assert_eq!(updates.len(), 2);

        // The text message decodes with chat/text and the (untrusted) username.
        assert_eq!(updates[0].update_id, 11);
        assert_eq!(updates[0].chat_id, 100);
        assert_eq!(updates[0].message_id, 5);
        assert_eq!(updates[0].text.as_deref(), Some("fix the bug"));
        assert_eq!(updates[0].from_username.as_deref(), Some("alice"));
        assert!(updates[0].callback_data.is_none());

        // The callback query decodes with the nested chat id + callback data.
        assert_eq!(updates[1].update_id, 12);
        assert_eq!(updates[1].chat_id, 100);
        assert_eq!(updates[1].callback_data.as_deref(), Some("ap:7:approve:00"));
        assert!(updates[1].text.is_none());
    }

    #[test]
    fn empty_result_is_an_empty_batch_not_an_error() {
        // A long-poll that times out with no updates returns `result: []`.
        let tg = client(vec![Canned::with_body(200, r#"{"ok":true,"result":[]}"#)]);
        assert!(tg.get_updates(7).unwrap().is_empty());
    }

    #[test]
    fn send_message_parses_message_id() {
        let tg = client(vec![Canned::with_body(
            200,
            r#"{"ok":true,"result":{"message_id":987,"chat":{"id":100}}}"#,
        )]);
        assert_eq!(tg.send_message(100, "hello").unwrap(), 987);
    }

    #[test]
    fn malformed_update_does_not_panic() {
        // Garbage / partial update objects decode to mostly-empty TgUpdates (the
        // daemon's normalize then drops them) — never a panic (untrusted data).
        let tg = client(vec![Canned::with_body(
            200,
            r#"{"ok":true,"result":[{"update_id":1},{"update_id":2,"message":{}},{}]}"#,
        )]);
        let updates = tg.get_updates(0).unwrap();
        assert_eq!(updates.len(), 3);
        assert_eq!(updates[0].update_id, 1);
        assert!(updates[0].text.is_none());
        assert_eq!(updates[2].update_id, 0); // missing update_id → 0, no panic
    }

    #[test]
    fn non_2xx_and_ok_false_never_fabricate_updates() {
        // 401 → Unauthorized (the token is bad), no fabricated update.
        assert_eq!(
            client(vec![Canned::with_body(401, "Unauthorized")])
                .get_updates(0)
                .unwrap_err(),
            TgError::Unauthorized
        );
        // 429 → RateLimited.
        assert_eq!(
            client(vec![Canned::with_body(429, "Too Many Requests")])
                .get_updates(0)
                .unwrap_err(),
            TgError::RateLimited
        );
        // 5xx → ServerError.
        assert_eq!(
            client(vec![Canned::with_body(503, "bad gateway")])
                .send_message(1, "x")
                .unwrap_err(),
            TgError::ServerError(503)
        );
        // A 2xx with `ok: false` → Api(description), not a fake success.
        match client(vec![Canned::with_body(
            200,
            r#"{"ok":false,"description":"chat not found"}"#,
        )])
        .send_message(1, "x")
        {
            Err(TgError::Api(m)) => assert!(m.contains("chat not found")),
            other => panic!("expected Api error, got {other:?}"),
        }
        // A 2xx with a junk body → BadResponse, NOT a fabricated update.
        assert!(matches!(
            client(vec![Canned::with_body(200, "not json")])
                .get_updates(0)
                .unwrap_err(),
            TgError::BadResponse(_)
        ));
    }

    #[test]
    fn missing_token_fails_closed_without_a_request() {
        // No credential configured for the label → no URL, no request: fail closed.
        let tg = RestTelegram::new(
            TELEGRAM_API,
            "absent",
            Rc::new(ReplayClient::new(vec![])), // would error "replay exhausted" if used
            Rc::new(StaticCredentials::new()),
        );
        assert_eq!(tg.get_updates(0).unwrap_err(), TgError::Unauthorized);
        assert_eq!(tg.send_message(1, "x").unwrap_err(), TgError::Unauthorized);
    }

    #[test]
    fn token_never_appears_in_an_error() {
        // Even an `ok: false` description that (hypothetically) echoed the token must
        // not surface it — but more importantly, our status-mapped errors are
        // status-only, so the token (which lives only in the URL path) never reaches
        // any TgError. A 401 maps to a bare Unauthorized.
        let err = client(vec![Canned::with_body(
            401,
            r#"{"ok":false,"description":"bot123456:SECRET-BOT-TOKEN is invalid"}"#,
        )])
        .get_updates(0)
        .unwrap_err();
        assert!(!format!("{err}").contains("SECRET-BOT-TOKEN"));
        assert_eq!(err, TgError::Unauthorized);
    }

    // The real HTTPS round-trip against api.telegram.org is `#[ignore]`d — it needs a
    // real bot token + network and never runs in CI (only the build/parse logic above
    // is CI-tested, with the ReplayClient).
    #[test]
    #[ignore = "live: requires a real Telegram bot token + network (TODO P9-net-live)"]
    #[cfg(feature = "live")]
    fn live_get_updates_smoke() {
        // To run: set the bot token under label "tg" and `cargo test --features live -- --ignored`.
        let token = std::env::var("CRUSTCORE_TG_BOT_TOKEN").expect("set CRUSTCORE_TG_BOT_TOKEN");
        let tg = RestTelegram::new(
            TELEGRAM_API,
            "tg",
            Rc::new(crate::transport::UreqClient::new()),
            Rc::new(StaticCredentials::new().with("tg", &token)),
        );
        // A single short long-poll; we only assert it round-trips without error.
        let _ = tg.get_updates(0).expect("getUpdates round-trip");
    }
}
