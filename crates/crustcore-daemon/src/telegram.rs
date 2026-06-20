// SPDX-License-Identifier: Apache-2.0
//! The Telegram runtime channel (`ROADMAP.md` §3.1, §18 Phase 9; `docs/telegram.md`).
//!
//! CrustCore's single default runtime human channel (invariants 5, 15, 16). This
//! module is the **sidecar** logic — allowlist binding, inbound normalization +
//! dedupe, the typed command set, queue/steer routing, nonce-bound expiring
//! approvals, and typed (redacted) outbound rendering. It is std-only and **not in
//! nano** (invariants 19, 20): a nano-only build has no runtime chat channel.
//!
//! The kernel never sees raw Telegram JSON — only normalized
//! `UserMessageQueued` / `UserSteerReceived` / `ApprovalResolved` events
//! (`docs/telegram.md` §1). The **runtime loop** ([`TelegramPoller`], P9-net) drives
//! the long-poll → dedupe → normalize → route pipeline over a [`TelegramApi`] and
//! sends only rendered, redacted [`ModelVisibleText`] back — fully testable with a
//! mock, no network. The live Bot API HTTP (getUpdates/sendMessage over the spawned
//! `crustcore-net` helper, the bot token in the URL path via the credential proxy)
//! is `TODO(P9-net-live)`; this module works on already-decoded [`RawUpdate`]s so the
//! trust-critical logic is deterministic and fully tested.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crustcore_policy::{Approved, AuthorizedUser};
use crustcore_secrets::{ModelVisibleText, Redactor};
use crustcore_types::hash::sha256;
use crustcore_types::status::ApprovalResolution;
use crustcore_types::{ApprovalId, BoundedText, Timestamp};

/// Cap on normalized inbound text (bounded everything; invariant 11).
pub const MAX_INBOUND_TEXT: usize = 8 * 1024;

/// How many recent `update_id`s the deduper retains (bounded). Anything older than
/// the largest value evicted from this window is assumed already processed.
pub const DEDUPE_WINDOW: usize = 4096;

// ---------------------------------------------------------------------------
// Chat-ID allowlist (the NullClaw lesson: empty = deny-all)
// ---------------------------------------------------------------------------

/// A Telegram chat id (the trusted identity, unlike a display name/username which
/// are untrusted mutable strings; `docs/telegram.md` §4–§5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChatId(pub i64);

/// The set of chats permitted to control the runtime. **An empty allowlist denies
/// all** — a freshly configured bot with no bound chat is inert (the single most
/// important fail-safe default; a leaked bot token is useless without a bound
/// chat). Binding happens through the trusted setup/admin path, never via a
/// message from an unknown chat (`docs/telegram.md` §4, invariant 16).
#[derive(Debug, Clone, Default)]
pub struct ChatAllowlist {
    ids: BTreeSet<i64>,
    wildcard: bool,
}

impl ChatAllowlist {
    /// The fail-safe default: an empty allowlist that denies every chat.
    #[must_use]
    pub fn deny_all() -> Self {
        ChatAllowlist {
            ids: BTreeSet::new(),
            wildcard: false,
        }
    }

    /// Binds an explicit set of allowed chat ids (the normal setup path).
    #[must_use]
    pub fn of(ids: &[i64]) -> Self {
        ChatAllowlist {
            ids: ids.iter().copied().collect(),
            wildcard: false,
        }
    }

    /// Explicit `*` opt-in — allow any chat. **Never a default**; only a deliberate
    /// operator choice (`docs/telegram.md` §4).
    #[must_use]
    pub fn wildcard() -> Self {
        ChatAllowlist {
            ids: BTreeSet::new(),
            wildcard: true,
        }
    }

    /// Whether `chat` may issue runtime commands. Empty + non-wildcard → `false`.
    #[must_use]
    pub fn allows(&self, chat: ChatId) -> bool {
        self.wildcard || self.ids.contains(&chat.0)
    }

    /// The authorized identity for an allowlisted chat (used to mint approvals).
    /// Returns `None` for a non-allowlisted chat — so a non-bound chat can never
    /// become an [`AuthorizedUser`] (invariant 4).
    #[must_use]
    pub fn authorized_user(&self, chat: ChatId) -> Option<AuthorizedUser> {
        if self.allows(chat) {
            // Chat ids are i64; map to the u64 identity space.
            Some(AuthorizedUser(chat.0 as u64))
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Raw update (already decoded from the Bot API JSON by the net layer)
// ---------------------------------------------------------------------------

/// A Telegram update after JSON decoding (the JSON parse itself is the
/// `TODO(P9-net)` Bot API layer). Everything here is **untrusted** until the
/// allowlist check; `from_username` is never used for identity.
#[derive(Debug, Clone, Default)]
pub struct RawUpdate {
    /// Telegram's monotonic update id (used for dedupe).
    pub update_id: i64,
    /// The chat the update came from (the trusted identity after allowlisting).
    pub chat_id: i64,
    /// The message id.
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

// ---------------------------------------------------------------------------
// The typed command set
// ---------------------------------------------------------------------------

/// A runtime command (`docs/telegram.md` §2). Commands are **typed verbs** parsed
/// by the daemon — never free text passed to a model. An unrecognized or malformed
/// command becomes [`Command::Unknown`], which yields a typed error reply (it never
/// falls through to a model as a prompt).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `/status` — snapshot of active tasks, budgets, channel health.
    Status,
    /// `/tasks` — list tasks with status.
    Tasks,
    /// `/task <id>` — detail on one task.
    Task(u128),
    /// `/approve <approval_id>` — resolve a pending approval (mints `Approved<T>`).
    Approve(u128),
    /// `/deny <approval_id>` — resolve a pending approval as denied.
    Deny(u128),
    /// `/pause <task_id>`.
    Pause(u128),
    /// `/resume <task_id>`.
    Resume(u128),
    /// `/cancel <task_id>` — graceful cancellation at the next safe boundary.
    Cancel(u128),
    /// `/kill <task_id>` — immediate hard teardown.
    Kill(u128),
    /// `/diff <task_id>` — render the bounded candidate diff.
    Diff(u128),
    /// `/logs <task_id>` — tail bounded, redacted logs.
    Logs(u128),
    /// `/budget` — budget consumption vs limits.
    Budget,
    /// `/policy` — effective policy/risk profile.
    Policy,
    /// `/repo` — bound repo/ref + GitHub posture.
    Repo,
    /// `/help` — list commands.
    Help,
    /// An unrecognized or malformed command (carries the raw text for the reply).
    Unknown(String),
}

impl Command {
    /// Parses a `/command [arg]` line. Whitespace-split, no shell/model
    /// interpretation. Unrecognized verbs or bad/missing numeric args become
    /// [`Command::Unknown`].
    #[must_use]
    pub fn parse(text: &str) -> Command {
        let mut toks = text.split_whitespace();
        let Some(verb) = toks.next() else {
            return Command::Unknown(text.to_string());
        };
        let arg = toks.next();
        let id = || arg.and_then(|a| a.parse::<u128>().ok());
        match verb {
            "/status" => Command::Status,
            "/tasks" => Command::Tasks,
            "/budget" => Command::Budget,
            "/policy" => Command::Policy,
            "/repo" => Command::Repo,
            "/help" => Command::Help,
            "/task" => id().map_or_else(|| Command::Unknown(text.to_string()), Command::Task),
            "/approve" => id().map_or_else(|| Command::Unknown(text.to_string()), Command::Approve),
            "/deny" => id().map_or_else(|| Command::Unknown(text.to_string()), Command::Deny),
            "/pause" => id().map_or_else(|| Command::Unknown(text.to_string()), Command::Pause),
            "/resume" => id().map_or_else(|| Command::Unknown(text.to_string()), Command::Resume),
            "/cancel" => id().map_or_else(|| Command::Unknown(text.to_string()), Command::Cancel),
            "/kill" => id().map_or_else(|| Command::Unknown(text.to_string()), Command::Kill),
            "/diff" => id().map_or_else(|| Command::Unknown(text.to_string()), Command::Diff),
            "/logs" => id().map_or_else(|| Command::Unknown(text.to_string()), Command::Logs),
            _ => Command::Unknown(text.to_string()),
        }
    }
}

// ---------------------------------------------------------------------------
// Inbound envelope + normalization
// ---------------------------------------------------------------------------

/// An approve/deny decision carried by an inline button.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallbackData {
    /// The approval this button resolves.
    pub approval_id: u128,
    /// The decision.
    pub decision: ApprovalResolution,
    /// The operation hash the nonce is bound to (so a tampered/replayed callback
    /// cannot authorize a different operation; `docs/telegram.md` §6).
    pub op_hash: [u8; 32],
}

impl CallbackData {
    /// Parses inline-button `callback_data` of the form
    /// `ap:<approval_id>:<approve|deny>:<op_hash_hex>`. Returns `None` if malformed.
    #[must_use]
    pub fn parse(data: &str) -> Option<CallbackData> {
        let mut parts = data.split(':');
        if parts.next()? != "ap" {
            return None;
        }
        let approval_id = parts.next()?.parse::<u128>().ok()?;
        let decision = match parts.next()? {
            "approve" => ApprovalResolution::Approve,
            "deny" => ApprovalResolution::Deny,
            _ => return None,
        };
        let hex = parts.next()?;
        if parts.next().is_some() {
            return None;
        }
        Some(CallbackData {
            approval_id,
            decision,
            op_hash: parse_hash_hex(hex)?,
        })
    }
}

/// What an [`InboundEnvelope`] carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeKind {
    /// A typed command.
    Command(Command),
    /// Plain text (queued, or steered if `steer_flag`).
    Text,
    /// An inline-button approval callback.
    Callback(CallbackData),
}

/// A normalized, allowlist-checked, deduped inbound message (`docs/telegram.md`
/// §5). The kernel is fed events derived from this — never a raw update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundEnvelope {
    /// The (allowlisted) source chat.
    pub source_chat_id: ChatId,
    /// Telegram's update id (already deduped).
    pub update_id: i64,
    /// The message id.
    pub message_id: i64,
    /// Host receive time (trusted), never a client-claimed timestamp.
    pub received_at: Timestamp,
    /// What the envelope carries.
    pub kind: EnvelopeKind,
    /// Trimmed, control-stripped, length-bounded text (the steer content for a
    /// steer; empty for a callback).
    pub normalized_text: BoundedText,
    /// True if this was a `!`-prefixed steer.
    pub steer_flag: bool,
}

/// Why a raw update was rejected at the daemon boundary (never normalized into a
/// kernel event).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectReason {
    /// The source chat is not allowlisted (spoof / unknown chat). The daemon loop
    /// counts these and (rate-limited) surfaces them as `RiskDetected`
    /// (`docs/telegram.md` §4); the per-chat counter/token-bucket lives with the
    /// polling loop wiring (`TODO(P9-net)`), not in this pure normalization step.
    NotAllowlisted,
    /// A replayed `update_id` (dedupe).
    Duplicate,
    /// The update carried no actionable content.
    Empty,
    /// A malformed inline-button callback payload.
    BadCallback,
}

/// Normalizes a raw update into an [`InboundEnvelope`], enforcing the allowlist and
/// producing a bounded, control-stripped text. Identity is the allowlisted
/// **chat id**, never the claimed username (`docs/telegram.md` §5). `now` is the
/// trusted host receive time. Dedupe is the caller's responsibility (see
/// [`Deduper`]) so this stays a pure function.
///
/// # Errors
/// [`RejectReason`] when the chat is not allowlisted or the update is empty/
/// malformed.
pub fn normalize(
    raw: &RawUpdate,
    allowlist: &ChatAllowlist,
    now: Timestamp,
) -> Result<InboundEnvelope, RejectReason> {
    let chat = ChatId(raw.chat_id);
    // Allowlist FIRST: everything before this check is untrusted.
    if !allowlist.allows(chat) {
        return Err(RejectReason::NotAllowlisted);
    }

    // Callback (inline approval button) path.
    if let Some(cb) = &raw.callback_data {
        let data = CallbackData::parse(cb).ok_or(RejectReason::BadCallback)?;
        return Ok(InboundEnvelope {
            source_chat_id: chat,
            update_id: raw.update_id,
            message_id: raw.message_id,
            received_at: now,
            kind: EnvelopeKind::Callback(data),
            normalized_text: BoundedText::truncated("", MAX_INBOUND_TEXT),
            steer_flag: false,
        });
    }

    // Message path.
    let text = raw.text.as_deref().unwrap_or("");
    let cleaned = clean_text(text);
    if cleaned.is_empty() {
        return Err(RejectReason::Empty);
    }

    let (kind, steer_flag, content) = if let Some(rest) = cleaned.strip_prefix('!') {
        // Steer: strip the `!`, keep the redirection content.
        (EnvelopeKind::Text, true, rest.trim().to_string())
    } else if cleaned.starts_with('/') {
        (
            EnvelopeKind::Command(Command::parse(&cleaned)),
            false,
            cleaned,
        )
    } else {
        (EnvelopeKind::Text, false, cleaned)
    };

    Ok(InboundEnvelope {
        source_chat_id: chat,
        update_id: raw.update_id,
        message_id: raw.message_id,
        received_at: now,
        kind,
        normalized_text: BoundedText::truncated(content, MAX_INBOUND_TEXT),
        steer_flag,
    })
}

/// Normalizes inbound text: whitespace control chars (newline/tab/…) become a
/// single space so tokens are not silently joined across line breaks, other
/// control chars are stripped, runs of whitespace are collapsed, and the result is
/// trimmed.
fn clean_text(text: &str) -> String {
    let spaced: String = text
        .chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .filter(|c| !c.is_control())
        .collect();
    spaced.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn parse_hash_hex(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Dedupe
// ---------------------------------------------------------------------------

/// Deduplicates updates by `update_id`. Telegram long-polling can redeliver on
/// retry; a replay must not double-apply an `/approve` or double-queue a steer
/// (Phase 9 acceptance, P9.7; `docs/telegram.md` §5).
///
/// `seen` is the authoritative set of the most-recent [`DEDUPE_WINDOW`] accepted
/// ids (bounded). When an id is evicted from `seen`, the **floor** is raised to the
/// largest *value* ever evicted: any later id at or below the floor that is not in
/// `seen` is assumed already processed. The floor is value-based (not the
/// oldest-*inserted* id), so a replay that arrived out of order and was then evicted
/// is still dropped — the earlier arrival-order floor mis-handled that case.
#[derive(Debug)]
pub struct Deduper {
    /// Largest `update_id` value ever evicted from `seen` (the assume-processed
    /// floor). `i64::MIN` until the window first overflows.
    floor: i64,
    window: VecDeque<i64>,
    seen: BTreeSet<i64>,
}

impl Default for Deduper {
    fn default() -> Self {
        Deduper {
            floor: i64::MIN,
            window: VecDeque::new(),
            seen: BTreeSet::new(),
        }
    }
}

impl Deduper {
    /// A fresh deduper.
    #[must_use]
    pub fn new() -> Self {
        Deduper::default()
    }

    /// Records `update_id` and returns `true` if it is new (should be processed),
    /// `false` if it is a duplicate (drop it).
    pub fn accept(&mut self, update_id: i64) -> bool {
        // In the window → definitely a duplicate.
        if self.seen.contains(&update_id) {
            return false;
        }
        // At/below the largest evicted value and not retained → already processed.
        if update_id <= self.floor {
            return false;
        }
        // New: record it, and evict the oldest-by-arrival id if over capacity,
        // raising the floor to the largest evicted value.
        self.window.push_back(update_id);
        self.seen.insert(update_id);
        while self.window.len() > DEDUPE_WINDOW {
            if let Some(evicted) = self.window.pop_front() {
                self.seen.remove(&evicted);
                self.floor = self.floor.max(evicted);
            }
        }
        true
    }
}

// ---------------------------------------------------------------------------
// Queue / steer routing
// ---------------------------------------------------------------------------

/// The kernel-facing intent derived from an envelope (`docs/telegram.md` §3).
/// Maps to `crustcore_kernel::EventKind`: queued turn → `UserMessageQueued`, steer
/// → `UserSteerReceived`, approval callback → `ApprovalResolved`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeEvent {
    /// A plain message: queue for the next safe boundary (FIFO, bounded).
    QueuedTurn(BoundedText),
    /// A `!`-prefixed steer: inject before pending actions execute. Advisory to the
    /// agent's reasoning; it grants no capabilities (§3.2).
    Steer(BoundedText),
    /// A typed command verb for the daemon to dispatch.
    Command(Command),
    /// An approval callback to resolve (the daemon runs it through the approval
    /// engine before it becomes an `ApprovalResolved` event).
    ApprovalCallback(CallbackData),
}

/// Routes a normalized envelope to its [`RuntimeEvent`]. Queue is the default; a
/// steer is only the `!` path; commands and callbacks are typed.
#[must_use]
pub fn route(envelope: InboundEnvelope) -> RuntimeEvent {
    match envelope.kind {
        EnvelopeKind::Command(cmd) => RuntimeEvent::Command(cmd),
        EnvelopeKind::Callback(cb) => RuntimeEvent::ApprovalCallback(cb),
        EnvelopeKind::Text => {
            if envelope.steer_flag {
                RuntimeEvent::Steer(envelope.normalized_text)
            } else {
                RuntimeEvent::QueuedTurn(envelope.normalized_text)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Nonce-bound, operation-bound, expiring approvals
// ---------------------------------------------------------------------------

/// A nonce the daemon emits with an approval request: it binds the approval id to
/// a hash of the *specific* operation and an expiry (`docs/telegram.md` §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApprovalNonce {
    /// The approval id.
    pub approval_id: u128,
    /// Hash of the exact operation this nonce authorizes.
    pub op_hash: [u8; 32],
    /// When the approval expires.
    pub expires_at: Timestamp,
}

impl ApprovalNonce {
    /// The `callback_data` an approve/deny inline button should carry.
    #[must_use]
    pub fn callback_data(&self, decision: ApprovalResolution) -> String {
        let verb = match decision {
            ApprovalResolution::Approve => "approve",
            ApprovalResolution::Deny => "deny",
        };
        format!("ap:{}:{verb}:{}", self.approval_id, hash_hex(&self.op_hash))
    }
}

/// The operation an [`Approved`] token authorizes (the `T` in `Approved<T>`).
/// Operation-bound: approving op A can never authorize op B (`docs/telegram.md`
/// §6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedOperation {
    /// The approval id.
    pub approval_id: u128,
    /// The exact operation hash this token is bound to.
    pub op_hash: [u8; 32],
    /// A short human description (for audit).
    pub summary: BoundedText,
}

/// The result of resolving an approval.
#[derive(Debug)]
pub enum ApprovalOutcome {
    /// Approved by an authorized user — carries the operation-bound, expiring token.
    Approved(Approved<ApprovedOperation>),
    /// Denied (the gated action is blocked).
    Denied { approval_id: u128 },
    /// The resolving chat is not allowlisted — dropped (§6).
    RejectedNotAllowlisted,
    /// No pending approval with that id — a stray id is surfaced as `RiskDetected`,
    /// not silently ignored (`docs/telegram.md` §2).
    RejectedUnknownNonce,
    /// The approval expired before resolution (§6).
    RejectedExpired,
    /// A callback's op hash did not match the pending operation (tampered/replayed
    /// against a different operation).
    RejectedOpMismatch,
}

struct Pending {
    op_hash: [u8; 32],
    summary: BoundedText,
    expires_at: Timestamp,
}

/// Tracks pending approvals and resolves them with nonce + operation + expiry +
/// single-use enforcement. The only path to an [`Approved`] token is an
/// allowlisted chat (→ [`AuthorizedUser`]) resolving the *matching* nonce — there
/// is no path from model output (invariant 4).
#[derive(Default)]
pub struct ApprovalEngine {
    pending: BTreeMap<u128, Pending>,
}

impl ApprovalEngine {
    /// A fresh engine.
    #[must_use]
    pub fn new() -> Self {
        ApprovalEngine {
            pending: BTreeMap::new(),
        }
    }

    /// Registers a pending approval for `operation` (bound by its hash) and returns
    /// the nonce to attach to the Telegram approval buttons.
    pub fn request(
        &mut self,
        approval_id: u128,
        operation: &str,
        summary: &str,
        expires_at: Timestamp,
    ) -> ApprovalNonce {
        let op_hash = sha256(operation.as_bytes());
        self.pending.insert(
            approval_id,
            Pending {
                op_hash,
                summary: BoundedText::truncated(summary, BoundedText::DEFAULT_MAX),
                expires_at,
            },
        );
        ApprovalNonce {
            approval_id,
            op_hash,
            expires_at,
        }
    }

    /// Whether an approval id is still pending (for diagnostics/tests).
    #[must_use]
    pub fn is_pending(&self, approval_id: u128) -> bool {
        self.pending.contains_key(&approval_id)
    }

    /// Resolves an approval. Enforces: allowlisted chat, a matching pending nonce
    /// (a stray id → `RejectedUnknownNonce`), not expired, optional op-hash match
    /// (the callback path), and **single-use** (the pending is consumed). On an
    /// approve from an authorized user, mints an operation-bound, expiring
    /// `Approved<ApprovedOperation>` via [`AuthorizedUser::approve`].
    #[must_use]
    pub fn resolve(
        &mut self,
        approval_id: u128,
        decision: ApprovalResolution,
        chat: ChatId,
        allowlist: &ChatAllowlist,
        now: Timestamp,
        callback_op_hash: Option<[u8; 32]>,
    ) -> ApprovalOutcome {
        let Some(user) = allowlist.authorized_user(chat) else {
            return ApprovalOutcome::RejectedNotAllowlisted;
        };
        let Some(pending) = self.pending.get(&approval_id) else {
            return ApprovalOutcome::RejectedUnknownNonce;
        };
        if now.as_millis() > pending.expires_at.as_millis() {
            self.pending.remove(&approval_id);
            return ApprovalOutcome::RejectedExpired;
        }
        if let Some(h) = callback_op_hash {
            if h != pending.op_hash {
                // Do NOT consume: a mismatched op hash is a tamper/replay signal.
                return ApprovalOutcome::RejectedOpMismatch;
            }
        }
        // Single-use: consume the pending now.
        let pending = self.pending.remove(&approval_id).expect("checked present");
        match decision {
            ApprovalResolution::Deny => ApprovalOutcome::Denied { approval_id },
            ApprovalResolution::Approve => {
                let op = ApprovedOperation {
                    approval_id,
                    op_hash: pending.op_hash,
                    summary: pending.summary,
                };
                // The only way to an Approved<T>: structurally requires the
                // AuthorizedUser (invariant 4). Carries the op binding + expiry.
                let token = user.approve(op, ApprovalId(approval_id), pending.expires_at);
                ApprovalOutcome::Approved(token)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Outbound rendering — the model does not speak Telegram directly
// ---------------------------------------------------------------------------

/// A typed status snapshot the daemon renders (never raw model text).
#[derive(Debug, Clone)]
pub struct StatusSnapshot {
    /// Number of active tasks.
    pub active_tasks: usize,
    /// Budget micros consumed.
    pub budget_used_micros: u64,
    /// Budget micros limit.
    pub budget_limit_micros: u64,
    /// Whether the runtime channel is healthy.
    pub channel_healthy: bool,
}

/// Builds outbound runtime messages from **typed, structured sources**, always
/// through the [`Redactor`] (`docs/telegram.md` §7–§8, invariants 2, 5, 15). There
/// is deliberately **no** `send(text: String)` taking arbitrary model text — the
/// model's intent is realized as a typed event that this renders, closing the
/// prompt-injection exfiltration path and keeping the redactor in the loop.
pub struct OutboundRenderer<'r> {
    redactor: &'r Redactor,
}

impl<'r> OutboundRenderer<'r> {
    /// A renderer over the broker's redactor (pre-loaded with all known secrets).
    #[must_use]
    pub fn new(redactor: &'r Redactor) -> Self {
        OutboundRenderer { redactor }
    }

    /// Renders a `/status` reply.
    #[must_use]
    pub fn status(&self, snap: &StatusSnapshot) -> ModelVisibleText {
        let text = format!(
            "status: {} active task(s); budget {}/{} micros; channel {}",
            snap.active_tasks,
            snap.budget_used_micros,
            snap.budget_limit_micros,
            if snap.channel_healthy {
                "ok"
            } else {
                "degraded"
            },
        );
        self.redactor.to_model_visible(&text)
    }

    /// Renders an approval request prompt (the buttons carry the nonce separately).
    #[must_use]
    pub fn approval_request(&self, summary: &str, nonce: &ApprovalNonce) -> ModelVisibleText {
        let text = format!(
            "approval needed (id {}): {summary}\n[approve] [deny]",
            nonce.approval_id
        );
        self.redactor.to_model_visible(&text)
    }

    /// Renders a verifier result (pass/fail + bounded evidence).
    #[must_use]
    pub fn verifier_result(&self, passed: bool, evidence: &str) -> ModelVisibleText {
        let text = format!(
            "verify {}: {evidence}",
            if passed { "PASSED" } else { "FAILED" }
        );
        self.redactor.to_model_visible(&text)
    }

    /// Renders a `/logs` tail — raw logs passed through the redactor. If a secret
    /// span cannot be proven clean, redaction replaces it; nothing raw is sent.
    #[must_use]
    pub fn logs(&self, raw_logs: &str) -> ModelVisibleText {
        self.redactor.to_model_visible(raw_logs)
    }
}

fn hash_hex(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

// ---------------------------------------------------------------------------
// The Bot API runtime loop (P9-net): long-poll → normalize/dedupe/route, and the
// redacted-only outbound send. The live HTTP transport (getUpdates/sendMessage over
// the spawned `crustcore-net` helper, authenticated by the credential proxy — the
// bot token goes in the URL path) is `TODO(P9-net-live)`; this loop drives the
// already-tested core over a `TelegramApi` so it is fully testable with no network.
// ---------------------------------------------------------------------------

/// A transport-level failure talking to the Bot API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TgError {
    /// A connect/timeout/io failure.
    Transport(String),
    /// The Bot API returned an error (`ok: false`) — never carrying the token.
    Api(String),
}

impl core::fmt::Display for TgError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TgError::Transport(e) => write!(f, "telegram transport: {e}"),
            TgError::Api(e) => write!(f, "telegram api: {e}"),
        }
    }
}

/// The Bot API operations the runtime loop needs. The live `crustcore-net`-backed
/// impl is `TODO(P9-net-live)`; a mock drives the loop deterministically in tests.
///
/// `send_message` takes a [`ModelVisibleText`] — which can be constructed **only**
/// through the [`Redactor`] — so by the type system the channel can emit nothing but
/// redacted, rendered output: the model cannot push arbitrary text to the user
/// (invariants 2, 5; `docs/telegram.md`).
pub trait TelegramApi {
    /// Long-poll for updates with `update_id >= offset` (Telegram's offset advances
    /// past acknowledged updates). The returned updates are **untrusted data**, and
    /// the live impl **must bound the batch** — Telegram's `getUpdates` takes a
    /// `limit` (default/max 100), which the live transport sets so a single poll can
    /// never return an unbounded `Vec` (invariant 11); the poller processes whatever
    /// it returns.
    ///
    /// # Errors
    /// [`TgError`] on a transport/API failure.
    fn get_updates(&self, offset: i64) -> Result<Vec<RawUpdate>, TgError>;

    /// Sends a **redacted, rendered** reply to a chat; returns the message id.
    ///
    /// # Errors
    /// [`TgError`] on a transport/API failure.
    fn send_message(&self, chat: ChatId, text: &ModelVisibleText) -> Result<i64, TgError>;
}

/// The inbound runtime loop: each poll fetches updates, advances the long-poll
/// offset past every fetched update (so Telegram does not re-deliver them), drops
/// duplicates ([`Deduper`]), enforces the allowlist + normalizes ([`normalize`]),
/// and routes survivors to [`RuntimeEvent`]s for the supervisor to dispatch. It holds
/// no outward channel itself — replies are sent explicitly via [`TelegramApi::send_message`]
/// with rendered [`ModelVisibleText`], so the model never gains a direct user channel
/// (invariant 5). Deterministic given the `TelegramApi`, so fully CI-testable.
pub struct TelegramPoller {
    offset: i64,
    deduper: Deduper,
    allowlist: ChatAllowlist,
    rejected: u32,
}

impl TelegramPoller {
    /// A poller over `allowlist`, starting at offset 0.
    #[must_use]
    pub fn new(allowlist: ChatAllowlist) -> Self {
        TelegramPoller {
            offset: 0,
            deduper: Deduper::new(),
            allowlist,
            rejected: 0,
        }
    }

    /// The next long-poll offset (one past the highest update seen).
    #[must_use]
    pub fn offset(&self) -> i64 {
        self.offset
    }

    /// How many updates have been rejected as not-allowlisted (a spoof/abuse signal
    /// the supervisor can rate-limit-surface as risk; `docs/telegram.md` §4).
    #[must_use]
    pub fn rejected_count(&self) -> u32 {
        self.rejected
    }

    /// Runs one poll cycle and returns the [`RuntimeEvent`]s for the supervisor to
    /// dispatch. Advances the offset past **every** fetched update (even rejected or
    /// duplicate ones) so they are acknowledged and never re-delivered.
    ///
    /// # Errors
    /// [`TgError`] if the fetch fails.
    pub fn poll_once(
        &mut self,
        api: &dyn TelegramApi,
        now: Timestamp,
    ) -> Result<Vec<RuntimeEvent>, TgError> {
        let updates = api.get_updates(self.offset)?;
        let mut events = Vec::new();
        for raw in &updates {
            // Acknowledge by advancing the offset past this update, regardless of
            // whether it survives dedupe/allowlisting.
            self.offset = self.offset.max(raw.update_id.saturating_add(1));
            if !self.deduper.accept(raw.update_id) {
                continue; // a replayed update_id
            }
            match normalize(raw, &self.allowlist, now) {
                Ok(envelope) => events.push(route(envelope)),
                Err(RejectReason::NotAllowlisted) => {
                    self.rejected = self.rejected.saturating_add(1);
                }
                // Empty / bad-callback updates are dropped (no kernel event).
                Err(_) => {}
            }
        }
        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(ms: u64) -> Timestamp {
        Timestamp::from_millis(ms)
    }

    fn msg(chat: i64, update_id: i64, text: &str) -> RawUpdate {
        RawUpdate {
            update_id,
            chat_id: chat,
            message_id: update_id,
            from_user_id: 1,
            from_username: Some("attacker".to_string()),
            text: Some(text.to_string()),
            callback_data: None,
        }
    }

    // --- allowlist: empty = deny-all; only bound chats control (P9.2, §4) ---

    #[test]
    fn empty_allowlist_denies_all() {
        let allow = ChatAllowlist::deny_all();
        assert!(!allow.allows(ChatId(123)));
        assert!(allow.authorized_user(ChatId(123)).is_none());
        let r = normalize(&msg(123, 1, "/status"), &allow, ts(1));
        assert_eq!(r.unwrap_err(), RejectReason::NotAllowlisted);
    }

    #[test]
    fn only_bound_chat_controls_runtime() {
        let allow = ChatAllowlist::of(&[42]);
        assert!(normalize(&msg(42, 1, "/status"), &allow, ts(1)).is_ok());
        assert_eq!(
            normalize(&msg(99, 2, "/status"), &allow, ts(1)).unwrap_err(),
            RejectReason::NotAllowlisted
        );
    }

    #[test]
    fn spoofed_username_does_not_grant_control() {
        // Identity is the chat id, not the (untrusted) claimed username.
        let allow = ChatAllowlist::of(&[42]);
        let mut spoof = msg(99, 1, "/kill 1");
        spoof.from_username = Some("admin".to_string()); // claims to be admin
        assert_eq!(
            normalize(&spoof, &allow, ts(1)).unwrap_err(),
            RejectReason::NotAllowlisted
        );
    }

    // --- normalization + commands (P9.3/P9.4, §5) ---

    #[test]
    fn commands_parse_to_typed_verbs() {
        assert_eq!(Command::parse("/status"), Command::Status);
        assert_eq!(Command::parse("/approve 7"), Command::Approve(7));
        assert_eq!(Command::parse("/kill 12"), Command::Kill(12));
        // Missing/bad arg → Unknown (typed error reply, never a model prompt).
        assert!(matches!(Command::parse("/approve"), Command::Unknown(_)));
        assert!(matches!(
            Command::parse("/approve abc"),
            Command::Unknown(_)
        ));
        assert!(matches!(Command::parse("/frobnicate"), Command::Unknown(_)));
    }

    #[test]
    fn normalize_strips_control_chars_and_bounds() {
        let allow = ChatAllowlist::of(&[1]);
        let env = normalize(&msg(1, 1, "  hello\u{0007}\nworld  "), &allow, ts(5)).unwrap();
        // Control char stripped; the newline becomes a space (tokens not joined).
        assert_eq!(env.normalized_text.as_str(), "hello world");
        assert_eq!(env.received_at, ts(5)); // trusted host time
        assert!(matches!(env.kind, EnvelopeKind::Text));
        assert!(!env.steer_flag);
    }

    // --- queue vs steer (P9.5, §3) ---

    #[test]
    fn plain_message_queues_bang_message_steers() {
        let allow = ChatAllowlist::of(&[1]);
        let queued =
            route(normalize(&msg(1, 1, "look at the auth module"), &allow, ts(1)).unwrap());
        assert!(matches!(queued, RuntimeEvent::QueuedTurn(_)));

        let steered =
            route(normalize(&msg(1, 2, "!focus on the failing test"), &allow, ts(1)).unwrap());
        match steered {
            RuntimeEvent::Steer(t) => assert_eq!(t.as_str(), "focus on the failing test"),
            other => panic!("expected Steer, got {other:?}"),
        }

        let cmd = route(normalize(&msg(1, 3, "/budget"), &allow, ts(1)).unwrap());
        assert_eq!(cmd, RuntimeEvent::Command(Command::Budget));
    }

    // --- dedupe (P9.7, §5) ---

    #[test]
    fn replayed_update_id_is_deduped() {
        let mut d = Deduper::new();
        assert!(d.accept(100));
        assert!(
            !d.accept(100),
            "replay of the same update_id must be dropped"
        );
        assert!(d.accept(101));
        assert!(!d.accept(101));
        // An out-of-order retry within the window is also caught.
        assert!(d.accept(105));
        assert!(!d.accept(105));
    }

    #[test]
    fn replay_of_an_evicted_out_of_order_id_is_still_dropped() {
        // Review dedupe-normalize-1: a high-valued id that arrived early, then was
        // evicted by a flood of later ids, must NOT be re-accepted on replay. (The
        // old arrival-order floor mis-handled this; the value floor fixes it.)
        let mut d = Deduper::new();
        assert!(d.accept(10));
        assert!(d.accept(500)); // out-of-order arrival, evicted by the flood below
                                // Flood with ids strictly above 500 so none collides with / re-accepts it;
                                // this pushes 500 out of the window and raises the floor past it.
        for id in 1000..=(1000 + DEDUPE_WINDOW as i64) {
            assert!(d.accept(id));
        }
        assert!(
            !d.accept(500),
            "a replayed, since-evicted out-of-order update_id must be dropped"
        );
        // A genuinely-new higher id is still accepted.
        assert!(d.accept(2_000_000));
    }

    // --- nonce approvals: operation-bound, expiring, single-use (P9.6, §6) ---

    fn engine_with_request(now: u64, ttl: u64) -> (ApprovalEngine, ApprovalNonce) {
        let mut eng = ApprovalEngine::new();
        let nonce = eng.request(
            7,
            "push branch claude/p10 to repoX",
            "push branch",
            ts(now + ttl),
        );
        (eng, nonce)
    }

    #[test]
    fn approving_one_operation_does_not_authorize_another() {
        let allow = ChatAllowlist::of(&[42]);
        let (mut eng, nonce) = engine_with_request(1000, 5000);
        // A callback bound to a DIFFERENT operation hash is rejected.
        let wrong_op = sha256(b"delete all branches");
        let out = eng.resolve(
            7,
            ApprovalResolution::Approve,
            ChatId(42),
            &allow,
            ts(1001),
            Some(wrong_op),
        );
        assert!(matches!(out, ApprovalOutcome::RejectedOpMismatch));
        // The correct op hash (from the nonce) approves.
        let out = eng.resolve(
            7,
            ApprovalResolution::Approve,
            ChatId(42),
            &allow,
            ts(1001),
            Some(nonce.op_hash),
        );
        match out {
            ApprovalOutcome::Approved(token) => {
                assert_eq!(token.value.op_hash, nonce.op_hash);
                assert!(token.is_valid_at(ts(1001)));
            }
            other => panic!("expected Approved, got {other:?}"),
        }
    }

    #[test]
    fn approval_is_single_use_and_expiring() {
        let allow = ChatAllowlist::of(&[42]);
        // Single-use: a second resolve finds no pending nonce.
        let (mut eng, _n) = engine_with_request(1000, 5000);
        assert!(matches!(
            eng.resolve(
                7,
                ApprovalResolution::Approve,
                ChatId(42),
                &allow,
                ts(1001),
                None
            ),
            ApprovalOutcome::Approved(_)
        ));
        assert!(matches!(
            eng.resolve(
                7,
                ApprovalResolution::Approve,
                ChatId(42),
                &allow,
                ts(1002),
                None
            ),
            ApprovalOutcome::RejectedUnknownNonce
        ));
        // Expiry: a resolve after expires_at is rejected.
        let (mut eng, _n) = engine_with_request(1000, 100);
        assert!(matches!(
            eng.resolve(
                7,
                ApprovalResolution::Approve,
                ChatId(42),
                &allow,
                ts(1101),
                None
            ),
            ApprovalOutcome::RejectedExpired
        ));
    }

    #[test]
    fn approval_from_non_allowlisted_chat_is_dropped() {
        let allow = ChatAllowlist::of(&[42]);
        let (mut eng, _n) = engine_with_request(1000, 5000);
        assert!(matches!(
            eng.resolve(
                7,
                ApprovalResolution::Approve,
                ChatId(99),
                &allow,
                ts(1001),
                None
            ),
            ApprovalOutcome::RejectedNotAllowlisted
        ));
        // The pending nonce is NOT consumed by a rejected non-allowlisted attempt.
        assert!(eng.is_pending(7));
    }

    #[test]
    fn stray_approval_id_is_a_signal_not_silently_ignored() {
        let allow = ChatAllowlist::of(&[42]);
        let mut eng = ApprovalEngine::new();
        assert!(matches!(
            eng.resolve(
                999,
                ApprovalResolution::Approve,
                ChatId(42),
                &allow,
                ts(1),
                None
            ),
            ApprovalOutcome::RejectedUnknownNonce
        ));
    }

    #[test]
    fn callback_nonce_roundtrips() {
        let (_eng, nonce) = engine_with_request(1000, 5000);
        let data = nonce.callback_data(ApprovalResolution::Approve);
        let parsed = CallbackData::parse(&data).expect("parse");
        assert_eq!(parsed.approval_id, 7);
        assert_eq!(parsed.decision, ApprovalResolution::Approve);
        assert_eq!(parsed.op_hash, nonce.op_hash);
        assert!(CallbackData::parse("garbage").is_none());
        assert!(CallbackData::parse("ap:7:maybe:00").is_none());
    }

    // --- outbound: model does not speak Telegram directly; redaction (§7–§8) ---

    #[test]
    fn outbound_is_typed_and_redacted() {
        let mut redactor = Redactor::new();
        redactor.register("model-key", b"sk-SENTINEL-tg");
        let out = OutboundRenderer::new(&redactor);

        // A status snapshot renders from typed fields (no model text path).
        let status = out.status(&StatusSnapshot {
            active_tasks: 2,
            budget_used_micros: 10,
            budget_limit_micros: 100,
            channel_healthy: true,
        });
        assert!(status.as_str().contains("2 active task"));

        // /logs passes raw logs through the redactor — a secret never reaches the
        // Telegram draft (invariants 2, 15).
        let logs = out.logs("deploy used sk-SENTINEL-tg to push\nok");
        assert!(
            !logs.as_str().contains("SENTINEL"),
            "secret leaked: {}",
            logs.as_str()
        );
        assert!(logs.as_str().contains("[REDACTED:model-key]"));
    }

    // --- P9-net runtime loop ---

    struct MockTelegram {
        updates: std::cell::RefCell<Vec<RawUpdate>>,
        sent: std::cell::RefCell<Vec<(ChatId, String)>>,
    }
    impl MockTelegram {
        fn new(updates: Vec<RawUpdate>) -> Self {
            MockTelegram {
                updates: std::cell::RefCell::new(updates),
                sent: std::cell::RefCell::new(Vec::new()),
            }
        }
    }
    impl TelegramApi for MockTelegram {
        fn get_updates(&self, offset: i64) -> Result<Vec<RawUpdate>, TgError> {
            // Honor Telegram's offset semantics: only updates at/after the offset.
            Ok(self
                .updates
                .borrow()
                .iter()
                .filter(|u| u.update_id >= offset)
                .cloned()
                .collect())
        }
        fn send_message(&self, chat: ChatId, text: &ModelVisibleText) -> Result<i64, TgError> {
            self.sent
                .borrow_mut()
                .push((chat, text.as_str().to_string()));
            Ok(self.sent.borrow().len() as i64)
        }
    }

    fn upd(update_id: i64, chat: i64, text: &str) -> RawUpdate {
        RawUpdate {
            update_id,
            chat_id: chat,
            message_id: update_id,
            from_user_id: 1,
            from_username: None,
            text: Some(text.into()),
            callback_data: None,
        }
    }

    #[test]
    fn poll_advances_offset_dedupes_allowlists_and_routes() {
        let api = MockTelegram::new(vec![
            upd(1, 100, "/help"),       // allowlisted command
            upd(2, 100, "fix the bug"), // allowlisted text -> queued turn
            upd(3, 100, "!steer now"),  // allowlisted steer
            upd(4, 999, "spoof"),       // NOT allowlisted -> rejected
            upd(2, 100, "replayed"),    // duplicate update_id 2 -> dropped
        ]);
        let mut poller = TelegramPoller::new(ChatAllowlist::of(&[100]));
        let events = poller.poll_once(&api, ts(1000)).unwrap();

        assert_eq!(events.len(), 3, "help + queued turn + steer survive");
        assert!(matches!(events[0], RuntimeEvent::Command(Command::Help)));
        assert!(matches!(events[1], RuntimeEvent::QueuedTurn(_)));
        assert!(matches!(events[2], RuntimeEvent::Steer(_)));
        // Offset advanced past the highest update id (4 → 5) — even rejected/dup ones.
        assert_eq!(poller.offset(), 5);
        // The non-allowlisted update was rejected and counted (spoof signal).
        assert_eq!(poller.rejected_count(), 1);
    }

    #[test]
    fn long_poll_offset_skips_acknowledged_and_send_is_redacted_only() {
        let api = MockTelegram::new(vec![upd(1, 100, "hi"), upd(2, 100, "there")]);
        let mut poller = TelegramPoller::new(ChatAllowlist::of(&[100]));
        assert_eq!(poller.poll_once(&api, ts(1)).unwrap().len(), 2);
        assert_eq!(poller.offset(), 3);
        // A second poll sees nothing new (offset acknowledged the first two).
        assert!(poller.poll_once(&api, ts(2)).unwrap().is_empty());

        // Outbound: the channel can emit ONLY redacted ModelVisibleText — the type of
        // `send_message` makes raw/unredacted text unrepresentable (invariants 2, 5).
        let mut redactor = Redactor::new();
        redactor.register("tok", b"sk-TGSENTINEL");
        let rendered = OutboundRenderer::new(&redactor).logs("status leaked sk-TGSENTINEL");
        api.send_message(ChatId(100), &rendered).unwrap();
        let sent = api.sent.borrow();
        assert_eq!(sent.len(), 1);
        assert!(
            !sent[0].1.contains("TGSENTINEL"),
            "outbound must be redacted"
        );
    }
}
