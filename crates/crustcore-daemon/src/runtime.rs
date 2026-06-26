// SPDX-License-Identifier: Apache-2.0
//! The **runtime loop** — the actual running Telegram bot (`docs/chat.md`, `docs/telegram.md`).
//!
//! Two layers, split so the whole bot's *decision logic* is CI-tested with no transport:
//!
//! - [`dispatch_event`] is the pure dispatch core: given ONE `(chat, RuntimeEvent)` plus
//!   the runtime state, it returns the redacted messages to send and an optional
//!   [`LoopAction`] (launch/cancel a task). It owns **no** I/O and the model consult is
//!   injected, so it is fully unit-tested with a canned model.
//! - [`run_serve_loop`] (behind the `live` feature) wires the real transports — the
//!   spawned `crustcore-net` helper (model consult) and
//!   `crustcore_net::telegram::RestTelegram` over the live `UreqClient` — and runs
//!   `poll_routed → dispatch_event → send_message → handle action` forever. The only
//!   thing it cannot run in CI is the real HTTPS socket (`TODO(P9-net-live)`).

use crustcore_chat::ChatRoute;
use crustcore_netproto::CompleteRequest;
use crustcore_secrets::ModelVisibleText;
use crustcore_types::{ApprovalResolution, Timestamp};

use crate::chat::{ChatBridge, ChatReply};
use crate::telegram::{
    ApprovalEngine, ApprovalOutcome, ChatAllowlist, ChatId, Command, OutboundRenderer,
    RuntimeEvent, StatusSnapshot,
};

/// One redacted message the loop must send. `text` is [`ModelVisibleText`] — the only
/// thing that can reach the wire (constructible solely via the [`Redactor`]).
///
/// [`Redactor`]: crustcore_secrets::Redactor
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outbound {
    /// The chat to reply to (the allowlisted source chat).
    pub chat: ChatId,
    /// The redacted, bounded text.
    pub text: ModelVisibleText,
}

/// An action the loop must perform *after* sending the messages. These need the loop's
/// task state / threads, so the pure dispatch core only **requests** them; the live loop
/// performs them ([`run_serve_loop`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoopAction {
    /// Launch a verified task for `prompt` (the chat classified an execution route).
    /// The task runs through the *same* worktree → sandbox → verifier gates as
    /// `crustcore run` (invariants 9, 13); the chat only decides *which* flow.
    LaunchTask {
        /// The non-converse route the classifier chose.
        route: ChatRoute,
        /// The user's goal text.
        prompt: String,
        /// The chat to report progress/result to.
        chat: ChatId,
    },
    /// Cancel the active task (`/cancel`).
    CancelTask {
        /// The chat that asked to cancel.
        chat: ChatId,
    },
}

/// The result of dispatching one event: messages to send now + an optional [`LoopAction`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dispatch {
    /// Redacted messages to send immediately, in order.
    pub outbound: Vec<Outbound>,
    /// An action the loop must take after sending (launch/cancel a task), if any.
    pub action: Option<LoopAction>,
}

impl Dispatch {
    /// A single message, no action.
    fn say(chat: ChatId, text: ModelVisibleText) -> Self {
        Dispatch {
            outbound: vec![Outbound { chat, text }],
            action: None,
        }
    }

    /// Nothing to do (e.g. a steer with no pending turn).
    fn quiet() -> Self {
        Dispatch {
            outbound: Vec::new(),
            action: None,
        }
    }
}

/// The runtime help listing (the user's vocabulary).
pub const HELP_TEXT: &str = "\
CrustCore runtime — talk to me, or use a command:
  (plain text)   chat: I answer, or start the work if it's a task.
  !<text>        steer: redirect the in-flight reasoning.
  /cancel        abort the active task (stay in the conversation).
  /status        active tasks, budget, channel health.
  /tasks         how many tasks are active.
  /budget        budget consumption.
  /approve <id>  approve a pending irreversible action.
  /deny <id>     deny a pending approval.
  /help          this listing.
Completion is verifier-owned: a task is done only when your verify command passes \
in a sandbox; irreversible actions need your /approve.";

/// Read-only dispatch context — the renderer, allowlist, current status, and clock the
/// dispatch core reads. Grouping these keeps [`dispatch_event`]'s signature small; the
/// mutable `bridge`/`approvals` and the injected `model` stay separate parameters.
pub struct DispatchCtx<'a, 'r> {
    /// The redacted-output renderer.
    pub renderer: &'a OutboundRenderer<'r>,
    /// The chat allowlist (principal trust).
    pub allowlist: &'a ChatAllowlist,
    /// The current runtime status snapshot (active task count, etc.).
    pub status: &'a StatusSnapshot,
    /// The host clock — the daemon adapter's wall time (the kernel never reads one).
    pub now: Timestamp,
}

/// Handle ONE `(chat, event)` end to end. **Pure + testable**: the model consult is
/// injected and there is no I/O. The runtime loop calls this per polled event, then
/// performs the sends and the optional [`LoopAction`].
pub fn dispatch_event(
    chat: ChatId,
    event: RuntimeEvent,
    bridge: &mut ChatBridge,
    approvals: &mut ApprovalEngine,
    ctx: &DispatchCtx<'_, '_>,
    model: &mut dyn FnMut(&CompleteRequest) -> Option<String>,
) -> Dispatch {
    match event {
        RuntimeEvent::Command(cmd) => dispatch_command(chat, cmd, approvals, ctx),
        // An approval inline-button callback: resolve it (allowlist + nonce + op-hash +
        // expiry + single-use are all enforced in the engine) and report the outcome.
        RuntimeEvent::ApprovalCallback(cb) => {
            let outcome = approvals.resolve(
                cb.approval_id,
                cb.decision,
                chat,
                ctx.allowlist,
                ctx.now,
                Some(cb.op_hash),
            );
            Dispatch::say(chat, render_approval_outcome(&outcome, ctx.renderer))
        }
        // A plain message or a `!`-steer: run it through the chat bridge.
        ev @ (RuntimeEvent::QueuedTurn(_) | RuntimeEvent::Steer(_)) => {
            match bridge.dispatch(ev, model) {
                ChatReply::Answer(a) => Dispatch::say(chat, a),
                ChatReply::StartTask { route, prompt } => Dispatch {
                    outbound: vec![Outbound {
                        chat,
                        text: ctx.renderer.notice(&format!(
                            "🛠️ on it — starting a {} task: {prompt}",
                            route.as_str()
                        )),
                    }],
                    action: Some(LoopAction::LaunchTask {
                        route,
                        prompt,
                        chat,
                    }),
                },
                ChatReply::Quiet => Dispatch::quiet(),
                // A turn never yields Command/Approval (those arrive as their own events).
                ChatReply::Command | ChatReply::Approval => Dispatch::quiet(),
            }
        }
    }
}

fn dispatch_command(
    chat: ChatId,
    cmd: Command,
    approvals: &mut ApprovalEngine,
    ctx: &DispatchCtx<'_, '_>,
) -> Dispatch {
    let r = ctx.renderer;
    match cmd {
        Command::Help => Dispatch::say(chat, r.notice(HELP_TEXT)),
        Command::Status => Dispatch::say(chat, r.status(ctx.status)),
        Command::Tasks => Dispatch::say(
            chat,
            r.notice(&format!("{} active task(s).", ctx.status.active_tasks)),
        ),
        Command::Budget => Dispatch::say(
            chat,
            r.notice(&format!(
                "budget {}/{} micros",
                ctx.status.budget_used_micros, ctx.status.budget_limit_micros
            )),
        ),
        // `/approve` and `/deny` are the only commands that mint/consume an approval
        // token (the command path, op-hash unbound — §6). The engine still requires an
        // allowlisted chat (→ AuthorizedUser) and a matching pending nonce.
        Command::Approve(id) => {
            let outcome = approvals.resolve(
                id,
                ApprovalResolution::Approve,
                chat,
                ctx.allowlist,
                ctx.now,
                None,
            );
            Dispatch::say(chat, render_approval_outcome(&outcome, r))
        }
        Command::Deny(id) => {
            let outcome = approvals.resolve(
                id,
                ApprovalResolution::Deny,
                chat,
                ctx.allowlist,
                ctx.now,
                None,
            );
            Dispatch::say(chat, render_approval_outcome(&outcome, r))
        }
        Command::Cancel(_) => Dispatch {
            outbound: vec![Outbound {
                chat,
                text: r.notice("⏹️ cancelling the active task (if any)."),
            }],
            action: Some(LoopAction::CancelTask { chat }),
        },
        // Commands that need richer multi-task runtime state than this single-task
        // runtime exposes are acknowledged as typed notices — they never fall through to
        // a model (invariant: commands are typed verbs, not prompts).
        Command::Task(_)
        | Command::Pause(_)
        | Command::Resume(_)
        | Command::Kill(_)
        | Command::Diff(_)
        | Command::Logs(_)
        | Command::Policy
        | Command::Repo => Dispatch::say(
            chat,
            r.notice(
                "received. This runtime supports /help /status /tasks /budget /approve \
                 /deny /cancel and plain-text chat.",
            ),
        ),
        Command::Unknown(raw) => Dispatch::say(
            chat,
            r.notice(&format!("unknown command '{raw}'. Try /help.")),
        ),
    }
}

/// Renders the result of an approval resolution as a daemon-authored notice.
fn render_approval_outcome(
    outcome: &ApprovalOutcome,
    renderer: &OutboundRenderer,
) -> ModelVisibleText {
    let text = match outcome {
        ApprovalOutcome::Approved(_) => "✅ approved — the operation is authorized.".to_string(),
        ApprovalOutcome::Denied { approval_id } => format!("🚫 denied approval {approval_id}."),
        ApprovalOutcome::RejectedNotAllowlisted => "ignored: not an allowlisted chat.".to_string(),
        ApprovalOutcome::RejectedUnknownNonce => {
            "⚠️ no pending approval with that id (this was logged).".to_string()
        }
        ApprovalOutcome::RejectedExpired => "⌛ that approval expired — re-request it.".to_string(),
        ApprovalOutcome::RejectedOpMismatch => {
            "⚠️ that approval did not match the operation (this was logged).".to_string()
        }
    };
    renderer.notice(&text)
}

// ===========================================================================
// The live loop (behind `live`) — wires the real transports.
// ===========================================================================
#[cfg(feature = "live")]
pub use live::{run_pair_discovery, run_serve_loop, ServeConfig, ServeError};

#[cfg(feature = "live")]
mod live {
    use std::rc::Rc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use crustcore_chat::{ChatConfig, OperatorSteering, Persona};
    use crustcore_net::credsource::StaticCredentials;
    use crustcore_net::telegram::{RestTelegram, TELEGRAM_API};
    use crustcore_net::transport::UreqClient;
    use crustcore_netproto::{CompleteRequest, SpawnedHelper};
    use crustcore_secrets::Redactor;
    use crustcore_types::Timestamp;

    use super::{dispatch_event, DispatchCtx, LoopAction};
    use crate::chat::ChatBridge;
    use crate::task::{TaskHandle, TaskSpec};
    use crate::telegram::{
        ChatAllowlist, LiveTelegramApi, OutboundRenderer, StatusSnapshot, TelegramApi,
        TelegramPoller,
    };

    /// The runtime configuration for [`run_serve_loop`].
    pub struct ServeConfig {
        /// The allowlist of chat ids that may control the runtime (empty = deny-all).
        pub allowlist: ChatAllowlist,
        /// The bot token (resolved from the operator's env/broker by the caller). It is
        /// handed to the net client's credential source and spliced into the URL path
        /// per call — never logged.
        pub bot_token: String,
        /// The `crustcore-net` helper program to spawn for model calls.
        pub helper_program: String,
        /// The persona for the model role.
        pub persona: Persona,
        /// Operator steering (`CRUSTCORE.md`/`AGENTS.md`).
        pub steering: OperatorSteering,
        /// The repo a chat-launched task runs against, and its verify command.
        pub task: Option<TaskSpec>,
        /// Milliseconds to wait between poll cycles (the long-poll already blocks
        /// server-side; this bounds a tight loop on errors).
        pub poll_backoff_ms: u64,
    }

    /// Why the runtime loop could not start (the loop itself logs+continues on transient
    /// per-request errors; only setup failures bubble up here).
    #[derive(Debug)]
    pub enum ServeError {
        /// The `crustcore-net` helper could not be spawned.
        Helper(String),
    }

    impl core::fmt::Display for ServeError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                ServeError::Helper(e) => write!(f, "cannot spawn net helper: {e}"),
            }
        }
    }

    fn now_ts() -> Timestamp {
        // The daemon (an adapter, not the kernel) may read the wall clock for runtime
        // sequencing; the kernel never does.
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Timestamp::from_millis(ms)
    }

    fn build_api(bot_token: &str) -> LiveTelegramApi<RestTelegram> {
        let http: Rc<dyn crustcore_net::transport::HttpClient> = Rc::new(UreqClient::new());
        let creds: Rc<dyn crustcore_net::credsource::CredentialSource> =
            Rc::new(StaticCredentials::new().with("telegram", bot_token));
        LiveTelegramApi::new(RestTelegram::new(TELEGRAM_API, "telegram", http, creds))
    }

    /// Run the live runtime loop: long-poll Telegram, dispatch each event through the
    /// tested core, send the redacted replies, and launch/cancel chat-requested tasks.
    /// Runs until the process is stopped. The bot token never reaches the model, a log,
    /// or an error body.
    ///
    /// # Errors
    /// [`ServeError`] only on a setup failure (e.g. the net helper cannot spawn); per-poll
    /// transport errors are logged to stderr and retried.
    pub fn run_serve_loop(config: ServeConfig) -> Result<(), ServeError> {
        let api = build_api(&config.bot_token);
        let mut helper = SpawnedHelper::spawn(&config.helper_program, &[])
            .map_err(|e| ServeError::Helper(e.to_string()))?;

        // No secret broker is wired into this standalone entry yet, so the redactor
        // starts empty (the converse renderer still bounds + seals). When the supervisor
        // hosts the surface it passes the broker's pre-loaded redactor.
        let redactor = Redactor::new();
        let cfg = ChatConfig {
            persona: config.persona,
            steering: config.steering,
            ..ChatConfig::default()
        };
        let mut bridge = ChatBridge::new(&redactor, cfg);
        let renderer = OutboundRenderer::new(&redactor);
        let mut approvals = crate::telegram::ApprovalEngine::new();
        let mut poller = TelegramPoller::new(config.allowlist.clone());
        let allowlist = config.allowlist;
        let task_spec = config.task;
        let mut active: Option<TaskHandle> = None;

        eprintln!("crustcore-daemon: runtime loop started (long-poll). Ctrl-C to stop.");
        loop {
            // 1. Drain any progress from a running task and forward it.
            if let Some(handle) = active.as_mut() {
                for msg in handle.drain() {
                    let text = renderer.notice(&msg);
                    let _ = api.send_message(handle.chat(), &text);
                }
                if handle.finished() {
                    active = None;
                }
            }

            // 2. Poll for new updates and dispatch them.
            let now = now_ts();
            match poller.poll_routed(&api, now) {
                Ok(events) => {
                    for (chat, event) in events {
                        let status = StatusSnapshot {
                            active_tasks: usize::from(active.is_some()),
                            budget_used_micros: 0,
                            budget_limit_micros: 0,
                            channel_healthy: true,
                        };
                        let ctx = DispatchCtx {
                            renderer: &renderer,
                            allowlist: &allowlist,
                            status: &status,
                            now,
                        };
                        let dispatch = {
                            let mut model = |req: &CompleteRequest| {
                                crustcore_chat::complete_text(helper.helper(), req)
                            };
                            dispatch_event(
                                chat,
                                event,
                                &mut bridge,
                                &mut approvals,
                                &ctx,
                                &mut model,
                            )
                        };
                        for o in &dispatch.outbound {
                            let _ = api.send_message(o.chat, &o.text);
                        }
                        handle_action(dispatch.action, &task_spec, &mut active, &renderer, &api);
                    }
                }
                Err(e) => eprintln!("crustcore-daemon: poll error (retrying): {e}"),
            }

            std::thread::sleep(Duration::from_millis(config.poll_backoff_ms.max(50)));
        }
    }

    fn handle_action(
        action: Option<LoopAction>,
        task_spec: &Option<TaskSpec>,
        active: &mut Option<TaskHandle>,
        renderer: &OutboundRenderer,
        api: &LiveTelegramApi<RestTelegram>,
    ) {
        match action {
            Some(LoopAction::LaunchTask { prompt, chat, .. }) => {
                if active.is_some() {
                    let t = renderer
                        .notice("a task is already running — /cancel it first, then retry.");
                    let _ = api.send_message(chat, &t);
                    return;
                }
                match task_spec {
                    Some(spec) => *active = Some(TaskHandle::spawn(spec.clone(), prompt, chat)),
                    None => {
                        let t = renderer.notice(
                            "I can chat here, but task execution needs a bound repo + verify \
                             command (start me with --dir and --verify).",
                        );
                        let _ = api.send_message(chat, &t);
                    }
                }
            }
            Some(LoopAction::CancelTask { chat }) => {
                if let Some(handle) = active.as_mut() {
                    handle.cancel();
                } else {
                    let t = renderer.notice("nothing to cancel — no task is running.");
                    let _ = api.send_message(chat, &t);
                }
            }
            None => {}
        }
    }

    /// **Pairing discovery** (`crustcore-daemon serve --pair`): poll the bot and print the
    /// chat id of every inbound message, so an operator can discover *their* id and bind
    /// it with `--chat-id`. It deliberately does **no** allowlisting and takes **no**
    /// action — it only reads and prints ids (the binding still happens via the trusted
    /// CLI, never a DM-to-pair flow; `docs/telegram.md` §4).
    ///
    /// # Errors
    /// [`ServeError`] never (transport errors are printed and retried); the signature is
    /// kept uniform with [`run_serve_loop`].
    pub fn run_pair_discovery(bot_token: &str, poll_backoff_ms: u64) -> Result<(), ServeError> {
        use crustcore_net::telegram::TelegramBotApi;
        let http: Rc<dyn crustcore_net::transport::HttpClient> = Rc::new(UreqClient::new());
        let creds: Rc<dyn crustcore_net::credsource::CredentialSource> =
            Rc::new(StaticCredentials::new().with("telegram", bot_token));
        let api = RestTelegram::new(TELEGRAM_API, "telegram", http, creds);

        println!("crustcore-daemon: PAIRING mode — message your bot; your chat id prints below.");
        println!("                  (Ctrl-C when you have it, then: serve --chat-id <id>)");
        let mut offset = 0i64;
        loop {
            match api.get_updates(offset) {
                Ok(updates) => {
                    for u in &updates {
                        offset = offset.max(u.update_id.saturating_add(1));
                        println!(
                            "  chat_id = {}   (bind: crustcore-daemon serve --chat-id {})",
                            u.chat_id, u.chat_id
                        );
                    }
                }
                Err(e) => eprintln!("crustcore-daemon: pair poll error (retrying): {e}"),
            }
            std::thread::sleep(Duration::from_millis(poll_backoff_ms.max(50)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crustcore_chat::ChatConfig;
    use crustcore_netproto::{BoundedText, MAX_TEXT_BYTES};
    use crustcore_secrets::{InMemoryStore, SecretBroker};
    use crustcore_types::SecretId;

    use crate::telegram::{CallbackData, ChatAllowlist, ChatId};
    use crustcore_types::ApprovalResolution;

    fn bt(s: &str) -> BoundedText {
        BoundedText::truncated(s, MAX_TEXT_BYTES)
    }

    fn status() -> StatusSnapshot {
        StatusSnapshot {
            active_tasks: 0,
            budget_used_micros: 0,
            budget_limit_micros: 0,
            channel_healthy: true,
        }
    }

    /// Drive one event through the dispatch core with a canned model + fresh state.
    fn drive(
        broker: &SecretBroker<InMemoryStore>,
        allowlist: &ChatAllowlist,
        approvals: &mut ApprovalEngine,
        event: RuntimeEvent,
        model: &mut dyn FnMut(&CompleteRequest) -> Option<String>,
    ) -> Dispatch {
        let renderer = OutboundRenderer::new(broker.redactor());
        let mut bridge = ChatBridge::new(broker.redactor(), ChatConfig::default());
        let st = status();
        let ctx = DispatchCtx {
            renderer: &renderer,
            allowlist,
            status: &st,
            now: Timestamp::from_millis(1000),
        };
        dispatch_event(ChatId(7), event, &mut bridge, approvals, &ctx, model)
    }

    #[test]
    fn help_command_renders_the_listing() {
        let broker = SecretBroker::new(InMemoryStore::new());
        let allow = ChatAllowlist::of(&[7]);
        let mut approvals = ApprovalEngine::new();
        let mut model = |_req: &CompleteRequest| None;
        let d = drive(
            &broker,
            &allow,
            &mut approvals,
            RuntimeEvent::Command(Command::Help),
            &mut model,
        );
        assert_eq!(d.outbound.len(), 1);
        assert!(d.outbound[0].text.as_str().contains("CrustCore runtime"));
        assert!(d.action.is_none());
    }

    #[test]
    fn a_question_is_answered_and_redacted() {
        let mut store = InMemoryStore::new();
        store.insert(SecretId(1), "model-key", b"sk-RTSENTINEL".to_vec());
        let broker = SecretBroker::new(store);
        let allow = ChatAllowlist::of(&[7]);
        let mut approvals = ApprovalEngine::new();
        let mut model =
            |_req: &CompleteRequest| Some("All green. key sk-RTSENTINEL is set.".to_string());
        let d = drive(
            &broker,
            &allow,
            &mut approvals,
            RuntimeEvent::QueuedTurn(bt("what's the status?")),
            &mut model,
        );
        assert_eq!(d.outbound.len(), 1);
        assert!(!d.outbound[0].text.as_str().contains("RTSENTINEL"));
        assert!(d.outbound[0].text.as_str().contains("[REDACTED:model-key]"));
        assert!(d.action.is_none());
    }

    #[test]
    fn an_execution_request_requests_a_launch_action() {
        let broker = SecretBroker::new(InMemoryStore::new());
        let allow = ChatAllowlist::of(&[7]);
        let mut approvals = ApprovalEngine::new();
        let mut model = |_req: &CompleteRequest| Some("feature".to_string());
        let d = drive(
            &broker,
            &allow,
            &mut approvals,
            RuntimeEvent::QueuedTurn(bt("implement the export feature")),
            &mut model,
        );
        // It both replies "on it" AND requests a LaunchTask the loop will perform.
        assert_eq!(d.outbound.len(), 1);
        assert!(d.outbound[0].text.as_str().contains("on it"));
        match d.action {
            Some(LoopAction::LaunchTask {
                route,
                prompt,
                chat,
            }) => {
                assert!(route.is_execution());
                assert_eq!(prompt, "implement the export feature");
                assert_eq!(chat, ChatId(7));
            }
            other => panic!("expected LaunchTask, got {other:?}"),
        }
    }

    #[test]
    fn cancel_command_requests_cancel_action() {
        let broker = SecretBroker::new(InMemoryStore::new());
        let allow = ChatAllowlist::of(&[7]);
        let mut approvals = ApprovalEngine::new();
        let mut model = |_req: &CompleteRequest| None;
        let d = drive(
            &broker,
            &allow,
            &mut approvals,
            RuntimeEvent::Command(Command::Cancel(0)),
            &mut model,
        );
        assert_eq!(d.action, Some(LoopAction::CancelTask { chat: ChatId(7) }));
    }

    #[test]
    fn approval_callback_resolves_through_the_engine() {
        let broker = SecretBroker::new(InMemoryStore::new());
        let allow = ChatAllowlist::of(&[7]);
        let mut approvals = ApprovalEngine::new();
        // Register a pending approval and reproduce its op-hash for the callback.
        let nonce = approvals.request(
            42,
            "push branch x",
            "push branch x",
            Timestamp::from_millis(10_000),
        );
        let cb = CallbackData {
            approval_id: 42,
            decision: ApprovalResolution::Approve,
            op_hash: nonce.op_hash,
        };
        let mut model = |_req: &CompleteRequest| None;
        let d = drive(
            &broker,
            &allow,
            &mut approvals,
            RuntimeEvent::ApprovalCallback(cb),
            &mut model,
        );
        assert!(d.outbound[0].text.as_str().contains("approved"));
        // Single-use: the pending is consumed.
        assert!(!approvals.is_pending(42));
    }

    #[test]
    fn approval_from_non_allowlisted_chat_is_ignored() {
        let broker = SecretBroker::new(InMemoryStore::new());
        let allow = ChatAllowlist::deny_all(); // chat 7 is NOT allowlisted
        let mut approvals = ApprovalEngine::new();
        let nonce = approvals.request(42, "op", "op", Timestamp::from_millis(10_000));
        let cb = CallbackData {
            approval_id: 42,
            decision: ApprovalResolution::Approve,
            op_hash: nonce.op_hash,
        };
        let mut model = |_req: &CompleteRequest| None;
        let d = drive(
            &broker,
            &allow,
            &mut approvals,
            RuntimeEvent::ApprovalCallback(cb),
            &mut model,
        );
        assert!(d.outbound[0].text.as_str().contains("not an allowlisted"));
        // Not consumed (a non-allowlisted resolution must not touch the pending).
        assert!(approvals.is_pending(42));
    }
}
