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
use crustcore_net::telegram::InlineKeyboard;
use crustcore_netproto::CompleteRequest;
use crustcore_policy::{Approved, GitHubWriteCap};
use crustcore_secrets::ModelVisibleText;
use crustcore_types::{
    ApprovalId, ApprovalResolution, BoundedText, BranchPrefix, RepoRef, ScopeId, Timestamp,
};

use crate::chat::{ChatBridge, ChatReply, STEER_BUTTON_DATA};
use crate::registry::{default_task_budget, RegistrySnapshot, TaskId, TaskPhase};
use crate::supervisor::AgentBudget;
use crate::telegram::{
    ApprovalEngine, ApprovalOutcome, ChatAllowlist, ChatId, Command, OutboundRenderer,
    RuntimeEvent, StatusSnapshot,
};

/// The per-task resource budget for a classified chat route (invariant 11). The classifier
/// distinguishes a bounded **QuickFix** ("one worktree, one verify") from a multi-step
/// **Feature** and a whole-project **Project** build, so the runtime honors that with
/// route-aware resource tiers — a quick fix gets a tight budget (fail fast), a project the
/// generous default. **Continue** maps to the Feature tier; true task *resumption*
/// (re-attaching a prior task's state) is the `TODO(chat-resume)` seam. Routing Feature/Project
/// to the multi-agent fan-out loop (`exec::run_fanout`) needs a live `SubagentExecutor`
/// (`TODO(P11-exec-live)`); the budget tier is the in-process honoring of the route today.
/// Pure + CI-tested.
#[must_use]
pub fn budget_for_route(route: ChatRoute) -> AgentBudget {
    match route {
        ChatRoute::QuickFix => AgentBudget {
            max_wall_ms: 5 * 60 * 1000,
            max_output_bytes: 256 * 1024,
            max_tokens: u64::MAX,
        },
        ChatRoute::Feature | ChatRoute::Continue => AgentBudget {
            max_wall_ms: 15 * 60 * 1000,
            max_output_bytes: 512 * 1024,
            max_tokens: u64::MAX,
        },
        // A whole-project build gets the generous default tier.
        ChatRoute::Project => default_task_budget(),
        // Converse never launches a task; default defensively (unreachable via LaunchTask).
        ChatRoute::Converse => default_task_budget(),
    }
}

/// Mint an `Approved<GitHubWriteCap>` for an allowlisted chat that just approved opening
/// a draft PR. This is the **only** place the chat front door mints GitHub write
/// authority: it requires the chat be allowlisted (→ `AuthorizedUser`, invariant 4) and
/// binds the cap to the configured repo + branch prefix + the approval's id/expiry
/// (invariant 14). Returns `None` for a non-allowlisted chat — so a stray approval can
/// never produce write authority. Pure + CI-tested (no transport).
#[must_use]
pub fn mint_github_write_cap(
    allowlist: &ChatAllowlist,
    chat: ChatId,
    repo: &str,
    branch_prefix: &str,
    approval_id: u128,
    expires_at: Timestamp,
) -> Option<Approved<GitHubWriteCap>> {
    let user = allowlist.authorized_user(chat)?;
    let cap = GitHubWriteCap {
        repo: RepoRef(BoundedText::truncated(repo, BoundedText::DEFAULT_MAX)),
        branch_prefix: BranchPrefix(BoundedText::truncated(
            branch_prefix,
            BoundedText::DEFAULT_MAX,
        )),
        scope: ScopeId(1),
    };
    Some(user.approve(cap, ApprovalId(approval_id), expires_at))
}

/// If `event` is an approve/deny resolution for `approval_id` — a button callback or the
/// `/approve`//`deny` command — returns `(decision, op_hash)`; else `None`. The loop uses
/// this to route a PR-gating approval to the pending-task resolver (so a real
/// `VerifiedPatch` never has to outlive the approval).
#[must_use]
pub fn pr_approval_match(
    event: &RuntimeEvent,
    approval_id: u128,
) -> Option<(ApprovalResolution, Option<[u8; 32]>)> {
    match event {
        RuntimeEvent::ApprovalCallback(cb) if cb.approval_id == approval_id => {
            Some((cb.decision, Some(cb.op_hash)))
        }
        RuntimeEvent::Command(Command::Approve(id)) if *id == approval_id => {
            Some((ApprovalResolution::Approve, None))
        }
        RuntimeEvent::Command(Command::Deny(id)) if *id == approval_id => {
            Some((ApprovalResolution::Deny, None))
        }
        _ => None,
    }
}

/// A 🛑 Steer inline keyboard attached to converse answers, so the user can interrupt
/// with a tap (NilCore parity). Tapping arms the next message as a steer. The button
/// carries only a fixed label + the `STEER_BUTTON_DATA` callback id — no secret.
fn steer_button() -> InlineKeyboard {
    InlineKeyboard::single_row(vec![(
        "🛑 Steer".to_string(),
        STEER_BUTTON_DATA.to_string(),
    )])
}

/// Approve/deny inline buttons for a pending approval (callback_data carries the
/// nonce-bound `ap:<id>:<approve|deny>:<op_hash>` so a tap is operation-bound).
#[must_use]
pub fn approval_keyboard(nonce: &crate::telegram::ApprovalNonce) -> InlineKeyboard {
    InlineKeyboard::single_row(vec![
        (
            "✅ approve".to_string(),
            nonce.callback_data(ApprovalResolution::Approve),
        ),
        (
            "🚫 deny".to_string(),
            nonce.callback_data(ApprovalResolution::Deny),
        ),
    ])
}

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
    /// An optional inline keyboard (the 🛑 Steer button on answers, approve/deny on an
    /// approval request). Carries only fixed labels + callback ids — never a secret.
    pub keyboard: Option<InlineKeyboard>,
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
    /// Cooperatively cancel task `id` (`/cancel <id>`) — graceful, at the next safe boundary.
    CancelTask {
        /// The chat that asked to cancel.
        chat: ChatId,
        /// The task to cancel.
        id: TaskId,
    },
    /// Hard-kill task `id` (`/kill <id>`) — immediate teardown.
    KillTask {
        /// The chat that asked to kill.
        chat: ChatId,
        /// The task to kill.
        id: TaskId,
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
    /// A single message (no keyboard, no action).
    fn say(chat: ChatId, text: ModelVisibleText) -> Self {
        Dispatch {
            outbound: vec![Outbound {
                chat,
                text,
                keyboard: None,
            }],
            action: None,
        }
    }

    /// A single message with an inline keyboard (no action).
    fn say_kb(chat: ChatId, text: ModelVisibleText, keyboard: InlineKeyboard) -> Self {
        Dispatch {
            outbound: vec![Outbound {
                chat,
                text,
                keyboard: Some(keyboard),
            }],
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
  /cancel <id>   gracefully cancel task <id> (stay in the conversation).
  /kill <id>     immediately kill task <id>.
  /status        active tasks, budget, channel health.
  /tasks         list active tasks with status.
  /task <id>     detail on one task.
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
    /// A bounded read-only view of the supervised tasks (for `/tasks` and `/task <id>`).
    pub registry: &'a RegistrySnapshot,
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
        // The 🛑 Steer button was tapped: arm the next message as a steer (grants
        // nothing — it only changes how the next turn is routed).
        RuntimeEvent::SteerButton => {
            bridge.arm_steer();
            Dispatch::say(
                chat,
                ctx.renderer
                    .notice("🛑 steer armed — send your next message to redirect."),
            )
        }
        // A plain message or a `!`-steer: run it through the chat bridge.
        ev @ (RuntimeEvent::QueuedTurn(_) | RuntimeEvent::Steer(_)) => {
            match bridge.dispatch(ev, model) {
                // A converse answer carries a 🛑 Steer button so the user can interrupt.
                ChatReply::Answer(a) => Dispatch::say_kb(chat, a, steer_button()),
                ChatReply::StartTask { route, prompt } => Dispatch {
                    outbound: vec![Outbound {
                        chat,
                        text: ctx.renderer.notice(&format!(
                            "🛠️ on it — starting a {} task: {prompt}",
                            route.as_str()
                        )),
                        keyboard: None,
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
        Command::Tasks => Dispatch::say(chat, r.notice(&render_task_list(ctx.registry))),
        Command::Task(id) => Dispatch::say(
            chat,
            r.notice(&render_task_detail(ctx.registry, TaskId(id as u64))),
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
        // `/cancel` and `/kill` are **owner-scoped**: the action is emitted only if `chat`
        // launched the named task (checked against the registry snapshot here, in the tested
        // core; the registry re-checks at execution). One operator cannot touch another's task.
        Command::Cancel(id) => {
            let tid = TaskId(id as u64);
            if ctx.registry.get(tid).map(|row| row.chat) == Some(chat) {
                Dispatch {
                    outbound: vec![Outbound {
                        chat,
                        text: r.notice(&format!("⏹️ cancelling task #{id} (graceful).")),
                        keyboard: None,
                    }],
                    action: Some(LoopAction::CancelTask { chat, id: tid }),
                }
            } else {
                Dispatch::say(chat, r.notice(&format!("no task #{id} you can cancel.")))
            }
        }
        Command::Kill(id) => {
            let tid = TaskId(id as u64);
            if ctx.registry.get(tid).map(|row| row.chat) == Some(chat) {
                Dispatch {
                    outbound: vec![Outbound {
                        chat,
                        text: r.notice(&format!("🛑 killing task #{id} (immediate).")),
                        keyboard: None,
                    }],
                    action: Some(LoopAction::KillTask { chat, id: tid }),
                }
            } else {
                Dispatch::say(chat, r.notice(&format!("no task #{id} you can kill.")))
            }
        }
        // Commands that need richer per-task runtime state this runtime does not yet expose
        // are acknowledged as typed notices — they never fall through to a model (invariant:
        // commands are typed verbs, not prompts).
        Command::Pause(_)
        | Command::Resume(_)
        | Command::Diff(_)
        | Command::Logs(_)
        | Command::Policy
        | Command::Repo => Dispatch::say(
            chat,
            r.notice(
                "received. This runtime supports /help /status /tasks /task /budget /approve \
                 /deny /cancel /kill and plain-text chat.",
            ),
        ),
        Command::Unknown(raw) => Dispatch::say(
            chat,
            r.notice(&format!("unknown command '{raw}'. Try /help.")),
        ),
    }
}

/// A short, non-sensitive phase label for a task row.
fn phase_label(phase: TaskPhase) -> &'static str {
    match phase {
        TaskPhase::Pending => "pending",
        TaskPhase::Running => "running",
        TaskPhase::Cancelling => "cancelling",
        TaskPhase::Done(done) => done.label(),
    }
}

/// Renders the `/tasks` listing from the registry snapshot (bounded by the concurrency cap).
fn render_task_list(snap: &RegistrySnapshot) -> String {
    if snap.rows.is_empty() {
        return "no active tasks.".to_string();
    }
    let mut s = format!("{} task(s):", snap.rows.len());
    for row in &snap.rows {
        s.push_str(&format!(
            "\n  #{} [{}] {}ms · {}B · lease {}s",
            row.id.0,
            phase_label(row.phase),
            row.wall_ms,
            row.output_bytes,
            row.lease_ttl_ms / 1000,
        ));
    }
    s
}

/// Renders the `/task <id>` detail, or a not-found notice.
fn render_task_detail(snap: &RegistrySnapshot, id: TaskId) -> String {
    match snap.get(id) {
        Some(row) => format!(
            "task #{}: {} · wall {}ms · output {}B · lease expires in {}s",
            row.id.0,
            phase_label(row.phase),
            row.wall_ms,
            row.output_bytes,
            row.lease_ttl_ms / 1000,
        ),
        None => format!("no task #{}.", id.0),
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
    use std::collections::BTreeMap;
    use std::rc::Rc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use crustcore_chat::{ChatConfig, ChatRoute, OperatorSteering, Persona};
    use crustcore_net::credsource::StaticCredentials;
    use crustcore_net::telegram::{RestTelegram, TELEGRAM_API};
    use crustcore_net::transport::UreqClient;
    use crustcore_netproto::{CompleteRequest, SpawnedHelper};
    use crustcore_policy::{Approved, GitHubWriteCap};
    use crustcore_secrets::Redactor;
    use crustcore_types::{ApprovalResolution, Timestamp};

    use super::{
        approval_keyboard, dispatch_event, mint_github_write_cap, pr_approval_match,
        render_approval_outcome, DispatchCtx, LoopAction,
    };
    use crate::chat::ChatBridge;
    use crate::registry::{
        AdmitError, LeaseOwner, RegistryAction, RegistrySnapshot, TaskId, TaskRegistry,
    };
    use crate::supervisor::AgentBudget;
    use crate::task::{TaskHandle, TaskSpec};
    use crate::telegram::{
        ApprovalOutcome, ChatAllowlist, ChatId, LiveTelegramApi, OutboundRenderer, StatusSnapshot,
        TelegramApi, TelegramPoller,
    };

    /// Max concurrently-supervised chat tasks (bounded fan-out; invariant 11). Small by
    /// design — a single-operator runtime is not a build farm.
    const MAX_CONCURRENT_TASKS: usize = 4;

    /// How long a chat task's PR-launch approval stays valid (bounded; invariant 14). If
    /// the operator doesn't approve within this window the nonce expires and the launch is
    /// dropped — they re-ask.
    const PR_APPROVAL_TTL_MS: u64 = 300_000;

    /// Couples the pure [`TaskRegistry`] (the supervision brain) with the live
    /// [`TaskHandle`]s it names. The registry decides lifecycle; the runner executes the
    /// [`RegistryAction`]s against the real threads.
    struct TaskRunner {
        registry: TaskRegistry,
        handles: BTreeMap<TaskId, TaskHandle>,
    }

    impl TaskRunner {
        fn new() -> Self {
            TaskRunner {
                // A single supervisor instance owns every lease (instance id 1).
                registry: TaskRegistry::new(MAX_CONCURRENT_TASKS, LeaseOwner(1)),
                handles: BTreeMap::new(),
            }
        }

        /// Admit + spawn a task (respecting the concurrency cap). Returns the new id, or
        /// `Err(AdmitError)` if at capacity.
        fn launch(
            &mut self,
            spec: TaskSpec,
            prompt: String,
            chat: ChatId,
            pr_cap: Option<Approved<GitHubWriteCap>>,
            budget: AgentBudget,
            now: Timestamp,
        ) -> Result<TaskId, AdmitError> {
            let id = self.registry.admit(chat, budget, now)?;
            let handle = TaskHandle::spawn(spec, prompt, chat, pr_cap);
            self.registry.mark_running(id, now);
            self.handles.insert(id, handle);
            Ok(id)
        }

        /// One supervision step: forward each task's drained (redacted) progress, feed
        /// proof-of-life + finish into the registry, then execute the registry's tick
        /// actions (cancel/kill/finalize/notify) against the live handles.
        fn pump(
            &mut self,
            now: Timestamp,
            renderer: &OutboundRenderer,
            api: &LiveTelegramApi<RestTelegram>,
        ) {
            // Phase 1: collect each handle's progress (immutable over handles). Read
            // `finished()` BEFORE `drain()`: `TaskHandle` sets its done flag only *after* the
            // final line is queued, so a `finished` observed before draining guarantees the
            // drain already includes that final line — the opposite order could drop it if the
            // worker finishes between the two calls.
            let drained: Vec<(TaskId, ChatId, Vec<String>, bool)> = self
                .handles
                .iter()
                .map(|(id, h)| {
                    let finished = h.finished();
                    (*id, h.chat(), h.drain(), finished)
                })
                .collect();
            // Phase 2: feed progress to the registry + forward the redacted lines. A still-
            // running handle is heartbeated every tick (proof the supervisor holds the live
            // thread), so a healthy but silent task never falsely expires.
            for (id, chat, lines, finished) in drained {
                for line in lines {
                    self.registry.observe_progress(id, line.len() as u64, now);
                    let text = renderer.notice(&line);
                    let _ = api.send_message(chat, &text, None);
                }
                if finished {
                    self.registry.observe_finished(id);
                } else {
                    self.registry.heartbeat(id, now);
                }
            }
            // Phase 3: step the supervisor and execute its bounded actions.
            for act in self.registry.tick(now) {
                match act {
                    RegistryAction::SendLine { chat, line } => {
                        let text = renderer.notice(&line);
                        let _ = api.send_message(chat, &text, None);
                    }
                    RegistryAction::RequestCancel { id } => {
                        if let Some(h) = self.handles.get(&id) {
                            h.cancel();
                        }
                    }
                    // Drop the handle (Drop joins the thread + tears the worktree down — the
                    // existing cooperative teardown; invariant 12 process handle).
                    RegistryAction::HardKill { id } | RegistryAction::Finalize { id, .. } => {
                        self.handles.remove(&id);
                    }
                }
            }
        }

        fn cancel(&mut self, id: TaskId, chat: ChatId) -> bool {
            self.registry.request_cancel(id, chat)
        }

        fn kill(&mut self, id: TaskId, chat: ChatId) -> bool {
            self.registry.request_kill(id, chat)
        }

        fn snapshot(&self, now: Timestamp) -> RegistrySnapshot {
            self.registry.snapshot(now)
        }

        fn len_active(&self) -> usize {
            self.registry.len_active()
        }
    }

    /// A chat task launch awaiting the operator's PR approval (PR mode only). Holds only
    /// the prompt + the source chat + the nonce id — **not** a `VerifiedPatch` (the patch
    /// is produced *after* approval, inside the task thread, so it never outlives the gate).
    struct PendingTask {
        prompt: String,
        chat: ChatId,
        approval_id: u128,
        /// The classified route, so the approved launch uses the route's budget tier.
        route: ChatRoute,
    }

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
        // The multi-task supervised registry + its live handles (replaces the old single
        // `active` task) — bounded concurrency, leases, heartbeats, cancellation (invariant 12).
        let mut runner = TaskRunner::new();
        // PR mode only: a launch awaiting the operator's approval, and the next nonce id.
        let mut pending_task: Option<PendingTask> = None;
        let mut next_approval_id: u128 = 1;

        eprintln!("crustcore-daemon: runtime loop started (long-poll). Ctrl-C to stop.");
        loop {
            // 1. Supervise: forward progress, feed heartbeats, expire leases, run lifecycle.
            let now = now_ts();
            runner.pump(now, &renderer, &api);

            // 2. Poll for new updates and dispatch them.
            match poller.poll_routed(&api, now) {
                Ok(events) => {
                    for (chat, event) in events {
                        // PR-gate interception: if a launch is awaiting approval and this
                        // event resolves *that* nonce, mint the cap + launch (or drop) here
                        // — the engine still enforces allowlist/op-hash/expiry/single-use.
                        if let Some(pending) = pending_task.as_ref() {
                            if let Some((decision, op_hash)) =
                                pr_approval_match(&event, pending.approval_id)
                            {
                                resolve_pending_pr(
                                    pending,
                                    decision,
                                    op_hash,
                                    chat,
                                    &allowlist,
                                    &mut approvals,
                                    &task_spec,
                                    &mut runner,
                                    &renderer,
                                    &api,
                                    now,
                                );
                                pending_task = None;
                                continue;
                            }
                        }

                        // Build the dispatch context (incl. a fresh registry snapshot for the
                        // /tasks //task commands) in a scope, so its borrow of `runner` ends
                        // before `handle_action` takes `&mut runner`.
                        let dispatch = {
                            let snap = runner.snapshot(now);
                            let status = StatusSnapshot {
                                active_tasks: runner.len_active(),
                                budget_used_micros: 0,
                                budget_limit_micros: 0,
                                channel_healthy: true,
                            };
                            let ctx = DispatchCtx {
                                renderer: &renderer,
                                allowlist: &allowlist,
                                status: &status,
                                registry: &snap,
                                now,
                            };
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
                            let _ = api.send_message(o.chat, &o.text, o.keyboard.as_ref());
                        }
                        // A launch requested in PR mode is gated: it returns a `PendingTask`
                        // (approval requested + buttons sent) instead of starting now.
                        if let Some(pending) = handle_action(
                            dispatch.action,
                            &task_spec,
                            &mut runner,
                            pending_task.is_some(),
                            &mut approvals,
                            &mut next_approval_id,
                            &renderer,
                            &api,
                            now,
                        ) {
                            pending_task = Some(pending);
                        }
                    }
                }
                Err(e) => eprintln!("crustcore-daemon: poll error (retrying): {e}"),
            }

            std::thread::sleep(Duration::from_millis(config.poll_backoff_ms.max(50)));
        }
    }

    /// Performs a [`LoopAction`]. Returns `Some(PendingTask)` when a PR-mode launch was
    /// **gated** — the operator was asked to approve (buttons sent) and the task starts
    /// only once they do (invariant 14). A non-PR launch starts immediately and returns
    /// `None`.
    #[allow(clippy::too_many_arguments)]
    fn handle_action(
        action: Option<LoopAction>,
        task_spec: &Option<TaskSpec>,
        runner: &mut TaskRunner,
        approval_pending: bool,
        approvals: &mut crate::telegram::ApprovalEngine,
        next_approval_id: &mut u128,
        renderer: &OutboundRenderer,
        api: &LiveTelegramApi<RestTelegram>,
        now: Timestamp,
    ) -> Option<PendingTask> {
        match action {
            Some(LoopAction::LaunchTask {
                route,
                prompt,
                chat,
            }) => {
                if approval_pending {
                    let t = renderer
                        .notice("an approval is already pending — approve or deny it first.");
                    let _ = api.send_message(chat, &t, None);
                    return None;
                }
                match task_spec {
                    // PR mode: opening a draft PR is irreversible — gate the launch on a
                    // human approval. Register a nonce, send approve/deny buttons, and
                    // park the launch; nothing runs until the operator approves.
                    Some(spec) if spec.pr.is_some() => {
                        let approval_id = *next_approval_id;
                        *next_approval_id = next_approval_id.wrapping_add(1);
                        let op = format!("run this task and open a draft PR: {prompt}");
                        let expires = Timestamp::from_millis(
                            now.as_millis().saturating_add(PR_APPROVAL_TTL_MS),
                        );
                        let nonce = approvals.request(approval_id, &op, &op, expires);
                        let text = renderer.notice(&format!(
                            "🔒 This runs the task and, if it verifies, opens a *draft* PR — \
                             that needs your approval.\n• {op}"
                        ));
                        let kb = approval_keyboard(&nonce);
                        let _ = api.send_message(chat, &text, Some(&kb));
                        return Some(PendingTask {
                            prompt,
                            chat,
                            approval_id,
                            route,
                        });
                    }
                    // No PR target: a sandboxed verify is reversible — start it under the
                    // route's budget tier, subject to the concurrency cap (invariant 11).
                    Some(spec) => match runner.launch(
                        spec.clone(),
                        prompt,
                        chat,
                        None,
                        super::budget_for_route(route),
                        now,
                    ) {
                        Ok(id) => {
                            let t = renderer.notice(&format!("▶️ started task #{}.", id.0));
                            let _ = api.send_message(chat, &t, None);
                        }
                        Err(AdmitError::ConcurrencyCap) => {
                            let t = renderer.notice(&format!(
                                "at capacity ({MAX_CONCURRENT_TASKS} tasks running) — \
                                 /cancel one first, then retry."
                            ));
                            let _ = api.send_message(chat, &t, None);
                        }
                    },
                    None => {
                        let t = renderer.notice(
                            "I can chat here, but task execution needs a bound repo + verify \
                             command (start me with --dir and --verify).",
                        );
                        let _ = api.send_message(chat, &t, None);
                    }
                }
            }
            // Graceful cancel / hard kill resolve against the registry by id; `tick` (in
            // `pump`) executes the cooperative cancel or the hard teardown next cycle. The
            // registry re-checks ownership (defense in depth; dispatch_command already gated).
            Some(LoopAction::CancelTask { id, chat }) => {
                let _ = runner.cancel(id, chat);
            }
            Some(LoopAction::KillTask { id, chat }) => {
                let _ = runner.kill(id, chat);
            }
            None => {}
        }
        None
    }

    /// Resolves a PR-launch approval: on approve, mint the human-approved
    /// `Approved<GitHubWriteCap>` (invariant 14) and launch the task **with** it (so the
    /// verified patch opens a draft PR); on deny/expiry, report and run nothing. The
    /// engine has already validated allowlist/op-hash/expiry/single-use.
    #[allow(clippy::too_many_arguments)]
    fn resolve_pending_pr(
        pending: &PendingTask,
        decision: ApprovalResolution,
        op_hash: Option<[u8; 32]>,
        chat: ChatId,
        allowlist: &ChatAllowlist,
        approvals: &mut crate::telegram::ApprovalEngine,
        task_spec: &Option<TaskSpec>,
        runner: &mut TaskRunner,
        renderer: &OutboundRenderer,
        api: &LiveTelegramApi<RestTelegram>,
        now: Timestamp,
    ) {
        let outcome =
            approvals.resolve(pending.approval_id, decision, chat, allowlist, now, op_hash);
        match outcome {
            ApprovalOutcome::Approved(_) => {
                let target = task_spec.as_ref().and_then(|s| s.pr.clone());
                let expires =
                    Timestamp::from_millis(now.as_millis().saturating_add(PR_APPROVAL_TTL_MS));
                match (task_spec.clone(), target) {
                    (Some(spec), Some(t)) => {
                        match mint_github_write_cap(
                            allowlist,
                            chat,
                            &t.repo,
                            &t.branch_prefix,
                            pending.approval_id,
                            expires,
                        ) {
                            Some(cap) => match runner.launch(
                                spec,
                                pending.prompt.clone(),
                                pending.chat,
                                Some(cap),
                                super::budget_for_route(pending.route),
                                now,
                            ) {
                                Ok(_) => {
                                    let t = renderer.notice(
                                        "✅ approved — running; I'll open a draft PR if it verifies.",
                                    );
                                    let _ = api.send_message(chat, &t, None);
                                }
                                Err(AdmitError::ConcurrencyCap) => {
                                    let t = renderer.notice(
                                        "✅ approved, but at task capacity — retry once a task frees up.",
                                    );
                                    let _ = api.send_message(chat, &t, None);
                                }
                            },
                            None => {
                                let t = renderer
                                    .notice("⚠️ could not authorize a PR for this chat (ignored).");
                                let _ = api.send_message(chat, &t, None);
                            }
                        }
                    }
                    _ => {
                        let t = renderer.notice("⚠️ PR mode is not configured — nothing to run.");
                        let _ = api.send_message(chat, &t, None);
                    }
                }
            }
            // Denied / rejected (expired, op-mismatch, not-allowlisted): report; run nothing.
            other => {
                let t = render_approval_outcome(&other, renderer);
                let _ = api.send_message(chat, &t, None);
            }
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

/// Maps a parsed GitHub `/crustcore` command (E.2) onto a [`LoopAction`] — the **same**
/// actions Telegram produces (invariants 8, 16), so a GitHub command routes through the
/// identical dispatch + policy gates, **not a parallel ungoverned surface**. The command
/// was parsed by the daemon from an untrusted comment (never model output — invariant 4);
/// the goal/dir are bounded literals (invariant 7).
///
/// `route` is the execution route the caller classified the goal into (`Run`/`Retry`).
/// `Cancel` becomes an owner-scoped [`LoopAction::CancelTask`] (the runtime re-checks the
/// task owner against the registry, exactly as for Telegram `/cancel` — invariant 12).
/// `Explain` / `RiskDetected` produce no action (the caller answers with status / a
/// surfaced warning).
#[must_use]
pub fn github_command_to_action(
    cmd: &crate::github_commands::GithubCommand,
    chat: ChatId,
    route: ChatRoute,
) -> Option<LoopAction> {
    use crate::github_commands::GithubCommand;
    match cmd {
        GithubCommand::Run { goal, dir } => Some(LoopAction::LaunchTask {
            route,
            prompt: match dir {
                Some(d) => format!("{goal} (in {d})"),
                None => goal.clone(),
            },
            chat,
        }),
        GithubCommand::Retry { id } => Some(LoopAction::LaunchTask {
            route,
            prompt: format!("retry task {id}"),
            chat,
        }),
        GithubCommand::Cancel { id } => Some(LoopAction::CancelTask {
            chat,
            id: TaskId(*id),
        }),
        GithubCommand::Explain { .. } | GithubCommand::RiskDetected(_) => None,
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

    // ----- E.2: GitHub command -> LoopAction wiring -----

    #[test]
    fn github_run_maps_to_a_launch_task_with_the_goal() {
        use crate::github_commands::GithubCommand;
        let act = github_command_to_action(
            &GithubCommand::Run {
                goal: "fix the bug".to_string(),
                dir: Some("crates/foo".to_string()),
            },
            ChatId(7),
            ChatRoute::Feature,
        );
        assert_eq!(
            act,
            Some(LoopAction::LaunchTask {
                route: ChatRoute::Feature,
                prompt: "fix the bug (in crates/foo)".to_string(),
                chat: ChatId(7),
            })
        );
    }

    #[test]
    fn github_cancel_is_owner_scoped_and_explain_or_risk_are_no_ops() {
        use crate::github_commands::GithubCommand;
        // Cancel routes to the SAME owner-scoped CancelTask as Telegram /cancel.
        assert_eq!(
            github_command_to_action(
                &GithubCommand::Cancel { id: 5 },
                ChatId(7),
                ChatRoute::Feature
            ),
            Some(LoopAction::CancelTask {
                chat: ChatId(7),
                id: TaskId(5),
            })
        );
        // Explain + a RiskDetected (malformed) command never produce an action.
        assert!(github_command_to_action(
            &GithubCommand::Explain { id: 1 },
            ChatId(7),
            ChatRoute::Feature
        )
        .is_none());
        assert!(github_command_to_action(
            &GithubCommand::RiskDetected("bad".to_string()),
            ChatId(7),
            ChatRoute::Feature
        )
        .is_none());
    }

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
        let registry = RegistrySnapshot::default();
        let ctx = DispatchCtx {
            renderer: &renderer,
            allowlist,
            status: &st,
            registry: &registry,
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
    fn cancel_command_requests_cancel_action_for_an_owned_task() {
        let reg = RegistrySnapshot {
            rows: vec![task_row(5, TaskPhase::Running)], // owned by chat 7
        };
        let d = drive_cmd(&reg, Command::Cancel(5));
        assert_eq!(
            d.action,
            Some(LoopAction::CancelTask {
                chat: ChatId(7),
                id: TaskId(5),
            })
        );
    }

    #[test]
    fn cancel_kill_of_an_unowned_or_missing_task_emits_no_action() {
        // No such task → no action.
        let empty = RegistrySnapshot::default();
        let d = drive_cmd(&empty, Command::Cancel(5));
        assert_eq!(d.action, None);
        assert!(d.outbound[0].text.as_str().contains("no task #5"));

        // A task owned by a DIFFERENT chat → the requester (chat 7) cannot cancel/kill it.
        let other = RegistrySnapshot {
            rows: vec![crate::registry::TaskRow {
                id: TaskId(5),
                chat: ChatId(999),
                phase: TaskPhase::Running,
                wall_ms: 0,
                output_bytes: 0,
                lease_ttl_ms: 1000,
            }],
        };
        assert_eq!(drive_cmd(&other, Command::Cancel(5)).action, None);
        assert_eq!(drive_cmd(&other, Command::Kill(5)).action, None);
    }

    fn task_row(id: u64, phase: TaskPhase) -> crate::registry::TaskRow {
        crate::registry::TaskRow {
            id: TaskId(id),
            chat: ChatId(7),
            phase,
            wall_ms: 1234,
            output_bytes: 50,
            lease_ttl_ms: 42_000,
        }
    }

    /// Drive a `/command` through the dispatch core with a supplied registry snapshot.
    fn drive_cmd(registry: &RegistrySnapshot, cmd: Command) -> Dispatch {
        let broker = SecretBroker::new(InMemoryStore::new());
        let allow = ChatAllowlist::of(&[7]);
        let mut approvals = ApprovalEngine::new();
        let renderer = OutboundRenderer::new(broker.redactor());
        let mut bridge = ChatBridge::new(broker.redactor(), ChatConfig::default());
        let st = status();
        let ctx = DispatchCtx {
            renderer: &renderer,
            allowlist: &allow,
            status: &st,
            registry,
            now: Timestamp::from_millis(1000),
        };
        let mut model = |_req: &CompleteRequest| None;
        dispatch_event(
            ChatId(7),
            RuntimeEvent::Command(cmd),
            &mut bridge,
            &mut approvals,
            &ctx,
            &mut model,
        )
    }

    #[test]
    fn tasks_lists_active_tasks_from_the_registry() {
        let reg = RegistrySnapshot {
            rows: vec![
                task_row(1, TaskPhase::Running),
                task_row(2, TaskPhase::Pending),
            ],
        };
        let text = drive_cmd(&reg, Command::Tasks).outbound[0]
            .text
            .as_str()
            .to_string();
        assert!(text.contains("2 task(s)"), "got: {text}");
        assert!(text.contains("#1 [running]"));
        assert!(text.contains("#2 [pending]"));
    }

    #[test]
    fn empty_registry_reports_no_tasks() {
        let d = drive_cmd(&RegistrySnapshot::default(), Command::Tasks);
        assert!(d.outbound[0].text.as_str().contains("no active tasks"));
    }

    #[test]
    fn task_detail_shows_one_or_reports_missing() {
        let reg = RegistrySnapshot {
            rows: vec![task_row(3, TaskPhase::Running)],
        };
        assert!(drive_cmd(&reg, Command::Task(3)).outbound[0]
            .text
            .as_str()
            .contains("task #3"));
        assert!(drive_cmd(&reg, Command::Task(9)).outbound[0]
            .text
            .as_str()
            .contains("no task #9"));
    }

    #[test]
    fn budget_for_route_is_tiered_by_complexity() {
        use crustcore_chat::ChatRoute;
        // A quick fix gets a tighter budget than a feature, which is tighter than a project.
        let quick = budget_for_route(ChatRoute::QuickFix);
        let feature = budget_for_route(ChatRoute::Feature);
        let project = budget_for_route(ChatRoute::Project);
        assert!(quick.max_wall_ms < feature.max_wall_ms);
        assert!(feature.max_wall_ms < project.max_wall_ms);
        assert!(quick.max_output_bytes < project.max_output_bytes);
        // Continue maps to the Feature tier (true resumption is a separate seam).
        assert_eq!(
            budget_for_route(ChatRoute::Continue).max_wall_ms,
            feature.max_wall_ms
        );
    }

    #[test]
    fn kill_command_emits_kill_action_for_an_owned_task() {
        let reg = RegistrySnapshot {
            rows: vec![task_row(8, TaskPhase::Running)], // owned by chat 7
        };
        let d = drive_cmd(&reg, Command::Kill(8));
        assert_eq!(
            d.action,
            Some(LoopAction::KillTask {
                chat: ChatId(7),
                id: TaskId(8),
            })
        );
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

    #[test]
    fn a_converse_answer_carries_a_steer_button() {
        let broker = SecretBroker::new(InMemoryStore::new());
        let allow = ChatAllowlist::of(&[7]);
        let mut approvals = ApprovalEngine::new();
        let mut model = |_req: &CompleteRequest| Some("here's the answer".to_string());
        let d = drive(
            &broker,
            &allow,
            &mut approvals,
            RuntimeEvent::QueuedTurn(bt("what's up?")),
            &mut model,
        );
        let kb = d.outbound[0]
            .keyboard
            .as_ref()
            .expect("a converse answer carries a 🛑 Steer button");
        assert!(kb
            .rows
            .iter()
            .flatten()
            .any(|(_, data)| data == crate::chat::STEER_BUTTON_DATA));
    }

    #[test]
    fn steer_button_event_arms_and_acknowledges() {
        let broker = SecretBroker::new(InMemoryStore::new());
        let allow = ChatAllowlist::of(&[7]);
        let mut approvals = ApprovalEngine::new();
        let mut model = |_req: &CompleteRequest| None;
        let d = drive(
            &broker,
            &allow,
            &mut approvals,
            RuntimeEvent::SteerButton,
            &mut model,
        );
        assert!(d.outbound[0].text.as_str().contains("steer armed"));
        assert!(d.action.is_none());
    }

    #[test]
    fn mint_github_write_cap_requires_an_allowlisted_chat() {
        let allow = ChatAllowlist::of(&[7]);
        let cap = mint_github_write_cap(
            &allow,
            ChatId(7),
            "owner/repo",
            "crustcore",
            5,
            Timestamp::from_millis(10_000),
        )
        .expect("an allowlisted chat mints a cap");
        assert_eq!(cap.value().repo.0.as_str(), "owner/repo");
        assert_eq!(cap.value().branch_prefix.0.as_str(), "crustcore");
        assert!(cap.is_valid_at(Timestamp::from_millis(1000)));
        // A non-allowlisted chat gets NO GitHub write authority (invariant 4).
        assert!(mint_github_write_cap(
            &ChatAllowlist::deny_all(),
            ChatId(7),
            "owner/repo",
            "crustcore",
            5,
            Timestamp::from_millis(10_000),
        )
        .is_none());
    }

    #[test]
    fn pr_approval_match_recognizes_callback_and_commands() {
        let cb = CallbackData {
            approval_id: 9,
            decision: ApprovalResolution::Approve,
            op_hash: [0u8; 32],
        };
        assert_eq!(
            pr_approval_match(&RuntimeEvent::ApprovalCallback(cb), 9),
            Some((ApprovalResolution::Approve, Some([0u8; 32])))
        );
        assert_eq!(
            pr_approval_match(&RuntimeEvent::Command(Command::Deny(9)), 9),
            Some((ApprovalResolution::Deny, None))
        );
        // A different id or an unrelated event never matches.
        assert_eq!(
            pr_approval_match(&RuntimeEvent::Command(Command::Approve(8)), 9),
            None
        );
        assert_eq!(
            pr_approval_match(&RuntimeEvent::Command(Command::Help), 9),
            None
        );
    }

    #[test]
    fn approval_keyboard_buttons_are_operation_bound() {
        // The approve/deny buttons carry the nonce-bound callback_data, so a tap is
        // op-bound exactly like the `/approve` command path.
        let mut approvals = ApprovalEngine::new();
        let nonce = approvals.request(9, "merge x", "merge x", Timestamp::from_millis(10_000));
        let kb = approval_keyboard(&nonce);
        let datas: Vec<&str> = kb.rows.iter().flatten().map(|(_, d)| d.as_str()).collect();
        assert!(datas.iter().any(|d| d.starts_with("ap:9:approve:")));
        assert!(datas.iter().any(|d| d.starts_with("ap:9:deny:")));
    }
}
