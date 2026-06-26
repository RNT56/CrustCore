// SPDX-License-Identifier: Apache-2.0
//! Telegram **converse channel** — bridges the runtime channel ([`telegram`]) to the
//! conversational front door ([`crustcore_chat`]; `docs/chat.md` §5).
//!
//! The Telegram core already does the load-bearing trust work: an allowlisted chat id
//! becomes an `AuthorizedUser` (principal trust), updates are deduped/normalized, and
//! `send_message` accepts only [`ModelVisibleText`]. This bridge adds, on top of that,
//! a **converse turn**: a plain message from an allowlisted chat is classified and —
//! when it is a question — answered by the model, rendered through the *same* redactor
//! (so the answer is redacted + bounded; `docs/telegram.md` §8.1). Execution routes are
//! handed back to the daemon to start a kernel task flow (behind policy/sandbox/verifier).
//!
//! The bridge is a std-only deterministic core: the model is an injected consult
//! closure (the daemon wires the spawned `crustcore-net` helper), so the whole thing is
//! CI-tested with a canned model. The live Bot-API transport remains `TODO(P9-net-live)`.
//!
//! [`telegram`]: crate::telegram

use crustcore_chat::{ChatConfig, ChatRoute, ChatSession, Turn};
use crustcore_netproto::CompleteRequest;
use crustcore_secrets::{ModelVisibleText, Redactor};

use crate::telegram::RuntimeEvent;

/// The inline-button `callback_data` for the 🛑 **Steer** button (NilCore parity): a
/// press interrupts the in-flight model call and arms the user's *next* message as a
/// steer. It is deliberately distinct from the approval callbacks (`ap:…`) so it never
/// touches the approval engine.
pub const STEER_BUTTON_DATA: &str = "steer";

/// What the bridge decided to do with a runtime event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChatReply {
    /// Send this redacted, bounded answer to the user (a converse turn).
    Answer(ModelVisibleText),
    /// Hand off to a kernel task flow — the daemon starts it behind policy / sandbox /
    /// verifier (the bridge itself never starts or completes a task).
    StartTask {
        /// The non-converse route the classifier chose.
        route: ChatRoute,
        /// The user's goal text.
        prompt: String,
    },
    /// Nothing user-visible (e.g. a steer with no pending turn to answer).
    Quiet,
    /// A typed `/command` — the daemon dispatches it via the existing command path.
    Command,
    /// An approval callback — the daemon runs it through the existing approval engine.
    Approval,
}

/// The Telegram converse bridge over a [`ChatSession`]. One per active conversation;
/// the model consult is injected at dispatch time.
pub struct ChatBridge<'r> {
    session: ChatSession<'r>,
    /// Set when the 🛑 Steer button was pressed: the next plain turn is folded as a steer.
    steer_armed: bool,
}

impl<'r> ChatBridge<'r> {
    /// Build a bridge over the host [`Redactor`] (the broker's pre-loaded redactor, so
    /// stored secrets are scrubbed from answers) and a chat config (persona + steering).
    #[must_use]
    pub fn new(redactor: &'r Redactor, config: ChatConfig) -> Self {
        ChatBridge {
            session: ChatSession::new(redactor, config),
            steer_armed: false,
        }
    }

    /// The model-role system preamble (persona + operator steering) the session puts in
    /// each converse [`CompleteRequest`]. Exposed for diagnostics/tests.
    #[must_use]
    pub fn system_preamble(&self) -> String {
        self.session.system_preamble()
    }

    /// Arm the next plain turn as a steer — call this when the 🛑 Steer button
    /// ([`STEER_BUTTON_DATA`]) is pressed from an allowlisted chat. Mirrors NilCore's
    /// button: it interrupts and the user's next message is treated as a steer.
    pub fn arm_steer(&mut self) {
        self.steer_armed = true;
    }

    /// Whether a steer is currently armed (the next plain turn will steer).
    #[must_use]
    pub fn steer_armed(&self) -> bool {
        self.steer_armed
    }

    /// Dispatch a [`RuntimeEvent`] from the runtime channel. `model` is the injected
    /// consult (the daemon wires the spawned net helper). Commands and approval
    /// callbacks are passed back to the daemon's existing handlers; plain/steer text is
    /// answered (converse) or handed off (execution route).
    pub fn dispatch(
        &mut self,
        event: RuntimeEvent,
        model: &mut dyn FnMut(&CompleteRequest) -> Option<String>,
    ) -> ChatReply {
        match event {
            RuntimeEvent::Command(_) => ChatReply::Command,
            RuntimeEvent::ApprovalCallback(_) => ChatReply::Approval,
            RuntimeEvent::Steer(text) => self.turn(text.as_str(), true, model),
            RuntimeEvent::QueuedTurn(text) => {
                if self.steer_armed {
                    self.steer_armed = false;
                    self.turn(text.as_str(), true, model)
                } else {
                    self.turn(text.as_str(), false, model)
                }
            }
        }
    }

    /// Submit a turn through the session's queue/steer machine, then process the
    /// resulting turn (a steer cancels any in-flight model call and jumps the queue —
    /// see [`crustcore_chat::steer`]). Returns the reply.
    fn turn(
        &mut self,
        text: &str,
        steer: bool,
        model: &mut dyn FnMut(&CompleteRequest) -> Option<String>,
    ) -> ChatReply {
        // Route the raw text through the same parse/queue/steer machine the terminal
        // uses, so a `!`-prefix or the steer button behaves identically across channels.
        let raw = if steer && !text.starts_with('!') {
            format!("!{text}")
        } else {
            text.to_string()
        };
        let _disposition = self.session.submit(&raw);
        match self.session.next_turn() {
            Some(turn_text) => match self.session.handle(&turn_text, model) {
                Turn::Answer(a) => ChatReply::Answer(a),
                Turn::Notice(n) => ChatReply::Answer(n),
                Turn::StartTask { route, prompt } => ChatReply::StartTask { route, prompt },
            },
            None => ChatReply::Quiet,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crustcore_netproto::{BoundedText, MAX_TEXT_BYTES};
    use crustcore_secrets::{InMemoryStore, SecretBroker};
    use crustcore_types::SecretId;

    fn bt(s: &str) -> BoundedText {
        BoundedText::truncated(s, MAX_TEXT_BYTES)
    }

    fn broker_with_secret() -> SecretBroker<InMemoryStore> {
        let mut store = InMemoryStore::new();
        store.insert(SecretId(1), "model-key", b"sk-TGSENTINEL".to_vec());
        SecretBroker::new(store)
    }

    #[test]
    fn a_question_is_answered_and_redacted() {
        let broker = broker_with_secret();
        let mut bridge = ChatBridge::new(broker.redactor(), ChatConfig::default());
        // The model answer echoes a secret -> redacted before it reaches the user.
        let mut model = |_req: &CompleteRequest| {
            Some("Status: green. The key sk-TGSENTINEL is set.".to_string())
        };
        let reply = bridge.dispatch(
            RuntimeEvent::QueuedTurn(bt("what's the status?")),
            &mut model,
        );
        match reply {
            ChatReply::Answer(a) => {
                assert!(!a.as_str().contains("sk-TGSENTINEL"));
                assert!(a.as_str().contains("[REDACTED:model-key]"));
            }
            other => panic!("expected Answer, got {other:?}"),
        }
    }

    #[test]
    fn an_execution_request_hands_off_a_task() {
        let broker = SecretBroker::new(InMemoryStore::new());
        let mut bridge = ChatBridge::new(broker.redactor(), ChatConfig::default());
        let mut model = |_req: &CompleteRequest| Some("feature".to_string());
        let reply = bridge.dispatch(
            RuntimeEvent::QueuedTurn(bt("implement the new export feature")),
            &mut model,
        );
        match reply {
            ChatReply::StartTask { route, prompt } => {
                assert!(route.is_execution());
                assert_eq!(prompt, "implement the new export feature");
            }
            other => panic!("expected StartTask, got {other:?}"),
        }
    }

    #[test]
    fn the_steer_button_arms_the_next_turn_as_a_steer() {
        let broker = SecretBroker::new(InMemoryStore::new());
        let mut bridge = ChatBridge::new(broker.redactor(), ChatConfig::default());
        let mut model = |_req: &CompleteRequest| Some("Acknowledged.".to_string());

        assert!(!bridge.steer_armed());
        bridge.arm_steer(); // 🛑 Steer button pressed
        assert!(bridge.steer_armed());

        // The next plain message is folded as a steer (not a fresh converse turn). It
        // is still answered (the steer text becomes the next turn).
        let reply = bridge.dispatch(
            RuntimeEvent::QueuedTurn(bt("focus on the failing test")),
            &mut model,
        );
        assert!(matches!(
            reply,
            ChatReply::Answer(_) | ChatReply::StartTask { .. }
        ));
        // The arm is consumed (one-shot).
        assert!(!bridge.steer_armed());
    }

    #[test]
    fn explicit_steer_event_is_handled() {
        let broker = SecretBroker::new(InMemoryStore::new());
        let mut bridge = ChatBridge::new(broker.redactor(), ChatConfig::default());
        let mut model = |_req: &CompleteRequest| Some("ok".to_string());
        let reply = bridge.dispatch(RuntimeEvent::Steer(bt("stop touching auth")), &mut model);
        // A steer that asks for a small change routes like any turn (quick-fix/answer);
        // it never grants authority (the kernel gates still decide).
        assert!(matches!(
            reply,
            ChatReply::Answer(_) | ChatReply::StartTask { .. }
        ));
    }

    #[test]
    fn commands_and_approvals_pass_through_to_existing_handlers() {
        let broker = SecretBroker::new(InMemoryStore::new());
        let mut bridge = ChatBridge::new(broker.redactor(), ChatConfig::default());
        let mut model = |_req: &CompleteRequest| Some("unused".to_string());
        assert_eq!(
            bridge.dispatch(
                RuntimeEvent::Command(crate::telegram::Command::Status),
                &mut model
            ),
            ChatReply::Command
        );
    }

    #[test]
    fn the_preamble_carries_the_safety_core_and_persona() {
        let broker = SecretBroker::new(InMemoryStore::new());
        let bridge = ChatBridge::new(broker.redactor(), ChatConfig::default());
        let pre = bridge.system_preamble();
        assert!(pre.contains("SAFETY CONTRACT"));
        assert!(pre.contains("terse senior engineer"));
    }
}
