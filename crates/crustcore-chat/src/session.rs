// SPDX-License-Identifier: Apache-2.0
//! The chat session — the single conversational front door tying routing, persona,
//! converse rendering, and queue/steer together.
//!
//! [`ChatSession`] is the deterministic orchestration core. It owns no I/O: the model
//! is reached through an injected [`ConsultFn`] closure (the live layer wires this to
//! the spawned `crustcore-net` helper), so the whole pipeline is CI-testable with a
//! canned consult. It produces typed [`Turn`]s the channel layer renders or acts on —
//! never raw model text directly.

use crustcore_netproto::{CompleteRequest, Require, Role};
use crustcore_secrets::{ModelVisibleText, Redactor};
use crustcore_types::BoundedText;

use crate::converse::ConverseRenderer;
use crate::persona::{OperatorSteering, Persona};
use crate::route::{ChatRoute, Classifier};
use crate::steer::{Activity, Disposition, Inbound, TurnQueue};

/// The injected model consult: given a [`CompleteRequest`], return the model's raw
/// (untrusted) text, or [`None`] on failure. The live channel layer adapts the spawned
/// net helper's `complete` to this shape; tests pass a closure.
pub type ConsultFn<'a> = dyn FnMut(&CompleteRequest) -> Option<String> + 'a;

/// Per-session configuration: the personality, operator steering, and converse
/// rendering posture. Defaults to the terse-senior-engineer voice, no steering,
/// reasoning hidden — the safe defaults.
#[derive(Debug, Clone)]
pub struct ChatConfig {
    /// The model-role personality.
    pub persona: Persona,
    /// Operator steering (`CRUSTCORE.md`/`AGENTS.md`), scoped below the safety core.
    pub steering: OperatorSteering,
    /// Full-parity option: stream the model's reasoning text (still redacted+bounded).
    pub reveal_reasoning: bool,
    /// Per-answer byte bound.
    pub max_answer_bytes: usize,
    /// Output-token ceiling for a converse answer.
    pub answer_max_tokens: u32,
}

impl Default for ChatConfig {
    fn default() -> Self {
        ChatConfig {
            persona: Persona::terse_senior_engineer(),
            steering: OperatorSteering::none(),
            reveal_reasoning: false,
            max_answer_bytes: crate::converse::MAX_CONVERSE_BYTES,
            answer_max_tokens: 1024,
        }
    }
}

/// What handling a user message produced. The channel layer renders/acts on these; it
/// never receives raw model text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Turn {
    /// A converse answer — redacted, bounded model-visible text to show the user.
    Answer(ModelVisibleText),
    /// A routed action: start a kernel task flow of this kind with `prompt`. The chat
    /// crate does NOT start it — that is the daemon/kernel's job, behind the policy,
    /// approval, sandbox, and verifier gates (invariants 8, 9, 13).
    StartTask {
        /// The non-converse route the classifier chose.
        route: ChatRoute,
        /// The user's (bounded) goal text.
        prompt: String,
    },
    /// A model-/user-visible notice from the chat layer itself (e.g. a converse call
    /// failed). Redacted + bounded.
    Notice(ModelVisibleText),
}

/// The conversational front door.
pub struct ChatSession<'r> {
    config: ChatConfig,
    redactor: &'r Redactor,
    queue: TurnQueue,
    activity: Activity,
}

impl<'r> ChatSession<'r> {
    /// Build a session over the host [`Redactor`] (the broker's pre-loaded redactor)
    /// and a config.
    #[must_use]
    pub fn new(redactor: &'r Redactor, config: ChatConfig) -> Self {
        ChatSession {
            config,
            redactor,
            queue: TurnQueue::new(),
            activity: Activity::Idle,
        }
    }

    /// The model-role system preamble for this session (safety core + persona +
    /// steering). The live layer puts this in [`CompleteRequest::system`].
    #[must_use]
    pub fn system_preamble(&self) -> String {
        self.config
            .persona
            .system_preamble(Some(&self.config.steering))
    }

    /// The current activity (what a steer would cancel/buffer).
    #[must_use]
    pub fn activity(&self) -> Activity {
        self.activity
    }

    /// Record what the agent is currently doing (the live loop calls this around model
    /// calls and tool runs so steer routing is correct).
    pub fn set_activity(&mut self, activity: Activity) {
        self.activity = activity;
    }

    /// Admit a raw inbound message through the queue/steer state machine, returning the
    /// [`Disposition`] the live loop must act on (cancel a model call, buffer, etc.).
    /// This does **not** call the model — it is the synchronous routing decision.
    pub fn submit(&mut self, raw: &str) -> Disposition {
        let inbound = Inbound::parse(raw);
        self.queue.admit(&inbound, self.activity)
    }

    /// Pop the next pending turn text (FIFO modulo steer front-jumps).
    pub fn next_turn(&mut self) -> Option<String> {
        self.queue.pop_next()
    }

    /// Cancel the active run: drop all pending/queued turns and return to idle (the
    /// `/cancel` path — aborts the run but keeps the conversation alive).
    pub fn cancel(&mut self) {
        self.queue.clear();
        self.activity = Activity::Idle;
    }

    /// Process one user turn end to end: classify it, and either produce a converse
    /// [`Turn::Answer`] (calling the model through `model`) or a [`Turn::StartTask`]
    /// for an execution route. The classifier uses the same `model` consult; a failed
    /// or unparseable classification falls back to the heuristic (never an error).
    pub fn handle(&mut self, message: &str, model: &mut ConsultFn<'_>) -> Turn {
        let route = Classifier::classify(message, Some(&mut *model));
        if route.is_execution() {
            return Turn::StartTask {
                route,
                prompt: message.to_string(),
            };
        }
        self.converse(message, model)
    }

    /// Run a converse turn: ask the model for an answer (with the persona preamble) and
    /// render it through the redact→bound boundary. A failed call yields a redacted
    /// [`Turn::Notice`] rather than nothing.
    fn converse(&mut self, message: &str, model: &mut ConsultFn<'_>) -> Turn {
        let req = CompleteRequest {
            role: Role::Research,
            system: BoundedText::truncated(self.system_preamble(), BoundedText::DEFAULT_MAX),
            prompt: BoundedText::truncated(message, BoundedText::DEFAULT_MAX),
            max_tokens: self.config.answer_max_tokens,
            stream: true,
            max_cost_micros: 0,
            require: Require::default(),
        };
        let renderer = ConverseRenderer::new(self.redactor)
            .with_max(self.config.max_answer_bytes)
            .reveal_reasoning(self.config.reveal_reasoning);
        match model(&req) {
            Some(raw) => Turn::Answer(renderer.render_answer(&raw)),
            None => Turn::Notice(
                self.redactor
                    .to_model_visible("(the model could not be reached for this turn)"),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crustcore_secrets::{InMemoryStore, SecretBroker};
    use crustcore_types::SecretId;

    fn broker() -> SecretBroker<InMemoryStore> {
        let mut store = InMemoryStore::new();
        store.insert(SecretId(1), "model-key", b"sk-SESSIONSENTINEL".to_vec());
        SecretBroker::new(store)
    }

    #[test]
    fn converse_question_returns_a_redacted_answer() {
        let b = broker();
        let mut s = ChatSession::new(b.redactor(), ChatConfig::default());
        // The model echoes a secret in its answer -> redacted before the user sees it.
        let mut model = |_req: &CompleteRequest| {
            Some("It's running fine; the token sk-SESSIONSENTINEL is set.".to_string())
        };
        let turn = s.handle("what is the status?", &mut model);
        match turn {
            Turn::Answer(a) => {
                assert!(!a.as_str().contains("SESSIONSENTINEL"));
                assert!(a.as_str().contains("[REDACTED:model-key]"));
            }
            other => panic!("expected Answer, got {other:?}"),
        }
    }

    #[test]
    fn execution_route_starts_a_task_does_not_converse() {
        let b = broker();
        let mut s = ChatSession::new(b.redactor(), ChatConfig::default());
        // A clear build ask routes to a task; the model consult is NOT used to answer.
        let mut model = |_req: &CompleteRequest| Some("feature".to_string());
        let turn = s.handle("implement the new export feature", &mut model);
        match turn {
            Turn::StartTask { route, prompt } => {
                assert!(route.is_execution());
                assert_eq!(prompt, "implement the new export feature");
            }
            other => panic!("expected StartTask, got {other:?}"),
        }
    }

    #[test]
    fn the_system_preamble_carries_persona_and_safety() {
        let b = broker();
        let cfg = ChatConfig {
            steering: OperatorSteering::from_content("Prefer minimal diffs."),
            ..ChatConfig::default()
        };
        let s = ChatSession::new(b.redactor(), cfg);
        let pre = s.system_preamble();
        assert!(pre.contains("SAFETY CONTRACT"));
        assert!(pre.contains("terse senior engineer"));
        assert!(pre.contains("Prefer minimal diffs"));
    }

    #[test]
    fn converse_failure_yields_a_notice_not_a_panic() {
        let b = broker();
        let mut s = ChatSession::new(b.redactor(), ChatConfig::default());
        let mut model = |_req: &CompleteRequest| None;
        let turn = s.handle("what's up?", &mut model);
        assert!(matches!(turn, Turn::Notice(_)));
    }

    #[test]
    fn steer_routing_runs_through_the_session() {
        let b = broker();
        let mut s = ChatSession::new(b.redactor(), ChatConfig::default());
        s.set_activity(Activity::ModelInFlight);
        assert_eq!(
            s.submit("!focus on the failing test"),
            Disposition::SteerCancelModel
        );
        s.set_activity(Activity::ToolRunning);
        assert_eq!(s.submit("!actually stop"), Disposition::SteerBuffered);
        // The model-in-flight steer jumped ahead of the tool-buffered one.
        assert_eq!(s.next_turn().as_deref(), Some("focus on the failing test"));
    }
}
