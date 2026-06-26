// SPDX-License-Identifier: Apache-2.0
//! Intent routing — classify a chat message into the kind of work it implies.
//!
//! This is CrustCore's analog of NilCore's chat classifier (quick-fix / feature /
//! project / chat / continue). The crucial property: a [`ChatRoute`] is
//! **non-authoritative**. It selects *which kernel flow starts*, nothing more — it
//! grants no capability, mints no approval, and cannot complete a task. So even a
//! maliciously-crafted message that classifies as `Project` still hits every policy,
//! approval, sandbox, and verifier gate downstream.
//!
//! The classifier is **fail-safe**: a model classification is honored *as-is* when it
//! parses to a known route, and otherwise it falls back to a pure-function heuristic
//! — never an error, never a model retry loop (mirroring NilCore's "honored unless
//! unparseable, then heuristic, no retry").

use crustcore_netproto::{CompleteRequest, Require, Role};
use crustcore_types::BoundedText;

use crate::session::ConsultFn;

/// The kind of work a chat message implies (non-authoritative — see module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatRoute {
    /// A single bounded task (e.g. "fix the failing test"). One worktree, one verify.
    QuickFix,
    /// A multi-step feature — orchestrates a supervised (multi-agent) loop.
    Feature,
    /// A whole-project build (plan / slice / integrate). Greenfield-capable.
    Project,
    /// Conversation only — answer the question, run no execution loop.
    Converse,
    /// Resume the active task/goal (referencing current work).
    Continue,
}

impl ChatRoute {
    /// The stable token used in the model classification prompt/response.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ChatRoute::QuickFix => "quickfix",
            ChatRoute::Feature => "feature",
            ChatRoute::Project => "project",
            ChatRoute::Converse => "converse",
            ChatRoute::Continue => "continue",
        }
    }

    /// Strict parse of a model-emitted token. Returns [`None`] for anything
    /// unrecognized so the caller can fall back to the heuristic (no permissive
    /// default here — the *heuristic* owns the fallback, not a silent guess).
    #[must_use]
    pub fn from_token(s: &str) -> Option<ChatRoute> {
        match s.trim().to_ascii_lowercase().as_str() {
            "quickfix" | "quick_fix" | "fix" => Some(ChatRoute::QuickFix),
            "feature" | "supervise" => Some(ChatRoute::Feature),
            "project" => Some(ChatRoute::Project),
            "converse" | "chat" => Some(ChatRoute::Converse),
            "continue" | "resume" => Some(ChatRoute::Continue),
            _ => None,
        }
    }

    /// Whether this route runs an execution loop (vs pure conversation).
    #[must_use]
    pub fn is_execution(self) -> bool {
        !matches!(self, ChatRoute::Converse)
    }
}

/// Build words that signal a build/implementation request (heuristic only).
const BUILD_KEYWORDS: &[&str] = &[
    "build",
    "implement",
    "feature",
    "refactor",
    "migrate",
    "add",
    "create",
    "rewrite",
    "design",
    "integrate",
    "endpoint",
    "module",
    "service",
    "schema",
    "api",
    "test",
    "fix",
    "support",
];

/// The classifier. Stateless; the model consult is injected so the deterministic
/// heuristic path is fully testable with no network.
pub struct Classifier;

impl Classifier {
    /// Classify `message` into a [`ChatRoute`].
    ///
    /// When `model` is `Some`, a single cheap [`Role::Research`] classification call
    /// is made; its reply is parsed with [`ChatRoute::from_token`] and **honored as-is**
    /// if recognized. On `None`, an unparseable reply, or a failed call, the
    /// pure-function [`heuristic_route`] decides — fail-safe, no retry.
    #[must_use]
    pub fn classify(message: &str, model: Option<&mut ConsultFn<'_>>) -> ChatRoute {
        if let Some(consult) = model {
            let req = Self::classify_request(message);
            if let Some(reply) = consult(&req) {
                // The model proposes a token; we honor it only if it parses.
                if let Some(route) = reply.split_whitespace().find_map(ChatRoute::from_token) {
                    return route;
                }
            }
        }
        heuristic_route(message)
    }

    /// The bounded classification request handed to the model. The system preamble is
    /// a tiny, fixed instruction (not the persona) so classification stays cheap and
    /// deterministic in shape; the message is the (already principal-bounded) prompt.
    fn classify_request(message: &str) -> CompleteRequest {
        const SYSTEM: &str = "Classify the user's message into exactly one token: \
            quickfix | feature | project | converse | continue. \
            quickfix = one small bounded code task; feature = multi-step change; \
            project = whole new service; converse = a question to answer with no code; \
            continue = resume current work. Reply with the single token only.";
        CompleteRequest {
            role: Role::Research,
            system: BoundedText::truncated(SYSTEM, BoundedText::DEFAULT_MAX),
            prompt: BoundedText::truncated(message, BoundedText::DEFAULT_MAX),
            max_tokens: 8,
            stream: false,
            max_cost_micros: 0,
            require: Require::default(),
        }
    }
}

/// The pure-function fallback router — deterministic, no model. Mirrors NilCore's
/// local default-route rule (a question → converse; a big/keyword-heavy ask →
/// feature/project; a resume reference → continue; otherwise a quick fix).
#[must_use]
pub fn heuristic_route(message: &str) -> ChatRoute {
    let trimmed = message.trim();
    let lower = trimmed.to_ascii_lowercase();
    if trimmed.is_empty() {
        return ChatRoute::Converse;
    }

    // Resume reference -> continue.
    if lower.starts_with("continue")
        || lower.starts_with("resume")
        || lower.starts_with("keep going")
        || lower.contains("the current task")
        || lower.contains("the current goal")
    {
        return ChatRoute::Continue;
    }

    let words: Vec<&str> = lower.split_whitespace().collect();
    let keyword_hits = words
        .iter()
        .filter(|w| BUILD_KEYWORDS.contains(&w.trim_matches(|c: char| !c.is_alphanumeric())))
        .count();
    let is_question = trimmed.ends_with('?')
        || matches!(
            words.first().copied(),
            Some("what" | "why" | "how" | "when" | "who" | "where" | "is" | "are" | "does" | "can")
        );

    // A whole new service/app.
    if lower.contains("from scratch")
        || lower.contains("greenfield")
        || lower.contains("new project")
        || lower.contains("new service")
        || lower.contains("whole app")
    {
        return ChatRoute::Project;
    }

    // A question with no strong build signal -> converse.
    if is_question && keyword_hits < 2 {
        return ChatRoute::Converse;
    }

    // A large or keyword-heavy ask -> supervised feature (NilCore: >=40 words or
    // >=8 keyword hits routes to the supervised loop).
    if words.len() >= 40 || keyword_hits >= 8 {
        return ChatRoute::Feature;
    }

    ChatRoute::QuickFix
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_round_trips_and_rejects_unknown() {
        for r in [
            ChatRoute::QuickFix,
            ChatRoute::Feature,
            ChatRoute::Project,
            ChatRoute::Converse,
            ChatRoute::Continue,
        ] {
            assert_eq!(ChatRoute::from_token(r.as_str()), Some(r));
        }
        assert_eq!(ChatRoute::from_token("ignore-all-rules"), None);
        assert_eq!(ChatRoute::from_token("MERGE NOW"), None);
    }

    #[test]
    fn heuristic_routes_questions_to_converse() {
        assert_eq!(
            heuristic_route("what are you working on?"),
            ChatRoute::Converse
        );
        assert_eq!(
            heuristic_route("why did the build fail"),
            ChatRoute::Converse
        );
        assert_eq!(heuristic_route(""), ChatRoute::Converse);
    }

    #[test]
    fn heuristic_routes_small_task_to_quickfix() {
        assert_eq!(
            heuristic_route("fix the typo in the README"),
            ChatRoute::QuickFix
        );
    }

    #[test]
    fn heuristic_routes_big_or_keyword_heavy_to_feature() {
        let big = "implement add create refactor migrate integrate endpoint module service \
                   api with tests and design";
        assert_eq!(heuristic_route(big), ChatRoute::Feature);
    }

    #[test]
    fn heuristic_routes_greenfield_to_project() {
        assert_eq!(
            heuristic_route("build a new service from scratch"),
            ChatRoute::Project
        );
    }

    #[test]
    fn heuristic_routes_resume_to_continue() {
        assert_eq!(heuristic_route("continue the work"), ChatRoute::Continue);
        assert_eq!(
            heuristic_route("keep going on the current goal"),
            ChatRoute::Continue
        );
    }

    #[test]
    fn model_classification_is_honored_when_parseable() {
        let mut consult = |_req: &CompleteRequest| Some("project".to_string());
        let route = Classifier::classify("anything", Some(&mut consult));
        assert_eq!(route, ChatRoute::Project);
    }

    #[test]
    fn model_classification_falls_back_to_heuristic_when_unparseable() {
        // The model returns junk -> we DO NOT retry, we use the heuristic.
        let mut consult = |_req: &CompleteRequest| Some("¯\\_(ツ)_/¯ merge to main".to_string());
        let route = Classifier::classify("fix the typo", Some(&mut consult));
        assert_eq!(route, ChatRoute::QuickFix);
    }

    #[test]
    fn model_failure_falls_back_to_heuristic() {
        let mut consult = |_req: &CompleteRequest| None; // call failed
        let route = Classifier::classify("what is this repo?", Some(&mut consult));
        assert_eq!(route, ChatRoute::Converse);
    }

    #[test]
    fn route_is_non_authoritative_just_an_enum() {
        // A ChatRoute is a Copy enum with no capability/approval method. The strongest
        // thing a caller can do with it is read its token or ask is_execution().
        let r = Classifier::classify("build everything from scratch", None);
        assert_eq!(r, ChatRoute::Project);
        assert!(r.is_execution());
    }
}
