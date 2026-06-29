// SPDX-License-Identifier: Apache-2.0
//! Native subagents + supervisor (`ROADMAP.md` §11, §18 Phase 11;
//! `docs/maintainer-agent.md` §4–§6). The parallel-agent orchestration model
//! CrustCore itself embodies (CLAUDE.md §7).
//!
//! **One supervisor** orchestrates; subagents are *workers* that explore, draft,
//! analyze, and produce patches and report back through the **blackboard / event
//! bus** — never by talking to the user (invariant 5), resolving secrets (1/3), or
//! writing to GitHub (only the supervisor does). The hard routing denials are made
//! structural here: [`AgentTarget`] has **no `User` variant**, so a subagent
//! *cannot name the user as a destination*. A subagent asks for anything it cannot
//! do itself via a [`MessageKind::CapabilityRequest`] to the supervisor, which
//! performs the gated action after policy/approval.
//!
//! This module is the std-only, deterministic orchestration core (the registry,
//! role output contracts, the budget-enforcing scheduler, the blackboard, and the
//! reviewer/security integration gate). Spawning real subagent *executions* (model
//! calls / external workers) and the live integration-worktree verify reuse the net
//! sidecar + `crustcore-worktree`/`crustcore-backend::verify` (`TODO(P11-exec)`);
//! the trust-critical routing/budget/integration logic is fully tested here.

use std::collections::BTreeMap;

use crustcore_types::BoundedText;

// ---------------------------------------------------------------------------
// Roles (P11.1/P11.2)
// ---------------------------------------------------------------------------

/// A subagent role (`docs/maintainer-agent.md` §5; `ROADMAP.md` §11.2). Only the
/// [`Role::Supervisor`] may talk to the user, integrate, push, or resolve secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// The single orchestrator — the only actor that talks to the user/integrates.
    Supervisor,
    /// Milestones, acceptance criteria, likely files, test strategy, risks.
    Planner,
    /// Background investigation / prior art (treated as untrusted data).
    Researcher,
    /// Stack/test/build/lint/CI/sensitive-file discovery.
    RepoAnalyst,
    /// Design and high-leverage structural decisions.
    Architect,
    /// Writes the patch in a worktree.
    Implementer,
    /// Builds and runs verification; produces evidence.
    Tester,
    /// Correctness/maintainability review; **can block integration**.
    Reviewer,
    /// Secrets/auth/CI/dependency review; **can block integration**.
    SecurityAuditor,
    /// Applies the dependency-admission policy.
    DependencyAnalyst,
    /// Release hardening, signing, size-gate compliance.
    ReleaseManager,
    /// Authors/maintains `docs/`.
    DocumentationWriter,
    /// Codex CLI external worker (patch producer, not authority — invariant 6).
    ExternalCodex,
    /// Claude Code external worker (patch producer, not authority).
    ExternalClaudeCode,
    /// Generic external-command worker under the backend contract.
    ExternalCommand,
}

impl Role {
    /// Whether this role is the supervisor (the only privileged actor).
    #[must_use]
    pub fn is_supervisor(self) -> bool {
        matches!(self, Role::Supervisor)
    }

    /// Whether this role's verdict can **block integration** (`docs/maintainer-agent.md`
    /// §5): Reviewer, SecurityAuditor, and Tester.
    #[must_use]
    pub fn can_block_integration(self) -> bool {
        matches!(self, Role::Reviewer | Role::SecurityAuditor | Role::Tester)
    }

    /// Whether this role is an external worker (its output is an `UnverifiedPatch`
    /// until the verifier runs — invariant 6).
    #[must_use]
    pub fn is_external_worker(self) -> bool {
        matches!(
            self,
            Role::ExternalCodex | Role::ExternalClaudeCode | Role::ExternalCommand
        )
    }
}

// ---------------------------------------------------------------------------
// Agent identity + registry (P11.1)
// ---------------------------------------------------------------------------

/// A spawned subagent's id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AgentId(pub u64);

/// A registered agent: its id, role, and budget.
#[derive(Debug, Clone)]
pub struct AgentSpec {
    /// The agent's id.
    pub id: AgentId,
    /// Its role.
    pub role: Role,
    /// Its resource budget (invariant 11).
    pub budget: AgentBudget,
}

/// The set of agents known to the supervisor.
#[derive(Default)]
pub struct AgentRegistry {
    agents: BTreeMap<u64, AgentSpec>,
}

impl AgentRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        AgentRegistry {
            agents: BTreeMap::new(),
        }
    }

    /// Registers an agent.
    pub fn register(&mut self, spec: AgentSpec) {
        self.agents.insert(spec.id.0, spec);
    }

    /// The spec for an agent id.
    #[must_use]
    pub fn get(&self, id: AgentId) -> Option<&AgentSpec> {
        self.agents.get(&id.0)
    }

    /// The role of an agent (defaults to a non-privileged classification if absent —
    /// an unknown agent is never treated as the supervisor).
    #[must_use]
    pub fn role(&self, id: AgentId) -> Option<Role> {
        self.agents.get(&id.0).map(|s| s.role)
    }
}

// ---------------------------------------------------------------------------
// Budgets + scheduler (P11.3) — subagents cannot exceed budgets
// ---------------------------------------------------------------------------

/// A subagent's resource budget (invariant 11; `docs/maintainer-agent.md` §4.3).
/// Runaway fan-out / unbounded work is a threat, so every axis is capped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentBudget {
    /// Wall-clock cap in milliseconds.
    pub max_wall_ms: u64,
    /// Output-bytes cap.
    pub max_output_bytes: u64,
    /// Model-token cap.
    pub max_tokens: u64,
}

/// Accumulated usage for one agent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AgentUsage {
    /// Wall-clock used (ms).
    pub wall_ms: u64,
    /// Output bytes produced.
    pub output_bytes: u64,
    /// Tokens consumed.
    pub tokens: u64,
}

/// Which budget axis a charge would breach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetError {
    /// Wall-clock cap exceeded.
    Wall,
    /// Output-bytes cap exceeded.
    Output,
    /// Token cap exceeded.
    Tokens,
}

impl AgentUsage {
    /// Charges `delta` against `budget`, returning the updated usage, or
    /// [`BudgetError`] if any axis would be exceeded (the charge is **not** applied
    /// on error — a subagent cannot exceed its budget; invariant 11).
    ///
    /// # Errors
    /// [`BudgetError`] naming the first axis that would breach.
    pub fn charge(
        self,
        delta: AgentUsage,
        budget: &AgentBudget,
    ) -> Result<AgentUsage, BudgetError> {
        let next = AgentUsage {
            wall_ms: self.wall_ms.saturating_add(delta.wall_ms),
            output_bytes: self.output_bytes.saturating_add(delta.output_bytes),
            tokens: self.tokens.saturating_add(delta.tokens),
        };
        if next.wall_ms > budget.max_wall_ms {
            return Err(BudgetError::Wall);
        }
        if next.output_bytes > budget.max_output_bytes {
            return Err(BudgetError::Output);
        }
        if next.tokens > budget.max_tokens {
            return Err(BudgetError::Tokens);
        }
        Ok(next)
    }
}

/// Why a spawn was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnRefused {
    /// The concurrency cap is reached (bounded fan-out).
    ConcurrencyCap,
}

/// A bounded-concurrency scheduler for subagents (`docs/maintainer-agent.md` §4.3).
/// Caps how many subagents run at once — runaway fan-out exhausts budget, so
/// concurrency is bounded and purposeful.
#[derive(Debug)]
pub struct Scheduler {
    max_concurrent: usize,
    running: usize,
}

impl Scheduler {
    /// A scheduler allowing at most `max_concurrent` simultaneous subagents.
    #[must_use]
    pub fn new(max_concurrent: usize) -> Self {
        Scheduler {
            max_concurrent: max_concurrent.max(1),
            running: 0,
        }
    }

    /// How many subagents are currently running.
    #[must_use]
    pub fn running(&self) -> usize {
        self.running
    }

    /// Reserves a concurrency slot, or refuses if the cap is reached.
    ///
    /// # Errors
    /// [`SpawnRefused::ConcurrencyCap`] when already at the limit.
    pub fn try_spawn(&mut self) -> Result<(), SpawnRefused> {
        if self.running >= self.max_concurrent {
            return Err(SpawnRefused::ConcurrencyCap);
        }
        self.running += 1;
        Ok(())
    }

    /// Releases a concurrency slot when a subagent finishes.
    pub fn finish(&mut self) {
        self.running = self.running.saturating_sub(1);
    }
}

// ---------------------------------------------------------------------------
// Blackboard / event bus (P11.4) — subagents cannot talk to the user
// ---------------------------------------------------------------------------

/// Where a subagent message may be addressed. **There is no `User` variant** — a
/// subagent structurally cannot name the user as a destination (invariant 5; only
/// the supervisor talks to the user, `docs/maintainer-agent.md` §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentTarget {
    /// The single supervisor.
    Supervisor,
    /// Another named agent.
    Agent(AgentId),
    /// The whole team (broadcast on the bus).
    BroadcastToTeam,
}

/// The kind of a subagent message (`docs/maintainer-agent.md` §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    /// A factual finding.
    Finding,
    /// A hypothesis to investigate.
    Hypothesis,
    /// A question for another agent / the supervisor.
    Question,
    /// An answer to a question.
    Answer,
    /// A plan / milestones.
    Plan,
    /// A proposed patch (an `UnverifiedPatch` reference; the verifier gates it).
    PatchProposal,
    /// A test/verification result.
    TestResult,
    /// A surfaced risk.
    Risk,
    /// A request for the **supervisor** to perform a gated action the subagent
    /// cannot do itself (resolve a secret handle, push, open a PR). The supervisor —
    /// not the subagent — performs it after policy/approval.
    CapabilityRequest,
    /// A completion report.
    Completion,
}

/// A structured subagent message — the only way a subagent communicates (no shared
/// giant chat transcript). Bounded (invariant 11).
#[derive(Debug, Clone)]
pub struct AgentMessage {
    /// The sending agent.
    pub from: AgentId,
    /// The sender's role, **for display only**. It is self-asserted and grants no
    /// authority: the supervisor (the trusted actor) acts on a message only after
    /// reconciling the sender against [`AgentRegistry`] by `from` id — never by
    /// trusting this field. The subagent execution path does exactly this — see
    /// [`crate::exec::run_subagent`], which sets `from_role` from the registry spec,
    /// not from any worker-supplied value.
    pub from_role: Role,
    /// The destination (never the user — see [`AgentTarget`]).
    pub target: AgentTarget,
    /// The message kind.
    pub kind: MessageKind,
    /// A bounded payload (a structured summary, never an unbounded dump).
    pub payload: BoundedText,
}

/// The shared blackboard / event bus. Subagents post structured messages here; the
/// supervisor reads them and is the only actor that acts on the outside world.
#[derive(Default)]
pub struct Blackboard {
    messages: Vec<AgentMessage>,
}

impl Blackboard {
    /// A fresh blackboard.
    #[must_use]
    pub fn new() -> Self {
        Blackboard {
            messages: Vec::new(),
        }
    }

    /// Posts a message to the bus. (There is no path to address the user — that is
    /// structural in [`AgentTarget`].)
    pub fn post(&mut self, message: AgentMessage) {
        self.messages.push(message);
    }

    /// All messages addressed to `target` (the supervisor reads `Supervisor` +
    /// `BroadcastToTeam`).
    #[must_use]
    pub fn messages_for(&self, target: AgentTarget) -> Vec<&AgentMessage> {
        self.messages
            .iter()
            .filter(|m| m.target == target || m.target == AgentTarget::BroadcastToTeam)
            .collect()
    }

    /// All messages of a given kind (e.g. every `Risk` or `CapabilityRequest`).
    #[must_use]
    pub fn of_kind(&self, kind: MessageKind) -> Vec<&AgentMessage> {
        self.messages.iter().filter(|m| m.kind == kind).collect()
    }

    /// Total messages posted.
    #[must_use]
    pub fn len(&self) -> usize {
        self.messages.len()
    }

    /// Whether the blackboard is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Reviewer/security integration gate (P11.5/P11.6)
// ---------------------------------------------------------------------------

/// A reviewer/security/tester verdict on a candidate integration.
#[derive(Debug, Clone)]
pub enum Verdict {
    /// Approve integration.
    Approve,
    /// Block integration, with a bounded reason.
    Block(BoundedText),
}

/// The supervisor's decision on whether a candidate may integrate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrationDecision {
    /// May integrate: all blocking roles approved **and** the patch is verified.
    Integrate,
    /// A blocking role vetoed it (carries the role + reason).
    BlockedBy { role: Role, reason: String },
    /// Not yet verified — parallel worktrees merge only after the verifier produces
    /// a `VerifiedPatch` (invariant 13; `docs/maintainer-agent.md` §4.3).
    NotVerified,
    /// A role that may not block cast a verdict, or no blocking review was provided.
    MissingReview,
}

/// Decides whether a candidate may integrate. **Both** must hold: every
/// blocking-capable reviewer (Reviewer/SecurityAuditor/Tester) that voted must
/// `Approve`, **and** `verified` must be true (a `VerifiedPatch` was minted by the
/// verifier). A single `Block` from a blocking role vetoes integration
/// (`docs/maintainer-agent.md` §4–§5). A verdict from a non-blocking role is ignored
/// for the gate; at least one blocking review must be present.
#[must_use]
pub fn decide_integration(verdicts: &[(Role, Verdict)], verified: bool) -> IntegrationDecision {
    let mut saw_blocking_review = false;
    for (role, verdict) in verdicts {
        if !role.can_block_integration() {
            continue; // non-blocking roles do not gate integration
        }
        saw_blocking_review = true;
        if let Verdict::Block(reason) = verdict {
            return IntegrationDecision::BlockedBy {
                role: *role,
                reason: reason.as_str().to_string(),
            };
        }
    }
    if !saw_blocking_review {
        return IntegrationDecision::MissingReview;
    }
    if !verified {
        return IntegrationDecision::NotVerified;
    }
    IntegrationDecision::Integrate
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bt(s: &str) -> BoundedText {
        BoundedText::truncated(s, 256)
    }

    fn msg(from: u64, role: Role, target: AgentTarget, kind: MessageKind) -> AgentMessage {
        AgentMessage {
            from: AgentId(from),
            from_role: role,
            target,
            kind,
            payload: bt("payload"),
        }
    }

    // --- subagents cannot talk to the user (invariant 5, structural) ---

    #[test]
    fn agent_target_has_no_user_variant() {
        // This test documents the structural guarantee: a subagent message can only
        // be addressed to the supervisor, another agent, or the team — never the
        // user. The only outward channel a subagent has is the blackboard, which the
        // supervisor reads; the supervisor alone holds the Telegram channel.
        let mut bb = Blackboard::new();
        bb.post(msg(
            1,
            Role::Reviewer,
            AgentTarget::Supervisor,
            MessageKind::Finding,
        ));
        bb.post(msg(
            2,
            Role::Implementer,
            AgentTarget::BroadcastToTeam,
            MessageKind::PatchProposal,
        ));
        // The supervisor reads Supervisor + Broadcast messages.
        assert_eq!(bb.messages_for(AgentTarget::Supervisor).len(), 2);
        // A subagent asks for a gated action via a CapabilityRequest, not by acting.
        bb.post(msg(
            1,
            Role::Implementer,
            AgentTarget::Supervisor,
            MessageKind::CapabilityRequest,
        ));
        assert_eq!(bb.of_kind(MessageKind::CapabilityRequest).len(), 1);
    }

    #[test]
    fn only_supervisor_role_is_privileged() {
        assert!(Role::Supervisor.is_supervisor());
        assert!(!Role::Implementer.is_supervisor());
        assert!(!Role::ExternalCodex.is_supervisor());
        assert!(Role::ExternalCodex.is_external_worker());
    }

    // --- subagents cannot exceed budgets (invariant 11) ---

    #[test]
    fn budget_charge_refuses_each_axis_overrun() {
        let budget = AgentBudget {
            max_wall_ms: 1000,
            max_output_bytes: 4096,
            max_tokens: 500,
        };
        let u = AgentUsage::default();
        // A charge within budget is applied.
        let u = u
            .charge(
                AgentUsage {
                    wall_ms: 500,
                    output_bytes: 2000,
                    tokens: 250,
                },
                &budget,
            )
            .unwrap();
        // Each axis overrun is refused (and not applied).
        assert_eq!(
            u.charge(
                AgentUsage {
                    wall_ms: 600,
                    ..Default::default()
                },
                &budget
            ),
            Err(BudgetError::Wall)
        );
        assert_eq!(
            u.charge(
                AgentUsage {
                    output_bytes: 3000,
                    ..Default::default()
                },
                &budget
            ),
            Err(BudgetError::Output)
        );
        assert_eq!(
            u.charge(
                AgentUsage {
                    tokens: 300,
                    ..Default::default()
                },
                &budget
            ),
            Err(BudgetError::Tokens)
        );
    }

    #[test]
    fn scheduler_caps_concurrency() {
        let mut s = Scheduler::new(2);
        assert!(s.try_spawn().is_ok());
        assert!(s.try_spawn().is_ok());
        assert_eq!(s.running(), 2);
        // Third spawn refused — bounded fan-out.
        assert_eq!(s.try_spawn(), Err(SpawnRefused::ConcurrencyCap));
        s.finish();
        assert!(s.try_spawn().is_ok()); // a freed slot can be reused
    }

    // --- registry (P11.1) ---

    #[test]
    fn registry_tracks_roles() {
        let mut reg = AgentRegistry::new();
        reg.register(AgentSpec {
            id: AgentId(7),
            role: Role::SecurityAuditor,
            budget: AgentBudget {
                max_wall_ms: 1,
                max_output_bytes: 1,
                max_tokens: 1,
            },
        });
        assert_eq!(reg.role(AgentId(7)), Some(Role::SecurityAuditor));
        assert_eq!(reg.role(AgentId(99)), None);
    }

    // --- reviewer/security can block integration; verify-gated (P11.5/P11.6) ---

    #[test]
    fn reviewer_or_security_block_vetoes_integration() {
        // A SecurityAuditor block vetoes, even if everything else approves + verified.
        let verdicts = vec![
            (Role::Reviewer, Verdict::Approve),
            (
                Role::SecurityAuditor,
                Verdict::Block(bt("hardcoded secret in patch")),
            ),
        ];
        assert!(matches!(
            decide_integration(&verdicts, true),
            IntegrationDecision::BlockedBy {
                role: Role::SecurityAuditor,
                ..
            }
        ));
    }

    #[test]
    fn integration_requires_verification_even_with_all_approvals() {
        let verdicts = vec![
            (Role::Reviewer, Verdict::Approve),
            (Role::SecurityAuditor, Verdict::Approve),
            (Role::Tester, Verdict::Approve),
        ];
        // All approve but not yet verified → merge is blocked (invariant 13).
        assert_eq!(
            decide_integration(&verdicts, false),
            IntegrationDecision::NotVerified
        );
        // Verified + all approve → integrate.
        assert_eq!(
            decide_integration(&verdicts, true),
            IntegrationDecision::Integrate
        );
    }

    #[test]
    fn non_blocking_role_verdicts_do_not_gate_and_a_review_is_required() {
        // A Planner "block" is not a blocking role; with no real reviewer present the
        // gate reports MissingReview rather than silently integrating.
        let verdicts = vec![(Role::Planner, Verdict::Block(bt("i disagree")))];
        assert_eq!(
            decide_integration(&verdicts, true),
            IntegrationDecision::MissingReview
        );
    }
}
