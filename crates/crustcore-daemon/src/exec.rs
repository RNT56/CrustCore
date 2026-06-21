// SPDX-License-Identifier: Apache-2.0
//! Subagent execution (P11-exec): the supervisor-owned control plane that runs one
//! subagent and folds its result back onto the blackboard.
//!
//! The trust-critical part lives here and is fully CI-tested over a mock executor:
//! - the [`Scheduler`] bounds fan-out and its slot is **always released** (invariant 11);
//! - the agent's budget bounds the work charged for the run (invariant 11);
//! - the role is bound to the [`AgentRegistry`] by id — **never** a worker's
//!   self-asserted claim (this fills the `TODO(P11-exec)` seam in `supervisor.rs`);
//! - the outcome is posted to the [`Blackboard`] addressed to
//!   [`AgentTarget::Supervisor`] and **never** the user (invariant 5; there is no user
//!   target to name, so it is structural); and
//! - **acceptance comes only from the verifier's evidence** — a worker's
//!   `self_claimed_done` never completes a task (invariants 6, 13).
//!
//! The live executor that actually runs a worker in a sandboxed throwaway worktree and
//! reruns the verifier — `crustcore_backend::worker::run_external_worker` followed by
//! `crustcore_backend::verify::run_verify`, both already tested in `crustcore-backend`
//! and chained in the `crustcore` harness (`crates/crustcore/src/main.rs`) — is the
//! `TODO(P11-exec-live)` seam on [`SubagentExecutor`]. It lands with the daemon runtime,
//! behind the very trait the mock drives here, so the orchestration above never changes.

use crustcore_types::{BoundedText, TaskId};

use crate::supervisor::{
    AgentId, AgentMessage, AgentRegistry, AgentSpec, AgentTarget, AgentUsage, Blackboard,
    BudgetError, MessageKind, Role, Scheduler,
};

/// Cap on a supervisor-visible subagent summary (bounded — invariant 11; §6.5).
pub const MAX_SUBAGENT_SUMMARY: usize = 8 * 1024;

/// The work handed to one subagent: the task it advances, a bounded goal, and the
/// **verify command** that alone gates completion. Primitives only — the live executor
/// maps these onto a backend `WorkerInput` + `VerifySpec` (`docs/backend-contract.md`).
#[derive(Debug, Clone)]
pub struct SubagentTask {
    /// The task this subagent advances.
    pub task_id: TaskId,
    /// A bounded description of the goal.
    pub goal: BoundedText,
    /// The verify program the supervisor reruns to gate completion (invariant 13).
    pub verify_program: String,
    /// Literal args to the verify program.
    pub verify_args: Vec<String>,
}

/// What an executor reports for one subagent run, **before** the supervisor turns it
/// into a posted outcome. `verified` is set ONLY from the executor's rerun of the
/// verifier; `self_claimed_done` is the worker's advisory claim, kept for contrast and
/// **never** used to complete (invariants 6, 13).
#[derive(Debug, Clone)]
pub struct RawSubagentResult {
    /// Did the supervisor's verifier pass? The sole completion authority (inv 6, 13).
    pub verified: bool,
    /// The worker's self-asserted "done" — advisory metadata, never authority.
    pub self_claimed_done: bool,
    /// A bounded summary of what the subagent did (untrusted, already bounded).
    pub summary: BoundedText,
    /// The resources the run consumed (charged against the agent's budget).
    pub usage: AgentUsage,
}

/// Why an executor could not run a subagent to a result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecError {
    /// The worker or verifier could not run (sandbox unavailable, spawn failure, an
    /// escaping write that rejected the result, …). Carries a bounded reason.
    Backend(String),
}

/// Runs one subagent task to a [`RawSubagentResult`]. The production impl
/// (`TODO(P11-exec-live)`) runs the worker in a sandboxed throwaway worktree via
/// `crustcore_backend::worker::run_external_worker` and then reruns the verifier via
/// `crustcore_backend::verify::run_verify` — exactly as the `crustcore` harness chains
/// them — so `verified` is true only when a `VerifiedPatch` was minted (invariant 13). A
/// mock implementation drives the CI tests here.
///
/// An executor **cannot** reach the user: it returns data to the supervisor, which alone
/// communicates outward (invariant 5).
pub trait SubagentExecutor {
    /// Runs `task` for the subagent described by `spec`, returning its raw result.
    ///
    /// # Errors
    /// [`ExecError`] if the worker or verifier could not run.
    fn execute(
        &self,
        spec: &AgentSpec,
        task: &SubagentTask,
    ) -> Result<RawSubagentResult, ExecError>;
}

/// What the supervisor learned from running a subagent: whether its candidate was
/// **accepted by the verifier** (the only completion authority), the agent's
/// registry-bound role, the worker's advisory self-claim (for contrast), a bounded
/// summary, and the updated usage. No field can address the user (invariant 5).
#[derive(Debug, Clone)]
pub struct SubagentOutcome {
    /// The agent that ran.
    pub agent: AgentId,
    /// Its role, bound from the [`AgentRegistry`] — not self-asserted.
    pub role: Role,
    /// Accepted iff the verifier passed (invariants 6, 13).
    pub accepted: bool,
    /// The worker's advisory self-claim (never used to accept).
    pub self_claimed_done: bool,
    /// A bounded summary of the run.
    pub summary: BoundedText,
    /// The agent's usage after charging this run.
    pub usage: AgentUsage,
}

/// Why [`run_subagent`] did not produce an outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunRefused {
    /// The agent is not registered — an unknown agent is never run (no implicit trust).
    UnknownAgent,
    /// The concurrency cap is reached (bounded fan-out, invariant 11).
    Concurrency,
    /// The run's usage would exceed the agent's budget (invariant 11); the named axis.
    Budget(BudgetError),
    /// The executor could not run the subagent.
    Exec(ExecError),
}

/// Runs one subagent end to end under the supervisor's control and posts its outcome to
/// the `blackboard` — addressed to [`AgentTarget::Supervisor`], **never** the user
/// (invariant 5; [`AgentTarget`] has no user variant, so this is structural).
///
/// Enforced here, in order:
/// 1. **Registry-bound identity** — `agent`'s role and budget come from `registry` by
///    id; an unregistered agent is refused. Privilege never derives from a self-asserted
///    field (this is the `TODO(P11-exec)` seam noted on `AgentMessage::from_role`).
/// 2. **Bounded fan-out** (invariant 11) — a [`Scheduler`] slot is reserved and **always
///    released**, even when the executor errors or the run is over budget.
/// 3. **Budget** (invariant 11) — the executor's reported usage is charged against the
///    agent's budget; an over-budget run is refused and **not** posted (and not charged).
/// 4. **Verifier-owned acceptance** (invariants 6, 13) — `accepted` is taken only from
///    [`RawSubagentResult::verified`]; the worker's `self_claimed_done` never accepts.
///
/// On success the outcome is posted as a [`MessageKind::PatchProposal`] (accepted) or a
/// [`MessageKind::TestResult`] (not accepted) from the agent to the supervisor.
///
/// # Errors
/// [`RunRefused`] if the agent is unknown, the concurrency cap is hit, the run is over
/// budget, or the executor failed.
pub fn run_subagent(
    agent: AgentId,
    registry: &AgentRegistry,
    task: &SubagentTask,
    executor: &dyn SubagentExecutor,
    scheduler: &mut Scheduler,
    usage: &mut AgentUsage,
    blackboard: &mut Blackboard,
) -> Result<SubagentOutcome, RunRefused> {
    let spec: AgentSpec = registry.get(agent).ok_or(RunRefused::UnknownAgent)?.clone();

    scheduler.try_spawn().map_err(|_| RunRefused::Concurrency)?;
    // Reserve-then-always-release: run + charge, free the slot, THEN propagate any
    // error — so a failed or over-budget run never leaks a concurrency slot.
    let charged = run_charged(&spec, task, executor, *usage);
    scheduler.finish();
    let (raw, next_usage) = charged?;
    *usage = next_usage;

    // Acceptance is verifier evidence ONLY — never the worker's self-claim (inv 6, 13).
    let accepted = raw.verified;
    let kind = if accepted {
        MessageKind::PatchProposal
    } else {
        MessageKind::TestResult
    };
    blackboard.post(AgentMessage {
        from: agent,
        from_role: spec.role,            // registry-bound, not self-asserted
        target: AgentTarget::Supervisor, // never the user (invariant 5)
        kind,
        payload: raw.summary.clone(),
    });

    Ok(SubagentOutcome {
        agent,
        role: spec.role,
        accepted,
        self_claimed_done: raw.self_claimed_done,
        summary: raw.summary,
        usage: next_usage,
    })
}

/// Runs the executor and charges the result against the budget, returning the raw result
/// and the updated usage — or the typed refusal. Split out so the caller releases the
/// scheduler slot before propagating either outcome.
fn run_charged(
    spec: &AgentSpec,
    task: &SubagentTask,
    executor: &dyn SubagentExecutor,
    usage: AgentUsage,
) -> Result<(RawSubagentResult, AgentUsage), RunRefused> {
    let raw = executor.execute(spec, task).map_err(RunRefused::Exec)?;
    let next = usage
        .charge(raw.usage, &spec.budget)
        .map_err(RunRefused::Budget)?;
    Ok((raw, next))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::AgentBudget;

    struct MockExecutor {
        result: RawSubagentResult,
    }
    impl SubagentExecutor for MockExecutor {
        fn execute(
            &self,
            _spec: &AgentSpec,
            _task: &SubagentTask,
        ) -> Result<RawSubagentResult, ExecError> {
            Ok(self.result.clone())
        }
    }

    struct FailingExecutor;
    impl SubagentExecutor for FailingExecutor {
        fn execute(
            &self,
            _spec: &AgentSpec,
            _task: &SubagentTask,
        ) -> Result<RawSubagentResult, ExecError> {
            Err(ExecError::Backend("no sandbox backend".into()))
        }
    }

    fn spec(id: u64, role: Role) -> AgentSpec {
        AgentSpec {
            id: AgentId(id),
            role,
            budget: AgentBudget {
                max_wall_ms: 10_000,
                max_output_bytes: 10_000,
                max_tokens: 10_000,
            },
        }
    }

    fn task() -> SubagentTask {
        SubagentTask {
            task_id: TaskId(1),
            goal: BoundedText::truncated("fix the failing test", 256),
            verify_program: "cargo".into(),
            verify_args: vec!["test".into()],
        }
    }

    fn raw(verified: bool, self_claimed: bool, usage: AgentUsage) -> RawSubagentResult {
        RawSubagentResult {
            verified,
            self_claimed_done: self_claimed,
            summary: BoundedText::truncated("did the work", 256),
            usage,
        }
    }

    fn registry_with(s: AgentSpec) -> AgentRegistry {
        let mut r = AgentRegistry::new();
        r.register(s);
        r
    }

    #[test]
    fn verified_run_is_accepted_and_posted_to_the_supervisor() {
        let reg = registry_with(spec(1, Role::ExternalCommand));
        let exec = MockExecutor {
            result: raw(
                true,
                true,
                AgentUsage {
                    wall_ms: 5,
                    output_bytes: 5,
                    tokens: 5,
                },
            ),
        };
        let mut sched = Scheduler::new(2);
        let mut usage = AgentUsage::default();
        let mut bb = Blackboard::new();

        let out = run_subagent(
            AgentId(1),
            &reg,
            &task(),
            &exec,
            &mut sched,
            &mut usage,
            &mut bb,
        )
        .unwrap();

        assert!(out.accepted);
        assert_eq!(out.role, Role::ExternalCommand);
        // Posted once, to the supervisor (never the user), as a PatchProposal.
        assert_eq!(bb.len(), 1);
        let msgs = bb.messages_for(AgentTarget::Supervisor);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].target, AgentTarget::Supervisor);
        assert_eq!(msgs[0].kind, MessageKind::PatchProposal);
        // Role is bound from the registry, not self-asserted.
        assert_eq!(msgs[0].from_role, Role::ExternalCommand);
        // Slot released; usage charged.
        assert_eq!(sched.running(), 0);
        assert_eq!(usage.tokens, 5);
    }

    #[test]
    fn self_claimed_done_without_verifier_evidence_is_not_accepted() {
        // The worker shouts "done", but the supervisor's verifier did not pass.
        let reg = registry_with(spec(1, Role::ExternalCommand));
        let exec = MockExecutor {
            result: raw(false, true, AgentUsage::default()),
        };
        let mut sched = Scheduler::new(2);
        let mut usage = AgentUsage::default();
        let mut bb = Blackboard::new();

        let out = run_subagent(
            AgentId(1),
            &reg,
            &task(),
            &exec,
            &mut sched,
            &mut usage,
            &mut bb,
        )
        .unwrap();

        assert!(!out.accepted); // inv 6, 13: a self-claim never completes
        assert!(out.self_claimed_done); // recorded, but not authority
        let msgs = bb.messages_for(AgentTarget::Supervisor);
        assert_eq!(msgs[0].kind, MessageKind::TestResult); // not PatchProposal
    }

    #[test]
    fn unknown_agent_is_refused_without_running_or_posting() {
        let reg = AgentRegistry::new(); // empty
        let exec = MockExecutor {
            result: raw(true, true, AgentUsage::default()),
        };
        let mut sched = Scheduler::new(2);
        let mut usage = AgentUsage::default();
        let mut bb = Blackboard::new();

        let r = run_subagent(
            AgentId(7),
            &reg,
            &task(),
            &exec,
            &mut sched,
            &mut usage,
            &mut bb,
        );
        assert_eq!(r.err(), Some(RunRefused::UnknownAgent));
        assert_eq!(sched.running(), 0);
        assert!(bb.is_empty());
    }

    #[test]
    fn concurrency_cap_refuses_and_posts_nothing() {
        let reg = registry_with(spec(1, Role::ExternalCommand));
        let exec = MockExecutor {
            result: raw(true, true, AgentUsage::default()),
        };
        let mut sched = Scheduler::new(1);
        sched.try_spawn().unwrap(); // fill the only slot
        let mut usage = AgentUsage::default();
        let mut bb = Blackboard::new();

        let r = run_subagent(
            AgentId(1),
            &reg,
            &task(),
            &exec,
            &mut sched,
            &mut usage,
            &mut bb,
        );
        assert_eq!(r.err(), Some(RunRefused::Concurrency));
        assert!(bb.is_empty());
        assert_eq!(sched.running(), 1); // unchanged — we never reserved a 2nd slot
    }

    #[test]
    fn over_budget_run_is_refused_and_releases_the_slot() {
        let reg = registry_with(spec(1, Role::ExternalCommand)); // caps at 10k tokens
        let exec = MockExecutor {
            result: raw(
                true,
                false,
                AgentUsage {
                    wall_ms: 0,
                    output_bytes: 0,
                    tokens: 999_999,
                },
            ),
        };
        let mut sched = Scheduler::new(2);
        let mut usage = AgentUsage::default();
        let mut bb = Blackboard::new();

        let r = run_subagent(
            AgentId(1),
            &reg,
            &task(),
            &exec,
            &mut sched,
            &mut usage,
            &mut bb,
        );
        assert_eq!(r.err(), Some(RunRefused::Budget(BudgetError::Tokens)));
        assert_eq!(sched.running(), 0); // slot released despite the refusal
        assert_eq!(usage, AgentUsage::default()); // not charged on refusal
        assert!(bb.is_empty());
    }

    #[test]
    fn executor_error_releases_the_slot_and_posts_nothing() {
        let reg = registry_with(spec(1, Role::ExternalCommand));
        let mut sched = Scheduler::new(2);
        let mut usage = AgentUsage::default();
        let mut bb = Blackboard::new();

        let r = run_subagent(
            AgentId(1),
            &reg,
            &task(),
            &FailingExecutor,
            &mut sched,
            &mut usage,
            &mut bb,
        );
        assert_eq!(
            r.err(),
            Some(RunRefused::Exec(ExecError::Backend(
                "no sandbox backend".into()
            )))
        );
        assert_eq!(sched.running(), 0); // released even on executor error
        assert!(bb.is_empty());
    }
}
