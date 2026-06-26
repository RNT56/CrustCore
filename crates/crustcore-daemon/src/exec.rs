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
//! and chained in the `crustcore` harness (`crates/crustcore/src/main.rs`) — is realized
//! by [`WorktreeSubagentExecutor`] (behind the `live` feature). It implements the very
//! [`SubagentExecutor`] trait the mock drives here, so the orchestration above never
//! changes: it creates a disposable worktree, runs the worker sandboxed, reruns the
//! verifier, and sets `verified` **only** from a verifier-minted `VerifiedPatch`
//! (invariants 6, 13) — accepting nothing on the worker's say-so. The only thing it
//! cannot do in CI is run the sandbox/worktree/worker for real (it needs a sandbox
//! backend), so that end-to-end run is the reduced `TODO(P11-exec-live)` seam, exercised
//! by an `#[ignore]`d test; the control-flow over the mock stays fully CI-tested.

use std::collections::BTreeMap;

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

/// Runs one subagent task to a [`RawSubagentResult`]. The production impl is
/// [`WorktreeSubagentExecutor`] (behind `live`): it runs the worker in a sandboxed
/// throwaway worktree via `crustcore_backend::worker::run_external_worker` and then reruns
/// the verifier via `crustcore_backend::verify::run_verify` — exactly as the `crustcore`
/// harness chains them — so `verified` is true only when a `VerifiedPatch` was minted
/// (invariant 13). A mock implementation drives the CI tests here; the live executor's
/// real sandbox/worktree run is the reduced `TODO(P11-exec-live)` seam (`#[ignore]`d).
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

    // Reserve a concurrency slot. The RAII guard releases it on EVERY exit — a normal
    // return, a `?` early-return, or an unwinding panic — so a failed, over-budget, or
    // panicking run can never leak a slot. Bounded fan-out is structural (invariant 11),
    // not a property of careful control flow.
    scheduler.try_spawn().map_err(|_| RunRefused::Concurrency)?;
    let _slot = SlotGuard {
        scheduler: &mut *scheduler,
    };

    let (raw, next_usage) = run_charged(&spec, task, executor, *usage)?;
    *usage = next_usage;

    // Acceptance is verifier evidence ONLY — never the worker's self-claim (inv 6, 13).
    let accepted = raw.verified;
    // Re-bound the (untrusted) summary on the supervisor side rather than trusting the
    // executor's chosen cap, so the declared `MAX_SUBAGENT_SUMMARY` actually holds here
    // (invariant 11, §6.5; invariant 7: an executor's output is untrusted data).
    let summary = BoundedText::truncated(raw.summary.as_str(), MAX_SUBAGENT_SUMMARY);
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
        payload: summary.clone(),
    });

    Ok(SubagentOutcome {
        agent,
        role: spec.role,
        accepted,
        self_claimed_done: raw.self_claimed_done,
        summary,
        usage: next_usage,
    })
}

/// Releases a reserved [`Scheduler`] slot on drop — on a normal return, a `?`
/// early-return, or an unwinding panic — so [`run_subagent`] cannot leak a concurrency
/// slot down any path (invariant 11).
struct SlotGuard<'a> {
    scheduler: &'a mut Scheduler,
}

impl Drop for SlotGuard<'_> {
    fn drop(&mut self) {
        self.scheduler.finish();
    }
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

// ---------------------------------------------------------------------------
// Fan-out coordinator (P11) — race K proposers, the verifier picks the winner
// ---------------------------------------------------------------------------

/// A bounded fan-out plan: run each `proposer` agent at the **same** goal (`task`); the
/// supervisor's verifier picks the winner. Proposers are registry-bound ids (an unregistered
/// agent is refused by [`run_subagent`]); the set is bounded by the caller.
#[derive(Debug, Clone)]
pub struct FanoutPlan {
    /// The shared goal + verify command every proposer attempts. The verify command — not a
    /// self-claim — gates acceptance (invariant 13).
    pub task: SubagentTask,
    /// The proposer agents to race, in priority order (the first verifier-accepted one wins).
    pub proposers: Vec<AgentId>,
}

/// The result of a [`run_fanout`]: every attempted proposer's outcome (or typed refusal), and
/// the verifier-accepted winner — the **first** proposer whose candidate the supervisor's
/// verifier accepted (invariants 6, 13). `verified` is true iff a winner was found.
#[derive(Debug, Clone)]
pub struct FanoutResult {
    /// Per-proposer results, in the order attempted (bounded by the plan, then early-stopped
    /// at the first accepted winner).
    pub results: Vec<(AgentId, Result<SubagentOutcome, RunRefused>)>,
    /// The first verifier-accepted proposer, if any. Selection is **verifier-owned**.
    pub winner: Option<AgentId>,
    /// Whether any proposer's candidate was accepted by the verifier.
    pub verified: bool,
}

/// Coordinate a **fan-out of proposers** at one goal under the supervisor's control: run each
/// proposer via [`run_subagent`] (registry-bound identity, bounded concurrency, per-agent
/// budget, verifier-owned acceptance, blackboard-posted to the supervisor — **never** the
/// user, invariant 5) and **stop at the first proposer the verifier accepts**.
///
/// This is the multi-proposer extension of [`run_subagent`]: many models may *propose*, but a
/// candidate is the winner only when the supervisor's verifier accepted it — never a worker's
/// `self_claimed_done` (invariants 6, 13). Stopping at the first acceptance keeps fan-out
/// bounded (invariant 11): once a `VerifiedPatch` exists, further proposers are wasted work. A
/// proposer that is unknown, over budget, at the concurrency cap, or whose executor failed
/// yields a typed [`RunRefused`] in `results` and the race continues to the next.
///
/// Deterministic over the proposer order; synchronous; it performs no I/O itself — the live
/// [`SubagentExecutor`] runs each candidate sandboxed. `usages` carries each agent's
/// accumulated usage so budgets persist across calls; a fresh agent starts at zero.
pub fn run_fanout(
    plan: &FanoutPlan,
    registry: &AgentRegistry,
    executor: &dyn SubagentExecutor,
    scheduler: &mut Scheduler,
    usages: &mut BTreeMap<AgentId, AgentUsage>,
    blackboard: &mut Blackboard,
) -> FanoutResult {
    let mut results = Vec::with_capacity(plan.proposers.len());
    let mut winner = None;
    for &agent in &plan.proposers {
        let usage = usages.entry(agent).or_default();
        let r = run_subagent(
            agent, registry, &plan.task, executor, scheduler, usage, blackboard,
        );
        let accepted = matches!(&r, Ok(o) if o.accepted);
        results.push((agent, r));
        if accepted {
            winner = Some(agent);
            break; // verifier accepted → stop the race (bounded work, invariant 11)
        }
    }
    FanoutResult {
        verified: winner.is_some(),
        winner,
        results,
    }
}

// ---------------------------------------------------------------------------
// Live worktree executor (P11-exec-live) — sandboxed worker → verifier rerun
// ---------------------------------------------------------------------------

/// The live [`SubagentExecutor`] (behind the `live` feature): runs one subagent in a
/// **sandboxed throwaway worktree** and reruns the verifier, accepting **only** a
/// verifier-minted `VerifiedPatch` (invariants 6, 13). It chains exactly what the
/// `crustcore` harness chains — `crustcore_backend::worker::run_external_worker` then
/// `crustcore_backend::verify::run_verify` — under the same trait the mock drives, so the
/// supervisor's control plane ([`run_subagent`]) never changes.
///
/// Construction is operator setup (trusted): the repo root, the sandbox cap + profile
/// (deny-all egress, writes confined to the worktree — invariant 9), and the receipt MAC
/// key. The coding backend is chosen from the agent's **registry-bound** role
/// ([`backend_for_role`]) — never a worker's self-claim.
///
/// `verified` is set **solely** from [`crustcore_backend::verify::VerifyOutcome::Verified`]
/// — a worker that wrote outside the worktree, produced an escaping change, or whose
/// verifier did not pass yields `verified: false` (or an [`ExecError`]); nothing completes
/// on the worker's say-so. The disposable worktree is **removed on every path** (success,
/// worker rejection, verify failure, or a refused sandbox).
///
/// The one thing this cannot do in CI is run the sandbox/worktree/worker for real (it
/// needs a sandbox backend), so the end-to-end run is the reduced `TODO(P11-exec-live)`
/// seam, exercised by an `#[ignore]`d test.
#[cfg(feature = "live")]
pub struct WorktreeSubagentExecutor {
    repo_root: std::path::PathBuf,
    cap: crustcore_policy::SandboxExecCap,
    profile: crustcore_sandbox::SandboxProfile,
    /// The receipt-chain MAC key bytes (a fresh `MacKey` is built per run — `MacKey`
    /// itself is intentionally non-`Copy`/`Clone` secret material).
    mac_key: [u8; 32],
    /// For the generic `ExternalCommand` role: the worker program + literal args.
    worker_cmd: Option<(String, Vec<String>)>,
}

#[cfg(feature = "live")]
impl WorktreeSubagentExecutor {
    /// Builds the live executor. `worker_cmd` is the program+args for the generic
    /// `ExternalCommand` role (Codex/Claude roles use their presets and ignore it).
    #[must_use]
    pub fn new(
        repo_root: impl Into<std::path::PathBuf>,
        cap: crustcore_policy::SandboxExecCap,
        profile: crustcore_sandbox::SandboxProfile,
        mac_key: [u8; 32],
        worker_cmd: Option<(String, Vec<String>)>,
    ) -> Self {
        WorktreeSubagentExecutor {
            repo_root: repo_root.into(),
            cap,
            profile,
            mac_key,
            worker_cmd,
        }
    }

    /// Selects the coding backend for an agent's **registry-bound** role. The two
    /// external-worker presets map to their CLIs; the generic role uses the configured
    /// `worker_cmd`. A role with no external-worker meaning (e.g. a planner) has no live
    /// worker here — those roles are handled by the model path, not this executor.
    fn backend_for_role(
        &self,
        role: Role,
    ) -> Option<Box<dyn crustcore_backend::worker::CodingBackend>> {
        use crustcore_backend::worker::{ClaudeCodeBackend, CodexBackend, ExternalCommandBackend};
        match role {
            Role::ExternalCodex => Some(Box::new(CodexBackend::default())),
            Role::ExternalClaudeCode => Some(Box::new(ClaudeCodeBackend::default())),
            Role::ExternalCommand => {
                let (p, a) = self.worker_cmd.clone()?;
                Some(Box::new(ExternalCommandBackend::new(p, a)))
            }
            _ => None,
        }
    }
}

#[cfg(feature = "live")]
impl SubagentExecutor for WorktreeSubagentExecutor {
    fn execute(
        &self,
        spec: &AgentSpec,
        task: &SubagentTask,
    ) -> Result<RawSubagentResult, ExecError> {
        use crustcore_worktree::WorktreeManager;

        // The backend is bound to the agent's REGISTRY role (never a self-claim). A role
        // with no live-worker meaning is a setup error for this executor.
        let backend = self.backend_for_role(spec.role).ok_or_else(|| {
            ExecError::Backend(format!(
                "no live worker backend for role {:?} (use the model path)",
                spec.role
            ))
        })?;

        // Disposable worktree — removed on EVERY exit path below.
        let manager = WorktreeManager::new(&self.repo_root);
        let worktree = manager
            .create_for(task.task_id)
            .map_err(|e| ExecError::Backend(format!("worktree: {e}")))?;

        // Run the worker → verifier, capturing the outcome BEFORE teardown so a teardown
        // failure cannot mask it. The worktree is then removed unconditionally.
        let outcome = run_worker_then_verify(
            backend.as_ref(),
            task,
            &worktree,
            &self.cap,
            &self.profile,
            self.mac_key,
        );
        // Best-effort teardown on every path (success or error) — never leak a worktree.
        let _ = manager.remove(&worktree);
        outcome
    }
}

/// Runs the worker sandboxed in `worktree`, then reruns the verifier — the live
/// worker→verify chain (the same one the `crustcore` harness uses). `verified` is set
/// **only** from a verifier-minted `VerifiedPatch` (invariants 6, 13). Split out so the
/// caller owns the worktree teardown (which must happen on every path).
#[cfg(feature = "live")]
fn run_worker_then_verify(
    backend: &dyn crustcore_backend::worker::CodingBackend,
    task: &SubagentTask,
    worktree: &crustcore_path::WorktreeRoot,
    cap: &crustcore_policy::SandboxExecCap,
    profile: &crustcore_sandbox::SandboxProfile,
    mac_key: [u8; 32],
) -> Result<RawSubagentResult, ExecError> {
    use crustcore_backend::verify::{run_verify, VerifyIds, VerifyOutcome, VerifySpec};
    use crustcore_backend::worker::{run_external_worker, WorkerInput};
    use crustcore_receipts::{MacKey, ReceiptChain};
    use crustcore_types::{EventSeq, JobId, ToolCallId};

    let input = WorkerInput::for_task(task.task_id, task.goal.as_str(), worktree);
    let product = run_external_worker(backend, &input, worktree, cap, profile)
        .map_err(|e| ExecError::Backend(format!("worker rejected: {e}")))?;

    // Rerun the verifier in a clean sandbox — the SOLE path to a VerifiedPatch.
    let spec_v = VerifySpec::new(task.verify_program.clone(), task.verify_args.clone());
    let mut receipts = ReceiptChain::new(MacKey::new(mac_key));
    let ids = VerifyIds {
        task_id: task.task_id,
        job_id: JobId(1),
        tool_call_id: ToolCallId(1),
        event_seq: EventSeq(1),
        now: crustcore_types::Timestamp::from_millis(0),
    };
    let outcome = run_verify(
        cap,
        profile,
        worktree,
        &spec_v,
        product.patch.0,
        &mut receipts,
        &ids,
    );

    // `verified` comes ONLY from the verifier (invariants 6, 13). The worker's
    // self_claimed_done is carried for contrast, never as authority.
    let (verified, evidence) = match outcome {
        VerifyOutcome::Verified(_) => (true, "verifier passed".to_string()),
        VerifyOutcome::Failed { status, .. } => (false, format!("verify failed ({status:?})")),
        // No sandbox backend / non-executing tier: NOT a pass — surface as a run error.
        VerifyOutcome::Refused(reason) => {
            return Err(ExecError::Backend(format!("verify refused: {reason}")))
        }
    };

    let summary = BoundedText::truncated(
        format!(
            "{evidence}; {} file(s) changed; {}",
            product.changed_files.len(),
            product.transcript.as_str()
        ),
        MAX_SUBAGENT_SUMMARY,
    );
    Ok(RawSubagentResult {
        verified,
        self_claimed_done: product.result.self_claimed_done,
        summary,
        // Charge the produced output bytes; wall/tokens are unknown here and left 0 (the
        // supervisor bounds against the agent's budget regardless).
        usage: AgentUsage {
            wall_ms: 0,
            output_bytes: product.transcript.as_str().len() as u64,
            tokens: 0,
        },
    })
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

    #[test]
    fn oversized_executor_summary_is_rebounded_by_the_supervisor() {
        // The executor hands back a summary far larger than MAX_SUBAGENT_SUMMARY (a
        // BoundedText lets a producer pick a looser cap). The supervisor must re-clamp
        // it on both the posted message and the returned outcome — it does not trust the
        // (untrusted) producer to self-bound to the stricter limit.
        let reg = registry_with(spec(1, Role::ExternalCommand));
        let big = "x".repeat(MAX_SUBAGENT_SUMMARY * 4);
        let exec = MockExecutor {
            result: RawSubagentResult {
                verified: true,
                self_claimed_done: false,
                summary: BoundedText::truncated(&big, 64 * 1024),
                usage: AgentUsage::default(),
            },
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

        assert!(out.summary.as_str().len() <= MAX_SUBAGENT_SUMMARY);
        let msgs = bb.messages_for(AgentTarget::Supervisor);
        assert!(msgs[0].payload.as_str().len() <= MAX_SUBAGENT_SUMMARY);
    }

    // --- live worktree executor (P11-exec-live) ---
    #[cfg(feature = "live")]
    mod live {
        use super::*;

        fn executor(worker_cmd: Option<(String, Vec<String>)>) -> WorktreeSubagentExecutor {
            use crustcore_policy::SandboxExecCap;
            use crustcore_sandbox::SandboxProfile;
            use crustcore_types::ScopeId;
            WorktreeSubagentExecutor::new(
                ".",
                SandboxExecCap {
                    profile: ScopeId(1),
                    scope: ScopeId(1),
                },
                SandboxProfile::default_sandboxed(),
                [0x5a; 32],
                worker_cmd,
            )
        }

        #[test]
        fn role_selects_the_right_coding_backend() {
            use crustcore_backend::BackendKind;
            let exec = executor(Some(("true".into(), vec![])));
            // The two external presets map to their CLIs; the generic role uses worker_cmd.
            assert_eq!(
                exec.backend_for_role(Role::ExternalCodex).unwrap().kind(),
                BackendKind::Codex
            );
            assert_eq!(
                exec.backend_for_role(Role::ExternalClaudeCode)
                    .unwrap()
                    .kind(),
                BackendKind::ClaudeCode
            );
            assert_eq!(
                exec.backend_for_role(Role::ExternalCommand).unwrap().kind(),
                BackendKind::ExternalCommand
            );
            // A non-worker role (e.g. a planner) has no live worker here.
            assert!(exec.backend_for_role(Role::Planner).is_none());
            // The generic role with no configured worker_cmd also has no backend.
            assert!(executor(None)
                .backend_for_role(Role::ExternalCommand)
                .is_none());
        }

        #[test]
        fn generic_role_without_worker_cmd_is_a_backend_error_not_a_panic() {
            // execute() for the generic role with no worker_cmd must be a typed ExecError —
            // and crucially NEVER `verified: true` (nothing completes without a real run).
            let exec = executor(None);
            let spec = spec(1, Role::ExternalCommand);
            let r = exec.execute(&spec, &task());
            assert!(matches!(r, Err(ExecError::Backend(_))));
        }

        // The real worker+verify run needs a sandbox backend + a git repo worktree; it is
        // `#[ignore]`d (the reduced TODO(P11-exec-live) seam). The control-flow over the
        // MockExecutor above is the CI-tested part; this asserts the live chain end to end.
        #[test]
        #[ignore = "live: requires a sandbox backend + repo worktree (TODO P11-exec-live)"]
        fn live_worktree_executor_accepts_only_verifier_evidence() {
            // To run on Linux with bubblewrap: a `true` worker (no-op) + a `true` verifier
            // mints a VerifiedPatch, so the result is accepted; a `false` verifier never is.
            let exec = executor(Some(("true".into(), vec![])));
            let spec = spec(1, Role::ExternalCommand);
            let mut t = task();
            t.verify_program = "true".into();
            t.verify_args = vec![];
            let out = exec.execute(&spec, &t).expect("live run");
            assert!(out.verified, "a passing verifier accepts the run");

            // A failing verifier never accepts — verifier evidence is the sole authority.
            let mut t_fail = task();
            t_fail.verify_program = "false".into();
            t_fail.verify_args = vec![];
            let out = exec.execute(&spec, &t_fail).expect("live run");
            assert!(!out.verified, "a failing verifier must not accept");
        }
    }

    // ---- Fan-out coordinator (run_fanout) -------------------------------------------------

    /// A mock executor returning a different `RawSubagentResult` per agent id (keyed on the
    /// registry-bound `spec.id`), so a fan-out can have some proposers fail and one pass.
    struct KeyedMock {
        by_id: BTreeMap<u64, RawSubagentResult>,
    }
    impl SubagentExecutor for KeyedMock {
        fn execute(
            &self,
            spec: &AgentSpec,
            _task: &SubagentTask,
        ) -> Result<RawSubagentResult, ExecError> {
            self.by_id
                .get(&spec.id.0)
                .cloned()
                .ok_or_else(|| ExecError::Backend("no canned result".into()))
        }
    }

    fn reg3() -> AgentRegistry {
        let mut r = AgentRegistry::new();
        r.register(spec(1, Role::ExternalCommand));
        r.register(spec(2, Role::ExternalCommand));
        r.register(spec(3, Role::ExternalCommand));
        r
    }

    fn u(n: u64) -> AgentUsage {
        AgentUsage {
            wall_ms: n,
            output_bytes: n,
            tokens: n,
        }
    }

    #[test]
    fn fanout_stops_at_the_first_verifier_accepted_winner() {
        // Proposer 1 fails the verifier, 2 passes, 3 would pass — the race stops at 2.
        let exec = KeyedMock {
            by_id: BTreeMap::from([
                (1, raw(false, true, u(5))),
                (2, raw(true, false, u(5))),
                (3, raw(true, true, u(5))),
            ]),
        };
        let plan = FanoutPlan {
            task: task(),
            proposers: vec![AgentId(1), AgentId(2), AgentId(3)],
        };
        let mut sched = Scheduler::new(2);
        let mut usages = BTreeMap::new();
        let mut bb = Blackboard::new();
        let res = run_fanout(&plan, &reg3(), &exec, &mut sched, &mut usages, &mut bb);

        assert_eq!(res.winner, Some(AgentId(2)));
        assert!(res.verified);
        // Stopped at agent 2 — agent 3 was never run.
        assert_eq!(res.results.len(), 2);
        // Blackboard: agent 1 posted a TestResult (rejected), agent 2 a PatchProposal.
        let proposals = bb.of_kind(MessageKind::PatchProposal);
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].from, AgentId(2));
        // Slot released after every run.
        assert_eq!(sched.running(), 0);
    }

    #[test]
    fn fanout_with_no_verified_proposer_has_no_winner() {
        let exec = KeyedMock {
            by_id: BTreeMap::from([(1, raw(false, true, u(1))), (2, raw(false, true, u(1)))]),
        };
        let plan = FanoutPlan {
            task: task(),
            proposers: vec![AgentId(1), AgentId(2)],
        };
        let mut sched = Scheduler::new(2);
        let mut usages = BTreeMap::new();
        let mut bb = Blackboard::new();
        let res = run_fanout(&plan, &reg3(), &exec, &mut sched, &mut usages, &mut bb);

        assert_eq!(res.winner, None);
        assert!(!res.verified);
        // Every proposer ran; none accepted → all TestResults, no PatchProposal.
        assert_eq!(res.results.len(), 2);
        assert_eq!(bb.of_kind(MessageKind::PatchProposal).len(), 0);
    }

    #[test]
    fn fanout_winner_is_verifier_owned_not_self_claim() {
        // Agent 1 claims done but the verifier rejected it; agent 2 did NOT self-claim but the
        // verifier accepted it. The winner is agent 2 — selection is verifier-owned (inv 6,13).
        let exec = KeyedMock {
            by_id: BTreeMap::from([(1, raw(false, true, u(1))), (2, raw(true, false, u(1)))]),
        };
        let plan = FanoutPlan {
            task: task(),
            proposers: vec![AgentId(1), AgentId(2)],
        };
        let mut sched = Scheduler::new(2);
        let mut usages = BTreeMap::new();
        let mut bb = Blackboard::new();
        let res = run_fanout(&plan, &reg3(), &exec, &mut sched, &mut usages, &mut bb);
        assert_eq!(res.winner, Some(AgentId(2)));
    }

    #[test]
    fn fanout_skips_an_unknown_agent_and_continues() {
        // Agent 9 is not registered → RunRefused::UnknownAgent, but the race continues and
        // agent 2 wins.
        let exec = KeyedMock {
            by_id: BTreeMap::from([(2, raw(true, false, u(1)))]),
        };
        let plan = FanoutPlan {
            task: task(),
            proposers: vec![AgentId(9), AgentId(2)],
        };
        let mut sched = Scheduler::new(2);
        let mut usages = BTreeMap::new();
        let mut bb = Blackboard::new();
        let res = run_fanout(&plan, &reg3(), &exec, &mut sched, &mut usages, &mut bb);

        assert_eq!(res.winner, Some(AgentId(2)));
        assert!(matches!(
            res.results[0],
            (AgentId(9), Err(RunRefused::UnknownAgent))
        ));
    }

    #[test]
    fn fanout_charges_each_agent_its_own_budget() {
        let exec = KeyedMock {
            by_id: BTreeMap::from([(1, raw(false, false, u(3))), (2, raw(false, false, u(7)))]),
        };
        let plan = FanoutPlan {
            task: task(),
            proposers: vec![AgentId(1), AgentId(2)],
        };
        let mut sched = Scheduler::new(2);
        let mut usages = BTreeMap::new();
        let mut bb = Blackboard::new();
        let _ = run_fanout(&plan, &reg3(), &exec, &mut sched, &mut usages, &mut bb);
        assert_eq!(usages.get(&AgentId(1)).unwrap().tokens, 3);
        assert_eq!(usages.get(&AgentId(2)).unwrap().tokens, 7);
    }
}
