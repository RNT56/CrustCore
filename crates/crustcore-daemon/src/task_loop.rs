// SPDX-License-Identifier: Apache-2.0
//! Task-loop wiring (roadmap-v0.6 D.1).
//!
//! Composes the v0.6 decision cores into one task-processing pipeline:
//!
//! ```text
//! task (shape, risk, budget, configured executors)
//!   -> plan_task        = decide_routing (C.1)  -> ExecutionPlan
//!        Single   -> run_subagent  (exec.rs, P11)         ┐ the live, sandboxed
//!        Fanout   -> run_fanout    (exec.rs, P11)         ┘ run is the live seam
//!        Advisory -> produce a plan for human review (no autonomous execution)
//!        Blocked  -> refuse (workflow/policy / no executor)
//!   -> finalize_task    = verifier result + orchestrate_review (C.2) -> TaskOutcome
//!        ReadyToIntegrate -> the credential-proxy draft-PR path (A.2/A.3)
//! ```
//!
//! Both functions here are **pure decision cores** — no filesystem, no sandbox, no
//! clock. The actual sandboxed worker→verifier run (via the live
//! [`WorktreeSubagentExecutor`](crate::exec)) and the real draft-PR POST are the
//! `TODO(P3-live-executor-wire)` seam, exercised only by an `#[ignore]`d test.
//!
//! Trust boundary: routing/finalization select a **worker and gate integration —
//! never authority** (invariant 6). Completion is verifier-owned: `finalize_task`
//! treats an unverified run as `Failed` regardless of any advisory approval
//! (invariant 13). Advisory verdicts can only *further* gate, never substitute for the
//! verifier (invariant 4). Outcomes flow to the supervisor, not the user (invariant 5).

use crate::product::{ExecutorKind, RiskTier, TaskShape};
use crate::reviewer::{orchestrate_review, required_reviewers, AdvisoryOutcome};
use crate::router::{decide_routing, BlockedReason, RoutingDecision};
use crate::supervisor::{IntegrationDecision, Role, Verdict};

/// How a routed task should be executed — the plan the supervisor hands to the live
/// executor. Pure: derived from the routing decision (C.1); the sandboxed run is the
/// live seam.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionPlan {
    /// Run exactly one executor (`run_subagent`).
    Single(ExecutorKind),
    /// Fan out to these executors; the verifier picks the winner (`run_fanout`).
    Fanout(Vec<ExecutorKind>),
    /// Do not execute autonomously — produce an advisory plan for human review.
    AdvisoryOnly,
    /// Refused before any execution (carries why).
    Blocked(BlockedReason),
}

/// Maps a task to its [`ExecutionPlan`] via the router (C.1). Pure and total.
#[must_use]
pub fn plan_task(
    task: TaskShape,
    risk: RiskTier,
    context_budget: u64,
    configured: &[ExecutorKind],
) -> ExecutionPlan {
    match decide_routing(task, risk, context_budget, configured) {
        RoutingDecision::SingleExecutor(k) => ExecutionPlan::Single(k),
        RoutingDecision::FanOut(fleet) => ExecutionPlan::Fanout(fleet),
        RoutingDecision::RequiresPlan => ExecutionPlan::AdvisoryOnly,
        RoutingDecision::Blocked(reason) => ExecutionPlan::Blocked(reason),
    }
}

/// The terminal outcome of a task after (optional) execution + the advisory gate.
/// `ReadyToIntegrate` is the only state that proceeds to the credential-proxy
/// draft-PR path (A.2/A.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskOutcome {
    /// Refused at routing — never executed.
    Blocked(BlockedReason),
    /// Too risky to run autonomously — an advisory plan was produced instead.
    AdvisoryRequested,
    /// Executed, but the verifier accepted no candidate (invariant 13 — nothing
    /// completes without verifier evidence).
    Failed,
    /// Verified, but one or more required blocking reviewers have not reported yet.
    AwaitingReview(Vec<Role>),
    /// Verified, but the required reviewers did not report before the deadline —
    /// refused, never hung.
    ReviewTimedOut(Vec<Role>),
    /// A blocking reviewer vetoed integration (invariant 4).
    ReviewBlocked(Role),
    /// Verified and all gates cleared — ready for the draft-PR path.
    ReadyToIntegrate,
}

/// Folds the execution result and the advisory verdicts into a terminal outcome.
///
/// `verified` is the verifier-owned acceptance — the **only** completion authority
/// (invariants 6, 13): an unverified run is `Failed` no matter what any reviewer said,
/// so an advisory approval can never substitute for verifier evidence. When verified,
/// the advisory gate (C.2) decides whether a blocking review is still required, pending,
/// timed out, vetoing, or cleared.
#[must_use]
pub fn finalize_task(
    task: TaskShape,
    risk: RiskTier,
    verified: bool,
    verdicts: &[(Role, Verdict)],
    waited_ms: u64,
    max_wait_ms: u64,
) -> TaskOutcome {
    // Verifier-owned completion: no advisory verdict resurrects an unverified run.
    if !verified {
        return TaskOutcome::Failed;
    }
    match orchestrate_review(task, risk, verdicts, verified, waited_ms, max_wait_ms) {
        AdvisoryOutcome::NotRequired => TaskOutcome::ReadyToIntegrate,
        AdvisoryOutcome::Pending(roles) => TaskOutcome::AwaitingReview(roles),
        AdvisoryOutcome::TimedOut(roles) => TaskOutcome::ReviewTimedOut(roles),
        AdvisoryOutcome::Decided(decision) => match decision {
            IntegrationDecision::Integrate => TaskOutcome::ReadyToIntegrate,
            IntegrationDecision::BlockedBy { role, .. } => TaskOutcome::ReviewBlocked(role),
            // Should not happen here (we passed verified = true), but stay total:
            // treat any non-integrate decision as still needing the required reviewers.
            IntegrationDecision::NotVerified | IntegrationDecision::MissingReview => {
                TaskOutcome::AwaitingReview(required_reviewers(task, risk))
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crustcore_types::BoundedText;

    const NATIVE: ExecutorKind = ExecutorKind::Native;
    const CODEX: ExecutorKind = ExecutorKind::Codex;

    fn approve(role: Role) -> (Role, Verdict) {
        (role, Verdict::Approve)
    }
    fn block(role: Role, reason: &str) -> (Role, Verdict) {
        (role, Verdict::Block(BoundedText::truncated(reason, 64)))
    }

    // ----- plan_task (routing → execution plan) -----

    #[test]
    fn docs_plans_a_single_executor() {
        assert_eq!(
            plan_task(TaskShape::DocsOnly, RiskTier::Standard, 100, &[NATIVE]),
            ExecutionPlan::Single(NATIVE)
        );
    }

    #[test]
    fn feature_plans_a_fanout_when_affordable() {
        assert_eq!(
            plan_task(
                TaskShape::Feature,
                RiskTier::Standard,
                100,
                &[NATIVE, CODEX]
            ),
            ExecutionPlan::Fanout(vec![NATIVE, CODEX])
        );
    }

    #[test]
    fn security_plans_advisory_only_and_workflow_blocks() {
        assert_eq!(
            plan_task(TaskShape::SecuritySensitive, RiskTier::High, 100, &[NATIVE]),
            ExecutionPlan::AdvisoryOnly
        );
        assert_eq!(
            plan_task(
                TaskShape::WorkflowChange,
                RiskTier::Standard,
                100,
                &[NATIVE]
            ),
            ExecutionPlan::Blocked(BlockedReason::WorkflowChange)
        );
    }

    // ----- finalize_task (verifier + advisory → terminal outcome) -----

    #[test]
    fn an_unverified_run_fails_even_with_reviewer_approval() {
        // Advisory approval can NEVER substitute for verifier evidence (invariant 13).
        let verdicts = [approve(Role::Reviewer), approve(Role::SecurityAuditor)];
        assert_eq!(
            finalize_task(
                TaskShape::SecuritySensitive,
                RiskTier::High,
                false, // not verified
                &verdicts,
                0,
                1000
            ),
            TaskOutcome::Failed
        );
    }

    #[test]
    fn a_verified_low_risk_task_is_ready_to_integrate() {
        assert_eq!(
            finalize_task(TaskShape::Feature, RiskTier::Standard, true, &[], 0, 1000),
            TaskOutcome::ReadyToIntegrate
        );
    }

    #[test]
    fn a_verified_security_task_awaits_then_clears_review() {
        // Verified but no verdicts yet → awaiting the required reviewers.
        assert_eq!(
            finalize_task(
                TaskShape::SecuritySensitive,
                RiskTier::High,
                true,
                &[],
                0,
                1000
            ),
            TaskOutcome::AwaitingReview(vec![Role::Reviewer, Role::SecurityAuditor])
        );
        // Both approve → ready.
        let ok = [approve(Role::Reviewer), approve(Role::SecurityAuditor)];
        assert_eq!(
            finalize_task(
                TaskShape::SecuritySensitive,
                RiskTier::High,
                true,
                &ok,
                0,
                1000
            ),
            TaskOutcome::ReadyToIntegrate
        );
    }

    #[test]
    fn a_reviewer_veto_blocks_a_verified_task() {
        let verdicts = [
            block(Role::Reviewer, "needs a test"),
            approve(Role::SecurityAuditor),
        ];
        assert_eq!(
            finalize_task(
                TaskShape::SecuritySensitive,
                RiskTier::High,
                true,
                &verdicts,
                0,
                1000
            ),
            TaskOutcome::ReviewBlocked(Role::Reviewer)
        );
    }

    #[test]
    fn a_stalled_review_times_out_into_a_refusal() {
        let verdicts = [approve(Role::Reviewer)]; // SecurityAuditor missing
        assert_eq!(
            finalize_task(
                TaskShape::WorkflowChange,
                RiskTier::High,
                true,
                &verdicts,
                1000,
                1000
            ),
            TaskOutcome::ReviewTimedOut(vec![Role::SecurityAuditor])
        );
    }

    // Live seam: the full pipeline against a real sandboxed WorktreeSubagentExecutor —
    // route → run_fanout/run_subagent → verify → finalize → draft PR. The decision
    // cores above are CI-tested; this needs a sandbox backend + a repo worktree.
    #[test]
    #[ignore = "live: route -> sandboxed run_fanout/WorktreeSubagentExecutor -> verify -> finalize -> draft PR (TODO(P3-live-executor-wire))"]
    fn live_executor_wire_smoke() {
        // See docs/live-socket-validation.md §C.6. Requires a sandbox backend
        // (bubblewrap/sandbox-exec), a git repo, and a configured executor.
        panic!("live seam: run manually with a sandbox backend + repo (see runbook §C.6)");
    }
}
