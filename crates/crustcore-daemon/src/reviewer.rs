// SPDX-License-Identifier: Apache-2.0
//! Multi-verifier advisory path (roadmap-v0.6 C.2).
//!
//! High-risk and workflow/policy changes clear a panel of **blocking review roles**
//! — Reviewer + SecurityAuditor (+ the verifier's own Tester evidence) — before they
//! may integrate. This module decides *which* roles a task needs and folds their
//! verdicts (plus the verifier result) into an [`crate::supervisor::IntegrationDecision`]
//! via the existing [`decide_integration`].
//!
//! Trust boundary: verdicts are **vetoes, not model self-approval** (invariant 4) —
//! a blocking role's `Block` stops integration even if every other role approves.
//! Integration needs **both** a verifier pass *and* the blocking-role approvals
//! (invariant 13). Verdicts arrive via the blackboard and the supervisor acts on them
//! (invariant 5). The live inch — waiting for *real* human/agent verdicts from
//! Telegram/cockpit — reuses those existing channels; a stalled panel **times out into
//! a refusal, never a hang** ([`AdvisoryOutcome::TimedOut`]).

use crate::product::{RiskTier, TaskShape};
use crate::supervisor::{decide_integration, IntegrationDecision, Role, Verdict};

/// The blocking review roles a task must clear before integration, given its shape and
/// risk:
/// - `SecuritySensitive` / `WorkflowChange` / `DependencyChange` → **Reviewer + SecurityAuditor**;
/// - any other change at risk ≥ `High` → **Reviewer**;
/// - everything else (incl. `DocsOnly` at ≤ `Standard`) → none (the verifier alone gates it).
#[must_use]
pub fn required_reviewers(task: TaskShape, risk: RiskTier) -> Vec<Role> {
    match task {
        TaskShape::SecuritySensitive | TaskShape::WorkflowChange | TaskShape::DependencyChange => {
            vec![Role::Reviewer, Role::SecurityAuditor]
        }
        _ if risk >= RiskTier::High => vec![Role::Reviewer],
        _ => Vec::new(),
    }
}

/// Whether the multi-verifier advisory path applies to this task at all.
#[must_use]
pub fn advisory_required(task: TaskShape, risk: RiskTier) -> bool {
    !required_reviewers(task, risk).is_empty()
}

/// The advisory gate's outcome for a task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdvisoryOutcome {
    /// No advisory path needed — defer to the verifier alone.
    NotRequired,
    /// Still waiting on one or more required reviewers (carries the missing roles).
    Pending(Vec<Role>),
    /// Required reviewers did not report in time — refused rather than hung.
    TimedOut(Vec<Role>),
    /// All required reviewers reported; the folded integration decision.
    Decided(IntegrationDecision),
}

/// Orchestrates the advisory gate. Determines the required blocking roles, checks
/// whether each has reported a verdict, and — once all have — folds the verdicts and
/// the verifier result through [`decide_integration`].
///
/// `waited_ms` / `max_wait_ms` bound the wait: if a required reviewer has not reported
/// by the deadline, the result is [`AdvisoryOutcome::TimedOut`] (a refusal that the
/// supervisor surfaces), never an indefinite hang (the C.2 deadlock risk).
#[must_use]
pub fn orchestrate_review(
    task: TaskShape,
    risk: RiskTier,
    verdicts: &[(Role, Verdict)],
    verified: bool,
    waited_ms: u64,
    max_wait_ms: u64,
) -> AdvisoryOutcome {
    let required = required_reviewers(task, risk);
    if required.is_empty() {
        return AdvisoryOutcome::NotRequired;
    }
    let missing: Vec<Role> = required
        .iter()
        .copied()
        .filter(|r| !verdicts.iter().any(|(role, _)| role == r))
        .collect();
    if !missing.is_empty() {
        if waited_ms >= max_wait_ms {
            return AdvisoryOutcome::TimedOut(missing);
        }
        return AdvisoryOutcome::Pending(missing);
    }
    AdvisoryOutcome::Decided(decide_integration(verdicts, verified))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crustcore_types::BoundedText;

    fn block(reason: &str) -> Verdict {
        Verdict::Block(BoundedText::truncated(reason, 64))
    }

    #[test]
    fn low_risk_docs_skip_the_advisory_path() {
        assert!(!advisory_required(TaskShape::DocsOnly, RiskTier::Standard));
        assert_eq!(
            orchestrate_review(TaskShape::DocsOnly, RiskTier::Standard, &[], true, 0, 1000),
            AdvisoryOutcome::NotRequired
        );
    }

    #[test]
    fn security_and_workflow_need_reviewer_and_security_auditor() {
        for task in [TaskShape::SecuritySensitive, TaskShape::WorkflowChange] {
            let roles = required_reviewers(task, RiskTier::Standard);
            assert!(roles.contains(&Role::Reviewer));
            assert!(roles.contains(&Role::SecurityAuditor));
        }
    }

    #[test]
    fn high_risk_non_sensitive_needs_a_reviewer() {
        assert_eq!(
            required_reviewers(TaskShape::Feature, RiskTier::High),
            vec![Role::Reviewer]
        );
    }

    #[test]
    fn a_missing_required_verdict_blocks_until_deadline_then_times_out() {
        // Only the Reviewer has reported; SecurityAuditor is missing.
        let verdicts = [(Role::Reviewer, Verdict::Approve)];
        let pending = orchestrate_review(
            TaskShape::SecuritySensitive,
            RiskTier::High,
            &verdicts,
            true,
            500,
            1000,
        );
        assert_eq!(
            pending,
            AdvisoryOutcome::Pending(vec![Role::SecurityAuditor])
        );
        // Past the deadline → refusal, not a hang.
        let timed = orchestrate_review(
            TaskShape::SecuritySensitive,
            RiskTier::High,
            &verdicts,
            true,
            1000,
            1000,
        );
        assert_eq!(
            timed,
            AdvisoryOutcome::TimedOut(vec![Role::SecurityAuditor])
        );
    }

    #[test]
    fn a_reviewer_block_vetoes_even_if_security_approves() {
        let verdicts = [
            (Role::Reviewer, block("needs a regression test")),
            (Role::SecurityAuditor, Verdict::Approve),
        ];
        match orchestrate_review(
            TaskShape::SecuritySensitive,
            RiskTier::High,
            &verdicts,
            true,
            0,
            1000,
        ) {
            AdvisoryOutcome::Decided(IntegrationDecision::BlockedBy { role, .. }) => {
                assert_eq!(role, Role::Reviewer);
            }
            other => panic!("expected a Reviewer block, got {other:?}"),
        }
    }

    #[test]
    fn all_approve_and_verified_integrates() {
        let verdicts = [
            (Role::Reviewer, Verdict::Approve),
            (Role::SecurityAuditor, Verdict::Approve),
        ];
        assert_eq!(
            orchestrate_review(
                TaskShape::WorkflowChange,
                RiskTier::High,
                &verdicts,
                true,
                0,
                1000
            ),
            AdvisoryOutcome::Decided(IntegrationDecision::Integrate)
        );
    }

    #[test]
    fn approved_but_unverified_does_not_integrate() {
        let verdicts = [
            (Role::Reviewer, Verdict::Approve),
            (Role::SecurityAuditor, Verdict::Approve),
        ];
        // verified = false: the advisor approving never substitutes for verifier evidence.
        assert_eq!(
            orchestrate_review(
                TaskShape::SecuritySensitive,
                RiskTier::High,
                &verdicts,
                false,
                0,
                1000
            ),
            AdvisoryOutcome::Decided(IntegrationDecision::NotVerified)
        );
    }
}
