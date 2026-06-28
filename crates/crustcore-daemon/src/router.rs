// SPDX-License-Identifier: Apache-2.0
//! Task-shape executor routing (roadmap-v0.6 C.1).
//!
//! A **pure** decision: given a task's [`TaskShape`], its [`RiskTier`], the available
//! context budget, and the configured [`ExecutorKind`]s, choose *how* to run it —
//! one executor (quick), a verifier-owned fan-out (feature work), an advisory plan
//! (risky work), or blocked (a workflow/policy change that needs human approval
//! first).
//!
//! Routing selects a **worker, never authority** (invariant 6): the verifier still
//! owns completion (invariant 13), and a [`RoutingDecision::Blocked`] *structures a
//! refusal* rather than letting the model proceed on its own say-so (invariant 4).
//!
//! The live inch — the supervisor actually spawning agents per the decision — reuses
//! the existing `exec::run_fanout` / `exec::run_subagent` seams (`TODO(P11-exec-live)`).
//! This module is pure and fully CI-tested; it adds no new live seam.

use crate::product::{ExecutorKind, RiskTier, TaskShape};

/// The minimum context-budget units a fan-out is worth: a fan-out runs several
/// workers, so below this we run a single executor even when two are configured.
pub const MIN_FANOUT_CONTEXT_BUDGET: u64 = 2;

/// Max executors a fan-out will spawn (bounded — invariant 11; runaway fan-out is a
/// budget-exhaustion threat, CLAUDE.md §7.5).
pub const MAX_FANOUT: usize = 2;

/// Why a task was refused at the routing boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockedReason {
    /// A workflow/CI/policy automation change — needs typed human approval before any
    /// executor runs (invariant 4; CLAUDE.md §6.3).
    WorkflowChange,
    /// No executor was configured, so nothing can run.
    NoExecutorConfigured,
}

impl BlockedReason {
    /// Stable label for audit/cockpit views.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            BlockedReason::WorkflowChange => "workflow-change-requires-approval",
            BlockedReason::NoExecutorConfigured => "no-executor-configured",
        }
    }
}

/// How CrustCore should execute a task. Selection only — completion is still the
/// verifier's (invariant 13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingDecision {
    /// Run exactly one executor (the quick/cheap path).
    SingleExecutor(ExecutorKind),
    /// Fan out to several executors; the verifier picks the winning patch.
    FanOut(Vec<ExecutorKind>),
    /// Too risky for autonomous execution: produce an advisory plan for human review
    /// (a *separate* advisory role, never the executor's authority — invariant 4).
    RequiresPlan,
    /// Refused here; the reason structures the refusal for the operator.
    Blocked(BlockedReason),
}

/// Picks the single executor to run, preferring the local/native path, then Claude
/// Code, then whatever is configured first. `configured` is assumed non-empty.
fn pick_single(configured: &[ExecutorKind]) -> ExecutorKind {
    for preferred in [ExecutorKind::Native, ExecutorKind::ClaudeCode] {
        if configured.contains(&preferred) {
            return preferred;
        }
    }
    configured[0]
}

/// Picks up to [`MAX_FANOUT`] distinct executors for a fan-out, preserving the
/// configured order (deterministic). Falls back to a single-element list if only one
/// distinct executor is configured.
fn pick_fanout(configured: &[ExecutorKind]) -> Vec<ExecutorKind> {
    let mut out: Vec<ExecutorKind> = Vec::new();
    for &k in configured {
        if out.len() >= MAX_FANOUT {
            break;
        }
        if !out.contains(&k) {
            out.push(k);
        }
    }
    out
}

/// Decides how to run a task. **Pure and total** — every shape/risk/config combination
/// returns a decision, and the chosen executor(s) are always drawn from `configured`.
///
/// Rules (in order, ~5):
/// 1. `WorkflowChange` → `Blocked(WorkflowChange)` (never auto-run policy/CI changes).
/// 2. No executor configured → `Blocked(NoExecutorConfigured)`.
/// 3. `SecuritySensitive` **or** risk ≥ `Critical` → `RequiresPlan` (advisory, not autonomous).
/// 4. `DocsOnly` **or** risk ≤ `Low` → `SingleExecutor` (cheap path).
/// 5. `Feature`/`UiChange` at ≤ `Standard` risk with ≥2 distinct executors and enough
///    budget → `FanOut`; otherwise a `SingleExecutor`.
#[must_use]
pub fn decide_routing(
    task: TaskShape,
    risk: RiskTier,
    context_budget: u64,
    configured: &[ExecutorKind],
) -> RoutingDecision {
    // 1. Workflow/policy changes are never executed autonomously (invariant 4).
    if matches!(task, TaskShape::WorkflowChange) {
        return RoutingDecision::Blocked(BlockedReason::WorkflowChange);
    }
    // 2. Nothing to run with.
    if configured.is_empty() {
        return RoutingDecision::Blocked(BlockedReason::NoExecutorConfigured);
    }
    // 3. Dangerous changes get an advisory plan, not an autonomous executor.
    if matches!(task, TaskShape::SecuritySensitive) || risk >= RiskTier::Critical {
        return RoutingDecision::RequiresPlan;
    }
    // 4. Docs / low-risk: one cheap executor.
    if matches!(task, TaskShape::DocsOnly) || risk <= RiskTier::Low {
        return RoutingDecision::SingleExecutor(pick_single(configured));
    }
    // 5. Feature/UI at standard risk: fan out if affordable, else single.
    if matches!(task, TaskShape::Feature | TaskShape::UiChange)
        && risk <= RiskTier::Standard
        && context_budget >= MIN_FANOUT_CONTEXT_BUDGET
    {
        let fleet = pick_fanout(configured);
        if fleet.len() >= 2 {
            return RoutingDecision::FanOut(fleet);
        }
    }
    // Default: a single executor.
    RoutingDecision::SingleExecutor(pick_single(configured))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NATIVE: ExecutorKind = ExecutorKind::Native;
    const CLAUDE: ExecutorKind = ExecutorKind::ClaudeCode;
    const CODEX: ExecutorKind = ExecutorKind::Codex;

    #[test]
    fn workflow_changes_are_blocked_before_anything_runs() {
        assert_eq!(
            decide_routing(
                TaskShape::WorkflowChange,
                RiskTier::Standard,
                100,
                &[NATIVE]
            ),
            RoutingDecision::Blocked(BlockedReason::WorkflowChange)
        );
    }

    #[test]
    fn no_executor_configured_is_blocked() {
        assert_eq!(
            decide_routing(TaskShape::Feature, RiskTier::Standard, 100, &[]),
            RoutingDecision::Blocked(BlockedReason::NoExecutorConfigured)
        );
    }

    #[test]
    fn security_or_critical_requires_a_plan() {
        assert_eq!(
            decide_routing(
                TaskShape::SecuritySensitive,
                RiskTier::Standard,
                100,
                &[NATIVE]
            ),
            RoutingDecision::RequiresPlan
        );
        assert_eq!(
            decide_routing(
                TaskShape::Feature,
                RiskTier::Critical,
                100,
                &[NATIVE, CODEX]
            ),
            RoutingDecision::RequiresPlan
        );
    }

    #[test]
    fn docs_routes_to_a_single_preferred_executor() {
        // Native preferred when configured.
        assert_eq!(
            decide_routing(
                TaskShape::DocsOnly,
                RiskTier::Standard,
                100,
                &[CODEX, NATIVE]
            ),
            RoutingDecision::SingleExecutor(NATIVE)
        );
        // Else Claude Code.
        assert_eq!(
            decide_routing(
                TaskShape::DocsOnly,
                RiskTier::Standard,
                100,
                &[CODEX, CLAUDE]
            ),
            RoutingDecision::SingleExecutor(CLAUDE)
        );
        // Else first configured.
        assert_eq!(
            decide_routing(TaskShape::DocsOnly, RiskTier::Standard, 100, &[CODEX]),
            RoutingDecision::SingleExecutor(CODEX)
        );
    }

    #[test]
    fn feature_fans_out_when_two_executors_and_budget() {
        let d = decide_routing(
            TaskShape::Feature,
            RiskTier::Standard,
            100,
            &[NATIVE, CODEX],
        );
        assert_eq!(d, RoutingDecision::FanOut(vec![NATIVE, CODEX]));
        // Fan-out is bounded to MAX_FANOUT even with more configured.
        if let RoutingDecision::FanOut(fleet) = decide_routing(
            TaskShape::Feature,
            RiskTier::Standard,
            100,
            &[NATIVE, CODEX, CLAUDE],
        ) {
            assert!(fleet.len() <= MAX_FANOUT);
        } else {
            panic!("expected fan-out");
        }
    }

    #[test]
    fn feature_runs_single_when_budget_too_low_or_one_executor() {
        // Budget below the fan-out threshold → single.
        assert_eq!(
            decide_routing(TaskShape::Feature, RiskTier::Standard, 1, &[NATIVE, CODEX]),
            RoutingDecision::SingleExecutor(NATIVE)
        );
        // Only one configured → single even with budget.
        assert_eq!(
            decide_routing(TaskShape::Feature, RiskTier::Standard, 100, &[CODEX]),
            RoutingDecision::SingleExecutor(CODEX)
        );
    }

    #[test]
    fn every_combo_is_total_and_picks_from_configured() {
        let shapes = [
            TaskShape::Unknown,
            TaskShape::BugFix,
            TaskShape::Feature,
            TaskShape::UiChange,
            TaskShape::DependencyChange,
            TaskShape::DocsOnly,
            TaskShape::WorkflowChange,
            TaskShape::SecuritySensitive,
        ];
        let risks = [
            RiskTier::Low,
            RiskTier::Standard,
            RiskTier::High,
            RiskTier::Critical,
        ];
        let configs: &[&[ExecutorKind]] = &[&[], &[NATIVE], &[NATIVE, CODEX, CLAUDE]];
        for &task in &shapes {
            for &risk in &risks {
                for &cfg in configs {
                    for &budget in &[0u64, 1, 100] {
                        let d = decide_routing(task, risk, budget, cfg);
                        // Any chosen executor must be from the configured list.
                        match &d {
                            RoutingDecision::SingleExecutor(k) => assert!(cfg.contains(k)),
                            RoutingDecision::FanOut(fleet) => {
                                assert!(!fleet.is_empty());
                                assert!(fleet.iter().all(|k| cfg.contains(k)));
                            }
                            RoutingDecision::RequiresPlan | RoutingDecision::Blocked(_) => {}
                        }
                    }
                }
            }
        }
    }
}
