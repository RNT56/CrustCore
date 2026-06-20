// SPDX-License-Identifier: Apache-2.0
//! Advisor/executor orchestration (`ROADMAP.md` §13.3, §18 Phase 12;
//! `docs/advisor-executor.md`). At high-risk moments the **executor** is paused
//! and an **advisor** (a higher-reasoning model in the advisor role) is consulted
//! for a second opinion before the executor proceeds.
//!
//! The load-bearing rule (`docs/advisor-executor.md` §4, Phase 12 acceptance):
//! **advisor output is advisory, not policy.** An advisor saying "go ahead"
//! mints no `Approved<T>` (invariant 4), grants no capability and relaxes no policy
//! (invariant 8), and cannot reach the user (invariant 5). It is untrusted model
//! output that improves judgment but holds no power — the typed gates
//! (`Approved<T>`, sandbox profiles, verifier-owned completion) still decide what is
//! actually permitted. This is structural here: [`AdvisorNote`] has **no** path to
//! an approval/capability.
//!
//! This module is the std-only trigger + simulated-flow + budget core. The native
//! provider advisor (P12.3) routes through the net sidecar's advisor role
//! (`docs/model-routing.md` §2; `TODO(P12-native)`); the simulated harness here is
//! the deterministic, fully-tested path.

use crustcore_types::BoundedText;

/// How the advisor is realized (`docs/advisor-executor.md` §1; P12.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvisorMode {
    /// No advisor loop (nano-equivalent: local verifier tasks only).
    Off,
    /// CrustCore orchestrates the consultation itself (the simulated flow, §3).
    Simulated,
    /// The provider's built-in advisor/second-model mechanism.
    Native,
}

/// The moments an advisor is consulted (`docs/advisor-executor.md` §2; P12.4). Not
/// every model call — only these high-leverage boundaries (invariant 11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdvisorTrigger {
    /// At task start — set direction before committing effort.
    TaskStart,
    /// Before a high-leverage, expensive-to-reverse design choice.
    ArchitectureDecision,
    /// Before a large patch — big diffs concentrate risk.
    LargePatch,
    /// Before a dependency change — supply-chain + size risk.
    DependencyChange,
    /// Before a CI/workflow modification — touches elevated CI credentials.
    WorkflowModification,
    /// After repeated failure — a stuck executor benefits from a fresh perspective.
    RepeatedFailure,
    /// Before a GitHub push — the last checkpoint before a side effect leaves local.
    BeforeGitHubPush,
    /// On low executor confidence.
    LowConfidence,
    /// On a security-sensitive change.
    SecurityRisk,
}

impl AdvisorTrigger {
    /// Whether this trigger is **high-risk** — preserved even under budget pressure
    /// (`docs/advisor-executor.md` §5). The riskiest steps (security, leaving the
    /// local boundary, elevated-credential surfaces) are never silently skipped.
    #[must_use]
    pub fn is_high_risk(self) -> bool {
        matches!(
            self,
            AdvisorTrigger::SecurityRisk
                | AdvisorTrigger::BeforeGitHubPush
                | AdvisorTrigger::WorkflowModification
                | AdvisorTrigger::DependencyChange
        )
    }
}

/// A **compacted, focused** consultation prompt (`docs/advisor-executor.md` §3
/// step 2): the decision at hand, relevant evidence, the proposed action — never
/// the whole transcript (keeps the call cheap; invariant 11). Untrusted material
/// stays wrapped as data (invariant 7).
#[derive(Debug, Clone)]
pub struct Consultation {
    /// What prompted the consult.
    pub trigger: AdvisorTrigger,
    /// The decision at hand (bounded).
    pub decision: BoundedText,
    /// The action the executor proposes (bounded).
    pub proposed_action: BoundedText,
}

/// The advisor's recommendation — **advisory only**. None of these grant authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recommendation {
    /// Looks fine to attempt (still subject to the typed gates).
    Proceed,
    /// Attempt, but with named caution.
    ProceedWithCaution,
    /// Rethink before attempting.
    Reconsider,
    /// Do not attempt this.
    Stop,
}

/// The advisor's note — persisted as an `advisor note` event in the hash-chained
/// log (auditable, replayable; `docs/advisor-executor.md` §3 step 4) and injected
/// into the executor's context **as advice** (step 5). It is **advisory, not
/// policy**: there is deliberately no method here that yields an `Approved<T>`, a
/// capability, or any authorization — the executor must still pass the typed gates
/// (`docs/advisor-executor.md` §4).
#[derive(Debug, Clone)]
pub struct AdvisorNote {
    /// The trigger this note answers.
    pub trigger: AdvisorTrigger,
    /// The recommendation (advisory).
    pub recommendation: Recommendation,
    /// A bounded rationale to weigh.
    pub rationale: BoundedText,
}

impl AdvisorNote {
    /// A one-line audit summary for the `advisor note` log event.
    #[must_use]
    pub fn audit_summary(&self) -> String {
        format!(
            "advisor[{:?}] {:?}: {}",
            self.trigger,
            self.recommendation,
            self.rationale.as_str()
        )
    }
}

/// Per-task advisor budget (`docs/advisor-executor.md` §5; P12.5).
#[derive(Debug, Clone, Copy)]
pub struct AdvisorBudget {
    /// Max advisor consultations per task (prevents an "advise about every step"
    /// loop, especially around `RepeatedFailure`).
    pub max_consults_per_task: u32,
}

/// Whether (and why not) to consult the advisor for a trigger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsultDecision {
    /// Consult the advisor.
    Consult,
    /// The advisor is off.
    SkipDisabled,
    /// The per-task consult budget is exhausted.
    SkipBudgetExhausted,
    /// Budget is tight and this is a low-value trigger — preserved budget goes to
    /// high-risk consults (`docs/advisor-executor.md` §5).
    SkipLowValueUnderPressure,
}

/// Decides whether to consult the advisor. Off → never; over the per-task cap →
/// skip; under budget pressure a low-risk trigger is skipped while a high-risk one
/// is preserved; otherwise consult. This is the budget control of invariant 11.
#[must_use]
pub fn should_consult(
    mode: AdvisorMode,
    trigger: AdvisorTrigger,
    consults_so_far: u32,
    budget: &AdvisorBudget,
    budget_pressure: bool,
) -> ConsultDecision {
    if mode == AdvisorMode::Off {
        return ConsultDecision::SkipDisabled;
    }
    if consults_so_far >= budget.max_consults_per_task {
        return ConsultDecision::SkipBudgetExhausted;
    }
    if budget_pressure && !trigger.is_high_risk() {
        return ConsultDecision::SkipLowValueUnderPressure;
    }
    ConsultDecision::Consult
}

/// Something that can answer a [`Consultation`]. The native provider advisor (P12.3)
/// implements this over the model router; [`SimulatedAdvisor`] is the deterministic
/// in-process harness (P12.2). Either way the result is an advisory [`AdvisorNote`].
pub trait Advisor {
    /// Produces an advisory note for the consultation.
    fn consult(&self, consultation: &Consultation) -> AdvisorNote;
}

/// A deterministic simulated advisor (P12.2) for dev/tests and providers without a
/// native advisor mode. Its heuristic is intentionally conservative: high-risk
/// triggers get a caution-or-reconsider lean. It holds no authority — it only
/// produces advice.
#[derive(Debug, Clone, Copy, Default)]
pub struct SimulatedAdvisor;

impl Advisor for SimulatedAdvisor {
    fn consult(&self, consultation: &Consultation) -> AdvisorNote {
        let recommendation = match consultation.trigger {
            AdvisorTrigger::SecurityRisk | AdvisorTrigger::WorkflowModification => {
                Recommendation::Reconsider
            }
            AdvisorTrigger::BeforeGitHubPush | AdvisorTrigger::DependencyChange => {
                Recommendation::ProceedWithCaution
            }
            AdvisorTrigger::RepeatedFailure => Recommendation::Reconsider,
            _ => Recommendation::Proceed,
        };
        AdvisorNote {
            trigger: consultation.trigger,
            recommendation,
            rationale: BoundedText::truncated(
                format!(
                    "simulated advisor on {:?}: weigh the proposed action against the decision; \
                     this is advice only — the typed approval/verifier gates still apply.",
                    consultation.trigger
                ),
                BoundedText::DEFAULT_MAX,
            ),
        }
    }
}

/// Runs the consultation step of the simulated flow (`docs/advisor-executor.md` §3):
/// if [`should_consult`] says so, the executor is (conceptually) paused, the advisor
/// is asked, and the advisory note is returned for the caller to record as an event
/// and inject into executor context. Returns the skip reason via `Err` when no
/// consult happens. **The note never authorizes anything** (§4).
///
/// # Errors
/// The [`ConsultDecision`] skip reason when no consultation occurs.
pub fn consult_before<A: Advisor>(
    advisor: &A,
    mode: AdvisorMode,
    consults_so_far: u32,
    budget: &AdvisorBudget,
    budget_pressure: bool,
    consultation: &Consultation,
) -> Result<AdvisorNote, ConsultDecision> {
    match should_consult(
        mode,
        consultation.trigger,
        consults_so_far,
        budget,
        budget_pressure,
    ) {
        ConsultDecision::Consult => Ok(advisor.consult(consultation)),
        skip => Err(skip),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn consultation(trigger: AdvisorTrigger) -> Consultation {
        Consultation {
            trigger,
            decision: BoundedText::truncated("push the verified patch", 256),
            proposed_action: BoundedText::truncated("git push crustcore/x", 256),
        }
    }

    fn budget(n: u32) -> AdvisorBudget {
        AdvisorBudget {
            max_consults_per_task: n,
        }
    }

    // --- triggers + consult decision (P12.4/P12.5) ---

    #[test]
    fn high_risk_triggers_are_classified() {
        assert!(AdvisorTrigger::SecurityRisk.is_high_risk());
        assert!(AdvisorTrigger::BeforeGitHubPush.is_high_risk());
        assert!(AdvisorTrigger::WorkflowModification.is_high_risk());
        assert!(!AdvisorTrigger::TaskStart.is_high_risk());
        assert!(!AdvisorTrigger::LargePatch.is_high_risk());
    }

    #[test]
    fn executor_consults_before_a_high_risk_action() {
        // Acceptance: the executor can consult before a high-risk action.
        assert_eq!(
            should_consult(
                AdvisorMode::Simulated,
                AdvisorTrigger::BeforeGitHubPush,
                0,
                &budget(3),
                false
            ),
            ConsultDecision::Consult
        );
    }

    #[test]
    fn advisor_off_never_consults() {
        assert_eq!(
            should_consult(
                AdvisorMode::Off,
                AdvisorTrigger::SecurityRisk,
                0,
                &budget(3),
                false
            ),
            ConsultDecision::SkipDisabled
        );
    }

    #[test]
    fn budget_cap_stops_runaway_consultation() {
        // At the cap, further consults are skipped (invariant 11; the repeated-
        // failure loop cannot recurse forever).
        assert_eq!(
            should_consult(
                AdvisorMode::Simulated,
                AdvisorTrigger::RepeatedFailure,
                3,
                &budget(3),
                false
            ),
            ConsultDecision::SkipBudgetExhausted
        );
    }

    #[test]
    fn budget_pressure_preserves_high_risk_drops_low_value() {
        // Under pressure: a low-value trigger is dropped...
        assert_eq!(
            should_consult(
                AdvisorMode::Simulated,
                AdvisorTrigger::TaskStart,
                0,
                &budget(3),
                true
            ),
            ConsultDecision::SkipLowValueUnderPressure
        );
        // ...but a high-risk one is preserved.
        assert_eq!(
            should_consult(
                AdvisorMode::Simulated,
                AdvisorTrigger::SecurityRisk,
                0,
                &budget(3),
                true
            ),
            ConsultDecision::Consult
        );
    }

    // --- simulated advisor harness (P12.2) ---

    #[test]
    fn simulated_advisor_is_deterministic_and_conservative() {
        let a = SimulatedAdvisor;
        let note = a.consult(&consultation(AdvisorTrigger::SecurityRisk));
        assert_eq!(note.recommendation, Recommendation::Reconsider);
        // Deterministic.
        assert_eq!(
            a.consult(&consultation(AdvisorTrigger::SecurityRisk))
                .recommendation,
            Recommendation::Reconsider
        );
        assert!(note.audit_summary().contains("advisor[SecurityRisk]"));
    }

    // --- advisory, NOT policy (the load-bearing rule, §4; acceptance) ---

    #[test]
    fn advisor_proceed_grants_no_authority() {
        use crate::github::{decide_merge, MergeDecision};
        use crustcore_types::Timestamp;

        // The advisor blesses a push.
        let note = SimulatedAdvisor.consult(&consultation(AdvisorTrigger::BeforeGitHubPush));
        assert!(matches!(
            note.recommendation,
            Recommendation::Proceed | Recommendation::ProceedWithCaution
        ));
        // ...yet there is NO path from an AdvisorNote to an Approved<T>: the merge
        // gate still requires a human approval (None here) regardless of the advice
        // (invariants 4, 8). The advisor changes *what is attempted*, not *what is
        // permitted*.
        assert_eq!(
            decide_merge(None, Timestamp::from_millis(1)),
            MergeDecision::RequiresApproval
        );
    }

    #[test]
    fn consult_before_skips_when_budget_exhausted() {
        let a = SimulatedAdvisor;
        let c = consultation(AdvisorTrigger::TaskStart);
        assert!(matches!(
            consult_before(&a, AdvisorMode::Simulated, 5, &budget(5), false, &c),
            Err(ConsultDecision::SkipBudgetExhausted)
        ));
        assert!(consult_before(&a, AdvisorMode::Simulated, 0, &budget(5), false, &c).is_ok());
    }
}
