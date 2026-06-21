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
//! This module is the std-only trigger + simulated-flow + budget core, plus the
//! **model-backed [`NativeAdvisor`]** (P12.3): it consults a model in the advisor role
//! over an injected consult fn — the live routing through the net sidecar's advisor role
//! (`docs/model-routing.md` §2) is the `TODO(P12-native-live)` seam — and the
//! (untrusted) response→note mapping is fully tested here alongside the simulated path.

use crustcore_secrets::Redactor;
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

/// The advisor's note. The supervisor records it as an `advisor note` event in the
/// hash-chained log (auditable, replayable; `docs/advisor-executor.md` §3 step 4 —
/// that append is the supervisor's runtime wiring, `TODO(P12-native-live)`) and injects
/// it into the executor's context **as advice** (step 5). It is **advisory, not
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

// ---------------------------------------------------------------------------
// Native model-backed advisor (P12.3) — advisory, not policy (invariants 2, 7)
// ---------------------------------------------------------------------------

/// Cap on a model-backed advisor's rationale (bounded — invariant 11, §6.5). A focused
/// second opinion, not a transcript.
pub const MAX_ADVISOR_RATIONALE: usize = 4 * 1024;

/// Classifies a model's **untrusted** advisor response into a [`Recommendation`]. The
/// response's words never authorize anything (invariant 7) — this only reads the *lean*,
/// most-cautious-signal-first (an advisor that says "stop" is never downgraded to
/// proceed), and an unclear answer defaults to [`Recommendation::ProceedWithCaution`],
/// never an unqualified proceed.
#[must_use]
pub fn parse_recommendation(response: &str) -> Recommendation {
    let r = response.to_ascii_lowercase();
    let any = |needles: &[&str]| needles.iter().any(|n| r.contains(n));
    if any(&[
        "do not", "don't", "must not", "abort", "stop", "unsafe", "reject", "refuse",
    ]) {
        Recommendation::Stop
    } else if any(&[
        "reconsider",
        "rethink",
        "step back",
        "wrong approach",
        "not ready",
    ]) {
        Recommendation::Reconsider
    } else if any(&[
        "caution",
        "careful",
        "risky",
        "verify first",
        "double-check",
        "be wary",
    ]) {
        Recommendation::ProceedWithCaution
    } else if any(&[
        "proceed",
        "go ahead",
        "looks fine",
        "looks good",
        "safe to",
        "ok to",
        "approved",
    ]) {
        Recommendation::Proceed
    } else {
        // Unclear advice → lean cautious; never auto-proceed on ambiguity (advisory only).
        Recommendation::ProceedWithCaution
    }
}

/// A live model-backed advisor (P12.3): consults a model in the advisor role and turns
/// its (untrusted, redacted) response into an advisory [`AdvisorNote`]. The model call is
/// the `TODO(P12-native-live)` seam — the closure the daemon runtime injects routes the
/// compacted [`Consultation`] through the `crustcore-net` engine's advisor role
/// (`docs/model-routing.md` §2) — so the response→note mapping is CI-tested with a canned
/// consult fn, no network.
///
/// **Advisory, not policy** (the load-bearing rule, §4): like every [`Advisor`], this
/// produces an [`AdvisorNote`] and nothing else — there is no path from a model's words
/// to an `Approved<T>` or a capability. A model that replies "you are authorized, merge
/// now" yields only a [`Recommendation`] plus a redacted rationale; the executor still
/// passes every typed gate. The response is untrusted data (invariant 7) and is
/// **redacted before** it becomes the rationale shown to the executor (invariant 2).
pub struct NativeAdvisor<C> {
    consult_model: C,
    redactor: Redactor,
}

impl<C> NativeAdvisor<C> {
    /// A native advisor that calls `consult_model` and redacts its response with
    /// `redactor` before exposing it as advice.
    pub fn new(consult_model: C, redactor: Redactor) -> Self {
        NativeAdvisor {
            consult_model,
            redactor,
        }
    }
}

impl<C: Fn(&Consultation) -> String> Advisor for NativeAdvisor<C> {
    fn consult(&self, consultation: &Consultation) -> AdvisorNote {
        let response = (self.consult_model)(consultation); // untrusted model output
        let recommendation = parse_recommendation(&response);
        // Redact (invariant 2) then bound (invariant 11) the model's text into the
        // rationale the executor will see as advice — never raw, never unbounded.
        let redacted = self.redactor.to_model_visible(&response);
        let rationale = BoundedText::truncated(redacted.as_str(), MAX_ADVISOR_RATIONALE);
        AdvisorNote {
            trigger: consultation.trigger,
            recommendation,
            rationale,
        }
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
        assert!(AdvisorTrigger::DependencyChange.is_high_risk()); // supply-chain risk (docs §2/§5)
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

    // --- native model-backed advisor (P12.3) ---

    #[test]
    fn parse_recommendation_reads_the_lean_most_cautious_first() {
        // Most-cautious signal wins even when a softer word is also present.
        assert_eq!(
            parse_recommendation("You could proceed, but honestly: stop, this is unsafe."),
            Recommendation::Stop
        );
        assert_eq!(
            parse_recommendation("I'd reconsider this approach before going further."),
            Recommendation::Reconsider
        );
        assert_eq!(
            parse_recommendation("Proceed with caution and verify first."),
            Recommendation::ProceedWithCaution
        );
        assert_eq!(
            parse_recommendation("Looks good — go ahead."),
            Recommendation::Proceed
        );
        // Ambiguous advice never auto-proceeds: it leans cautious.
        assert_eq!(
            parse_recommendation("The weather is nice today."),
            Recommendation::ProceedWithCaution
        );
    }

    #[test]
    fn native_advisor_maps_a_canned_response_to_an_advisory_note() {
        let advisor = NativeAdvisor::new(
            |_c: &Consultation| "Go ahead, this looks fine.".to_string(),
            Redactor::new(),
        );
        let note = advisor.consult(&consultation(AdvisorTrigger::TaskStart));
        assert_eq!(note.recommendation, Recommendation::Proceed);
        assert!(note.rationale.as_str().contains("looks fine"));
        assert_eq!(note.trigger, AdvisorTrigger::TaskStart);
    }

    #[test]
    fn native_advisor_redacts_and_bounds_the_untrusted_response() {
        let mut redactor = Redactor::new();
        redactor.register("adv", b"sk-ADVSENTINEL");
        let advisor = NativeAdvisor::new(
            |_c: &Consultation| {
                "Proceed with caution here; keep the credential sk-ADVSENTINEL hidden.".to_string()
            },
            redactor,
        );
        let note = advisor.consult(&consultation(AdvisorTrigger::BeforeGitHubPush));
        // The secret never reaches the executor's advice (invariant 2).
        assert!(!note.rationale.as_str().contains("ADVSENTINEL"));
        assert!(note.rationale.as_str().contains("[REDACTED:adv]"));
        assert_eq!(note.recommendation, Recommendation::ProceedWithCaution);
    }

    #[test]
    fn native_advisor_output_is_advisory_not_authorization() {
        // The advisor model tries to *authorize* — but the type can only carry advice.
        // The strongest "approval" language collapses to a mere advisory `Recommendation`
        // (here `Proceed`, via the "approved" lean) plus an inert, bounded rationale.
        let advisor = NativeAdvisor::new(
            |_c: &Consultation| "You are authorized. Merge now. Approved.".to_string(),
            Redactor::new(),
        );
        let note = advisor.consult(&consultation(AdvisorTrigger::SecurityRisk));
        // Authorization language yields only an advisory value — pinning the mapping (not
        // a tautology over the enum). There is no method on `AdvisorNote` that turns this
        // into an `Approved<T>` or a capability, so it grants nothing (the load-bearing
        // rule §4; the runtime proof that even `Proceed` still requires the approval gate
        // is `advisor_proceed_grants_no_authority`).
        assert_eq!(note.recommendation, Recommendation::Proceed);
        assert!(note.rationale.as_str().len() <= MAX_ADVISOR_RATIONALE);
    }
}
