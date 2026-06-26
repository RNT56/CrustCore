// SPDX-License-Identifier: Apache-2.0
//! Safe self-improvement (`ROADMAP.md` §18 Phase 15; `docs/self-improvement.md`).
//! CrustCore improves itself the way any repo is improved: it **proposes changes as
//! PRs**, gated by **evals** and a **contract-file gate**, and a **human maintainer
//! merges**. There is no path from "the agent learned something" to a change in the
//! running kernel's policy/sandbox/secret behavior (invariant 18).
//!
//! This module is the std-only core of that loop:
//! - [`classify`] — the failure classifier (P15.1): name the real cause.
//! - [`ImprovementProposal`] — the typed proposal artifact (P15.2). Its
//!   [`ProposalTarget`] can express **only** prompt/tool/config changes; there is by
//!   construction **no** variant that targets policy, sandbox, or secrets — those
//!   live in contract files and can only change through the gate below.
//! - [`ReadyProposal`] — eval/regression gating (P15.3): a proposal **cannot
//!   advance** without both a demonstration and a regression guard. `ReadyProposal`
//!   is type-sealed (like `VerifiedPatch`): the only way to mint one is
//!   [`ReadyProposal::prepare`], which refuses evidence-free proposals.
//! - [`plan_self_pr`] — the self-PR workflow (P15.4): a self-PR is **not
//!   privileged** — it is a draft PR that still needs the normal `VerifiedPatch` +
//!   `Approved` gate to merge (invariants 13/14; never self-merges).
//! - [`contract_gate`] — the contract-file gate (P15.5): a self-PR touching **any**
//!   contract file is flagged `RequiresMaintainerApproval` and cannot auto-advance,
//!   catching the *silent-weakening* attack (`docs/self-improvement.md` §4).
//!
//! **No live mutation, by construction:** every function here returns an inert
//! *artifact* or *decision* (data). Nothing takes `&mut` of a running policy,
//! sandbox, or secret store — the module has no power to change the kernel; it can
//! only emit proposals a human must merge.
//!
//! **Memory is never authority** (`docs/self-improvement.md` §2): the classifier may
//! draw on failure memory, but a memory entry alone mints nothing — it only seeds a
//! proposal that must still pass [`ReadyProposal::prepare`] and the gate.
//!
//! **Live wiring (behind the `live` feature) preserves every gate.** [`LiveEvalRunner`]
//! dispatches each eval to a sandboxed subagent worker and emits an [`EvalRef`] only when
//! the eval's verifier passed (evidence, never a say-so). [`draft_pr_request`] connects a
//! `DraftReady` cycle outcome to the GitHub flow — but it routes through
//! `crustcore_backend::integrate::open_pr`, which **structurally requires** a
//! `VerifiedPatch` (by value) + a valid `Approved<GitHubWriteCap>` and always opens a
//! **draft** (invariants 13, 14). So the live half adds no power: there is still no
//! `Merged`/`Applied` outcome, no live kernel mutation, and the contract-file gate still
//! blocks any guardrail-touching change. The real eval run + the PR POST are the reduced
//! `TODO(B5-autoloop-live)` seams (`#[ignore]`d); the mapping is CI-tested.

use crustcore_types::BoundedText;

// ---------------------------------------------------------------------------
// Failure classifier (P15.1)
// ---------------------------------------------------------------------------

/// A named failure cause — so an improvement targets a real category rather than a
/// one-off (`docs/self-improvement.md` §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureClass {
    /// The approach was wrong (re-plan, don't patch the symptom).
    WrongApproach,
    /// The verifier is nondeterministic (a flaky test, not a real regression).
    FlakyVerifier,
    /// The model lacked context it needed (retrieval/capsule gap).
    MissingContext,
    /// The prompt was ambiguous or deficient.
    PromptDeficiency,
    /// A needed tool was missing or awkward (tool gap/ergonomics).
    ToolGap,
    /// A recurring error class seen across runs.
    RecurringError,
    /// Not enough signal to classify (the safe default — proposes nothing specific).
    Unclassified,
}

/// The observed, untrusted signal a failure produced. It is *prior observation*
/// (invariant 7; `docs/self-improvement.md` §2), not authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FailureSignal {
    /// The verifier command failed (non-zero exit).
    pub verifier_failed: bool,
    /// The same input produced different verifier outcomes (nondeterminism).
    pub nondeterministic: bool,
    /// How many times this same failure recurred.
    pub repetitions: u32,
    /// The model signaled it lacked needed context.
    pub context_missing: bool,
    /// A required tool was unavailable.
    pub tool_unavailable: bool,
    /// The prompt was flagged ambiguous/insufficient.
    pub prompt_ambiguous: bool,
}

/// Classifies a failure signal into a named cause. Deterministic; specific causes
/// take precedence over generic ones, and an unhelpful signal stays `Unclassified`
/// (never invents a cause). A flaky verifier is recognized **before** "wrong
/// approach" so a nondeterministic test is not mistaken for a real regression.
#[must_use]
pub fn classify(signal: &FailureSignal) -> FailureClass {
    if signal.nondeterministic {
        return FailureClass::FlakyVerifier;
    }
    if signal.tool_unavailable {
        return FailureClass::ToolGap;
    }
    if signal.context_missing {
        return FailureClass::MissingContext;
    }
    if signal.prompt_ambiguous {
        return FailureClass::PromptDeficiency;
    }
    if signal.repetitions >= 2 {
        return FailureClass::RecurringError;
    }
    if signal.verifier_failed {
        return FailureClass::WrongApproach;
    }
    FailureClass::Unclassified
}

// ---------------------------------------------------------------------------
// Improvement proposal artifact (P15.2)
// ---------------------------------------------------------------------------

/// What an improvement may target. **By construction this enumerates only the
/// permitted scope** (`docs/self-improvement.md` §3.2, Phase 15 acceptance: "propose
/// prompt/tool/config improvements"): there is deliberately **no** variant for
/// policy, sandbox, or secrets. Those are contract-file concerns and can change only
/// through the [`contract_gate`] with explicit maintainer approval — a proposal
/// cannot even *express* "weaken the sandbox".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalTarget {
    /// A prompt improvement.
    Prompt,
    /// A tool definition / tool-ergonomics change.
    ToolDefinition,
    /// A non-contract config / default change.
    Config,
}

/// The proposer's risk estimate (advisory metadata).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalRisk {
    /// Low risk.
    Low,
    /// Medium risk.
    Medium,
    /// High risk.
    High,
}

/// A typed improvement proposal (`docs/self-improvement.md` §3.2) — not a free-text
/// suggestion: what to change, the failure class it addresses, the expected effect,
/// and the risk. It is inert data; it grants nothing on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImprovementProposal {
    /// The failure class this addresses.
    pub failure_class: FailureClass,
    /// What it targets (constrained to the permitted scope).
    pub target: ProposalTarget,
    /// Why — bounded rationale.
    pub rationale: BoundedText,
    /// The expected effect — bounded.
    pub expected_effect: BoundedText,
    /// The proposer's risk estimate.
    pub risk: ProposalRisk,
}

// ---------------------------------------------------------------------------
// Eval / regression gating (P15.3) — a proposal cannot advance without evidence
// ---------------------------------------------------------------------------

/// What an attached eval proves (`docs/self-improvement.md` §3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvalKind {
    /// Demonstrates the improvement helps.
    Demonstrates,
    /// Guards against regression (proves it breaks nothing existing).
    GuardsRegression,
}

/// A reference to an eval/regression backing a proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvalRef {
    /// The eval's name/id (in the eval suite).
    pub name: BoundedText,
    /// What it proves.
    pub kind: EvalKind,
}

/// Why a proposal could not advance to a [`ReadyProposal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvanceError {
    /// No eval demonstrates the improvement helps (P15.3).
    NoDemonstration,
    /// No eval guards against regression (P15.3).
    NoRegressionGuard,
}

/// A proposal that has cleared the evidence bar — **type-sealed**. The only way to
/// obtain one is [`ReadyProposal::prepare`], which refuses an evidence-free proposal
/// (`docs/self-improvement.md` §3.3, §7.1 "evals required"). A `ReadyProposal` is the
/// self-improvement analogue of `VerifiedPatch`: evidence, not a model's say-so, is
/// what lets a proposal advance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyProposal {
    // Private fields: cannot be constructed outside this module except via `prepare`.
    proposal: ImprovementProposal,
    evidence: Vec<EvalRef>,
}

impl ReadyProposal {
    /// Advances a proposal to ready **iff** it carries both a demonstration and a
    /// regression guard. A proposal without supporting evals does not advance — the
    /// same evidence discipline the verifier applies to any change.
    ///
    /// # Errors
    /// [`AdvanceError::NoDemonstration`] / [`AdvanceError::NoRegressionGuard`] if the
    /// corresponding eval kind is absent.
    pub fn prepare(
        proposal: ImprovementProposal,
        evidence: Vec<EvalRef>,
    ) -> Result<ReadyProposal, AdvanceError> {
        if !evidence.iter().any(|e| e.kind == EvalKind::Demonstrates) {
            return Err(AdvanceError::NoDemonstration);
        }
        if !evidence
            .iter()
            .any(|e| e.kind == EvalKind::GuardsRegression)
        {
            return Err(AdvanceError::NoRegressionGuard);
        }
        Ok(ReadyProposal { proposal, evidence })
    }

    /// The underlying proposal.
    #[must_use]
    pub fn proposal(&self) -> &ImprovementProposal {
        &self.proposal
    }

    /// The backing evals.
    #[must_use]
    pub fn evidence(&self) -> &[EvalRef] {
        &self.evidence
    }
}

// ---------------------------------------------------------------------------
// Contract-file gate (P15.5) — invariant 18 / docs/self-improvement.md §4
// ---------------------------------------------------------------------------

/// The contract files (`CLAUDE.md` §7.3, `docs/self-improvement.md` §4). A change to
/// any of these is the trust boundary — it can only ship with explicit maintainer
/// approval and serialized review, never auto-advanced by the improvement loop.
pub const CONTRACT_FILES: &[&str] = &[
    "CLAUDE.md",
    "AGENTS.md",
    "INVARIANTS.md",
    "THREAT_MODEL.md",
    "SECURITY.md",
    "docs/policy.md",
    "docs/secrets.md",
    "docs/sandbox.md",
    "docs/backend-contract.md",
    "crates/crustcore-kernel/src/event.rs",
    "crates/crustcore-kernel/src/action.rs",
    "crates/crustcore-policy/src/decision.rs",
    "crates/crustcore-secrets/src/lib.rs",
    "Cargo.toml",
    "Cargo.lock",
];

/// Normalizes a changed-path string into a repo-relative, lowercase, single-slash
/// form for robust gate matching. The gate's stated posture is to **err toward
/// flagging** (a false positive only asks a human), so normalization is deliberately
/// aggressive and matches the case-insensitive convention CrustCore already uses in
/// its sibling path guards (`crustcore-worktree::tools` `.git` guard,
/// `crustcore-sandbox` matching — "defense in depth"). It folds the variants an
/// adversarial or non-canonical path source might use to slip a contract file past an
/// exact match: backslash separators, repeated slashes, a leading `./` or `/`, a
/// trailing slash, and case. (Lexical `..` is intentionally not resolved — the
/// canonical caller is `git diff --name-only`, which never emits `..`/`//`.)
fn normalize_contract_path(path: &str) -> String {
    let mut p = path.trim().replace('\\', "/");
    while p.contains("//") {
        p = p.replace("//", "/");
    }
    // Strip any leading "./" segments, then any leading "/" (absolute → repo-relative).
    while let Some(rest) = p.strip_prefix("./") {
        p = rest.to_string();
    }
    let p = p.trim_start_matches('/').trim_end_matches('/');
    p.to_ascii_lowercase()
}

/// Whether `path` is a contract file. Matches the canonical [`CONTRACT_FILES`] paths
/// (after [`normalize_contract_path`], so `docs//policy.md`, `./docs/policy.md`,
/// `/docs/policy.md`, `docs/policy.md/`, `docs\policy.md`, and `DOCS/POLICY.MD` all
/// flag), and additionally **any** `Cargo.toml`/`Cargo.lock` (a dependency manifest
/// anywhere is dependency-policy-sensitive — `CLAUDE.md` §6.4 "no drive-by dependency
/// additions"). Erring toward flagging is correct: a flagged change only *requires a
/// human*, it never weakens anything.
#[must_use]
pub fn is_contract_file(path: &str) -> bool {
    let p = normalize_contract_path(path);
    if CONTRACT_FILES.iter().any(|c| c.eq_ignore_ascii_case(&p)) {
        return true;
    }
    let base = p.rsplit('/').next().unwrap_or(&p);
    matches!(base, "cargo.toml" | "cargo.lock")
}

/// The contract-file gate's decision for a set of changed paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateDecision {
    /// No contract file touched — the improvement loop may auto-advance to a *draft*
    /// PR (which still needs the normal `Approved` gate to merge).
    AutoAdvanceAllowed,
    /// One or more contract files were touched — **blocked from auto-advance**; an
    /// explicit maintainer approval is required, and the contract change must be
    /// serialized into its own task (it may not be bundled here).
    RequiresMaintainerApproval {
        /// The contract files that were touched (sorted, deduped).
        touched: Vec<String>,
    },
}

/// Runs the contract-file gate over a self-PR's changed paths. If **any** path is a
/// contract file — even bundled among unrelated changes — the gate returns
/// [`GateDecision::RequiresMaintainerApproval`]; the loop cannot slip a contract
/// change through by mixing it with prompt/tool/config edits. This is what catches
/// *silent weakening* (`docs/self-improvement.md` §4): loosening a policy decision,
/// widening a sandbox profile, or relaxing a secret type all touch a contract file.
#[must_use]
pub fn contract_gate(changed_paths: &[&str]) -> GateDecision {
    let mut touched: Vec<String> = changed_paths
        .iter()
        .filter(|p| is_contract_file(p))
        // Report the path as the caller gave it (trimmed) so the maintainer sees the
        // actual diff path; matching itself is normalization-robust (is_contract_file).
        .map(|p| p.trim().to_string())
        .collect();
    if touched.is_empty() {
        return GateDecision::AutoAdvanceAllowed;
    }
    touched.sort();
    touched.dedup();
    GateDecision::RequiresMaintainerApproval { touched }
}

// ---------------------------------------------------------------------------
// Self-PR workflow (P15.4)
// ---------------------------------------------------------------------------

/// The outcome of planning a self-PR for a [`ReadyProposal`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelfPrDecision {
    /// May open a **draft** PR for human review. It is not privileged: it still needs
    /// a `VerifiedPatch` + `Approved` to merge (invariants 13/14) and never
    /// self-merges. Carries the proposal's risk for the reviewer.
    DraftPr {
        /// The proposal's risk estimate (advisory).
        risk: ProposalRisk,
    },
    /// Blocked: the change touches contract files and needs explicit maintainer
    /// approval before it can advance at all.
    BlockedPendingMaintainer {
        /// The contract files touched.
        touched: Vec<String>,
    },
}

/// Plans a self-PR: requires an evidence-backed [`ReadyProposal`] (so an
/// unsubstantiated idea can never reach here), runs the [`contract_gate`] over the
/// patch's changed paths, and yields either a draft PR (human-reviewed, never
/// auto-merged) or a maintainer-approval block. This function only ever returns a
/// *decision* — it performs no side effect and mutates no kernel state (invariant
/// 18).
#[must_use]
pub fn plan_self_pr(ready: &ReadyProposal, changed_paths: &[&str]) -> SelfPrDecision {
    match contract_gate(changed_paths) {
        GateDecision::RequiresMaintainerApproval { touched } => {
            SelfPrDecision::BlockedPendingMaintainer { touched }
        }
        GateDecision::AutoAdvanceAllowed => SelfPrDecision::DraftPr {
            risk: ready.proposal().risk,
        },
    }
}

// ---------------------------------------------------------------------------
// The self-improvement loop runner (B5-autoloop) — drive the gated cycle end to end
// ---------------------------------------------------------------------------

/// Runs the evals that back a proposal — the evidence bar [`ReadyProposal::prepare`]
/// requires. The **live** implementation ([`LiveEvalRunner`], behind the `live` feature)
/// dispatches each eval to a sandboxed subagent worker (P11-exec, via the
/// [`SubagentExecutor`](crate::exec::SubagentExecutor)) and emits an [`EvalRef`] **only**
/// for an eval whose verifier passed; a mock drives CI. An eval that does **not** pass
/// yields no [`EvalRef`], so a proposal whose evals fail simply cannot advance — evidence,
/// not a model's say-so, is the gate. The real sandboxed eval run is the reduced
/// `TODO(B5-autoloop-live)` seam (`#[ignore]`d, needs a sandbox backend); the
/// pass→`EvalRef` mapping is CI-tested.
pub trait EvalRunner {
    /// Runs `proposal`'s evals, returning an [`EvalRef`] for **each that passed**.
    fn run_evals(&self, proposal: &ImprovementProposal) -> Vec<EvalRef>;
}

/// The outcome of one self-improvement cycle. There is deliberately **no** `Merged` or
/// `Applied` variant: the best a cycle can produce is a *draft* PR intent — the loop
/// never self-merges and never mutates the running kernel (invariant 18).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CycleOutcome {
    /// Evidence cleared and no contract file was touched: a **draft** self-PR may be
    /// opened for human review (never auto-merged). Carries the proposal's risk.
    DraftReady {
        /// The proposal's advisory risk estimate.
        risk: ProposalRisk,
    },
    /// The change touches a contract file → **blocked**, routed to the maintainer; it
    /// must be serialized into its own approved task, never auto-advanced here.
    BlockedForMaintainer {
        /// The contract files touched.
        touched: Vec<String>,
    },
    /// The proposal could not advance: its evals did not establish the required evidence
    /// (no demonstration and/or no regression guard).
    NotReady(AdvanceError),
}

/// Drives one self-improvement cycle end to end over the P15 core: run `proposal`'s evals
/// (via `eval_runner`), require **both** a demonstration and a regression guard
/// ([`ReadyProposal::prepare`]), then run the contract-gate over the proposed
/// `changed_paths` ([`plan_self_pr`]). It only ever returns a **decision** — a draft PR
/// intent or a maintainer block — and mutates no kernel state (invariant 18).
///
/// The structural guarantees of the core hold unchanged: a proposal cannot even *express*
/// weakening a guardrail ([`ProposalTarget`] has no policy/sandbox/secrets variant), a
/// contract-touching change is blocked here ([`contract_gate`]), an evidence-free proposal
/// cannot advance, and there is **no path to self-merge** ([`CycleOutcome`] tops out at a
/// draft). This is the gated half the live evals/PRs (`TODO(B5-autoloop-live)`) drive.
#[must_use]
pub fn run_cycle(
    proposal: ImprovementProposal,
    changed_paths: &[&str],
    eval_runner: &dyn EvalRunner,
) -> CycleOutcome {
    let evidence = eval_runner.run_evals(&proposal);
    let ready = match ReadyProposal::prepare(proposal, evidence) {
        Ok(r) => r,
        Err(e) => return CycleOutcome::NotReady(e),
    };
    match plan_self_pr(&ready, changed_paths) {
        SelfPrDecision::DraftPr { risk } => CycleOutcome::DraftReady { risk },
        SelfPrDecision::BlockedPendingMaintainer { touched } => {
            CycleOutcome::BlockedForMaintainer { touched }
        }
    }
}

// ---------------------------------------------------------------------------
// Live eval runner (B5-autoloop-live) — sandboxed eval workers → EvalRefs
// ---------------------------------------------------------------------------

/// One eval the loop runs to back a proposal: a name, what it proves, and the
/// **sandboxed subagent task** (a worker + verify command) that constitutes the eval. The
/// eval passes iff that task's verifier passes (invariant 13) — never on a worker's claim.
#[cfg(feature = "live")]
#[derive(Clone)]
pub struct LiveEval {
    /// The eval's name/id (surfaced in the resulting [`EvalRef`]).
    pub name: BoundedText,
    /// What a pass proves (a demonstration or a regression guard).
    pub kind: EvalKind,
    /// The subagent task whose verifier *is* this eval.
    pub task: crate::exec::SubagentTask,
    /// The agent (registry-bound) to run the eval under.
    pub agent: crate::supervisor::AgentSpec,
}

/// The live [`EvalRunner`] (behind the `live` feature): dispatches each [`LiveEval`] to a
/// sandboxed subagent worker via a [`SubagentExecutor`](crate::exec::SubagentExecutor) and
/// emits an [`EvalRef`] **only** for an eval whose verifier passed. An eval that fails (or
/// could not run) yields no ref, so a proposal whose evals do not establish *both* a
/// demonstration and a regression guard cannot advance ([`ReadyProposal::prepare`]) —
/// evidence is the gate, exactly as in the mock-driven cycle.
///
/// It mutates **no** kernel state and opens **no** PR: it only produces evidence. The real
/// sandboxed eval run is the reduced `TODO(B5-autoloop-live)` seam (`#[ignore]`d, needs a
/// sandbox backend); the pass→`EvalRef` mapping is CI-tested over a mock executor.
#[cfg(feature = "live")]
pub struct LiveEvalRunner<'e> {
    executor: &'e dyn crate::exec::SubagentExecutor,
    evals: Vec<LiveEval>,
}

#[cfg(feature = "live")]
impl<'e> LiveEvalRunner<'e> {
    /// Builds a runner over `executor` and the eval suite `evals`.
    #[must_use]
    pub fn new(executor: &'e dyn crate::exec::SubagentExecutor, evals: Vec<LiveEval>) -> Self {
        LiveEvalRunner { executor, evals }
    }
}

#[cfg(feature = "live")]
impl EvalRunner for LiveEvalRunner<'_> {
    fn run_evals(&self, _proposal: &ImprovementProposal) -> Vec<EvalRef> {
        let mut passed = Vec::new();
        for eval in &self.evals {
            // Run the eval as a sandboxed subagent. Acceptance is the verifier's call: only
            // a `verified` result yields an EvalRef (invariants 6, 13). A run error or a
            // failing verifier contributes NO evidence — the proposal simply can't advance.
            match self.executor.execute(&eval.agent, &eval.task) {
                Ok(result) if result.verified => passed.push(EvalRef {
                    name: eval.name.clone(),
                    kind: eval.kind,
                }),
                _ => {}
            }
        }
        passed
    }
}

// ---------------------------------------------------------------------------
// Draft-PR opening seam (B5-autoloop-live) — gate-preserving
// ---------------------------------------------------------------------------

/// Builds the **draft** PR request for a self-improvement change, routing through the
/// type-13/14 gate `crustcore_backend::integrate::open_pr` (behind the `live` feature).
///
/// This is the connector from a [`CycleOutcome::DraftReady`] to the GitHub flow, and it
/// **cannot widen the gate**: `open_pr` takes a `VerifiedPatch` **by value** (only the
/// verifier mints one — invariant 13) and a valid `Approved<GitHubWriteCap>` (only a human
/// `AuthorizedUser` mints one — invariants 4, 14), and always produces a *draft*
/// (`docs/github.md` §3.1). A self-PR is therefore never privileged: it is a draft awaiting
/// human review, exactly like any other. The actual POST (via `crustcore_net`'s
/// `RestGitHub::create_pull`) is the reduced `TODO(B5-autoloop-live)` socket, `#[ignore]`d.
///
/// `head_branch`/`base_branch` are confined by `open_pr` to the cap's branch prefix; the
/// body is the verifier's evidence (never a model claim).
///
/// # Errors
/// A `crustcore_backend::integrate::IntegrateError` if the approval expired or the head
/// branch is out of the cap's scope (the same fail-closed gate the credential proxy uses).
#[cfg(feature = "live")]
pub fn draft_pr_request(
    approval: &crustcore_policy::Approved<crustcore_policy::GitHubWriteCap>,
    patch: crustcore_backend::VerifiedPatch,
    head_branch: &str,
    base_branch: &str,
    now: crustcore_types::Timestamp,
) -> Result<crustcore_net::github::CreatePrRequest, crustcore_backend::integrate::IntegrateError> {
    // The gate: requires the VerifiedPatch + the live Approved; always a draft.
    let intent =
        crustcore_backend::integrate::open_pr(approval, patch, head_branch, base_branch, now)?;
    debug_assert!(intent.draft, "self-PRs are always draft (invariants 13/14)");
    Ok(crustcore_net::github::CreatePrRequest {
        repo: intent.repo.0.as_str().to_string(),
        head: intent.head_branch,
        base: intent.base_branch,
        title: intent.title,
        body: intent.body,
        draft: true, // never auto-mergeable; a human reviews/merges (invariant 18)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bt(s: &str) -> BoundedText {
        BoundedText::truncated(s, 4096)
    }

    fn proposal(target: ProposalTarget) -> ImprovementProposal {
        ImprovementProposal {
            failure_class: FailureClass::PromptDeficiency,
            target,
            rationale: bt("the task prompt omitted the verify command"),
            expected_effect: bt("fewer missing-context failures"),
            risk: ProposalRisk::Low,
        }
    }

    // --- failure classifier (P15.1) ---

    #[test]
    fn classify_is_deterministic_and_precise() {
        // Flaky is recognized before "wrong approach": a nondeterministic verifier is
        // not a real regression.
        let flaky = FailureSignal {
            verifier_failed: true,
            nondeterministic: true,
            ..Default::default()
        };
        assert_eq!(classify(&flaky), FailureClass::FlakyVerifier);

        assert_eq!(
            classify(&FailureSignal {
                tool_unavailable: true,
                ..Default::default()
            }),
            FailureClass::ToolGap
        );
        assert_eq!(
            classify(&FailureSignal {
                context_missing: true,
                ..Default::default()
            }),
            FailureClass::MissingContext
        );
        assert_eq!(
            classify(&FailureSignal {
                repetitions: 3,
                ..Default::default()
            }),
            FailureClass::RecurringError
        );
        assert_eq!(
            classify(&FailureSignal {
                verifier_failed: true,
                ..Default::default()
            }),
            FailureClass::WrongApproach
        );
        // No useful signal → Unclassified (never invents a cause).
        assert_eq!(
            classify(&FailureSignal::default()),
            FailureClass::Unclassified
        );
    }

    // --- eval gating (P15.3) — a proposal cannot advance without evidence ---

    #[test]
    fn proposal_needs_demonstration_and_regression_guard() {
        let demo = EvalRef {
            name: bt("prompt_includes_verify_cmd"),
            kind: EvalKind::Demonstrates,
        };
        let guard = EvalRef {
            name: bt("existing_tasks_unaffected"),
            kind: EvalKind::GuardsRegression,
        };
        // No evidence at all → cannot advance.
        assert_eq!(
            ReadyProposal::prepare(proposal(ProposalTarget::Prompt), vec![]),
            Err(AdvanceError::NoDemonstration)
        );
        // Only a demonstration, no regression guard → cannot advance.
        assert_eq!(
            ReadyProposal::prepare(proposal(ProposalTarget::Prompt), vec![demo.clone()]),
            Err(AdvanceError::NoRegressionGuard)
        );
        // Only a regression guard, no demonstration → cannot advance.
        assert_eq!(
            ReadyProposal::prepare(proposal(ProposalTarget::Prompt), vec![guard.clone()]),
            Err(AdvanceError::NoDemonstration)
        );
        // Both → advances.
        let ready =
            ReadyProposal::prepare(proposal(ProposalTarget::Prompt), vec![demo, guard]).unwrap();
        assert_eq!(ready.proposal().target, ProposalTarget::Prompt);
        assert_eq!(ready.evidence().len(), 2);
    }

    // --- contract-file gate (P15.5) — invariant 18 ---

    #[test]
    fn contract_gate_flags_contract_files_even_when_bundled() {
        // A pure prompt/tool/config change auto-advances (to a draft PR).
        assert_eq!(
            contract_gate(&["prompts/system.txt", "crates/crustcore-net/src/lib.rs"]),
            GateDecision::AutoAdvanceAllowed
        );
        // Touching a policy/sandbox/secret contract file is flagged...
        assert!(matches!(
            contract_gate(&["docs/policy.md"]),
            GateDecision::RequiresMaintainerApproval { .. }
        ));
        assert!(matches!(
            contract_gate(&["crates/crustcore-secrets/src/lib.rs"]),
            GateDecision::RequiresMaintainerApproval { .. }
        ));
        // ...and is *still* flagged when bundled among innocuous edits (no slipping a
        // silent weakening through by mixing it in).
        let bundled = contract_gate(&[
            "prompts/system.txt",
            "crates/crustcore-policy/src/decision.rs",
            "README.md",
        ]);
        match bundled {
            GateDecision::RequiresMaintainerApproval { touched } => {
                assert_eq!(touched, vec!["crates/crustcore-policy/src/decision.rs"]);
            }
            GateDecision::AutoAdvanceAllowed => panic!("bundled contract change not flagged"),
        }
        // A dependency manifest anywhere is dependency-policy-sensitive.
        assert!(is_contract_file("crates/crustcore-mcp/Cargo.toml"));
        assert!(is_contract_file("./Cargo.lock"));
    }

    #[test]
    fn contract_gate_is_normalization_robust() {
        // The gate errs toward flagging: path variants an adversarial / non-canonical
        // source might use to dodge an exact match are all still flagged.
        for variant in [
            "docs//policy.md",    // repeated slash
            "docs///policy.md",   // many slashes
            ".//docs/policy.md",  // leading ./ + repeated slash
            "/docs/policy.md",    // leading slash (absolute-ish)
            "docs/policy.md/",    // trailing slash
            "docs\\policy.md",    // backslash separator
            "Docs/Policy.md",     // mixed case
            "DOCS/POLICY.MD",     // upper case
            "  docs/policy.md  ", // surrounding whitespace
            "crates//crustcore-secrets/src/lib.rs",
            "CRATES/CRUSTCORE-POLICY/SRC/DECISION.RS",
            "crates/crustcore-mcp/cargo.toml", // lowercased manifest basename
        ] {
            assert!(
                is_contract_file(variant),
                "normalization-robust gate failed to flag {variant:?}"
            );
            assert!(
                matches!(
                    contract_gate(&[variant]),
                    GateDecision::RequiresMaintainerApproval { .. }
                ),
                "contract_gate failed to flag {variant:?}"
            );
        }
        // A genuinely different file that merely shares a basename is NOT a false
        // positive (no suffix matching): vendored copies stay out of the gate.
        assert!(!is_contract_file("vendor/CLAUDE.md"));
        assert!(!is_contract_file("docs/policy.md.bak"));
    }

    // --- self-PR workflow (P15.4) — draft only, gate-blocked on contract files ---

    #[test]
    fn self_pr_is_draft_for_clean_change_and_blocked_on_contract_files() {
        let ready = ReadyProposal::prepare(
            proposal(ProposalTarget::ToolDefinition),
            vec![
                EvalRef {
                    name: bt("demo"),
                    kind: EvalKind::Demonstrates,
                },
                EvalRef {
                    name: bt("guard"),
                    kind: EvalKind::GuardsRegression,
                },
            ],
        )
        .unwrap();

        // A clean change → a draft PR (still needs Approved to merge — never auto).
        assert_eq!(
            plan_self_pr(&ready, &["tools/grep.json"]),
            SelfPrDecision::DraftPr {
                risk: ProposalRisk::Low
            }
        );
        // A change touching a contract file → blocked pending maintainer approval.
        assert!(matches!(
            plan_self_pr(&ready, &["tools/grep.json", "docs/sandbox.md"]),
            SelfPrDecision::BlockedPendingMaintainer { .. }
        ));
    }

    // --- the loop runner (B5-autoloop) ---

    struct FullEvals;
    impl EvalRunner for FullEvals {
        fn run_evals(&self, _p: &ImprovementProposal) -> Vec<EvalRef> {
            vec![
                EvalRef {
                    name: bt("demo"),
                    kind: EvalKind::Demonstrates,
                },
                EvalRef {
                    name: bt("guard"),
                    kind: EvalKind::GuardsRegression,
                },
            ]
        }
    }

    /// Evals that did not pass produce no refs.
    struct FailingEvals;
    impl EvalRunner for FailingEvals {
        fn run_evals(&self, _p: &ImprovementProposal) -> Vec<EvalRef> {
            Vec::new()
        }
    }

    /// Only a demonstration passed (no regression guard).
    struct OnlyDemo;
    impl EvalRunner for OnlyDemo {
        fn run_evals(&self, _p: &ImprovementProposal) -> Vec<EvalRef> {
            vec![EvalRef {
                name: bt("demo"),
                kind: EvalKind::Demonstrates,
            }]
        }
    }

    #[test]
    fn cycle_with_full_evidence_yields_a_draft_only() {
        let out = run_cycle(
            proposal(ProposalTarget::Prompt),
            &["src/prompts/system.txt"],
            &FullEvals,
        );
        // The strongest possible outcome is a DRAFT — there is no Merged/Applied variant,
        // so the loop structurally cannot self-merge (invariant 18).
        assert_eq!(
            out,
            CycleOutcome::DraftReady {
                risk: ProposalRisk::Low
            }
        );
    }

    #[test]
    fn evidence_free_proposal_cannot_advance() {
        // No evals passed → cannot advance (evidence, not a say-so, is the gate).
        assert_eq!(
            run_cycle(
                proposal(ProposalTarget::Config),
                &["src/prompts/x.txt"],
                &FailingEvals
            ),
            CycleOutcome::NotReady(AdvanceError::NoDemonstration)
        );
        // Only a demonstration, no regression guard → still cannot advance.
        assert_eq!(
            run_cycle(
                proposal(ProposalTarget::Config),
                &["src/prompts/x.txt"],
                &OnlyDemo
            ),
            CycleOutcome::NotReady(AdvanceError::NoRegressionGuard)
        );
    }

    #[test]
    fn contract_touching_cycle_is_blocked_for_the_maintainer() {
        // Even with full evidence, a change that touches a contract file is blocked —
        // silent weakening of a guardrail can never auto-advance (invariant 18).
        let out = run_cycle(
            proposal(ProposalTarget::Config),
            &["src/prompts/x.txt", "docs/policy.md"],
            &FullEvals,
        );
        match out {
            CycleOutcome::BlockedForMaintainer { touched } => {
                assert!(touched.iter().any(|t| t.contains("policy.md")));
            }
            other => panic!("expected BlockedForMaintainer, got {other:?}"),
        }
    }

    // --- live eval runner + draft-PR gate (B5-autoloop-live) ---
    #[cfg(feature = "live")]
    mod live {
        use super::*;
        use crate::exec::{ExecError, RawSubagentResult, SubagentExecutor, SubagentTask};
        use crate::supervisor::{AgentBudget, AgentId, AgentSpec, AgentUsage, Role};
        use crustcore_types::TaskId;

        /// A mock executor that returns a fixed `verified` for every eval — so the
        /// pass→EvalRef mapping is CI-tested with no sandbox.
        struct MockExec {
            verified: bool,
        }
        impl SubagentExecutor for MockExec {
            fn execute(
                &self,
                _spec: &AgentSpec,
                _task: &SubagentTask,
            ) -> Result<RawSubagentResult, ExecError> {
                Ok(RawSubagentResult {
                    verified: self.verified,
                    self_claimed_done: true, // shouted, but never authority
                    summary: bt("ran the eval"),
                    usage: AgentUsage::default(),
                })
            }
        }

        /// A mock executor that always errors — a non-running eval yields NO evidence.
        struct FailingExec;
        impl SubagentExecutor for FailingExec {
            fn execute(
                &self,
                _spec: &AgentSpec,
                _task: &SubagentTask,
            ) -> Result<RawSubagentResult, ExecError> {
                Err(ExecError::Backend("no sandbox backend".into()))
            }
        }

        fn agent() -> AgentSpec {
            AgentSpec {
                id: AgentId(1),
                role: Role::ExternalCommand,
                budget: AgentBudget {
                    max_wall_ms: 10_000,
                    max_output_bytes: 10_000,
                    max_tokens: 10_000,
                },
            }
        }

        fn eval(name: &str, kind: EvalKind) -> LiveEval {
            LiveEval {
                name: bt(name),
                kind,
                task: SubagentTask {
                    task_id: TaskId(1),
                    goal: bt("run eval"),
                    verify_program: "true".into(),
                    verify_args: vec![],
                },
                agent: agent(),
            }
        }

        #[test]
        fn passing_evals_yield_refs_and_a_cycle_advances_to_a_draft_only() {
            let evals = vec![
                eval("demo", EvalKind::Demonstrates),
                eval("guard", EvalKind::GuardsRegression),
            ];
            let exec = MockExec { verified: true };
            let runner = LiveEvalRunner::new(&exec, evals);

            // The runner emits a ref per passing eval...
            let refs = runner.run_evals(&proposal(ProposalTarget::Prompt));
            assert_eq!(refs.len(), 2);
            assert!(refs.iter().any(|r| r.kind == EvalKind::Demonstrates));
            assert!(refs.iter().any(|r| r.kind == EvalKind::GuardsRegression));

            // ...and driving the WHOLE cycle over the live runner still tops out at a draft
            // (no Merged/Applied variant exists — invariant 18 holds structurally).
            let out = run_cycle(
                proposal(ProposalTarget::Prompt),
                &["src/prompts/system.txt"],
                &runner,
            );
            assert_eq!(
                out,
                CycleOutcome::DraftReady {
                    risk: ProposalRisk::Low
                }
            );
        }

        #[test]
        fn failing_or_unrun_evals_yield_no_evidence_so_the_proposal_cannot_advance() {
            // A failing verifier → no refs → cannot advance (evidence is the gate).
            let exec = MockExec { verified: false };
            let runner = LiveEvalRunner::new(&exec, vec![eval("demo", EvalKind::Demonstrates)]);
            assert!(runner
                .run_evals(&proposal(ProposalTarget::Prompt))
                .is_empty());
            assert_eq!(
                run_cycle(
                    proposal(ProposalTarget::Prompt),
                    &["src/prompts/x.txt"],
                    &runner
                ),
                CycleOutcome::NotReady(AdvanceError::NoDemonstration)
            );

            // An eval that could not run (no sandbox) likewise contributes no evidence.
            let runner = LiveEvalRunner::new(
                &FailingExec,
                vec![eval("guard", EvalKind::GuardsRegression)],
            );
            assert!(runner
                .run_evals(&proposal(ProposalTarget::Prompt))
                .is_empty());
        }

        #[test]
        fn a_contract_touching_change_is_still_blocked_over_the_live_runner() {
            // Even with all evals passing live, a contract-file change is blocked for the
            // maintainer — the live runner adds NO power to slip a silent weakening through.
            let evals = vec![
                eval("demo", EvalKind::Demonstrates),
                eval("guard", EvalKind::GuardsRegression),
            ];
            let exec = MockExec { verified: true };
            let runner = LiveEvalRunner::new(&exec, evals);
            let out = run_cycle(
                proposal(ProposalTarget::Config),
                &["src/prompts/x.txt", "docs/sandbox.md"],
                &runner,
            );
            assert!(matches!(out, CycleOutcome::BlockedForMaintainer { .. }));
        }

        // The draft-PR opening seam is gate-preserving BY TYPE: `draft_pr_request` cannot be
        // called without a `VerifiedPatch` (only the verifier mints one — invariant 13) and a
        // valid `Approved<GitHubWriteCap>` (only a human AuthorizedUser mints one — inv 4/14),
        // and it always sets `draft: true`. That compile-time signature is the proof; the real
        // PR POST against api.github.com is the `#[ignore]`d TODO(B5-autoloop-live) socket.
        //
        // A daemon-side test cannot mint a `VerifiedPatch` (its constructor is crate-private to
        // crustcore-backend), so there is no CI test here — the type system enforces the gate,
        // and `crustcore_backend::integrate::open_pr` is itself fully tested in that crate.
        #[test]
        #[ignore = "live: requires a minted VerifiedPatch + Approved + a PR POST (TODO B5-autoloop-live)"]
        fn live_draft_pr_post_smoke() {
            // Intentionally empty: the live PR POST needs a real VerifiedPatch (verifier-minted)
            // + a human Approved + network. The gate is proven by `draft_pr_request`'s signature.
        }
    }
}
