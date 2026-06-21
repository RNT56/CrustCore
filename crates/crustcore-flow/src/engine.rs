// SPDX-License-Identifier: Apache-2.0
//! The deterministic scheduler (C3.3).
//!
//! [`FlowEngine::run`] walks the graph from its entry, threading typed
//! [`FlowState`] and [`FlowUsage`]. It owns **no I/O**: every effectful node goes
//! through the injected [`FlowDrivers`]. Evaluation is deterministic — the same node
//! results produce the same path, every time.
//!
//! What the engine enforces, in order, per node:
//! - **Budget** (invariant 11): every node charges a step; model nodes charge cost;
//!   `Parallel` charges fan-out — a breach halts the run before the over-limit work.
//! - **Policy** (invariant 8): a `Tool` node is classified through
//!   `PolicySnapshot::classify(spec.reversibility)`; `Deny` → halt,
//!   `RequireApproval`/irreversible → the approval gate.
//! - **Approval** (invariant 14): an irreversible tool node halts unless a valid
//!   `Approved<T>` is present in `FlowState` (which no node can forge).
//! - **Untrusted data** (invariant 7): every effectful node's output is redacted +
//!   bounded ([`crate::predicate::declassify`]) before it enters typed state.
//! - **Caps** (invariant 11): `Parallel` honors `max_concurrency`; `LoopUntil` honors
//!   `max_iterations`.
//! - **Completion** (invariant 13): only a `Verify` node's `Verified` outcome ends the
//!   run as [`FlowOutcome::Completed`] with a real `VerifiedPatch`.
//!
//! The engine has **no** integration path: there is no call to
//! `crustcore_daemon::supervisor::decide_integration` and no node that integrates
//! (invariant 6). The flow is a plan; the supervisor stays the integration authority.

use crustcore_backend::verify::VerifyOutcome;
use crustcore_policy::{PolicyDecision, PolicySnapshot};
use crustcore_secrets::Redactor;

use crate::budget::{FlowBudget, FlowUsage};
use crate::drivers::{FlowDrivers, ToolInvocation};
use crate::graph::{Flow, FlowError, FlowState, Node, NodeId, ToolSpec};
use crate::outcome::FlowOutcome;
use crate::predicate::declassify;

/// What a finished run reports back: the outcome plus the final state and usage (for
/// audit/diagnostics). The [`FlowState`] is returned by value so the caller can
/// inspect recorded (redacted) outputs and flags.
pub struct RunReport {
    /// How the flow ended.
    pub outcome: FlowOutcome,
    /// The final typed state (redacted outputs, flags, counters).
    pub state: FlowState,
    /// What the run charged against the budget.
    pub usage: FlowUsage,
}

impl core::fmt::Debug for RunReport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // FlowState is intentionally not Debug (it holds approval tokens); summarize it
        // so a `.unwrap_err()` on a Result<RunReport, _> can render without exposing it.
        f.debug_struct("RunReport")
            .field("outcome", &self.outcome)
            .field("usage", &self.usage)
            .finish_non_exhaustive()
    }
}

/// The pure deterministic scheduler. Holds the policy snapshot and redactor it needs
/// to gate tools and declassify untrusted output; performs no I/O itself.
pub struct FlowEngine<'e> {
    policy: &'e PolicySnapshot,
    redactor: &'e Redactor,
    /// Adapter-supplied wall clock for approval validity, in ms. The engine reads no
    /// real clock (determinism); the caller fixes it.
    now_millis: u64,
}

impl<'e> FlowEngine<'e> {
    /// Builds an engine over a policy snapshot and a redactor, with a fixed `now` for
    /// approval validity. No real clock is read (determinism).
    #[must_use]
    pub fn new(policy: &'e PolicySnapshot, redactor: &'e Redactor, now_millis: u64) -> Self {
        FlowEngine {
            policy,
            redactor,
            now_millis,
        }
    }

    /// Runs `flow` over `drivers`, starting from `state`. Deterministic: the same
    /// driver results and the same starting state always produce the same path and
    /// outcome.
    ///
    /// # Errors
    /// [`FlowError`] on a structural problem, a policy denial, a missing approval, a
    /// driver failure, or a budget/step-cap breach.
    pub fn run(
        &self,
        flow: &Flow,
        drivers: &FlowDrivers<'_>,
        budget: &FlowBudget,
        mut state: FlowState,
    ) -> Result<RunReport, FlowError> {
        flow.validate()?;
        let mut usage = FlowUsage::default();
        let outcome = self.run_from(flow.entry(), flow, drivers, budget, &mut state, &mut usage)?;
        Ok(RunReport {
            outcome,
            state,
            usage,
        })
    }

    /// Walks the graph iteratively from `start`. Iterative (not recursive) for the
    /// linear chain so depth is bounded by the step cap, not the call stack;
    /// `Parallel` recurses per child (bounded by fan-out + step caps).
    fn run_from(
        &self,
        start: NodeId,
        flow: &Flow,
        drivers: &FlowDrivers<'_>,
        budget: &FlowBudget,
        state: &mut FlowState,
        usage: &mut FlowUsage,
    ) -> Result<FlowOutcome, FlowError> {
        let mut current = start;
        loop {
            // Charge a step first: a breach halts before the work (invariant 11). The
            // step cap is also the structural backstop against a cyclic non-loop graph.
            usage
                .charge_step(budget)
                .map_err(|_| FlowError::StepCapExceeded)?;

            let node = flow.node(current).ok_or(FlowError::UnknownNode(current))?;
            match node {
                Node::Model {
                    prompt,
                    out_key,
                    next,
                } => {
                    let (raw, cost) = drivers
                        .model
                        .run_model(prompt)
                        .map_err(|e| FlowError::Driver(e.0))?;
                    usage
                        .charge_model(cost, budget)
                        .map_err(|b| FlowError::BudgetExceeded(b.axis().to_string()))?;
                    // Untrusted model output → redact + bound before it enters state.
                    state.set_output(out_key.clone(), declassify(&raw, self.redactor));
                    current = *next;
                }
                Node::Tool {
                    spec,
                    args,
                    out_key,
                    next,
                } => {
                    self.gate_tool(current, spec, state)?;
                    let inv = ToolInvocation { spec, args };
                    let raw = drivers
                        .tool
                        .run_tool(&inv)
                        .map_err(|e| FlowError::Driver(e.0))?;
                    state.set_output(out_key.clone(), declassify(&raw, self.redactor));
                    current = *next;
                }
                Node::Verify { on_fail } => {
                    // The sole completion path (invariant 13). Only a Verified outcome
                    // completes; everything else continues to on_fail.
                    match drivers.verify.verify() {
                        VerifyOutcome::Verified(patch) => {
                            // The patch came from the public run_verify (the only minter).
                            // Surface it as the single verifier-owned terminal.
                            return Ok(FlowOutcome::Completed(patch));
                        }
                        VerifyOutcome::Failed { .. } | VerifyOutcome::Refused(_) => {
                            // No fabrication: a non-pass never mints anything.
                            current = *on_fail;
                        }
                    }
                }
                Node::Review { out_key, next } => {
                    let raw = drivers
                        .review
                        .review()
                        .map_err(|e| FlowError::Driver(e.0))?;
                    // Advisory only; redacted + bounded, recorded as engine-internal data.
                    state.set_output(out_key.clone(), declassify(&raw, self.redactor));
                    current = *next;
                }
                Node::Parallel {
                    children,
                    max_concurrency,
                    join,
                } => {
                    self.run_parallel(
                        children,
                        *max_concurrency,
                        flow,
                        drivers,
                        budget,
                        state,
                        usage,
                    )?;
                    current = *join;
                }
                Node::LoopUntil {
                    body,
                    until,
                    max_iterations,
                    next,
                } => {
                    let mut iter = 0u32;
                    // Bounded iteration (invariant 11): exit when the typed-state
                    // predicate holds OR the cap is reached — never loops forever.
                    while iter < *max_iterations && !until.eval(state) {
                        if let Some(done) =
                            self.run_subgraph(*body, flow, drivers, budget, state, usage)?
                        {
                            // A verify inside the loop body completed the flow.
                            return Ok(done);
                        }
                        iter += 1;
                    }
                    state.set_counter("__loop_iterations", i64::from(iter));
                    current = *next;
                }
                Node::Route {
                    predicate,
                    if_true,
                    if_false,
                } => {
                    // Branch over typed state ONLY (invariant 7).
                    current = if predicate.eval(state) {
                        *if_true
                    } else {
                        *if_false
                    };
                }
                Node::Join { next } => {
                    current = *next;
                }
                Node::End => return Ok(FlowOutcome::Finished),
            }
        }
    }

    /// Runs one bounded fan-out wave set. Children run in deterministic order, in waves
    /// of at most `max_concurrency` (the deterministic engine cannot truly parallelize,
    /// but it enforces the cap as a wave width and charges total fan-out). If any child
    /// path completes the flow via verify, that completion is returned immediately.
    #[allow(clippy::too_many_arguments)]
    fn run_parallel(
        &self,
        children: &[NodeId],
        max_concurrency: usize,
        flow: &Flow,
        drivers: &FlowDrivers<'_>,
        budget: &FlowBudget,
        state: &mut FlowState,
        usage: &mut FlowUsage,
    ) -> Result<(), FlowError> {
        // Cap fan-out: charge the number of children against the total-fan-out budget
        // (invariant 11). A breach halts before scheduling any of them.
        let n = u32::try_from(children.len()).unwrap_or(u32::MAX);
        usage
            .charge_fanout(n, budget)
            .map_err(|b| FlowError::BudgetExceeded(b.axis().to_string()))?;

        // `max_concurrency` is the wave width: a hard cap on how many children are
        // "in flight" at once. The deterministic engine cannot truly parallelize, so it
        // runs each child to its terminal in deterministic order, in waves of this
        // width — enforcing the cap and keeping the join merge deterministic.
        //
        // A parallel branch is for advisory/exploration fan-out; **completion is not a
        // valid outcome inside a child** (the sole completion site is the top-level
        // verify path, invariant 13). A child that completes the flow via verify is a
        // mis-built plan, rejected rather than allowed to complete from inside a join.
        let width = max_concurrency.max(1);
        for wave in children.chunks(width) {
            for &child in wave {
                if self
                    .run_subgraph(child, flow, drivers, budget, state, usage)?
                    .is_some()
                {
                    return Err(FlowError::Driver(
                        "a verify completion inside a parallel child is not a valid plan; \
                         completion is reserved for the top-level verify path"
                            .to_string(),
                    ));
                }
            }
        }
        Ok(())
    }

    /// Runs a bounded subgraph rooted at `start` to a terminal (`End`/`Join`-less
    /// dead end) or to a flow completion. Returns `Some(outcome)` only if the subgraph
    /// completed the flow via a verify node; otherwise `None` once it reaches a
    /// terminal. Used by loop bodies and parallel children.
    fn run_subgraph(
        &self,
        start: NodeId,
        flow: &Flow,
        drivers: &FlowDrivers<'_>,
        budget: &FlowBudget,
        state: &mut FlowState,
        usage: &mut FlowUsage,
    ) -> Result<Option<FlowOutcome>, FlowError> {
        match self.run_from(start, flow, drivers, budget, state, usage)? {
            FlowOutcome::Completed(p) => Ok(Some(FlowOutcome::Completed(p))),
            FlowOutcome::Finished => Ok(None),
        }
    }

    /// Gates a tool node through policy + the approval token (invariants 8, 14). A
    /// `Deny` halts; an irreversible/`RequireApproval` tool halts unless a valid
    /// approval is present in state. The classification defaults to the spec's
    /// reversibility, which the builder sets to `Destructive` when unspecified (fail
    /// closed).
    fn gate_tool(&self, node: NodeId, spec: &ToolSpec, state: &FlowState) -> Result<(), FlowError> {
        match self.policy.classify(spec.reversibility) {
            PolicyDecision::Allow => {
                // Defense in depth: even if a profile would Allow, an irreversible spec
                // still requires an approval token (invariant 14). With the stock
                // profiles classify() already routes irreversible → RequireApproval, so
                // this is belt-and-braces, not the primary gate.
                if spec.requires_approval() && !state.has_valid_approval(self.now_millis) {
                    return Err(FlowError::ApprovalRequired(node));
                }
                Ok(())
            }
            PolicyDecision::RequireApproval { .. } => {
                if state.has_valid_approval(self.now_millis) {
                    Ok(())
                } else {
                    Err(FlowError::ApprovalRequired(node))
                }
            }
            PolicyDecision::Deny { reason } => Err(FlowError::PolicyDenied { node, reason }),
        }
    }
}
