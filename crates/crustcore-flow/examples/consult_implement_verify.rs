// SPDX-License-Identifier: Apache-2.0
//! Example: the safe path is the easy path (C3.8).
//!
//! Builds a small `consult → implement → verify` flow with the typed [`FlowBuilder`]
//! and runs it over the CI [`FakeDrivers`]. It shows:
//! - the builder defaults a tool to the fail-closed [`ToolSpec`] (Destructive,
//!   execution-capable), so an irreversible tool needs an approval token;
//! - the flow **cannot** complete without a real `VerifiedPatch` — over the fakes the
//!   verify node returns `Failed`, so the flow ends as `Finished`, never `Completed`;
//! - the only way to reach `Completed` is the live `run_verify` driver (the
//!   `live-flow` `#[ignore]`d test), because `VerifiedPatch` is type-sealed.
//!
//! Run with: `cargo run -p crustcore-flow --example consult_implement_verify`

use crustcore_flow::{FakeDrivers, FlowBuilder, FlowEngine, FlowOutcome, FlowState, ToolSpec};
use crustcore_policy::caps::AuthorizedUser;
use crustcore_policy::{PolicySnapshot, RiskProfile};
use crustcore_secrets::Redactor;
use crustcore_types::{ApprovalId, Reversibility, Timestamp};

fn main() {
    // --- Build a consult → implement → verify → (loop back on fail) flow. ---
    let mut b = FlowBuilder::new();
    let consult = b.reserve();
    let implement = b.reserve();
    let verify = b.reserve();
    let done = b.reserve(); // failure sink (no completion)

    b.entry(consult)
        // 1. Consult a model for direction. Advisory only — recorded redacted.
        .model(
            consult,
            "How should I fix the failing test?",
            "plan",
            implement,
        )
        // 2. An implement tool. A reversible edit needs no approval; we classify it so.
        .tool(
            implement,
            ToolSpec {
                name: "edit".into(),
                reversibility: Reversibility::Reversible,
                execution_capable: false,
            },
            "apply the fix",
            "edit_result",
            verify,
        )
        // 3. Verify — the SOLE completion path. On fail, end without completing.
        .verify(verify, done)
        .end(done);

    let flow = b.build().expect("valid flow");

    // --- Run it over the deterministic CI fakes. ---
    let policy = PolicySnapshot::new(RiskProfile::Supervised);
    let redactor = Redactor::new();
    let engine = FlowEngine::new(&policy, &redactor, 1_000);
    let drivers = FakeDrivers::new();

    let report = engine
        .run(&flow, &drivers.as_bundle(), &big_budget(), FlowState::new())
        .expect("run");

    // Over the fakes, verify cannot mint a VerifiedPatch (the seal), so the flow ends
    // Finished — done, but NOT completed. No patch, no integration.
    assert!(matches!(report.outcome, FlowOutcome::Finished));
    assert!(!report.outcome.is_completed());
    println!("outcome: {:?}", report.outcome);
    println!("plan (redacted): {:?}", report.state.output("plan"));
    println!("edit (redacted): {:?}", report.state.output("edit_result"));

    // --- The approval gate, illustrated. ---
    // A fail-closed (Destructive) tool halts unless a valid approval token is present.
    let mut b2 = FlowBuilder::new();
    let danger = b2.reserve();
    let sink = b2.reserve();
    b2.entry(danger)
        .tool_fail_closed(danger, "rm", "-rf build/", "rm_out", sink)
        .end(sink);
    let flow2 = b2.build().unwrap();

    // Without an approval: halts.
    let no_approval = engine.run(
        &flow2,
        &drivers.as_bundle(),
        &big_budget(),
        FlowState::new(),
    );
    println!(
        "destructive tool without approval: {}",
        no_approval
            .as_ref()
            .err()
            .map_or("ok", |_| "halted (ApprovalRequired)")
    );
    assert!(no_approval.is_err());

    // With an externally-minted approval (only AuthorizedUser::approve can make one):
    let mut state = FlowState::new();
    let user = AuthorizedUser::bind(42);
    state.add_approval(user.approve((), ApprovalId(1), Timestamp::from_millis(10_000)));
    let approved = engine.run(&flow2, &drivers.as_bundle(), &big_budget(), state);
    println!(
        "destructive tool WITH approval: {}",
        if approved.is_ok() {
            "ran (approved)"
        } else {
            "halted"
        }
    );
    assert!(approved.is_ok());
}

fn big_budget() -> crustcore_flow::FlowBudget {
    crustcore_flow::FlowBudget::new(1_000, 1_000_000, 256, 64)
}
