// SPDX-License-Identifier: Apache-2.0
//! The ergonomic safe path: a capability-pack tool authored with `#[crust_tool]`
//! (C2.7 demonstration). Compare with the hand-written
//! `crustcore-toolkit/examples/safe_tool.rs` — the macro collapses the same five-step
//! safety dance (schema · bound · redact · receipt · classify) into a derive while
//! making the safe path the easy path (Track C principle P2).
//!
//! Run with: `cargo run -p crustcore-tool-macro --example crust_tool_demo`

use crustcore_policy::{PolicyDecision, PolicySnapshot, RiskProfile};
use crustcore_receipts::{MacKey, ReceiptChain};
use crustcore_secrets::Redactor;
use crustcore_tool_macro::crust_tool;
use crustcore_toolkit::{CrustTool, HostTool, ReceiptContext, ToolArgs, ToolError};
use crustcore_types::{EventSeq, JobId, TaskId, ToolCallId};

/// A side-effecting tool with NO explicit reversibility => the fail-safe `Destructive`
/// default. The author writes only the body; schema/bound/redact/receipt/classify are
/// all generated.
#[crust_tool]
fn deploy_plan(_host: &mut HostTool, service: String, replicas: u32) -> Result<String, ToolError> {
    Ok(format!("plan: deploy {service} with {replicas} replicas"))
}

fn main() {
    let mut redactor = Redactor::new();
    redactor.register("deploy-token", b"sk-DEPLOY-SECRET");
    let mut chain = ReceiptChain::new(MacKey::new([1u8; 32]));
    let ctx = ReceiptContext {
        task_id: TaskId(1),
        job_id: JobId(1),
        tool_call_id: ToolCallId(1),
        event_seq: EventSeq(1),
    };

    // Fail-safe risk default => gated on approval under Supervised.
    let policy = PolicySnapshot::new(RiskProfile::Supervised);
    match DeployPlan::classify(&policy) {
        PolicyDecision::RequireApproval { reason } => {
            println!("policy: requires approval ({reason})");
        }
        other => println!("policy: {other:?}"),
    }

    let host = HostTool::new(&redactor, &mut chain, ctx);
    let tool = DeployPlan::new(host);
    let args =
        ToolArgs::new(b"service=api with sk-DEPLOY-SECRET\nreplicas=3".to_vec()).expect("args");
    let outcome = tool.invoke(&args).expect("invoke");

    let shown = outcome.visible.as_str();
    println!("model sees: {shown}");
    assert!(!shown.contains("DEPLOY-SECRET"));
    assert!(!redactor.would_leak(shown));
    println!("receipts minted: {}", chain.len());
}
