// SPDX-License-Identifier: Apache-2.0
//! A representative capability-pack tool authored against the toolkit's safe path,
//! end to end (C2.7, the CI-runnable example).
//!
//! This is the *hand-written* shape that `#[crust_tool]` collapses into a derive: a
//! `CrustTool` whose `invoke` parses bounded untrusted args, does work, and hands the
//! raw result to the host's `emit` (redact → bound → mint). It mirrors what a real
//! `crustcore-mcp` server-side tool or `crustcore-daemon` helper tool does, so the
//! migration of a live pack tool (deferred to keep this PR's blast radius small —
//! see the CHANGELOG note) is a mechanical swap of this boilerplate for the macro.
//!
//! Run with: `cargo run -p crustcore-toolkit --example safe_tool`

use crustcore_policy::{PolicyDecision, PolicySnapshot, RiskProfile};
use crustcore_receipts::{MacKey, ReceiptChain};
use crustcore_secrets::Redactor;
use crustcore_toolkit::{
    CrustTool, HostTool, ParamSchema, ReceiptContext, Reversibility, SchemaType, ToolArgs,
    ToolError, ToolOutcome, ToolSchema,
};
use crustcore_types::{EventSeq, JobId, TaskId, ToolCallId};

/// A tool that reports a "deploy plan" for a service. It is a side-effecting tool,
/// so it keeps the fail-safe `Destructive` default — a host will gate it on approval.
struct DeployPlanTool<'h> {
    host: core::cell::RefCell<HostTool<'h>>,
}

impl<'h> DeployPlanTool<'h> {
    fn new(host: HostTool<'h>) -> Self {
        DeployPlanTool {
            host: core::cell::RefCell::new(host),
        }
    }
}

impl CrustTool for DeployPlanTool<'_> {
    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "deploy_plan".to_string(),
            params: vec![
                ParamSchema {
                    name: "service".to_string(),
                    ty: SchemaType::String,
                    required: true,
                },
                ParamSchema {
                    name: "replicas".to_string(),
                    ty: SchemaType::Integer,
                    required: true,
                },
            ],
            result: SchemaType::String,
        }
    }

    fn default_reversibility() -> Reversibility {
        // Side-effecting => keep the most restrictive default (fail-safe).
        Reversibility::Destructive
    }

    fn invoke(&self, args: &ToolArgs) -> Result<ToolOutcome, ToolError> {
        // Args are untrusted data (invariant 7): parse, never obey.
        let blob = args
            .as_str()
            .ok_or_else(|| ToolError::InvalidArgs("non-utf8".into()))?;
        let service = field(blob, "service")
            .ok_or_else(|| ToolError::InvalidArgs("missing `service`".into()))?;
        let replicas: u32 = field(blob, "replicas")
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| ToolError::InvalidArgs("bad `replicas`".into()))?;

        // The raw result may, accidentally, echo something sensitive; the host's
        // `emit` redacts → bounds → mints regardless.
        let raw = format!("plan: deploy {service} with {replicas} replicas");
        let mut host = self.host.borrow_mut();
        let (outcome, _receipt) = host.emit("deploy_plan", args.as_bytes(), &raw, &[])?;
        Ok(outcome)
    }
}

fn field<'a>(blob: &'a str, key: &str) -> Option<&'a str> {
    blob.lines()
        .find_map(|l| l.split_once('=').filter(|(k, _)| k.trim() == key))
        .map(|(_, v)| v.trim())
}

fn main() {
    // The trusted host owns the redactor (pre-loaded with secrets) and the MacKey.
    let mut redactor = Redactor::new();
    redactor.register("deploy-token", b"sk-DEPLOY-SECRET");
    let mut chain = ReceiptChain::new(MacKey::new([1u8; 32]));
    let ctx = ReceiptContext {
        task_id: TaskId(1),
        job_id: JobId(1),
        tool_call_id: ToolCallId(1),
        event_seq: EventSeq(1),
    };

    // 1. Policy decides whether this tool may run. The fail-safe default gates it.
    let policy = PolicySnapshot::new(RiskProfile::Supervised);
    match policy.classify(DeployPlanTool::default_reversibility()) {
        PolicyDecision::RequireApproval { reason } => {
            println!("policy: requires approval ({reason})");
        }
        other => println!("policy: {other:?}"),
    }

    // 2. Invoke (a host would do this only after the approval the policy demanded).
    let host = HostTool::new(&redactor, &mut chain, ctx);
    let tool = DeployPlanTool::new(host);
    let args = ToolArgs::new(b"service=api with sk-DEPLOY-SECRET\nreplicas=3".to_vec())
        .expect("bounded args");
    let outcome = tool.invoke(&args).expect("invoke");

    // The model-visible result is redactor-sealed and the secret never appears.
    let shown = outcome.visible.as_str();
    println!("model sees: {shown}");
    assert!(!shown.contains("DEPLOY-SECRET"));
    assert!(!redactor.would_leak(shown));
    println!("receipts minted: {}", chain.len());
}
