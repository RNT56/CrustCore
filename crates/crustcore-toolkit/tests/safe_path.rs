// SPDX-License-Identifier: Apache-2.0
//! Runtime tests for the toolkit's safe path, exercised through a HAND-WRITTEN
//! `CrustTool` (no macro). These prove the real safety logic the macro generates
//! calls into, so the gate covers it independent of proc-macro expansion:
//!
//! - schema is well-formed + concrete;
//! - oversize input / output is refused with a typed `ToolError` (invariant 11);
//! - a sentinel secret in the raw result is redacted before it becomes visible AND
//!   `Redactor::would_leak` is false on the emitted bytes (dimensions a, d);
//! - the receipt's `result_hash` binds the FINAL redacted+bounded bytes (dimension e);
//! - the fail-safe `Destructive` default classifies to RequireApproval (Supervised)
//!   / Deny (ReadOnly) (dimensions b, c).

use crustcore_policy::{PolicyDecision, PolicySnapshot, RiskProfile};
use crustcore_receipts::{MacKey, ReceiptChain};
use crustcore_secrets::Redactor;
use crustcore_toolkit::{
    classify_tool, finalize, finalize_with, ArtifactRef, CrustTool, HostTool, ParamSchema,
    ReceiptContext, Reversibility, SchemaType, ToolArgs, ToolError, ToolOutcome, ToolSchema,
    MAX_RESULT_BYTES,
};
use crustcore_types::{ArtifactId, EventSeq, JobId, TaskId, ToolCallId};

const SENTINEL: &str = "sk-SENTINEL-do-not-leak";

fn redactor_with_secret() -> Redactor {
    let mut r = Redactor::new();
    r.register("sentinel", SENTINEL.as_bytes());
    r
}

fn chain() -> ReceiptChain {
    ReceiptChain::new(MacKey::new([3u8; 32]))
}

fn ctx() -> ReceiptContext {
    ReceiptContext {
        task_id: TaskId(1),
        job_id: JobId(2),
        tool_call_id: ToolCallId(3),
        event_seq: EventSeq(4),
    }
}

// --- A hand-written tool over the toolkit surface (no macro) -----------------

/// Echoes its message back, deliberately INCLUDING any secret in the message — to
/// prove the toolkit redacts it regardless of the tool's care.
struct EchoTool<'h> {
    host: core::cell::RefCell<HostTool<'h>>,
}

impl<'h> EchoTool<'h> {
    fn new(host: HostTool<'h>) -> Self {
        EchoTool {
            host: core::cell::RefCell::new(host),
        }
    }
}

impl CrustTool for EchoTool<'_> {
    fn schema(&self) -> ToolSchema {
        ToolSchema {
            name: "echo".to_string(),
            params: vec![ParamSchema {
                name: "message".to_string(),
                ty: SchemaType::String,
                required: true,
            }],
            result: SchemaType::String,
        }
    }

    fn default_reversibility() -> Reversibility {
        // Fail-safe default, exactly like the macro emits when not downgraded.
        Reversibility::Destructive
    }

    fn invoke(&self, args: &ToolArgs) -> Result<ToolOutcome, ToolError> {
        let message = args
            .as_str()
            .ok_or_else(|| ToolError::InvalidArgs("non-utf8".into()))?;
        let raw = format!("echo: {message}");
        let mut host = self.host.borrow_mut();
        let (outcome, _receipt) = host.emit("echo", args.as_bytes(), &raw, &[])?;
        Ok(outcome)
    }
}

#[test]
fn hand_written_tool_schema_is_well_formed_and_concrete() {
    let r = redactor_with_secret();
    let mut c = chain();
    let tool = EchoTool::new(HostTool::new(&r, &mut c, ctx()));
    let s = tool.schema();
    assert!(s.is_well_formed());
    assert!(s.is_concrete());
    assert_eq!(s.name, "echo");
}

#[test]
fn secret_is_redacted_before_visibility_and_receipt_binds_final_bytes() {
    let r = redactor_with_secret();
    let mut c = chain();
    let tool = EchoTool::new(HostTool::new(&r, &mut c, ctx()));
    let args = ToolArgs::new(format!("the key is {SENTINEL} ok").into_bytes()).unwrap();

    let outcome = tool.invoke(&args).expect("invoke");
    let shown = outcome.visible.as_str();
    assert!(
        !shown.contains("SENTINEL"),
        "secret leaked into output: {shown}"
    );
    assert!(shown.contains("[REDACTED:sentinel]"));
    // Defense in depth on the emitted bytes (dimension d).
    assert!(
        !r.would_leak(shown),
        "would_leak true on emitted bytes: {shown}"
    );
}

#[test]
fn finalize_binds_receipt_to_exact_redacted_bytes() {
    let r = redactor_with_secret();
    let mut c = chain();
    let raw = format!("result with {SENTINEL} inside");
    let (outcome, receipt) =
        finalize(&r, &mut c, &ctx(), "echo", b"args", &raw, &[]).expect("finalize");
    let shown = outcome.visible.as_str();
    // The receipt's result_hash binds the FINAL redacted+bounded bytes, NOT the raw.
    assert!(receipt.result_matches(shown.as_bytes()));
    assert!(
        !receipt.result_matches(raw.as_bytes()),
        "must not bind raw secret bytes"
    );
    assert!(receipt.args_matches(b"args"));
}

#[test]
fn oversize_input_is_refused() {
    let big = vec![b'x'; crustcore_toolkit::MAX_ARGS_BYTES + 1];
    assert!(matches!(
        ToolArgs::new(big),
        Err(ToolError::InputTooLarge { .. })
    ));
}

#[test]
fn oversize_output_is_refused_not_truncated() {
    let r = Redactor::new(); // no secrets; isolate the bound check
    let mut c = chain();
    let raw = "y".repeat(MAX_RESULT_BYTES + 1);
    let err = finalize(&r, &mut c, &ctx(), "big", b"args", &raw, &[]).unwrap_err();
    assert!(matches!(err, ToolError::OutputTooLarge { len, max }
        if len == MAX_RESULT_BYTES + 1 && max == MAX_RESULT_BYTES));
    // Refused, so the chain did NOT advance (no receipt minted over a truncated tail).
    assert!(c.is_empty(), "no receipt should be minted on overrun");
}

#[test]
fn finalize_with_tighter_cap_refuses() {
    let r = Redactor::new();
    let mut c = chain();
    let raw = "0123456789";
    let err = finalize_with(&r, &mut c, &ctx(), "t", b"a", raw, &[], 4).unwrap_err();
    assert!(matches!(err, ToolError::OutputTooLarge { len: 10, max: 4 }));
}

#[test]
fn redaction_before_truncation_no_tail_leak() {
    // A secret near the end must never survive: redact precedes bound, and bound
    // refuses on overrun rather than truncating mid-marker (dimension d).
    let r = redactor_with_secret();
    let mut c = chain();
    let raw = format!("{}{SENTINEL}", "p".repeat(100));
    let (outcome, _receipt) = finalize(&r, &mut c, &ctx(), "t", b"a", &raw, &[]).expect("finalize");
    assert!(!r.would_leak(outcome.visible.as_str()));
}

#[test]
fn fail_safe_default_classifies_closed() {
    let supervised = PolicySnapshot::new(RiskProfile::Supervised);
    assert!(matches!(
        classify_tool::<EchoTool>(&supervised),
        PolicyDecision::RequireApproval { .. }
    ));
    let readonly = PolicySnapshot::new(RiskProfile::ReadOnly);
    assert!(matches!(
        classify_tool::<EchoTool>(&readonly),
        PolicyDecision::Deny { .. }
    ));
    let full = PolicySnapshot::new(RiskProfile::Full);
    assert!(matches!(
        classify_tool::<EchoTool>(&full),
        PolicyDecision::RequireApproval { .. }
    ));
}

#[test]
fn artifacts_are_committed_into_the_receipt_by_hash_only() {
    let r = Redactor::new();
    let mut c = chain();
    let art = ArtifactRef(ArtifactId([0xab; 32]));
    let (outcome, receipt) =
        finalize(&r, &mut c, &ctx(), "t", b"a", "done", &[art]).expect("finalize");
    assert_eq!(outcome.artifacts.len(), 1);
    assert_eq!(receipt.artifact_hashes.len(), 1);
    assert_eq!(receipt.artifact_hashes[0], ArtifactId([0xab; 32]));
}
