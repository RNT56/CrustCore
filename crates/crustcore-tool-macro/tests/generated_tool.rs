// SPDX-License-Identifier: Apache-2.0
//! Runtime tests over tools authored with `#[crust_tool]`. These prove the GENERATED
//! wiring matches the hand-written safe path: derived schema, bounded I/O, redaction
//! into `ModelVisibleText`, host-minted receipt over the final bytes, and the
//! fail-safe `Destructive` default. The macro also emits its own `#[cfg(test)]`
//! fixtures per tool (C2.6); those run too when this crate is tested.

use crustcore_policy::{PolicyDecision, PolicySnapshot, RiskProfile};
use crustcore_receipts::{MacKey, ReceiptChain};
use crustcore_secrets::Redactor;
use crustcore_tool_macro::crust_tool;
use crustcore_toolkit::{CrustTool, HostTool, ReceiptContext, SchemaType, ToolArgs, ToolError};
use crustcore_types::{EventSeq, JobId, TaskId, ToolCallId};

const SENTINEL: &str = "sk-SENTINEL-do-not-leak";

// --- Tool 1: default (fail-safe Destructive) reversibility, mixed param types ---

/// Joins a label, count, and flag into a result line — and deliberately echoes any
/// secret in `label` so the redactor's role is observable.
#[crust_tool]
fn summarize(
    _host: &mut HostTool,
    label: String,
    count: u32,
    verbose: bool,
) -> Result<String, ToolError> {
    let detail = if verbose { " (verbose)" } else { "" };
    Ok(format!("{label} x{count}{detail}"))
}

// --- Tool 2: explicitly downgraded to Reversible, with Option/Vec params ---

/// A read-only-ish tool with optional + array params, to exercise the schema mapper
/// and the downgrade path.
#[crust_tool(reversibility = "Reversible")]
fn lookup(
    _host: &mut HostTool,
    key: String,
    fallbacks: Vec<String>,
    limit: Option<u32>,
) -> Result<String, ToolError> {
    let n = limit.unwrap_or(0);
    Ok(format!("key={key} fallbacks={} limit={n}", fallbacks.len()))
}

fn redactor_with_secret() -> Redactor {
    let mut r = Redactor::new();
    r.register("sentinel", SENTINEL.as_bytes());
    r
}

fn chain() -> ReceiptChain {
    ReceiptChain::new(MacKey::new([5u8; 32]))
}

fn ctx() -> ReceiptContext {
    ReceiptContext {
        task_id: TaskId(1),
        job_id: JobId(1),
        tool_call_id: ToolCallId(1),
        event_seq: EventSeq(1),
    }
}

#[test]
fn generated_schema_is_derived_from_the_signature() {
    let r = Redactor::new();
    let mut c = chain();
    let tool = Summarize::new(HostTool::new(&r, &mut c, ctx()));
    let s = tool.schema();
    assert_eq!(s.name, "summarize");
    assert!(s.is_well_formed() && s.is_concrete());
    assert_eq!(s.params.len(), 3);
    assert_eq!(s.params[0].name, "label");
    assert!(matches!(s.params[0].ty, SchemaType::String));
    assert!(s.params[0].required);
    assert_eq!(s.params[1].name, "count");
    assert!(matches!(s.params[1].ty, SchemaType::Integer));
    assert_eq!(s.params[2].name, "verbose");
    assert!(matches!(s.params[2].ty, SchemaType::Boolean));
    assert!(matches!(s.result, SchemaType::String));
}

#[test]
fn generated_schema_maps_option_and_vec() {
    let r = Redactor::new();
    let mut c = chain();
    let tool = Lookup::new(HostTool::new(&r, &mut c, ctx()));
    let s = tool.schema();
    assert_eq!(s.params.len(), 3);
    // Vec<String> -> Array(String), still required.
    assert!(matches!(s.params[1].ty, SchemaType::Array(_)));
    assert!(s.params[1].required);
    // Option<u32> -> Optional(Integer), NOT required.
    assert!(matches!(s.params[2].ty, SchemaType::Optional(_)));
    assert!(!s.params[2].required, "Option param must not be required");
    assert!(s.is_concrete());
}

#[test]
fn generated_invoke_parses_decodes_and_runs() {
    let r = Redactor::new();
    let mut c = chain();
    let tool = Summarize::new(HostTool::new(&r, &mut c, ctx()));
    let args = ToolArgs::new(b"label=widgets\ncount=3\nverbose=true".to_vec()).unwrap();
    let outcome = tool.invoke(&args).expect("invoke");
    assert_eq!(outcome.visible.as_str(), "widgets x3 (verbose)");
}

#[test]
fn generated_tool_redacts_secret_before_visibility() {
    let r = redactor_with_secret();
    let mut c = chain();
    let tool = Summarize::new(HostTool::new(&r, &mut c, ctx()));
    let args =
        ToolArgs::new(format!("label={SENTINEL}\ncount=1\nverbose=false").into_bytes()).unwrap();
    let outcome = tool.invoke(&args).expect("invoke");
    let shown = outcome.visible.as_str();
    assert!(!shown.contains("SENTINEL"), "secret leaked: {shown}");
    assert!(shown.contains("[REDACTED:sentinel]"));
    assert!(!r.would_leak(shown));
    // The receipt chain advanced exactly once over the redacted result.
    assert_eq!(c.len(), 1);
}

#[test]
fn generated_invoke_surfaces_typed_error_on_bad_args() {
    let r = Redactor::new();
    let mut c = chain();
    let tool = Summarize::new(HostTool::new(&r, &mut c, ctx()));
    // `count` is not an integer.
    let args = ToolArgs::new(b"label=x\ncount=notanumber\nverbose=true".to_vec()).unwrap();
    let err = tool.invoke(&args).unwrap_err();
    assert!(matches!(err, ToolError::InvalidArgs(_)));
    // No receipt minted on a parse failure.
    assert!(c.is_empty());
}

#[test]
fn generated_optional_param_defaults_to_none() {
    let r = Redactor::new();
    let mut c = chain();
    let tool = Lookup::new(HostTool::new(&r, &mut c, ctx()));
    // `limit` absent => None => 0; `fallbacks` two entries.
    let args = ToolArgs::new(b"key=k\nfallbacks=a,b".to_vec()).unwrap();
    let outcome = tool.invoke(&args).expect("invoke");
    assert_eq!(outcome.visible.as_str(), "key=k fallbacks=2 limit=0");
}

#[test]
fn default_reversibility_is_fail_safe_destructive() {
    assert_eq!(
        <Summarize as CrustTool>::default_reversibility(),
        crustcore_toolkit::Reversibility::Destructive
    );
    let supervised = PolicySnapshot::new(RiskProfile::Supervised);
    assert!(matches!(
        Summarize::classify(&supervised),
        PolicyDecision::RequireApproval { .. }
    ));
    let readonly = PolicySnapshot::new(RiskProfile::ReadOnly);
    assert!(matches!(
        Summarize::classify(&readonly),
        PolicyDecision::Deny { .. }
    ));
}

#[test]
fn explicit_downgrade_is_honored_but_still_denied_under_readonly() {
    assert_eq!(
        <Lookup as CrustTool>::default_reversibility(),
        crustcore_toolkit::Reversibility::Reversible
    );
    let supervised = PolicySnapshot::new(RiskProfile::Supervised);
    // A Reversible tool is allowed under Supervised...
    assert_eq!(Lookup::classify(&supervised), PolicyDecision::Allow);
    // ...but ReadOnly still denies ALL side effects.
    let readonly = PolicySnapshot::new(RiskProfile::ReadOnly);
    assert!(matches!(
        Lookup::classify(&readonly),
        PolicyDecision::Deny { .. }
    ));
}
