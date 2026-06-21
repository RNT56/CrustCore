// SPDX-License-Identifier: Apache-2.0
//! Generating per-tool `#[test]` fixtures (C2.6).
//!
//! For each annotated tool the macro emits a `#[cfg(test)]` module asserting the
//! safety properties hold for THIS tool, mechanically:
//! - the derived schema is well-formed and concrete (no `Any`; dimension f);
//! - the fail-safe classification under `Supervised` is `RequireApproval` and under
//!   `ReadOnly` is `Deny` whenever the tool defaults to `Destructive` (dimension b);
//! - an oversize input is refused with `InputTooLarge` (invariant 11);
//! - a sentinel secret placed in the redactor never appears in a tool's visible
//!   output, and `Redactor::would_leak` is false on the emitted bytes (dimensions a,
//!   d) — exercised through a generic round-trip over a hand-shaped result.
//!
//! These are scaffolding the host crate compiles in its own test build; they prove
//! the generated wiring, not the author's logic.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use crate::parse::{ToolDef, DEFAULT_REVERSIBILITY};

/// Generates the `#[cfg(test)]` fixture module for a tool.
pub fn generate_tests(def: &ToolDef) -> TokenStream {
    let struct_ident = &def.struct_ident;
    let tool_name = &def.tool_name;
    let mod_ident = format_ident!("__crust_tool_tests_{}", def.func.sig.ident);
    let is_failsafe_default = def.reversibility == DEFAULT_REVERSIBILITY;

    // The classification asserts only apply when the tool kept the fail-safe
    // `Destructive` default; an explicitly-downgraded tool asserts the weaker
    // "never Allow under ReadOnly" property instead.
    let classify_asserts = if is_failsafe_default {
        quote! {
            // Fail-safe default: Destructive => RequireApproval (Supervised), Deny (ReadOnly).
            let supervised = ::crustcore_policy::PolicySnapshot::new(
                ::crustcore_policy::RiskProfile::Supervised);
            assert!(matches!(
                #struct_ident::classify(&supervised),
                ::crustcore_policy::PolicyDecision::RequireApproval { .. }
            ), "fail-safe default must gate on approval under Supervised");
            let readonly = ::crustcore_policy::PolicySnapshot::new(
                ::crustcore_policy::RiskProfile::ReadOnly);
            assert!(matches!(
                #struct_ident::classify(&readonly),
                ::crustcore_policy::PolicyDecision::Deny { .. }
            ), "fail-safe default must be denied under ReadOnly");
        }
    } else {
        quote! {
            // Explicitly-downgraded tool: still never `Allow` under ReadOnly.
            let readonly = ::crustcore_policy::PolicySnapshot::new(
                ::crustcore_policy::RiskProfile::ReadOnly);
            assert!(!matches!(
                #struct_ident::classify(&readonly),
                ::crustcore_policy::PolicyDecision::Allow
            ), "no tool may be allowed under ReadOnly");
        }
    };

    quote! {
        #[cfg(test)]
        #[allow(non_snake_case)]
        mod #mod_ident {
            #[allow(unused_imports)]
            use super::*;

            // Build a host handle with a redactor carrying a sentinel secret + a
            // CrustCore-keyed receipt chain, the way the trusted host would.
            fn __crust_host_and_redactor() -> (
                ::crustcore_secrets::Redactor,
                ::crustcore_receipts::ReceiptChain,
            ) {
                let mut store = ::crustcore_secrets::InMemoryStore::new();
                store.insert(
                    ::crustcore_types::SecretId(1),
                    "sentinel",
                    b"sk-SENTINEL-do-not-leak".to_vec(),
                );
                let broker = ::crustcore_secrets::SecretBroker::new(store);
                // The broker pre-registers stored secrets with its redactor; clone the
                // registration into a standalone redactor for the host handle.
                let mut redactor = ::crustcore_secrets::Redactor::new();
                redactor.register("sentinel", b"sk-SENTINEL-do-not-leak");
                let _ = broker; // broker held only to mirror the host setup
                let chain = ::crustcore_receipts::ReceiptChain::new(
                    ::crustcore_receipts::MacKey::new([9u8; 32]));
                (redactor, chain)
            }

            fn __crust_ctx() -> ::crustcore_toolkit::ReceiptContext {
                ::crustcore_toolkit::ReceiptContext {
                    task_id: ::crustcore_types::TaskId(1),
                    job_id: ::crustcore_types::JobId(1),
                    tool_call_id: ::crustcore_types::ToolCallId(1),
                    event_seq: ::crustcore_types::EventSeq(1),
                }
            }

            #[test]
            fn schema_is_well_formed_and_concrete() {
                let (redactor, mut chain) = __crust_host_and_redactor();
                let host = ::crustcore_toolkit::HostTool::new(&redactor, &mut chain, __crust_ctx());
                let tool = #struct_ident::new(host);
                let schema = ::crustcore_toolkit::CrustTool::schema(&tool);
                assert_eq!(schema.name, #tool_name);
                assert!(schema.is_well_formed(), "schema must be well-formed");
                assert!(schema.is_concrete(), "macro schema must never contain `Any`");
            }

            #[test]
            fn classification_fails_closed() {
                #classify_asserts
            }

            #[test]
            fn oversize_input_is_refused() {
                let big = ::std::vec![b'x'; ::crustcore_toolkit::MAX_ARGS_BYTES + 1];
                assert!(matches!(
                    ::crustcore_toolkit::ToolArgs::new(big),
                    ::std::result::Result::Err(::crustcore_toolkit::ToolError::InputTooLarge { .. })
                ));
            }

            #[test]
            fn host_redacts_and_receipts_the_visible_result() {
                // Defense-in-depth: prove the host path this tool uses redacts a
                // sentinel and binds the receipt to the final bytes — independent of
                // the tool's own logic (dimensions a, d, e).
                let (redactor, mut chain) = __crust_host_and_redactor();
                let ctx = __crust_ctx();
                let raw = "leaking sk-SENTINEL-do-not-leak in the result";
                let (outcome, receipt) = ::crustcore_toolkit::finalize(
                    &redactor, &mut chain, &ctx, #tool_name, b"args", raw, &[]
                ).expect("small result must finalize");
                let shown = outcome.visible.as_str();
                assert!(!shown.contains("SENTINEL"), "secret survived: {shown}");
                assert!(!redactor.would_leak(shown), "would_leak true on emitted bytes");
                assert!(receipt.result_matches(shown.as_bytes()),
                    "receipt must bind the exact redacted+bounded bytes");
            }
        }
    }
}
