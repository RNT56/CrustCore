// SPDX-License-Identifier: Apache-2.0
//! `crustcore-tool-macro` — the `#[crust_tool]` proc-macro (C2-toolmacro;
//! `docs/roadmap-v0.2.md` §C2).
//!
//! Annotating a free function with `#[crust_tool]` GENERATES, mechanically, a safe
//! capability-pack tool: a [`CrustTool`] impl whose schema is derived from the typed
//! signature, whose I/O is bounded and redacted, whose model-visible result is a
//! receipted [`ModelVisibleText`], and whose risk default is the fail-safe
//! `Reversibility::Destructive`. The macro emits *wiring only* — it consumes the
//! `crustcore-policy` / `crustcore-secrets` / `crustcore-receipts` / `crustcore-types`
//! contracts UNCHANGED through `crustcore-toolkit`, and never embeds an allow/deny
//! decision, never lets generated code hold a `MacKey`, and never lets it construct an
//! `Approved<T>` (invariants 4, 8, 10, 11).
//!
//! `syn`/`quote`/`proc-macro2` are **build-time only** deps: they run at compile time
//! and ship in no binary. Neither this crate nor those deps ever enter the nano
//! feature graph (`xtask forbidden-deps` proves it).
//!
//! # Authoring shape
//!
//! ```ignore
//! use crustcore_tool_macro::crust_tool;
//! use crustcore_toolkit::{HostTool, ToolError};
//!
//! /// A read-only tool: explicitly downgraded from the fail-safe default.
//! #[crust_tool(reversibility = "Reversible")]
//! fn greet(host: &mut HostTool, name: String, times: u32) -> Result<String, ToolError> {
//!     Ok(format!("hello {name}").repeat(times as usize))
//! }
//! // generates: `struct Greet<'h>` impl `CrustTool`, plus `Greet::classify(&policy)`.
//! ```
//!
//! The first argument is the trusted-host handle [`HostTool`]; the remaining typed
//! arguments become the schema. The body returns a raw `String`, which the generated
//! `invoke` redacts → bounds → receipts before it can be model-visible.

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn, Meta};

mod codegen_io;
mod codegen_risk;
mod codegen_tests;
mod parse;
mod schema;

/// The `#[crust_tool]` attribute macro. See the crate docs for the authoring shape.
///
/// Accepts an optional `reversibility = "Reversible|ReversibleWithCleanup|\
/// Irreversible|Destructive"`; absent ⇒ the fail-safe `Destructive` default. An
/// unknown attribute key or value, an unsupported parameter/result type, or a
/// reference to a self-authorization / receipt-forgery symbol in the body is a hard
/// compile error.
#[proc_macro_attribute]
pub fn crust_tool(attr: TokenStream, item: TokenStream) -> TokenStream {
    let func = parse_macro_input!(item as ItemFn);

    // Parse the attribute (empty => bare path => fail-safe default).
    let reversibility = if attr.is_empty() {
        parse::DEFAULT_REVERSIBILITY.to_string()
    } else {
        // Wrap the raw args as a `Meta::List` so the nested-meta parser runs.
        let attr2: proc_macro2::TokenStream = attr.into();
        let meta: Meta = match syn::parse2(quote!(crust_tool(#attr2))) {
            Ok(m) => m,
            Err(e) => return e.to_compile_error().into(),
        };
        match parse::parse_attr_reversibility(&meta) {
            Ok(r) => r,
            Err(e) => return e.to_compile_error().into(),
        }
    };

    expand(func, reversibility)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

/// The fallible expansion, separated so errors lower to `compile_error!`.
fn expand(func: ItemFn, reversibility: String) -> syn::Result<proc_macro2::TokenStream> {
    // Belt-and-suspenders: reject obvious self-authorization / forgery symbols in the
    // body (the structural guarantee is the real defense; this is a clearer error).
    parse::reject_forbidden_tokens(&func)?;

    let def = parse::lower_fn(func, reversibility)?;

    let struct_def = codegen_io::generate_struct(&def);
    let field_helper = codegen_io::generate_field_helper(&def);
    let schema_method = schema::generate_schema_method(&def);
    let reversibility_method = codegen_risk::generate_default_reversibility(&def);
    let invoke_method = codegen_io::generate_invoke_method(&def);
    let classify_method = codegen_risk::generate_classify_method(&def);
    let tests = codegen_tests::generate_tests(&def);

    let struct_ident = &def.struct_ident;
    let original_fn = &def.func;

    Ok(quote! {
        // The author's body, re-emitted verbatim (it takes `&mut HostTool` first).
        #original_fn

        // The std-only argument field accessor used by the generated `invoke`.
        #field_helper

        // The generated tool struct + its `new(host)` constructor.
        #struct_def

        // The CrustTool impl: derived schema + fail-safe reversibility + wired invoke.
        impl ::crustcore_toolkit::CrustTool for #struct_ident<'_> {
            #schema_method
            #reversibility_method
            #invoke_method
        }

        // The policy-classify convenience (forwards to PolicySnapshot::classify).
        #classify_method

        // Per-tool safety fixtures.
        #tests
    })
}
