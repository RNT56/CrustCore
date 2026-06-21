// SPDX-License-Identifier: Apache-2.0
//! Generating the bounded-I/O + redaction + receipt wiring (C2.4).
//!
//! The generated `invoke`:
//! 1. takes the bounded, untrusted [`ToolArgs`](crustcore_toolkit::ToolArgs) (input
//!    bounding already enforced at construction — invariant 11),
//! 2. parses each typed parameter out of the canonical argument encoding,
//! 3. calls the author's body, which returns a raw `String` result,
//! 4. hands that raw string to the host through
//!    [`HostTool::emit`](crustcore_toolkit::HostTool::emit), which runs the fixed
//!    order **redact → bound → mint** and returns the `ModelVisibleText` outcome +
//!    the host-minted receipt.
//!
//! Generated code never holds a `MacKey`, never calls `ReceiptChain::mint`, and
//! never constructs a model-visible `String` — the only visible value it can produce
//! is the `ModelVisibleText` that `emit` returns (dimensions a, e).

use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use crate::parse::{ParamDef, ToolDef};
use crate::schema::ParamType;

/// Generates the per-parameter decode statements. Arguments arrive as a canonical
/// newline-separated `name=value` encoding (one bounded, std-only format — no
/// serde_json dep in the toolkit/macro). Each decode is fallible and surfaces a
/// typed [`ToolError::InvalidArgs`](crustcore_toolkit::ToolError) — never a panic
/// (invariant 7: arguments are untrusted data).
fn decode_param(p: &ParamDef, field_fn: &syn::Ident) -> TokenStream {
    let name = &p.name;
    let key = name.to_string();
    let rust_ty = &p.rust_ty;
    match &p.ty {
        ParamType::StringTy => quote! {
            let #name: #rust_ty = #field_fn(__crust_args_str, #key)
                .ok_or_else(|| ::crustcore_toolkit::ToolError::InvalidArgs(
                    ::std::format!("missing required string parameter `{}`", #key)))?
                .to_string();
        },
        ParamType::Integer => quote! {
            let #name: #rust_ty = #field_fn(__crust_args_str, #key)
                .ok_or_else(|| ::crustcore_toolkit::ToolError::InvalidArgs(
                    ::std::format!("missing required integer parameter `{}`", #key)))?
                .trim()
                .parse()
                .map_err(|_| ::crustcore_toolkit::ToolError::InvalidArgs(
                    ::std::format!("parameter `{}` is not a valid integer", #key)))?;
        },
        ParamType::Boolean => quote! {
            let #name: #rust_ty = match #field_fn(__crust_args_str, #key)
                .ok_or_else(|| ::crustcore_toolkit::ToolError::InvalidArgs(
                    ::std::format!("missing required bool parameter `{}`", #key)))?
                .trim()
            {
                "true" | "1" => true,
                "false" | "0" => false,
                _ => return ::std::result::Result::Err(
                    ::crustcore_toolkit::ToolError::InvalidArgs(
                        ::std::format!("parameter `{}` is not a valid bool", #key))),
            };
        },
        ParamType::Optional(inner) => {
            // Optional params: absent => None; present => parse the inner type.
            let inner_parse = decode_optional_inner(inner, &key);
            quote! {
                let #name: #rust_ty = match #field_fn(__crust_args_str, #key) {
                    ::std::option::Option::None => ::std::option::Option::None,
                    ::std::option::Option::Some(__crust_v) => {
                        ::std::option::Option::Some(#inner_parse)
                    }
                };
            }
        }
        ParamType::Array(inner) => {
            // Arrays: comma-separated values under the key; empty => empty vec.
            let inner_parse = decode_array_inner(inner, &key);
            quote! {
                let #name: #rust_ty = match #field_fn(__crust_args_str, #key) {
                    ::std::option::Option::None => ::std::vec::Vec::new(),
                    ::std::option::Option::Some(__crust_list) if __crust_list.is_empty() =>
                        ::std::vec::Vec::new(),
                    ::std::option::Option::Some(__crust_list) => {
                        let mut __crust_out = ::std::vec::Vec::new();
                        for __crust_v in __crust_list.split(',') {
                            __crust_out.push(#inner_parse);
                        }
                        __crust_out
                    }
                };
            }
        }
    }
}

/// The per-tool name of the generated argument field accessor, kept unique so two
/// tools in one module do not collide (`E0428`).
fn field_fn_ident(def: &ToolDef) -> syn::Ident {
    format_ident!("__crust_field_{}", def.func.sig.ident)
}

/// Parse expression for the inner type of an `Option<T>`, over the binding `__crust_v`.
fn decode_optional_inner(inner: &ParamType, key: &str) -> TokenStream {
    scalar_parse(inner, key)
}

/// Parse expression for the element type of a `Vec<T>`, over the binding `__crust_v`.
fn decode_array_inner(inner: &ParamType, key: &str) -> TokenStream {
    scalar_parse(inner, key)
}

/// A scalar parse expression over the `&str` binding `__crust_v`, used for the inner
/// types of `Option`/`Vec`. Nested `Option`/`Vec` are not supported as element types
/// (the parse format is flat) — those were already accepted by the schema mapper, so
/// we degrade to a typed error rather than a panic.
fn scalar_parse(inner: &ParamType, key: &str) -> TokenStream {
    match inner {
        ParamType::StringTy => quote!(__crust_v.to_string()),
        ParamType::Integer => quote! {
            __crust_v.trim().parse().map_err(|_|
                ::crustcore_toolkit::ToolError::InvalidArgs(
                    ::std::format!("element of `{}` is not a valid integer", #key)))?
        },
        ParamType::Boolean => quote! {
            match __crust_v.trim() {
                "true" | "1" => true,
                "false" | "0" => false,
                _ => return ::std::result::Result::Err(
                    ::crustcore_toolkit::ToolError::InvalidArgs(
                        ::std::format!("element of `{}` is not a valid bool", #key))),
            }
        },
        ParamType::Optional(_) | ParamType::Array(_) => quote! {
            return ::std::result::Result::Err(
                ::crustcore_toolkit::ToolError::InvalidArgs(
                    ::std::format!("nested container element of `{}` is not supported by the \
                                    flat arg encoding", #key)))
        },
    }
}

/// Generates the tool struct definition: a `'h`-borrowing wrapper holding the host
/// handle behind a `RefCell` (interior mutability so the `&self` `invoke` can advance
/// the host receipt chain). The struct is built from a [`HostTool`](crustcore_toolkit::HostTool).
pub fn generate_struct(def: &ToolDef) -> TokenStream {
    let struct_ident = &def.struct_ident;
    let doc = format!(
        "Tool generated by `#[crust_tool]` for `{}`. Built from a host handle; the \
         only model-visible output is the redactor-sealed `ModelVisibleText` its \
         `invoke` returns.",
        def.tool_name
    );
    quote! {
        #[doc = #doc]
        pub struct #struct_ident<'h> {
            host: ::core::cell::RefCell<::crustcore_toolkit::HostTool<'h>>,
        }

        impl<'h> #struct_ident<'h> {
            /// Builds the tool from the trusted host handle. Only the host (which owns
            /// the `MacKey` inside the receipt chain) can construct a `HostTool`.
            #[must_use]
            pub fn new(host: ::crustcore_toolkit::HostTool<'h>) -> Self {
                Self { host: ::core::cell::RefCell::new(host) }
            }
        }
    }
}

/// Generates the `CrustTool::invoke` method body (without the surrounding `impl`).
///
/// `invoke` decodes the params from the bounded, untrusted `ToolArgs`, calls the
/// author body with `&mut HostTool`, and the body's raw `String` result is handed to
/// `host.emit`, which redacts → bounds → mints and yields the visible outcome. The
/// receipt is advanced into the host's chain.
pub fn generate_invoke_method(def: &ToolDef) -> TokenStream {
    let fn_ident = &def.func.sig.ident;
    let tool_name = &def.tool_name;
    let field_fn = field_fn_ident(def);
    let decodes: Vec<TokenStream> = def
        .params
        .iter()
        .map(|p| decode_param(p, &field_fn))
        .collect();
    let param_idents: Vec<&syn::Ident> = def.params.iter().map(|p| &p.name).collect();

    quote! {
        #[allow(unused_variables, clippy::let_unit_value)]
        fn invoke(
            &self,
            args: &::crustcore_toolkit::ToolArgs,
        ) -> ::std::result::Result<
            ::crustcore_toolkit::ToolOutcome,
            ::crustcore_toolkit::ToolError,
        > {
            // The bytes are untrusted data (invariant 7); require UTF-8 then decode
            // each typed field. Input bounding was enforced when the `ToolArgs` was
            // constructed (invariant 11).
            let __crust_args_str = args.as_str().ok_or_else(||
                ::crustcore_toolkit::ToolError::InvalidArgs(
                    ::std::string::String::from("tool arguments are not valid UTF-8")))?;

            #(#decodes)*

            // Borrow the host mutably across the call so the receipt chain (which
            // holds the MacKey) can advance. The generated tool never touches the key
            // or `mint` directly.
            let mut __crust_host = self.host.borrow_mut();
            let __crust_raw: ::std::string::String =
                #fn_ident(&mut __crust_host, #(#param_idents),*)?;

            // redact -> bound -> mint over the EXACT shown bytes (host-owned key).
            let (__crust_outcome, _receipt) = __crust_host.emit(
                #tool_name,
                args.as_bytes(),
                &__crust_raw,
                &[],
            )?;
            ::std::result::Result::Ok(__crust_outcome)
        }
    }
}

/// Generates the small std-only field accessor used by the decode glue. Emitted once
/// per tool (uniquely named) at module scope so two tools in one module do not
/// collide and so the generated `invoke` can call it.
pub fn generate_field_helper(def: &ToolDef) -> TokenStream {
    let field_fn = field_fn_ident(def);
    quote! {
        /// Reads the value for `key` from a newline-separated `key=value` argument
        /// blob. Returns the first match's value (trailing `\r` trimmed). Bounded,
        /// std-only — no serde dependency in the toolkit/macro graph.
        #[doc(hidden)]
        fn #field_fn<'a>(blob: &'a str, key: &str) -> ::std::option::Option<&'a str> {
            for line in blob.lines() {
                if let ::std::option::Option::Some((k, v)) = line.split_once('=') {
                    if k.trim() == key {
                        return ::std::option::Option::Some(v.trim_end_matches('\r'));
                    }
                }
            }
            ::std::option::Option::None
        }
    }
}
