// SPDX-License-Identifier: Apache-2.0
//! Parsing the `#[crust_tool]` attribute and the annotated function signature
//! (C2.2). Validates attribute args and lowers the typed signature into the small
//! IR (`ToolDef`) the codegen modules consume.

use proc_macro2::Span;
use syn::spanned::Spanned;
use syn::{Attribute, Expr, ExprLit, FnArg, ItemFn, Lit, Meta, Pat, ReturnType, Type};

use crate::schema::ParamType;

/// The fail-safe default reversibility a tool gets when the author writes no
/// `reversibility = "…"` — the most restrictive (invariant 14, dimension b).
pub const DEFAULT_REVERSIBILITY: &str = "Destructive";

/// One typed parameter lowered from the function signature.
pub struct ParamDef {
    /// The binding name (also the schema/JSON key).
    pub name: syn::Ident,
    /// The schema-mapped type.
    pub ty: ParamType,
    /// The original Rust type (re-emitted verbatim for the parse glue).
    pub rust_ty: Box<Type>,
}

/// The lowered tool definition the codegen modules consume.
pub struct ToolDef {
    /// The annotated function (re-emitted as the tool body).
    pub func: ItemFn,
    /// The tool's exported name (the function name unless overridden).
    pub tool_name: String,
    /// The generated tool struct's identifier (PascalCase of the fn name).
    pub struct_ident: syn::Ident,
    /// The typed parameters (excluding the leading host-context argument).
    pub params: Vec<ParamDef>,
    /// The result type mapped to a schema type.
    pub result: ParamType,
    /// The author-chosen (or fail-safe default) reversibility, as the variant ident
    /// string (validated against the known set).
    pub reversibility: String,
}

/// Parses the `#[crust_tool(...)]` attribute arguments. Currently supports a single
/// `reversibility = "Variant"` knob; an unknown key or value is a hard error (a
/// typo'd classification must not silently fall back to a permissive posture —
/// dimension b/c).
pub fn parse_attr_reversibility(attr_args: &Meta) -> syn::Result<String> {
    // The attribute is `#[crust_tool]` or `#[crust_tool(reversibility = "…")]`.
    match attr_args {
        // Bare `#[crust_tool]`: fail-safe default.
        Meta::Path(_) => Ok(DEFAULT_REVERSIBILITY.to_string()),
        Meta::List(list) => {
            // Default fail-safe unless an explicit, validated `reversibility` is given.
            let mut reversibility = DEFAULT_REVERSIBILITY.to_string();
            list.parse_nested_meta(|nested| {
                if nested.path.is_ident("reversibility") {
                    let value = nested.value()?;
                    let lit: syn::LitStr = value.parse()?;
                    reversibility = validate_reversibility(&lit.value(), lit.span())?;
                    Ok(())
                } else {
                    Err(nested.error(
                        "unknown #[crust_tool] argument; the only supported key is \
                         `reversibility = \"Reversible|ReversibleWithCleanup|Irreversible|Destructive\"`",
                    ))
                }
            })?;
            Ok(reversibility)
        }
        Meta::NameValue(nv) => Err(syn::Error::new(
            nv.span(),
            "#[crust_tool] takes arguments in list form, e.g. \
             #[crust_tool(reversibility = \"Reversible\")]",
        )),
    }
}

/// Validates a reversibility string against the known `crustcore_types::Reversibility`
/// variants. An unknown value is a hard compile error — never a permissive fallback.
fn validate_reversibility(value: &str, span: Span) -> syn::Result<String> {
    const KNOWN: &[&str] = &[
        "Reversible",
        "ReversibleWithCleanup",
        "Irreversible",
        "Destructive",
    ];
    if KNOWN.contains(&value) {
        Ok(value.to_string())
    } else {
        Err(syn::Error::new(
            span,
            format!(
                "unknown reversibility `{value}`; expected one of {}",
                KNOWN.join(", ")
            ),
        ))
    }
}

/// Lowers an annotated `fn` into a [`ToolDef`].
///
/// The function's FIRST parameter is the host-context handle (it carries the
/// redactor/receipt-chain/ctx the generated code threads into `finalize`); it is not
/// part of the schema. Every remaining parameter must be a supported type — an
/// unsupported type is a hard compile error (never an `Any` schema; dimension f).
/// The return type must be `Result<String, ToolError>`-shaped; the `String` is the
/// raw result the generated code redacts (it never reaches the model un-redacted).
pub fn lower_fn(func: ItemFn, reversibility: String) -> syn::Result<ToolDef> {
    let fn_ident = func.sig.ident.clone();
    let tool_name = fn_ident.to_string();
    let struct_ident = syn::Ident::new(&to_pascal_case(&tool_name), fn_ident.span());

    let mut inputs = func.sig.inputs.iter();
    // First arg is the host context handle; require it so generated code can mint a
    // receipt over the host's key (the tool can never hold a MacKey itself).
    let Some(first) = inputs.next() else {
        return Err(syn::Error::new(
            func.sig.span(),
            "a #[crust_tool] fn must take the host context handle as its first \
             argument, e.g. `fn my_tool(host: &mut crustcore_toolkit::HostTool, …)`",
        ));
    };
    if matches!(first, FnArg::Receiver(_)) {
        return Err(syn::Error::new(
            first.span(),
            "a #[crust_tool] fn must be a free function, not a method (no `self`)",
        ));
    }

    let mut params = Vec::new();
    for arg in inputs {
        let FnArg::Typed(pat_ty) = arg else {
            return Err(syn::Error::new(arg.span(), "unexpected `self` parameter"));
        };
        let Pat::Ident(pat_ident) = pat_ty.pat.as_ref() else {
            return Err(syn::Error::new(
                pat_ty.pat.span(),
                "#[crust_tool] parameters must be simple named bindings",
            ));
        };
        let name = pat_ident.ident.clone();
        // Map the Rust type to a schema type; an unsupported type errors here.
        let ty = ParamType::from_rust_type(pat_ty.ty.as_ref())?;
        params.push(ParamDef {
            name,
            ty,
            rust_ty: pat_ty.ty.clone(),
        });
    }

    // Result type: unwrap `Result<Ok, _>` and require the Ok type be a supported
    // schema type (so the schema's result is concrete, dimension f).
    let result = match &func.sig.output {
        ReturnType::Default => {
            return Err(syn::Error::new(
                func.sig.span(),
                "a #[crust_tool] fn must return `Result<String, crustcore_toolkit::ToolError>` \
                 (or another supported Ok type)",
            ));
        }
        ReturnType::Type(_, ty) => {
            let ok = result_ok_type(ty)?;
            ParamType::from_rust_type(&ok)?
        }
    };

    Ok(ToolDef {
        func,
        tool_name,
        struct_ident,
        params,
        result,
        reversibility,
    })
}

/// Extracts the `Ok` type from a `Result<Ok, Err>` return type. Anything else is a
/// hard error (the contract is `Result<_, ToolError>`).
fn result_ok_type(ty: &Type) -> syn::Result<Type> {
    if let Type::Path(tp) = ty {
        if let Some(seg) = tp.path.segments.last() {
            if seg.ident == "Result" {
                if let syn::PathArguments::AngleBracketed(args) = &seg.arguments {
                    if let Some(syn::GenericArgument::Type(ok)) = args.args.first() {
                        return Ok(ok.clone());
                    }
                }
            }
        }
    }
    Err(syn::Error::new(
        ty.span(),
        "a #[crust_tool] fn must return a `Result<Ok, crustcore_toolkit::ToolError>`",
    ))
}

/// Rejects a banned identifier appearing literally in the annotated fn body, as a
/// belt-and-suspenders compile-time guard that generated/author code in a tool does
/// not reach the self-authorization or receipt-forgery surface (dimensions c, e).
/// The structural guarantee (no `MacKey` in scope, `ModelVisibleText`-only output)
/// is the real defense; this is a clear early error.
pub fn reject_forbidden_tokens(func: &ItemFn) -> syn::Result<()> {
    let src = quote::quote!(#func).to_string();
    const FORBIDDEN: &[(&str, &str)] = &[
        (
            "AuthorizedUser",
            "generated tool code cannot reach `AuthorizedUser::approve`",
        ),
        (
            "Approved",
            "generated tool code cannot construct an `Approved<T>` (no self-authorization)",
        ),
        (
            "MacKey",
            "generated tool code cannot hold a `MacKey` (the host owns it)",
        ),
    ];
    for (needle, msg) in FORBIDDEN {
        if token_present(&src, needle) {
            return Err(syn::Error::new(
                func.sig.span(),
                format!("{msg} (invariants 4, 8, 10)"),
            ));
        }
    }
    Ok(())
}

/// Whether `needle` appears as a whole token in the (whitespace-normalized) source.
fn token_present(src: &str, needle: &str) -> bool {
    src.split(|c: char| !c.is_alphanumeric() && c != '_')
        .any(|tok| tok == needle)
}

/// Pull a single `#[crust_tool(...)]` (or bare `#[crust_tool]`) off a function's
/// attribute list when the macro is invoked as a derive-like helper. (Unused by the
/// attribute entry point, which receives the args directly; kept for the parse API.)
#[allow(dead_code)]
pub fn find_crust_tool_attr(attrs: &[Attribute]) -> Option<&Attribute> {
    attrs.iter().find(|a| a.path().is_ident("crust_tool"))
}

/// Converts `snake_case` (or any) identifier to `PascalCase` for the struct name.
fn to_pascal_case(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut upper = true;
    for ch in s.chars() {
        if ch == '_' {
            upper = true;
        } else if upper {
            out.extend(ch.to_uppercase());
            upper = false;
        } else {
            out.push(ch);
        }
    }
    if out.is_empty() {
        out.push_str("Tool");
    }
    out
}

/// Helper for literal extraction in tests / future attr knobs.
#[allow(dead_code)]
pub fn lit_str(expr: &Expr) -> Option<String> {
    if let Expr::Lit(ExprLit {
        lit: Lit::Str(s), ..
    }) = expr
    {
        Some(s.value())
    } else {
        None
    }
}
