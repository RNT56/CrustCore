// SPDX-License-Identifier: Apache-2.0
//! Mapping Rust types to the toolkit's `SchemaType`, and generating the
//! `CrustTool::schema()` body (C2.3).
//!
//! The whole point of this module is that **an unsupported type is a hard compile
//! error, never a permissive `Any` schema** (dimension f): widening the accepted
//! input surface by accident is exactly the failure mode the macro must rule out.

use proc_macro2::TokenStream;
use quote::quote;
use syn::spanned::Spanned;
use syn::{GenericArgument, PathArguments, Type};

use crate::parse::ToolDef;

/// A supported parameter/result type, mirroring `crustcore_toolkit::SchemaType`
/// minus the `Any` escape hatch (the macro never emits `Any`).
#[derive(Clone)]
pub enum ParamType {
    /// `String`.
    StringTy,
    /// Any Rust integer width (`i8`..`u128`, `usize`, `isize`).
    Integer,
    /// `bool`.
    Boolean,
    /// `Option<T>` of a supported `T`.
    Optional(Box<ParamType>),
    /// `Vec<T>` of a supported `T`.
    Array(Box<ParamType>),
}

const INT_IDENTS: &[&str] = &[
    "i8", "i16", "i32", "i64", "i128", "isize", "u8", "u16", "u32", "u64", "u128", "usize",
];

impl ParamType {
    /// Maps a Rust type to a [`ParamType`]. An unsupported type is a hard compile
    /// error (with a span pointing at the offending type) — never a fallback.
    pub fn from_rust_type(ty: &Type) -> syn::Result<ParamType> {
        match ty {
            // Drill through a leading reference (`&str`, `&String`) for ergonomics.
            Type::Reference(r) => ParamType::from_rust_type(&r.elem),
            Type::Path(tp) => {
                let Some(seg) = tp.path.segments.last() else {
                    return Err(unsupported(ty));
                };
                let ident = seg.ident.to_string();
                match ident.as_str() {
                    "String" | "str" => Ok(ParamType::StringTy),
                    "bool" => Ok(ParamType::Boolean),
                    name if INT_IDENTS.contains(&name) => Ok(ParamType::Integer),
                    "Option" => {
                        let inner = single_generic(seg, ty)?;
                        Ok(ParamType::Optional(Box::new(ParamType::from_rust_type(
                            &inner,
                        )?)))
                    }
                    "Vec" => {
                        let inner = single_generic(seg, ty)?;
                        Ok(ParamType::Array(Box::new(ParamType::from_rust_type(
                            &inner,
                        )?)))
                    }
                    _ => Err(unsupported(ty)),
                }
            }
            _ => Err(unsupported(ty)),
        }
    }

    /// Whether this type is optional at the top level (an `Option<T>`), which makes
    /// the param non-`required` in the schema.
    fn is_optional(&self) -> bool {
        matches!(self, ParamType::Optional(_))
    }

    /// Emits the `crustcore_toolkit::SchemaType` constructor expression for this
    /// type, using fully-qualified paths so author code cannot shadow it (hygiene).
    fn to_schema_expr(&self) -> TokenStream {
        match self {
            ParamType::StringTy => quote!(::crustcore_toolkit::SchemaType::String),
            ParamType::Integer => quote!(::crustcore_toolkit::SchemaType::Integer),
            ParamType::Boolean => quote!(::crustcore_toolkit::SchemaType::Boolean),
            ParamType::Optional(inner) => {
                let i = inner.to_schema_expr();
                quote!(::crustcore_toolkit::SchemaType::Optional(::std::boxed::Box::new(#i)))
            }
            ParamType::Array(inner) => {
                let i = inner.to_schema_expr();
                quote!(::crustcore_toolkit::SchemaType::Array(::std::boxed::Box::new(#i)))
            }
        }
    }
}

/// Extracts the single generic argument of `Option<T>` / `Vec<T>` (`T`); anything
/// else (no args, multiple args, a lifetime/const) is a hard error.
fn single_generic(seg: &syn::PathSegment, outer: &Type) -> syn::Result<Type> {
    if let PathArguments::AngleBracketed(args) = &seg.arguments {
        let tys: Vec<&Type> = args
            .args
            .iter()
            .filter_map(|a| match a {
                GenericArgument::Type(t) => Some(t),
                _ => None,
            })
            .collect();
        if tys.len() == 1 {
            return Ok(tys[0].clone());
        }
    }
    Err(unsupported(outer))
}

/// The standard "unsupported type" compile error. Names the supported set so the
/// author knows what to do — and makes clear this is deliberate, not a TODO.
fn unsupported(ty: &Type) -> syn::Error {
    syn::Error::new(
        ty.span(),
        "unsupported #[crust_tool] type: only String, the integer types, bool, \
         Option<T>, and Vec<T> of those are supported. An unsupported type is a hard \
         error (never a permissive `any` schema) so the accepted-input surface stays \
         exactly the declared types (invariant 7).",
    )
}

/// Generates the `fn schema(&self) -> ToolSchema` body for a tool, building the
/// param list and result type from the lowered signature.
pub fn generate_schema_method(def: &ToolDef) -> TokenStream {
    let tool_name = &def.tool_name;
    let params = def.params.iter().map(|p| {
        let name = p.name.to_string();
        let ty_expr = p.ty.to_schema_expr();
        let required = !p.ty.is_optional();
        quote! {
            ::crustcore_toolkit::ParamSchema {
                name: ::std::string::String::from(#name),
                ty: #ty_expr,
                required: #required,
            }
        }
    });
    let result_expr = def.result.to_schema_expr();
    quote! {
        fn schema(&self) -> ::crustcore_toolkit::ToolSchema {
            ::crustcore_toolkit::ToolSchema {
                name: ::std::string::String::from(#tool_name),
                params: ::std::vec![ #(#params),* ],
                result: #result_expr,
            }
        }
    }
}
