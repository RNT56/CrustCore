// SPDX-License-Identifier: Apache-2.0
//! Generating the fail-safe risk default + the policy-classify wiring (C2.5).
//!
//! The generated `default_reversibility()` returns the author-chosen variant or, by
//! default, the most restrictive [`Reversibility::Destructive`](crustcore_types::Reversibility)
//! — which [`PolicySnapshot::classify`](crustcore_policy::PolicySnapshot::classify)
//! maps to `RequireApproval` (or `Deny` under `ReadOnly`). A forgotten or typo'd
//! classification therefore fails closed (dimensions b, c).
//!
//! The real decision is NEVER inlined: the generated `classify` convenience just
//! forwards to `PolicySnapshot::classify` (the host-owned chokepoint). Generated code
//! has no path to `AuthorizedUser::approve` or to constructing an `Approved<T>` — the
//! macro only ever names `Reversibility` and `PolicyDecision`, never the
//! authorization types (invariants 4, 8).

use proc_macro2::TokenStream;
use quote::quote;
use syn::Ident;

use crate::parse::ToolDef;

/// Generates the `fn default_reversibility() -> Reversibility` method body for the
/// `CrustTool` impl, using the validated variant from the attribute (default
/// `Destructive`).
pub fn generate_default_reversibility(def: &ToolDef) -> TokenStream {
    // `def.reversibility` was validated in parse against the known variant set, so
    // this ident is always a real `crustcore_types::Reversibility` variant.
    let variant = Ident::new(&def.reversibility, proc_macro2::Span::call_site());
    quote! {
        fn default_reversibility() -> ::crustcore_types::Reversibility {
            ::crustcore_types::Reversibility::#variant
        }
    }
}

/// Generates an inherent `classify` convenience on the tool struct that forwards to
/// the host policy snapshot — the *real* decision, never inlined. It is the single
/// place a caller asks "may this tool run under the host's profile?" and it cannot
/// return anything but a [`PolicyDecision`](crustcore_policy::PolicyDecision); there
/// is no generated path to an `Approved<T>`.
pub fn generate_classify_method(def: &ToolDef) -> TokenStream {
    let struct_ident = &def.struct_ident;
    quote! {
        impl #struct_ident<'_> {
            /// Classifies this tool under `policy` by forwarding to the host-owned
            /// `PolicySnapshot::classify` over the fail-safe `default_reversibility()`.
            /// The decision is never inlined and can never be an `Approved<T>`.
            #[must_use]
            pub fn classify(
                policy: &::crustcore_policy::PolicySnapshot,
            ) -> ::crustcore_policy::PolicyDecision {
                ::crustcore_toolkit::classify_tool::<Self>(policy)
            }
        }
    }
}
