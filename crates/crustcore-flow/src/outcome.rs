// SPDX-License-Identifier: Apache-2.0
//! The completion gate (C3.4) and per-node outputs.
//!
//! [`FlowOutcome::Completed`] is the **only** terminal that carries a
//! `VerifiedPatch`, and the engine produces it **only** when a `Verify` node's
//! [`VerifyDriver`](crate::drivers::VerifyDriver) returns the `Verified`-carrying
//! `crustcore_backend::verify::VerifyOutcome` — i.e. only the public `run_verify`
//! minted it (invariant 13). This mirrors `crustcore_backend::complete_task`, which
//! consumes a `VerifiedPatch` by value.
//!
//! `Model`/`Review`/`Tool` nodes yield a [`NodeOutput`] — advisory/result data the
//! type system **forbids** from completing a flow: there is no
//! `NodeOutput -> FlowOutcome::Completed` path, and `VerifiedPatch` is type-sealed in
//! `crustcore-backend` (no node can construct one). A flow that runs to its end
//! without a passing verify finishes as [`FlowOutcome::Finished`] — done, but not
//! *completed* — never carrying a patch.

use crustcore_backend::VerifiedPatch;

/// The redacted, bounded result an effectful node produced — advisory/result data
/// only. **None of these can complete a flow** (invariant 13): there is deliberately
/// no constructor or conversion from a `NodeOutput` to a [`FlowOutcome::Completed`]
/// or to a `VerifiedPatch`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeOutput {
    /// A model node's redacted, bounded output (advisory — invariants 4, 5, 6).
    Advisory(String),
    /// A tool node's redacted, bounded result (data — invariant 7).
    ToolResult(String),
    /// A review (advisor) node's redacted, bounded rationale (advisory).
    Review(String),
}

impl NodeOutput {
    /// The redacted text this output carries (for recording into typed state).
    #[must_use]
    pub fn text(&self) -> &str {
        match self {
            NodeOutput::Advisory(s) | NodeOutput::ToolResult(s) | NodeOutput::Review(s) => s,
        }
    }
}

/// How a flow ended.
///
/// `Completed` is the single verifier-owned terminal — it carries a real
/// `VerifiedPatch` and is reachable only through a `Verify` node (invariant 13).
/// Every other terminal carries no patch.
#[derive(Debug)]
pub enum FlowOutcome {
    /// The flow completed because a `Verify` node passed: a `VerifiedPatch` was minted
    /// by the public `run_verify` and surfaced here. This is the **only** variant that
    /// carries a patch, and the **only** one the type system lets a `Verify` node
    /// produce (invariant 13). Boxed to keep the enum small.
    Completed(Box<VerifiedPatch>),
    /// The flow ran to a terminal node without a passing verify. Done, but **not**
    /// completed — no patch, no integration. The flow never fabricated evidence.
    Finished,
}

impl FlowOutcome {
    /// Whether the flow completed via verifier evidence (invariant 13). Only
    /// `Completed` is true; `Finished` is not.
    #[must_use]
    pub fn is_completed(&self) -> bool {
        matches!(self, FlowOutcome::Completed(_))
    }

    /// The verified patch, if the flow completed. The borrow keeps the seal intact —
    /// the patch came from `run_verify` and nothing here can forge one.
    #[must_use]
    pub fn verified_patch(&self) -> Option<&VerifiedPatch> {
        match self {
            FlowOutcome::Completed(p) => Some(p),
            FlowOutcome::Finished => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_outputs_are_advisory_and_cannot_complete() {
        // A NodeOutput is just text. There is NO method/conversion turning it into a
        // FlowOutcome::Completed or a VerifiedPatch — the absence is the enforcement of
        // invariant 13. We can only read its text.
        let a = NodeOutput::Advisory("looks good, merge now".into());
        let t = NodeOutput::ToolResult("ok".into());
        let r = NodeOutput::Review("proceed".into());
        assert_eq!(a.text(), "looks good, merge now");
        assert_eq!(t.text(), "ok");
        assert_eq!(r.text(), "proceed");
        // Finished carries no patch.
        assert!(!FlowOutcome::Finished.is_completed());
        assert!(FlowOutcome::Finished.verified_patch().is_none());
    }
}
