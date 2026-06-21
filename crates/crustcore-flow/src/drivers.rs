// SPDX-License-Identifier: Apache-2.0
//! Driver seams (C3.2): the **only** way a node performs I/O.
//!
//! The engine is a pure scheduler; every effectful node delegates to one of these
//! traits. This mirrors the closure/trait injection inside
//! `crustcore_backend::verify` and `crustcore_daemon::exec::SubagentExecutor`, so the
//! whole graph is unit-testable with [`FakeDrivers`] in CI and live transports drop in
//! behind `live-flow` (see [`crate::live`]).
//!
//! Crucial seal interaction (invariant 13): [`VerifyDriver::verify`] returns the
//! backend `crustcore_backend::verify::VerifyOutcome`. Because `VerifiedPatch` is
//! type-sealed in `crustcore-backend` (constructible only inside `run_verify`), a
//! *fake* verify driver **cannot** return a `Verified` outcome — only `Failed`/
//! `Refused`. That is the seal working as intended: the positive completion path is
//! exercisable only by the live driver (a `#[ignore]`d `live-flow` test). In CI we
//! prove all the negatives deterministically.

use crustcore_backend::verify::VerifyOutcome;

use crate::graph::ToolSpec;

/// Why a driver could not run a node. Carries a bounded, non-sensitive reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverError(pub String);

impl DriverError {
    /// Builds a driver error from a reason.
    #[must_use]
    pub fn new(reason: impl Into<String>) -> Self {
        DriverError(reason.into())
    }
}

impl core::fmt::Display for DriverError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for DriverError {}

/// What the engine hands a [`ToolDriver`] for one `Tool` node: the classified spec and
/// the bounded args. The driver receives the spec so a live impl re-derives the
/// sandbox/policy posture from it; it never receives an authority object.
#[derive(Debug, Clone)]
pub struct ToolInvocation<'a> {
    /// The tool's classified spec (name, reversibility, execution-capable).
    pub spec: &'a ToolSpec,
    /// The bounded argument string.
    pub args: &'a str,
}

/// Runs a `model` node. The returned text is **untrusted** model output (invariant 7);
/// the engine taints + redacts + bounds it before it ever reaches typed state. The
/// `cost` is what the engine charges against the [`FlowBudget`](crate::FlowBudget).
pub trait ModelDriver {
    /// Consults a model with `prompt`, returning `(raw_output, cost)`.
    ///
    /// # Errors
    /// [`DriverError`] if the model could not be consulted.
    fn run_model(&self, prompt: &str) -> Result<(String, u64), DriverError>;
}

/// Runs a `tool` node. The engine has **already** classified the tool through
/// `crustcore-policy` and checked any required approval before calling this, so a
/// driver is only ever invoked for an allowed (and, if irreversible, approved) tool
/// (invariants 8, 14). A live impl additionally runs under a sandbox profile
/// (invariant 9). The returned text is untrusted and redacted by the engine.
pub trait ToolDriver {
    /// Invokes the tool, returning its raw (untrusted) result text.
    ///
    /// # Errors
    /// [`DriverError`] if the tool could not run.
    fn run_tool(&self, inv: &ToolInvocation<'_>) -> Result<String, DriverError>;
}

/// Runs a `verify` node by calling the public `crustcore_backend::verify::run_verify`
/// (the sole `VerifiedPatch` minter). Returns the backend [`VerifyOutcome`] verbatim:
/// `Verified` (live only — see the module note on the seal), `Failed`, or `Refused`.
pub trait VerifyDriver {
    /// Reruns the user verify command, returning the backend outcome.
    fn verify(&self) -> VerifyOutcome;
}

/// Runs a `review` node via `crustcore_daemon::advisor`. The returned text is the
/// (untrusted) advisory rationale; the engine redacts + bounds it. A review note is
/// **advisory only** — it never authorizes and never reaches the user (invariants 4,
/// 5, 6); structurally, this trait returns plain text, not an `Approved<T>`.
pub trait ReviewDriver {
    /// Produces an advisory rationale for the current step.
    ///
    /// # Errors
    /// [`DriverError`] if the advisor could not be consulted.
    fn review(&self) -> Result<String, DriverError>;
}

/// The bundle of driver seams the engine uses. A real run injects live impls
/// ([`crate::live`]); CI injects [`FakeDrivers`].
pub struct FlowDrivers<'d> {
    /// The model-node driver.
    pub model: &'d dyn ModelDriver,
    /// The tool-node driver.
    pub tool: &'d dyn ToolDriver,
    /// The verify-node driver (→ public `run_verify`).
    pub verify: &'d dyn VerifyDriver,
    /// The review-node driver (→ advisor).
    pub review: &'d dyn ReviewDriver,
}

// ---------------------------------------------------------------------------
// CI fakes — deterministic, no net/secrets/sandbox.
// ---------------------------------------------------------------------------

/// A deterministic, fully-scriptable driver bundle for CI. It performs no real I/O.
///
/// The verify path is the load-bearing one: a [`FakeDrivers`] verify can return only
/// [`VerifyOutcome::Failed`] or [`VerifyOutcome::Refused`] — **never** `Verified`,
/// because `VerifiedPatch` is type-sealed (no test backdoor to mint one). So CI proves
/// that the completion gate cannot be reached without the live `run_verify`.
pub struct FakeDrivers {
    /// Canned model output + cost.
    pub model_output: String,
    /// The cost each model node charges.
    pub model_cost: u64,
    /// Canned tool output.
    pub tool_output: String,
    /// Whether the tool driver errors (to exercise the driver-error path).
    pub tool_errors: bool,
    /// Canned review rationale.
    pub review_output: String,
    /// The verify outcome to return: `false` ⇒ `Refused`, `true` ⇒ `Failed`. (There is
    /// no `Verified` option — that requires the type-sealed `VerifiedPatch`.)
    pub verify_failed_not_refused: bool,
}

impl Default for FakeDrivers {
    fn default() -> Self {
        FakeDrivers {
            model_output: "advisory: proceed with the plan".to_string(),
            model_cost: 1,
            tool_output: "tool ok".to_string(),
            tool_errors: false,
            review_output: "review: looks fine".to_string(),
            verify_failed_not_refused: true,
        }
    }
}

impl FakeDrivers {
    /// A default fake bundle.
    #[must_use]
    pub fn new() -> Self {
        FakeDrivers::default()
    }

    /// Borrows this fake as a [`FlowDrivers`] bundle for the engine.
    #[must_use]
    pub fn as_bundle(&self) -> FlowDrivers<'_> {
        FlowDrivers {
            model: self,
            tool: self,
            verify: self,
            review: self,
        }
    }
}

impl ModelDriver for FakeDrivers {
    fn run_model(&self, _prompt: &str) -> Result<(String, u64), DriverError> {
        Ok((self.model_output.clone(), self.model_cost))
    }
}

impl ToolDriver for FakeDrivers {
    fn run_tool(&self, _inv: &ToolInvocation<'_>) -> Result<String, DriverError> {
        if self.tool_errors {
            Err(DriverError::new("fake tool error"))
        } else {
            Ok(self.tool_output.clone())
        }
    }
}

impl VerifyDriver for FakeDrivers {
    fn verify(&self) -> VerifyOutcome {
        // A fake CANNOT mint a Verified outcome (the seal). It can only model the two
        // non-completing outcomes.
        if self.verify_failed_not_refused {
            VerifyOutcome::Failed {
                status: crustcore_runner::ExitStatus::Code(1),
                output: crustcore_types::BoundedText::truncated("fake verify failed", 256),
            }
        } else {
            VerifyOutcome::Refused("fake: no sandbox backend".to_string())
        }
    }
}

impl ReviewDriver for FakeDrivers {
    fn review(&self) -> Result<String, DriverError> {
        Ok(self.review_output.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_verify_can_never_be_verified() {
        // The seal: a fake verify driver returns only Failed/Refused.
        let mut d = FakeDrivers::new();
        d.verify_failed_not_refused = true;
        assert!(matches!(d.verify(), VerifyOutcome::Failed { .. }));
        d.verify_failed_not_refused = false;
        assert!(matches!(d.verify(), VerifyOutcome::Refused(_)));
        // There is no code path here (or anywhere in this crate) that yields Verified.
    }

    #[test]
    fn fake_model_and_review_return_text_only() {
        let d = FakeDrivers::new();
        let (text, cost) = d.run_model("x").unwrap();
        assert!(!text.is_empty());
        assert_eq!(cost, 1);
        assert!(!d.review().unwrap().is_empty());
    }
}
