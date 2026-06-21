// SPDX-License-Identifier: Apache-2.0
//! Live drivers (C3.7) — behind the `live-flow` feature; **never linked in CI**.
//!
//! These wrap the real transports the engine's seams abstract over. The engine itself
//! is identical to the CI path; only the injected driver changes. Every integration
//! test exercising these is `#[ignore]`d and runs out-of-band against a real net
//! helper, a real sandbox (bubblewrap), and the public `run_verify`.
//!
//! The trust posture is the same as the fakes — and the seal does the work:
//! - [`LiveVerifyDriver`] is the **only** driver that can yield a `Verified` outcome,
//!   because it calls the public `crustcore_backend::verify::run_verify` (the sole
//!   `VerifiedPatch` minter, invariant 13). Nothing else in this crate mints one.
//! - [`LiveModelDriver`] wraps a model call (e.g. through `run_subagent` / the net
//!   helper); its output is untrusted and the engine redacts it (invariant 7).
//! - [`LiveToolDriver`] runs only after the engine's policy + approval gate, and runs
//!   execution-capable tools under a sandbox profile (invariants 8, 9).
//! - [`LiveReviewDriver`] wraps a `crustcore_daemon::advisor::Advisor` (e.g.
//!   `NativeAdvisor`); its note is advisory only (invariants 4, 5, 6).

use crustcore_backend::verify::{run_verify, VerifyIds, VerifyOutcome, VerifySpec};
use crustcore_backend::PatchRef;
use crustcore_daemon::advisor::{Advisor, Consultation};
use crustcore_path::WorktreeRoot;
use crustcore_policy::SandboxExecCap;
use crustcore_receipts::ReceiptChain;
use crustcore_sandbox::SandboxProfile;

use crate::drivers::{DriverError, ModelDriver, ReviewDriver, ToolDriver, ToolInvocation};

/// A live model driver: routes the prompt through an injected closure that calls the
/// model (in practice the spawned `crustcore-net` helper / `run_subagent` in the
/// advisor role — `docs/model-routing.md`). The output is untrusted; the engine
/// redacts + bounds it (invariant 7).
pub struct LiveModelDriver<F> {
    consult: F,
}

impl<F> LiveModelDriver<F> {
    /// Builds a live model driver over a consult closure returning `(text, cost)`.
    pub fn new(consult: F) -> Self {
        LiveModelDriver { consult }
    }
}

impl<F> ModelDriver for LiveModelDriver<F>
where
    F: Fn(&str) -> Result<(String, u64), String>,
{
    fn run_model(&self, prompt: &str) -> Result<(String, u64), DriverError> {
        (self.consult)(prompt).map_err(DriverError::new)
    }
}

/// A live tool driver: runs the tool through an injected closure. The engine has
/// already classified the tool through `crustcore-policy` and checked any required
/// approval before calling this (invariants 8, 14); a real impl runs an
/// execution-capable tool under a sandbox profile (invariant 9). The closure receives
/// the classified spec so it can choose the sandbox posture from `execution_capable`.
pub struct LiveToolDriver<F> {
    run: F,
}

impl<F> LiveToolDriver<F> {
    /// Builds a live tool driver over a run closure.
    pub fn new(run: F) -> Self {
        LiveToolDriver { run }
    }
}

impl<F> ToolDriver for LiveToolDriver<F>
where
    F: Fn(&ToolInvocation<'_>) -> Result<String, String>,
{
    fn run_tool(&self, inv: &ToolInvocation<'_>) -> Result<String, DriverError> {
        (self.run)(inv).map_err(DriverError::new)
    }
}

/// A live verify driver: calls the public `crustcore_backend::verify::run_verify` —
/// the **sole** `VerifiedPatch` minter (invariant 13). This is the only driver in the
/// whole crate that can produce a `Verified` outcome, and it can do so only because it
/// goes through the real, sandboxed verify loop. It owns the inputs `run_verify`
/// needs; the engine just calls [`VerifyDriver::verify`](crate::drivers::VerifyDriver).
pub struct LiveVerifyDriver<'v> {
    cap: &'v SandboxExecCap,
    profile: &'v SandboxProfile,
    worktree: &'v WorktreeRoot,
    spec: &'v VerifySpec,
    patch: PatchRef,
    receipts: std::cell::RefCell<&'v mut ReceiptChain>,
    ids: &'v VerifyIds,
}

impl<'v> LiveVerifyDriver<'v> {
    /// Builds a live verify driver over everything `run_verify` needs.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cap: &'v SandboxExecCap,
        profile: &'v SandboxProfile,
        worktree: &'v WorktreeRoot,
        spec: &'v VerifySpec,
        patch: PatchRef,
        receipts: &'v mut ReceiptChain,
        ids: &'v VerifyIds,
    ) -> Self {
        LiveVerifyDriver {
            cap,
            profile,
            worktree,
            spec,
            patch,
            receipts: std::cell::RefCell::new(receipts),
            ids,
        }
    }
}

impl crate::drivers::VerifyDriver for LiveVerifyDriver<'_> {
    fn verify(&self) -> VerifyOutcome {
        let mut receipts = self.receipts.borrow_mut();
        run_verify(
            self.cap,
            self.profile,
            self.worktree,
            self.spec,
            self.patch.clone(),
            &mut receipts,
            self.ids,
        )
    }
}

/// A live review driver: wraps a `crustcore_daemon::advisor::Advisor` (e.g.
/// `NativeAdvisor`). The advisor note is advisory only — there is no path from it to
/// an `Approved<T>` or the user (invariants 4, 5, 6); this driver returns its
/// (already-redacted-by-the-advisor) rationale as plain text, which the engine
/// re-redacts + bounds.
pub struct LiveReviewDriver<'a, A: Advisor> {
    advisor: &'a A,
    consultation: Consultation,
}

impl<'a, A: Advisor> LiveReviewDriver<'a, A> {
    /// Builds a live review driver over an advisor and the fixed consultation it
    /// answers for this node.
    pub fn new(advisor: &'a A, consultation: Consultation) -> Self {
        LiveReviewDriver {
            advisor,
            consultation,
        }
    }
}

impl<A: Advisor> ReviewDriver for LiveReviewDriver<'_, A> {
    fn review(&self) -> Result<String, DriverError> {
        let note = self.advisor.consult(&self.consultation);
        Ok(note.rationale.as_str().to_string())
    }
}
