// SPDX-License-Identifier: Apache-2.0
//! The one backend contract (`ROADMAP.md` §7.5; Phase 5/6).
//!
//! Native agent, Codex CLI, Claude Code, and any future worker all return the
//! same [`BackendResult`]. Crucially, a result is **unverified** until CrustCore
//! reruns the verifier in a clean sandbox and produces a [`VerifiedPatch`]. Only
//! a `VerifiedPatch` may integrate, complete, or open a PR (invariant 13).
//! `self_claimed_done` is advisory metadata, never authority (invariant 6).
//!
//! The type split is the enforcement: there is **no** `From<UnverifiedPatch> for
//! VerifiedPatch`. The only constructor of `VerifiedPatch` is the verifier
//! (`docs/backend-contract.md`).
#![forbid(unsafe_code)]

use crustcore_receipts::ToolReceipt;
use crustcore_types::{BoundedText, Timestamp};

/// Which backend produced a result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BackendKind {
    /// The native in-process implementer.
    Native,
    /// Codex CLI (external worker).
    Codex,
    /// Claude Code (external worker).
    ClaudeCode,
    /// A generic external command worker.
    ExternalCommand,
}

/// A reference to a patch (e.g. a content-addressed diff artifact).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchRef {
    /// Content hash of the diff.
    pub diff_hash: [u8; 32],
}

/// A risk flagged by a backend (treated as an untrusted claim).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Risk {
    /// Short description of the risk.
    pub summary: BoundedText,
}

/// A record of a command a backend claims to have run (untrusted until
/// re-derived from the worktree/transcript).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandRecord {
    /// The command line as reported.
    pub command: BoundedText,
}

/// What a backend returns. Everything here is an **untrusted claim** until the
/// supervisor re-derives the diff and reruns the verifier.
#[derive(Debug, Clone)]
pub struct BackendResult {
    /// Which backend produced this.
    pub backend: BackendKind,
    /// A bounded summary of what was done.
    pub summary: BoundedText,
    /// The proposed patch, if any.
    pub patch: Option<PatchRef>,
    /// The backend's own claim that it is done — advisory only (invariant 6).
    pub self_claimed_done: bool,
    /// Commands the backend claims to have run.
    pub commands_run: Vec<CommandRecord>,
    /// Risks the backend flagged.
    pub risks: Vec<Risk>,
}

/// A patch that has **not** been verified. Cannot integrate or complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnverifiedPatch(pub PatchRef);

/// Evidence that a verifier command passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandEvidence {
    /// The verifier command that ran.
    pub command: BoundedText,
    /// Whether it succeeded.
    pub passed: bool,
}

/// A patch the verifier has confirmed in a clean sandbox. **Only** the verifier
/// constructs this (no `From<UnverifiedPatch>`); it is the only thing that may
/// integrate, complete, or open a PR (invariant 13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPatch {
    patch: PatchRef,
    verifier: BoundedText,
    commands: Vec<CommandEvidence>,
    passed_at: Timestamp,
    receipt: ToolReceipt,
}

impl VerifiedPatch {
    /// Constructed by the verifier only.
    ///
    /// TODO(P5.4): make this callable solely from the verify loop (a sealed
    /// constructor / module-private token) so no other code can forge a
    /// `VerifiedPatch`. The doc-hidden marker signals intent for the scaffold.
    #[doc(hidden)]
    #[must_use]
    pub fn from_verifier(
        patch: PatchRef,
        verifier: BoundedText,
        commands: Vec<CommandEvidence>,
        passed_at: Timestamp,
        receipt: ToolReceipt,
    ) -> Self {
        VerifiedPatch {
            patch,
            verifier,
            commands,
            passed_at,
            receipt,
        }
    }

    /// The verified patch reference.
    #[must_use]
    pub fn patch(&self) -> &PatchRef {
        &self.patch
    }

    /// The verifier that produced the evidence.
    #[must_use]
    pub fn verifier(&self) -> &BoundedText {
        &self.verifier
    }

    /// The verifier command evidence.
    #[must_use]
    pub fn commands(&self) -> &[CommandEvidence] {
        &self.commands
    }

    /// When verification passed.
    #[must_use]
    pub fn passed_at(&self) -> Timestamp {
        self.passed_at
    }

    /// The receipt tying verification to the event log.
    #[must_use]
    pub fn receipt(&self) -> &ToolReceipt {
        &self.receipt
    }
}
