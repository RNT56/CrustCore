// SPDX-License-Identifier: Apache-2.0
//! Capability tokens and approval tokens (`ROADMAP.md` §8.3–§8.4).
//!
//! These are the "authority objects" tools require. A tool signature like
//! `fn write_file(cap: &FsWriteCap, path: ConfinedWritePath<'_>, ...)` means it
//! is *impossible* to call without both a write capability and a confined path.

use crustcore_path::WorktreeRoot;
use crustcore_types::{
    ApprovalId, BranchPrefix, DomainAllowlist, RepoRef, Reversibility, ScopeId, Timestamp,
};

/// Authority to read files within a worktree root.
#[derive(Debug)]
pub struct FsReadCap {
    /// The worktree this capability is scoped to.
    pub root: WorktreeRoot,
    /// The policy scope that issued it.
    pub scope: ScopeId,
}

/// Authority to write files within a worktree root.
#[derive(Debug)]
pub struct FsWriteCap {
    /// The worktree this capability is scoped to.
    pub root: WorktreeRoot,
    /// The policy scope that issued it.
    pub scope: ScopeId,
}

/// Authority to make network egress to an allowlisted set of domains.
#[derive(Debug)]
pub struct NetworkCap {
    /// Allowed domains; empty means deny-all (invariant 9; NullClaw lesson).
    pub allowlist: DomainAllowlist,
    /// The policy scope that issued it.
    pub scope: ScopeId,
}

/// Authority to push/PR to a repository under a branch prefix.
#[derive(Debug)]
pub struct GitHubWriteCap {
    /// The repository this capability is scoped to.
    pub repo: RepoRef,
    /// The branch prefix writes are confined to (e.g. `crustcore/`).
    pub branch_prefix: BranchPrefix,
    /// The policy scope that issued it.
    pub scope: ScopeId,
}

/// Authority to execute commands under a specific sandbox profile.
#[derive(Debug)]
pub struct SandboxExecCap {
    /// Identifier of the sandbox profile to run under (see `crustcore-sandbox`).
    pub profile: ScopeId,
    /// The policy scope that issued it.
    pub scope: ScopeId,
}

/// A user authorized to grant approvals (e.g. an allowlisted Telegram chat).
/// The model is never an `AuthorizedUser` (invariant 4).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthorizedUser(pub u64);

/// Wraps a value (capability or action) together with the human approval that
/// unlocked it. Irreversible operations take `Approved<T>`, never bare `T`
/// (invariant 14). Only the approval engine constructs this; there is no path
/// from model output to an `Approved<T>`.
#[derive(Debug)]
pub struct Approved<T> {
    /// The approved value.
    pub value: T,
    /// The approval that authorized it.
    pub approval_id: ApprovalId,
    /// Who approved it.
    pub approved_by: AuthorizedUser,
    /// When the approval expires.
    pub expires_at: Timestamp,
}

impl<T> Approved<T> {
    /// Constructed by the approval engine only. TODO(P1.5/P8): make this
    /// `pub(crate)` to the approval engine and route minting through it.
    #[doc(hidden)]
    #[must_use]
    pub fn new(
        value: T,
        approval_id: ApprovalId,
        approved_by: AuthorizedUser,
        expires_at: Timestamp,
    ) -> Self {
        Approved {
            value,
            approval_id,
            approved_by,
            expires_at,
        }
    }

    /// Whether the approval is still valid at `now`.
    #[must_use]
    pub fn is_valid_at(&self, now: Timestamp) -> bool {
        now <= self.expires_at
    }
}

/// Marker for an irreversible action that must be wrapped in [`Approved`] before
/// it can be emitted. The reversibility classification comes from the risk
/// engine ([`super::decision`]).
#[derive(Debug)]
pub struct IrreversibleAction {
    /// A short description of the action (for the approval prompt).
    pub summary: crustcore_types::BoundedText,
    /// How irreversible it is.
    pub reversibility: Reversibility,
}
