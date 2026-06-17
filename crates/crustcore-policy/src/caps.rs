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
/// The model is never an `AuthorizedUser` (invariant 4). Instances exist only
/// where the runtime binds an authorized identity at setup; model/worker output
/// never becomes one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuthorizedUser(pub u64);

impl AuthorizedUser {
    /// Mints an [`Approved`] token for `value`. This is the **only** public path
    /// to an `Approved<T>`, and it structurally requires an `AuthorizedUser`
    /// (`&self`): there is no path from model/worker output to this call
    /// (invariant 4 — the model cannot approve its own side effects). The kernel
    /// never invokes this from event payloads; it flips an internal approval
    /// status after an `Actor::User` resolution and the runtime mints the token.
    #[must_use]
    pub fn approve<T>(
        &self,
        value: T,
        approval_id: ApprovalId,
        expires_at: Timestamp,
    ) -> Approved<T> {
        Approved::new(value, approval_id, *self, expires_at)
    }
}

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
    /// Constructed by the approval engine only. Crate-private so the **only** way
    /// to obtain an `Approved<T>` is [`AuthorizedUser::approve`] — there is no
    /// constructor reachable from model-derived data (invariant 4).
    #[must_use]
    pub(crate) fn new(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crustcore_types::ApprovalId;

    #[test]
    fn authorized_user_is_the_only_mint_path() {
        let user = AuthorizedUser(7);
        let approved = user.approve(42u32, ApprovalId(1), Timestamp::from_millis(1_000));
        assert_eq!(approved.value, 42);
        assert_eq!(approved.approved_by, user);
        assert_eq!(approved.approval_id, ApprovalId(1));
    }

    #[test]
    fn approval_validity_respects_expiry() {
        let user = AuthorizedUser(7);
        let approved = user.approve((), ApprovalId(1), Timestamp::from_millis(1_000));
        assert!(approved.is_valid_at(Timestamp::from_millis(1_000)));
        assert!(approved.is_valid_at(Timestamp::from_millis(999)));
        assert!(!approved.is_valid_at(Timestamp::from_millis(1_001)));
    }
}
