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
    root: WorktreeRoot,
    /// The policy scope that issued it.
    scope: ScopeId,
}

/// Authority to write files within a worktree root.
#[derive(Debug)]
pub struct FsWriteCap {
    /// The worktree this capability is scoped to.
    root: WorktreeRoot,
    /// The policy scope that issued it.
    scope: ScopeId,
}

/// Authority to make network egress to an allowlisted set of domains.
#[derive(Debug)]
pub struct NetworkCap {
    /// Allowed domains; empty means deny-all (invariant 9; NullClaw lesson).
    allowlist: DomainAllowlist,
    /// The policy scope that issued it.
    scope: ScopeId,
}

/// Authority to push/PR to a repository under a branch prefix.
#[derive(Debug)]
pub struct GitHubWriteCap {
    /// The repository this capability is scoped to.
    repo: RepoRef,
    /// The branch prefix writes are confined to (e.g. `crustcore/`).
    branch_prefix: BranchPrefix,
    /// The policy scope that issued it.
    scope: ScopeId,
}

/// Authority to execute commands under a specific sandbox profile.
#[derive(Debug)]
pub struct SandboxExecCap {
    /// Identifier of the sandbox profile to run under (see `crustcore-sandbox`).
    profile: ScopeId,
    /// The policy scope that issued it.
    scope: ScopeId,
}

/// Policy-authorized capability factory. Its fields are private and it can only
/// be created by [`crate::PolicySnapshot::authorize_reversible`], so capability
/// structs are no longer forgeable with public literals in downstream crates.
#[derive(Debug)]
pub struct CapabilityIssuer {
    pub(crate) scope: ScopeId,
}

impl CapabilityIssuer {
    #[must_use]
    pub fn fs_read(&self, root: WorktreeRoot) -> FsReadCap {
        FsReadCap {
            root,
            scope: self.scope,
        }
    }

    #[must_use]
    pub fn fs_write(&self, root: WorktreeRoot) -> FsWriteCap {
        FsWriteCap {
            root,
            scope: self.scope,
        }
    }

    #[must_use]
    pub fn network(&self, allowlist: DomainAllowlist) -> NetworkCap {
        NetworkCap {
            allowlist,
            scope: self.scope,
        }
    }

    #[must_use]
    pub fn sandbox_exec(&self, profile: ScopeId) -> SandboxExecCap {
        SandboxExecCap {
            profile,
            scope: self.scope,
        }
    }
}

impl FsReadCap {
    #[must_use]
    pub fn root(&self) -> &WorktreeRoot {
        &self.root
    }

    #[must_use]
    pub fn scope(&self) -> ScopeId {
        self.scope
    }
}

impl FsWriteCap {
    #[must_use]
    pub fn root(&self) -> &WorktreeRoot {
        &self.root
    }

    #[must_use]
    pub fn scope(&self) -> ScopeId {
        self.scope
    }
}

impl NetworkCap {
    #[must_use]
    pub fn allowlist(&self) -> &DomainAllowlist {
        &self.allowlist
    }

    #[must_use]
    pub fn scope(&self) -> ScopeId {
        self.scope
    }
}

impl GitHubWriteCap {
    #[must_use]
    pub fn repo(&self) -> &RepoRef {
        &self.repo
    }

    #[must_use]
    pub fn branch_prefix(&self) -> &BranchPrefix {
        &self.branch_prefix
    }

    #[must_use]
    pub fn scope(&self) -> ScopeId {
        self.scope
    }
}

impl SandboxExecCap {
    #[must_use]
    pub fn profile(&self) -> ScopeId {
        self.profile
    }

    #[must_use]
    pub fn scope(&self) -> ScopeId {
        self.scope
    }
}

/// A user authorized to grant approvals (e.g. an allowlisted Telegram chat).
/// The model is never an `AuthorizedUser` (invariant 4). The inner id is **private**
/// so an `AuthorizedUser` can be minted only through [`AuthorizedUser::bind`] — there
/// is no struct-literal / tuple-field path by which model/worker/comment data could
/// become one (mirrors the seal on `VerifiedPatch`). Since `AuthorizedUser` is required
/// to call [`AuthorizedUser::approve`] (the only mint path for an [`Approved`]), this seal
/// transitively protects invariants 4 and 14.
///
/// The seal is enforced by the type system — a tuple-struct literal does not compile:
/// ```compile_fail
/// // error[E0603]: tuple struct constructor `AuthorizedUser` is private
/// let _forged = crustcore_policy::AuthorizedUser(42);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AuthorizedUser(u64);

impl AuthorizedUser {
    /// Binds a runtime-authorized identity (e.g. the numeric id of an allowlisted
    /// Telegram chat resolved by `ChatAllowlist`). Call this **only** at the trusted
    /// setup boundary where an authorized identity is established — never from
    /// model/worker output or an untrusted comment author id (invariant 4). It is a
    /// named, greppable mint path so every `AuthorizedUser` is auditable.
    #[must_use]
    pub fn bind(id: u64) -> Self {
        AuthorizedUser(id)
    }

    /// The bound identity id (for audit/equality).
    #[must_use]
    pub fn id(self) -> u64 {
        self.0
    }

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

    /// Issues the two GitHub write grants needed by trusted onboarding: one
    /// registry capability for push validation and one approval-wrapped
    /// capability for the irreversible draft-PR action. Constructing both here
    /// keeps raw `GitHubWriteCap` minting inside the policy crate.
    #[must_use]
    pub fn approve_github_write(
        &self,
        repo: RepoRef,
        branch_prefix: BranchPrefix,
        scope: ScopeId,
        approval_id: ApprovalId,
        expires_at: Timestamp,
    ) -> (GitHubWriteCap, Approved<GitHubWriteCap>) {
        let registry = GitHubWriteCap {
            repo: RepoRef(repo.0.clone()),
            branch_prefix: BranchPrefix(branch_prefix.0.clone()),
            scope,
        };
        let approved = self.approve(
            GitHubWriteCap {
                repo,
                branch_prefix,
                scope,
            },
            approval_id,
            expires_at,
        );
        (registry, approved)
    }
}

/// Wraps a value (capability or action) together with the human approval that
/// unlocked it. Irreversible operations take `Approved<T>`, never bare `T`
/// (invariant 14). The fields are **private** so the only way to obtain one is
/// [`AuthorizedUser::approve`] — there is no struct-literal path from model/worker
/// output to an `Approved<T>` (mirrors the seal on `VerifiedPatch`; read via the
/// accessors below).
#[derive(Debug)]
pub struct Approved<T> {
    value: T,
    approval_id: ApprovalId,
    approved_by: AuthorizedUser,
    expires_at: Timestamp,
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

    /// The approved value.
    #[must_use]
    pub fn value(&self) -> &T {
        &self.value
    }

    /// The approval that authorized it.
    #[must_use]
    pub fn approval_id(&self) -> ApprovalId {
        self.approval_id
    }

    /// Who approved it.
    #[must_use]
    pub fn approved_by(&self) -> AuthorizedUser {
        self.approved_by
    }

    /// When the approval expires.
    #[must_use]
    pub fn expires_at(&self) -> Timestamp {
        self.expires_at
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
        let user = AuthorizedUser::bind(7);
        let approved = user.approve(42u32, ApprovalId(1), Timestamp::from_millis(1_000));
        assert_eq!(approved.value, 42);
        assert_eq!(approved.approved_by, user);
        assert_eq!(approved.approval_id, ApprovalId(1));
    }

    #[test]
    fn approval_validity_respects_expiry() {
        let user = AuthorizedUser::bind(7);
        let approved = user.approve((), ApprovalId(1), Timestamp::from_millis(1_000));
        assert!(approved.is_valid_at(Timestamp::from_millis(1_000)));
        assert!(approved.is_valid_at(Timestamp::from_millis(999)));
        assert!(!approved.is_valid_at(Timestamp::from_millis(1_001)));
    }
}
