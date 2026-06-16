// SPDX-License-Identifier: Apache-2.0
//! Lightweight references shared by the policy and adapter layers: repository
//! refs, branch prefixes, and domain allowlists. These are plain value types so
//! that capability tokens (`crustcore-policy`) can name what they authorize
//! without depending on a heavy adapter crate.

use crate::text::BoundedText;

/// A reference to a repository (e.g. `owner/name`). Opaque to the kernel.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RepoRef(pub BoundedText);

/// A branch-name prefix an actor is allowed to create/push under
/// (e.g. `crustcore/`). Used by `GitHubWriteCap`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BranchPrefix(pub BoundedText);

/// An egress domain allowlist. Empty means **deny all** (NullClaw lesson:
/// `ROADMAP.md` §1.2; sandbox network posture is deny-by-default, invariant 9).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DomainAllowlist {
    domains: Vec<String>,
}

impl DomainAllowlist {
    /// An empty allowlist: denies all egress.
    #[must_use]
    pub fn deny_all() -> Self {
        Self {
            domains: Vec::new(),
        }
    }

    /// Builds an allowlist from explicit domains.
    #[must_use]
    pub fn from_domains(domains: Vec<String>) -> Self {
        Self { domains }
    }

    /// Returns true if `domain` is explicitly allowed. `*` is never implied;
    /// it must be an explicit entry (NullClaw lesson: `*` is opt-in, not default).
    #[must_use]
    pub fn allows(&self, domain: &str) -> bool {
        self.domains.iter().any(|d| d == domain || d == "*")
    }

    /// Returns true if nothing is allowed.
    #[must_use]
    pub fn is_deny_all(&self) -> bool {
        self.domains.is_empty()
    }
}
