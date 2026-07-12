// SPDX-License-Identifier: Apache-2.0
//! Policy decisions (`ROADMAP.md` §9). **CONTRACT FILE** — changes are
//! serialized and reviewed (CLAUDE.md §7.3).
//!
//! Every side effect passes through policy (invariant 8). The kernel holds a
//! [`PolicySnapshot`] and asks it to classify a proposed action into a
//! [`PolicyDecision`]; the kernel never performs the side effect itself.

use crustcore_types::{Reversibility, ScopeId};

use crate::caps::CapabilityIssuer;

/// A coding-adapted risk profile (`ROADMAP.md` §1.3 ZeroClaw lesson, adapted).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RiskProfile {
    /// No side effects: plan, review, summarize.
    ReadOnly,
    /// Reversible side effects run; irreversible ones gate on approval.
    #[default]
    Supervised,
    /// Broad autonomy within budget (still: irreversible ⇒ approval).
    Full,
}

/// The outcome of evaluating a proposed action against policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// The action may proceed now.
    Allow,
    /// The action is denied outright.
    Deny {
        /// Human-readable reason (non-sensitive).
        reason: String,
    },
    /// The action requires an approval token before it may be emitted
    /// (invariant 14).
    RequireApproval {
        /// Why approval is needed.
        reason: String,
    },
}

/// An immutable snapshot of policy the kernel evaluates against. Kept as a value
/// the kernel owns so `Kernel::step` stays deterministic and side-effect free.
#[derive(Debug, Clone)]
pub struct PolicySnapshot {
    /// The active risk profile.
    pub profile: RiskProfile,
}

impl PolicySnapshot {
    /// Constructs a snapshot for a given profile.
    #[must_use]
    pub fn new(profile: RiskProfile) -> Self {
        PolicySnapshot { profile }
    }

    /// Classifies a proposed action by its reversibility under the current
    /// profile. This is the core "every side effect passes through policy"
    /// chokepoint (invariant 8).
    ///
    /// Budget state and approval request/resolution are implemented in the kernel; the
    /// remaining policy extension is capability checks, taint, and per-operation
    /// deny/ask defaults (`docs/policy.md`, `docs/github.md`).
    #[must_use]
    pub fn classify(&self, reversibility: Reversibility) -> PolicyDecision {
        match self.profile {
            RiskProfile::ReadOnly => PolicyDecision::Deny {
                reason: "read-only profile forbids side effects".to_string(),
            },
            RiskProfile::Supervised | RiskProfile::Full => {
                if reversibility.requires_approval() {
                    PolicyDecision::RequireApproval {
                        reason: "irreversible action requires an approval token".to_string(),
                    }
                } else {
                    PolicyDecision::Allow
                }
            }
        }
    }

    /// Produces a capability issuer only when this policy explicitly allows a
    /// reversible side effect. Read-only policy and approval-requiring actions
    /// return their original decision and mint no authority.
    pub fn authorize_reversible(&self, scope: ScopeId) -> Result<CapabilityIssuer, PolicyDecision> {
        match self.classify(Reversibility::Reversible) {
            PolicyDecision::Allow => Ok(CapabilityIssuer { scope }),
            other => Err(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readonly_denies_all_side_effects() {
        let p = PolicySnapshot::new(RiskProfile::ReadOnly);
        assert!(matches!(
            p.classify(Reversibility::Reversible),
            PolicyDecision::Deny { .. }
        ));
    }

    #[test]
    fn supervised_allows_reversible_gates_irreversible() {
        let p = PolicySnapshot::new(RiskProfile::Supervised);
        assert_eq!(p.classify(Reversibility::Reversible), PolicyDecision::Allow);
        assert!(matches!(
            p.classify(Reversibility::Irreversible),
            PolicyDecision::RequireApproval { .. }
        ));
    }

    #[test]
    fn only_allowing_policy_can_mint_a_capability_issuer() {
        let readonly = PolicySnapshot::new(RiskProfile::ReadOnly);
        assert!(readonly.authorize_reversible(ScopeId(1)).is_err());
        let supervised = PolicySnapshot::new(RiskProfile::Supervised);
        let issuer = supervised
            .authorize_reversible(ScopeId(7))
            .expect("supervised reversible authority");
        assert_eq!(issuer.sandbox_exec(ScopeId(3)).scope(), ScopeId(7));
    }
}
