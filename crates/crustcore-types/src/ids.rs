// SPDX-License-Identifier: Apache-2.0
//! Compact identifier newtypes (`ROADMAP.md` §7.1).
//!
//! Nano uses compact integer/array IDs; a UUID crate is optional outside nano.
//! Keeping these as plain newtypes (no external crate) keeps the kernel and the
//! nano build dependency-free.

/// Identifies a task (a unit of user-requested work).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TaskId(pub u128);

/// Identifies a job (a single execution attempt under a task).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct JobId(pub u128);

/// Monotonic sequence number of an event in the append-only log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EventSeq(pub u64);

/// Identifies an approval request/grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ApprovalId(pub u128);

/// Identifies a single tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ToolCallId(pub u128);

/// Content address of an artifact (e.g. BLAKE3/SHA-256 of its bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ArtifactId(pub [u8; 32]);

/// Handle id for a stored secret (the model only ever sees this, never bytes).
///
/// See [`crustcore-secrets`](../../../crustcore-secrets/src/lib.rs) and
/// invariants 1–3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SecretId(pub u32);

/// Identifies a capability grant (a typed authority object).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CapabilityId(pub u32);

/// Identifies a policy/authority scope (e.g. one task's filesystem scope).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ScopeId(pub u64);

/// Identifies the holder of a job lease (invariant 12). The lease owner is the
/// adapter/worker that currently drives a job; an event from a non-owner is
/// treated as stale (`crustcore-kernel`, `docs/architecture.md` §2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LeaseOwner(pub u64);

impl EventSeq {
    /// The first valid sequence number. Also used as the "unsequenced" sentinel
    /// for kernel-internal events (see `crustcore-kernel`'s idempotency frontier).
    pub const FIRST: EventSeq = EventSeq(0);

    /// Returns the next sequence number.
    ///
    /// # Panics
    /// Panics in debug builds on overflow at `u64::MAX`. Prefer
    /// [`EventSeq::next_saturating`] on any path that processes untrusted/external
    /// sequence numbers.
    #[must_use]
    pub const fn next(self) -> EventSeq {
        EventSeq(self.0 + 1)
    }

    /// Returns the next sequence number, saturating at `u64::MAX` instead of
    /// overflowing. This is the no-panic path the kernel uses so a hostile event
    /// seq near `u64::MAX` can never panic (`docs/architecture.md` §2.3).
    #[must_use]
    pub const fn next_saturating(self) -> EventSeq {
        EventSeq(self.0.saturating_add(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_saturating_does_not_overflow_at_max() {
        assert_eq!(EventSeq::FIRST.next_saturating(), EventSeq(1));
        assert_eq!(EventSeq(u64::MAX).next_saturating(), EventSeq(u64::MAX));
        assert_eq!(EventSeq(u64::MAX - 1).next_saturating(), EventSeq(u64::MAX));
    }
}
