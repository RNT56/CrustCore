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

impl EventSeq {
    /// The first valid sequence number.
    pub const FIRST: EventSeq = EventSeq(0);

    /// Returns the next sequence number.
    #[must_use]
    pub const fn next(self) -> EventSeq {
        EventSeq(self.0 + 1)
    }
}
