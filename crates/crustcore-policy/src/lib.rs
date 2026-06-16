// SPDX-License-Identifier: Apache-2.0
//! Risk/capability/approval engine (`ROADMAP.md` §8.3–§8.4, §9; Phase 1+).
//!
//! Two ideas drive this crate:
//!
//! 1. **Pass authority objects, not booleans.** Tools take typed capability
//!    tokens ([`caps`]) — `FsWriteCap`, `SandboxExecCap`, … — never a bare
//!    `can_write: bool`. A capability names exactly what it authorizes.
//! 2. **Irreversible actions need an approval token.** [`caps::Approved<T>`]
//!    wraps a capability/action with the approval that unlocked it (invariant
//!    14). The model can never mint one (invariant 4).
//!
//! See [`docs/policy.md`](../../../docs/policy.md). The decision evaluator lives
//! in [`decision`] (a contract file).
#![forbid(unsafe_code)]

pub mod caps;
pub mod decision;

pub use caps::{
    Approved, AuthorizedUser, FsReadCap, FsWriteCap, GitHubWriteCap, NetworkCap, SandboxExecCap,
};
pub use decision::{PolicyDecision, PolicySnapshot, RiskProfile};
