// SPDX-License-Identifier: Apache-2.0
//! Shared primitive types for CrustCore: compact IDs, task/job status enums,
//! reversibility, and bounded text/time wrappers.
//!
//! This crate has **no heavy dependencies** (std only) and is depended on by the
//! kernel and every adapter, so it must stay tiny. See
//! [`docs/architecture.md`](../../../docs/architecture.md) and the data model in
//! `ROADMAP.md` §7.
//!
//! Status: Phase 0 scaffold. The types here are real and stable enough to build
//! on; behavior (transition rules, encoding) is implemented in later phases and
//! marked with `TODO(Pn)`.
#![forbid(unsafe_code)]

pub mod budget;
pub mod hash;
pub mod ids;
pub mod refs;
pub mod status;
pub mod text;
pub mod time;

pub use budget::{Budget, BudgetAxis, BudgetCheck, BudgetDelta, Meter, BUDGET_AXIS_COUNT};
pub use hash::{hmac_sha256, sha256};
pub use ids::{
    ApprovalId, ArtifactId, CapabilityId, EventSeq, JobId, LeaseOwner, ScopeId, SecretId, TaskId,
    ToolCallId,
};
pub use refs::{BranchPrefix, DomainAllowlist, RepoRef};
pub use status::{ApprovalResolution, ApprovalStatus, JobStatus, Reversibility, TaskStatus};
pub use text::{BoundedText, BoundedTextError};
pub use time::Timestamp;
