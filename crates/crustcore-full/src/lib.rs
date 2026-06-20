// SPDX-License-Identifier: Apache-2.0
//! Convenience all-in-one composition (`ROADMAP.md` §2.6).
//!
//! `crustcore-full` links every tier together for users who want one binary with
//! everything. It is useful but is **never** the flagship size claim — that
//! belongs to `crustcore-nano` (`docs/nano-size-budget.md`). Nothing linked here
//! may ever leak back into nano (invariants 19/20).
//!
//! Status: implemented. Re-exports every tier crate's facade (kernel through
//! index) behind one entry point; the heavy tiers stay feature-gated upstream so
//! nano never links them.
#![forbid(unsafe_code)]

pub use crustcore_backend as backend;
pub use crustcore_daemon as daemon;
pub use crustcore_eventlog as eventlog;
pub use crustcore_index as index;
pub use crustcore_kernel as kernel;
pub use crustcore_mcp as mcp;
pub use crustcore_net as net;
pub use crustcore_path as path;
pub use crustcore_policy as policy;
pub use crustcore_receipts as receipts;
pub use crustcore_runner as runner;
pub use crustcore_sandbox as sandbox;
pub use crustcore_secrets as secrets;
pub use crustcore_types as types;
pub use crustcore_worktree as worktree;

/// The CrustCore version this composition was built from.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
