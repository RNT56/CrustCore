// SPDX-License-Identifier: Apache-2.0
//! Convenience all-in-one composition (`ROADMAP.md` §2.6).
//!
//! `crustcore-full` links every tier together for users who want one binary with
//! everything. It is useful but is **never** the flagship size claim — that
//! belongs to `crustcore-nano` (`docs/nano-size-budget.md`). Nothing linked here
//! may ever leak back into nano (invariants 19/20).
//!
//! Status: implemented. Re-exports every tier crate's facade — the trusted core, the
//! capability packs (net/daemon/mcp/index), the Track C ergonomics packs
//! (index-rag/telemetry/session/flow/dev/toolkit), and the chat front door — behind one
//! entry point. The heavy capabilities stay feature-gated upstream so nano never links
//! them; the **`all`** feature turns the whole capability matrix on at once.
#![forbid(unsafe_code)]

pub use crustcore_backend as backend;
pub use crustcore_chat as chat;
pub use crustcore_daemon as daemon;
pub use crustcore_dev as dev;
pub use crustcore_eventlog as eventlog;
pub use crustcore_flow as flow;
pub use crustcore_index as index;
pub use crustcore_index_rag as index_rag;
pub use crustcore_kernel as kernel;
pub use crustcore_mcp as mcp;
pub use crustcore_net as net;
pub use crustcore_path as path;
pub use crustcore_policy as policy;
pub use crustcore_receipts as receipts;
pub use crustcore_runner as runner;
pub use crustcore_sandbox as sandbox;
pub use crustcore_secrets as secrets;
pub use crustcore_session as session;
pub use crustcore_telemetry as telemetry;
pub use crustcore_toolkit as toolkit;
pub use crustcore_types as types;
pub use crustcore_worktree as worktree;

/// The CrustCore version this composition was built from.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
