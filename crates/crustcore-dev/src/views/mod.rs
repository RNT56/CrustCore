// SPDX-License-Identifier: Apache-2.0
//! Read-first views (`C7.3`–`C7.6`). Each view is a pure function over borrowed data
//! that produces a typed, redacted, bounded view model. No view mints, writes, appends a
//! frame, advances a budget, or reaches the verifier.

pub mod approvals;
pub mod flow;
pub mod inspector;
pub mod mcp;
pub mod provider;
pub mod replay;
