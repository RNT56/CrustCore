// SPDX-License-Identifier: Apache-2.0
//! Read-first views (`C7.3`–`C7.6`). Each view is a pure function over borrowed data
//! that produces a typed, redacted, bounded view model. No view mints, writes, appends a
//! frame, advances a budget, or reaches the verifier.

pub mod approvals;
/// Cockpit view (roadmap-v0.6 E.1): composes the read-model into a bounded task/evidence/
/// approval frame. Renders evidence + surfaces op-hash-bound approval forms — never
/// approves, completes, or integrates.
pub mod cockpit;
pub mod flow;
pub mod inspector;
pub mod mcp;
pub mod provider;
pub mod replay;
