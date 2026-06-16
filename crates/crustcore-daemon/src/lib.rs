// SPDX-License-Identifier: Apache-2.0
//! Long-running runtime (`ROADMAP.md` §2.3; Phase 9/10).
//!
//! Hosts the Telegram runtime channel, the GitHub task/PR loop, the admin
//! socket, and task supervision (leases, heartbeats, recovery). It drives the
//! kernel by feeding it events and executing the actions it emits
//! (`docs/telegram.md`, `docs/github.md`, `docs/maintainer-agent.md`).
//!
//! Status: Phase 0 scaffold (std only). The supervised event loop lands in
//! Phase 9/10 (`TODO(P9.*/P10.*)`).
#![forbid(unsafe_code)]

/// Surfaces the daemon supervises. Marker enum so the crate is real.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonSurface {
    /// The Telegram runtime channel (default human channel; invariant 15).
    Telegram,
    /// The GitHub task/PR control plane.
    GitHub,
    /// The authenticated local/remote admin socket.
    AdminSocket,
}
