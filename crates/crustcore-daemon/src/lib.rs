// SPDX-License-Identifier: Apache-2.0
//! Long-running runtime (`ROADMAP.md` §2.3; Phase 9/10).
//!
//! Hosts the Telegram runtime channel, the GitHub task/PR loop, the admin
//! socket, and task supervision (leases, heartbeats, recovery). It drives the
//! kernel by feeding it events and executing the actions it emits
//! (`docs/telegram.md`, `docs/github.md`, `docs/maintainer-agent.md`).
//!
//! Status: the **Telegram runtime channel** logic ([`telegram`]) is implemented
//! (Phase 9: allowlist, dedupe, normalization, commands, queue/steer, nonce
//! approvals, typed redacted outbound). The Bot API HTTP long-polling/send
//! (`TODO(P9-net)`), the GitHub loop, and supervision land in later phases.
#![forbid(unsafe_code)]

pub mod github;
pub mod telegram;

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
