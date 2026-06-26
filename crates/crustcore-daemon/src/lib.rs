// SPDX-License-Identifier: Apache-2.0
//! Long-running runtime (`ROADMAP.md` §2.3; Phase 9/10).
//!
//! Hosts the Telegram runtime channel, the GitHub task/PR loop, the admin
//! socket, and task supervision (leases, heartbeats, recovery). It drives the
//! kernel by feeding it events and executing the actions it emits
//! (`docs/telegram.md`, `docs/github.md`, `docs/maintainer-agent.md`).
//!
//! Status: the **Telegram runtime channel** logic ([`telegram`]), the **subagent
//! execution control plane** ([`exec`], P11-exec: scheduler/budget/blackboard/no-user/
//! verifier-owned acceptance over a [`SubagentExecutor`](crate::exec::SubagentExecutor)
//! trait), the **model-backed advisor** ([`advisor`], P12-native:
//! [`NativeAdvisor`](crate::advisor::NativeAdvisor) over an injected consult fn,
//! advisory-not-policy preserved, untrusted response redacted), the **hardened
//! webhook ingestion** ([`webhook`], B2-gh-app: HMAC-SHA256 constant-time signature
//! verification + size-bound + replay-dedup → a redacted, bounded `GitHubEnvelope`), and
//! the **self-improvement loop runner** ([`run_cycle`](crate::selfimprove::run_cycle),
//! B5-autoloop: eval-run → evidence-gate → contract-gate → *draft* self-PR over an
//! `EvalRunner` seam — no self-merge, no kernel mutation) are implemented and CI-tested.
//! The Bot API HTTP long-polling/send (`TODO(P9-net)`), the GitHub loop, the live
//! `WorktreeSubagentExecutor` (`TODO(P11-exec-live)`), the live advisor routing +
//! advisor-note log append (`TODO(P12-native-live)`), the live webhook HTTP listener +
//! GitHub App JWT/RS256 auth (`TODO(B2-webhook-live)`/`TODO(B2-gh-app-live)`), the live
//! autoloop evals/PRs + multi-repo orchestration (`TODO(B5-autoloop-live)`), and
//! supervision land in later phases.
#![forbid(unsafe_code)]

pub mod advisor;
pub mod chat;
pub mod exec;
pub mod github;
pub mod selfimprove;
pub mod supervisor;
pub mod telegram;
pub mod webhook;

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
