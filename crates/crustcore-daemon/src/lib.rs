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
//!
//! **The live transports are now wired behind the `live` cargo feature** (the default
//! build stays mock-driven and CI-green): the Telegram Bot API HTTP via
//! [`telegram::LiveTelegramApi`] over `crustcore_net::telegram::RestTelegram`
//! (`TODO(P9-net-live)`), the GitHub App installation-token mint
//! ([`github::mint_installation_token`], `TODO(B2-gh-app-live)`) + the git
//! credential-helper argv parser ([`github::parse_push_argv`]), the live webhook HTTP
//! listener ([`webhook::serve_webhooks_once`], `TODO(B2-webhook-live)`), the live
//! [`exec::WorktreeSubagentExecutor`] (`TODO(P11-exec-live)`), the live advisor routing
//! through the spawned net helper ([`advisor::consult_via_net_helper`],
//! `TODO(P12-native-live)`), and the live [`selfimprove::LiveEvalRunner`] + gate-preserving
//! draft-PR seam ([`selfimprove::draft_pr_request`], `TODO(B5-autoloop-live)`). Each
//! reduced `TODO(*-live)` is now only the irreducible network/sandbox/provider socket
//! (`#[ignore]`d); the mapping/adapter glue is CI-tested. The GitHub task/PR loop driver,
//! the admin socket, leases/heartbeats/recovery, and multi-repo orchestration
//! (`TODO(P10-net)`) land with the daemon runtime entry point.
#![forbid(unsafe_code)]

pub mod advisor;
pub mod chat;
pub mod exec;
pub mod github;
pub mod runtime;
pub mod selfimprove;
pub mod supervisor;
/// Chat-launched verified tasks (the "do the work" half of the front door). Behind the
/// `live` feature — it reuses the worktree/sandbox/verifier flow (non-nano deps).
#[cfg(feature = "live")]
pub mod task;
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
