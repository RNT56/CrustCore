// SPDX-License-Identifier: Apache-2.0
//! Sandbox profiles and backends (`ROADMAP.md` §10; Phase 4). Every
//! execution-capable operation runs under an explicit sandbox profile
//! (invariant 9), with deny-all egress by default and a sanitized environment
//! (`docs/sandbox.md`).
//!
//! Status: Phase 0 scaffold. Profiles/tiers and the backend trait are defined;
//! the Linux backend (Landlock/namespaces/bubblewrap), env sanitation, and
//! path-list env validation land in Phase 4 (`TODO(P4.*)`).
//!
//! NOTE: unlike the pure kernel crates, the real backends here will require
//! `unsafe`/FFI for syscalls. Such code must be isolated, justified, and tested
//! (CLAUDE.md §6.5); add `#![deny(unsafe_code)]` exceptions per-module with a
//! written rationale rather than relaxing it crate-wide.
#![forbid(unsafe_code)]

use crustcore_runner::{CommandResult, CommandSpec};

/// Execution tiers (`ROADMAP.md` §10.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutionTier {
    /// Tier 0: no execution (planning, review, summarization).
    None,
    /// Tier 1: structured host-side, no arbitrary execution (confined file ops).
    StructuredHost,
    /// Tier 2: sandboxed execution (tests, builds, shell, external workers).
    Sandboxed,
    /// Tier 3: hostile execution (untrusted code; microVM/container, net denied).
    Hostile,
}

/// Network posture for a sandbox profile.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkPosture {
    /// Deny all egress (default).
    #[default]
    DenyAll,
    /// Allow only the profile's allowlisted domains via the trusted proxy.
    Allowlist,
}

/// A sandbox execution profile.
#[derive(Debug, Clone)]
pub struct SandboxProfile {
    /// The execution tier this profile grants.
    pub tier: ExecutionTier,
    /// The network posture (deny-all by default).
    pub network: NetworkPosture,
    /// Environment variable names that are stripped before launch
    /// (`docs/sandbox.md` env sanitation list).
    pub stripped_env: Vec<String>,
}

impl SandboxProfile {
    /// A conservative default profile: sandboxed tier, deny-all network, and the
    /// standard dangerous-variable strip list.
    #[must_use]
    pub fn default_sandboxed() -> Self {
        SandboxProfile {
            tier: ExecutionTier::Sandboxed,
            network: NetworkPosture::DenyAll,
            stripped_env: default_stripped_env(),
        }
    }
}

/// Default list of environment variables stripped before any sandbox launch
/// (`ROADMAP.md` §10.4). Path-list variables are additionally validated
/// component-by-component in Phase 4.
#[must_use]
pub fn default_stripped_env() -> Vec<String> {
    [
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "GIT_CONFIG",
        "GIT_CONFIG_GLOBAL",
        "SSH_AUTH_SOCK",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "GCP_CREDENTIALS",
        "AZURE_CLIENT_SECRET",
        "NPM_TOKEN",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect()
}

/// A sandbox backend that can run a command under a profile.
pub trait SandboxBackend {
    /// Runs `spec` under `profile`, returning a bounded result.
    ///
    /// # Errors
    /// Returns a backend-specific error if the sandbox could not be set up.
    fn run(
        &self,
        profile: &SandboxProfile,
        spec: CommandSpec,
    ) -> Result<CommandResult, SandboxError>;
}

/// Errors from sandbox setup/execution.
#[derive(Debug)]
pub enum SandboxError {
    /// No suitable backend is available on this host.
    NoBackend,
    /// Setting up the sandbox failed.
    Setup(String),
}

impl core::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SandboxError::NoBackend => write!(f, "no sandbox backend available on this host"),
            SandboxError::Setup(e) => write!(f, "sandbox setup failed: {e}"),
        }
    }
}

impl std::error::Error for SandboxError {}
