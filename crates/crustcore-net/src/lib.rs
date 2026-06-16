// SPDX-License-Identifier: Apache-2.0
//! Network/provider sidecar (`ROADMAP.md` §2.2, §13; Phase 7).
//!
//! This crate is where the heavy network stack lives so the nano binary never
//! has to: Tokio, a minimal HTTP client, TLS, and provider adapters
//! (OpenAI/Anthropic/OpenRouter/local), plus the Telegram and GitHub helpers and
//! the credential-proxy endpoints. Nano talks to this as an out-of-process
//! helper, never by linking it (`docs/model-routing.md`, `docs/architecture.md`).
//!
//! Status: Phase 0 scaffold (std only). The async runtime and provider clients
//! are added in Phase 7 (`TODO(P7.*)`); this environment has no network access,
//! so the dependencies are documented in `Cargo.toml` rather than added yet.
#![forbid(unsafe_code)]

/// Capability packs this sidecar will expose to the kernel via the helper
/// protocol. Present as a marker so the crate is real and discoverable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetCapability {
    /// Model transport (chat/completions/streaming).
    ModelTransport,
    /// Telegram Bot API runtime channel.
    Telegram,
    /// GitHub REST/GraphQL helper.
    GitHub,
    /// Credential-proxy endpoints (git/model header injection).
    CredentialProxy,
}

/// The local helper-protocol version nano speaks to this sidecar.
pub const HELPER_PROTOCOL_VERSION: u16 = 1;
