// SPDX-License-Identifier: Apache-2.0
//! MCP gateway/client/server and code-mode (`ROADMAP.md` §14; Phase 13).
//!
//! MCP output, resources, tool descriptions, and server prompts are all
//! **untrusted data** (invariant 7). MCP credentials never enter model context;
//! code-mode glue runs in the sandbox; calls are policy-checked and receipted
//! (`docs/mcp.md`). The model sees small typed APIs, not the whole MCP universe.
//!
//! Status: Phase 0 scaffold (std only). The registry, gateway, redaction, and
//! generated stubs land in Phase 13 (`TODO(P13.*)`).
#![forbid(unsafe_code)]

/// Trust level assigned to a registered MCP server.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum TrustLevel {
    /// Unknown/untrusted (default).
    #[default]
    Untrusted,
    /// Registered and version/manifest-pinned, still not trusted with secrets.
    Registered,
}
