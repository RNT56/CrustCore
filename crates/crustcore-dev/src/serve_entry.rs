// SPDX-License-Identifier: Apache-2.0
//! The `crustcore-daemon serve` alias entry (`C7.7`, behind the `serve` feature).
//!
//! C7 promises the dev UI is reachable both as its own binary and as
//! `crustcore-daemon serve`. To keep this pass scoped to `crustcore-dev` (the workspace
//! `Cargo.toml` member-add is the only contract-file touch), the wiring lives **here** as
//! a single public entry the daemon can call: `crustcore-daemon`'s `serve` subcommand
//! would forward its parsed args to [`run`] without copying any server logic.
//!
//! **Scoped deviation (noted as a follow-up):** actually adding the `serve` subcommand to
//! `crustcore-daemon`'s CLI requires editing the daemon crate's tree, which is out of
//! scope for this pass (the instructions say not to modify the daemon's tree here). The
//! alias is therefore *enabled* (this entry exists and is callable) but not yet *wired*
//! into the daemon's argument parser; that one-line forward is a follow-up.

use crate::backend::DevBackend;
use crate::config::DevConfig;
use crate::serve::{mint_launch_token, serve};

/// Launch options for the dev UI entry point.
#[derive(Debug, Clone)]
pub struct ServeOptions {
    /// The launch configuration (loopback by default; off-loopback is a warned opt-in).
    pub config: DevConfig,
}

impl Default for ServeOptions {
    fn default() -> Self {
        ServeOptions {
            config: DevConfig::loopback(),
        }
    }
}

/// Run the dev UI to completion over the supplied backend. Mints a fresh per-launch
/// bearer token (printed once), then serves the loopback HTTP surface. This is the entry
/// `crustcore-daemon serve` forwards to.
///
/// `TODO(C7-serve-live)`: the production entry constructs a live `DevBackend` (real event
/// log + spawned `crustcore-net` helper + P13-net MCP transport) and passes it here. The
/// backend is a parameter precisely so that wiring drops in without touching this entry.
///
/// # Errors
/// Propagates any I/O error from binding the socket or running the server.
pub async fn run<B: DevBackend + Send + 'static>(
    backend: B,
    options: ServeOptions,
) -> std::io::Result<()> {
    let token = mint_launch_token();
    serve(backend, options.config, token).await
}
