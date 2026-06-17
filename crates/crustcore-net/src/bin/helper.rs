// SPDX-License-Identifier: Apache-2.0
//! The `crustcore-net` sidecar helper binary (`ROADMAP.md` §2.1, §7.1;
//! `docs/model-routing.md` §6).
//!
//! Nano spawns this process and speaks the std-only local helper protocol
//! (`crustcore-netproto`) over stdin/stdout — exactly as it spawns `git`/`codex`/
//! `claude` — so the sub-800kB binary never links HTTP/TLS (invariants 19, 20).
//!
//! v0.1 serves the routing engine over **deterministic mock providers** (no
//! network). Live OpenAI/Anthropic/OpenRouter/local adapters land once the secret
//! broker (Phase 8) can supply credentials without ever handing a worker/provider
//! a raw key (invariant 1) — see `crustcore_net`'s `TODO(P7-live)`.
#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut engine = crustcore_net::default_mock_engine();
    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();
    match crustcore_net::serve(&mut engine, &mut reader, &mut writer) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("crustcore-net helper: {e}");
            ExitCode::from(1)
        }
    }
}
