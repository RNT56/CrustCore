// SPDX-License-Identifier: Apache-2.0
//! The `crustcore-net` sidecar helper binary (`ROADMAP.md` §2.1, §7.1;
//! `docs/model-routing.md` §6).
//!
//! Nano spawns this process and speaks the std-only local helper protocol
//! (`crustcore-netproto`) over stdin/stdout — exactly as it spawns `git`/`codex`/
//! `claude` — so the sub-800kB binary never links HTTP/TLS (invariants 19, 20).
//!
//! With **no args** (or `--mock`) it serves the routing engine over deterministic
//! **mock providers** (no network) — this keeps CI, the subprocess integration test,
//! and offline `crustcore doctor` unchanged. With `--providers <file>` and the
//! **`live`** feature it builds a live engine from the provider config, resolving
//! each provider's credential via the secret broker at call time (a worker/provider
//! never gets a raw key — invariant 1). The `serve` loop, protocol, and streaming
//! sink are identical for both engines.
#![forbid(unsafe_code)]

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut engine = match build_engine(&args) {
        Ok(engine) => engine,
        Err(e) => {
            eprintln!("crustcore-net helper: {e}");
            return ExitCode::from(2);
        }
    };
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

/// Selects the engine from argv. `--providers <file>` (live feature) builds a live
/// engine; anything else is the mock default.
fn build_engine(args: &[String]) -> Result<crustcore_net::Engine, String> {
    match args.first().map(String::as_str) {
        Some("--providers") => build_live_engine(args.get(1).map(String::as_str)),
        _ => Ok(crustcore_net::default_mock_engine()),
    }
}

#[cfg(feature = "live")]
fn build_live_engine(path: Option<&str>) -> Result<crustcore_net::Engine, String> {
    use std::rc::Rc;

    let path = path.ok_or_else(|| "--providers needs a config file path".to_string())?;
    let json = std::fs::read_to_string(path).map_err(|e| format!("reading {path}: {e}"))?;
    let configs = crustcore_net::config::parse_providers(&json)?;

    // Credentials come from the broker/keychain the operator populates. The helper
    // reads each provider's secret-handle label and resolves the key at call time;
    // the key is never in the config (handles only) and never reaches the model or
    // the sandbox env. `CRUSTCORE_NET_KEY_<LABEL>` env vars are a minimal operator
    // path; a native keychain/vault (P8-store) plugs in behind the same trait.
    let mut creds = crustcore_net::credsource::StaticCredentials::new();
    for cfg in &configs {
        if let Some(label) = &cfg.secret_label {
            let var = format!(
                "CRUSTCORE_NET_KEY_{}",
                label.to_ascii_uppercase().replace('-', "_")
            );
            if let Ok(key) = std::env::var(&var) {
                creds = creds.with(label, &key);
            }
        }
    }
    Ok(crustcore_net::live_engine(
        &configs,
        Rc::new(creds) as Rc<dyn crustcore_net::credsource::CredentialSource>,
    ))
}

#[cfg(not(feature = "live"))]
fn build_live_engine(_path: Option<&str>) -> Result<crustcore_net::Engine, String> {
    Err("live providers require building crustcore-net with --features live".to_string())
}
