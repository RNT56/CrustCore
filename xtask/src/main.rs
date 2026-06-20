// SPDX-License-Identifier: Apache-2.0
//! CrustCore workspace task runner.
//!
//! `cargo xtask <command>` (alias in `.cargo/config.toml`):
//!
//! - `verify` — the full gate: fmt, clippy, test, nano build, size gate, and the
//!   forbidden-dependency check (CLAUDE.md §9.1).
//! - `size-check` — build `crustcore-nano` and fail if it exceeds the budget
//!   (invariant 19, `docs/nano-size-budget.md`).
//! - `forbidden-deps` — fail if a banned crate is linked into the nano build.
//! - `fmt` / `clippy` / `test` / `nano-build` — individual steps.
//!
//! This runner is std-only so it works in minimal/offline environments. Where a
//! step needs network (e.g. `cargo bloat`), it is best-effort and skipped with a
//! warning if unavailable.
#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::{Command, ExitCode};

/// Nano size budget in bytes (800 KiB hard target; stretch 600 KiB).
/// Mirrors ROADMAP.md §17.1 and docs/nano-size-budget.md. Raising this requires
/// an explicit, justified change (invariant 19).
const NANO_BUDGET_BYTES: u64 = 800 * 1024;

/// Crates that must never be linked into the nano build (CLAUDE.md §5.1).
const FORBIDDEN_IN_NANO: &[&str] = &[
    "tokio",
    "reqwest",
    "hyper",
    "rustls",
    "axum",
    "tower",
    "clap",
    "sqlx",
    "rusqlite",
    "redb",
    "rmcp",
    "serde_json",
    // Crypto/RNG belongs in feature-gated sidecar backends (the P8-store vault),
    // never in nano — nano hashes with the vendored SHA-256 and reads /dev/urandom.
    "aes-gcm",
    "scrypt",
    "getrandom",
];

fn main() -> ExitCode {
    let cmd = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "verify".to_string());
    let result = match cmd.as_str() {
        "verify" => verify(),
        "fmt" => fmt_check(),
        "clippy" => clippy(),
        "test" => test(),
        "nano-build" => nano_build().map(|_| ()),
        "size-check" => size_check(),
        "release" => release(),
        "forbidden-deps" => forbidden_deps(),
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        other => Err(format!(
            "unknown xtask command '{other}' (try `cargo xtask help`)"
        )),
    };

    match result {
        Ok(()) => {
            println!("\nxtask {cmd}: OK");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("\nxtask {cmd}: FAILED\n  {e}");
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!(
        "cargo xtask <command>\n\n\
         COMMANDS:\n\
         \x20 verify          fmt + clippy + test + nano build + size gate + forbidden-deps\n\
         \x20 fmt             cargo fmt --check\n\
         \x20 clippy          cargo clippy --workspace -- -D warnings\n\
         \x20 test            cargo test --workspace\n\
         \x20 nano-build      build crustcore-nano (profile nano)\n\
         \x20 size-check      build nano and enforce the size budget\n\
         \x20 release         build nano, enforce size, emit SHA256SUMS + manifest\n\
         \x20 forbidden-deps  fail if a banned crate is linked into nano\n"
    );
}

/// Builds a release artifact set for the nano binary (Phase 16, P16.1/P16.2): build
/// under the nano profile, enforce the size budget, then emit a content checksum
/// (`SHA256SUMS`) and a human-readable `release-manifest.txt` next to the binary.
/// "Reproducible enough for audit": the manifest records exactly what was built and
/// its SHA-256, so a downstream signer (minisign/cosign over `SHA256SUMS` — see
/// `docs/releasing.md`) and any auditor can verify the bytes. Signing itself is a
/// keyed, irreversible step done out-of-band, never wired into this offline runner.
fn release() -> Result<(), String> {
    let bin = nano_build()?;
    size_check()?;

    let bytes = std::fs::read(&bin).map_err(|e| format!("cannot read {}: {e}", bin.display()))?;
    let digest = crustcore_types::hash::sha256(&bytes);
    let hex = hex_lower(&digest);
    let size = bytes.len();
    let name = bin
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "crustcore".to_string());
    let dir = bin
        .parent()
        .ok_or_else(|| "nano binary has no parent dir".to_string())?;

    // SHA256SUMS in the conventional `<hex>  <name>` format (sha256sum -c friendly).
    let sums = format!("{hex}  {name}\n");
    let sums_path = dir.join("SHA256SUMS");
    std::fs::write(&sums_path, &sums)
        .map_err(|e| format!("cannot write {}: {e}", sums_path.display()))?;

    let pkg_version = env!("CARGO_PKG_VERSION");
    let manifest = format!(
        "crustcore release manifest\n\
         version:     {pkg_version}\n\
         artifact:    {name}\n\
         profile:     nano (--no-default-features --features nano)\n\
         size_bytes:  {size}\n\
         size_kib:    {:.1}\n\
         budget_pct:  {:.1}\n\
         sha256:      {hex}\n",
        size as f64 / 1024.0,
        (size as f64 / NANO_BUDGET_BYTES as f64) * 100.0,
    );
    let manifest_path = dir.join("release-manifest.txt");
    std::fs::write(&manifest_path, &manifest)
        .map_err(|e| format!("cannot write {}: {e}", manifest_path.display()))?;

    println!("\n{manifest}");
    println!("  wrote {}", sums_path.display());
    println!("  wrote {}", manifest_path.display());
    println!("  next: sign SHA256SUMS out-of-band (minisign/cosign) — see docs/releasing.md");
    Ok(())
}

/// Lowercase hex encoding of a byte slice (no external dep).
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// The full verification gate (CLAUDE.md §9.1). Steps run in increasing cost
/// order so the cheapest failures surface first.
fn verify() -> Result<(), String> {
    step("fmt", fmt_check)?;
    step("clippy", clippy)?;
    step("clippy-features", clippy_features)?;
    step("test", test)?;
    step("test-features", test_features)?;
    step("forbidden-deps", forbidden_deps)?;
    step("size-check", size_check)?;
    Ok(())
}

fn step(name: &str, f: impl FnOnce() -> Result<(), String>) -> Result<(), String> {
    println!("\n=== xtask: {name} ===");
    f()
}

fn fmt_check() -> Result<(), String> {
    run("cargo", &["fmt", "--all", "--check"])
}

fn clippy() -> Result<(), String> {
    run(
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    )
}

/// Clippy the **feature-gated** code the default `--workspace` clippy does not see
/// (it does not enable per-crate features): the live HTTP transport
/// (`crustcore-net --features live`, P7-live) and the encrypted-file vault
/// (`crustcore-secrets --features vault-file`, P8-store).
fn clippy_features() -> Result<(), String> {
    run(
        "cargo",
        &[
            "clippy",
            "--package",
            "crustcore-net",
            "--features",
            "live",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    run(
        "cargo",
        &[
            "clippy",
            "--package",
            "crustcore-secrets",
            "--features",
            "vault-file",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ],
    )
}

/// Run the tests behind cargo features the default `--workspace` test run does not
/// enable. The vault's seal/open/tamper tests live behind `vault-file`; the net
/// adapter tests run under `--workspace` already (only `UreqClient` is feature-gated).
fn test_features() -> Result<(), String> {
    run(
        "cargo",
        &[
            "test",
            "--package",
            "crustcore-secrets",
            "--features",
            "vault-file",
        ],
    )
}

fn test() -> Result<(), String> {
    run("cargo", &["test", "--workspace"])
}

/// Builds the nano binary and returns its path.
fn nano_build() -> Result<PathBuf, String> {
    run(
        "cargo",
        &[
            "build",
            "--profile",
            "nano",
            "--package",
            "crustcore",
            "--no-default-features",
            "--features",
            "nano",
        ],
    )?;
    Ok(workspace_root().join("target/nano/crustcore"))
}

/// Enforces the nano size budget (invariant 19).
fn size_check() -> Result<(), String> {
    let bin = nano_build()?;
    let size = std::fs::metadata(&bin)
        .map_err(|e| format!("cannot stat {}: {e}", bin.display()))?
        .len();
    let pct = (size as f64 / NANO_BUDGET_BYTES as f64) * 100.0;
    println!(
        "  crustcore-nano: {size} bytes ({:.1} KiB), budget {} bytes ({} KiB), {pct:.1}% of budget",
        size as f64 / 1024.0,
        NANO_BUDGET_BYTES,
        NANO_BUDGET_BYTES / 1024,
    );
    if size > NANO_BUDGET_BYTES {
        return Err(format!(
            "nano binary {size} bytes exceeds budget {NANO_BUDGET_BYTES} bytes. \
             Either shrink it or raise NANO_BUDGET_BYTES with justification (invariant 19)."
        ));
    }
    Ok(())
}

/// Fails if any forbidden crate is linked into the nano build, or if the `net`
/// build links the HTTP-bearing sidecar (`crustcore-net`) or any forbidden stack.
///
/// The `net` check codifies the Phase-7 boundary (`docs/model-routing.md` §6): the
/// caller links only the std-only `crustcore-netproto` and *spawns* the
/// `crustcore-net` helper — so even the net build embeds no HTTP/TLS. Without this
/// gate, a future feature repoint or a heavy dep sneaking into `crustcore-netproto`
/// would silently break invariant 20.
fn forbidden_deps() -> Result<(), String> {
    // 1. The nano build links no forbidden crate.
    let nano = tree_crate_names("nano")?;
    let found: Vec<&str> = FORBIDDEN_IN_NANO
        .iter()
        .copied()
        .filter(|b| nano.iter().any(|n| n == b))
        .collect();
    if !found.is_empty() {
        return Err(format!(
            "forbidden crate(s) linked into nano: {}. These belong in sidecar crates only (CLAUDE.md §5.1).",
            found.join(", ")
        ));
    }
    println!(
        "  no forbidden crates in the nano dependency tree ({} checked)",
        FORBIDDEN_IN_NANO.len()
    );

    // 2. The `net` build links the std-only protocol only — never the HTTP-bearing
    //    `crustcore-net` helper (it is spawned), nor any forbidden stack.
    let net = tree_crate_names("net")?;
    let mut net_found: Vec<String> = FORBIDDEN_IN_NANO
        .iter()
        .filter(|b| net.iter().any(|n| n == *b))
        .map(|s| (*s).to_string())
        .collect();
    if net.iter().any(|n| n == "crustcore-net") {
        net_found.push(
            "crustcore-net (the HTTP-bearing helper must be spawned, not linked)".to_string(),
        );
    }
    if !net_found.is_empty() {
        return Err(format!(
            "the `net` build links what it must not: {}. The caller links only crustcore-netproto and spawns the helper (docs/model-routing.md §6, invariant 20).",
            net_found.join(", ")
        ));
    }
    println!("  net build links the std-only protocol only (no crustcore-net / HTTP/TLS)");

    // 3. The DEFAULT `crustcore-net` helper build (no `live` feature) links no HTTP/TLS
    //    stack — the network transport is gated behind `live` only, so the spawned mock
    //    helper, the workspace build, and CI stay HTTP-free (P7-live, CLAUDE.md §5.1).
    let net_helper = package_tree_crate_names("crustcore-net")?;
    const HTTP_TLS: &[&str] = &[
        "ureq",
        "rustls",
        "ring",
        "tokio",
        "hyper",
        "reqwest",
        "native-tls",
    ];
    let helper_found: Vec<&str> = HTTP_TLS
        .iter()
        .copied()
        .filter(|b| net_helper.iter().any(|n| n == b))
        .collect();
    if !helper_found.is_empty() {
        return Err(format!(
            "the DEFAULT crustcore-net build links an HTTP/TLS stack: {}. The live transport must be behind the `live` feature only (P7-live).",
            helper_found.join(", ")
        ));
    }
    println!("  default crustcore-net helper links no HTTP/TLS (live transport is feature-gated)");
    Ok(())
}

/// Crate names in a package's default (no-default-features) dependency tree.
fn package_tree_crate_names(package: &str) -> Result<Vec<String>, String> {
    let out = Command::new("cargo")
        .args([
            "tree",
            "--package",
            package,
            "--no-default-features",
            "--edges",
            "normal",
            "--prefix",
            "none",
        ])
        .current_dir(workspace_root())
        .output()
        .map_err(|e| format!("failed to run `cargo tree`: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("`cargo tree -p {package}` failed:\n{stderr}"));
    }
    let tree = String::from_utf8_lossy(&out.stdout);
    Ok(tree
        .lines()
        .filter_map(|l| l.split_whitespace().next().map(str::to_string))
        .collect())
}

/// Returns the set of crate names in the `crustcore` dependency tree built with
/// the given feature (and no defaults). `cargo tree --prefix none` prints
/// "name vX.Y.Z" per line, so the first whitespace token is the crate name.
fn tree_crate_names(feature: &str) -> Result<Vec<String>, String> {
    let out = Command::new("cargo")
        .args([
            "tree",
            "--package",
            "crustcore",
            "--no-default-features",
            "--features",
            feature,
            "--edges",
            "normal",
            "--prefix",
            "none",
        ])
        .output()
        .map_err(|e| format!("failed to run `cargo tree`: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!(
            "`cargo tree --features {feature}` failed:\n{stderr}"
        ));
    }
    let tree = String::from_utf8_lossy(&out.stdout);
    Ok(tree
        .lines()
        .filter_map(|l| l.split_whitespace().next().map(str::to_string))
        .collect())
}

/// Runs a command, inheriting stdio, and errors on non-zero exit.
fn run(program: &str, args: &[&str]) -> Result<(), String> {
    println!("  $ {program} {}", args.join(" "));
    let status = Command::new(program)
        .args(args)
        .current_dir(workspace_root())
        .status()
        .map_err(|e| format!("failed to spawn `{program}`: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "`{program} {}` exited with {status}",
            args.join(" ")
        ))
    }
}

/// The workspace root (the parent of this `xtask` crate directory).
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask has a parent directory")
        .to_path_buf()
}
