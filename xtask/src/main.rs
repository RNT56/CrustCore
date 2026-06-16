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
         \x20 forbidden-deps  fail if a banned crate is linked into nano\n"
    );
}

/// The full verification gate (CLAUDE.md §9.1). Steps run in increasing cost
/// order so the cheapest failures surface first.
fn verify() -> Result<(), String> {
    step("fmt", fmt_check)?;
    step("clippy", clippy)?;
    step("test", test)?;
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

/// Fails if any forbidden crate appears in the nano dependency tree.
fn forbidden_deps() -> Result<(), String> {
    let out = Command::new("cargo")
        .args([
            "tree",
            "--package",
            "crustcore",
            "--no-default-features",
            "--features",
            "nano",
            "--edges",
            "normal",
            "--prefix",
            "none",
        ])
        .output()
        .map_err(|e| format!("failed to run `cargo tree`: {e}"))?;

    if !out.status.success() {
        // Offline environments may fail to build the tree if a network fetch is
        // required; in the dependency-free scaffold this should not happen.
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("`cargo tree` failed:\n{stderr}"));
    }

    let tree = String::from_utf8_lossy(&out.stdout);
    let mut found = Vec::new();
    for banned in FORBIDDEN_IN_NANO {
        // Match a crate name at a line/word boundary (cargo tree prints
        // "name vX.Y.Z" per line with --prefix none).
        if tree
            .lines()
            .any(|l| l.split_whitespace().next() == Some(banned))
        {
            found.push(*banned);
        }
    }

    if found.is_empty() {
        println!(
            "  no forbidden crates in the nano dependency tree ({} checked)",
            FORBIDDEN_IN_NANO.len()
        );
        Ok(())
    } else {
        Err(format!(
            "forbidden crate(s) linked into nano: {}. These belong in sidecar crates only (CLAUDE.md §5.1).",
            found.join(", ")
        ))
    }
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
