// SPDX-License-Identifier: Apache-2.0
//! The `crustcore` nano binary entry point.
//!
//! Implements `--version`/`--help`, `inspect <log>` and `export <log>` (Phase 2:
//! verify/replay the hash-chained event log and render it as JSONL), and a hidden
//! `selftest` that drives the kernel + event-log pipeline so the trusted-core
//! crates are linked and checked. `run` lands in Phase 5. See ROADMAP.md §18.
#![forbid(unsafe_code)]

use std::process::ExitCode;

use crustcore_cli::Command;
use crustcore_eventlog::{ChainStatus, EventLog, FrameMeta};
use crustcore_kernel::{Actor, Event, EventKind, Kernel, Visibility};
use crustcore_policy::{PolicySnapshot, RiskProfile};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Hidden self-test used by CI to prove the trusted-core pipeline links/runs.
    if args.first().map(String::as_str) == Some("selftest") {
        return selftest();
    }

    match crustcore_cli::parse(&args) {
        Command::Version => {
            println!("crustcore {}", crustcore_cli::VERSION);
            ExitCode::SUCCESS
        }
        Command::Help => {
            print!("{}", crustcore_cli::help_text());
            ExitCode::SUCCESS
        }
        Command::Run => not_yet("run", "Phase 5 (worktree verify loop)"),
        Command::Inspect => inspect(args.get(1).map(String::as_str)),
        Command::Export => export(args.get(1).map(String::as_str)),
        Command::Unknown(cmd) => {
            eprintln!("crustcore: unknown command '{cmd}'\n");
            print!("{}", crustcore_cli::help_text());
            ExitCode::from(2)
        }
    }
}

fn not_yet(cmd: &str, phase: &str) -> ExitCode {
    eprintln!("crustcore: '{cmd}' is not yet implemented — scheduled for {phase}.");
    eprintln!("This is a pre-implementation scaffold; see ROADMAP.md and CLAUDE.md.");
    ExitCode::from(3)
}

fn load_log(path: Option<&str>, cmd: &str) -> Result<EventLog, ExitCode> {
    let Some(path) = path else {
        eprintln!("crustcore: '{cmd}' needs a log path — usage: crustcore {cmd} <log-file>");
        return Err(ExitCode::from(2));
    };
    match std::fs::read(path) {
        Ok(bytes) => Ok(EventLog::from_bytes(bytes)),
        Err(e) => {
            eprintln!("crustcore: cannot read '{path}': {e}");
            Err(ExitCode::from(2))
        }
    }
}

/// `crustcore inspect <log>` — verify the chain and print a task summary. Exits
/// non-zero if the chain is broken (so scripts can gate on integrity).
fn inspect(path: Option<&str>) -> ExitCode {
    let log = match load_log(path, "inspect") {
        Ok(l) => l,
        Err(code) => return code,
    };
    let report = log.inspect();
    print!("{report}");
    match report.status {
        ChainStatus::Intact { .. } => ExitCode::SUCCESS,
        ChainStatus::Broken { .. } => ExitCode::from(1),
    }
}

/// `crustcore export <log>` — render the log as JSONL on stdout. The export is
/// verification-gated (only verified frames are emitted, and never a tampered
/// payload); if the chain is broken, a diagnostic goes to stderr and the exit
/// code is non-zero so a pipeline notices.
fn export(path: Option<&str>) -> ExitCode {
    let log = match load_log(path, "export") {
        Ok(l) => l,
        Err(code) => return code,
    };
    print!("{}", log.export_jsonl());
    match log.verify() {
        ChainStatus::Intact { .. } => ExitCode::SUCCESS,
        ChainStatus::Broken {
            frame_index,
            reason,
        } => {
            eprintln!(
                "crustcore: WARNING — chain broken at frame {frame_index}: {reason}; \
                 only the verified prefix was exported."
            );
            ExitCode::from(1)
        }
    }
}

/// Drives the kernel + event log to confirm the trusted core is wired together.
fn selftest() -> ExitCode {
    // Kernel pipeline.
    let mut kernel = Kernel::new(PolicySnapshot::new(RiskProfile::Supervised));
    let actions = kernel.step(Event::internal(EventKind::TaskCreated));

    // Event-log pipeline: append a couple of frames and verify the chain.
    let mut log = EventLog::new();
    log.append(
        &FrameMeta::new(1, EventKind::TaskCreated)
            .actor(Actor::Adapter)
            .visibility(Visibility::Internal),
        b"selftest",
    );
    log.append(
        &FrameMeta::new(2, EventKind::TaskCompleted).actor(Actor::Kernel),
        b"ok",
    );
    let intact = log.verify().is_intact();

    println!(
        "crustcore selftest ok: kernel produced {} action(s), next_seq={}; \
         event log {} frame(s), chain {}",
        actions.len(),
        kernel.next_seq().0,
        log.len(),
        if intact { "INTACT" } else { "BROKEN" },
    );
    if intact {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
