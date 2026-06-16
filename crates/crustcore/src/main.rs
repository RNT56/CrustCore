// SPDX-License-Identifier: Apache-2.0
//! The `crustcore` nano binary entry point.
//!
//! Phase 0 scaffold: implements `--version`/`--help` and a hidden `selftest`
//! that exercises the kernel pipeline (so the trusted-core crates are linked and
//! checked). `run`/`inspect`/`export` are recognized and routed to "not yet
//! implemented" until their phases land. See ROADMAP.md §18 and CLAUDE.md §11.
#![forbid(unsafe_code)]

use std::process::ExitCode;

use crustcore_cli::Command;
use crustcore_kernel::{Event, EventKind, Kernel};
use crustcore_policy::{PolicySnapshot, RiskProfile};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Hidden self-test used by CI to prove the kernel pipeline links and runs.
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
        Command::Inspect => not_yet("inspect", "Phase 2 (event log + inspect)"),
        Command::Export => not_yet("export", "Phase 2 (JSONL export)"),
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

/// Drives one kernel step to confirm the trusted core is wired together.
fn selftest() -> ExitCode {
    let mut kernel = Kernel::new(PolicySnapshot::new(RiskProfile::Supervised));
    let actions = kernel.step(Event::internal(EventKind::TaskCreated));
    println!(
        "crustcore selftest ok: kernel produced {} action(s), next_seq={}",
        actions.len(),
        kernel.next_seq().0
    );
    ExitCode::SUCCESS
}
