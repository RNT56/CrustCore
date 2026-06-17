// SPDX-License-Identifier: Apache-2.0
//! Tiny CLI argument parsing for the nano binary (`ROADMAP.md` §2.1, Phase 0/2).
//!
//! The CLI is **setup/admin/emergency only**, not a hidden chat channel
//! (invariant 16). It deliberately avoids `clap` to stay within the nano size
//! budget; this is a minimal, allocation-light hand-rolled parser.
//!
//! Status: Phase 0 scaffold. `version` is real; `run`/`inspect`/`export` are
//! recognized and routed in later phases (`TODO(P2.4/P5.1)`).
#![forbid(unsafe_code)]

/// The CrustCore semantic version (from the crate metadata at build time).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// A parsed top-level command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Print version and exit.
    Version,
    /// Print help and exit.
    Help,
    /// Run a task (`crustcore run -dir . -goal ... -verify ...`). Phase 5.
    Run,
    /// Inspect/verify the event log. Phase 2.
    Inspect,
    /// Export the event log as JSONL. Phase 2.
    Export,
    /// An unrecognized command (carry the token for the error message).
    Unknown(String),
}

/// Parses argv (excluding the program name) into a [`Command`].
///
/// Recognizes `--version`/`-V`/`version` and `--help`/`-h`/`help` now; the
/// subcommands are recognized so the binary can route them as they are built.
#[must_use]
pub fn parse<I, S>(args: I) -> Command
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut iter = args.into_iter();
    match iter.next() {
        None => Command::Help,
        Some(first) => match first.as_ref() {
            "--version" | "-V" | "version" => Command::Version,
            "--help" | "-h" | "help" => Command::Help,
            "run" => Command::Run,
            "inspect" => Command::Inspect,
            "export" => Command::Export,
            other => Command::Unknown(other.to_string()),
        },
    }
}

/// The help text shown by `crustcore --help`.
#[must_use]
pub fn help_text() -> String {
    format!(
        "crustcore {VERSION} — a sub-800kB Rust coding-agent verifier kernel\n\
         \n\
         USAGE:\n\
         \x20   crustcore <command>\n\
         \n\
         COMMANDS:\n\
         \x20   run            Run a verified coding task in a disposable worktree (Phase 5)\n\
         \x20   inspect <log>  Verify the event-log hash chain and print a task summary\n\
         \x20   export  <log>  Export the event log as JSONL\n\
         \x20   version        Print version\n\
         \x20   help           Print this help\n\
         \n\
         The CLI is setup/admin/emergency only. Runtime control is via Telegram\n\
         (see docs/telegram.md). This is a pre-implementation scaffold.\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_version_and_help() {
        assert_eq!(parse(["--version"]), Command::Version);
        assert_eq!(parse(["version"]), Command::Version);
        assert_eq!(parse(["-h"]), Command::Help);
        assert_eq!(parse(Vec::<String>::new()), Command::Help);
    }

    #[test]
    fn routes_subcommands() {
        assert_eq!(parse(["run"]), Command::Run);
        assert_eq!(parse(["inspect"]), Command::Inspect);
        assert_eq!(parse(["nope"]), Command::Unknown("nope".to_string()));
    }
}
