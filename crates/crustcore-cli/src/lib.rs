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

/// Parsed arguments for `crustcore run` (`-dir`/`-goal`/`-verify`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunArgs {
    /// The repository directory (`-dir`). Defaults to `.` when omitted.
    pub dir: Option<String>,
    /// The task goal (`-goal`). Recorded; the autonomous backend lands in Phase 6.
    pub goal: Option<String>,
    /// The verify command (`-verify`), as a raw whitespace-separated string. When
    /// omitted, the caller detects one from the repo shape.
    pub verify: Option<String>,
}

/// Parses `run` arguments (everything after the `run` subcommand). Accepts both
/// `-flag value` and `--flag value`. Each known flag consumes the next token; an
/// unknown flag or a flag missing its value is an error (no silent guessing —
/// the CLI is admin/setup, invariant 16).
///
/// # Errors
/// Returns a human-readable message for an unknown flag or a missing value.
pub fn parse_run(args: &[String]) -> Result<RunArgs, String> {
    let mut out = RunArgs::default();
    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        let take = |i: &mut usize| -> Result<String, String> {
            *i += 1;
            args.get(*i)
                .cloned()
                .ok_or_else(|| format!("flag '{flag}' needs a value"))
        };
        match flag {
            "-dir" | "--dir" => out.dir = Some(take(&mut i)?),
            "-goal" | "--goal" => out.goal = Some(take(&mut i)?),
            "-verify" | "--verify" => out.verify = Some(take(&mut i)?),
            other => return Err(format!("unknown 'run' flag '{other}'")),
        }
        i += 1;
    }
    Ok(out)
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
         \x20   run            Run a verified coding task in a disposable worktree\n\
         \x20   inspect <log>  Verify the event-log hash chain and print a task summary\n\
         \x20   export  <log>  Export the event log as JSONL\n\
         \x20   version        Print version\n\
         \x20   help           Print this help\n\
         \n\
         RUN:\n\
         \x20   crustcore run -dir <repo> -goal <text> -verify <command>\n\
         \x20   Creates a disposable git worktree, reruns <command> in a sandbox,\n\
         \x20   and completes only if it passes (-verify auto-detected if omitted).\n\
         \n\
         The CLI is setup/admin/emergency only. Runtime control is via Telegram\n\
         (see docs/telegram.md).\n"
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

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_string()).collect()
    }

    #[test]
    fn parse_run_collects_flags() {
        let a = parse_run(&s(&[
            "-dir",
            ".",
            "-goal",
            "fix it",
            "-verify",
            "cargo test",
        ]))
        .unwrap();
        assert_eq!(a.dir.as_deref(), Some("."));
        assert_eq!(a.goal.as_deref(), Some("fix it"));
        assert_eq!(a.verify.as_deref(), Some("cargo test"));
        // Long forms and empty args also work.
        assert_eq!(parse_run(&[]).unwrap(), RunArgs::default());
        assert_eq!(
            parse_run(&s(&["--dir", "/repo"])).unwrap().dir.as_deref(),
            Some("/repo")
        );
    }

    #[test]
    fn parse_run_rejects_unknown_flag_and_missing_value() {
        assert!(parse_run(&s(&["-bogus", "x"])).is_err());
        assert!(parse_run(&s(&["-dir"])).is_err());
    }
}
