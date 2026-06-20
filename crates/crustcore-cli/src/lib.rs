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
    /// Check environment readiness (git, sandbox backend, state dir). Phase 16.
    Doctor,
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
            "doctor" => Command::Doctor,
            other => Command::Unknown(other.to_string()),
        },
    }
}

/// Parsed arguments for `crustcore run` (`-dir`/`-goal`/`-verify`/`-backend`/`-worker-cmd`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunArgs {
    /// The repository directory (`-dir`). Defaults to `.` when omitted.
    pub dir: Option<String>,
    /// The task goal (`-goal`). Passed to a worker backend; recorded otherwise.
    pub goal: Option<String>,
    /// The verify command (`-verify`), as a raw whitespace-separated string. When
    /// omitted, the caller detects one from the repo shape.
    pub verify: Option<String>,
    /// The coding backend (`-backend`): `native` (default — verify the worktree as
    /// is), `codex`, `claude`, or `cmd` (a generic external worker, see
    /// `-worker-cmd`). An external worker produces a candidate change in the
    /// worktree that is then re-derived and verified (Phase 6).
    pub backend: Option<String>,
    /// The generic external worker command (`-worker-cmd`), required when
    /// `-backend cmd`. Whitespace-split into program + args with **no shell
    /// interpretation** (invariant 7).
    pub worker_cmd: Option<String>,
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
            "-backend" | "--backend" => out.backend = Some(take(&mut i)?),
            "-worker-cmd" | "--worker-cmd" => out.worker_cmd = Some(take(&mut i)?),
            other => return Err(format!("unknown 'run' flag '{other}'")),
        }
        i += 1;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// `crustcore doctor` — environment readiness (Phase 16, P16.3)
// ---------------------------------------------------------------------------

/// The status of one readiness check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckStatus {
    /// The check passed.
    Ok,
    /// A non-blocking concern (degraded, but not a hard stop).
    Warn,
    /// A blocking problem — the host is not ready to run verified tasks.
    Fail,
}

impl CheckStatus {
    /// A short, stable glyph for the status line.
    #[must_use]
    pub fn glyph(self) -> &'static str {
        match self {
            CheckStatus::Ok => "ok  ",
            CheckStatus::Warn => "warn",
            CheckStatus::Fail => "FAIL",
        }
    }
}

/// One environment readiness check (name + status + a human-readable detail).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorCheck {
    /// The thing checked (e.g. `git`, `sandbox`, `state-dir`).
    pub name: &'static str,
    /// The outcome.
    pub status: CheckStatus,
    /// A one-line, bounded explanation.
    pub detail: String,
}

impl DoctorCheck {
    /// Convenience constructor.
    #[must_use]
    pub fn new(name: &'static str, status: CheckStatus, detail: impl Into<String>) -> Self {
        DoctorCheck {
            name,
            status,
            detail: detail.into(),
        }
    }
}

/// The result of `crustcore doctor`: a list of checks, a rendered report, and a
/// readiness verdict. Pure data + pure rendering so the decision is testable; the
/// nano binary supplies the actual probes (git on `PATH`, sandbox backend, a
/// writable state dir).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DoctorReport {
    /// The checks performed, in display order.
    pub checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    /// An empty report.
    #[must_use]
    pub fn new() -> Self {
        DoctorReport { checks: Vec::new() }
    }

    /// Adds a check.
    pub fn push(&mut self, check: DoctorCheck) {
        self.checks.push(check);
    }

    /// Whether the host is ready to run verified tasks — true iff **no** check
    /// failed. `Warn`s do not block (they are degradations, not stops).
    #[must_use]
    pub fn is_ready(&self) -> bool {
        !self.checks.iter().any(|c| c.status == CheckStatus::Fail)
    }

    /// The process exit code: 0 when ready, 1 otherwise (admin-tool convention).
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        u8::from(!self.is_ready())
    }

    /// Renders the human-readable report (one line per check + a verdict line).
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = format!("crustcore {VERSION} — environment readiness\n\n");
        for c in &self.checks {
            out.push_str(&format!(
                "  [{}] {:<10} {}\n",
                c.status.glyph(),
                c.name,
                c.detail
            ));
        }
        out.push('\n');
        if self.is_ready() {
            out.push_str("ready: this host can run verified tasks.\n");
        } else {
            out.push_str("NOT ready: fix the FAIL items above before running tasks.\n");
        }
        out
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
         \x20   run            Run a verified coding task in a disposable worktree\n\
         \x20   inspect <log>  Verify the event-log hash chain and print a task summary\n\
         \x20   export  <log>  Export the event log as JSONL\n\
         \x20   doctor         Check environment readiness (git, sandbox, state dir)\n\
         \x20   version        Print version\n\
         \x20   help           Print this help\n\
         \n\
         RUN:\n\
         \x20   crustcore run -dir <repo> -goal <text> -verify <command>\n\
         \x20                 [-backend native|codex|claude|cmd] [-worker-cmd <command>]\n\
         \x20   Creates a disposable git worktree, reruns <command> in a sandbox,\n\
         \x20   and completes only if it passes (-verify auto-detected if omitted).\n\
         \x20   With -backend, an external worker first produces a candidate change\n\
         \x20   in the worktree (sandboxed, no secrets); CrustCore re-derives the\n\
         \x20   diff, rejects out-of-root writes, then verifies. -worker-cmd gives\n\
         \x20   the generic worker command for -backend cmd.\n\
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
        assert_eq!(parse(["export"]), Command::Export);
        assert_eq!(parse(["doctor"]), Command::Doctor);
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

    #[test]
    fn parse_run_collects_backend_flags() {
        let a = parse_run(&s(&["-backend", "cmd", "-worker-cmd", "/bin/sh -c true"])).unwrap();
        assert_eq!(a.backend.as_deref(), Some("cmd"));
        assert_eq!(a.worker_cmd.as_deref(), Some("/bin/sh -c true"));
        // Backend flags are optional (Phase-5 behavior when omitted).
        assert_eq!(parse_run(&s(&["-dir", "."])).unwrap().backend, None);
    }

    #[test]
    fn doctor_report_readiness_and_exit_code() {
        // All Ok (plus a Warn) → ready, exit 0.
        let mut r = DoctorReport::new();
        r.push(DoctorCheck::new(
            "git",
            CheckStatus::Ok,
            "git found on PATH",
        ));
        r.push(DoctorCheck::new(
            "sandbox",
            CheckStatus::Warn,
            "bubblewrap missing; install for sandboxed execution",
        ));
        assert!(r.is_ready());
        assert_eq!(r.exit_code(), 0);
        assert!(r
            .render()
            .contains("ready: this host can run verified tasks."));

        // Any Fail → not ready, exit 1.
        r.push(DoctorCheck::new(
            "state-dir",
            CheckStatus::Fail,
            "state dir not writable",
        ));
        assert!(!r.is_ready());
        assert_eq!(r.exit_code(), 1);
        assert!(r.render().contains("NOT ready"));
        // Every check appears in the rendered report.
        let rendered = r.render();
        for name in ["git", "sandbox", "state-dir"] {
            assert!(rendered.contains(name), "report missing check {name}");
        }
    }
}
