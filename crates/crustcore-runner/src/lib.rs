// SPDX-License-Identifier: Apache-2.0
//! Process runner (`ROADMAP.md` §18 Phase 4). Spawns child processes with
//! **bounded** stdout/stderr capture, a timeout, and process-tree kill. The
//! runner itself does not sandbox — it is wrapped by `crustcore-sandbox`, which
//! supplies the sandbox profile and environment sanitation.
//!
//! Status: Phase 0 scaffold. `CommandSpec`/`CommandResult` are defined; spawn,
//! bounded capture, and timeout/kill land in Phase 4 (`TODO(P4.*)`).
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::time::Duration;

/// A fully specified command to run. Built by trusted code, not by free-text
/// from a model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandSpec {
    /// The program to execute (resolved, not shell-interpreted).
    pub program: String,
    /// Arguments, passed without shell interpolation.
    pub args: Vec<String>,
    /// Working directory (typically a confined worktree path).
    pub cwd: Option<String>,
    /// The *minimal* environment to expose (no inherited ambient secrets).
    pub env: BTreeMap<String, String>,
    /// Maximum wall-clock duration before the process tree is killed.
    pub timeout: Duration,
    /// Maximum captured output per stream, in bytes (bounded; invariant 11).
    pub max_output_bytes: usize,
}

impl CommandSpec {
    /// A spec with safe defaults: empty env, 5-minute timeout, 8 MiB output cap.
    #[must_use]
    pub fn new(program: impl Into<String>) -> Self {
        CommandSpec {
            program: program.into(),
            args: Vec::new(),
            cwd: None,
            env: BTreeMap::new(),
            timeout: Duration::from_secs(300),
            max_output_bytes: 8 * 1024 * 1024,
        }
    }
}

/// How a command terminated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    /// Exited with the given code.
    Code(i32),
    /// Terminated by a signal (Unix).
    Signal(i32),
    /// Killed because it exceeded its timeout.
    TimedOut,
}

/// The bounded result of running a [`CommandSpec`].
#[derive(Debug, Clone)]
pub struct CommandResult {
    /// How it exited.
    pub status: ExitStatus,
    /// Captured stdout (truncated to `max_output_bytes`).
    pub stdout: Vec<u8>,
    /// Captured stderr (truncated to `max_output_bytes`).
    pub stderr: Vec<u8>,
    /// Whether either stream was truncated.
    pub truncated: bool,
}

impl CommandResult {
    /// Whether the command exited successfully (code 0).
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self.status, ExitStatus::Code(0))
    }
}

/// Errors from spawning/running a command.
#[derive(Debug)]
pub enum RunError {
    /// The process could not be spawned (e.g. program not found).
    Spawn(String),
    /// An I/O error occurred while running.
    Io(String),
}

impl core::fmt::Display for RunError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RunError::Spawn(e) => write!(f, "failed to spawn command: {e}"),
            RunError::Io(e) => write!(f, "command io error: {e}"),
        }
    }
}

impl std::error::Error for RunError {}

/// Grace period between SIGTERM and SIGKILL when killing a timed-out process tree.
const KILL_GRACE: Duration = Duration::from_millis(200);

/// Runs a [`CommandSpec`] to completion (or timeout), returning a **bounded**
/// [`CommandResult`]. The command runs in its **own process group** so that, on
/// timeout, the whole tree (not just the direct child) is signalled — orphaned
/// grandchildren cannot survive (`docs/sandbox.md` §6.2, invariant 12). Output is
/// captured up to `max_output_bytes` per stream and then drained (so the child
/// never blocks on a full pipe), with truncation flagged (invariant 11).
///
/// This is the raw process runner; it performs **no** sandboxing or environment
/// sanitation itself — `crustcore-sandbox` wraps it with a profile, a sanitized
/// environment, and network/filesystem confinement (invariant 9). Unix-only (the
/// nano target is Linux).
///
/// # Errors
/// [`RunError::Spawn`] if the process cannot start; [`RunError::Io`] on a wait
/// error.
#[cfg(unix)]
pub fn run(spec: &CommandSpec) -> Result<CommandResult, RunError> {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::time::Instant;

    let mut cmd = Command::new(&spec.program);
    cmd.args(&spec.args)
        .env_clear()
        .envs(&spec.env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Own process group (pgid == child pid) so we can signal the whole tree.
        .process_group(0);
    if let Some(cwd) = &spec.cwd {
        cmd.current_dir(cwd);
    }

    let mut child = cmd.spawn().map_err(|e| RunError::Spawn(e.to_string()))?;
    let pgid = child.id();

    let out_reader = child
        .stdout
        .take()
        .map(|s| spawn_reader(s, spec.max_output_bytes));
    let err_reader = child
        .stderr
        .take()
        .map(|s| spawn_reader(s, spec.max_output_bytes));

    let start = Instant::now();
    let mut timed_out = false;
    let exit_status = loop {
        match child.try_wait().map_err(|e| RunError::Io(e.to_string()))? {
            Some(status) => break status,
            None => {
                if start.elapsed() >= spec.timeout {
                    kill_group(pgid, "TERM");
                    timed_out = true;
                    break wait_after_kill(&mut child, pgid)?;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    };

    let (stdout, out_trunc) = join_reader(out_reader);
    let (stderr, err_trunc) = join_reader(err_reader);

    let status = if timed_out {
        ExitStatus::TimedOut
    } else {
        from_std_status(&exit_status)
    };

    Ok(CommandResult {
        status,
        stdout,
        stderr,
        truncated: out_trunc || err_trunc,
    })
}

#[cfg(unix)]
fn from_std_status(st: &std::process::ExitStatus) -> ExitStatus {
    use std::os::unix::process::ExitStatusExt;
    if let Some(code) = st.code() {
        ExitStatus::Code(code)
    } else if let Some(sig) = st.signal() {
        ExitStatus::Signal(sig)
    } else {
        ExitStatus::Code(-1)
    }
}

/// Signals a whole process group via `kill -<sig> -<pgid>` (negative pid = group).
/// Std-only (no libc): the child was placed in its own group, so `pgid == child
/// pid`.
#[cfg(unix)]
fn kill_group(pgid: u32, sig: &str) {
    use std::process::{Command, Stdio};
    let _ = Command::new("kill")
        .args([format!("-{sig}"), format!("-{pgid}")])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// After a SIGTERM to the group, wait briefly for the child to exit; if it
/// lingers past the grace period, SIGKILL the group and reap.
#[cfg(unix)]
fn wait_after_kill(
    child: &mut std::process::Child,
    pgid: u32,
) -> Result<std::process::ExitStatus, RunError> {
    let deadline = std::time::Instant::now() + KILL_GRACE;
    loop {
        match child.try_wait().map_err(|e| RunError::Io(e.to_string()))? {
            Some(status) => return Ok(status),
            None => {
                if std::time::Instant::now() >= deadline {
                    kill_group(pgid, "KILL");
                    return child.wait().map_err(|e| RunError::Io(e.to_string()));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

/// Spawns a thread that reads up to `max` bytes from `stream`, then drains the
/// remainder (so the child never blocks on a full pipe). Returns the captured
/// bytes and whether the stream was truncated.
fn spawn_reader<R: std::io::Read + Send + 'static>(
    mut stream: R,
    max: usize,
) -> std::thread::JoinHandle<(Vec<u8>, bool)> {
    use std::io::Read;
    std::thread::spawn(move || {
        let mut captured = Vec::new();
        let _ = (&mut stream).take(max as u64).read_to_end(&mut captured);
        // Drain the rest to EOF so the writer never blocks on a full pipe.
        let mut scratch = [0u8; 8192];
        let mut truncated = false;
        loop {
            match stream.read(&mut scratch) {
                Ok(0) => break,
                Ok(_) => truncated = true,
                Err(_) => break,
            }
        }
        (captured, truncated)
    })
}

fn join_reader(handle: Option<std::thread::JoinHandle<(Vec<u8>, bool)>>) -> (Vec<u8>, bool) {
    handle
        .map(|h| h.join().unwrap_or((Vec::new(), false)))
        .unwrap_or((Vec::new(), false))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn spec(program: &str, args: &[&str]) -> CommandSpec {
        let mut s = CommandSpec::new(program);
        s.args = args.iter().map(|a| (*a).to_string()).collect();
        s
    }

    #[test]
    fn captures_stdout_and_exit_code() {
        let r = run(&spec("/bin/echo", &["hello"])).unwrap();
        assert!(r.is_success());
        assert_eq!(r.stdout, b"hello\n");
        assert!(!r.truncated);
    }

    #[test]
    fn reports_nonzero_exit() {
        let r = run(&spec("/bin/sh", &["-c", "exit 3"])).unwrap();
        assert_eq!(r.status, ExitStatus::Code(3));
        assert!(!r.is_success());
    }

    #[test]
    fn bounds_output_and_flags_truncation() {
        // Produce far more than the cap; capture must stop at the cap and flag it.
        let mut s = spec("/bin/sh", &["-c", "yes AAAA | head -c 100000"]);
        s.max_output_bytes = 1024;
        let r = run(&s).unwrap();
        assert_eq!(r.stdout.len(), 1024);
        assert!(r.truncated);
    }

    #[test]
    fn times_out_and_kills_the_process_tree() {
        // A parent that spawns a long-lived child and then waits: a naive
        // child-only kill would leave the grandchild; the group kill reaps both.
        let mut s = spec("/bin/sh", &["-c", "sleep 30 & sleep 30"]);
        s.timeout = Duration::from_millis(300);
        let start = std::time::Instant::now();
        let r = run(&s).unwrap();
        assert_eq!(r.status, ExitStatus::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn env_is_built_from_scratch_not_inherited() {
        // The runner clears the env and applies only spec.env.
        std::env::set_var("CC_RUNNER_LEAK", "should-not-appear");
        let mut s = spec(
            "/bin/sh",
            &["-c", "printf '[%s][%s]' \"$CC_RUNNER_LEAK\" \"$CC_SET\""],
        );
        s.env.insert("CC_SET".to_string(), "present".to_string());
        let r = run(&s).unwrap();
        assert_eq!(r.stdout, b"[][present]");
        std::env::remove_var("CC_RUNNER_LEAK");
    }
}
