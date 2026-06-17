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

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Grace period between SIGTERM and SIGKILL when killing a timed-out process tree.
const KILL_GRACE: Duration = Duration::from_millis(200);

/// Maximum time to wait for reader threads to finish after the process group has
/// been swept. After this, a still-blocked reader (a grandchild that escaped the
/// group via `setsid` and holds the pipe — only possible without a PID namespace)
/// is detached so `run()` returns with the output captured so far, never hanging.
const READER_DRAIN: Duration = Duration::from_secs(5);

/// Shared, incrementally-filled capture for a stream reader thread, so `run()`
/// can recover the bytes read so far even if it has to detach the thread.
struct Capture {
    buf: Mutex<Vec<u8>>,
    truncated: AtomicBool,
    done: AtomicBool,
}

impl Capture {
    fn new() -> Arc<Self> {
        Arc::new(Capture {
            buf: Mutex::new(Vec::new()),
            truncated: AtomicBool::new(false),
            done: AtomicBool::new(false),
        })
    }
}

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

    let (out_cap, out_h) = match child.stdout.take() {
        Some(s) => {
            let cap = Capture::new();
            (
                Some(cap.clone()),
                Some(spawn_reader(s, spec.max_output_bytes, cap)),
            )
        }
        None => (None, None),
    };
    let (err_cap, err_h) = match child.stderr.take() {
        Some(s) => {
            let cap = Capture::new();
            (
                Some(cap.clone()),
                Some(spawn_reader(s, spec.max_output_bytes, cap)),
            )
        }
        None => (None, None),
    };

    let start = Instant::now();
    let mut timed_out = false;
    let leader_status = loop {
        match child.try_wait().map_err(|e| RunError::Io(e.to_string()))? {
            Some(status) => break status,
            None => {
                if start.elapsed() >= spec.timeout {
                    timed_out = true;
                    // Ask the whole tree to stop, give it the grace window, then
                    // SIGKILL the group unconditionally (a SIGTERM-ignoring
                    // grandchild must not survive — invariant 12).
                    kill_group(pgid, "TERM");
                    let grace = Instant::now() + KILL_GRACE;
                    while Instant::now() < grace
                        && child
                            .try_wait()
                            .map_err(|e| RunError::Io(e.to_string()))?
                            .is_none()
                    {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    // Escalate: SIGKILL the whole group (reaps grandchildren the
                    // leader backgrounded) AND, as a std-only guarantee that does
                    // not depend on an external `kill` binary or its argv parsing,
                    // SIGKILL the leader directly via its `Child` handle. The group
                    // kill is still sent *before* `wait()` reaps the leader, so the
                    // leader keeps pinning `pgid` and the group target cannot race a
                    // reused pid.
                    kill_group(pgid, "KILL");
                    let _ = child.kill();
                    break child.wait().map_err(|e| RunError::Io(e.to_string()))?;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    };

    // On a clean exit we deliberately do NOT sweep the group: the leader has been
    // reaped (its pid is freed), so signaling `pgid` here could race a reused pid
    // onto an unrelated, newly-created group. A grandchild the command backgrounded
    // and left holding the stdout/stderr pipe is instead bounded by the reader
    // deadline below (and, in the real sandboxed path, killed by the bubblewrap pid
    // namespace when the sandbox exits) — so `run()` still returns without an
    // errant cross-group SIGKILL.

    // Collect with a hard deadline so nothing can make `run()` hang.
    let deadline = Instant::now() + READER_DRAIN;
    let (stdout, out_trunc) = collect_reader(out_cap, out_h, deadline);
    let (stderr, err_trunc) = collect_reader(err_cap, err_h, deadline);

    let status = if timed_out {
        ExitStatus::TimedOut
    } else {
        from_std_status(&leader_status)
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

/// Signals a whole process group via `kill -<sig> -<pgid>` (negative pid = the
/// group), to reap grandchildren the leader spawned. Std-only (no libc): the child
/// was placed in its own group, so `pgid == child pid`. Uses an **absolute** `kill`
/// path (not PATH-resolved) so the signal delivery cannot be redirected.
/// Best-effort: a kill targeting an already-empty group simply does nothing, the
/// leader itself is also killed directly via its `Child` handle, and the bounded
/// reader collection guarantees `run()` returns regardless of whether `kill`
/// exists at all (e.g. a minimal container without `procps`).
///
/// The group target is a negative pid (`-<pgid>`), whose leading dash is parsed
/// differently across `kill` implementations. BSD `kill` (macOS) accepts
/// `kill -TERM -<pgid>`. The Linux `procps-ng` `kill`, when invoked with an argv
/// of exactly `["-TERM", "-<pgid>"]`, does **not** deliver to the group and
/// returns success silently — it needs a `--` end-of-options separator
/// (`kill -TERM -- -<pgid>`). This is the verified cause of the CI hang on
/// `ubuntu-latest`: the timeout fired, `kill` "succeeded", yet the process tree
/// survived and `wait()` blocked for the full sleep. We therefore issue both
/// argument forms (signals are idempotent): the form the local `kill` rejects is a
/// harmless no-op, and the form it accepts fires.
#[cfg(unix)]
fn kill_group(pgid: u32, sig: &str) {
    use std::process::{Command, Stdio};
    for kill_bin in ["/bin/kill", "/usr/bin/kill"] {
        if std::path::Path::new(kill_bin).exists() {
            for args in [
                vec![format!("-{sig}"), format!("-{pgid}")],
                vec![format!("-{sig}"), "--".to_string(), format!("-{pgid}")],
            ] {
                let _ = Command::new(kill_bin)
                    .args(&args)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
            return;
        }
    }
}

/// Spawns a thread that reads `stream` into a shared [`Capture`]: it keeps the
/// first `max` bytes and drains the rest (so the writer never blocks on a full
/// pipe), flagging truncation, and sets `done` when the stream reaches EOF.
fn spawn_reader<R: std::io::Read + Send + 'static>(
    mut stream: R,
    max: usize,
    cap: Arc<Capture>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut total = 0usize;
        let mut chunk = [0u8; 8192];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    if total < max {
                        let take = (max - total).min(n);
                        if let Ok(mut buf) = cap.buf.lock() {
                            buf.extend_from_slice(&chunk[..take]);
                        }
                        total += take;
                        if take < n {
                            cap.truncated.store(true, Ordering::Relaxed);
                        }
                    } else {
                        cap.truncated.store(true, Ordering::Relaxed);
                    }
                }
                Err(_) => break,
            }
        }
        cap.done.store(true, Ordering::Relaxed);
    })
}

/// Waits (until `deadline`) for a reader to finish, joining it cleanly if so;
/// otherwise detaches it (the thread is left blocked on a pipe a `setsid`-escaped
/// straggler still holds) and returns the bytes captured so far — so `run()`
/// never hangs.
fn collect_reader(
    cap: Option<Arc<Capture>>,
    handle: Option<std::thread::JoinHandle<()>>,
    deadline: std::time::Instant,
) -> (Vec<u8>, bool) {
    let Some(cap) = cap else {
        return (Vec::new(), false);
    };
    while !cap.done.load(Ordering::Relaxed) && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    if let Some(h) = handle {
        if cap.done.load(Ordering::Relaxed) {
            let _ = h.join();
        }
        // else: drop `h` to detach the still-blocked reader thread.
    }
    let buf = cap.buf.lock().map(|b| b.clone()).unwrap_or_default();
    (buf, cap.truncated.load(Ordering::Relaxed))
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
    fn signal_ignoring_grandchild_does_not_hang_run() {
        // Parent backgrounds a grandchild that IGNORES SIGTERM and inherits the
        // stdout pipe, then sleeps. A naive child-only kill (or unbounded reader
        // join) would hang run() forever; the unconditional group SIGKILL reaps
        // the grandchild so the pipe closes and run() returns promptly.
        let mut s = spec(
            "/bin/sh",
            &["-c", "sh -c 'trap \"\" TERM; sleep 30' & sleep 30"],
        );
        s.timeout = Duration::from_millis(300);
        let start = std::time::Instant::now();
        let r = run(&s).unwrap();
        assert_eq!(r.status, ExitStatus::TimedOut);
        assert!(
            start.elapsed() < Duration::from_secs(8),
            "run() hung on a signal-ignoring grandchild: {:?}",
            start.elapsed()
        );
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
