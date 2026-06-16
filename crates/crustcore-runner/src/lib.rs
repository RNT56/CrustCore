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
