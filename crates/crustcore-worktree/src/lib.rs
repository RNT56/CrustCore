// SPDX-License-Identifier: Apache-2.0
//! Throwaway git worktrees (`ROADMAP.md` §12.5; Phase 5). Each task edits a
//! disposable worktree, not the user's canonical tree (NilCore lesson). The
//! worktree root is the anchor for path confinement (`crustcore-path`).
//!
//! Status: Phase 0 scaffold. The manager wraps `git worktree` via a fixed set of
//! subcommands (no hooks, no model-written config); the operations land in
//! Phase 5 (`TODO(P5.*)`).
#![forbid(unsafe_code)]

use crustcore_path::WorktreeRoot;
use crustcore_types::TaskId;

/// Manages creation and teardown of per-task git worktrees.
#[derive(Debug, Clone)]
pub struct WorktreeManager {
    /// The canonical repository these worktrees are derived from.
    repo_root: std::path::PathBuf,
}

/// Errors from worktree operations.
#[derive(Debug)]
pub enum WorktreeError {
    /// A git invocation failed.
    Git(String),
    /// An I/O error occurred.
    Io(std::io::Error),
}

impl core::fmt::Display for WorktreeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WorktreeError::Git(e) => write!(f, "git worktree error: {e}"),
            WorktreeError::Io(e) => write!(f, "worktree io error: {e}"),
        }
    }
}

impl std::error::Error for WorktreeError {}

impl From<std::io::Error> for WorktreeError {
    fn from(e: std::io::Error) -> Self {
        WorktreeError::Io(e)
    }
}

impl WorktreeManager {
    /// Creates a manager rooted at a canonical repository.
    #[must_use]
    pub fn new(repo_root: impl Into<std::path::PathBuf>) -> Self {
        WorktreeManager {
            repo_root: repo_root.into(),
        }
    }

    /// The canonical repository root.
    #[must_use]
    pub fn repo_root(&self) -> &std::path::Path {
        &self.repo_root
    }

    /// Creates (or reuses) a disposable worktree for `task`, returning its root.
    ///
    /// TODO(P5.1): shell out to `git worktree add` under the sandbox runner,
    /// using a fixed subcommand set (never executing repo hooks or
    /// model-written config), and return the verified root.
    ///
    /// # Errors
    /// Returns [`WorktreeError`] if the worktree could not be created.
    pub fn create_for(&self, _task: TaskId) -> Result<WorktreeRoot, WorktreeError> {
        Err(WorktreeError::Git(
            "TODO(P5.1): worktree creation not yet implemented".to_string(),
        ))
    }
}
