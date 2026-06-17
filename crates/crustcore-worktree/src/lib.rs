// SPDX-License-Identifier: Apache-2.0
//! Throwaway git worktrees (`ROADMAP.md` §12.5; Phase 5). Each task edits a
//! disposable worktree, not the user's canonical tree (NilCore lesson). The
//! worktree root is the anchor for path confinement (`crustcore-path`).
//!
//! Phase 3 adds the structured, capability-gated file tools and safe git
//! wrappers in [`tools`]. Phase 5 adds the [`WorktreeManager`] lifecycle
//! (create/reuse/remove) used by the verify loop.
#![forbid(unsafe_code)]

pub mod tools;

pub use tools::{
    git_apply, git_diff, git_log, git_status, read_file, search, write_file, SearchHit, ToolError,
};

use std::path::{Path, PathBuf};

use crustcore_path::WorktreeRoot;
use crustcore_types::TaskId;

/// Manages creation, reuse, and teardown of per-task git worktrees (`ROADMAP.md`
/// §12.5; Phase 5 P5.1). Each task edits a **disposable** worktree checked out
/// from the canonical repository, never the canonical tree itself.
///
/// Worktrees are created with the hardened git invocation (`tools::hardened_git`):
/// hooks, the pager, and global/system config are disabled and the environment is
/// scrubbed, so a worktree add cannot run hooks or read model-written global
/// config (invariant 7). Phase 5 targets the user's *own* (trusted) repository
/// (`crustcore run -dir .`), so repo-local filters run normally during checkout
/// (e.g. Git LFS keeps working — CrustCore does **not** mutate the canonical
/// repo's `.git/info/attributes`). Hardening the checkout of an *untrusted* clone
/// against smudge-filter execution is a Phase 6 (external-worker) concern.
#[derive(Debug, Clone)]
pub struct WorktreeManager {
    /// The canonical repository these worktrees are derived from.
    repo_root: PathBuf,
    /// The directory under which per-task worktrees are created (outside the
    /// canonical tree, so a worktree is never confused with the repo itself).
    base: PathBuf,
}

/// Errors from worktree operations.
#[derive(Debug)]
pub enum WorktreeError {
    /// A git invocation failed.
    Git(String),
    /// An I/O error occurred.
    Io(std::io::Error),
    /// The created worktree path could not be opened as a confined root.
    Path(String),
}

impl core::fmt::Display for WorktreeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WorktreeError::Git(e) => write!(f, "git worktree error: {e}"),
            WorktreeError::Io(e) => write!(f, "worktree io error: {e}"),
            WorktreeError::Path(e) => write!(f, "worktree path error: {e}"),
        }
    }
}

impl std::error::Error for WorktreeError {}

impl From<std::io::Error> for WorktreeError {
    fn from(e: std::io::Error) -> Self {
        WorktreeError::Io(e)
    }
}

impl From<ToolError> for WorktreeError {
    fn from(e: ToolError) -> Self {
        match e {
            ToolError::Git(s) => WorktreeError::Git(s),
            ToolError::Io(s) => WorktreeError::Io(std::io::Error::other(s)),
            other => WorktreeError::Git(other.to_string()),
        }
    }
}

impl WorktreeManager {
    /// Creates a manager rooted at a canonical repository. Worktrees are created
    /// under the system temp dir (`<tmp>/crustcore-worktrees`); use
    /// [`WorktreeManager::with_base`] to choose a different location.
    #[must_use]
    pub fn new(repo_root: impl Into<PathBuf>) -> Self {
        let base = std::env::temp_dir().join("crustcore-worktrees");
        WorktreeManager {
            repo_root: repo_root.into(),
            base,
        }
    }

    /// Creates a manager with an explicit base directory for the worktrees.
    #[must_use]
    pub fn with_base(repo_root: impl Into<PathBuf>, base: impl Into<PathBuf>) -> Self {
        WorktreeManager {
            repo_root: repo_root.into(),
            base: base.into(),
        }
    }

    /// The canonical repository root.
    #[must_use]
    pub fn repo_root(&self) -> &Path {
        &self.repo_root
    }

    /// The path a worktree for `task` would live at (deterministic, so a reused
    /// task maps to the same worktree).
    #[must_use]
    pub fn worktree_path(&self, task: TaskId) -> PathBuf {
        self.base.join(format!("cc-wt-{:032x}", task.0))
    }

    /// Creates — or reuses, if it already exists — a disposable worktree for
    /// `task`, returning its confined root.
    ///
    /// Uses a fixed git subcommand (`git worktree add --detach <path> HEAD`) under
    /// the hardened invocation, so the add cannot run repo hooks, the pager, or
    /// model-written global/system config. A detached HEAD is used so no branch is
    /// created or moved.
    ///
    /// # Errors
    /// Returns [`WorktreeError`] if git is unavailable, the repo has no commit to
    /// check out, or the worktree path cannot be opened as a confined root.
    pub fn create_for(&self, task: TaskId) -> Result<WorktreeRoot, WorktreeError> {
        let path = self.worktree_path(task);

        // Reuse an existing worktree: a linked worktree has a `.git` *file* (a
        // gitdir pointer), so its presence marks a prior create we can reuse.
        if path.join(".git").exists() {
            return WorktreeRoot::open(&path).map_err(|e| WorktreeError::Path(format!("{e:?}")));
        }

        std::fs::create_dir_all(&self.base)?;

        // Drop any stale registration for a path we are about to (re)create.
        let mut prune = tools::hardened_git(&self.repo_root);
        prune.args(["worktree", "prune"]);
        let _ = tools::run_git(prune, None);

        let path_str = path
            .to_str()
            .ok_or_else(|| WorktreeError::Path("worktree path is not valid UTF-8".to_string()))?;
        let mut add = tools::hardened_git(&self.repo_root);
        add.args(["worktree", "add", "--detach", path_str, "HEAD"]);
        tools::run_git(add, None)?;

        WorktreeRoot::open(&path).map_err(|e| WorktreeError::Path(format!("{e:?}")))
    }

    /// The commit the worktree's `HEAD` points at (hardened `git rev-parse HEAD`).
    /// Used to reference *what state* was verified without diffing — and without
    /// mutating the canonical repo. Returns the 40-char hex id.
    ///
    /// # Errors
    /// Returns [`WorktreeError`] if git fails (e.g. an unborn HEAD).
    pub fn head_commit(&self, root: &WorktreeRoot) -> Result<String, WorktreeError> {
        let mut cmd = tools::hardened_git(root.as_path());
        cmd.args(["rev-parse", "HEAD"]);
        Ok(tools::run_git(cmd, None)?.trim().to_string())
    }

    /// Removes a disposable worktree (force-removing it and pruning the
    /// registration). Best-effort cleanup; safe to call on an already-gone tree.
    ///
    /// # Errors
    /// Returns [`WorktreeError`] only if the `git worktree remove` invocation
    /// itself fails for a still-present worktree.
    pub fn remove(&self, root: &WorktreeRoot) -> Result<(), WorktreeError> {
        let path_str = root
            .as_path()
            .to_str()
            .ok_or_else(|| WorktreeError::Path("worktree path is not valid UTF-8".to_string()))?;
        let mut remove = tools::hardened_git(&self.repo_root);
        remove.args(["worktree", "remove", "--force", path_str]);
        // If the worktree is already gone, prune handles it; only surface a hard
        // failure when the dir still exists after the attempt.
        let result = tools::run_git(remove, None);
        let mut prune = tools::hardened_git(&self.repo_root);
        prune.args(["worktree", "prune"]);
        let _ = tools::run_git(prune, None);
        match result {
            Ok(_) => Ok(()),
            Err(_) if !root.as_path().exists() => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crustcore_types::TaskId;

    /// Runs git for test setup, scrubbing config so a developer's global hooks/
    /// filters don't perturb the fixture. Returns false if git is unavailable.
    fn git(dir: &Path, args: &[&str]) -> bool {
        std::process::Command::new("git")
            .current_dir(dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("HOME", "/dev/null")
            .args(args)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn init_repo(dir: &Path) -> bool {
        if !git(dir, &["init", "-q"]) {
            return false;
        }
        std::fs::write(dir.join("README.md"), b"hello\n").unwrap();
        git(dir, &["add", "."])
            && git(
                dir,
                &[
                    "-c",
                    "user.email=ci@cc",
                    "-c",
                    "user.name=ci",
                    "commit",
                    "-q",
                    "-m",
                    "init",
                ],
            )
    }

    #[test]
    fn creates_reuses_and_removes_a_worktree() {
        let base_tmp = std::env::temp_dir().join(format!("cc-wtmgr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base_tmp);
        let repo = base_tmp.join("repo");
        let wt_base = base_tmp.join("wts");
        std::fs::create_dir_all(&repo).unwrap();

        if !init_repo(&repo) {
            eprintln!("skipping: git unavailable");
            let _ = std::fs::remove_dir_all(&base_tmp);
            return;
        }

        let mgr = WorktreeManager::with_base(&repo, &wt_base);
        let task = TaskId(7);

        // Create: the worktree exists, has the checked-out file, and HEAD resolves.
        let wt = mgr.create_for(task).expect("create worktree");
        assert!(wt.as_path().join("README.md").is_file());
        let head = mgr.head_commit(&wt).expect("head commit");
        assert_eq!(head.len(), 40, "rev-parse HEAD should be a 40-char sha1");

        // Reuse: a second create_for returns the same path without error.
        let wt2 = mgr.create_for(task).expect("reuse worktree");
        assert_eq!(wt.as_path(), wt2.as_path());

        // Remove: the worktree directory is gone afterward.
        mgr.remove(&wt).expect("remove worktree");
        assert!(!wt.as_path().exists(), "worktree dir should be removed");

        // Idempotent remove on an already-gone worktree is Ok.
        assert!(mgr.remove(&wt).is_ok());

        let _ = std::fs::remove_dir_all(&base_tmp);
    }
}
