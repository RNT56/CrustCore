// SPDX-License-Identifier: Apache-2.0
//! Structured, capability-gated file tools and safe git wrappers
//! (`ROADMAP.md` §8.3, Phase 3, tasks P3.3–P3.5).
//!
//! Every operation requires **both** an authority token (`FsReadCap`/`FsWriteCap`
//! from `crustcore-policy`, invariant 8) **and**, for file ops, a
//! [`ConfinedReadPath`]/[`ConfinedWritePath`] (`crustcore-path`) that proves the
//! target is inside the worktree and symlink-safe. A raw path string can never
//! reach a write tool. The capability's root must match the path's root, so a
//! token minted for one worktree cannot act on another.
//!
//! The git wrappers run a **fixed** subcommand set with hooks and external config
//! disabled (`core.hooksPath=/dev/null`, `GIT_CONFIG_*`, scrubbed env), so a
//! repository cannot execute hooks or have the model's written config influence
//! the command (Phase 3 acceptance). Phase 4 will additionally route these
//! through the sandbox runner.

use std::io::Read;
use std::path::Path;
use std::process::Command;

use crustcore_path::{ConfinedReadPath, ConfinedWritePath, WorktreeRoot};
use crustcore_policy::{FsReadCap, FsWriteCap};

/// Default cap on bytes read into memory (bounded everything, `CLAUDE.md` §6.5).
pub const DEFAULT_MAX_READ: usize = 8 * 1024 * 1024;

/// Cap on captured git stdout (bytes).
const MAX_GIT_OUTPUT: usize = 4 * 1024 * 1024;

/// Errors from the structured tools.
#[derive(Debug)]
pub enum ToolError {
    /// The capability's worktree root does not match the path's root.
    CapRootMismatch,
    /// A write targeted the `.git` metadata directory (refused).
    GitDir,
    /// A filesystem error.
    Io(String),
    /// A git invocation failed (captured stderr).
    Git(String),
}

impl core::fmt::Display for ToolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ToolError::CapRootMismatch => {
                write!(f, "capability root does not match the path's worktree root")
            }
            ToolError::GitDir => write!(f, "refusing to write into the .git directory"),
            ToolError::Io(e) => write!(f, "tool io error: {e}"),
            ToolError::Git(e) => write!(f, "git error: {e}"),
        }
    }
}

impl std::error::Error for ToolError {}

fn io(e: std::io::Error) -> ToolError {
    ToolError::Io(e.to_string())
}

fn roots_match(cap_root: &WorktreeRoot, path_root: &WorktreeRoot) -> bool {
    cap_root.as_path() == path_root.as_path()
}

/// Reads up to `max_bytes` of a confined file (bounded). Requires a read
/// capability whose root matches the path's root.
///
/// # Errors
/// [`ToolError::CapRootMismatch`] if the cap/path roots differ, or
/// [`ToolError::Io`] on a filesystem error.
pub fn read_file(
    cap: &FsReadCap,
    path: &ConfinedReadPath<'_>,
    max_bytes: usize,
) -> Result<Vec<u8>, ToolError> {
    if !roots_match(&cap.root, path.root()) {
        return Err(ToolError::CapRootMismatch);
    }
    let file = std::fs::File::open(path.to_path()).map_err(io)?;
    let mut buf = Vec::new();
    file.take(max_bytes as u64)
        .read_to_end(&mut buf)
        .map_err(io)?;
    Ok(buf)
}

/// Writes `bytes` to a confined path, creating in-root parent directories.
/// Refuses writes into `.git/`. Requires a write capability whose root matches.
///
/// # Errors
/// [`ToolError::CapRootMismatch`], [`ToolError::GitDir`], or [`ToolError::Io`].
pub fn write_file(
    cap: &FsWriteCap,
    path: &ConfinedWritePath<'_>,
    bytes: &[u8],
) -> Result<(), ToolError> {
    if !roots_match(&cap.root, path.root()) {
        return Err(ToolError::CapRootMismatch);
    }
    // The git metadata dir is off-limits to structured writes (so the model can
    // never plant config/hooks that a later git command would honor).
    if path
        .relative()
        .components()
        .any(|c| c.as_os_str() == ".git")
    {
        return Err(ToolError::GitDir);
    }
    let target = path.to_path();
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).map_err(io)?;
    }
    std::fs::write(&target, bytes).map_err(io)
}

/// A single search hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchHit {
    /// Path relative to the worktree root.
    pub path: String,
    /// 1-based line number.
    pub line: u32,
    /// The matching line (bounded, lossy UTF-8).
    pub text: String,
}

/// Searches regular files under the capability's worktree root for `needle`
/// (substring), returning up to `max_hits` hits. Skips the `.git` directory and
/// does not follow symlinked directories (no escape during the walk).
///
/// # Errors
/// [`ToolError::Io`] if the root cannot be read.
pub fn search(cap: &FsReadCap, needle: &str, max_hits: usize) -> Result<Vec<SearchHit>, ToolError> {
    let root = cap.root.as_path().to_path_buf();
    let mut hits = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            if hits.len() >= max_hits {
                return Ok(hits);
            }
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            // metadata() follows symlinks; use symlink_metadata to skip links.
            let ftype = match entry.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if ftype.is_symlink() {
                continue;
            }
            let p = entry.path();
            if ftype.is_dir() {
                if p.file_name().is_some_and(|n| n == ".git") {
                    continue;
                }
                stack.push(p);
            } else if meta.is_file() {
                scan_file(&root, &p, needle, max_hits, &mut hits);
            }
        }
    }
    Ok(hits)
}

fn scan_file(root: &Path, file: &Path, needle: &str, max_hits: usize, hits: &mut Vec<SearchHit>) {
    let Ok(f) = std::fs::File::open(file) else {
        return;
    };
    let mut buf = Vec::new();
    if f.take(DEFAULT_MAX_READ as u64)
        .read_to_end(&mut buf)
        .is_err()
    {
        return;
    }
    let text = String::from_utf8_lossy(&buf);
    let rel = file
        .strip_prefix(root)
        .unwrap_or(file)
        .to_string_lossy()
        .into_owned();
    for (i, line) in text.lines().enumerate() {
        if hits.len() >= max_hits {
            return;
        }
        if line.contains(needle) {
            hits.push(SearchHit {
                path: rel.clone(),
                line: (i as u32).saturating_add(1),
                text: line.chars().take(512).collect(),
            });
        }
    }
}

/// Builds a hardened `git` command rooted at `worktree`: scrubbed environment,
/// no system/global config, no hooks, no pager, no prompts. Callers append the
/// fixed subcommand.
fn hardened_git(worktree: &Path) -> Command {
    let mut c = Command::new("git");
    c.current_dir(worktree)
        // Scrub the environment so model-set GIT_* / injected vars cannot leak in.
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
        .env("HOME", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        // Disable hooks and pager regardless of repo-local config.
        .args(["-c", "core.hooksPath=/dev/null"])
        .args(["-c", "core.pager=cat"])
        .args(["-c", "core.fsmonitor=false"]);
    c
}

fn run_git(mut cmd: Command, stdin: Option<&[u8]>) -> Result<String, ToolError> {
    use std::process::Stdio;
    cmd.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(io)?;
    if let Some(bytes) = stdin {
        use std::io::Write as _;
        if let Some(mut sink) = child.stdin.take() {
            sink.write_all(bytes).map_err(io)?;
        }
    }
    let out = child.wait_with_output().map_err(io)?;
    if out.status.success() {
        let mut stdout = out.stdout;
        stdout.truncate(MAX_GIT_OUTPUT);
        Ok(String::from_utf8_lossy(&stdout).into_owned())
    } else {
        let mut stderr = out.stderr;
        stderr.truncate(MAX_GIT_OUTPUT);
        Err(ToolError::Git(
            String::from_utf8_lossy(&stderr).trim().to_string(),
        ))
    }
}

/// `git status --porcelain` in the worktree (read capability).
///
/// # Errors
/// [`ToolError::Git`] if git fails, [`ToolError::Io`] if it cannot be spawned.
pub fn git_status(cap: &FsReadCap) -> Result<String, ToolError> {
    let mut c = hardened_git(cap.root.as_path());
    c.args(["status", "--porcelain"]);
    run_git(c, None)
}

/// `git diff` of the worktree (read capability).
///
/// # Errors
/// As [`git_status`].
pub fn git_diff(cap: &FsReadCap) -> Result<String, ToolError> {
    let mut c = hardened_git(cap.root.as_path());
    c.args(["diff", "--no-color"]);
    run_git(c, None)
}

/// `git log --oneline -n <max_entries>` (read capability).
///
/// # Errors
/// As [`git_status`].
pub fn git_log(cap: &FsReadCap, max_entries: u32) -> Result<String, ToolError> {
    let mut c = hardened_git(cap.root.as_path());
    c.args([
        "log",
        "--oneline",
        "--no-color",
        "-n",
        &max_entries.to_string(),
    ]);
    run_git(c, None)
}

/// Applies a unified-diff `patch` to the worktree via `git apply` (write
/// capability). git's own path handling confines the patch to the tree (no
/// `--unsafe-paths`); combined with the scrubbed env this is a safe apply.
///
/// # Errors
/// [`ToolError::Git`] if the patch does not apply cleanly.
pub fn git_apply(cap: &FsWriteCap, patch: &[u8]) -> Result<(), ToolError> {
    let mut c = hardened_git(cap.root.as_path());
    c.args(["apply", "--whitespace=nowarn"]);
    run_git(c, Some(patch)).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crustcore_types::ScopeId;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("cc-wt-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p.canonicalize().unwrap()
    }

    fn caps(root: &std::path::Path) -> (WorktreeRoot, WorktreeRoot) {
        (
            WorktreeRoot::open(root).unwrap(),
            WorktreeRoot::open(root).unwrap(),
        )
    }

    #[test]
    fn write_then_read_roundtrips() {
        let dir = temp_dir("rw");
        let root = WorktreeRoot::open(&dir).unwrap();
        let rcap = FsReadCap {
            root: WorktreeRoot::open(&dir).unwrap(),
            scope: ScopeId(1),
        };
        let wcap = FsWriteCap {
            root: WorktreeRoot::open(&dir).unwrap(),
            scope: ScopeId(1),
        };
        let wpath = root.confine_write("src/lib.rs").unwrap();
        write_file(&wcap, &wpath, b"fn main() {}").unwrap();
        let rpath = root.confine_read("src/lib.rs").unwrap();
        let got = read_file(&rcap, &rpath, DEFAULT_MAX_READ).unwrap();
        assert_eq!(got, b"fn main() {}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_into_dot_git_is_refused() {
        let dir = temp_dir("gitdir");
        let root = WorktreeRoot::open(&dir).unwrap();
        let wcap = FsWriteCap {
            root: WorktreeRoot::open(&dir).unwrap(),
            scope: ScopeId(1),
        };
        let wpath = root.confine_write(".git/hooks/pre-commit").unwrap();
        assert!(matches!(
            write_file(&wcap, &wpath, b"#!/bin/sh\nevil").unwrap_err(),
            ToolError::GitDir
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cap_for_other_root_is_rejected() {
        let dir_a = temp_dir("root-a");
        let dir_b = temp_dir("root-b");
        let root_a = WorktreeRoot::open(&dir_a).unwrap();
        let wcap_b = FsWriteCap {
            root: WorktreeRoot::open(&dir_b).unwrap(),
            scope: ScopeId(1),
        };
        let path_in_a = root_a.confine_write("x.txt").unwrap();
        assert!(matches!(
            write_file(&wcap_b, &path_in_a, b"nope").unwrap_err(),
            ToolError::CapRootMismatch
        ));
        let _ = std::fs::remove_dir_all(&dir_a);
        let _ = std::fs::remove_dir_all(&dir_b);
    }

    #[test]
    fn search_finds_matches_and_skips_git() {
        let dir = temp_dir("search");
        let root = WorktreeRoot::open(&dir).unwrap();
        let wcap = FsWriteCap {
            root: WorktreeRoot::open(&dir).unwrap(),
            scope: ScopeId(1),
        };
        let rcap = FsReadCap {
            root: WorktreeRoot::open(&dir).unwrap(),
            scope: ScopeId(1),
        };
        write_file(
            &wcap,
            &root.confine_write("a.txt").unwrap(),
            b"hello\nNEEDLE here\n",
        )
        .unwrap();
        write_file(&wcap, &root.confine_write("b.txt").unwrap(), b"nothing\n").unwrap();
        // A .git file that should be skipped.
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        std::fs::write(dir.join(".git/config"), b"NEEDLE in git\n").unwrap();
        let hits = search(&rcap, "NEEDLE", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].path, "a.txt");
        assert_eq!(hits[0].line, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- git wrappers (require a real repo; the test env has git) ---

    fn git_repo(tag: &str) -> Option<std::path::PathBuf> {
        let dir = temp_dir(tag);
        let init = hardened_git(&dir).args(["init", "-q"]).status().ok()?;
        if !init.success() {
            return None;
        }
        // Commit a file using the hardened, config-scrubbed git (identity via -c).
        std::fs::write(dir.join("README.md"), b"hello\n").ok()?;
        let add = hardened_git(&dir).args(["add", "."]).status().ok()?;
        let commit = hardened_git(&dir)
            .args([
                "-c",
                "user.email=ci@crustcore",
                "-c",
                "user.name=ci",
                "commit",
                "-q",
                "-m",
                "init",
            ])
            .status()
            .ok()?;
        if add.success() && commit.success() {
            Some(dir)
        } else {
            None
        }
    }

    #[test]
    fn git_status_and_log_and_diff_work() {
        let Some(dir) = git_repo("gitwrap") else {
            eprintln!("skipping: git unavailable");
            return;
        };
        let (rroot, _) = caps(&dir);
        let rcap = FsReadCap {
            root: rroot,
            scope: ScopeId(1),
        };
        // Clean tree.
        assert_eq!(git_status(&rcap).unwrap().trim(), "");
        // Modify a tracked file -> status + diff reflect it.
        std::fs::write(dir.join("README.md"), b"hello\nworld\n").unwrap();
        assert!(git_status(&rcap).unwrap().contains("README.md"));
        assert!(git_diff(&rcap).unwrap().contains("+world"));
        // Log shows the init commit.
        assert!(git_log(&rcap, 10).unwrap().contains("init"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn git_apply_applies_a_confined_patch() {
        let Some(dir) = git_repo("gitapply") else {
            eprintln!("skipping: git unavailable");
            return;
        };
        let wcap = FsWriteCap {
            root: WorktreeRoot::open(&dir).unwrap(),
            scope: ScopeId(1),
        };
        // Note: context/added lines must keep their leading " "/"+"; avoid string
        // line-continuations (which strip leading whitespace).
        let patch = concat!(
            "diff --git a/README.md b/README.md\n",
            "--- a/README.md\n",
            "+++ b/README.md\n",
            "@@ -1 +1,2 @@\n",
            " hello\n",
            "+added-line\n",
        );
        git_apply(&wcap, patch.as_bytes()).unwrap();
        assert!(std::fs::read_to_string(dir.join("README.md"))
            .unwrap()
            .contains("added-line"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
