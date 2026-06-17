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

/// Whether a path component is the git metadata dir, case-insensitively (so a
/// case-insensitive filesystem cannot smuggle `.GIT` past the guard).
fn is_dot_git(c: std::path::Component<'_>) -> bool {
    c.as_os_str()
        .to_str()
        .is_some_and(|s| s.eq_ignore_ascii_case(".git"))
}

/// Refuses a write whose *real* on-disk location resolves inside `<root>/.git`,
/// catching in-root symlinks that point at the git metadata dir (the lexical
/// component check alone misses these).
fn refuse_real_git_dir(root: &WorktreeRoot, target: &Path) -> Result<(), ToolError> {
    let Ok(root_canon) = root.as_path().canonicalize() else {
        return Ok(()); // root not on disk yet; lexical check already ran
    };
    let git_dir = root_canon.join(".git");
    if let Ok(existing) = crustcore_path::canonical_existing_ancestor(target) {
        // Compare case-insensitively to match case-insensitive filesystems.
        let a = existing.to_string_lossy().to_lowercase();
        let g = git_dir.to_string_lossy().to_lowercase();
        if a == g || a.starts_with(&format!("{g}/")) {
            return Err(ToolError::GitDir);
        }
    }
    Ok(())
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
    // never plant config/hooks that a later git command would honor). Compare
    // case-insensitively: on case-insensitive filesystems (macOS/Windows) `.GIT`
    // is the same directory as `.git`.
    if path.relative().components().any(is_dot_git) {
        return Err(ToolError::GitDir);
    }
    let target = path.to_path();
    // Lexical rejection above is not enough: an in-root symlink (e.g. `link` ->
    // `.git`) would let `link/config` slip past the component check. Resolve the
    // real on-disk location of the deepest existing ancestor and refuse if it
    // lands inside `<root>/.git`.
    refuse_real_git_dir(&cap.root, &target)?;
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
    // Canonicalize the cap root before walking: a cap built from a non-canonical
    // (`WorktreeRoot::new`) symlinked root would otherwise make `read_dir` follow
    // the root symlink and enumerate files outside the intended worktree.
    let root = cap.root.as_path().canonicalize().map_err(io)?;
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
                if p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.eq_ignore_ascii_case(".git"))
                {
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
pub(crate) fn hardened_git(worktree: &Path) -> Command {
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
        // Disable hooks and pager regardless of repo-local config, and ignore any
        // global attributes file (in-tree `.gitattributes` is further neutralized
        // per-command, e.g. `git diff --no-textconv --no-ext-diff`).
        .args(["-c", "core.hooksPath=/dev/null"])
        .args(["-c", "core.pager=cat"])
        .args(["-c", "core.fsmonitor=false"])
        .args(["-c", "core.attributesFile=/dev/null"]);
    c
}

pub(crate) fn run_git(mut cmd: Command, stdin: Option<&[u8]>) -> Result<String, ToolError> {
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

/// Neutralizes attribute-driven git **filter** drivers for the repo by writing
/// `* -filter` to its `.git/info/attributes` (highest-precedence attributes file,
/// name-agnostic). This is the load-bearing defense against arbitrary code
/// execution from an untrusted repo: a repo-local `.git/config`
/// `filter.<n>.clean`/`smudge`/`process` mapped by an in-tree `.gitattributes`
/// would otherwise run during `git diff` (clean) or `git apply` (smudge).
/// `core.attributesFile`/`--no-textconv` do NOT cover in-tree attributes;
/// overriding `info/attributes` does (invariant 7; `docs/sandbox.md`).
///
/// Only `-filter` is set (not `-diff`/`-text`): the diff textconv/external driver
/// RCE is already blocked by `--no-textconv --no-ext-diff` on the diff command,
/// and `-diff` would wrongly turn every textual diff into "binary files differ".
/// Best-effort: if the repo dir cannot be resolved the caller git command will
/// surface the real error.
pub(crate) fn neutralize_attribute_drivers(worktree: &Path) -> Result<(), ToolError> {
    let mut probe = hardened_git(worktree);
    probe.args(["rev-parse", "--git-path", "info/attributes"]);
    let Ok(rel) = run_git(probe, None) else {
        return Ok(()); // not a repo (or git missing); the real command will error
    };
    let rel = rel.trim();
    if rel.is_empty() {
        return Ok(());
    }
    let path = worktree.join(rel);
    // No-follow: a hostile repo could ship `.git/info` or `.git/info/attributes`
    // as a symlink pointing out of the worktree, turning this write into an
    // arbitrary out-of-tree clobber. Refuse rather than write through a symlink
    // (invariant 7; THREAT_MODEL R10 "no-follow writes"). Refusing — not skipping
    // — keeps the neutralizer un-bypassable: a symlinked info/attributes makes the
    // git command fail instead of silently running with filters live.
    for p in [path.parent(), Some(path.as_path())].into_iter().flatten() {
        if let Ok(meta) = std::fs::symlink_metadata(p) {
            if meta.file_type().is_symlink() {
                return Err(ToolError::Git(
                    "refusing: .git/info attributes path is a symlink".to_string(),
                ));
            }
        }
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(io)?;
    }
    const NEUTRALIZER: &str = "* -filter";
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    if !existing.lines().any(|l| l.trim() == NEUTRALIZER) {
        // Append so it is the last (winning) line for filter/diff/text on all paths.
        let mut content = existing;
        if !content.is_empty() && !content.ends_with('\n') {
            content.push('\n');
        }
        content.push_str(NEUTRALIZER);
        content.push('\n');
        std::fs::write(&path, content).map_err(io)?;
    }
    Ok(())
}

/// `git status --porcelain` in the worktree (read capability).
///
/// # Errors
/// [`ToolError::Git`] if git fails, [`ToolError::Io`] if it cannot be spawned.
pub fn git_status(cap: &FsReadCap) -> Result<String, ToolError> {
    neutralize_attribute_drivers(cap.root.as_path())?;
    let mut c = hardened_git(cap.root.as_path());
    c.args(["status", "--porcelain"]);
    run_git(c, None)
}

/// `git status --porcelain --untracked-files=all` (read capability): like
/// [`git_status`] but lists every untracked file **individually** rather than
/// collapsing a new directory to a single entry. The supervisor's worker
/// validation needs per-file paths so each changed file is independently confined
/// (rejecting symlink/`..` escapes) and classified (`docs/backend-contract.md`
/// §4.2). Renames are decomposed (`--no-renames`) so each side is a plain path.
///
/// # Errors
/// As [`git_status`].
pub fn git_status_all(cap: &FsReadCap) -> Result<String, ToolError> {
    neutralize_attribute_drivers(cap.root.as_path())?;
    let mut c = hardened_git(cap.root.as_path());
    c.args([
        "status",
        "--porcelain",
        "--untracked-files=all",
        "--no-renames",
    ]);
    run_git(c, None)
}

/// `git diff` of the worktree (read capability).
///
/// # Errors
/// As [`git_status`].
pub fn git_diff(cap: &FsReadCap) -> Result<String, ToolError> {
    // Neutralize attribute drivers (filter.clean would otherwise run during diff),
    // plus belt-and-braces flags against textconv/external-diff.
    neutralize_attribute_drivers(cap.root.as_path())?;
    let mut c = hardened_git(cap.root.as_path());
    c.args(["diff", "--no-color", "--no-ext-diff", "--no-textconv"]);
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
/// capability). git refuses `../`/absolute paths and writes-through-symlinks (no
/// `--unsafe-paths`); combined with the scrubbed env and the symlink-creation
/// guard below, the patch cannot escape or plant out-of-tree footholds.
///
/// Symlink-*creating* patches (`mode 120000`) are rejected: git would otherwise
/// happily create an in-tree symlink pointing anywhere, a planted foothold a
/// later (symlink-following) tool could traverse. Phase 3 patches are code, not
/// symlinks.
///
/// # Errors
/// [`ToolError::Git`] if the patch creates a symlink or does not apply cleanly.
pub fn git_apply(cap: &FsWriteCap, patch: &[u8]) -> Result<(), ToolError> {
    if patch_creates_symlink(patch) {
        return Err(ToolError::Git(
            "refusing a patch that creates or retargets a symlink (mode 120000)".to_string(),
        ));
    }
    // Critical: `git apply` runs the smudge filter on the working tree. Neutralize
    // attribute-driven filter/diff drivers before applying.
    neutralize_attribute_drivers(cap.root.as_path())?;
    let mut c = hardened_git(cap.root.as_path());
    c.args(["apply", "--whitespace=nowarn"]);
    run_git(c, Some(patch)).map(|_| ())
}

/// Whether a unified diff declares a symlink mode (`120000`) on a real diff
/// extended-header line. Header lines (`new file mode 120000`, `old mode …`,
/// `new mode …`, `deleted file mode …`) sit at column 0; hunk content lines carry
/// a `+`/`-`/space prefix, so we match WITHOUT trimming the leading char to avoid
/// flagging a file content line that merely reads `mode 120000`.
fn patch_creates_symlink(patch: &[u8]) -> bool {
    String::from_utf8_lossy(patch).lines().any(|line| {
        (line.starts_with("new file mode ")
            || line.starts_with("old mode ")
            || line.starts_with("new mode ")
            || line.starts_with("deleted file mode "))
            && line.trim_end().ends_with("120000")
    })
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
        // Case-insensitive: `.GIT` is the same dir on macOS/Windows and is refused.
        let upper = root.confine_write(".GIT/config").unwrap();
        assert!(matches!(
            write_file(&wcap, &upper, b"[core]\n").unwrap_err(),
            ToolError::GitDir
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // An in-root symlink to `.git` must not let a write reach the metadata dir
    // (the lexical component check alone misses this; the canonical check catches
    // it).
    #[test]
    fn write_through_inroot_symlink_to_git_is_refused() {
        let dir = temp_dir("symgit");
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        std::os::unix::fs::symlink(dir.join(".git"), dir.join("link")).unwrap();
        let root = WorktreeRoot::open(&dir).unwrap();
        let wcap = FsWriteCap {
            root: WorktreeRoot::open(&dir).unwrap(),
            scope: ScopeId(1),
        };
        // `link/config` is lexically clean but really resolves into `.git`.
        let wpath = root.confine_write("link/config").unwrap();
        assert!(matches!(
            write_file(&wcap, &wpath, b"[core]\n").unwrap_err(),
            ToolError::GitDir
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // search() must not follow an in-tree symlink that points outside the root.
    #[test]
    fn search_does_not_follow_symlink_outside() {
        let dir = temp_dir("search-sym");
        let outside = temp_dir("search-outside");
        std::fs::write(outside.join("secret.txt"), b"NEEDLE outside\n").unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("escape")).unwrap();
        let rcap = FsReadCap {
            root: WorktreeRoot::open(&dir).unwrap(),
            scope: ScopeId(1),
        };
        let hits = search(&rcap, "NEEDLE", 10).unwrap();
        assert!(
            hits.is_empty(),
            "search followed a symlink outside: {hits:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn git_apply_rejects_symlink_creating_patch() {
        let dir = temp_dir("apply-sym");
        let wcap = FsWriteCap {
            root: WorktreeRoot::open(&dir).unwrap(),
            scope: ScopeId(1),
        };
        let patch = concat!(
            "diff --git a/link b/link\n",
            "new file mode 120000\n",
            "--- /dev/null\n",
            "+++ b/link\n",
            "@@ -0,0 +1 @@\n",
            "+/etc/passwd\n",
            "\\ No newline at end of file\n",
        );
        assert!(matches!(
            git_apply(&wcap, patch.as_bytes()).unwrap_err(),
            ToolError::Git(_)
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

    // RCE regression (critical): a malicious repo-local `.git/config` textconv
    // driver must NOT execute during git_diff (`--no-textconv`/`--no-ext-diff`).
    #[test]
    fn git_diff_does_not_run_repo_textconv_driver() {
        let Some(dir) = git_repo("rce-textconv") else {
            eprintln!("skipping: git unavailable");
            return;
        };
        let marker = dir.join("PWNED");
        // Plant a textconv driver that would run an arbitrary command.
        let mut config = std::fs::read_to_string(dir.join(".git/config")).unwrap();
        config.push_str(&format!(
            "[diff \"evil\"]\n\ttextconv = touch {}\n",
            marker.display()
        ));
        std::fs::write(dir.join(".git/config"), config).unwrap();
        std::fs::write(dir.join(".gitattributes"), b"README.md diff=evil\n").unwrap();
        // Give the diff something to render.
        std::fs::write(dir.join("README.md"), b"hello\nchanged\n").unwrap();

        let rcap = FsReadCap {
            root: WorktreeRoot::open(&dir).unwrap(),
            scope: ScopeId(1),
        };
        let _ = git_diff(&rcap).unwrap();
        assert!(
            !marker.exists(),
            "git_diff executed a repo-local textconv driver (RCE)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // RCE regression (critical): repo-local `filter.<n>.clean`/`smudge` drivers
    // (mapped by in-tree `.gitattributes`) must NOT execute during git_diff
    // (clean) or git_apply (smudge). The `.git/info/attributes` neutralizer
    // disables them.
    #[test]
    fn git_wrappers_do_not_run_repo_filter_drivers() {
        let Some(dir) = git_repo("filter-rce") else {
            eprintln!("skipping: git unavailable");
            return;
        };
        let clean_marker = dir.join("CLEAN_PWNED");
        let smudge_marker = dir.join("SMUDGE_PWNED");

        // Plant a filter driver in the repo-local config.
        let mut config = std::fs::read_to_string(dir.join(".git/config")).unwrap();
        config.push_str(&format!(
            "[filter \"evil\"]\n\tclean = touch {}\n\tsmudge = touch {}\n",
            clean_marker.display(),
            smudge_marker.display()
        ));
        std::fs::write(dir.join(".git/config"), config).unwrap();

        // Commit an in-tree .gitattributes mapping + a tracked file (setup may run
        // the clean filter; we clear markers afterward to isolate the wrappers).
        std::fs::write(dir.join(".gitattributes"), b"*.rs filter=evil\n").unwrap();
        std::fs::write(dir.join("a.rs"), b"x\n").unwrap();
        hardened_git(&dir).args(["add", "."]).status().unwrap();
        hardened_git(&dir)
            .args([
                "-c",
                "user.email=ci@cc",
                "-c",
                "user.name=ci",
                "commit",
                "-q",
                "-m",
                "attrs",
            ])
            .status()
            .unwrap();

        // git_diff: clean must not run.
        std::fs::write(dir.join("a.rs"), b"y\n").unwrap();
        let _ = std::fs::remove_file(&clean_marker);
        let rcap = FsReadCap {
            root: WorktreeRoot::open(&dir).unwrap(),
            scope: ScopeId(1),
        };
        let _ = git_diff(&rcap);
        assert!(
            !clean_marker.exists(),
            "git_diff executed a repo filter.clean driver (RCE)"
        );

        // git_apply: smudge must not run.
        hardened_git(&dir)
            .args(["checkout", "--", "a.rs"])
            .status()
            .ok();
        let _ = std::fs::remove_file(&smudge_marker);
        let wcap = FsWriteCap {
            root: WorktreeRoot::open(&dir).unwrap(),
            scope: ScopeId(1),
        };
        let patch = concat!(
            "--- a/a.rs\n",
            "+++ b/a.rs\n",
            "@@ -1 +1,2 @@\n",
            " x\n",
            "+added\n"
        );
        let _ = git_apply(&wcap, patch.as_bytes());
        assert!(
            !smudge_marker.exists(),
            "git_apply executed a repo filter.smudge driver (RCE)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // A hostile repo that symlinks .git/info/attributes out of the worktree must
    // not get our neutralizer write redirected through it (no-follow; invariant 7).
    #[test]
    fn neutralizer_refuses_symlinked_info_attributes() {
        let Some(dir) = git_repo("info-symlink") else {
            eprintln!("skipping: git unavailable");
            return;
        };
        let outside = temp_dir("info-outside");
        let victim = outside.join("victim.txt");
        std::fs::write(&victim, b"original-contents\n").unwrap();
        // Replace .git/info/attributes with a symlink to the outside victim.
        std::fs::create_dir_all(dir.join(".git/info")).unwrap();
        let attrs = dir.join(".git/info/attributes");
        let _ = std::fs::remove_file(&attrs);
        std::os::unix::fs::symlink(&victim, &attrs).unwrap();

        let rcap = FsReadCap {
            root: WorktreeRoot::open(&dir).unwrap(),
            scope: ScopeId(1),
        };
        // The wrapper refuses rather than following the symlink.
        assert!(matches!(git_status(&rcap), Err(ToolError::Git(_))));
        // The out-of-tree victim is untouched.
        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "original-contents\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&outside);
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
