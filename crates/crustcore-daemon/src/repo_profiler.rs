// SPDX-License-Identifier: Apache-2.0
//! Bounded repo path profiler for verifier planning.
//!
//! The profiler observes file names only. It does not read repo contents, follow
//! symlinks, run commands, mint authority, or prove completion. Its output feeds
//! the pure product-layer verifier planner, which still requires sandboxed
//! command evidence before a patch can complete.

use std::fmt;
use std::fs;
use std::path::Path;

use crate::product::{RepoProfile, RepoSignals, TaskShape, VerifierPlan};

/// Default maximum traversal depth from the repo root.
pub const DEFAULT_PROFILE_MAX_DEPTH: usize = 4;

/// Default maximum observed path count.
pub const DEFAULT_PROFILE_MAX_PATHS: usize = 512;

const MAX_PROFILE_PATH_LEN: usize = 512;

/// Bounded traversal settings for repo profiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepoProfilerConfig {
    /// Maximum directory depth to traverse below the root.
    pub max_depth: usize,
    /// Maximum relative paths to retain.
    pub max_paths: usize,
}

impl Default for RepoProfilerConfig {
    fn default() -> Self {
        RepoProfilerConfig {
            max_depth: DEFAULT_PROFILE_MAX_DEPTH,
            max_paths: DEFAULT_PROFILE_MAX_PATHS,
        }
    }
}

/// Bounded marker-path snapshot of a repo.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RepoPathSnapshot {
    /// Relative path observations, sorted deterministically by traversal order.
    pub paths: Vec<String>,
    /// Whether traversal hit `max_depth` or `max_paths`.
    pub truncated: bool,
    /// Symlinks skipped rather than followed.
    pub skipped_symlinks: usize,
    /// Invalid or overlong path components skipped.
    pub skipped_paths: usize,
}

impl RepoPathSnapshot {
    /// Profiles a repo root with default bounds.
    ///
    /// # Errors
    /// Returns an error when the root is not a readable directory.
    pub fn profile(root: impl AsRef<Path>) -> Result<Self, RepoProfilerError> {
        Self::profile_with_config(root, RepoProfilerConfig::default())
    }

    /// Profiles a repo root with explicit bounds.
    ///
    /// # Errors
    /// Returns an error when the root is not a readable directory.
    pub fn profile_with_config(
        root: impl AsRef<Path>,
        config: RepoProfilerConfig,
    ) -> Result<Self, RepoProfilerError> {
        let root = root.as_ref();
        let metadata = fs::symlink_metadata(root).map_err(|err| {
            RepoProfilerError::new("", format!("cannot inspect repo root: {err}"))
        })?;
        if !metadata.is_dir() {
            return Err(RepoProfilerError::new("", "repo root is not a directory"));
        }

        let mut snapshot = RepoPathSnapshot::default();
        profile_dir(root, "", 0, config, &mut snapshot)?;
        Ok(snapshot)
    }

    /// Converts observed paths into verifier-planner repo signals.
    #[must_use]
    pub fn to_signals(&self) -> RepoSignals {
        RepoSignals::from_paths(self.paths.iter().map(String::as_str))
    }

    /// Plans verification by combining profiled repo paths with changed paths.
    ///
    /// Changed paths are treated as untrusted path observations and are only used
    /// for sanitized targeted hints. They do not prove task completion.
    #[must_use]
    pub fn plan_verification<I, P>(
        &self,
        profile: &RepoProfile,
        changed_paths: I,
        task: TaskShape,
    ) -> VerifierPlan
    where
        I: IntoIterator<Item = P>,
        P: AsRef<str>,
    {
        let signals = RepoSignals::from_repo_and_changed_paths(
            self.paths.iter().map(String::as_str),
            changed_paths,
        );
        profile.plan_verification(&signals, task)
    }
}

/// Repo profiler failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoProfilerError {
    /// Relative path where profiling failed; empty means the repo root.
    pub path: String,
    /// Human-readable failure reason.
    pub reason: String,
}

impl RepoProfilerError {
    fn new(path: impl Into<String>, reason: impl Into<String>) -> Self {
        RepoProfilerError {
            path: path.into(),
            reason: reason.into(),
        }
    }
}

impl fmt::Display for RepoProfilerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.path.is_empty() {
            write!(f, "repo profiler: {}", self.reason)
        } else {
            write!(f, "repo profiler: {}: {}", self.path, self.reason)
        }
    }
}

impl std::error::Error for RepoProfilerError {}

fn profile_dir(
    root: &Path,
    rel_dir: &str,
    depth: usize,
    config: RepoProfilerConfig,
    snapshot: &mut RepoPathSnapshot,
) -> Result<bool, RepoProfilerError> {
    if snapshot.paths.len() >= config.max_paths {
        snapshot.truncated = true;
        return Ok(false);
    }

    let dir = if rel_dir.is_empty() {
        root.to_path_buf()
    } else {
        root.join(rel_dir)
    };
    let mut entries = Vec::new();
    for entry in fs::read_dir(&dir)
        .map_err(|err| RepoProfilerError::new(rel_dir, format!("cannot read directory: {err}")))?
    {
        entries.push(
            entry.map_err(|err| {
                RepoProfilerError::new(rel_dir, format!("cannot read entry: {err}"))
            })?,
        );
    }
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        if snapshot.paths.len() >= config.max_paths {
            snapshot.truncated = true;
            return Ok(false);
        }

        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            snapshot.skipped_paths += 1;
            continue;
        };
        if !safe_component_name(name) {
            snapshot.skipped_paths += 1;
            continue;
        }
        if should_skip_dir_name(name) {
            continue;
        }

        let child_rel = join_rel(rel_dir, name);
        if child_rel.len() > MAX_PROFILE_PATH_LEN {
            snapshot.skipped_paths += 1;
            continue;
        }

        let file_type = entry.file_type().map_err(|err| {
            RepoProfilerError::new(&child_rel, format!("cannot inspect entry: {err}"))
        })?;
        if file_type.is_symlink() {
            snapshot.skipped_symlinks += 1;
            continue;
        }

        push_profile_path(snapshot, child_rel.clone(), config);
        if file_type.is_dir() {
            if depth >= config.max_depth {
                snapshot.truncated = true;
                continue;
            }
            if !profile_dir(root, &child_rel, depth + 1, config, snapshot)? {
                return Ok(false);
            }
        }
    }

    Ok(true)
}

fn push_profile_path(snapshot: &mut RepoPathSnapshot, path: String, config: RepoProfilerConfig) {
    if snapshot.paths.len() >= config.max_paths {
        snapshot.truncated = true;
        return;
    }
    snapshot.paths.push(path);
}

fn join_rel(parent: &str, child: &str) -> String {
    if parent.is_empty() {
        child.to_string()
    } else {
        format!("{parent}/{child}")
    }
}

fn safe_component_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && !name.chars().any(char::is_control)
}

fn should_skip_dir_name(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | ".hg"
            | ".svn"
            | "target"
            | "node_modules"
            | ".next"
            | ".turbo"
            | "dist"
            | "build"
            | ".venv"
            | "__pycache__"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn profiler_feeds_repo_markers_and_changed_path_hints_into_planner() {
        let root = TestRepo::new("planner");
        root.file("Cargo.toml");
        root.file("pyproject.toml");
        root.file("crates/crustcore-daemon/src/product.rs");
        root.file("tests/test_smoke.py");

        let snapshot = RepoPathSnapshot::profile(root.path()).unwrap();

        assert!(snapshot.paths.contains(&"Cargo.toml".to_string()));
        assert!(snapshot.paths.contains(&"pyproject.toml".to_string()));
        assert!(!snapshot.truncated);

        let plan = snapshot.plan_verification(
            &RepoProfile::default(),
            [
                "crates/crustcore-daemon/src/product.rs",
                "tests/test_smoke.py",
            ],
            TaskShape::Feature,
        );

        assert_eq!(plan.commands[0].command, "cargo test -p crustcore-daemon");
        assert_eq!(
            plan.commands[0].stage,
            crate::product::VerifierCommandStage::Targeted
        );
        assert!(plan
            .command_lines()
            .contains(&"python -m pytest tests/test_smoke.py"));
        assert!(plan.command_lines().contains(&"cargo test --workspace"));
    }

    #[test]
    fn profiler_is_deterministic_bounded_and_skips_build_dirs() {
        let root = TestRepo::new("bounded");
        root.file("b.txt");
        root.file("a.txt");
        root.file("target/ignored.rs");
        root.file("node_modules/ignored.js");

        let snapshot = RepoPathSnapshot::profile_with_config(
            root.path(),
            RepoProfilerConfig {
                max_depth: DEFAULT_PROFILE_MAX_DEPTH,
                max_paths: DEFAULT_PROFILE_MAX_PATHS,
            },
        )
        .unwrap();

        assert_eq!(
            snapshot.paths,
            vec!["a.txt".to_string(), "b.txt".to_string()]
        );
        assert!(!snapshot.truncated);
    }

    #[test]
    fn profiler_marks_truncated_when_path_cap_is_hit() {
        let root = TestRepo::new("path-cap");
        root.file("a.txt");
        root.file("b.txt");
        root.file("c.txt");

        let snapshot = RepoPathSnapshot::profile_with_config(
            root.path(),
            RepoProfilerConfig {
                max_depth: DEFAULT_PROFILE_MAX_DEPTH,
                max_paths: 2,
            },
        )
        .unwrap();

        assert_eq!(
            snapshot.paths,
            vec!["a.txt".to_string(), "b.txt".to_string()]
        );
        assert!(snapshot.truncated);
    }

    #[test]
    fn profiler_marks_truncated_when_depth_cap_is_hit() {
        let root = TestRepo::new("depth-cap");
        root.file("a/b/c.txt");

        let snapshot = RepoPathSnapshot::profile_with_config(
            root.path(),
            RepoProfilerConfig {
                max_depth: 1,
                max_paths: DEFAULT_PROFILE_MAX_PATHS,
            },
        )
        .unwrap();

        assert!(snapshot.paths.contains(&"a".to_string()));
        assert!(snapshot.paths.contains(&"a/b".to_string()));
        assert!(!snapshot.paths.contains(&"a/b/c.txt".to_string()));
        assert!(snapshot.truncated);
    }

    #[cfg(unix)]
    #[test]
    fn profiler_skips_symlinks() {
        use std::os::unix::fs::symlink;

        let root = TestRepo::new("symlink");
        root.file("Cargo.toml");
        symlink(
            root.path().join("Cargo.toml"),
            root.path().join("linked.toml"),
        )
        .unwrap();

        let snapshot = RepoPathSnapshot::profile(root.path()).unwrap();

        assert!(snapshot.paths.contains(&"Cargo.toml".to_string()));
        assert!(!snapshot.paths.contains(&"linked.toml".to_string()));
        assert_eq!(snapshot.skipped_symlinks, 1);
    }

    #[test]
    fn profiler_rejects_non_directory_root() {
        let root = TestRepo::new("not-dir");
        root.file("file.txt");

        let err = RepoPathSnapshot::profile(root.path().join("file.txt")).unwrap_err();

        assert!(err.reason.contains("not a directory"));
    }

    struct TestRepo {
        root: std::path::PathBuf,
    }

    impl TestRepo {
        fn new(label: &str) -> Self {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let root = std::env::temp_dir().join(format!(
                "crustcore-repo-profiler-{label}-{}-{nanos}",
                std::process::id()
            ));
            fs::create_dir_all(&root).unwrap();
            TestRepo { root }
        }

        fn path(&self) -> &Path {
            &self.root
        }

        fn file(&self, rel: &str) {
            let path = self.root.join(rel);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            File::create(path).unwrap();
        }
    }

    impl Drop for TestRepo {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
