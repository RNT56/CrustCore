// SPDX-License-Identifier: Apache-2.0
//! Typed, worktree-confined paths (`ROADMAP.md` §8.2, Phase 3).
//!
//! The whole point of this crate is that **structured file tools accept only
//! confined paths** — a raw `&str`/`PathBuf` can never reach `write_file`. Only
//! the resolver in this crate can mint a [`ConfinedReadPath`]/[`ConfinedWritePath`],
//! and it does so only after rejecting null bytes, absolute escapes, and symlink
//! escapes. See invariant 7 and `tests/redteam` (malicious path fixtures).
//!
//! Status: Phase 0 scaffold. The *types* and resolver API are in place; the
//! symlink-safe resolution and no-follow write semantics are implemented in
//! Phase 3 (`TODO(P3.*)`).
#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

/// The root of a task's throwaway worktree. All confined paths are relative to a
/// `WorktreeRoot` and can never escape it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorktreeRoot(PathBuf);

/// A path that has been validated for reading within a [`WorktreeRoot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfinedReadPath<'root> {
    root: &'root WorktreeRoot,
    relative: PathBuf,
}

/// A path that has been validated for writing within a [`WorktreeRoot`]
/// (no-follow semantics where available).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfinedWritePath<'root> {
    root: &'root WorktreeRoot,
    relative: PathBuf,
}

/// Why a path was rejected by the resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    /// The path contained an interior NUL byte.
    NullByte,
    /// An absolute path was supplied where only a relative one is allowed.
    AbsoluteNotAllowed,
    /// The normalized path escaped the worktree root (e.g. via `..`).
    Escape,
    /// A symlink in the path would resolve outside the worktree root.
    SymlinkEscape,
    /// The path could not be resolved for an I/O reason.
    Io(String),
}

impl core::fmt::Display for PathError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PathError::NullByte => write!(f, "path contains a NUL byte"),
            PathError::AbsoluteNotAllowed => write!(f, "absolute path is not allowed here"),
            PathError::Escape => write!(f, "path escapes the worktree root"),
            PathError::SymlinkEscape => write!(f, "path escapes via a symlink"),
            PathError::Io(e) => write!(f, "path resolution io error: {e}"),
        }
    }
}

impl std::error::Error for PathError {}

impl WorktreeRoot {
    /// Wraps an existing directory as a worktree root.
    ///
    /// In Phase 3 this will canonicalize and verify the directory exists and is
    /// a directory; for now it stores the path.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        WorktreeRoot(path.into())
    }

    /// Returns the root as a path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// Resolves a relative path for reading inside this root.
    ///
    /// # Errors
    /// Returns [`PathError`] if the path is absolute, contains a NUL byte,
    /// escapes the root, or escapes via a symlink.
    pub fn confine_read<'a>(&'a self, rel: &str) -> Result<ConfinedReadPath<'a>, PathError> {
        let relative = self.validate(rel)?;
        Ok(ConfinedReadPath {
            root: self,
            relative,
        })
    }

    /// Resolves a relative path for writing inside this root (no-follow).
    ///
    /// # Errors
    /// Returns [`PathError`] under the same conditions as [`Self::confine_read`].
    pub fn confine_write<'a>(&'a self, rel: &str) -> Result<ConfinedWritePath<'a>, PathError> {
        let relative = self.validate(rel)?;
        Ok(ConfinedWritePath {
            root: self,
            relative,
        })
    }

    /// Shared validation. TODO(P3.2): normalize, resolve the deepest existing
    /// ancestor, and reject symlink escapes with no-follow semantics. This
    /// scaffold rejects the obvious cases so the type contract is real.
    fn validate(&self, rel: &str) -> Result<PathBuf, PathError> {
        if rel.as_bytes().contains(&0) {
            return Err(PathError::NullByte);
        }
        let p = Path::new(rel);
        if p.is_absolute() {
            return Err(PathError::AbsoluteNotAllowed);
        }
        if p.components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            // TODO(P3.2): allow interior `..` that still resolves within root;
            // for now any `..` is rejected as a conservative default.
            return Err(PathError::Escape);
        }
        Ok(p.to_path_buf())
    }
}

impl ConfinedReadPath<'_> {
    /// The absolute path on disk (root joined with the validated relative path).
    #[must_use]
    pub fn to_path(&self) -> PathBuf {
        self.root.as_path().join(&self.relative)
    }

    /// The validated relative component.
    #[must_use]
    pub fn relative(&self) -> &Path {
        &self.relative
    }
}

impl ConfinedWritePath<'_> {
    /// The absolute path on disk (root joined with the validated relative path).
    #[must_use]
    pub fn to_path(&self) -> PathBuf {
        self.root.as_path().join(&self.relative)
    }

    /// The validated relative component.
    #[must_use]
    pub fn relative(&self) -> &Path {
        &self.relative
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_absolute_paths() {
        let root = WorktreeRoot::new("/tmp/wt");
        assert_eq!(
            root.confine_write("/etc/passwd").unwrap_err(),
            PathError::AbsoluteNotAllowed
        );
    }

    #[test]
    fn rejects_parent_escape() {
        let root = WorktreeRoot::new("/tmp/wt");
        assert_eq!(
            root.confine_read("../secrets").unwrap_err(),
            PathError::Escape
        );
    }

    #[test]
    fn accepts_simple_relative() {
        let root = WorktreeRoot::new("/tmp/wt");
        let p = root.confine_write("src/main.rs").unwrap();
        assert_eq!(p.relative(), Path::new("src/main.rs"));
    }
}
