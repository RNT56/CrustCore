// SPDX-License-Identifier: Apache-2.0
//! Typed, worktree-confined paths (`ROADMAP.md` §8.2, Phase 3).
//!
//! The whole point of this crate is that **structured file tools accept only
//! confined paths** — a raw `&str`/`PathBuf` can never reach `write_file`. Only
//! the resolver here can mint a [`ConfinedReadPath`]/[`ConfinedWritePath`], and it
//! does so only after:
//!
//! 1. rejecting NUL bytes and absolute paths,
//! 2. **lexically normalizing** the path (resolving `.`/`..`), rejecting any path
//!    that pops above the root,
//! 3. **symlink-escape checking**: canonicalizing the deepest existing ancestor
//!    and requiring it to stay under the canonical worktree root, and
//! 4. for writes, **no-follow** semantics: refusing to write through a final
//!    component that is an existing symlink.
//!
//! Together these enforce "no arbitrary path string reaches a write tool" and
//! "symlink escapes fail" (Phase 3 acceptance; invariant 7). The residual TOCTOU
//! window between check and open is narrowed by the sandbox (Phase 4) and the
//! no-follow rule; full `openat`/`O_NOFOLLOW` would need `unsafe`/libc, which this
//! crate forbids.
#![forbid(unsafe_code)]

use std::path::{Component, Path, PathBuf};

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
/// (no-follow semantics on the final component).
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

/// Lexically normalizes a relative path: rejects NUL bytes and absolute paths,
/// drops `.`, and applies `..` by popping — rejecting any path that would pop
/// above the root. Returns the normalized (no `.`/`..`) relative path. This is
/// purely textual; the fs symlink check is separate.
fn normalize_relative(rel: &str) -> Result<PathBuf, PathError> {
    if rel.as_bytes().contains(&0) {
        return Err(PathError::NullByte);
    }
    let p = Path::new(rel);
    let mut out: Vec<std::ffi::OsString> = Vec::new();
    for comp in p.components() {
        match comp {
            Component::Prefix(_) | Component::RootDir => return Err(PathError::AbsoluteNotAllowed),
            Component::CurDir => {}
            Component::ParentDir => {
                if out.pop().is_none() {
                    return Err(PathError::Escape);
                }
            }
            Component::Normal(c) => out.push(c.to_os_string()),
        }
    }
    let mut norm = PathBuf::new();
    for c in out {
        norm.push(c);
    }
    Ok(norm)
}

/// Canonicalizes the deepest existing ancestor of `target` (resolving any
/// symlinks along the way). A non-existent leaf (a file about to be created)
/// walks up to the nearest existing directory. Useful to callers that need the
/// *real* on-disk location of a would-be path (e.g. to reject writes that land
/// in `.git` via an in-root symlink).
///
/// # Errors
/// [`PathError::Io`] if no ancestor exists or canonicalization fails.
pub fn canonical_existing_ancestor(target: &Path) -> Result<PathBuf, PathError> {
    deepest_existing_canonical(target)
}

/// Canonicalizes the deepest existing ancestor of `target`. A non-existent leaf
/// (a file about to be created) walks up to the nearest existing directory.
fn deepest_existing_canonical(target: &Path) -> Result<PathBuf, PathError> {
    let mut cur = target;
    loop {
        match cur.canonicalize() {
            Ok(canon) => return Ok(canon),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => match cur.parent() {
                Some(parent) if !parent.as_os_str().is_empty() => cur = parent,
                _ => return Err(PathError::Io("no existing ancestor".to_string())),
            },
            Err(e) => return Err(PathError::Io(e.to_string())),
        }
    }
}

/// Requires the deepest existing ancestor of `target` to canonicalize to a path
/// under `root_canonical` — i.e. no symlink along the way escapes the root.
fn assert_under_root(root_canonical: &Path, target: &Path) -> Result<(), PathError> {
    let canon = deepest_existing_canonical(target)?;
    if canon.starts_with(root_canonical) {
        Ok(())
    } else {
        Err(PathError::SymlinkEscape)
    }
}

impl WorktreeRoot {
    /// Wraps a path as a worktree root **without** canonicalizing it — for tests
    /// and value-holding only.
    ///
    /// **Do not** build a capability token from a `new()` root that might be a
    /// symlink: the tools would then confine to the symlink's *target*. Use
    /// [`WorktreeRoot::open`] (which canonicalizes) for any root that gates real
    /// filesystem access.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        WorktreeRoot(path.into())
    }

    /// Opens an existing directory as a worktree root, canonicalizing it (so the
    /// root itself is symlink-resolved) and verifying it is a directory.
    ///
    /// # Errors
    /// Returns [`PathError::Io`] if the path does not exist or is not a directory.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PathError> {
        let canon = path
            .as_ref()
            .canonicalize()
            .map_err(|e| PathError::Io(e.to_string()))?;
        if !canon.is_dir() {
            return Err(PathError::Io(
                "worktree root is not a directory".to_string(),
            ));
        }
        Ok(WorktreeRoot(canon))
    }

    /// Returns the root as a path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// The canonical root (symlinks resolved), used for confinement comparisons.
    fn canonical(&self) -> Result<PathBuf, PathError> {
        self.0
            .canonicalize()
            .map_err(|e| PathError::Io(e.to_string()))
    }

    /// Resolves a relative path for reading inside this root.
    ///
    /// # Errors
    /// Returns [`PathError`] if the path is absolute, contains a NUL byte,
    /// escapes the root lexically, or escapes via a symlink.
    pub fn confine_read<'a>(&'a self, rel: &str) -> Result<ConfinedReadPath<'a>, PathError> {
        let relative = normalize_relative(rel)?;
        let root_canonical = self.canonical()?;
        let target = root_canonical.join(&relative);
        assert_under_root(&root_canonical, &target)?;
        Ok(ConfinedReadPath {
            root: self,
            relative,
        })
    }

    /// Resolves a relative path for writing inside this root (no-follow on the
    /// final component).
    ///
    /// # Errors
    /// Returns [`PathError`] under the same conditions as [`Self::confine_read`],
    /// and [`PathError::SymlinkEscape`] if the final component is an existing
    /// symlink (writing through it is refused).
    pub fn confine_write<'a>(&'a self, rel: &str) -> Result<ConfinedWritePath<'a>, PathError> {
        let relative = normalize_relative(rel)?;
        if relative.as_os_str().is_empty() {
            // The root itself is not a writable file target.
            return Err(PathError::Escape);
        }
        let root_canonical = self.canonical()?;
        let target = root_canonical.join(&relative);

        // No-follow: never write through an existing symlink leaf.
        if let Ok(meta) = std::fs::symlink_metadata(&target) {
            if meta.file_type().is_symlink() {
                return Err(PathError::SymlinkEscape);
            }
        }
        // The parent directory must resolve under the root (catches symlinked
        // ancestor directories pointing outside).
        let parent = target.parent().ok_or(PathError::Escape)?;
        assert_under_root(&root_canonical, parent)?;

        Ok(ConfinedWritePath {
            root: self,
            relative,
        })
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

    /// The worktree root this path is confined to.
    #[must_use]
    pub fn root(&self) -> &WorktreeRoot {
        self.root
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

    /// The worktree root this path is confined to.
    #[must_use]
    pub fn root(&self) -> &WorktreeRoot {
        self.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A unique temp directory for an isolated worktree fixture.
    fn temp_root(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("cc-path-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        // Canonicalize so comparisons are stable (macOS /tmp -> /private/tmp).
        p.canonicalize().unwrap()
    }

    // --- Lexical checks (no real fs needed; rejected before fs touch) ---

    #[test]
    fn rejects_absolute_paths() {
        let root = WorktreeRoot::new("/tmp/does-not-matter");
        assert_eq!(
            root.confine_write("/etc/passwd").unwrap_err(),
            PathError::AbsoluteNotAllowed
        );
    }

    #[test]
    fn rejects_parent_escape() {
        let root = WorktreeRoot::new("/tmp/does-not-matter");
        assert_eq!(
            root.confine_read("../secrets").unwrap_err(),
            PathError::Escape
        );
        assert_eq!(
            root.confine_read("a/../../etc").unwrap_err(),
            PathError::Escape
        );
    }

    #[test]
    fn rejects_nul_byte() {
        let root = WorktreeRoot::new("/tmp/does-not-matter");
        assert_eq!(root.confine_read("a\0b").unwrap_err(), PathError::NullByte);
    }

    #[test]
    fn normalizes_interior_dot_and_parent() {
        assert_eq!(
            normalize_relative("src/./a/../main.rs").unwrap(),
            PathBuf::from("src/main.rs")
        );
    }

    // --- Real-fs confinement / symlink fixtures (P3.6) ---

    #[test]
    fn accepts_simple_relative_in_real_root() {
        let dir = temp_root("simple");
        let root = WorktreeRoot::open(&dir).unwrap();
        let p = root.confine_write("src/main.rs").unwrap();
        assert_eq!(p.relative(), Path::new("src/main.rs"));
        let r = root.confine_read("src/main.rs").unwrap();
        assert_eq!(r.relative(), Path::new("src/main.rs"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn symlink_to_outside_is_rejected_on_read() {
        let dir = temp_root("symesc-read");
        // Create a symlink inside the root pointing at /etc (outside).
        let link = dir.join("escape");
        std::os::unix::fs::symlink("/etc", &link).unwrap();
        let root = WorktreeRoot::open(&dir).unwrap();
        // Reading through the escaping symlink must fail.
        assert_eq!(
            root.confine_read("escape/passwd").unwrap_err(),
            PathError::SymlinkEscape
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_through_symlink_leaf_is_refused() {
        let dir = temp_root("symesc-write");
        // A symlink leaf pointing outside the root.
        let link = dir.join("evil");
        std::os::unix::fs::symlink("/tmp/cc-should-not-write", &link).unwrap();
        let root = WorktreeRoot::open(&dir).unwrap();
        assert_eq!(
            root.confine_write("evil").unwrap_err(),
            PathError::SymlinkEscape
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn symlinked_parent_dir_to_outside_is_rejected() {
        let dir = temp_root("symesc-parent");
        let link = dir.join("outdir");
        std::os::unix::fs::symlink("/tmp", &link).unwrap();
        let root = WorktreeRoot::open(&dir).unwrap();
        // Writing into a symlinked-out directory must fail.
        assert_eq!(
            root.confine_write("outdir/pwned").unwrap_err(),
            PathError::SymlinkEscape
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn in_root_symlink_is_allowed() {
        let dir = temp_root("sym-inroot");
        std::fs::create_dir_all(dir.join("real")).unwrap();
        // A symlink that stays inside the root is fine for reads.
        std::os::unix::fs::symlink(dir.join("real"), dir.join("alias")).unwrap();
        let root = WorktreeRoot::open(&dir).unwrap();
        assert!(root.confine_read("alias/file.txt").is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
