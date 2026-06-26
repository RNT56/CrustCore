// SPDX-License-Identifier: Apache-2.0
//! P14-exec: live repo enumeration via **hardened, dependency-free `git`** invocations.
//!
//! Two seams that feed the deterministic, already-tested transforms in [`crate`]:
//! - [`list_files`] runs `git ls-files` and parses its output into the path listing
//!   [`RepoMap::from_paths`](crate::RepoMap::from_paths) consumes.
//! - [`grep_lines`] runs `git grep -n <pattern>` and parses its output into the
//!   [`SourceLine`](crate::SourceLine)s [`GrepCodeIntel`](crate::GrepCodeIntel) consumes.
//!
//! **Hardened git (invariant 7; `docs/sandbox.md`).** An untrusted repo must not get
//! code-exec via git config: every invocation `env_clear()`s and rebuilds a minimal safe
//! environment, disables hooks/pager/attribute drivers (`-c core.hooksPath=/dev/null
//! -c core.pager=cat -c core.attributesFile=/dev/null`, `GIT_CONFIG_*=/dev/null`,
//! `GIT_TERMINAL_PROMPT=0`), and runs inside the given repo dir. This mirrors
//! `crustcore-worktree::tools::hardened_git`; the parsing here is pure and dependency-free.
//!
//! **Bounded (invariant 11, §6.5).** Output is drained through a cap on both **total bytes**
//! ([`MAX_GIT_OUTPUT_BYTES`]) and **line count** ([`MAX_GIT_OUTPUT_LINES`]) so a hostile repo
//! (millions of tiny files, or one enormous file) cannot OOM the supervisor. The reader keeps
//! draining the pipe past the cap (discarding) so the child never blocks on a full pipe.
//!
//! The **parsing** ([`parse_ls_files`] / [`parse_grep_lines`]) is CI-tested with canned `git`
//! output; the **real `git` invocation** is `#[ignore]`d (it needs a real git repo). This crate
//! stays `#![forbid(unsafe_code)]`.

use std::path::Path;
use std::process::{Command, Stdio};

use crate::SourceLine;

/// Cap on total bytes drained from a `git` stream (bounded — a hostile repo with one
/// enormous file cannot OOM us; invariant 11, §6.5). Anything past this is discarded.
pub const MAX_GIT_OUTPUT_BYTES: usize = 8 * 1024 * 1024;

/// Cap on how many output lines (paths / grep hits) we retain (bounded fan-out — a repo with
/// millions of tiny files cannot blow up the path listing). Excess lines are dropped.
pub const MAX_GIT_OUTPUT_LINES: usize = 200_000;

/// Cap on the bytes of a single retained line (a single pathological line cannot dominate
/// memory; longer lines are truncated on a char boundary).
pub const MAX_GIT_LINE_BYTES: usize = 8 * 1024;

/// Why a live `git` enumeration failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecError {
    /// Spawning / waiting on `git` failed (bounded message).
    Spawn(String),
    /// `git` exited non-zero (bounded stderr tail). For `git grep`, exit code 1 means
    /// "no matches" and is **not** an error — [`grep_lines`] maps it to an empty result.
    Git(String),
    /// The supplied pattern was rejected (empty, or an option-injection attempt).
    BadPattern,
}

impl core::fmt::Display for ExecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ExecError::Spawn(e) => write!(f, "git spawn: {e}"),
            ExecError::Git(e) => write!(f, "git error: {e}"),
            ExecError::BadPattern => write!(f, "rejected git grep pattern"),
        }
    }
}

impl std::error::Error for ExecError {}

/// Builds a hardened `git` [`Command`] rooted at `repo`: scrubbed environment, no
/// system/global config, no hooks, no pager, no attribute drivers, no prompts. The caller
/// appends the fixed subcommand. Mirrors `crustcore-worktree::tools::hardened_git` so the
/// confinement story is identical across the two crates that shell out to `git`.
fn hardened_git(repo: &Path) -> Command {
    let mut c = Command::new("git");
    c.current_dir(repo)
        // Scrub the environment so model-set GIT_* / injected vars cannot leak in.
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
        .env("HOME", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        // Disable hooks, pager, fsmonitor, and any global attributes file regardless of
        // repo-local config — an untrusted repo must not get code-exec via git config.
        .args(["-c", "core.hooksPath=/dev/null"])
        .args(["-c", "core.pager=cat"])
        .args(["-c", "core.fsmonitor=false"])
        .args(["-c", "core.attributesFile=/dev/null"]);
    c
}

/// Runs a prepared hardened `git` command, draining stdout into a **bounded** buffer. Returns
/// `(stdout_text, success, stderr_tail)`. `ok_codes` lists non-zero exit codes the caller
/// treats as success (e.g. `git grep` returns 1 for "no matches").
fn run_capped(mut cmd: Command, ok_codes: &[i32]) -> Result<(String, bool, String), ExecError> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| ExecError::Spawn(e.to_string()))?;

    // Drain BOTH streams on threads into bounded buffers so a hostile repo's git output
    // cannot OOM us and the child never blocks on a full pipe (matches the worktree-tools
    // capped-reader posture).
    let out_h = child
        .stdout
        .take()
        .map(|s| spawn_capped_reader(s, MAX_GIT_OUTPUT_BYTES));
    let err_h = child
        .stderr
        .take()
        // stderr is for diagnostics only; a tighter cap is fine.
        .map(|s| spawn_capped_reader(s, 64 * 1024));

    let status = child.wait().map_err(|e| ExecError::Spawn(e.to_string()))?;
    let stdout = out_h
        .map(|h| h.join().unwrap_or_default())
        .unwrap_or_default();
    let stderr = err_h
        .map(|h| h.join().unwrap_or_default())
        .unwrap_or_default();

    let success = status.success() || status.code().is_some_and(|c| ok_codes.contains(&c));
    Ok((
        String::from_utf8_lossy(&stdout).into_owned(),
        success,
        String::from_utf8_lossy(&stderr).trim().to_string(),
    ))
}

/// Reads `r` to EOF into a buffer capped at `cap` bytes, **continuing to drain** (and
/// discard) anything beyond the cap so the child never blocks on a full pipe.
fn spawn_capped_reader<R: std::io::Read + Send + 'static>(
    mut r: R,
    cap: usize,
) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            match r.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    if buf.len() < cap {
                        let take = (cap - buf.len()).min(n);
                        buf.extend_from_slice(&chunk[..take]);
                    }
                    // Beyond the cap: keep reading to drain, discard the bytes.
                }
                Err(_) => break,
            }
        }
        buf
    })
}

/// Lists the repo's tracked files via `git ls-files`, returning the bounded path listing
/// [`RepoMap::from_paths`](crate::RepoMap::from_paths) consumes.
///
/// Hardened + bounded (see module docs). The path-parsing is pure; the live `git` call is
/// the only non-deterministic part (`#[ignore]`d in tests — it needs a real repo).
///
/// # Errors
/// [`ExecError::Spawn`] if `git` cannot be launched; [`ExecError::Git`] if `git ls-files`
/// exits non-zero (e.g. not a git repo) with a bounded stderr tail.
pub fn list_files(repo: &Path) -> Result<Vec<String>, ExecError> {
    let mut cmd = hardened_git(repo);
    // `--` terminates options so nothing downstream is treated as a flag.
    cmd.args(["ls-files", "--"]);
    let (stdout, success, stderr) = run_capped(cmd, &[])?;
    if !success {
        return Err(ExecError::Git(bounded_tail(&stderr)));
    }
    Ok(parse_ls_files(&stdout))
}

/// Greps tracked files for `pattern` via `git grep -n <pattern>`, returning the bounded
/// [`SourceLine`]s [`GrepCodeIntel`](crate::GrepCodeIntel) consumes.
///
/// `pattern` is treated as a **fixed string** (`-F`) and passed after `-e` + `--`, so a
/// pattern starting with `-` cannot inject a `git grep` option and a regex metacharacter is
/// matched literally (predictable for symbol lookup). An empty pattern is rejected. `git
/// grep` exit code 1 ("no matches") is mapped to an empty result, not an error.
///
/// # Errors
/// [`ExecError::BadPattern`] for an empty pattern; [`ExecError::Spawn`] if `git` cannot be
/// launched; [`ExecError::Git`] if `git grep` exits with a real error (code ≥ 2).
pub fn grep_lines(repo: &Path, pattern: &str) -> Result<Vec<SourceLine>, ExecError> {
    if pattern.is_empty() {
        return Err(ExecError::BadPattern);
    }
    let mut cmd = hardened_git(repo);
    // -I skip binary, -n line numbers, -F fixed string, --no-color, -e <pat> (so a leading
    // '-' in the pattern is data not a flag), then `--` to terminate option parsing.
    cmd.args(["grep", "-I", "-n", "-F", "--no-color", "-e", pattern, "--"]);
    // Exit 1 = "no matches" for git grep; treat it as success (empty result).
    let (stdout, success, stderr) = run_capped(cmd, &[1])?;
    if !success {
        return Err(ExecError::Git(bounded_tail(&stderr)));
    }
    Ok(parse_grep_lines(&stdout))
}

/// Parses `git ls-files` output (one repo-relative path per line) into a bounded path list.
/// Blank lines are skipped; the list is capped at [`MAX_GIT_OUTPUT_LINES`] and each path at
/// [`MAX_GIT_LINE_BYTES`]. Pure + dependency-free (CI-tested with canned output).
#[must_use]
pub fn parse_ls_files(stdout: &str) -> Vec<String> {
    let mut out = Vec::new();
    for raw in stdout.lines() {
        if out.len() >= MAX_GIT_OUTPUT_LINES {
            break;
        }
        let line = raw.trim_end_matches(['\r']).trim();
        if line.is_empty() {
            continue;
        }
        out.push(truncate_on_char_boundary(line, MAX_GIT_LINE_BYTES));
    }
    out
}

/// Parses `git grep -n` output (`path:line:text`) into bounded [`SourceLine`]s. Lines whose
/// shape is unexpected (no `path:line:` prefix, non-numeric or zero line) are skipped. The
/// list is capped at [`MAX_GIT_OUTPUT_LINES`] and each `text` at [`MAX_GIT_LINE_BYTES`].
/// Pure + dependency-free (CI-tested with canned output).
#[must_use]
pub fn parse_grep_lines(stdout: &str) -> Vec<SourceLine> {
    let mut out = Vec::new();
    for raw in stdout.lines() {
        if out.len() >= MAX_GIT_OUTPUT_LINES {
            break;
        }
        let line = raw.trim_end_matches(['\r']);
        // `path:line:text`. Split into exactly the first two colons so a colon in the
        // matched text is preserved verbatim.
        let Some((path, rest)) = line.split_once(':') else {
            continue;
        };
        let Some((num, text)) = rest.split_once(':') else {
            continue;
        };
        if path.is_empty() {
            continue;
        }
        let Ok(line_no) = num.parse::<u32>() else {
            continue;
        };
        if line_no == 0 {
            continue;
        }
        out.push(SourceLine {
            path: truncate_on_char_boundary(path, MAX_GIT_LINE_BYTES),
            line: line_no,
            text: truncate_on_char_boundary(text, MAX_GIT_LINE_BYTES),
        });
    }
    out
}

/// Truncates `s` to at most `max` bytes on a char boundary (alloc-once, never panics).
fn truncate_on_char_boundary(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Keeps a bounded tail of a `git` stderr message for an error (never floods context).
fn bounded_tail(s: &str) -> String {
    truncate_on_char_boundary(s.trim(), 1024)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- parsing (CI-tested with canned `git` output; pure, dependency-free) ---

    #[test]
    fn parse_ls_files_handles_paths_blanks_and_crlf() {
        let canned = "Cargo.toml\r\nsrc/lib.rs\n\nsrc/util/mod.rs\n   \ndocs/readme.md\n";
        let paths = parse_ls_files(canned);
        assert_eq!(
            paths,
            vec![
                "Cargo.toml".to_string(),
                "src/lib.rs".to_string(),
                "src/util/mod.rs".to_string(),
                "docs/readme.md".to_string(),
            ]
        );
        // Feeds RepoMap::from_paths directly.
        let refs: Vec<&str> = paths.iter().map(String::as_str).collect();
        let map = crate::RepoMap::from_paths(&refs);
        assert_eq!(map.file_count, 4);
        assert_eq!(map.by_extension.first().unwrap().0, "rs");
        assert!(map.markers.contains(&"Cargo.toml".to_string()));
    }

    #[test]
    fn parse_ls_files_is_line_bounded() {
        let many = "f.rs\n".repeat(MAX_GIT_OUTPUT_LINES + 100);
        let paths = parse_ls_files(&many);
        assert_eq!(paths.len(), MAX_GIT_OUTPUT_LINES);
    }

    #[test]
    fn parse_ls_files_bounds_long_path() {
        let long = "a".repeat(MAX_GIT_LINE_BYTES + 50);
        let paths = parse_ls_files(&long);
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0].len(), MAX_GIT_LINE_BYTES);
    }

    #[test]
    fn parse_grep_lines_parses_path_line_text() {
        let canned = "src/lib.rs:10:pub fn gateway_check() {}\n\
                      src/other.rs:3:let x = 1;\n";
        let lines = parse_grep_lines(canned);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].path, "src/lib.rs");
        assert_eq!(lines[0].line, 10);
        assert_eq!(lines[0].text, "pub fn gateway_check() {}");
        // Feeds GrepCodeIntel directly.
        let intel = crate::GrepCodeIntel::new(lines);
        let hits = crate::CodeIntel::lookup(&intel, "gateway_check");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].line, 10);
    }

    #[test]
    fn parse_grep_lines_preserves_colons_in_matched_text() {
        // A matched line that itself contains colons must survive (we only split on the
        // first two colons: path:line:rest).
        let canned = "src/net.rs:42:let url = \"http://x:8080/a:b\";\n";
        let lines = parse_grep_lines(canned);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].path, "src/net.rs");
        assert_eq!(lines[0].line, 42);
        assert_eq!(lines[0].text, "let url = \"http://x:8080/a:b\";");
    }

    #[test]
    fn parse_grep_lines_skips_malformed_lines() {
        let canned = "no-colons-here\n\
                      src/a.rs:notanumber:text\n\
                      src/b.rs:0:zero line is dropped\n\
                      :5:empty path dropped\n\
                      src/ok.rs:7:kept\n";
        let lines = parse_grep_lines(canned);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].path, "src/ok.rs");
        assert_eq!(lines[0].line, 7);
        assert_eq!(lines[0].text, "kept");
    }

    #[test]
    fn parse_grep_lines_is_line_bounded() {
        let many = "f.rs:1:x\n".repeat(MAX_GIT_OUTPUT_LINES + 100);
        let lines = parse_grep_lines(&many);
        assert_eq!(lines.len(), MAX_GIT_OUTPUT_LINES);
    }

    #[test]
    fn grep_lines_rejects_empty_pattern() {
        // No git invocation needed: empty pattern is rejected up front.
        let err = grep_lines(Path::new("."), "").unwrap_err();
        assert_eq!(err, ExecError::BadPattern);
    }

    // --- live git invocations (need a real repo; ignored in CI) ---

    #[test]
    #[ignore = "needs a real git repo on PATH; TODO(P14-exec) live invocation"]
    fn live_list_files_on_this_repo() {
        // Run against the crate's own dir; walk up until a repo root is found by git.
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let files = list_files(&dir).expect("git ls-files");
        assert!(!files.is_empty());
        assert!(files.iter().any(|p| p.ends_with("Cargo.toml")));
    }

    #[test]
    #[ignore = "needs a real git repo on PATH; TODO(P14-exec) live invocation"]
    fn live_grep_lines_on_this_repo() {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let hits = grep_lines(&dir, "GrepCodeIntel").expect("git grep");
        assert!(hits.iter().any(|l| l.text.contains("GrepCodeIntel")));
        // A pattern that matches nothing returns an empty result, NOT an error.
        let none = grep_lines(&dir, "zzz_no_such_symbol_zzz_4271").expect("git grep empty");
        assert!(none.is_empty());
    }
}
