// SPDX-License-Identifier: Apache-2.0
//! Sandbox profiles and backends (`ROADMAP.md` §10; Phase 4). Every
//! execution-capable operation runs under an explicit sandbox profile
//! (invariant 9), with deny-all egress by default and a sanitized environment
//! (`docs/sandbox.md`).
//!
//! Status: implemented (Phase 4). Profiles/tiers, the backend trait, the Linux
//! `bubblewrap` backend (deny-all egress), env sanitation, and path-list env
//! validation are in place; execution is refused when no backend is available.
//!
//! NOTE: unlike the pure kernel crates, the real backends here will require
//! `unsafe`/FFI for syscalls. Such code must be isolated, justified, and tested
//! (CLAUDE.md §6.5); add `#![deny(unsafe_code)]` exceptions per-module with a
//! written rationale rather than relaxing it crate-wide.
#![forbid(unsafe_code)]

use crustcore_runner::{CommandResult, CommandSpec};

/// Execution tiers (`ROADMAP.md` §10.1). Ordered by **isolation strength** (the variant
/// order): `None` < `StructuredHost` < `Sandboxed` < `Hostile`, so a higher tier means
/// stronger isolation. [`select_backend`] uses this order to refuse rather than downgrade
/// (a Tier-3 task never runs in a Tier-2 backend).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ExecutionTier {
    /// Tier 0: no execution (planning, review, summarization).
    None,
    /// Tier 1: structured host-side, no arbitrary execution (confined file ops).
    StructuredHost,
    /// Tier 2: sandboxed execution (tests, builds, shell, external workers).
    Sandboxed,
    /// Tier 3: hostile execution (untrusted code; microVM/container, net denied).
    Hostile,
}

/// Network posture for a sandbox profile.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkPosture {
    /// Deny all egress (default).
    #[default]
    DenyAll,
    /// Allow only the profile's allowlisted domains via the trusted proxy.
    Allowlist,
}

/// A sandbox execution profile.
#[derive(Debug, Clone)]
pub struct SandboxProfile {
    /// The execution tier this profile grants.
    pub tier: ExecutionTier,
    /// The network posture (deny-all by default).
    pub network: NetworkPosture,
    /// Environment variable names that are stripped before launch
    /// (`docs/sandbox.md` env sanitation list).
    pub stripped_env: Vec<String>,
}

impl SandboxProfile {
    /// A conservative default profile: sandboxed tier, deny-all network, and the
    /// standard dangerous-variable strip list.
    #[must_use]
    pub fn default_sandboxed() -> Self {
        SandboxProfile {
            tier: ExecutionTier::Sandboxed,
            network: NetworkPosture::DenyAll,
            stripped_env: default_stripped_env(),
        }
    }
}

/// Default list of environment variables stripped before any sandbox launch
/// (`ROADMAP.md` §10.4). Path-list variables are additionally validated
/// component-by-component in Phase 4.
#[must_use]
pub fn default_stripped_env() -> Vec<String> {
    [
        // Loader injection.
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        // Git config/hook redirection.
        "GIT_CONFIG",
        "GIT_CONFIG_GLOBAL",
        // Agent/credential forwarding.
        "SSH_AUTH_SOCK",
        "SSH_ASKPASS",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "GCP_CREDENTIALS",
        "AZURE_CLIENT_SECRET",
        "NPM_TOKEN",
        // Interpreter/shell code-execution vectors: each can run arbitrary code
        // when the corresponding interpreter starts inside the sandbox.
        "BASH_ENV",
        "ENV",
        "SHELLOPTS",
        "BASHOPTS",
        "PROMPT_COMMAND",
        "PS4",
        "PERL5OPT",
        "PERL5DB",
        "RUBYOPT",
        "PYTHONSTARTUP",
        "PYTHONINSPECT",
        "NODE_OPTIONS",
        "GEM_HOME",
        "RUBYLIB",
        // Interpreter library/home redirection: load an attacker module ahead of
        // the real one (PERLLIB like PERL5LIB) or repoint the whole stdlib
        // (PYTHONHOME) so a trusted `import` resolves to model-written code.
        "PERLLIB",
        "PYTHONHOME",
        // JVM: every `java`/`mvn`/`gradle` start honors these and they accept
        // `-javaagent:`/`-D...` to load and run arbitrary code.
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
        "JDK_JAVA_OPTIONS",
        // Go toolchain: `GOFLAGS=-toolexec=<prog>` runs an arbitrary program
        // during `go build`/`go test`; GOENV redirects the toolchain's config.
        "GOFLAGS",
        "GOENV",
        // zsh startup-file redirection (runs .zshenv/.zshrc on every zsh start);
        // the bash side is covered by BASH_ENV/ENV above.
        "ZDOTDIR",
        // Pager/preprocessor exec vectors — git shells out to a pager (`less`),
        // whose LESSOPEN/LESSCLOSE run an arbitrary input-preprocessor command.
        "LESSOPEN",
        "LESSCLOSE",
    ]
    .iter()
    .map(|s| (*s).to_string())
    .collect()
}

/// A sandbox backend that can run a command under a profile.
pub trait SandboxBackend {
    /// Runs `spec` under `profile`, returning a bounded result.
    ///
    /// # Errors
    /// Returns a backend-specific error if the sandbox could not be set up.
    fn run(
        &self,
        profile: &SandboxProfile,
        spec: CommandSpec,
    ) -> Result<CommandResult, SandboxError>;

    /// The highest [`ExecutionTier`] this backend can **safely** provide. [`select_backend`]
    /// refuses to run a task whose required tier exceeds every available backend's
    /// `provided_tier` — there is **no downgrade** (a Tier-3 hostile task never falls back
    /// to a Tier-2 sandbox). Defaults to [`ExecutionTier::Sandboxed`] (Tier 2 — the
    /// bubblewrap/Seatbelt level); the Firecracker microVM backend
    /// ([`FirecrackerBackend`], `firecracker` feature) overrides this to
    /// [`ExecutionTier::Hostile`] (Tier 3), and the Windows-native stub
    /// ([`WindowsBackend`], `windows-native` feature) keeps Tier 2.
    fn provided_tier(&self) -> ExecutionTier {
        ExecutionTier::Sandboxed
    }
}

/// Selects the backend to run a task at `required` tier from the `backends` available on
/// this host: the **least-over-isolating** backend whose [`provided_tier`](SandboxBackend::provided_tier)
/// still **meets** `required` (meeting the tier is sufficient; a microVM for a Tier-2
/// build is wasteful). If no available backend can provide `required`, execution is
/// **refused** ([`SandboxError::NoBackend`]) — there is no downgrade path (invariant 9;
/// `docs/sandbox.md` §3). This is the seam the Firecracker (Tier-3) and Windows-native
/// backends plug into as they land.
///
/// # Errors
/// [`SandboxError::NoBackend`] if no available backend provides `required`.
pub fn select_backend<'a>(
    required: ExecutionTier,
    backends: &[&'a dyn SandboxBackend],
) -> Result<&'a dyn SandboxBackend, SandboxError> {
    backends
        .iter()
        .filter(|b| b.provided_tier() >= required)
        .min_by_key(|b| b.provided_tier())
        .copied()
        .ok_or(SandboxError::NoBackend)
}

/// Errors from sandbox setup/execution.
#[derive(Debug)]
pub enum SandboxError {
    /// No suitable backend is available on this host.
    NoBackend,
    /// Setting up the sandbox failed.
    Setup(String),
}

impl core::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SandboxError::NoBackend => write!(f, "no sandbox backend available on this host"),
            SandboxError::Setup(e) => write!(f, "sandbox setup failed: {e}"),
        }
    }
}

impl std::error::Error for SandboxError {}

// ---------------------------------------------------------------------------
// Environment sanitation (P4.4) and path-list validation (P4.5)
// ---------------------------------------------------------------------------

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crustcore_policy::SandboxExecCap;
use crustcore_runner::run;

/// Names of path-list environment variables that must be validated
/// component-by-component before crossing into a sandbox (`docs/sandbox.md` §5.2).
pub const PATH_LIST_VARS: &[&str] = &[
    "PATH",
    "LD_LIBRARY_PATH",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "PYTHONPATH",
    "NODE_PATH",
    "GEM_PATH",
    "PERL5LIB",
    "CLASSPATH",
];

/// Dangerous environment-variable name prefixes stripped before launch
/// (loaders + cloud/credential namespaces; `docs/sandbox.md` §5.1).
const STRIPPED_PREFIXES: &[&str] = &[
    "LD_", "DYLD_", "GIT_", "AWS_", "GCP_", "GOOGLE_", "AZURE_", "NPM_", "DOCKER_",
];

/// Single-path env vars that select a directory from which a tool reads its
/// startup/config files. If model-controlled — relative (so resolved against the
/// worktree cwd) or pointing inside the worktree — they become a *config*
/// code-execution vector even when no `*_OPTIONS` var survives: e.g. `git` reads
/// `$HOME/.gitconfig` / `$XDG_CONFIG_HOME/git/config`, whose `core.pager`,
/// `alias.*`, and `core.fsmonitor` keys run arbitrary commands. They are not
/// stripped outright (a sandbox usually needs a real `HOME` for caches), but must
/// be absolute and must not resolve into the writable worktree.
pub const HOME_DIR_VARS: &[&str] = &["HOME", "XDG_CONFIG_HOME"];

/// Whether an env var must be stripped before a sandbox launch: it is in the
/// profile's explicit list, matches a dangerous prefix, or its name looks like a
/// credential (so secrets are never inherited — invariant 2).
#[must_use]
pub fn is_stripped(name: &str, profile: &SandboxProfile) -> bool {
    // Match case-insensitively throughout (defense in depth).
    let upper = name.to_ascii_uppercase();
    if profile
        .stripped_env
        .iter()
        .any(|s| s.eq_ignore_ascii_case(name))
    {
        return true;
    }
    if STRIPPED_PREFIXES.iter().any(|p| upper.starts_with(p)) {
        return true;
    }
    [
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
        "APIKEY",
        "API_KEY",
        "PRIVATE_KEY",
        "CREDENTIAL",
    ]
    .iter()
    .any(|needle| upper.contains(needle))
}

/// Validates a path-list env value component-by-component
/// (`docs/sandbox.md` §5.2). A single bad component fails the whole variable —
/// no silent drop-and-continue. Blocks the empty/relative-component code-exec
/// vectors (e.g. a writable dir or `.` prepended to `PATH`).
///
/// # Errors
/// Returns a human-readable reason for the first offending component.
pub fn validate_path_list(value: &str) -> Result<(), String> {
    for comp in value.split(':') {
        if comp.is_empty() {
            return Err("empty component (an empty entry means the current directory)".to_string());
        }
        if comp.contains('\0') {
            return Err("component contains a NUL byte".to_string());
        }
        let p = Path::new(comp);
        if !p.is_absolute() {
            return Err(format!("relative component '{comp}' (must be absolute)"));
        }
        if p.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        }) {
            return Err(format!("component '{comp}' contains '.' or '..'"));
        }
    }
    Ok(())
}

/// Builds the sanitized environment for a sandbox launch from a requested set:
/// strips dangerous/credential vars, validates path-list vars, and rejects NUL
/// bytes (`docs/sandbox.md` §5). When `worktree` is given, a path-list component
/// inside it is rejected too — a writable worktree dir on `PATH`/`PYTHONPATH`/…
/// is a code-execution vector (the model controls the worktree contents).
///
/// # Errors
/// [`SandboxError::Setup`] if a surviving path-list var has an invalid component
/// or any value contains a NUL byte.
pub fn sanitize_env(
    requested: &BTreeMap<String, String>,
    profile: &SandboxProfile,
    worktree: Option<&Path>,
) -> Result<BTreeMap<String, String>, SandboxError> {
    let mut out = BTreeMap::new();
    for (name, value) in requested {
        if is_stripped(name, profile) {
            continue;
        }
        if value.contains('\0') {
            return Err(SandboxError::Setup(format!(
                "env {name}: value contains a NUL byte"
            )));
        }
        if PATH_LIST_VARS.contains(&name.as_str()) {
            validate_path_list(value)
                .map_err(|e| SandboxError::Setup(format!("env {name}: {e}")))?;
            if let Some(root) = worktree {
                for comp in value.split(':') {
                    if Path::new(comp).starts_with(root) {
                        return Err(SandboxError::Setup(format!(
                            "env {name}: component '{comp}' is inside the (writable) worktree"
                        )));
                    }
                }
            }
        }
        if HOME_DIR_VARS.contains(&name.as_str()) {
            let p = Path::new(value);
            if !p.is_absolute() {
                return Err(SandboxError::Setup(format!(
                    "env {name}: '{value}' must be an absolute path"
                )));
            }
            // NOTE: lexical containment only — a symlink whose path is outside the
            // worktree but resolves inside is not caught here (tracked as a known
            // path-validation hardening item; the bwrap bind mounts still confine
            // writes to the worktree).
            if let Some(root) = worktree {
                if p.starts_with(root) {
                    return Err(SandboxError::Setup(format!(
                        "env {name}: '{value}' is inside the (writable) worktree"
                    )));
                }
            }
        }
        out.insert(name.clone(), value.clone());
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Linux backend v1: bubblewrap (P4.6)
// ---------------------------------------------------------------------------

fn find_executable(name: &str) -> Option<PathBuf> {
    for dir in ["/usr/bin", "/bin", "/usr/local/bin", "/opt/homebrew/bin"] {
        let candidate = Path::new(dir).join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// The Linux `bubblewrap` backend (`docs/sandbox.md` §3): wraps the command in an
/// unprivileged container with a read-only system, a read-write worktree, and
/// **no network** (`--unshare-all`). Network is never re-enabled here in v1:
/// allowlisted egress requires the trusted proxy (not yet built), so an
/// `Allowlist` profile is **refused** by [`run_command`] rather than granting raw
/// unproxied host networking.
#[derive(Debug, Clone)]
pub struct BubblewrapBackend {
    bwrap: PathBuf,
}

impl BubblewrapBackend {
    /// Detects `bwrap` on this host, returning `None` if it is not installed.
    #[must_use]
    pub fn detect() -> Option<Self> {
        find_executable("bwrap").map(|bwrap| BubblewrapBackend { bwrap })
    }

    /// Builds the `bwrap`-wrapped [`CommandSpec`] for `inner`. Network is always
    /// denied (`--unshare-all`, no `--share-net`).
    fn wrap(&self, inner: &CommandSpec) -> CommandSpec {
        let mut args: Vec<String> = vec![
            "--die-with-parent".into(),
            // Unshare every namespace, including the network: deny-all egress.
            "--unshare-all".into(),
            "--new-session".into(),
        ];
        // Read-only system directories.
        for ro in ["/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/opt"] {
            if Path::new(ro).exists() {
                args.push("--ro-bind".into());
                args.push(ro.into());
                args.push(ro.into());
            }
        }
        args.push("--proc".into());
        args.push("/proc".into());
        args.push("--dev".into());
        args.push("/dev".into());
        args.push("--tmpfs".into());
        args.push("/tmp".into());
        // Read-write worktree, and run there.
        if let Some(cwd) = &inner.cwd {
            args.push("--bind".into());
            args.push(cwd.clone());
            args.push(cwd.clone());
            args.push("--chdir".into());
            args.push(cwd.clone());
        }
        args.push("--".into());
        args.push(inner.program.clone());
        args.extend(inner.args.iter().cloned());

        CommandSpec {
            program: self.bwrap.to_string_lossy().into_owned(),
            args,
            cwd: None,
            env: inner.env.clone(),
            // Forward the inner command's stdin through bwrap to the worker.
            stdin: inner.stdin.clone(),
            timeout: inner.timeout,
            max_output_bytes: inner.max_output_bytes,
        }
    }

    /// The bwrap argv this backend would use (exposed for tests/inspection).
    #[must_use]
    pub fn wrapped_spec(&self, inner: &CommandSpec) -> CommandSpec {
        self.wrap(inner)
    }
}

impl SandboxBackend for BubblewrapBackend {
    fn run(
        &self,
        profile: &SandboxProfile,
        spec: CommandSpec,
    ) -> Result<CommandResult, SandboxError> {
        // Sanitize the environment at the launch boundary (not just one layer up),
        // so invoking the backend directly cannot fail open.
        let worktree = spec.cwd.clone().map(PathBuf::from);
        let env = sanitize_env(&spec.env, profile, worktree.as_deref())?;
        let wrapped = self.wrap(&CommandSpec { env, ..spec });
        run(&wrapped).map_err(|e| SandboxError::Setup(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// macOS backend v1: sandbox-exec / Seatbelt (`docs/sandbox.md` §3 "macOS")
// ---------------------------------------------------------------------------

/// Escapes a path for embedding inside an SBPL double-quoted string literal.
/// Backslashes and double quotes are the only characters that terminate or
/// re-interpret a Scheme/SBPL string, so escaping them defensively prevents a
/// crafted worktree/TMPDIR path from breaking out of the `(subpath "...")` form
/// and injecting rules. Returns the escaped contents (without surrounding quotes).
///
/// Compiled on macOS (the only platform that uses Seatbelt) and under `test` (the
/// deterministic profile-shape test runs on every platform); elided elsewhere so
/// a non-macOS release build sees no unused code.
#[cfg(any(target_os = "macos", test))]
#[must_use]
fn sbpl_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c == '\\' || c == '"' {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Builds the Seatbelt (SBPL) profile string that confines a run: deny-all
/// network egress and writes confined to the worktree + temp dirs. Pure (no I/O),
/// so the deterministic profile-shape test runs on every platform.
///
/// `worktree` and `tmpdir` MUST already be **canonical** (real, symlink-resolved)
/// absolute paths — SBPL `subpath` matches the kernel's resolved path, and macOS
/// symlinks `/tmp`→`/private/tmp`, `/var`→`/private/var`, and worktrees under
/// `/var/folders/...`. Embedding an unresolved path would either fail open (a
/// rule that never matches) or block legitimate worktree writes. Canonicalization
/// (and the fail-closed-on-error policy) happens in [`SeatbeltBackend::profile_for`].
///
/// The recipe is "allow-all, then deny the two load-bearing classes, then
/// re-allow the writable surface" (later SBPL rules override earlier ones):
/// `(deny network*)` is the deny-all-egress guarantee (mirrors bubblewrap's
/// `--unshare-all`); `(deny file-write*)` followed by re-allowing only the
/// worktree + temp dirs is the write-confinement guarantee.
///
/// Compiled on macOS and under `test` (see [`sbpl_escape`]); elided on a non-macOS
/// release build where nothing references it.
#[cfg(any(target_os = "macos", test))]
#[must_use]
fn build_seatbelt_profile(worktree: &Path, tmpdir: &Path) -> String {
    let wt = sbpl_escape(&worktree.to_string_lossy());
    let tmp = sbpl_escape(&tmpdir.to_string_lossy());
    format!(
        "(version 1)\n\
         (allow default)\n\
         (deny network*)\n\
         (deny file-write*)\n\
         (allow file-write*\n\
         \x20   (subpath \"{wt}\")\n\
         \x20   (subpath \"{tmp}\")\n\
         \x20   (subpath \"/private/tmp\")\n\
         \x20   (subpath \"/private/var/tmp\")\n\
         \x20   (literal \"/dev/null\") (literal \"/dev/zero\")\n\
         \x20   (literal \"/dev/stdout\") (literal \"/dev/stderr\") (literal \"/dev/tty\")\n\
         \x20   (literal \"/dev/dtracehelper\") (literal \"/dev/urandom\"))\n"
    )
}

/// The macOS `sandbox-exec` (Seatbelt) backend (`docs/sandbox.md` §3 "macOS"):
/// wraps the command under an SBPL profile that **denies all network egress** and
/// **confines writes to the worktree** (plus the system temp dirs and a few
/// harmless `/dev` nodes), matching the bubblewrap backend's security posture
/// (Tier 2). Like bubblewrap, network is never re-enabled here in v1 — an
/// `Allowlist` profile is **refused** by [`run_command`] rather than granting raw
/// unproxied host networking.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone)]
pub struct SeatbeltBackend {
    sandbox_exec: PathBuf,
}

#[cfg(target_os = "macos")]
impl SeatbeltBackend {
    /// Detects `sandbox-exec` on this host, returning `None` if it is missing.
    /// It ships at `/usr/bin/sandbox-exec` on every macOS, but we probe rather
    /// than assume so a stripped host refuses (no silent unsandboxed degrade).
    #[must_use]
    pub fn detect() -> Option<Self> {
        let path = Path::new("/usr/bin/sandbox-exec");
        if path.is_file() {
            return Some(SeatbeltBackend {
                sandbox_exec: path.to_path_buf(),
            });
        }
        // Fall back to the standard search path (Homebrew etc.) for unusual hosts.
        find_executable("sandbox-exec").map(|sandbox_exec| SeatbeltBackend { sandbox_exec })
    }

    /// Resolves the canonical worktree + TMPDIR and builds the SBPL profile for a
    /// run rooted at `cwd`. **Fail-closed:** if a path cannot be canonicalized we
    /// return [`SandboxError::Setup`] rather than embedding an unresolved path
    /// (which would either fail open or block legitimate worktree writes — see
    /// [`build_seatbelt_profile`]). The TMPDIR is taken from the *sanitized* env
    /// when present, else the process `TMPDIR`, else `/private/tmp`.
    fn profile_for(cwd: &str, env: &BTreeMap<String, String>) -> Result<String, SandboxError> {
        let worktree = std::fs::canonicalize(cwd).map_err(|e| {
            SandboxError::Setup(format!("cannot canonicalize worktree '{cwd}': {e}"))
        })?;
        // Prefer the sanitized env's TMPDIR (what the child will actually see),
        // then the ambient one, then the macOS default.
        let tmp_raw = env
            .get("TMPDIR")
            .cloned()
            .or_else(|| std::env::var("TMPDIR").ok())
            .unwrap_or_else(|| "/private/tmp".to_string());
        let tmpdir = std::fs::canonicalize(&tmp_raw).map_err(|e| {
            SandboxError::Setup(format!("cannot canonicalize TMPDIR '{tmp_raw}': {e}"))
        })?;
        Ok(build_seatbelt_profile(&worktree, &tmpdir))
    }

    /// Builds the `sandbox-exec`-wrapped [`CommandSpec`] for `inner` under
    /// `profile_str`. Runs `sandbox-exec -p '<profile>' -- <program> <args...>`
    /// with `cwd` preserved so the child starts in the worktree, forwarding the
    /// (already-sanitized) env, stdin, timeout, and output cap.
    fn wrap(&self, inner: &CommandSpec, profile_str: &str) -> CommandSpec {
        let mut args: Vec<String> = vec![
            "-p".into(),
            profile_str.to_string(),
            "--".into(),
            inner.program.clone(),
        ];
        args.extend(inner.args.iter().cloned());
        CommandSpec {
            program: self.sandbox_exec.to_string_lossy().into_owned(),
            args,
            // Preserve the worktree cwd so the child process starts there.
            cwd: inner.cwd.clone(),
            env: inner.env.clone(),
            stdin: inner.stdin.clone(),
            timeout: inner.timeout,
            max_output_bytes: inner.max_output_bytes,
        }
    }

    /// The `sandbox-exec` argv this backend would use for `inner` (exposed for
    /// tests/inspection, mirroring [`BubblewrapBackend::wrapped_spec`]). Requires a
    /// worktree `cwd` to build the confinement profile.
    ///
    /// # Errors
    /// [`SandboxError::Setup`] if `inner` has no `cwd`, or a path cannot be
    /// canonicalized (fail-closed).
    pub fn wrapped_spec(&self, inner: &CommandSpec) -> Result<CommandSpec, SandboxError> {
        let cwd = inner.cwd.as_deref().ok_or_else(|| {
            SandboxError::Setup("seatbelt backend requires a worktree cwd".to_string())
        })?;
        let profile_str = Self::profile_for(cwd, &inner.env)?;
        Ok(self.wrap(inner, &profile_str))
    }
}

#[cfg(target_os = "macos")]
impl SandboxBackend for SeatbeltBackend {
    fn run(
        &self,
        profile: &SandboxProfile,
        spec: CommandSpec,
    ) -> Result<CommandResult, SandboxError> {
        // Sanitize the environment at the launch boundary (not just one layer up),
        // so invoking the backend directly cannot fail open — same as bubblewrap.
        let worktree = spec.cwd.clone().map(PathBuf::from);
        let cwd = spec.cwd.clone().ok_or_else(|| {
            SandboxError::Setup("seatbelt backend requires a worktree cwd".to_string())
        })?;
        let env = sanitize_env(&spec.env, profile, worktree.as_deref())?;
        // Build the SBPL confinement from the canonical worktree + (sanitized)
        // TMPDIR; fail closed if either cannot be resolved.
        let profile_str = Self::profile_for(&cwd, &env)?;
        let wrapped = self.wrap(&CommandSpec { env, ..spec }, &profile_str);
        run(&wrapped).map_err(|e| SandboxError::Setup(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Tier-3 backend (B4-firecracker): Firecracker microVM (Hostile)
// ---------------------------------------------------------------------------

/// The Firecracker microVM backend (`docs/sandbox.md` §3; Tier 3 — Hostile).
///
/// Unlike the Tier-2 namespace/Seatbelt sandboxes, this provides a **microVM
/// boundary** (a separate guest kernel) for running *untrusted* code, so it is
/// the only backend [`select_backend`] will hand an [`ExecutionTier::Hostile`]
/// task (a Tier-3 task with only Tier-2 backends is still **refused** — no
/// downgrade). It is **dependency-free**: it shells out to the `firecracker`
/// binary via `std::process` (through [`crustcore_runner`]), so it adds nothing
/// to the build and contains no `unsafe`.
///
/// Security posture matches the other backends (and the kernel contract):
/// **deny-all egress** (the microVM is booted with no network device) and
/// **writes confined to the worktree** (only the worktree block device / shared
/// dir is mounted read-write inside the guest; the rootfs is read-only). The
/// environment is sanitized at the launch boundary via [`sanitize_env`], exactly
/// like bubblewrap/Seatbelt, so secrets and exec-injection vars never cross into
/// the guest.
///
/// Available behind the off-by-default `firecracker` cargo feature. The argv
/// construction ([`Self::wrapped_spec`]) is pure and unit-tested on every
/// platform; the actual guest **VM boot + in-guest exec** is the live seam
/// (`TODO(B4-firecracker-live)`): wiring up the jailer, the VM socket API, the
/// kernel image + worktree block device, and harvesting the guest's exit
/// status/output back into a [`CommandResult`]. Until that lands, [`run`](SandboxBackend::run)
/// returns [`SandboxError::Setup`] rather than silently running unconfined.
#[cfg(feature = "firecracker")]
#[derive(Debug, Clone)]
pub struct FirecrackerBackend {
    firecracker: PathBuf,
}

#[cfg(feature = "firecracker")]
impl FirecrackerBackend {
    /// Detects the `firecracker` binary on this host, returning `None` when it is
    /// not installed. Returning `None` keeps the refuse-if-no-backend contract:
    /// a Tier-3 task on a host without Firecracker is refused, never downgraded.
    #[must_use]
    pub fn detect() -> Option<Self> {
        find_executable("firecracker").map(|firecracker| FirecrackerBackend { firecracker })
    }

    /// Builds the `firecracker`-wrapped [`CommandSpec`] for `inner`. The argv
    /// boots the microVM from a JSON VM config (no network device — deny-all
    /// egress) and runs the inner command inside the guest with the worktree as
    /// its working directory.
    ///
    /// The shape is `firecracker --no-api --config-file <vm.json> -- <program>
    /// <args...>`: `--no-api` boots straight from the static config (no live API
    /// socket needed for a one-shot run), the config pins the read-only rootfs +
    /// read-write worktree drive and **omits any network interface**, and the
    /// inner program/args are forwarded after `--` (the live boot wiring resolves
    /// these inside the guest; `TODO(B4-firecracker-live)`).
    ///
    /// The (already-sanitized) env, stdin, timeout, and output cap are forwarded
    /// unchanged. `cwd` is preserved so the *host-side* launcher (jailer) starts
    /// in the worktree; the guest mounts that same worktree read-write.
    fn wrap(&self, inner: &CommandSpec, vm_config: &Path) -> CommandSpec {
        let mut args: Vec<String> = vec![
            "--no-api".into(),
            "--config-file".into(),
            vm_config.to_string_lossy().into_owned(),
            "--".into(),
            inner.program.clone(),
        ];
        args.extend(inner.args.iter().cloned());
        CommandSpec {
            program: self.firecracker.to_string_lossy().into_owned(),
            args,
            // Preserve the worktree cwd for the host-side launcher; the guest
            // mounts the same worktree read-write.
            cwd: inner.cwd.clone(),
            env: inner.env.clone(),
            stdin: inner.stdin.clone(),
            timeout: inner.timeout,
            max_output_bytes: inner.max_output_bytes,
        }
    }

    /// The `firecracker` argv this backend would use for `inner` (exposed for
    /// tests/inspection, mirroring [`BubblewrapBackend::wrapped_spec`] and
    /// [`SeatbeltBackend::wrapped_spec`]). Requires a worktree `cwd`: the guest
    /// mounts that worktree read-write and runs there. The VM config path is the
    /// per-run generated config the live boot will materialize.
    ///
    /// # Errors
    /// [`SandboxError::Setup`] if `inner` has no `cwd` (the microVM needs a
    /// worktree to mount; fail-closed).
    pub fn wrapped_spec(
        &self,
        inner: &CommandSpec,
        vm_config: &Path,
    ) -> Result<CommandSpec, SandboxError> {
        if inner.cwd.is_none() {
            return Err(SandboxError::Setup(
                "firecracker backend requires a worktree cwd to mount into the guest".to_string(),
            ));
        }
        Ok(self.wrap(inner, vm_config))
    }
}

#[cfg(feature = "firecracker")]
impl SandboxBackend for FirecrackerBackend {
    fn run(
        &self,
        profile: &SandboxProfile,
        spec: CommandSpec,
    ) -> Result<CommandResult, SandboxError> {
        // Sanitize the environment at the launch boundary (not just one layer up),
        // so invoking the backend directly cannot fail open — same as the Tier-2
        // backends. A worktree cwd is required (the guest mounts it).
        let worktree = spec.cwd.clone().map(PathBuf::from);
        let _env = sanitize_env(&spec.env, profile, worktree.as_deref())?;
        let _cwd = spec.cwd.clone().ok_or_else(|| {
            SandboxError::Setup(
                "firecracker backend requires a worktree cwd to mount into the guest".to_string(),
            )
        })?;
        // TODO(B4-firecracker-live): boot the microVM and run `spec` inside it.
        // The argv construction (`wrap`/`wrapped_spec`) and env sanitization above
        // are done and tested; the remaining live steps are: (1) materialize the
        // per-run VM JSON config — read-only rootfs drive, read-write worktree
        // drive, NO network interface (deny-all egress), sanitized `_env` injected
        // as the guest's environment; (2) launch via the jailer for the host-side
        // isolation; (3) boot through the VM socket / `--no-api` config, run the
        // inner command in the guest with `_cwd` as the working directory; and
        // (4) harvest the guest's exit status + (bounded) stdout/stderr back into a
        // `CommandResult`. Until that lands we refuse rather than run unconfined.
        Err(SandboxError::Setup(
            "firecracker microVM boot is not yet wired up (TODO(B4-firecracker-live)); \
             refusing rather than running unconfined"
                .to_string(),
        ))
    }

    fn provided_tier(&self) -> ExecutionTier {
        // The microVM boundary is the only thing strong enough for hostile code.
        ExecutionTier::Hostile
    }
}

// ---------------------------------------------------------------------------
// Windows-native backend STUB (B4-windows): selectable, Tier-2
// ---------------------------------------------------------------------------

/// A **selectable stub** for a Windows-native Tier-2 sandbox, behind the
/// off-by-default `windows-native` cargo feature.
///
/// Why a stub and not the real thing: a real Windows confinement (a job object
/// with UI/process limits, plus an AppContainer / restricted token for
/// filesystem + network isolation) requires Win32 calls that are `unsafe` FFI
/// and need a platform crate (e.g. `windows-sys`). This crate is
/// `#![forbid(unsafe_code)]` and is a **nano dependency**, so it cannot take that
/// dependency or write that `unsafe`. The real OS confinement is therefore
/// deferred to `TODO(B4-windows-live)` and must arrive via a **safe** Win32
/// wrapper crate (one exposing job-object / AppContainer setup behind a safe
/// API) in a *non-nano* crate — never by relaxing this crate's `forbid(unsafe)`.
///
/// What is real today: the **selection plumbing**. [`Self::detect`] returns
/// `None` off Windows (so it never claims to confine on a platform it cannot),
/// the backend declares Tier 2 ([`ExecutionTier::Sandboxed`]), and it is wired
/// into [`run_command`]'s backend list so [`select_backend`] can pick it. Like
/// the Firecracker stub, [`run`](SandboxBackend::run) **refuses** (returns
/// [`SandboxError::Setup`]) rather than running unconfined — no fail-open.
#[cfg(feature = "windows-native")]
#[derive(Debug, Clone)]
pub struct WindowsBackend {
    _private: (),
}

#[cfg(feature = "windows-native")]
impl WindowsBackend {
    /// Detects whether a Windows-native sandbox is usable on this host. Returns
    /// `Some` only on Windows; `None` everywhere else (so it is never selected on
    /// a platform where it cannot actually confine — refuse-if-no-backend holds).
    ///
    /// Even on Windows it currently reports availability only as the *selection*
    /// stub — the actual confinement is `TODO(B4-windows-live)`; until that lands,
    /// [`run`](SandboxBackend::run) refuses rather than running unconfined.
    #[must_use]
    pub fn detect() -> Option<Self> {
        if cfg!(target_os = "windows") {
            Some(WindowsBackend { _private: () })
        } else {
            None
        }
    }
}

#[cfg(feature = "windows-native")]
impl SandboxBackend for WindowsBackend {
    fn run(
        &self,
        profile: &SandboxProfile,
        spec: CommandSpec,
    ) -> Result<CommandResult, SandboxError> {
        // Sanitize the environment at the launch boundary — same contract as the
        // other backends — so the plumbing is honest even though confinement is
        // deferred.
        let worktree = spec.cwd.clone().map(PathBuf::from);
        let _env = sanitize_env(&spec.env, profile, worktree.as_deref())?;
        // TODO(B4-windows-live): set up the real Windows confinement here — a job
        // object (process/UI limits, kill-on-close) plus an AppContainer or
        // restricted-token launch confining writes to the worktree and denying
        // network egress (mirroring bubblewrap/Seatbelt Tier 2). That needs Win32
        // calls, which are `unsafe` FFI requiring a platform crate. Because this
        // crate is `#![forbid(unsafe_code)]` AND a nano dependency, it must come
        // through a SAFE Win32 wrapper crate in a non-nano crate — do NOT add
        // `windows-sys` here or relax `forbid(unsafe_code)`. Until then, refuse
        // rather than run unconfined.
        Err(SandboxError::Setup(
            "windows-native confinement is not yet implemented (TODO(B4-windows-live)); \
             refusing rather than running unconfined"
                .to_string(),
        ))
    }

    fn provided_tier(&self) -> ExecutionTier {
        // A job object + AppContainer is a Tier-2 (sandboxed) boundary, not a
        // microVM — it must never be handed a Tier-3 (hostile) task.
        ExecutionTier::Sandboxed
    }
}

/// Runs `spec` under `profile`, gated by a [`SandboxExecCap`] (invariant 9: no
/// capability, no execution). The environment is sanitized (§5), path-list vars
/// validated (§5.2), and the strongest available backend selected; if no backend
/// can provide the required tier, execution is **refused** — there is no
/// "run unsandboxed" degrade path (`docs/sandbox.md` §3).
///
/// `_cap`'s presence is the authorization; the kernel resolves the cap's
/// `SandboxProfileRef` to `profile` (that wiring lands with the runtime).
///
/// # Errors
/// [`SandboxError::NoBackend`] if no backend can run the tier on this host;
/// [`SandboxError::Setup`] on env/path validation failure or a non-executing tier.
pub fn run_command(
    _cap: &SandboxExecCap,
    profile: &SandboxProfile,
    spec: CommandSpec,
) -> Result<CommandResult, SandboxError> {
    match profile.tier {
        ExecutionTier::None | ExecutionTier::StructuredHost => {
            return Err(SandboxError::Setup(
                "this tier does not execute arbitrary commands (use the structured tools)"
                    .to_string(),
            ));
        }
        ExecutionTier::Sandboxed | ExecutionTier::Hostile => {}
    }

    // Allowlisted egress requires the trusted proxy (not yet built); until then,
    // refuse rather than grant raw unproxied host networking.
    if profile.network == NetworkPosture::Allowlist {
        return Err(SandboxError::Setup(
            "network allowlist requires the egress proxy (not yet implemented)".to_string(),
        ));
    }

    // Assemble the backends built on this host. The Linux bubblewrap Tier-2 backend
    // (`detect()` returns `None` off Linux) and the macOS Seatbelt Tier-2 backend
    // (`#[cfg(target_os = "macos")]`) are always compiled in; the Firecracker
    // Tier-3 backend (`firecracker` feature) and the Windows-native Tier-2 stub
    // (`windows-native` feature) append here when their off-by-default features are
    // enabled. Each backend `detect()`s itself and is pushed only when present, so
    // `select_backend` chooses the least-over-isolating backend that MEETS the tier
    // (and refuses — never downgrades — when none does).
    let bwrap = BubblewrapBackend::detect();
    #[cfg(target_os = "macos")]
    let seatbelt = SeatbeltBackend::detect();
    #[cfg(feature = "firecracker")]
    let firecracker = FirecrackerBackend::detect();
    #[cfg(feature = "windows-native")]
    let windows = WindowsBackend::detect();
    let mut backends: Vec<&dyn SandboxBackend> = Vec::new();
    if let Some(b) = bwrap.as_ref() {
        backends.push(b);
    }
    #[cfg(target_os = "macos")]
    if let Some(s) = seatbelt.as_ref() {
        backends.push(s);
    }
    #[cfg(feature = "firecracker")]
    if let Some(fc) = firecracker.as_ref() {
        backends.push(fc);
    }
    #[cfg(feature = "windows-native")]
    if let Some(w) = windows.as_ref() {
        backends.push(w);
    }

    // Select a backend that MEETS the required tier, or refuse. A Tier-3 (hostile) task
    // with only the Tier-2 bubblewrap backend is refused — never downgraded (the
    // microVM requirement is enforced by `select_backend`, not a special case here). The
    // chosen backend sanitizes the environment at the launch boundary (§5).
    let backend = select_backend(profile.tier, &backends)?;
    backend.run(profile, spec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crustcore_types::ScopeId;

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn sanitizer_strips_dangerous_and_keeps_safe() {
        let profile = SandboxProfile::default_sandboxed();
        let requested = env(&[
            ("PATH", "/usr/bin:/bin"),
            ("LD_PRELOAD", "/tmp/evil.so"),
            ("DYLD_INSERT_LIBRARIES", "/tmp/evil.dylib"),
            ("AWS_SECRET_ACCESS_KEY", "sekret"),
            ("GITHUB_TOKEN", "ghp_xxx"),
            ("GIT_CONFIG", "/tmp/evil"),
            ("MY_PASSWORD", "hunter2"),
            ("RUST_BACKTRACE", "1"),
            ("LANG", "C"),
        ]);
        let out = sanitize_env(&requested, &profile, None).unwrap();
        // Safe vars survive.
        assert_eq!(out.get("PATH").map(String::as_str), Some("/usr/bin:/bin"));
        assert_eq!(out.get("RUST_BACKTRACE").map(String::as_str), Some("1"));
        assert_eq!(out.get("LANG").map(String::as_str), Some("C"));
        // Dangerous/credential vars are gone.
        for k in [
            "LD_PRELOAD",
            "DYLD_INSERT_LIBRARIES",
            "AWS_SECRET_ACCESS_KEY",
            "GITHUB_TOKEN",
            "GIT_CONFIG",
            "MY_PASSWORD",
        ] {
            assert!(!out.contains_key(k), "{k} should be stripped");
        }
    }

    #[test]
    fn path_list_validator_rejects_bad_components() {
        assert!(validate_path_list("/usr/bin:/bin").is_ok());
        assert!(validate_path_list("/usr/bin::/bin").is_err()); // empty (cwd)
        assert!(validate_path_list("/usr/bin:.").is_err()); // relative cwd
        assert!(validate_path_list("relative/dir").is_err()); // relative
        assert!(validate_path_list("/usr/bin:../evil").is_err()); // parent
        assert!(validate_path_list("/a\0b").is_err()); // nul
    }

    #[test]
    fn sanitizer_rejects_path_with_empty_component() {
        let profile = SandboxProfile::default_sandboxed();
        // A prepended empty PATH entry (current dir) is an exec-injection vector.
        let requested = env(&[("PATH", ":/usr/bin")]);
        assert!(sanitize_env(&requested, &profile, None).is_err());
    }

    #[test]
    fn sanitizer_strips_interpreter_exec_vars() {
        let profile = SandboxProfile::default_sandboxed();
        let requested = env(&[
            ("BASH_ENV", "/tmp/evil.sh"),
            ("ENV", "/tmp/evil.sh"),
            ("NODE_OPTIONS", "--require /tmp/evil.js"),
            ("PERL5OPT", "-Mevil"),
            ("RUBYOPT", "-revil"),
            ("RUBYLIB", "/tmp/evil"),
            ("PERLLIB", "/tmp/evil"),
            ("PYTHONHOME", "/tmp/evil"),
            ("PROMPT_COMMAND", "evil"),
            ("PYTHONSTARTUP", "/tmp/evil.py"),
            // JVM, Go, zsh, and pager exec vectors.
            ("JAVA_TOOL_OPTIONS", "-javaagent:/tmp/evil.jar"),
            ("_JAVA_OPTIONS", "-javaagent:/tmp/evil.jar"),
            ("JDK_JAVA_OPTIONS", "-javaagent:/tmp/evil.jar"),
            ("GOFLAGS", "-toolexec=/tmp/evil"),
            ("GOENV", "/tmp/evil/go/env"),
            ("ZDOTDIR", "/tmp/evil"),
            ("LESSOPEN", "|/tmp/evil %s"),
            ("LESSCLOSE", "/tmp/evil %s %s"),
        ]);
        let out = sanitize_env(&requested, &profile, None).unwrap();
        assert!(
            out.is_empty(),
            "interpreter exec vars must be stripped: {out:?}"
        );
    }

    #[test]
    fn sanitizer_rejects_writable_worktree_on_path() {
        use std::path::Path;
        let profile = SandboxProfile::default_sandboxed();
        // A PATH component inside the (model-writable) worktree is an exec vector.
        let requested = env(&[("PATH", "/work/tree/bin:/usr/bin")]);
        assert!(sanitize_env(&requested, &profile, Some(Path::new("/work/tree"))).is_err());
        // Outside the worktree it is accepted.
        let ok = env(&[("PATH", "/usr/bin:/bin")]);
        assert!(sanitize_env(&ok, &profile, Some(Path::new("/work/tree"))).is_ok());
    }

    #[test]
    fn sanitizer_rejects_home_pointed_into_worktree() {
        use std::path::Path;
        let profile = SandboxProfile::default_sandboxed();
        let root = Path::new("/work/tree");
        // HOME / XDG_CONFIG_HOME inside the writable worktree is a git-config
        // (core.pager/alias/core.fsmonitor) code-execution vector.
        for var in ["HOME", "XDG_CONFIG_HOME"] {
            let inside = env(&[(var, "/work/tree/.fakehome")]);
            assert!(
                sanitize_env(&inside, &profile, Some(root)).is_err(),
                "{var} inside the worktree must be rejected"
            );
            // A relative value (resolved against the worktree cwd) is also rejected.
            let relative = env(&[(var, "somedir")]);
            assert!(
                sanitize_env(&relative, &profile, Some(root)).is_err(),
                "relative {var} must be rejected"
            );
            // A safe absolute HOME outside the worktree survives.
            let outside = env(&[(var, "/home/runner")]);
            assert!(
                sanitize_env(&outside, &profile, Some(root)).is_ok(),
                "{var} outside the worktree must be accepted"
            );
        }
    }

    #[test]
    fn bwrap_argv_denies_network_and_binds_worktree() {
        // Build the argv without needing bwrap installed.
        let backend = BubblewrapBackend {
            bwrap: PathBuf::from("/usr/bin/bwrap"),
        };
        let mut inner = CommandSpec::new("/bin/echo");
        inner.args = vec!["hi".to_string()];
        inner.cwd = Some("/work/tree".to_string());
        let wrapped = backend.wrapped_spec(&inner);
        assert!(wrapped.program.ends_with("bwrap"));
        assert!(wrapped.args.iter().any(|a| a == "--unshare-all"));
        assert!(!wrapped.args.iter().any(|a| a == "--share-net")); // deny-all => no net
        assert!(wrapped
            .args
            .windows(3)
            .any(|w| w == ["--bind", "/work/tree", "/work/tree"]));
        assert!(wrapped
            .args
            .windows(2)
            .any(|w| w == ["--chdir", "/work/tree"]));
        // The inner command is after the `--` separator.
        let sep = wrapped.args.iter().position(|a| a == "--").unwrap();
        assert_eq!(wrapped.args[sep + 1], "/bin/echo");
        assert_eq!(wrapped.args[sep + 2], "hi");
    }

    #[test]
    fn seatbelt_profile_denies_network_confines_writes_and_escapes_paths() {
        // Deterministic on every platform: `build_seatbelt_profile` is pure. It must
        // emit the two load-bearing deny rules, allow writes only inside the
        // (canonical) worktree, and NOT grant write to an arbitrary outside path.
        let worktree = Path::new("/private/tmp/cc-worktree-abc");
        let tmpdir = Path::new("/private/var/folders/xx/cc-tmp");
        let profile = build_seatbelt_profile(worktree, tmpdir);

        // Deny-all egress (mirrors bwrap --unshare-all).
        assert!(
            profile.contains("(deny network*)"),
            "must deny all network egress"
        );
        // Write confinement: deny-all-writes then re-allow the worktree.
        assert!(
            profile.contains("(deny file-write*)"),
            "must deny all writes by default"
        );
        assert!(
            profile.contains("(subpath \"/private/tmp/cc-worktree-abc\")"),
            "must allow writes inside the canonical worktree"
        );
        assert!(
            profile.contains("(subpath \"/private/var/folders/xx/cc-tmp\")"),
            "must allow writes inside the canonical TMPDIR"
        );
        // An arbitrary outside path is NOT granted write.
        assert!(
            !profile.contains("/Users/someone/.ssh"),
            "must not grant write to an arbitrary outside path"
        );
        // The deny rules precede the re-allow (later SBPL rules override earlier).
        let deny_at = profile.find("(deny file-write*)").unwrap();
        let allow_at = profile.find("(allow file-write*").unwrap();
        assert!(deny_at < allow_at, "deny must precede the re-allow");
    }

    #[test]
    fn seatbelt_profile_escapes_quotes_and_backslashes_in_paths() {
        // A crafted path with a quote/backslash must not break out of the SBPL
        // string literal — both are backslash-escaped.
        let worktree = Path::new("/tmp/a\"b\\c");
        let tmpdir = Path::new("/private/tmp");
        let profile = build_seatbelt_profile(worktree, tmpdir);
        assert!(
            profile.contains("(subpath \"/tmp/a\\\"b\\\\c\")"),
            "quote and backslash must be escaped in the embedded path: {profile}"
        );
    }

    #[test]
    fn allowlist_profile_is_refused_until_proxy_exists() {
        // Until the trusted egress proxy is built, an allowlist profile must be
        // refused rather than granting raw, unproxied host networking.
        let cap = SandboxExecCap {
            profile: ScopeId(1),
            scope: ScopeId(1),
        };
        let profile = SandboxProfile {
            tier: ExecutionTier::Sandboxed,
            network: NetworkPosture::Allowlist,
            stripped_env: default_stripped_env(),
        };
        assert!(matches!(
            run_command(&cap, &profile, CommandSpec::new("/bin/true")),
            Err(SandboxError::Setup(_))
        ));
    }

    #[test]
    fn non_executing_tiers_refuse() {
        let cap = SandboxExecCap {
            profile: ScopeId(1),
            scope: ScopeId(1),
        };
        for tier in [ExecutionTier::None, ExecutionTier::StructuredHost] {
            let profile = SandboxProfile {
                tier,
                network: NetworkPosture::DenyAll,
                stripped_env: default_stripped_env(),
            };
            assert!(run_command(&cap, &profile, CommandSpec::new("/bin/echo")).is_err());
        }
    }

    /// Whether *any* real Tier-2 backend is available on this host (bubblewrap on
    /// Linux, Seatbelt on macOS). The refusal test only holds on a backend-less host.
    fn any_real_backend_available() -> bool {
        if BubblewrapBackend::detect().is_some() {
            return true;
        }
        #[cfg(target_os = "macos")]
        if SeatbeltBackend::detect().is_some() {
            return true;
        }
        false
    }

    #[test]
    fn refuses_when_no_backend_available() {
        // On a host with NO sandbox backend, a sandboxed run is refused rather than
        // downgraded to unsandboxed execution. Skip when any real backend is present
        // (Linux w/ bubblewrap, or macOS w/ sandbox-exec) — the refusal can't be
        // observed there.
        if any_real_backend_available() {
            return;
        }
        let cap = SandboxExecCap {
            profile: ScopeId(1),
            scope: ScopeId(1),
        };
        let profile = SandboxProfile::default_sandboxed();
        let err = run_command(&cap, &profile, CommandSpec::new("/bin/echo")).unwrap_err();
        assert!(matches!(err, SandboxError::NoBackend));
    }

    #[test]
    fn hostile_tier_is_refused_without_microvm() {
        // A Tier-3 (hostile) task is refused when no Tier-3 backend is present —
        // never downgraded to a Tier-2 sandbox. Skip if a real Firecracker backend
        // is detectable on this host (only possible with `--features firecracker`),
        // where the refusal cannot be observed: there the run reaches the live-boot
        // `TODO(B4-firecracker-live)` refusal (`SandboxError::Setup`) instead.
        #[cfg(feature = "firecracker")]
        if FirecrackerBackend::detect().is_some() {
            return;
        }
        let cap = SandboxExecCap {
            profile: ScopeId(1),
            scope: ScopeId(1),
        };
        let profile = SandboxProfile {
            tier: ExecutionTier::Hostile,
            network: NetworkPosture::DenyAll,
            stripped_env: default_stripped_env(),
        };
        assert!(matches!(
            run_command(&cap, &profile, CommandSpec::new("/bin/echo")),
            Err(SandboxError::NoBackend)
        ));
    }

    /// A mock backend that declares a tier but does not execute — exercises the tier
    /// selection (`select_backend` never calls `run`).
    struct MockBackend {
        tier: ExecutionTier,
    }
    impl SandboxBackend for MockBackend {
        fn run(
            &self,
            _profile: &SandboxProfile,
            _spec: CommandSpec,
        ) -> Result<CommandResult, SandboxError> {
            Err(SandboxError::Setup("mock backend does not execute".into()))
        }
        fn provided_tier(&self) -> ExecutionTier {
            self.tier
        }
    }

    #[test]
    fn select_backend_meets_the_tier_or_refuses_without_downgrade() {
        let t2 = MockBackend {
            tier: ExecutionTier::Sandboxed,
        };
        let t3 = MockBackend {
            tier: ExecutionTier::Hostile,
        };

        // A Tier-2 task: a Tier-2 backend suffices.
        assert_eq!(
            select_backend(ExecutionTier::Sandboxed, &[&t2])
                .unwrap()
                .provided_tier(),
            ExecutionTier::Sandboxed
        );
        // A Tier-3 (hostile) task with only a Tier-2 backend → refused, never downgraded.
        assert!(matches!(
            select_backend(ExecutionTier::Hostile, &[&t2]),
            Err(SandboxError::NoBackend)
        ));
        // A Tier-3 task with a Tier-3 backend available → selected.
        assert_eq!(
            select_backend(ExecutionTier::Hostile, &[&t2, &t3])
                .unwrap()
                .provided_tier(),
            ExecutionTier::Hostile
        );
        // No backends at all → refuse.
        assert!(matches!(
            select_backend(ExecutionTier::Sandboxed, &[]),
            Err(SandboxError::NoBackend)
        ));
    }

    #[test]
    fn select_backend_prefers_the_least_over_isolating_sufficient_backend() {
        let t2 = MockBackend {
            tier: ExecutionTier::Sandboxed,
        };
        let t3 = MockBackend {
            tier: ExecutionTier::Hostile,
        };
        // A Tier-2 task with BOTH available → the Tier-2 backend (don't over-isolate).
        assert_eq!(
            select_backend(ExecutionTier::Sandboxed, &[&t3, &t2])
                .unwrap()
                .provided_tier(),
            ExecutionTier::Sandboxed
        );
        // A Tier-2 task with ONLY a Tier-3 backend → the Tier-3 backend (it is sufficient).
        assert_eq!(
            select_backend(ExecutionTier::Sandboxed, &[&t3])
                .unwrap()
                .provided_tier(),
            ExecutionTier::Hostile
        );
    }

    // -----------------------------------------------------------------------
    // B4: Firecracker Tier-3 backend (selection + command construction). These
    // are cross-platform — they never boot a VM; the real boot is gated behind
    // `TODO(B4-firecracker-live)`.
    // -----------------------------------------------------------------------
    #[cfg(feature = "firecracker")]
    mod firecracker_tests {
        use super::*;

        /// A `FirecrackerBackend` for tests, bypassing `detect()` (no `firecracker`
        /// binary needed to exercise argv construction / tier selection).
        fn fake_firecracker() -> FirecrackerBackend {
            FirecrackerBackend {
                firecracker: PathBuf::from("/usr/bin/firecracker"),
            }
        }

        #[test]
        fn firecracker_backend_is_tier_3() {
            assert_eq!(fake_firecracker().provided_tier(), ExecutionTier::Hostile);
        }

        #[test]
        fn tier3_task_selects_firecracker_when_present() {
            // A Tier-3 task with a Tier-2 backend AND the firecracker Tier-3 backend
            // available selects the microVM (the only thing that MEETS Tier 3).
            let t2 = MockBackend {
                tier: ExecutionTier::Sandboxed,
            };
            let fc = fake_firecracker();
            let chosen = select_backend(ExecutionTier::Hostile, &[&t2, &fc]).unwrap();
            assert_eq!(chosen.provided_tier(), ExecutionTier::Hostile);
        }

        #[test]
        fn tier3_task_refused_with_only_tier2_no_downgrade() {
            // The crux of the no-downgrade rule: a Tier-3 task with only Tier-2
            // backends (even several) is REFUSED, never run in a Tier-2 sandbox.
            let t2a = MockBackend {
                tier: ExecutionTier::Sandboxed,
            };
            let t2b = MockBackend {
                tier: ExecutionTier::Sandboxed,
            };
            assert!(matches!(
                select_backend(ExecutionTier::Hostile, &[&t2a, &t2b]),
                Err(SandboxError::NoBackend)
            ));
        }

        #[test]
        fn tier2_task_does_not_needlessly_select_firecracker() {
            // A Tier-2 task with both a Tier-2 backend and the Tier-3 microVM
            // available picks the Tier-2 backend — never over-isolates onto the VM.
            let t2 = MockBackend {
                tier: ExecutionTier::Sandboxed,
            };
            let fc = fake_firecracker();
            let chosen = select_backend(ExecutionTier::Sandboxed, &[&fc, &t2]).unwrap();
            assert_eq!(chosen.provided_tier(), ExecutionTier::Sandboxed);
        }

        #[test]
        fn firecracker_argv_is_well_formed() {
            let backend = fake_firecracker();
            let mut inner = CommandSpec::new("/bin/echo");
            inner.args = vec!["hi".to_string()];
            inner.cwd = Some("/work/tree".to_string());
            let cfg = Path::new("/run/cc/vm-abc.json");
            let wrapped = backend.wrapped_spec(&inner, cfg).unwrap();

            // Launches firecracker, boots from the static config (no live API socket).
            assert!(wrapped.program.ends_with("firecracker"));
            assert!(wrapped.args.iter().any(|a| a == "--no-api"));
            assert!(wrapped
                .args
                .windows(2)
                .any(|w| w == ["--config-file", "/run/cc/vm-abc.json"]));
            // The worktree cwd is preserved for the host-side launcher.
            assert_eq!(wrapped.cwd.as_deref(), Some("/work/tree"));
            // The inner command is forwarded after the `--` separator.
            let sep = wrapped.args.iter().position(|a| a == "--").unwrap();
            assert_eq!(wrapped.args[sep + 1], "/bin/echo");
            assert_eq!(wrapped.args[sep + 2], "hi");
        }

        #[test]
        fn firecracker_requires_a_worktree_cwd() {
            // No cwd → fail-closed (the guest has nothing to mount).
            let backend = fake_firecracker();
            let inner = CommandSpec::new("/bin/echo");
            assert!(matches!(
                backend.wrapped_spec(&inner, Path::new("/run/cc/vm.json")),
                Err(SandboxError::Setup(_))
            ));
        }

        #[test]
        fn firecracker_run_sanitizes_env_then_refuses_live_boot() {
            // `run` must sanitize the env (so a bad PATH/credential is caught at the
            // boundary) and, the live boot being unimplemented, refuse with `Setup`
            // rather than fail open. A PATH component inside the writable worktree is
            // an exec vector → env sanitation rejects it before the live TODO.
            let backend = fake_firecracker();
            let profile = SandboxProfile {
                tier: ExecutionTier::Hostile,
                network: NetworkPosture::DenyAll,
                stripped_env: default_stripped_env(),
            };
            let mut bad = CommandSpec::new("/bin/echo");
            bad.cwd = Some("/work/tree".to_string());
            bad.env = env(&[("PATH", "/work/tree/bin:/usr/bin")]);
            assert!(
                matches!(backend.run(&profile, bad), Err(SandboxError::Setup(_))),
                "a writable-worktree PATH component must be rejected by env sanitation"
            );

            // With a clean env the live boot is still unimplemented → `Setup` refusal,
            // never an unconfined run.
            let mut ok = CommandSpec::new("/bin/echo");
            ok.cwd = Some("/work/tree".to_string());
            ok.env = env(&[("PATH", "/usr/bin:/bin")]);
            assert!(matches!(
                backend.run(&profile, ok),
                Err(SandboxError::Setup(_))
            ));
        }
    }

    // -----------------------------------------------------------------------
    // B4: Windows-native backend STUB (selection plumbing only; real Win32
    // confinement is `TODO(B4-windows-live)`).
    // -----------------------------------------------------------------------
    #[cfg(feature = "windows-native")]
    mod windows_tests {
        use super::*;

        fn stub_windows() -> WindowsBackend {
            WindowsBackend { _private: () }
        }

        #[test]
        fn windows_backend_is_tier_2() {
            assert_eq!(stub_windows().provided_tier(), ExecutionTier::Sandboxed);
        }

        #[test]
        fn windows_detect_is_none_off_windows() {
            // The stub only reports availability on Windows; everywhere else it is
            // `None`, so `select_backend` never picks it on a platform it cannot
            // confine (refuse-if-no-backend holds).
            if cfg!(target_os = "windows") {
                assert!(WindowsBackend::detect().is_some());
            } else {
                assert!(WindowsBackend::detect().is_none());
            }
        }

        #[test]
        fn windows_stub_can_satisfy_a_tier2_selection() {
            // The selection plumbing is real: a Tier-2 task with only the Windows
            // backend selects it (it MEETS Tier 2); a Tier-3 task does NOT (no
            // downgrade — the stub is not a microVM).
            let w = stub_windows();
            assert_eq!(
                select_backend(ExecutionTier::Sandboxed, &[&w])
                    .unwrap()
                    .provided_tier(),
                ExecutionTier::Sandboxed
            );
            assert!(matches!(
                select_backend(ExecutionTier::Hostile, &[&w]),
                Err(SandboxError::NoBackend)
            ));
        }

        #[test]
        fn windows_run_sanitizes_env_then_refuses_unimplemented_confinement() {
            // Same honesty contract as the other backends: sanitize at the boundary,
            // then refuse (the real Win32 confinement is deferred) rather than fail
            // open.
            let w = stub_windows();
            let profile = SandboxProfile::default_sandboxed();
            let mut bad = CommandSpec::new("cmd");
            bad.cwd = Some("/work/tree".to_string());
            bad.env = env(&[("PATH", "/work/tree/bin:/usr/bin")]);
            assert!(matches!(w.run(&profile, bad), Err(SandboxError::Setup(_))));

            let mut ok = CommandSpec::new("cmd");
            ok.cwd = Some("/work/tree".to_string());
            ok.env = env(&[("PATH", "/usr/bin:/bin")]);
            assert!(matches!(w.run(&profile, ok), Err(SandboxError::Setup(_))));
        }
    }

    // -----------------------------------------------------------------------
    // macOS live confinement (proves the Seatbelt backend actually confines on
    // this host). Skips if `sandbox-exec` is missing. These run a real child
    // through the backend and assert: writes inside the worktree succeed, writes
    // outside are DENIED, network egress is DENIED, and env is sanitized.
    // -----------------------------------------------------------------------
    #[cfg(target_os = "macos")]
    mod macos_live {
        use super::*;

        /// Runs `/bin/sh -c <script>` through the Seatbelt backend in `worktree`,
        /// with the given extra env merged onto a minimal base.
        fn run_in_seatbelt(
            worktree: &Path,
            script: &str,
            extra_env: &[(&str, &str)],
        ) -> CommandResult {
            let backend = SeatbeltBackend::detect().expect("sandbox-exec present");
            let mut env: BTreeMap<String, String> = BTreeMap::new();
            env.insert("PATH".to_string(), "/usr/bin:/bin".to_string());
            for (k, v) in extra_env {
                env.insert((*k).to_string(), (*v).to_string());
            }
            let mut spec = CommandSpec::new("/bin/sh");
            spec.args = vec!["-c".to_string(), script.to_string()];
            spec.cwd = Some(worktree.to_string_lossy().into_owned());
            spec.env = env;
            spec.timeout = std::time::Duration::from_secs(15);
            backend
                .run(&SandboxProfile::default_sandboxed(), spec)
                .expect("seatbelt run set up")
        }

        #[test]
        fn write_inside_worktree_succeeds() {
            if SeatbeltBackend::detect().is_none() {
                return; // sandbox-exec missing; skip
            }
            let tmp = std::env::temp_dir().join(format!("cc-sbx-in-{}", std::process::id()));
            std::fs::create_dir_all(&tmp).unwrap();
            let canon = std::fs::canonicalize(&tmp).unwrap();

            let r = run_in_seatbelt(&canon, "echo hi > inside.txt && echo DONE", &[]);
            assert!(
                r.is_success(),
                "writing inside the worktree must succeed: {r:?}"
            );
            assert!(
                canon.join("inside.txt").exists(),
                "the file must be created"
            );

            std::fs::remove_dir_all(&tmp).ok();
        }

        #[test]
        fn write_outside_worktree_is_denied() {
            if SeatbeltBackend::detect().is_none() {
                return; // sandbox-exec missing; skip
            }
            let tmp = std::env::temp_dir().join(format!("cc-sbx-out-{}", std::process::id()));
            std::fs::create_dir_all(&tmp).unwrap();
            let canon = std::fs::canonicalize(&tmp).unwrap();

            // Target a path OUTSIDE the worktree (the user's HOME).
            let escape = format!(
                "{}/.crustcore-sbx-escape-test-{}",
                std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string()),
                std::process::id()
            );
            let escape_path = PathBuf::from(&escape);
            // Best-effort pre-clean.
            std::fs::remove_file(&escape_path).ok();

            let script = format!("echo pwned > '{escape}'");
            let r = run_in_seatbelt(&canon, &script, &[]);
            assert!(
                !r.is_success(),
                "writing OUTSIDE the worktree must be denied (non-zero exit): {r:?}"
            );
            assert!(
                !escape_path.exists(),
                "the out-of-worktree file must NOT have been created"
            );

            std::fs::remove_file(&escape_path).ok();
            std::fs::remove_dir_all(&tmp).ok();
        }

        #[test]
        fn network_egress_is_denied() {
            if SeatbeltBackend::detect().is_none() {
                return; // sandbox-exec missing; skip
            }
            if !Path::new("/usr/bin/nc").exists() {
                return; // nc missing; skip the live network probe
            }
            let tmp = std::env::temp_dir().join(format!("cc-sbx-net-{}", std::process::id()));
            std::fs::create_dir_all(&tmp).unwrap();
            let canon = std::fs::canonicalize(&tmp).unwrap();

            // A TCP connect to a public resolver must fail under deny-all egress.
            let r = run_in_seatbelt(&canon, "/usr/bin/nc -z -G1 1.1.1.1 53", &[]);
            assert!(
                !r.is_success(),
                "network egress must be denied (nc must fail): {r:?}"
            );

            std::fs::remove_dir_all(&tmp).ok();
        }

        #[test]
        fn env_is_sanitized_inside_the_sandbox() {
            if SeatbeltBackend::detect().is_none() {
                return; // sandbox-exec missing; skip
            }
            let tmp = std::env::temp_dir().join(format!("cc-sbx-env-{}", std::process::id()));
            std::fs::create_dir_all(&tmp).unwrap();
            let canon = std::fs::canonicalize(&tmp).unwrap();

            // A credential-looking var must be stripped before reaching the child;
            // a benign var must survive. Print both so we can assert on the output.
            let r = run_in_seatbelt(
                &canon,
                "printf '[%s][%s]' \"$MY_SECRET_TOKEN\" \"$CC_BENIGN\"",
                &[
                    ("MY_SECRET_TOKEN", "ghp_should_be_stripped"),
                    ("CC_BENIGN", "ok"),
                ],
            );
            assert!(r.is_success(), "the probe command must run: {r:?}");
            let out = String::from_utf8_lossy(&r.stdout);
            assert_eq!(
                out, "[][ok]",
                "the credential var must be stripped and the benign var preserved: {out:?}"
            );

            std::fs::remove_dir_all(&tmp).ok();
        }
    }
}
