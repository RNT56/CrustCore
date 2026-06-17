// SPDX-License-Identifier: Apache-2.0
//! Sandbox profiles and backends (`ROADMAP.md` §10; Phase 4). Every
//! execution-capable operation runs under an explicit sandbox profile
//! (invariant 9), with deny-all egress by default and a sanitized environment
//! (`docs/sandbox.md`).
//!
//! Status: Phase 0 scaffold. Profiles/tiers and the backend trait are defined;
//! the Linux backend (Landlock/namespaces/bubblewrap), env sanitation, and
//! path-list env validation land in Phase 4 (`TODO(P4.*)`).
//!
//! NOTE: unlike the pure kernel crates, the real backends here will require
//! `unsafe`/FFI for syscalls. Such code must be isolated, justified, and tested
//! (CLAUDE.md §6.5); add `#![deny(unsafe_code)]` exceptions per-module with a
//! written rationale rather than relaxing it crate-wide.
#![forbid(unsafe_code)]

use crustcore_runner::{CommandResult, CommandSpec};

/// Execution tiers (`ROADMAP.md` §10.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

    // Tier 3 (hostile) requires a microVM (Firecracker), out of scope for v0.1:
    // refuse rather than downgrade to bwrap.
    if profile.tier == ExecutionTier::Hostile {
        return Err(SandboxError::NoBackend);
    }

    // The backend sanitizes the environment at the launch boundary (§5).
    let backend = BubblewrapBackend::detect().ok_or(SandboxError::NoBackend)?;
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

    #[test]
    fn refuses_when_no_backend_available() {
        // On a host without bwrap (e.g. macOS dev box), a sandboxed run is refused
        // rather than downgraded to unsandboxed execution.
        if BubblewrapBackend::detect().is_some() {
            return; // bwrap present (Linux CI w/ bubblewrap); skip the refusal check
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
}
