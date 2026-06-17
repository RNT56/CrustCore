// SPDX-License-Identifier: Apache-2.0
//! External worker backends (`ROADMAP.md` §11.4, §18 Phase 6; tasks P6.1–P6.6).
//!
//! A coding backend is anything that produces a candidate change: the native
//! agent, an external `codex` subprocess, an external `claude` (Claude Code)
//! subprocess, or any future worker. They all return the same [`BackendResult`]
//! (`docs/backend-contract.md`). This module implements the **external** ones and,
//! crucially, the **supervisor validation** that makes a worker a *patch producer,
//! not a truth authority* (invariant 6):
//!
//! 1. Run the worker **in the sandbox** ([`crustcore_sandbox::run_command`]),
//!    confined to the disposable worktree, with **no secrets** and **deny-all
//!    egress** (invariants 1–3, 9; the input contract's `"secrets":"none"` /
//!    `"network":"deny"` are *type-level* here — [`WorkerSecrets`]/[`WorkerNetwork`]
//!    have no other inhabitant).
//! 2. Capture the (untrusted) transcript, **bounded** (invariant 11).
//! 3. **Detect out-of-root writes** with a [`GuardManifest`] over the worktree's
//!    sibling space, and reject the whole result if anything outside the worktree
//!    changed (defense in depth that holds even where the OS sandbox is
//!    non-functional).
//! 4. **Extract the actual diff from the worktree** with the hardened git wrappers
//!    — never the worker's self-reported diff — and **confine every changed path**
//!    (a symlink/`..` escape rejects the result).
//! 5. Classify changed files (CI workflows, dependency manifests, credential-ish
//!    names) so a later reviewer/security pass can gate on them.
//!
//! The product is an [`UnverifiedPatch`]: nothing here mints a [`VerifiedPatch`].
//! Completion still flows only through [`verify::run_verify`](crate::verify) —
//! `self_claimed_done` is advisory metadata, never authority (invariants 6, 13).
//!
//! Like [`verify`](crate::verify), the orchestrator is parameterized over a
//! command executor so the validation logic is unit-tested deterministically on
//! every platform; in production the executor is always the sandbox.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crustcore_path::WorktreeRoot;
use crustcore_policy::{FsReadCap, SandboxExecCap};
use crustcore_runner::{CommandResult, CommandSpec};
use crustcore_sandbox::{run_command, SandboxError, SandboxProfile};
use crustcore_types::hash::sha256;
use crustcore_types::{BoundedText, ScopeId, TaskId};
use crustcore_worktree::{git_diff, git_status_all, ToolError};

use crate::{BackendKind, BackendResult, CommandRecord, PatchRef, Risk, UnverifiedPatch};

/// Cap on captured worker transcript bytes (bounded everything, `CLAUDE.md` §6.5).
const MAX_WORKER_OUTPUT: usize = 4 * 1024 * 1024;

/// Cap on the bounded human/model summary distilled from a transcript.
const MAX_SUMMARY: usize = 4 * 1024;

/// Cap on the extracted diff bytes folded into the patch content address.
const MAX_DIFF_BYTES: usize = 1024 * 1024;

/// Upper bound on entries recorded in a [`GuardManifest`] walk (bounded; a runaway
/// directory cannot make snapshotting unbounded). Far above any real worktree base.
const MAX_GUARD_ENTRIES: usize = 50_000;

/// Upper bound on guard-walk recursion depth.
const MAX_GUARD_DEPTH: usize = 32;

/// A minimal, secret-free `PATH` for a sandboxed worker. Every component is
/// absolute and outside the worktree, so [`crustcore_sandbox::sanitize_env`]
/// accepts it and the bubblewrap profile read-only-binds the directories.
const SAFE_PATH: &str = "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin";

/// A marker a cooperative worker may print to claim completion. **Advisory only**
/// (invariant 6): a worker can print it and still not complete a task — only the
/// verifier completes one. Kept deliberately explicit so free-text in a transcript
/// is never mistaken for a "done" claim.
pub const DONE_MARKER: &str = "[[CRUSTCORE_DONE]]";

/// Network posture handed to an external worker. v0.1 has exactly one inhabitant:
/// **deny-all egress**. Allowlisted egress requires the trusted proxy (a later
/// phase), so there is no way to construct a worker that is granted raw network
/// (invariant 9; `docs/sandbox.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerNetwork {
    /// Deny all egress (the only option in v0.1).
    Deny,
}

impl WorkerNetwork {
    /// The contract token (`"deny"`) for the worker input JSON.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            WorkerNetwork::Deny => "deny",
        }
    }
}

/// Secrets posture handed to an external worker. There is exactly one inhabitant:
/// **none**. A worker never receives credentials, secret-bearing env, or a
/// credential proxy (invariants 1–3). Because this type has no other variant,
/// "hand a worker a secret" is **unrepresentable** — `docs/backend-contract.md`
/// §4.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerSecrets {
    /// No secrets are ever passed to the worker (the only option).
    None,
}

impl WorkerSecrets {
    /// The contract token (`"none"`) for the worker input JSON.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            WorkerSecrets::None => "none",
        }
    }
}

/// The input contract handed to an external worker (`ROADMAP.md` §11.4;
/// `docs/backend-contract.md` §4.1). Everything the worker returns is treated as
/// untrusted claims and re-derived by the supervisor.
#[derive(Debug, Clone)]
pub struct WorkerInput {
    /// The task this worker serves.
    pub task_id: TaskId,
    /// The goal (bounded; untrusted free text that the worker may read).
    pub goal: BoundedText,
    /// The repo root the worker operates in (the disposable worktree).
    pub repo_root: String,
    /// Roots the worker may write to (the worktree + a tmp area).
    pub allowed_roots: Vec<String>,
    /// Paths explicitly off-limits, advertised to the worker.
    pub forbidden_paths: Vec<String>,
    /// Network posture (always [`WorkerNetwork::Deny`] in v0.1).
    pub network: WorkerNetwork,
    /// Secrets posture (always [`WorkerSecrets::None`]).
    pub secrets: WorkerSecrets,
    /// Wall-clock budget in seconds (invariant 11).
    pub max_seconds: u64,
    /// Output budget in MiB the worker is asked to respect (invariant 11). The
    /// supervisor additionally caps its own capture at [`MAX_WORKER_OUTPUT`].
    pub max_output_mb: u64,
}

impl WorkerInput {
    /// Builds the standard input contract for a task running in `worktree`, with
    /// conservative budgets and the fixed deny/none postures.
    #[must_use]
    pub fn for_task(task_id: TaskId, goal: &str, worktree: &WorktreeRoot) -> Self {
        let root = worktree.as_path().to_string_lossy().into_owned();
        WorkerInput {
            task_id,
            goal: BoundedText::truncated(goal, BoundedText::DEFAULT_MAX),
            repo_root: root.clone(),
            allowed_roots: vec![root, "/tmp".to_string()],
            forbidden_paths: default_forbidden_paths(),
            network: WorkerNetwork::Deny,
            secrets: WorkerSecrets::None,
            max_seconds: 1800,
            max_output_mb: 50,
        }
    }

    /// The worker input as the contract JSON (`docs/backend-contract.md` §4.1),
    /// serialized by hand (nano links no JSON crate). `secrets` is always `"none"`
    /// and `network` always `"deny"`, by type.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut s = String::with_capacity(256);
        s.push('{');
        json_kv_str(&mut s, "task_id", &format!("{:032x}", self.task_id.0));
        s.push(',');
        json_kv_str(&mut s, "goal", self.goal.as_str());
        s.push(',');
        json_kv_str(&mut s, "repo_root", &self.repo_root);
        s.push(',');
        json_kv_arr(&mut s, "allowed_roots", &self.allowed_roots);
        s.push(',');
        json_kv_arr(&mut s, "forbidden_paths", &self.forbidden_paths);
        s.push(',');
        json_kv_str(&mut s, "network", self.network.as_str());
        s.push(',');
        json_kv_str(&mut s, "secrets", self.secrets.as_str());
        s.push(',');
        s.push_str(&format!("\"max_seconds\":{}", self.max_seconds));
        s.push(',');
        s.push_str(&format!("\"max_output_mb\":{}", self.max_output_mb));
        s.push(',');
        json_kv_arr(
            &mut s,
            "must_return",
            &[
                "summary".to_string(),
                "diff".to_string(),
                "tests_run".to_string(),
                "commands_run".to_string(),
                "risks".to_string(),
                "files_changed".to_string(),
            ],
        );
        s.push('}');
        s
    }
}

/// The default off-limits paths advertised to a worker (`docs/backend-contract.md`
/// §4.1). These are *data* in the input JSON; confinement is enforced by the
/// sandbox and the [`GuardManifest`], not by trusting the worker to honor them.
#[must_use]
pub fn default_forbidden_paths() -> Vec<String> {
    ["~/.ssh", "~/.config", "/etc", "/var"]
        .iter()
        .map(|s| (*s).to_string())
        .collect()
}

/// The command an adapter wants run for a worker. Built by trusted code; the
/// `goal`/input is passed as argv/stdin **data**, never shell-interpreted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerCommand {
    /// Program to execute (resolved/absolute; not shell-parsed).
    pub program: String,
    /// Literal arguments.
    pub args: Vec<String>,
    /// Bytes piped to the worker's stdin (e.g. the input-contract JSON).
    pub stdin: Vec<u8>,
}

/// The one backend contract: anything that produces a candidate change implements
/// this. The supervisor never special-cases a worker's privileges by kind
/// (`docs/backend-contract.md` §1) — `kind` is provenance, not authority.
pub trait CodingBackend {
    /// Which backend this is (provenance only).
    fn kind(&self) -> BackendKind;

    /// Builds the sandboxed command that runs this worker for `input`.
    fn build_command(&self, input: &WorkerInput) -> WorkerCommand;

    /// Parses the worker's (untrusted) transcript into advisory claims. The
    /// default is conservative: `self_claimed_done` is true only if the explicit
    /// [`DONE_MARKER`] appears; no command/risk claims are extracted (everything a
    /// worker says is untrusted and re-derived by the supervisor anyway).
    fn parse_transcript(&self, transcript: &[u8]) -> WorkerClaims {
        let done = find_subslice(transcript, DONE_MARKER.as_bytes());
        WorkerClaims {
            self_claimed_done: done,
            commands_run: Vec::new(),
            risks: Vec::new(),
        }
    }
}

/// A generic external-command worker (P6.2): runs an explicit program with explicit
/// args, piping the input-contract JSON to stdin. Codex/Claude Code are thin
/// presets over this shape.
#[derive(Debug, Clone)]
pub struct ExternalCommandBackend {
    /// Program to run (absolute path or PATH-resolvable name).
    pub program: String,
    /// Literal args appended before the input JSON is piped to stdin.
    pub args: Vec<String>,
    /// The provenance reported for results (defaults to [`BackendKind::ExternalCommand`]).
    pub kind: BackendKind,
}

impl ExternalCommandBackend {
    /// A generic external worker running `program args…` with the input JSON on
    /// stdin.
    #[must_use]
    pub fn new(program: impl Into<String>, args: Vec<String>) -> Self {
        ExternalCommandBackend {
            program: program.into(),
            args,
            kind: BackendKind::ExternalCommand,
        }
    }
}

impl CodingBackend for ExternalCommandBackend {
    fn kind(&self) -> BackendKind {
        self.kind
    }

    fn build_command(&self, input: &WorkerInput) -> WorkerCommand {
        WorkerCommand {
            program: self.program.clone(),
            args: self.args.clone(),
            stdin: input.to_json().into_bytes(),
        }
    }
}

/// The Codex CLI adapter (P6.3). A thin preset over [`ExternalCommandBackend`]:
/// the default program is `codex` and the input contract is piped on stdin. The
/// exact argv is configuration (invariant 17: provider/tool names are config,
/// capability-probed), so the program and a `--`-terminated arg template are
/// overridable; the *security* properties (sandboxed, no secrets, confined diff)
/// hold regardless of the argv.
#[derive(Debug, Clone)]
pub struct CodexBackend {
    /// The codex program (default `codex`).
    pub program: String,
    /// Args passed before stdin (default: none).
    pub args: Vec<String>,
}

impl Default for CodexBackend {
    fn default() -> Self {
        CodexBackend {
            program: "codex".to_string(),
            args: Vec::new(),
        }
    }
}

impl CodingBackend for CodexBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Codex
    }

    fn build_command(&self, input: &WorkerInput) -> WorkerCommand {
        WorkerCommand {
            program: self.program.clone(),
            args: self.args.clone(),
            stdin: input.to_json().into_bytes(),
        }
    }
}

/// The Claude Code adapter (P6.4). Like [`CodexBackend`] but defaults the program
/// to `claude` and reports [`BackendKind::ClaudeCode`].
#[derive(Debug, Clone)]
pub struct ClaudeCodeBackend {
    /// The claude program (default `claude`).
    pub program: String,
    /// Args passed before stdin (default: none).
    pub args: Vec<String>,
}

impl Default for ClaudeCodeBackend {
    fn default() -> Self {
        ClaudeCodeBackend {
            program: "claude".to_string(),
            args: Vec::new(),
        }
    }
}

impl CodingBackend for ClaudeCodeBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::ClaudeCode
    }

    fn build_command(&self, input: &WorkerInput) -> WorkerCommand {
        WorkerCommand {
            program: self.program.clone(),
            args: self.args.clone(),
            stdin: input.to_json().into_bytes(),
        }
    }
}

/// Advisory claims parsed from a worker transcript. All untrusted (invariant 6).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkerClaims {
    /// The worker's claim that it finished — advisory, grants nothing.
    pub self_claimed_done: bool,
    /// Commands the worker says it ran — context only, not evidence.
    pub commands_run: Vec<CommandRecord>,
    /// Risks the worker surfaced.
    pub risks: Vec<Risk>,
}

/// How sensitive a changed file is, for the reviewer/security pass
/// (`docs/backend-contract.md` §4.2 "classify changed files").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sensitivity {
    /// An ordinary source/text file.
    Normal,
    /// A file that warrants extra scrutiny, with a short reason.
    Sensitive(&'static str),
}

/// A file the worker changed in the worktree, with its classification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangedFile {
    /// Worktree-relative path (confirmed in-root and symlink-safe).
    pub path: String,
    /// Its sensitivity classification.
    pub sensitivity: Sensitivity,
}

/// Errors from running/validating an external worker. Any of these **rejects the
/// result** — no patch is produced, so nothing can be verified or completed.
#[derive(Debug)]
pub enum WorkerError {
    /// A path outside the worktree changed during the worker run (invariant 6/7;
    /// `docs/backend-contract.md` §4.3). The result is rejected.
    OutOfRootWrite(String),
    /// A worktree-relative change resolves outside the root (a `..`/absolute/
    /// symlink escape). The result is rejected.
    EscapingChange(String),
    /// The worker could not run in the sandbox (no backend, setup failure, etc.).
    /// Not a pass: nothing is produced.
    Sandbox(String),
    /// Extracting the diff/status from the worktree failed.
    Git(String),
}

impl core::fmt::Display for WorkerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WorkerError::OutOfRootWrite(p) => {
                write!(f, "worker wrote outside the worktree: {p}")
            }
            WorkerError::EscapingChange(p) => {
                write!(f, "worker change escapes the worktree root: {p}")
            }
            WorkerError::Sandbox(e) => write!(f, "worker sandbox error: {e}"),
            WorkerError::Git(e) => write!(f, "worktree diff extraction failed: {e}"),
        }
    }
}

impl std::error::Error for WorkerError {}

impl From<ToolError> for WorkerError {
    fn from(e: ToolError) -> Self {
        WorkerError::Git(e.to_string())
    }
}

/// What an external worker produced — **before** verification. The patch is an
/// [`UnverifiedPatch`] by construction: this whole module never mints a
/// [`VerifiedPatch`](crate::VerifiedPatch) (that is [`verify::run_verify`](crate::verify)'s
/// sole job).
#[derive(Debug, Clone)]
pub struct WorkerProduct {
    /// The one backend contract value (`docs/backend-contract.md` §2.1).
    pub result: BackendResult,
    /// The proposed patch — unverified.
    pub patch: UnverifiedPatch,
    /// The real unified diff extracted from the worktree (bounded), not the
    /// worker's self-reported diff.
    pub diff: Vec<u8>,
    /// The classified changed-file list re-derived from the worktree.
    pub changed_files: Vec<ChangedFile>,
    /// The bounded, untrusted worker transcript.
    pub transcript: BoundedText,
    /// The advisory claims parsed from the transcript.
    pub claims: WorkerClaims,
}

/// Runs an external worker for `input` in `worktree`, **in the sandbox**, and
/// validates the result (`docs/backend-contract.md` §4.2). On success returns an
/// [`UnverifiedPatch`] product; the caller must still run the verifier to mint a
/// [`VerifiedPatch`](crate::VerifiedPatch).
///
/// Invariant-critical behavior:
/// - The worker runs with a built-from-scratch, secret-free environment (only a
///   safe `PATH`), deny-all egress, and the worktree as its only writable root
///   (invariants 1–3, 9).
/// - Any write outside the worktree, or any changed path that escapes the root,
///   **rejects** the result (invariant 6/7).
/// - The patch content is hashed from the **worktree's own** status+diff, never
///   from anything the worker claims.
///
/// # Errors
/// [`WorkerError`] if the worker could not run, wrote outside the worktree, or
/// produced an escaping change.
pub fn run_external_worker(
    backend: &dyn CodingBackend,
    input: &WorkerInput,
    worktree: &WorktreeRoot,
    cap: &SandboxExecCap,
    profile: &SandboxProfile,
) -> Result<WorkerProduct, WorkerError> {
    run_external_worker_with(backend, input, worktree, |command| {
        run_command(cap, profile, command)
    })
}

/// The worker orchestrator parameterized over the command executor. `exec` is the
/// only way the worker process runs; in production it is the sandbox
/// ([`run_command`]). Crate-private — exposing an alternative executor publicly
/// would be a footgun (the worker is meant to run sandboxed). The supervisor's
/// confinement checks (guard manifest, path confinement) run regardless of which
/// executor is used, and the verifier — the actual completion gate — always runs
/// sandboxed.
fn run_external_worker_with<E>(
    backend: &dyn CodingBackend,
    input: &WorkerInput,
    worktree: &WorktreeRoot,
    exec: E,
) -> Result<WorkerProduct, WorkerError>
where
    E: FnOnce(CommandSpec) -> Result<CommandResult, SandboxError>,
{
    let spec = build_command_spec(backend, input, worktree);

    // Canary the worktree's sibling space BEFORE running the worker, so a write
    // that lands outside the worktree is detected even where the OS sandbox is
    // non-functional (the sandbox is the primary defense; this is depth).
    let guard = GuardManifest::snapshot_parent(worktree);

    let result = exec(spec).map_err(|e| WorkerError::Sandbox(e.to_string()))?;

    // Reject the whole result if anything outside the worktree changed.
    guard.check()?;

    // Bounded, untrusted transcript (stdout then stderr).
    let mut bytes = result.stdout;
    bytes.extend_from_slice(&result.stderr);
    bytes.truncate(MAX_WORKER_OUTPUT);
    let transcript = BoundedText::truncated(String::from_utf8_lossy(&bytes), MAX_WORKER_OUTPUT);
    let claims = backend.parse_transcript(&bytes);

    // Re-derive the truth from the worktree: confined changed files + real diff.
    let changed_files = confine_worktree_changes(worktree)?;
    let (status_bytes, diff) = extract_change(worktree)?;

    // Content-address the patch over the worktree's OWN observed change state —
    // never the worker's self-reported diff.
    let mut addr = status_bytes;
    addr.extend_from_slice(&diff);
    let patch = PatchRef {
        diff_hash: sha256(&addr),
    };

    // Surface sensitive files as risks for the later reviewer/security pass.
    let mut risks = claims.risks.clone();
    for cf in &changed_files {
        if let Sensitivity::Sensitive(reason) = cf.sensitivity {
            risks.push(Risk {
                summary: BoundedText::truncated(
                    format!("sensitive file changed ({reason}): {}", cf.path),
                    BoundedText::DEFAULT_MAX,
                ),
            });
        }
    }

    let summary = BoundedText::truncated(summarize(transcript.as_str()), MAX_SUMMARY);
    let result = BackendResult {
        backend: backend.kind(),
        summary,
        patch: Some(patch.clone()),
        self_claimed_done: claims.self_claimed_done,
        commands_run: claims.commands_run.clone(),
        risks,
    };

    Ok(WorkerProduct {
        result,
        patch: UnverifiedPatch(patch),
        diff,
        changed_files,
        transcript,
        claims,
    })
}

/// Builds the sandboxed [`CommandSpec`] for a worker: the adapter's program/args,
/// the worktree as cwd, a **secret-free** environment (only a safe `PATH`), and
/// budgets from the input contract. The environment is built from scratch — the
/// host environment is never inherited — so no credential can leak to the worker
/// (invariants 1–3). The sandbox additionally sanitizes at the launch boundary.
fn build_command_spec(
    backend: &dyn CodingBackend,
    input: &WorkerInput,
    worktree: &WorktreeRoot,
) -> CommandSpec {
    let wc = backend.build_command(input);
    let mut env = BTreeMap::new();
    env.insert("PATH".to_string(), SAFE_PATH.to_string());

    let mut spec = CommandSpec::new(wc.program);
    spec.args = wc.args;
    spec.cwd = Some(worktree.as_path().to_string_lossy().into_owned());
    spec.env = env;
    // The input-contract JSON is delivered to the worker on stdin (as data), then
    // EOF. It is bounded (the contract shape), and the runner writes it after the
    // output readers start, so it cannot deadlock.
    spec.stdin = wc.stdin;
    spec.timeout = Duration::from_secs(input.max_seconds);
    spec.max_output_bytes = MAX_WORKER_OUTPUT;
    spec
}

/// Distills a bounded, single-line-ish summary from a transcript (first non-empty
/// lines). Untrusted content — used as a label, never as instructions.
fn summarize(transcript: &str) -> String {
    let mut out = String::new();
    for line in transcript.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str(line);
        if out.len() >= MAX_SUMMARY {
            break;
        }
    }
    if out.is_empty() {
        out.push_str("(worker produced no transcript output)");
    }
    out
}

/// Enumerates the worktree's changed files (`git status --porcelain`), **confines
/// every path** (rejecting `..`/absolute/symlink escapes — invariant 7), and
/// classifies each. A changed path that escapes the root rejects the whole result.
///
/// # Errors
/// [`WorkerError::EscapingChange`] for an escaping path, or [`WorkerError::Git`].
pub fn confine_worktree_changes(worktree: &WorktreeRoot) -> Result<Vec<ChangedFile>, WorkerError> {
    let cap = read_cap(worktree);
    let porcelain = git_status_all(&cap)?;
    let mut out = Vec::new();
    for line in porcelain.lines() {
        let Some(path) = porcelain_path(line) else {
            continue;
        };
        // Confine the changed path: it must resolve inside the worktree and not
        // traverse an escaping symlink. This is the per-path arm of "reject
        // outside-root changes".
        if worktree.confine_read(&path).is_err() {
            return Err(WorkerError::EscapingChange(path));
        }
        out.push(ChangedFile {
            sensitivity: classify(&path),
            path,
        });
    }
    Ok(out)
}

/// Extracts `(status_porcelain_bytes, diff_bytes)` from the worktree with the
/// hardened git wrappers (filter/textconv neutralized — no RCE). The diff is
/// bounded.
fn extract_change(worktree: &WorktreeRoot) -> Result<(Vec<u8>, Vec<u8>), WorkerError> {
    let cap = read_cap(worktree);
    let status = git_status_all(&cap)?.into_bytes();
    let mut diff = git_diff(&cap)?.into_bytes();
    diff.truncate(MAX_DIFF_BYTES);
    Ok((status, diff))
}

/// Builds a read capability for the worktree (a fresh confined root; scope is a
/// placeholder until the kernel wires real scopes through the worker path).
fn read_cap(worktree: &WorktreeRoot) -> FsReadCap {
    FsReadCap {
        root: worktree.clone(),
        scope: ScopeId(0),
    }
}

/// Parses the destination path from a `git status --porcelain` line, handling the
/// rename form `XY orig -> dest`. Returns `None` for a blank line. Quoted paths
/// (rare; `core.quotepath`) are returned verbatim and will fail confinement —
/// failing closed rather than silently mishandling them.
fn porcelain_path(line: &str) -> Option<String> {
    if line.len() < 4 {
        return None;
    }
    // Format: two status chars, a space, then the path (byte offset 3).
    let rest = &line[3..];
    let path = match rest.split_once(" -> ") {
        Some((_, dest)) => dest,
        None => rest,
    };
    let path = path.trim();
    if path.is_empty() {
        None
    } else {
        Some(path.to_string())
    }
}

/// Classifies a changed path for the reviewer/security pass.
fn classify(path: &str) -> Sensitivity {
    let lower = path.to_ascii_lowercase();
    let base = lower.rsplit('/').next().unwrap_or(&lower);

    if lower.starts_with(".github/workflows/") || lower.contains("/.github/workflows/") {
        return Sensitivity::Sensitive("ci-workflow");
    }
    // A change touching git metadata should never reach here (structured writes
    // refuse `.git`), but flag it loudly if a worker manufactured one.
    if lower == ".git" || lower.starts_with(".git/") || lower.contains("/.git/") {
        return Sensitivity::Sensitive("git-metadata");
    }
    const DEP_MANIFESTS: &[&str] = &[
        "cargo.toml",
        "cargo.lock",
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "go.mod",
        "go.sum",
        "requirements.txt",
        "pyproject.toml",
        "poetry.lock",
        "gemfile",
        "gemfile.lock",
    ];
    if DEP_MANIFESTS.contains(&base) {
        return Sensitivity::Sensitive("dependency-manifest");
    }
    const CRED_NEEDLES: &[&str] = &[
        "secret",
        "credential",
        "id_rsa",
        "id_ed25519",
        ".env",
        ".npmrc",
        ".pypirc",
        ".netrc",
    ];
    if CRED_NEEDLES.iter().any(|n| base.contains(n))
        || base.ends_with(".pem")
        || base.ends_with(".key")
    {
        return Sensitivity::Sensitive("possible-credential");
    }
    Sensitivity::Normal
}

// ---------------------------------------------------------------------------
// Out-of-root write detection: the guard manifest
// ---------------------------------------------------------------------------

/// A point-in-time snapshot of a set of guard roots, used to detect writes
/// **outside** the worktree (`docs/backend-contract.md` §4.2 "reject outside-root
/// changes"). The OS sandbox is the primary defense (it makes everything but the
/// worktree read-only/absent); this manifest is defense in depth that holds even
/// where the sandbox is non-functional, and it makes out-of-root rejection
/// deterministically testable.
///
/// It snapshots the worktree's **sibling space** (its parent, excluding the
/// worktree subtree) — the directory disposable worktrees live in — so a worker
/// scribbling on a sibling worktree, the worktree base, or an adjacent file is
/// caught. It deliberately does **not** recursively walk system directories
/// (`/etc`, `/var`) — that is expensive and racy, and is exactly what the sandbox
/// confines.
#[derive(Debug, Clone)]
pub struct GuardManifest {
    entries: BTreeMap<PathBuf, GuardEntry>,
    roots: Vec<PathBuf>,
    excluded: Vec<PathBuf>,
    truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GuardEntry {
    is_dir: bool,
    len: u64,
    mtime: Option<Duration>,
}

impl GuardManifest {
    /// Snapshots the parent of `worktree` (excluding the worktree subtree itself).
    #[must_use]
    pub fn snapshot_parent(worktree: &WorktreeRoot) -> GuardManifest {
        let wt = worktree.as_path().to_path_buf();
        match wt.parent() {
            Some(parent) => {
                GuardManifest::snapshot(std::slice::from_ref(&parent.to_path_buf()), &[wt])
            }
            // Degenerate: worktree has no parent (filesystem root). Nothing to guard.
            None => GuardManifest {
                entries: BTreeMap::new(),
                roots: Vec::new(),
                excluded: Vec::new(),
                truncated: false,
            },
        }
    }

    /// Snapshots `roots` recursively (bounded), pruning any path equal to or under
    /// an `exclude` entry. Public so the red-team suite can canary an arbitrary
    /// directory directly.
    #[must_use]
    pub fn snapshot(roots: &[PathBuf], exclude: &[PathBuf]) -> GuardManifest {
        let mut entries = BTreeMap::new();
        let mut truncated = false;
        for root in roots {
            walk_guard(root, exclude, &mut entries, &mut truncated, 0);
        }
        GuardManifest {
            entries,
            roots: roots.to_vec(),
            excluded: exclude.to_vec(),
            truncated,
        }
    }

    /// Re-snapshots the same roots and rejects if anything changed (added, removed,
    /// or modified). Fails closed: if the original walk was truncated, any size
    /// change is still detected, and a re-walk that is itself truncated cannot
    /// silently hide an addition because entries are compared by sorted path.
    ///
    /// # Errors
    /// [`WorkerError::OutOfRootWrite`] naming the first changed path.
    pub fn check(&self) -> Result<(), WorkerError> {
        let now = GuardManifest::snapshot(&self.roots, &self.excluded);
        // Any path present in exactly one snapshot, or whose entry differs, is a
        // change outside the worktree.
        for (path, before) in &self.entries {
            match now.entries.get(path) {
                Some(after) if after == before => {}
                _ => return Err(WorkerError::OutOfRootWrite(path.display().to_string())),
            }
        }
        for path in now.entries.keys() {
            if !self.entries.contains_key(path) {
                return Err(WorkerError::OutOfRootWrite(path.display().to_string()));
            }
        }
        Ok(())
    }

    /// Whether the snapshot hit the entry cap (bounded walk). Exposed for callers
    /// that want to surface it as a risk.
    #[must_use]
    pub fn truncated(&self) -> bool {
        self.truncated
    }
}

/// Recursively records guard entries under `dir`, pruning excluded subtrees and
/// respecting the entry/depth caps. Symlinks are recorded as entries but **not
/// followed** (a symlinked directory is not descended), so the walk cannot be
/// redirected outside the guard roots.
fn walk_guard(
    dir: &Path,
    exclude: &[PathBuf],
    entries: &mut BTreeMap<PathBuf, GuardEntry>,
    truncated: &mut bool,
    depth: usize,
) {
    if depth > MAX_GUARD_DEPTH {
        *truncated = true;
        return;
    }
    let read = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(_) => return,
    };
    for entry in read.flatten() {
        if entries.len() >= MAX_GUARD_ENTRIES {
            *truncated = true;
            return;
        }
        let path = entry.path();
        if exclude.iter().any(|ex| path == *ex || path.starts_with(ex)) {
            continue;
        }
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let ft = meta.file_type();
        let is_dir = ft.is_dir();
        let ge = GuardEntry {
            is_dir,
            len: meta.len(),
            mtime: meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(SystemTime::UNIX_EPOCH).ok()),
        };
        entries.insert(path.clone(), ge);
        // Descend into real directories only (never through symlinks).
        if is_dir && !ft.is_symlink() {
            walk_guard(&path, exclude, entries, truncated, depth + 1);
        }
    }
}

// ---------------------------------------------------------------------------
// tiny helpers (no serde in nano)
// ---------------------------------------------------------------------------

/// Appends `"key":"<escaped value>"` to `s`.
fn json_kv_str(s: &mut String, key: &str, value: &str) {
    s.push('"');
    s.push_str(key);
    s.push_str("\":");
    json_str(s, value);
}

/// Appends `"key":[ "<v0>", "<v1>", … ]` to `s`.
fn json_kv_arr(s: &mut String, key: &str, values: &[String]) {
    s.push('"');
    s.push_str(key);
    s.push_str("\":[");
    for (i, v) in values.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        json_str(s, v);
    }
    s.push(']');
}

/// Appends a JSON-escaped string literal (quotes included).
fn json_str(s: &mut String, value: &str) {
    s.push('"');
    for c in value.chars() {
        match c {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            '\n' => s.push_str("\\n"),
            '\r' => s.push_str("\\r"),
            '\t' => s.push_str("\\t"),
            c if (c as u32) < 0x20 => s.push_str(&format!("\\u{:04x}", c as u32)),
            c => s.push(c),
        }
    }
    s.push('"');
}

/// Whether `haystack` contains `needle` (small, allocation-free substring search).
fn find_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cc-worker-{tag}-{}-{}",
            std::process::id(),
            std::thread::current()
                .name()
                .unwrap_or("t")
                .replace("::", "_")
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn fake_result(stdout: &[u8]) -> CommandResult {
        CommandResult {
            status: crustcore_runner::ExitStatus::Code(0),
            stdout: stdout.to_vec(),
            stderr: Vec::new(),
            truncated: false,
        }
    }

    // --- input contract ---

    #[test]
    fn worker_input_json_pins_secrets_none_and_network_deny() {
        let dir = tmp("json");
        let wt = WorktreeRoot::open(&dir).unwrap();
        let input = WorkerInput::for_task(TaskId(1), "fix the bug", &wt);
        let json = input.to_json();
        assert!(json.contains("\"secrets\":\"none\""), "{json}");
        assert!(json.contains("\"network\":\"deny\""), "{json}");
        assert!(json.contains("\"must_return\":["));
        for field in [
            "summary",
            "diff",
            "tests_run",
            "commands_run",
            "risks",
            "files_changed",
        ] {
            assert!(json.contains(&format!("\"{field}\"")), "missing {field}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn worker_input_json_escapes_goal() {
        let dir = tmp("jsonesc");
        let wt = WorktreeRoot::open(&dir).unwrap();
        // A goal with quotes/newlines must not break the JSON or smuggle structure.
        let input = WorkerInput::for_task(TaskId(1), "do \"x\"\nthen y", &wt);
        let json = input.to_json();
        assert!(json.contains("do \\\"x\\\"\\nthen y"), "{json}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- the secret-free, sandboxed command spec ---

    #[test]
    fn command_spec_env_has_only_path_no_secrets() {
        let dir = tmp("env");
        let wt = WorktreeRoot::open(&dir).unwrap();
        let input = WorkerInput::for_task(TaskId(1), "g", &wt);
        let backend = CodexBackend::default();
        let spec = build_command_spec(&backend, &input, &wt);
        // Built from scratch: exactly PATH, nothing inherited.
        assert_eq!(spec.env.keys().cloned().collect::<Vec<_>>(), vec!["PATH"]);
        assert_eq!(
            spec.cwd.as_deref(),
            Some(wt.as_path().to_string_lossy().as_ref())
        );
        assert_eq!(spec.timeout, Duration::from_secs(1800));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn adapters_report_distinct_kinds() {
        assert_eq!(CodexBackend::default().kind(), BackendKind::Codex);
        assert_eq!(ClaudeCodeBackend::default().kind(), BackendKind::ClaudeCode);
        assert_eq!(
            ExternalCommandBackend::new("x", vec![]).kind(),
            BackendKind::ExternalCommand
        );
    }

    // --- transcript claims are advisory ---

    #[test]
    fn done_marker_is_parsed_but_advisory() {
        let backend = ExternalCommandBackend::new("x", vec![]);
        assert!(!backend.parse_transcript(b"working...").self_claimed_done);
        let claims = backend.parse_transcript(b"done now [[CRUSTCORE_DONE]] bye");
        assert!(claims.self_claimed_done);
        // Advisory only: nothing here produces a VerifiedPatch — there is no API on
        // WorkerClaims/WorkerProduct that completes a task.
    }

    // --- guard manifest: out-of-root detection ---

    #[test]
    fn guard_detects_sibling_write() {
        let base = tmp("guard");
        let wt_dir = base.join("cc-wt-1");
        std::fs::create_dir_all(&wt_dir).unwrap();
        let wt = WorktreeRoot::open(&wt_dir).unwrap();

        let guard = GuardManifest::snapshot_parent(&wt);
        // Clean: nothing changed outside the worktree.
        assert!(guard.check().is_ok());

        // A write INSIDE the worktree is allowed (excluded from the guard).
        std::fs::write(wt_dir.join("in_root.txt"), b"ok").unwrap();
        assert!(
            guard.check().is_ok(),
            "in-worktree writes must not trip the guard"
        );

        // A write to a SIBLING of the worktree (outside it) is detected.
        std::fs::write(base.join("escaped.txt"), b"pwned").unwrap();
        assert!(matches!(guard.check(), Err(WorkerError::OutOfRootWrite(_))));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn guard_detects_change_to_forbidden_canary_dir() {
        let home = tmp("home");
        let ssh = home.join(".ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        std::fs::write(ssh.join("authorized_keys"), b"existing\n").unwrap();

        let guard = GuardManifest::snapshot(std::slice::from_ref(&home), &[]);
        assert!(guard.check().is_ok());

        // The classic worker escape: append to ~/.ssh/authorized_keys.
        std::fs::write(ssh.join("authorized_keys"), b"existing\nattacker-key\n").unwrap();
        assert!(matches!(guard.check(), Err(WorkerError::OutOfRootWrite(_))));

        let _ = std::fs::remove_dir_all(&home);
    }

    // --- porcelain parsing + classification ---

    #[test]
    fn porcelain_parsing_and_classification() {
        assert_eq!(
            porcelain_path(" M src/lib.rs").as_deref(),
            Some("src/lib.rs")
        );
        assert_eq!(porcelain_path("?? new.txt").as_deref(), Some("new.txt"));
        assert_eq!(
            porcelain_path("R  old.rs -> new.rs").as_deref(),
            Some("new.rs")
        );
        assert_eq!(porcelain_path(""), None);

        assert_eq!(classify("src/main.rs"), Sensitivity::Normal);
        assert_eq!(
            classify(".github/workflows/ci.yml"),
            Sensitivity::Sensitive("ci-workflow")
        );
        assert_eq!(
            classify("Cargo.toml"),
            Sensitivity::Sensitive("dependency-manifest")
        );
        assert_eq!(
            classify("crates/x/Cargo.lock"),
            Sensitivity::Sensitive("dependency-manifest")
        );
        assert_eq!(
            classify("config/prod.env"),
            Sensitivity::Sensitive("possible-credential")
        );
        assert_eq!(
            classify("keys/server.pem"),
            Sensitivity::Sensitive("possible-credential")
        );
    }

    // --- end-to-end via the executor seam (no OS sandbox needed) ---

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

    /// A worktree-shaped git repo for seam tests, nested under a private per-test
    /// base so the worktree's *parent* (which the out-of-root guard snapshots)
    /// contains only this worktree — mirroring production, where worktrees live
    /// under a dedicated base, not the shared temp dir. Returns `(base, worktree
    /// dir, root)` or `None` if git is missing.
    fn git_worktree(tag: &str) -> Option<(PathBuf, PathBuf, WorktreeRoot)> {
        let base = tmp(tag);
        let dir = base.join("wt");
        std::fs::create_dir_all(&dir).unwrap();
        if !git(&dir, &["init", "-q"]) {
            eprintln!("skipping: git unavailable");
            let _ = std::fs::remove_dir_all(&base);
            return None;
        }
        std::fs::write(dir.join("README.md"), b"hello\n").ok()?;
        git(&dir, &["add", "."]);
        git(
            &dir,
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
        );
        let root = WorktreeRoot::open(&dir).unwrap();
        Some((base, dir, root))
    }

    #[test]
    fn seam_extracts_diff_from_worktree_not_worker_claim() {
        let Some((base, dir, wt)) = git_worktree("diff-truth") else {
            return;
        };
        let backend = ExternalCommandBackend::new("/bin/true", vec![]);
        let input = WorkerInput::for_task(TaskId(1), "g", &wt);

        // The "worker" runs (the seam): it makes a REAL in-root change, and its
        // transcript LIES about a different diff.
        let dir2 = dir.clone();
        let product = run_external_worker_with(&backend, &input, &wt, move |_spec| {
            std::fs::write(dir2.join("README.md"), b"hello\nreal-change\n").unwrap();
            Ok(fake_result(
                b"I changed totally_different_file.rs\n[[CRUSTCORE_DONE]]\n",
            ))
        })
        .expect("worker produces an unverified patch");

        // The patch is content-addressed over the worktree's OWN change, and the
        // extracted diff reflects the real edit — not the worker's claim.
        assert!(product.patch.0.diff_hash != [0u8; 32]);
        let diff = String::from_utf8_lossy(&product.diff);
        assert!(diff.contains("real-change"), "diff from worktree: {diff}");
        assert!(
            !diff.contains("totally_different_file"),
            "diff must come from the worktree, not the transcript claim"
        );
        // self_claimed_done is carried but advisory.
        assert!(product.result.self_claimed_done);
        assert!(matches!(product.patch, UnverifiedPatch(_)));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn seam_rejects_out_of_root_write() {
        let Some((base, _dir, wt)) = git_worktree("oob") else {
            return;
        };
        let backend = ExternalCommandBackend::new("/bin/true", vec![]);
        let input = WorkerInput::for_task(TaskId(1), "g", &wt);

        // The "worker" writes OUTSIDE the worktree (a sibling under the base). Must
        // be rejected: no product, hence no patch, hence nothing to verify/complete.
        let base2 = base.clone();
        let err = run_external_worker_with(&backend, &input, &wt, move |_spec| {
            std::fs::write(base2.join("escaped.txt"), b"pwned").unwrap();
            Ok(fake_result(b"done\n"))
        })
        .unwrap_err();
        assert!(matches!(err, WorkerError::OutOfRootWrite(_)), "{err}");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn seam_surfaces_sandbox_error() {
        let Some((base, _dir, wt)) = git_worktree("sberr") else {
            return;
        };
        let backend = ExternalCommandBackend::new("/bin/true", vec![]);
        let input = WorkerInput::for_task(TaskId(1), "g", &wt);
        let err =
            run_external_worker_with(&backend, &input, &wt, |_spec| Err(SandboxError::NoBackend))
                .unwrap_err();
        assert!(matches!(err, WorkerError::Sandbox(_)), "{err}");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn seam_flags_sensitive_changed_file_as_risk() {
        let Some((base, dir, wt)) = git_worktree("sensitive") else {
            return;
        };
        let backend = ExternalCommandBackend::new("/bin/true", vec![]);
        let input = WorkerInput::for_task(TaskId(1), "g", &wt);
        let dir2 = dir.clone();
        let product = run_external_worker_with(&backend, &input, &wt, move |_spec| {
            std::fs::create_dir_all(dir2.join(".github/workflows")).unwrap();
            std::fs::write(dir2.join(".github/workflows/ci.yml"), b"on: push\n").unwrap();
            Ok(fake_result(b"added ci\n"))
        })
        .expect("produces a patch");
        assert!(
            product
                .changed_files
                .iter()
                .any(|c| matches!(c.sensitivity, Sensitivity::Sensitive("ci-workflow"))),
            "ci workflow change should be classified sensitive: {:?}",
            product.changed_files
        );
        assert!(
            product
                .result
                .risks
                .iter()
                .any(|r| r.summary.as_str().contains("ci-workflow")),
            "sensitive change should surface as a risk"
        );
        let _ = std::fs::remove_dir_all(&base);
    }
}
