// SPDX-License-Identifier: Apache-2.0
//! The `crustcore` nano binary entry point.
//!
//! Implements `--version`/`--help`, `run` (Phase 5: create a disposable worktree,
//! rerun the verify command in a sandbox, complete only on a `VerifiedPatch`),
//! `inspect <log>` and `export <log>` (Phase 2: verify/replay the hash-chained
//! event log and render it as JSONL), and a hidden `selftest` that drives the
//! kernel + event-log pipeline so the trusted-core crates are linked and checked.
//! See ROADMAP.md §18.
#![forbid(unsafe_code)]

use std::process::ExitCode;

use crustcore_backend::verify::{run_verify, VerifyIds, VerifyOutcome, VerifySpec};
use crustcore_backend::worker::{
    run_external_worker, ClaudeCodeBackend, CodexBackend, CodingBackend, ExternalCommandBackend,
    WorkerInput, WorkerProduct,
};
use crustcore_backend::{complete_task, PatchRef};
use crustcore_cli::{Command, RunArgs};
use crustcore_eventlog::{ChainStatus, EventLog, FrameMeta};
use crustcore_kernel::{Actor, Event, EventKind, Kernel, Visibility};
use crustcore_policy::{PolicySnapshot, RiskProfile, SandboxExecCap};
use crustcore_receipts::{MacKey, ReceiptChain};
use crustcore_sandbox::SandboxProfile;
use crustcore_types::hash::sha256;
use crustcore_types::{EventSeq, JobId, ScopeId, TaskId, Timestamp, ToolCallId};
use crustcore_worktree::WorktreeManager;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // Hidden self-test used by CI to prove the trusted-core pipeline links/runs.
    if args.first().map(String::as_str) == Some("selftest") {
        return selftest();
    }

    match crustcore_cli::parse(&args) {
        Command::Version => {
            println!("crustcore {}", crustcore_cli::VERSION);
            ExitCode::SUCCESS
        }
        Command::Help => {
            print!("{}", crustcore_cli::help_text());
            ExitCode::SUCCESS
        }
        Command::Run => run_task(&args[1..]),
        Command::Inspect => inspect(args.get(1).map(String::as_str)),
        Command::Export => export(args.get(1).map(String::as_str)),
        Command::Unknown(cmd) => {
            eprintln!("crustcore: unknown command '{cmd}'\n");
            print!("{}", crustcore_cli::help_text());
            ExitCode::from(2)
        }
    }
}

/// `crustcore run -dir <repo> -goal <text> -verify <command>` — create a
/// disposable worktree, rerun the verify command in a clean sandbox, and complete
/// the task only if it passes (invariant 13). On failure or a missing sandbox
/// backend, exits non-zero with a clear state — nothing is "done" without
/// verifier evidence.
fn run_task(run_args: &[String]) -> ExitCode {
    let parsed = match crustcore_cli::parse_run(run_args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("crustcore run: {e}");
            eprintln!("usage: crustcore run -dir <repo> -goal <text> -verify <command>");
            return ExitCode::from(2);
        }
    };

    let dir = parsed.dir.as_deref().unwrap_or(".");
    let repo_root = match std::fs::canonicalize(dir) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("crustcore run: cannot resolve -dir '{dir}': {e}");
            return ExitCode::from(2);
        }
    };

    // Resolve the verify command: explicit `-verify` or best-effort detection.
    let spec = match resolve_verify_spec(parsed.verify.as_deref(), &repo_root) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("crustcore run: {e}");
            return ExitCode::from(2);
        }
    };

    // Validate the backend selection up front (before any side effect).
    let backend = match select_backend(&parsed) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("crustcore run: {e}");
            return ExitCode::from(2);
        }
    };

    if let Some(goal) = parsed.goal.as_deref() {
        println!("goal: {goal}");
    }
    println!("backend: {}", backend.label());
    println!("verify: {}", spec.display());

    // One task per `run` (the autonomous, multi-task supervisor is later phases).
    let task = TaskId(1);
    let manager = WorktreeManager::new(&repo_root);
    let worktree = match manager.create_for(task) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("crustcore run: could not create worktree: {e}");
            return ExitCode::from(1);
        }
    };
    println!("worktree: {}", worktree.as_path().display());

    let cap = SandboxExecCap {
        profile: ScopeId(1),
        scope: ScopeId(1),
    };
    let profile = SandboxProfile::default_sandboxed();

    // Produce a candidate change. The native path verifies the worktree as-is and
    // references the verified state by HEAD. An external worker (codex/claude/cmd)
    // runs sandboxed with no secrets, then CrustCore re-derives the real diff from
    // the worktree and rejects any out-of-root write — the patch a worker produces
    // is an *unverified* proposal (invariants 6/7). Either way the verifier below is
    // the only thing that can complete the task (invariant 13).
    let patch = match produce_patch(&backend, &parsed, &manager, &worktree, &cap, &profile) {
        Ok(p) => p,
        Err(code) => {
            let _ = manager.remove(&worktree);
            return code;
        }
    };

    let mut receipts = ReceiptChain::new(MacKey::new(run_key()));
    let ids = VerifyIds {
        task_id: task,
        job_id: JobId(1),
        tool_call_id: ToolCallId(1),
        event_seq: EventSeq(1),
        now: now_ts(),
    };

    let outcome = run_verify(&cap, &profile, &worktree, &spec, patch, &mut receipts, &ids);
    let code = match outcome {
        VerifyOutcome::Verified(verified) => {
            let _completion = complete_task(*verified);
            println!("VERIFIED: '{}' passed — task completed.", spec.display());
            ExitCode::SUCCESS
        }
        VerifyOutcome::Failed { status, output } => {
            eprintln!("VERIFY FAILED ({status:?}) — task NOT completed.");
            if !output.as_str().is_empty() {
                eprintln!("--- verify output (bounded) ---");
                eprint!("{}", output.as_str());
                if !output.as_str().ends_with('\n') {
                    eprintln!();
                }
            }
            ExitCode::from(1)
        }
        VerifyOutcome::Refused(reason) => {
            eprintln!("VERIFY REFUSED: {reason}");
            eprintln!(
                "execution requires a sandbox backend (Linux bubblewrap); \
                 see docs/sandbox.md. Nothing is completed without sandboxed verifier evidence."
            );
            ExitCode::from(1)
        }
    };

    // Tear down the disposable worktree on every path (best-effort).
    let _ = manager.remove(&worktree);
    code
}

/// The coding backend selected for a run. `Native` verifies the worktree as-is;
/// the others run an external worker that produces a candidate change first.
enum Backend {
    /// No external worker: verify the worktree as it stands (Phase 5 behavior).
    Native,
    /// Codex CLI worker.
    Codex,
    /// Claude Code worker.
    ClaudeCode,
    /// A generic external worker: `program` + literal `args`.
    Cmd(String, Vec<String>),
}

impl Backend {
    fn label(&self) -> String {
        match self {
            Backend::Native => "native (verify worktree as-is)".to_string(),
            Backend::Codex => "codex".to_string(),
            Backend::ClaudeCode => "claude".to_string(),
            Backend::Cmd(p, _) => format!("cmd ({p})"),
        }
    }

    /// Builds the trait object for an external worker, or `None` for `Native`.
    fn as_coding_backend(&self) -> Option<Box<dyn CodingBackend>> {
        match self {
            Backend::Native => None,
            Backend::Codex => Some(Box::new(CodexBackend::default())),
            Backend::ClaudeCode => Some(Box::new(ClaudeCodeBackend::default())),
            Backend::Cmd(p, a) => Some(Box::new(ExternalCommandBackend::new(p.clone(), a.clone()))),
        }
    }
}

/// Selects the backend from `-backend`/`-worker-cmd`. The `-worker-cmd` string is
/// split on whitespace into program + args with **no shell interpretation**
/// (invariant 7), mirroring `-verify`.
///
/// # Errors
/// Returns a message for an unknown backend or a missing/empty `-worker-cmd`.
fn select_backend(parsed: &RunArgs) -> Result<Backend, String> {
    match parsed.backend.as_deref() {
        None | Some("native") => Ok(Backend::Native),
        Some("codex") => Ok(Backend::Codex),
        Some("claude") => Ok(Backend::ClaudeCode),
        Some("cmd") => {
            let raw = parsed
                .worker_cmd
                .as_deref()
                .ok_or("-backend cmd requires -worker-cmd <command>")?;
            let mut toks = raw.split_whitespace().map(str::to_string);
            let program = toks.next().ok_or("-worker-cmd was empty")?;
            Ok(Backend::Cmd(program, toks.collect()))
        }
        Some(other) => Err(format!(
            "unknown -backend '{other}' (expected native|codex|claude|cmd)"
        )),
    }
}

/// Produces the candidate patch reference for the run. For `Native`, this is the
/// worktree HEAD (no external change). For an external worker, it runs the worker
/// sandboxed, re-derives the real diff from the worktree, and returns the
/// *unverified* patch reference — failing (with a non-zero [`ExitCode`]) if the
/// worker could not run sandboxed, wrote outside the worktree, or produced an
/// escaping change. Nothing here completes the task; the verifier does.
fn produce_patch(
    backend: &Backend,
    parsed: &RunArgs,
    manager: &WorktreeManager,
    worktree: &crustcore_path::WorktreeRoot,
    cap: &SandboxExecCap,
    profile: &SandboxProfile,
) -> Result<PatchRef, ExitCode> {
    let Some(coding) = backend.as_coding_backend() else {
        // Native: reference the verified state by HEAD (no diffing, canonical repo
        // untouched). Precise patch-content addressing is the worker path's job.
        let head = manager.head_commit(worktree).unwrap_or_default();
        return Ok(PatchRef {
            diff_hash: sha256(head.as_bytes()),
        });
    };

    let goal = parsed.goal.as_deref().unwrap_or("");
    let input = WorkerInput::for_task(TaskId(1), goal, worktree);
    match run_external_worker(coding.as_ref(), &input, worktree, cap, profile) {
        Ok(product) => {
            report_product(&product);
            // The worker's proposal is unverified; take only its re-derived patch
            // reference. self_claimed_done / commands_run are advisory metadata.
            Ok(product.patch.0)
        }
        Err(e) => {
            eprintln!("WORKER REJECTED: {e}");
            eprintln!(
                "the worker's result was not accepted; nothing is completed without a \
                 verified, confined patch (invariants 6, 7, 13)."
            );
            Err(ExitCode::from(1))
        }
    }
}

/// Prints a bounded summary of what a worker produced (all untrusted/derived).
fn report_product(product: &WorkerProduct) {
    println!(
        "worker produced a candidate change: {} file(s) changed",
        product.changed_files.len()
    );
    for cf in &product.changed_files {
        match &cf.sensitivity {
            crustcore_backend::worker::Sensitivity::Sensitive(reason) => {
                println!("  - {} [SENSITIVE: {reason}]", cf.path);
            }
            crustcore_backend::worker::Sensitivity::Normal => {
                println!("  - {}", cf.path);
            }
        }
    }
    if !product.result.risks.is_empty() {
        println!("worker-flagged risks: {}", product.result.risks.len());
    }
    if product.result.self_claimed_done {
        println!("note: worker self-claimed done (advisory only — the verifier decides).");
    }
}

/// Resolves the verify command from an explicit `-verify` string or, when absent,
/// by detecting it from the repo shape. The explicit string is split on
/// whitespace into program + args with **no shell interpretation**, so an
/// untrusted value cannot smuggle a second command (invariant 7).
///
/// # Errors
/// Returns a message if `-verify` is empty/blank or no command can be detected.
fn resolve_verify_spec(
    verify: Option<&str>,
    repo_root: &std::path::Path,
) -> Result<VerifySpec, String> {
    match verify {
        Some(raw) => {
            let mut toks = raw.split_whitespace().map(str::to_string);
            match toks.next() {
                Some(program) => Ok(VerifySpec::new(program, toks.collect())),
                None => Err("-verify was empty".to_string()),
            }
        }
        None => VerifySpec::detect(repo_root).ok_or_else(|| {
            "no -verify command given and none could be detected \
             (no Cargo.toml/package.json/Makefile)"
                .to_string()
        }),
    }
}

/// A per-run MAC key for the receipt chain. CrustCore holds this key; the model
/// never does, so receipts are unforgeable (invariant 10). Persistent key
/// management arrives with the runtime; for a single local run we draw a fresh
/// random key (falling back to a fixed dev key if the OS RNG is unavailable).
fn run_key() -> [u8; 32] {
    use std::io::Read as _;
    let mut key = [0u8; 32];
    // Read exactly 32 bytes — `/dev/urandom` never reaches EOF, so a bounded
    // `read_exact` is required (a plain read-to-end would never return).
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if f.read_exact(&mut key).is_ok() {
            return key;
        }
    }
    // Deterministic fallback (no OS RNG): clearly-marked dev key.
    for (i, b) in key.iter_mut().enumerate() {
        *b = 0xC0u8 ^ (i as u8);
    }
    key
}

/// Wall-clock timestamp for stamping the verify run. Time is supplied by the
/// adapter layer (here, the CLI), never read inside the kernel.
fn now_ts() -> Timestamp {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    Timestamp::from_millis(ms)
}

fn load_log(path: Option<&str>, cmd: &str) -> Result<EventLog, ExitCode> {
    let Some(path) = path else {
        eprintln!("crustcore: '{cmd}' needs a log path — usage: crustcore {cmd} <log-file>");
        return Err(ExitCode::from(2));
    };
    match std::fs::read(path) {
        Ok(bytes) => Ok(EventLog::from_bytes(bytes)),
        Err(e) => {
            eprintln!("crustcore: cannot read '{path}': {e}");
            Err(ExitCode::from(2))
        }
    }
}

/// `crustcore inspect <log>` — verify the chain and print a task summary. Exits
/// non-zero if the chain is broken (so scripts can gate on integrity).
fn inspect(path: Option<&str>) -> ExitCode {
    let log = match load_log(path, "inspect") {
        Ok(l) => l,
        Err(code) => return code,
    };
    let report = log.inspect();
    print!("{report}");
    match report.status {
        ChainStatus::Intact { .. } => ExitCode::SUCCESS,
        ChainStatus::Broken { .. } => ExitCode::from(1),
    }
}

/// `crustcore export <log>` — render the log as JSONL on stdout. The export is
/// verification-gated (only verified frames are emitted, and never a tampered
/// payload); if the chain is broken, a diagnostic goes to stderr and the exit
/// code is non-zero so a pipeline notices.
fn export(path: Option<&str>) -> ExitCode {
    let log = match load_log(path, "export") {
        Ok(l) => l,
        Err(code) => return code,
    };
    print!("{}", log.export_jsonl());
    match log.verify() {
        ChainStatus::Intact { .. } => ExitCode::SUCCESS,
        ChainStatus::Broken {
            frame_index,
            reason,
        } => {
            eprintln!(
                "crustcore: WARNING — chain broken at frame {frame_index}: {reason}; \
                 only the verified prefix was exported."
            );
            ExitCode::from(1)
        }
    }
}

/// Drives the kernel + event log to confirm the trusted core is wired together.
fn selftest() -> ExitCode {
    // Kernel pipeline.
    let mut kernel = Kernel::new(PolicySnapshot::new(RiskProfile::Supervised));
    let actions = kernel.step(Event::internal(EventKind::TaskCreated));

    // Event-log pipeline: append a couple of frames and verify the chain.
    let mut log = EventLog::new();
    log.append(
        &FrameMeta::new(1, EventKind::TaskCreated)
            .actor(Actor::Adapter)
            .visibility(Visibility::Internal),
        b"selftest",
    );
    log.append(
        &FrameMeta::new(2, EventKind::TaskCompleted).actor(Actor::Kernel),
        b"ok",
    );
    let intact = log.verify().is_intact();

    println!(
        "crustcore selftest ok: kernel produced {} action(s), next_seq={}; \
         event log {} frame(s), chain {}",
        actions.len(),
        kernel.next_seq().0,
        log.len(),
        if intact { "INTACT" } else { "BROKEN" },
    );
    if intact {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_verify_spec_splits_without_shell_interpretation() {
        // A shell-injection attempt is split on whitespace into inert argv tokens:
        // `true` runs with `;`, `rm`, ... as literal args — no second command runs.
        let dir = std::env::temp_dir();
        let spec = resolve_verify_spec(Some("true ; rm -rf /"), &dir).unwrap();
        assert_eq!(spec.program, "true");
        assert_eq!(spec.args, vec![";", "rm", "-rf", "/"]);
        // Quotes are literal, not shell-stripped.
        let spec2 = resolve_verify_spec(Some("sh -c \"evil\""), &dir).unwrap();
        assert_eq!(spec2.program, "sh");
        assert_eq!(spec2.args, vec!["-c", "\"evil\""]);
    }

    #[test]
    fn resolve_verify_spec_rejects_blank_and_detects_otherwise() {
        let dir = std::env::temp_dir().join(format!("cc-rvs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Blank -verify is an error.
        assert!(resolve_verify_spec(Some("   "), &dir).is_err());
        // No -verify and no recognizable project => error (no guessing).
        assert!(resolve_verify_spec(None, &dir).is_err());
        // No -verify but a Cargo.toml => detected `cargo test`.
        std::fs::write(dir.join("Cargo.toml"), b"[package]\n").unwrap();
        let detected = resolve_verify_spec(None, &dir).unwrap();
        assert_eq!(detected.program, "cargo");
        assert_eq!(detected.args, vec!["test"]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_key_returns_nonzero_key() {
        // Either the OS RNG (normal) or the deterministic fallback yields a
        // non-zero 32-byte key; an all-zero key would be a bug.
        assert_ne!(run_key(), [0u8; 32]);
    }
}
