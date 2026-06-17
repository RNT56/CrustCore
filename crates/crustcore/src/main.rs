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
use crustcore_backend::{complete_task, PatchRef};
use crustcore_cli::Command;
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

    if let Some(goal) = parsed.goal.as_deref() {
        println!("goal: {goal}");
    }
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

    // Reference the verified state by the worktree's HEAD commit (no diffing, so
    // the canonical repo is never mutated). Precise patch-content addressing
    // arrives with the backends that produce diffs (Phase 6).
    let head = manager.head_commit(&worktree).unwrap_or_default();
    let patch = PatchRef {
        diff_hash: sha256(head.as_bytes()),
    };

    let cap = SandboxExecCap {
        profile: ScopeId(1),
        scope: ScopeId(1),
    };
    let profile = SandboxProfile::default_sandboxed();
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
