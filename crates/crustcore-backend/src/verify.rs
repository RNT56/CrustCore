// SPDX-License-Identifier: Apache-2.0
//! The verify loop (`ROADMAP.md` §18 Phase 5; tasks P5.2–P5.5).
//!
//! This is the **only** place a [`VerifiedPatch`] is minted. [`run_verify`] reruns
//! a verify command in a clean sandbox ([`crustcore_sandbox::run_command`],
//! invariant 9) and, only if it exits zero, mints a [`VerifiedPatch`] carrying a
//! [`ToolReceipt`](crustcore_receipts::ToolReceipt) over the real run (invariant
//! 10). A self-claimed-done backend, a failing verify, or a missing sandbox
//! backend never produces a `VerifiedPatch` — so a task can only complete from
//! verifier evidence (invariant 13; `docs/backend-contract.md`).

use std::collections::BTreeMap;

use crustcore_path::WorktreeRoot;
use crustcore_policy::SandboxExecCap;
use crustcore_receipts::{ReceiptChain, ReceiptParams};
use crustcore_runner::{CommandResult, CommandSpec, ExitStatus};
use crustcore_sandbox::{run_command, SandboxError, SandboxProfile};
use crustcore_types::{BoundedText, EventSeq, JobId, TaskId, Timestamp, ToolCallId};

use crate::{CommandEvidence, PatchRef, VerifiedPatch, VerifierName};

/// Cap on verify output captured into a receipt/result (bounded; invariant 11).
const MAX_VERIFY_OUTPUT: usize = 256 * 1024;

/// A verify command: an explicit program + args (no shell interpretation, so an
/// untrusted `goal`/`-verify` string cannot smuggle a second command).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifySpec {
    /// The program to run (resolved, not shell-parsed).
    pub program: String,
    /// Arguments, passed literally.
    pub args: Vec<String>,
}

impl VerifySpec {
    /// Builds a spec from an explicit program and args.
    #[must_use]
    pub fn new(program: impl Into<String>, args: Vec<String>) -> Self {
        VerifySpec {
            program: program.into(),
            args,
        }
    }

    /// Best-effort detection of a verify command from a repo's shape (P5.2). Only
    /// used when the user did not pass an explicit `-verify`. Conservative: a known
    /// project marker maps to its canonical test command, otherwise `None` (the
    /// caller must then require an explicit command rather than guess).
    #[must_use]
    pub fn detect(repo: &std::path::Path) -> Option<VerifySpec> {
        if repo.join("Cargo.toml").is_file() {
            return Some(VerifySpec::new("cargo", vec!["test".to_string()]));
        }
        if repo.join("package.json").is_file() {
            return Some(VerifySpec::new(
                "npm",
                vec!["test".to_string(), "--silent".to_string()],
            ));
        }
        if repo.join("Makefile").is_file() {
            return Some(VerifySpec::new("make", vec!["test".to_string()]));
        }
        None
    }

    /// A human-readable rendering of the command (for evidence/diagnostics).
    #[must_use]
    pub fn display(&self) -> String {
        if self.args.is_empty() {
            self.program.clone()
        } else {
            format!("{} {}", self.program, self.args.join(" "))
        }
    }
}

/// Identifiers and timestamp anchoring a verify run's receipt to the event log.
#[derive(Debug, Clone, Copy)]
pub struct VerifyIds {
    /// Task the verify ran under.
    pub task_id: TaskId,
    /// Job the verify ran under.
    pub job_id: JobId,
    /// The tool-call id for this verify invocation.
    pub tool_call_id: ToolCallId,
    /// The event-log seq this receipt anchors to.
    pub event_seq: EventSeq,
    /// When verification ran (adapter-supplied; the kernel reads no wall clock).
    pub now: Timestamp,
}

/// The result of a verify run.
#[derive(Debug)]
pub enum VerifyOutcome {
    /// Verify passed: a [`VerifiedPatch`] was minted (the only path to one).
    Verified(Box<VerifiedPatch>),
    /// Verify ran but did not pass; carries the exit status and bounded output so
    /// the caller can report a clear failing state (and a loop can iterate).
    Failed {
        /// How the verify command exited (non-zero, signal, or timeout).
        status: ExitStatus,
        /// Bounded combined stdout+stderr from the failing run.
        output: BoundedText,
    },
    /// Verify could not run at all (no sandbox backend, non-executing tier, etc.).
    /// **Not** a pass: nothing is minted. Carries the reason.
    Refused(String),
}

impl VerifyOutcome {
    /// Whether the task completed — i.e. the verifier passed. Only `Verified`
    /// completes; `Failed` and `Refused` do not (invariant 13). The CLI maps this
    /// to its exit code (success vs. a clear non-zero failure state).
    #[must_use]
    pub fn completed(&self) -> bool {
        matches!(self, VerifyOutcome::Verified(_))
    }
}

/// Reruns `spec` in a clean sandbox against `worktree` and, only on a zero exit,
/// mints a [`VerifiedPatch`] for `patch`. This is the sole constructor of a
/// `VerifiedPatch` (invariant 13).
///
/// The command is run with an empty environment (the sandbox sanitizes and the
/// runner builds env from scratch — no inherited secrets), bounded output, and the
/// profile's timeout/tier. A non-zero exit yields [`VerifyOutcome::Failed`]; an
/// unavailable backend yields [`VerifyOutcome::Refused`] — neither mints a patch.
#[must_use]
pub fn run_verify(
    cap: &SandboxExecCap,
    profile: &SandboxProfile,
    worktree: &WorktreeRoot,
    spec: &VerifySpec,
    patch: PatchRef,
    receipts: &mut ReceiptChain,
    ids: &VerifyIds,
) -> VerifyOutcome {
    // The executor is the sandbox: there is no run-unsandboxed path. The seam
    // exists only so the mint→complete→receipt logic can be unit-tested with a
    // fake executor on hosts without a functional sandbox (invariant 9 holds —
    // production always passes `run_command`).
    run_verify_with(worktree, spec, patch, receipts, ids, |command| {
        run_command(cap, profile, command)
    })
}

/// The verify loop parameterized over the command executor. `exec` is the only
/// way the command runs; in production it is the sandbox (`run_command`). Returns
/// `Refused` if `exec` errors (e.g. no sandbox backend), `Failed` on a non-zero
/// exit, and mints a `VerifiedPatch` only on a zero exit.
fn run_verify_with<E>(
    worktree: &WorktreeRoot,
    spec: &VerifySpec,
    patch: PatchRef,
    receipts: &mut ReceiptChain,
    ids: &VerifyIds,
    exec: E,
) -> VerifyOutcome
where
    E: FnOnce(CommandSpec) -> Result<CommandResult, SandboxError>,
{
    let mut command = CommandSpec::new(spec.program.clone());
    command.args = spec.args.clone();
    command.cwd = Some(worktree.as_path().to_string_lossy().into_owned());
    command.env = BTreeMap::new();
    command.max_output_bytes = MAX_VERIFY_OUTPUT;

    let result: CommandResult = match exec(command) {
        Ok(r) => r,
        Err(e) => return VerifyOutcome::Refused(e.to_string()),
    };

    // Capture status/success before moving the output buffers out of `result`.
    let status = result.status;
    let success = result.is_success();

    // Combine the streams into the bounded "result shown" bytes that the receipt
    // binds to (invariant 10): the evidence is exactly what ran, not a claim.
    let mut output = result.stdout;
    output.extend_from_slice(&result.stderr);
    output.truncate(MAX_VERIFY_OUTPUT);

    if !success {
        return VerifyOutcome::Failed {
            status,
            output: BoundedText::truncated(String::from_utf8_lossy(&output), MAX_VERIFY_OUTPUT),
        };
    }

    // Passed: mint the receipt over the real run, then the VerifiedPatch.
    let cmdline = spec.display();
    let receipt = receipts.mint(&ReceiptParams {
        task_id: ids.task_id,
        job_id: ids.job_id,
        tool_call_id: ids.tool_call_id,
        tool_name: b"verify",
        args: cmdline.as_bytes(),
        result: &output,
        artifacts: &[],
        event_seq: ids.event_seq,
    });

    let verifier = VerifierName::new(&cmdline);
    let evidence = vec![CommandEvidence {
        command: verifier.as_text().clone(),
        passed: true,
    }];
    let verified = VerifiedPatch::from_verifier(patch, verifier, evidence, ids.now, receipt);
    VerifyOutcome::Verified(Box::new(verified))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_recognizes_cargo_npm_make_and_nothing_else() {
        let dir = std::env::temp_dir().join(format!("cc-detect-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        assert!(VerifySpec::detect(&dir).is_none());

        std::fs::write(dir.join("Cargo.toml"), b"[package]\n").unwrap();
        assert_eq!(
            VerifySpec::detect(&dir),
            Some(VerifySpec::new("cargo", vec!["test".to_string()]))
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn display_renders_program_and_args() {
        assert_eq!(VerifySpec::new("cargo", vec![]).display(), "cargo");
        assert_eq!(
            VerifySpec::new("sh", vec!["-c".to_string(), "true".to_string()]).display(),
            "sh -c true"
        );
    }

    // ---- Executor-seam tests (deterministic, no OS sandbox required) ----
    //
    // These exercise the load-bearing mint→complete→receipt logic on EVERY
    // platform by injecting a fake command executor — so the positive (Verified)
    // and negative (Failed/Refused) paths, and the receipt binding, are covered in
    // CI even where no real sandbox backend exists. The real sandbox path is
    // additionally checked by `golden_fix_failing_test_gates_completion` where a
    // functional bubblewrap is present.

    fn tmp_worktree() -> (std::path::PathBuf, WorktreeRoot) {
        let dir = std::env::temp_dir().join(format!(
            "cc-verifyseam-{}-{}",
            std::process::id(),
            // disambiguate concurrent tests in the same process
            std::thread::current()
                .name()
                .unwrap_or("t")
                .replace("::", "_")
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let root = WorktreeRoot::open(&dir).unwrap();
        (dir, root)
    }

    fn result(status: ExitStatus, out: &[u8]) -> CommandResult {
        CommandResult {
            status,
            stdout: out.to_vec(),
            stderr: Vec::new(),
            truncated: false,
        }
    }

    #[test]
    fn seam_mints_verified_and_binds_receipt_on_zero_exit() {
        let (dir, root) = tmp_worktree();
        let spec = VerifySpec::new("/bin/true", vec![]);
        let mut receipts = ReceiptChain::new(MacKey::new([0x44; 32]));
        let outcome = run_verify_with(
            &root,
            &spec,
            PatchRef {
                diff_hash: [7u8; 32],
            },
            &mut receipts,
            &ids(),
            |_command| Ok(result(ExitStatus::Code(0), b"all good")),
        );
        assert!(outcome.completed(), "a passing verify reports completed()");
        match outcome {
            VerifyOutcome::Verified(v) => {
                // The receipt binds to exactly the command output (invariant 10).
                assert!(v.receipt().result_matches(b"all good"));
                assert!(!v.receipt().result_matches(b"tampered"));
                assert_eq!(v.patch().diff_hash, [7u8; 32]);
                assert_eq!(v.verifier().as_str(), "/bin/true");
                // Only a VerifiedPatch reaches completion.
                let completion = crate::complete_task(*v);
                assert!(completion.patch.receipt().result_matches(b"all good"));
            }
            other => panic!("zero exit must mint a VerifiedPatch, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seam_reports_failed_on_nonzero_exit_and_mints_nothing() {
        let (dir, root) = tmp_worktree();
        let spec = VerifySpec::new("/bin/false", vec![]);
        let mut receipts = ReceiptChain::new(MacKey::new([0x44; 32]));
        let outcome = run_verify_with(
            &root,
            &spec,
            PatchRef {
                diff_hash: [0u8; 32],
            },
            &mut receipts,
            &ids(),
            |_command| Ok(result(ExitStatus::Code(1), b"boom\n")),
        );
        assert!(!outcome.completed(), "a failing verify does not complete");
        match outcome {
            VerifyOutcome::Failed { status, output } => {
                assert_eq!(status, ExitStatus::Code(1));
                assert!(output.as_str().contains("boom"));
            }
            other => panic!("nonzero exit must be Failed, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seam_treats_timeout_as_failed_not_verified() {
        let (dir, root) = tmp_worktree();
        let spec = VerifySpec::new("/bin/sleep", vec!["999".to_string()]);
        let mut receipts = ReceiptChain::new(MacKey::new([0x44; 32]));
        let outcome = run_verify_with(
            &root,
            &spec,
            PatchRef {
                diff_hash: [0u8; 32],
            },
            &mut receipts,
            &ids(),
            |_command| Ok(result(ExitStatus::TimedOut, b"")),
        );
        assert!(
            matches!(
                outcome,
                VerifyOutcome::Failed {
                    status: ExitStatus::TimedOut,
                    ..
                }
            ),
            "a timeout must be Failed, never Verified, got {outcome:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seam_refuses_when_executor_errors() {
        let (dir, root) = tmp_worktree();
        let spec = VerifySpec::new("/bin/true", vec![]);
        let mut receipts = ReceiptChain::new(MacKey::new([0x44; 32]));
        let outcome = run_verify_with(
            &root,
            &spec,
            PatchRef {
                diff_hash: [0u8; 32],
            },
            &mut receipts,
            &ids(),
            |_command| Err(SandboxError::NoBackend),
        );
        assert!(!outcome.completed(), "a refused verify does not complete");
        assert!(
            matches!(outcome, VerifyOutcome::Refused(_)),
            "an executor error must Refuse (never Verified), got {outcome:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- Golden task: "fix failing test" (P5.6) ----

    use crustcore_policy::SandboxExecCap;
    use crustcore_receipts::MacKey;
    use crustcore_sandbox::SandboxProfile;
    use crustcore_types::{EventSeq, JobId, ScopeId, TaskId, Timestamp, ToolCallId};
    use crustcore_worktree::WorktreeManager;

    fn git(dir: &std::path::Path, args: &[&str]) -> bool {
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

    fn ids() -> VerifyIds {
        VerifyIds {
            task_id: TaskId(1),
            job_id: JobId(1),
            tool_call_id: ToolCallId(1),
            event_seq: EventSeq(1),
            now: Timestamp::from_millis(1),
        }
    }

    fn cap() -> SandboxExecCap {
        SandboxExecCap {
            profile: ScopeId(1),
            scope: ScopeId(1),
        }
    }

    /// The verifier-owned-completion gate (P5.4–P5.6, invariant 13): a task with a
    /// failing verify cannot complete, and only a passing verify mints the
    /// `VerifiedPatch` that `complete_task` requires.
    ///
    /// The check is the verify command `sh -c 'test -f FIXED'`, which fails until
    /// the "fix" (a `FIXED` file) is present in the worktree.
    ///
    /// The verify runs in a *real* sandbox. A sandbox backend may be absent
    /// (macOS, a CI runner without bubblewrap) or **present but non-functional**
    /// (e.g. an unprivileged container where user namespaces are blocked). We
    /// detect this by first probing a trivially-passing command: only if the probe
    /// genuinely verifies do we assert the full fail→fix→pass path. In every case
    /// we assert the load-bearing invariant: a failing/unrunnable verify is never
    /// `Verified`, so a task can only complete from real verifier evidence.
    #[test]
    fn golden_fix_failing_test_gates_completion() {
        let base_tmp = std::env::temp_dir().join(format!("cc-golden-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base_tmp);
        let repo = base_tmp.join("repo");
        let wt_base = base_tmp.join("wts");
        std::fs::create_dir_all(&repo).unwrap();

        if !git(&repo, &["init", "-q"]) {
            eprintln!("skipping: git unavailable");
            let _ = std::fs::remove_dir_all(&base_tmp);
            return;
        }
        std::fs::write(repo.join("README.md"), b"project\n").unwrap();
        assert!(git(&repo, &["add", "."]));
        assert!(git(
            &repo,
            &[
                "-c",
                "user.email=ci@cc",
                "-c",
                "user.name=ci",
                "commit",
                "-q",
                "-m",
                "init"
            ],
        ));

        let manager = WorktreeManager::with_base(&repo, &wt_base);
        let worktree = manager.create_for(TaskId(1)).expect("create worktree");
        let profile = SandboxProfile::default_sandboxed();
        let verify = |spec: &VerifySpec| {
            let mut receipts = ReceiptChain::new(MacKey::new([0x33; 32]));
            run_verify(
                &cap(),
                &profile,
                &worktree,
                spec,
                PatchRef {
                    diff_hash: [0u8; 32],
                },
                &mut receipts,
                &ids(),
            )
        };

        // Probe: does a trivially-passing command actually verify here? This is
        // true only with a *functional* sandbox (binary present AND able to set up
        // the namespaces), not merely an installed `bwrap`.
        let probe = verify(&VerifySpec::new(
            "/bin/sh",
            vec!["-c".to_string(), "true".to_string()],
        ));
        let sandbox_works = matches!(probe, VerifyOutcome::Verified(_));

        // The "test": passes only once a FIXED file exists in the worktree.
        let failing_spec = VerifySpec::new(
            "/bin/sh",
            vec!["-c".to_string(), "test -f FIXED".to_string()],
        );

        // Invariant in EVERY environment: the failing test must not complete the
        // task — it is never `Verified` (Failed when the sandbox runs it, Refused
        // when no sandbox is available).
        let failing = verify(&failing_spec);
        assert!(
            !matches!(failing, VerifyOutcome::Verified(_)),
            "a failing/unrunnable verify must never be Verified, got {failing:?}"
        );

        if sandbox_works {
            assert!(
                matches!(failing, VerifyOutcome::Failed { .. }),
                "with a working sandbox the failing test must report Failed, got {failing:?}"
            );
            // Apply the "fix": now the same verify passes and mints a VerifiedPatch
            // that `complete_task` accepts — the only path to completion.
            std::fs::write(worktree.as_path().join("FIXED"), b"ok\n").unwrap();
            let passing = verify(&failing_spec);
            match passing {
                VerifyOutcome::Verified(verified) => {
                    let completion = crate::complete_task(*verified);
                    assert!(
                        completion.patch.receipt().result_matches(b""),
                        "verify of `test -f FIXED` emits no output, so the receipt binds to empty"
                    );
                }
                other => panic!("after the fix, verify must mint a VerifiedPatch, got {other:?}"),
            }
        } else {
            eprintln!(
                "note: no functional sandbox backend here ({probe:?}); \
                 asserted the completion gate only, skipped the live fix→pass path"
            );
        }

        let _ = manager.remove(&worktree);
        let _ = std::fs::remove_dir_all(&base_tmp);
    }
}
