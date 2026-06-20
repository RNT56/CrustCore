// SPDX-License-Identifier: Apache-2.0
//! Golden coding-task suite (`ROADMAP.md` §19.4).
//!
//! Each golden task is `#[ignore]`d until the phase that makes it runnable. They
//! exercise the verifier-owned completion loop end to end.

/// Golden (P5.6 / P16.7), the flagship task: a repo has a **failing test**; a worker
/// fixes it in a disposable worktree, and **only the verifier completes** the task
/// (DoD #3/#4/#5). It exercises the load-bearing properties through public APIs:
/// the *failing* state mints no `VerifiedPatch` (an unverified patch cannot
/// complete), and only after the worker's fix does `run_verify` mint the
/// `VerifiedPatch` that `complete_task` requires (invariants 5, 9, 13).
///
/// Sandbox-adaptive like [`golden_add_small_feature`]: where no functional sandbox
/// exists (macOS, a CI runner without user namespaces) the worker is refused and
/// nothing completes — so the load-bearing assertion ("done only from real, confined,
/// verified evidence") holds in every environment.
#[test]
fn golden_fix_failing_test() {
    use crustcore_backend::verify::{run_verify, VerifyIds, VerifyOutcome, VerifySpec};
    use crustcore_backend::worker::{run_external_worker, ExternalCommandBackend, WorkerInput};
    use crustcore_backend::{complete_task, PatchRef};
    use crustcore_policy::SandboxExecCap;
    use crustcore_receipts::{MacKey, ReceiptChain};
    use crustcore_sandbox::SandboxProfile;
    use crustcore_types::{EventSeq, JobId, ScopeId, TaskId, Timestamp, ToolCallId};
    use crustcore_worktree::WorktreeManager;

    let base = std::env::temp_dir().join(format!("cc-golden-fix-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let repo = base.join("repo");
    let wt_base = base.join("wts");
    std::fs::create_dir_all(&repo).unwrap();

    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .current_dir(&repo)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("HOME", "/dev/null")
            .args(args)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };
    if !git(&["init", "-q"]) {
        eprintln!("skipping: git unavailable");
        let _ = std::fs::remove_dir_all(&base);
        return;
    }
    // The repo starts in a FAILING state: the "test" asserts answer.txt says PASS.
    std::fs::write(repo.join("answer.txt"), b"WRONG\n").unwrap();
    assert!(git(&["add", "."]));
    assert!(git(&[
        "-c",
        "user.email=ci@cc",
        "-c",
        "user.name=ci",
        "commit",
        "-q",
        "-m",
        "init (failing)",
    ]));

    let manager = WorktreeManager::with_base(&repo, &wt_base);
    let worktree = manager.create_for(TaskId(1)).expect("create worktree");
    let profile = SandboxProfile::default_sandboxed();
    let cap = SandboxExecCap {
        profile: ScopeId(1),
        scope: ScopeId(1),
    };
    let ids = VerifyIds {
        task_id: TaskId(1),
        job_id: JobId(1),
        tool_call_id: ToolCallId(1),
        event_seq: EventSeq(1),
        now: Timestamp::from_millis(1),
    };
    // The "test": answer.txt must contain PASS. It fails on the initial WRONG content.
    let verify_spec = VerifySpec::new(
        "/bin/sh",
        vec!["-c".to_string(), "grep -q PASS answer.txt".to_string()],
    );

    // Probe whether the sandbox is functional here (a trivially-true command).
    let sandbox_works = {
        let mut receipts = ReceiptChain::new(MacKey::new([0x55; 32]));
        matches!(
            run_verify(
                &cap,
                &profile,
                &worktree,
                &VerifySpec::new("/bin/sh", vec!["-c".to_string(), "true".to_string()]),
                PatchRef {
                    diff_hash: [0u8; 32]
                },
                &mut receipts,
                &ids,
            ),
            VerifyOutcome::Verified(_)
        )
    };

    if sandbox_works {
        // (1) BEFORE the fix, the failing test mints NO VerifiedPatch — an unverified
        //     (here, failing) state cannot complete (DoD #5, invariant 13).
        let mut receipts = ReceiptChain::new(MacKey::new([0x60; 32]));
        let failing = run_verify(
            &cap,
            &profile,
            &worktree,
            &verify_spec,
            PatchRef {
                diff_hash: [0u8; 32],
            },
            &mut receipts,
            &ids,
        );
        assert!(
            !matches!(failing, VerifyOutcome::Verified(_)),
            "the failing test must NOT mint a VerifiedPatch, got {failing:?}"
        );

        // (2) The worker fixes the test in the disposable worktree (sandboxed, no
        //     secrets): make answer.txt say PASS.
        let worker = ExternalCommandBackend::new(
            "/bin/sh",
            vec![
                "-c".to_string(),
                "printf 'PASS\\n' > answer.txt".to_string(),
            ],
        );
        let input = WorkerInput::for_task(TaskId(1), "make the test pass", &worktree);
        let product = run_external_worker(&worker, &input, &worktree, &cap, &profile)
            .expect("worker should produce a candidate change");
        assert!(
            product.changed_files.iter().any(|c| c.path == "answer.txt"),
            "the fix should appear in the re-derived change set: {:?}",
            product.changed_files
        );

        // (3) AFTER the fix, the same verifier passes and mints the VerifiedPatch that
        //     complete_task requires — completion comes only from verifier evidence.
        let mut receipts = ReceiptChain::new(MacKey::new([0x66; 32]));
        match run_verify(
            &cap,
            &profile,
            &worktree,
            &verify_spec,
            product.patch.0.clone(),
            &mut receipts,
            &ids,
        ) {
            VerifyOutcome::Verified(verified) => {
                let completion = complete_task(*verified);
                assert_eq!(completion.patch.patch(), &product.patch.0);
            }
            other => {
                panic!("with the test passing, verify must mint a VerifiedPatch, got {other:?}")
            }
        }
    } else {
        // No functional sandbox: the worker is refused; nothing is produced, verified,
        // or completed. The fix-from-failing path cannot fake completion.
        let produced = {
            let worker = ExternalCommandBackend::new(
                "/bin/sh",
                vec![
                    "-c".to_string(),
                    "printf 'PASS\\n' > answer.txt".to_string(),
                ],
            );
            let input = WorkerInput::for_task(TaskId(1), "make the test pass", &worktree);
            run_external_worker(&worker, &input, &worktree, &cap, &profile)
        };
        assert!(
            produced.is_err(),
            "without a functional sandbox the worker must be refused, got Ok(..)"
        );
        eprintln!("note: no functional sandbox backend here; asserted the refusal gate only");
    }

    let _ = manager.remove(&worktree);
    let _ = std::fs::remove_dir_all(&base);
}

/// Golden (P6): an **external worker** adds a small feature in a disposable
/// worktree, and only the verifier completes the task. This exercises the full
/// Phase-6 composition through public APIs: a generic external-command worker runs
/// sandboxed (no secrets), the supervisor re-derives the *actual* change from the
/// worktree (rejecting any out-of-root write), and `run_verify` mints the
/// `VerifiedPatch` that `complete_task` requires (invariants 6, 9, 13).
///
/// Like `golden_fix_failing_test`, the verify and worker run in a *real* sandbox;
/// where no functional sandbox exists (macOS, a CI runner without working user
/// namespaces) the worker is refused and nothing completes — so in every
/// environment the load-bearing assertion holds: a task completes only from real,
/// confined, verified evidence. Where the sandbox works, the full
/// produce→verify→complete path runs.
#[test]
fn golden_add_small_feature() {
    use crustcore_backend::verify::{run_verify, VerifyIds, VerifyOutcome, VerifySpec};
    use crustcore_backend::worker::{run_external_worker, ExternalCommandBackend, WorkerInput};
    use crustcore_backend::{complete_task, PatchRef};
    use crustcore_policy::SandboxExecCap;
    use crustcore_receipts::{MacKey, ReceiptChain};
    use crustcore_sandbox::SandboxProfile;
    use crustcore_types::{EventSeq, JobId, ScopeId, TaskId, Timestamp, ToolCallId};
    use crustcore_worktree::WorktreeManager;

    let base = std::env::temp_dir().join(format!("cc-golden-feat-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let repo = base.join("repo");
    let wt_base = base.join("wts");
    std::fs::create_dir_all(&repo).unwrap();

    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .current_dir(&repo)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("HOME", "/dev/null")
            .args(args)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };
    if !git(&["init", "-q"]) {
        eprintln!("skipping: git unavailable");
        let _ = std::fs::remove_dir_all(&base);
        return;
    }
    std::fs::write(repo.join("README.md"), b"project\n").unwrap();
    assert!(git(&["add", "."]));
    assert!(git(&[
        "-c",
        "user.email=ci@cc",
        "-c",
        "user.name=ci",
        "commit",
        "-q",
        "-m",
        "init",
    ]));

    let manager = WorktreeManager::with_base(&repo, &wt_base);
    let worktree = manager.create_for(TaskId(1)).expect("create worktree");
    let profile = SandboxProfile::default_sandboxed();
    let cap = SandboxExecCap {
        profile: ScopeId(1),
        scope: ScopeId(1),
    };
    let ids = VerifyIds {
        task_id: TaskId(1),
        job_id: JobId(1),
        tool_call_id: ToolCallId(1),
        event_seq: EventSeq(1),
        now: Timestamp::from_millis(1),
    };

    // Probe: is the sandbox functional here? Only then does the worker run.
    let probe = {
        let mut receipts = ReceiptChain::new(MacKey::new([0x55; 32]));
        run_verify(
            &cap,
            &profile,
            &worktree,
            &VerifySpec::new("/bin/sh", vec!["-c".to_string(), "true".to_string()]),
            PatchRef {
                diff_hash: [0u8; 32],
            },
            &mut receipts,
            &ids,
        )
    };
    let sandbox_works = matches!(probe, VerifyOutcome::Verified(_));

    // The worker: a generic external command that writes the feature file.
    let worker = ExternalCommandBackend::new(
        "/bin/sh",
        vec![
            "-c".to_string(),
            "printf 'pub fn feature() -> u32 { 42 }\\n' > feature.rs".to_string(),
        ],
    );
    let input = WorkerInput::for_task(TaskId(1), "add the feature", &worktree);
    let produced = run_external_worker(&worker, &input, &worktree, &cap, &profile);

    // The verify command that gates completion: the feature file must exist.
    let verify_spec = VerifySpec::new(
        "/bin/sh",
        vec!["-c".to_string(), "test -f feature.rs".to_string()],
    );

    if sandbox_works {
        let product = produced.expect("worker should produce a candidate change");
        // The supervisor re-derived the real change from the worktree.
        assert!(
            product.changed_files.iter().any(|c| c.path == "feature.rs"),
            "worker's feature file should appear in the re-derived change set: {:?}",
            product.changed_files
        );
        assert!(worktree.as_path().join("feature.rs").is_file());

        // Verify mints a VerifiedPatch over the worker's (unverified) patch ref.
        let mut receipts = ReceiptChain::new(MacKey::new([0x66; 32]));
        let outcome = run_verify(
            &cap,
            &profile,
            &worktree,
            &verify_spec,
            product.patch.0.clone(),
            &mut receipts,
            &ids,
        );
        match outcome {
            VerifyOutcome::Verified(verified) => {
                let completion = complete_task(*verified);
                // Completion carries the worker's re-derived patch reference.
                assert_eq!(completion.patch.patch(), &product.patch.0);
            }
            other => {
                panic!("with the feature present, verify must mint a VerifiedPatch, got {other:?}")
            }
        }
    } else {
        // No functional sandbox: the worker is refused — nothing is produced, so
        // nothing can be verified or completed.
        assert!(
            produced.is_err(),
            "without a functional sandbox the worker must be refused, got Ok(..)"
        );
        eprintln!("note: no functional sandbox backend here; asserted the refusal gate only");
    }

    let _ = manager.remove(&worktree);
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
#[ignore = "TODO(P10): GitHub issue-to-PR flow from a VerifiedPatch"]
fn golden_issue_to_pr_flow() {}
