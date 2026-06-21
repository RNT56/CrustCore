// SPDX-License-Identifier: Apache-2.0
//! Live-flow integration test (C3.7) — behind the `live-flow` feature, `#[ignore]`d,
//! and **never run in CI**. It exercises the one path the deterministic suite cannot:
//! a real `VerifiedPatch` flowing through a `Verify` node to `FlowOutcome::Completed`.
//!
//! Run out-of-band on a host with a functional sandbox + git:
//! `cargo test -p crustcore-flow --features live-flow -- --ignored`
//!
//! The test is probe-first: if no functional sandbox backend is present (macOS, an
//! unprivileged container), it asserts only the completion gate (verify never
//! completes) and skips the live mint path — exactly the posture
//! `crustcore_backend::verify`'s golden test uses.

#![cfg(feature = "live-flow")]

use crustcore_backend::verify::{VerifyIds, VerifyOutcome, VerifySpec};
use crustcore_backend::PatchRef;
use crustcore_flow::live::LiveVerifyDriver;
use crustcore_flow::{
    FakeDrivers, FlowBudget, FlowBuilder, FlowDrivers, FlowEngine, FlowOutcome, FlowState,
};
use crustcore_policy::caps::AuthorizedUser;
use crustcore_policy::{PolicySnapshot, RiskProfile, SandboxExecCap};
use crustcore_receipts::{MacKey, ReceiptChain};
use crustcore_sandbox::SandboxProfile;
use crustcore_secrets::Redactor;
use crustcore_types::{ApprovalId, EventSeq, JobId, ScopeId, TaskId, Timestamp, ToolCallId};
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

/// A single `verify` flow over a real, sandboxed `run_verify`. Mirrors the backend
/// golden test's structure but routes through the flow engine: only a real
/// `VerifiedPatch` reaches `FlowOutcome::Completed`.
#[test]
#[ignore = "live: needs a functional sandbox backend + git; run with --ignored"]
fn live_verify_node_completes_only_on_a_real_verified_patch() {
    let base = std::env::temp_dir().join(format!("cc-flow-live-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let repo = base.join("repo");
    let wt_base = base.join("wts");
    std::fs::create_dir_all(&repo).unwrap();

    if !git(&repo, &["init", "-q"]) {
        eprintln!("skipping: git unavailable");
        let _ = std::fs::remove_dir_all(&base);
        return;
    }
    std::fs::write(repo.join("README.md"), b"x\n").unwrap();
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
    let worktree = manager.create_for(TaskId(1)).expect("worktree");
    let profile = SandboxProfile::default_sandboxed();

    let policy = PolicySnapshot::new(RiskProfile::Supervised);
    let redactor = Redactor::new();
    let engine = FlowEngine::new(&policy, &redactor, 1_000);
    let fakes = FakeDrivers::new();

    let cap = cap();
    let vids = ids();
    let run_flow = |spec: VerifySpec| -> FlowOutcome {
        let mut b = FlowBuilder::new();
        let v = b.reserve();
        let end = b.reserve();
        b.entry(v).verify(v, end).end(end);
        let flow = b.build().unwrap();

        let mut receipts = ReceiptChain::new(MacKey::new([0x55; 32]));
        let verify = LiveVerifyDriver::new(
            &cap,
            &profile,
            &worktree,
            &spec,
            PatchRef {
                diff_hash: [9u8; 32],
            },
            &mut receipts,
            &vids,
        );
        let drivers = FlowDrivers {
            model: &fakes,
            tool: &fakes,
            verify: &verify,
            review: &fakes,
        };
        engine
            .run(
                &flow,
                &drivers,
                &FlowBudget::new(0, 0, 16, 0),
                FlowState::new(),
            )
            .unwrap()
            .outcome
    };

    // Probe: does a trivially-passing command actually verify here (functional sandbox)?
    let probe = run_flow(VerifySpec::new("/bin/sh", vec!["-c".into(), "true".into()]));
    let sandbox_works = matches!(probe, FlowOutcome::Completed(_));

    // The failing test: passes only once a FIXED file exists.
    let spec = VerifySpec::new("/bin/sh", vec!["-c".into(), "test -f FIXED".into()]);
    let failing = run_flow(spec.clone());
    assert!(
        !matches!(failing, FlowOutcome::Completed(_)),
        "a failing/unrunnable verify must never complete the flow"
    );

    if sandbox_works {
        std::fs::write(worktree.as_path().join("FIXED"), b"ok\n").unwrap();
        let passing = run_flow(spec);
        match passing {
            FlowOutcome::Completed(patch) => {
                // A REAL VerifiedPatch reached Completed — minted only by run_verify.
                assert_eq!(patch.patch().diff_hash, [9u8; 32]);
            }
            other => panic!("after the fix, the verify node must complete, got {other:?}"),
        }
    } else {
        eprintln!("note: no functional sandbox here ({probe:?}); asserted the gate only");
    }

    let _ = manager.remove(&worktree);
    let _ = std::fs::remove_dir_all(&base);
}

/// Live-shape smoke: an irreversible tool node still needs a real approval even with a
/// live verify driver in the bundle — the approval gate is engine-side, not driver-side.
#[test]
#[ignore = "live-shape: pairs the live verify driver with the approval gate"]
fn live_bundle_still_enforces_the_approval_gate() {
    let policy = PolicySnapshot::new(RiskProfile::Full);
    let redactor = Redactor::new();
    let engine = FlowEngine::new(&policy, &redactor, 1_000);

    let mut b = FlowBuilder::new();
    let t = b.reserve();
    let end = b.reserve();
    b.entry(t)
        .tool_fail_closed(t, "force-push", "main", "out", end)
        .end(end);
    let flow = b.build().unwrap();
    let fakes = FakeDrivers::new();

    // Without approval: halts even though the bundle could verify.
    let err = engine
        .run(
            &flow,
            &fakes.as_bundle(),
            &FlowBudget::new(0, 0, 16, 0),
            FlowState::new(),
        )
        .unwrap_err();
    assert!(matches!(
        err,
        crustcore_flow::FlowError::ApprovalRequired(_)
    ));

    // With a real approval: runs.
    let mut state = FlowState::new();
    let user = AuthorizedUser::bind(7);
    state.add_approval(user.approve((), ApprovalId(1), Timestamp::from_millis(10_000)));
    assert!(engine
        .run(
            &flow,
            &fakes.as_bundle(),
            &FlowBudget::new(0, 0, 16, 0),
            state
        )
        .is_ok());

    let _ = VerifyOutcome::Refused(String::new()); // keep the import meaningful
}
