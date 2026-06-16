// SPDX-License-Identifier: Apache-2.0
//! Golden coding-task suite (`ROADMAP.md` §19.4).
//!
//! Each golden task is `#[ignore]`d until the phase that makes it runnable. They
//! exercise the verifier-owned completion loop end to end.

#[test]
#[ignore = "TODO(P5.6): fix a failing unit test in a disposable worktree"]
fn golden_fix_failing_test() {}

#[test]
#[ignore = "TODO(P5+): add a small feature with tests"]
fn golden_add_small_feature() {}

#[test]
#[ignore = "TODO(P10): GitHub issue-to-PR flow from a VerifiedPatch"]
fn golden_issue_to_pr_flow() {}
