// SPDX-License-Identifier: Apache-2.0
//! Eval, golden-task, and red-team harness (`ROADMAP.md` §19; cross-phase).
//!
//! This crate hosts the runnable verification suite that keeps CrustCore honest:
//! golden coding tasks (`ROADMAP.md` §19.4) and the red-team scenarios
//! (`ROADMAP.md` §19.3, `THREAT_MODEL.md`). Fixtures and golden data live under
//! the repo-root `tests/` and `fixtures/` trees; the runnable assertions live in
//! this crate's `tests/`.
//!
//! Status: implemented. The red-team and golden suites run end to end; each
//! scenario is a real fixture. A few remain `#[ignore]`d **only** where they need
//! live network/exec (e.g. the GitHub issue-to-PR flow) — shown as ignored, never
//! as false green. See `tests/redteam.rs` and `tests/golden.rs`.
#![forbid(unsafe_code)]

/// A red-team scenario id (mirrors `ROADMAP.md` §19.3 / `THREAT_MODEL.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedTeamScenario {
    RepoFileAsksForToken,
    IssueCommentSaysIgnorePolicy,
    TestOutputSaysExfiltrate,
    McpHiddenInstructions,
    DependencyPostinstallNetwork,
    WorkerWritesOutsideWorktree,
    ModelFabricatesToolResult,
    MisleadingApprovalText,
    SneakedWorkflowModification,
    SymlinkEscape,
    PathEnvEscape,
    GitConfigOrHookExecution,
}

/// The full set of red-team scenarios that must each have a passing fixture
/// before v0.1 (`ROADMAP.md` §19.3, `INVARIANTS.md`).
#[must_use]
pub fn required_redteam_scenarios() -> &'static [RedTeamScenario] {
    use RedTeamScenario::*;
    &[
        RepoFileAsksForToken,
        IssueCommentSaysIgnorePolicy,
        TestOutputSaysExfiltrate,
        McpHiddenInstructions,
        DependencyPostinstallNetwork,
        WorkerWritesOutsideWorktree,
        ModelFabricatesToolResult,
        MisleadingApprovalText,
        SneakedWorkflowModification,
        SymlinkEscape,
        PathEnvEscape,
        GitConfigOrHookExecution,
    ]
}
