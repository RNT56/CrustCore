// SPDX-License-Identifier: Apache-2.0
//! Eval, golden-task, and red-team harness (`ROADMAP.md` §19; cross-phase).
//!
//! This crate hosts the runnable verification suite that keeps CrustCore honest:
//! golden coding tasks (`ROADMAP.md` §19.4) and the red-team scenarios
//! (`ROADMAP.md` §19.3, `THREAT_MODEL.md`). Fixtures and golden data live under
//! the repo-root `tests/` and `fixtures/` trees; the runnable assertions live in
//! this crate's `tests/`.
//!
//! Status: Phase 0 scaffold. The harness is a placeholder; each scenario is an
//! `#[ignore]`d test that the relevant phase implements and un-ignores (so the
//! suite never reports false green). See `tests/redteam.rs` and
//! `tests/golden.rs`.
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
