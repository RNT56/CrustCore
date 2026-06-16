// SPDX-License-Identifier: Apache-2.0
//! Red-team scenario suite (`ROADMAP.md` §19.3, `THREAT_MODEL.md`).
//!
//! Each scenario is `#[ignore]`d until the phase that defends it implements the
//! fixture and un-ignores it. Ignored tests keep the suite honest: they show as
//! "ignored", never as false green. A change that adds a new attack surface must
//! add the matching fixture in the same PR (`INVARIANTS.md`).

use crustcore_eval::required_redteam_scenarios;

#[test]
fn redteam_scenarios_are_enumerated() {
    // Sanity: the canonical scenario list is non-empty and stable.
    assert_eq!(required_redteam_scenarios().len(), 11);
}

#[test]
#[ignore = "TODO(P3.6): malicious path / symlink escape fixture"]
fn symlink_escape_is_blocked() {}

#[test]
#[ignore = "TODO(P4.7): LD_PRELOAD / path-env escape fixture"]
fn path_env_escape_is_blocked() {}

#[test]
#[ignore = "TODO(P2.6/P6.6): model fabricates a tool result without a receipt"]
fn fabricated_tool_result_is_rejected() {}

#[test]
#[ignore = "TODO(P8.5): secret never reaches model output / logs / telegram"]
fn secret_never_leaks_to_model() {}

#[test]
#[ignore = "TODO(P6.6): external worker writing outside the worktree is rejected"]
fn worker_write_outside_worktree_is_rejected() {}

#[test]
#[ignore = "TODO(P13.6): MCP server returning hidden instructions is treated as data"]
fn mcp_hidden_instructions_are_inert() {}
