// SPDX-License-Identifier: Apache-2.0
//! The integration gate: only a [`VerifiedPatch`] may open a PR (`ROADMAP.md`
//! §7.5, §12.8; `docs/github.md` §6; Phase 10 P10.5/P10.6, invariants 13, 14).
//!
//! [`open_pr`] is the type-level chokepoint: it accepts a [`VerifiedPatch`] **by
//! value** (so a self-claimed/unverified patch cannot reach it — invariant 13) and
//! an `Approved<GitHubWriteCap>` (so opening a PR requires a human approval —
//! invariant 14). It produces a [`PrIntent`] — a **draft** PR description built from
//! the verifier's *evidence* (verifier name, command evidence, receipt-backed pass
//! time), never the model's `self_claimed_done` (invariant 6). The daemon turns the
//! intent into an actual draft PR (redacting the body at the outbound boundary) and
//! never self-merges.

use crustcore_policy::{Approved, GitHubWriteCap};
use crustcore_types::{ApprovalId, RepoRef, Timestamp};

use crate::VerifiedPatch;

/// A verified, approved intent to open a **draft** PR (`docs/github.md` §6). Carries
/// the evidence the daemon renders into the PR body; the actual REST call is performed
/// by `crustcore-net::github::RestGitHub::create_pull` (the daemon maps this `PrIntent`
/// onto a `CreatePrRequest`).
#[derive(Debug, Clone)]
pub struct PrIntent {
    /// The repository (from the approved capability, not from model/comment input).
    pub repo: RepoRef,
    /// The head branch (confined to the cap's branch prefix).
    pub head_branch: String,
    /// The base branch to target.
    pub base_branch: String,
    /// Always `true`: CrustCore opens **draft** PRs awaiting human review.
    pub draft: bool,
    /// The PR title.
    pub title: String,
    /// The PR body — verifier *evidence* (plain text; the daemon redacts it through
    /// the secret broker before it is posted, `docs/secrets.md`).
    pub body: String,
    /// The approval that authorized opening this PR (audit).
    pub approval_id: ApprovalId,
}

/// Why opening a PR was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrateError {
    /// The approval token has expired (invariant 14).
    ApprovalExpired,
    /// The head branch is not under the capability's branch prefix (a write outside
    /// the granted scope; `docs/github.md` §4 — the credential proxy enforces this
    /// at push time too).
    BranchNotUnderPrefix(String),
}

impl core::fmt::Display for IntegrateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IntegrateError::ApprovalExpired => write!(f, "approval expired"),
            IntegrateError::BranchNotUnderPrefix(b) => {
                write!(f, "branch '{b}' is not under the capability's prefix")
            }
        }
    }
}

impl std::error::Error for IntegrateError {}

/// Opens a **draft** PR from a [`VerifiedPatch`] under an approved
/// `GitHubWriteCap`. The signature is the enforcement (`docs/github.md` §6):
/// - `patch: VerifiedPatch` **by value** — only the verifier mints one
///   (invariant 13); a `BackendResult`/`UnverifiedPatch` cannot be passed here.
/// - `approval: &Approved<GitHubWriteCap>` — opening a PR is gated on a human
///   approval (invariant 14); the model cannot mint an `Approved<T>` (invariant 4).
///
/// The head branch must be under the cap's branch prefix, and the approval must be
/// valid at `now`. The result is a *draft* intent; merging still requires a
/// separate approval and is never autonomous (`docs/github.md` §3.1).
///
/// # Errors
/// [`IntegrateError`] if the approval expired or the branch is out of scope.
pub fn open_pr(
    approval: &Approved<GitHubWriteCap>,
    patch: VerifiedPatch,
    head_branch: &str,
    base_branch: &str,
    now: Timestamp,
) -> Result<PrIntent, IntegrateError> {
    if !approval.is_valid_at(now) {
        return Err(IntegrateError::ApprovalExpired);
    }
    let cap = approval.value();
    if !branch_under_prefix(head_branch, cap.branch_prefix.0.as_str()) {
        return Err(IntegrateError::BranchNotUnderPrefix(
            head_branch.to_string(),
        ));
    }
    let body = format_pr_body(&patch);
    Ok(PrIntent {
        repo: RepoRef(cap.repo.0.clone()),
        head_branch: head_branch.to_string(),
        base_branch: base_branch.to_string(),
        draft: true,
        title: format!("[crustcore] verified patch on {head_branch}"),
        body,
        approval_id: approval.approval_id(),
    })
}

/// Whether `branch` is under `prefix` at a **segment boundary** (so a prefix of
/// `crustcore` does not match `crustcore-evil/x`), rejecting `.`/`..` traversal and
/// an empty prefix (fail closed). Mirrors `crustcore_daemon::github::branch_under_prefix`
/// — the credential proxy is the real push-time enforcement; this is the
/// defense-in-depth check at PR-open time (`docs/github.md` §4).
#[must_use]
pub fn branch_under_prefix(branch: &str, prefix: &str) -> bool {
    if branch.split('/').any(|seg| seg == ".." || seg == ".") {
        return false;
    }
    let prefix = prefix.trim_end_matches('/');
    if prefix.is_empty() {
        return false;
    }
    branch == prefix || branch.starts_with(&format!("{prefix}/"))
}

/// Builds the PR body from the verifier's **evidence** — the verifier name, the
/// commands it ran, and the receipt-backed pass time — exactly what made the patch
/// a [`VerifiedPatch`]. It deliberately does **not** include any model
/// `self_claimed_done` claim (invariant 6, `docs/github.md` §6 "evidence, not
/// marketing").
#[must_use]
pub fn format_pr_body(patch: &VerifiedPatch) -> String {
    let mut s = String::new();
    s.push_str("## CrustCore evidence-backed draft PR\n\n");
    s.push_str(
        "**Human review required before merge.** CrustCore verified this patch; it did not \
         approve deployment, release, or merge.\n\n",
    );
    s.push_str("### Verification\n\n");
    s.push_str(&format!(
        "**Verifier:** `{}`\n\n",
        patch.verifier().as_str()
    ));
    s.push_str("**Command evidence:**\n");
    if patch.commands().is_empty() {
        s.push_str("- (none recorded)\n");
    } else {
        for c in patch.commands() {
            s.push_str(&format!(
                "- `{}` — {}\n",
                c.command.as_str(),
                if c.passed { "passed" } else { "FAILED" }
            ));
        }
    }
    s.push_str("\n### Patch and receipt references\n\n");
    s.push_str(&format!(
        "- Patch hash: `{}`\n",
        hex32(&patch.patch().diff_hash)
    ));
    s.push_str(&format!(
        "- Receipt event seq: `{}` (task `{}`, job `{}`, tool call `{}`)\n",
        patch.receipt().event_seq.0,
        patch.receipt().task_id.0,
        patch.receipt().job_id.0,
        patch.receipt().tool_call_id.0
    ));
    s.push_str(&format!(
        "- Receipt result hash: `{}`\n",
        hex32(&patch.receipt().result_hash)
    ));
    s.push_str("\n### Risk notes\n\n");
    s.push_str("- No unresolved risk was attached to this verified integration gate.\n");
    s.push_str("- Review changed files, tests, and CI before merging.\n");
    s.push_str(&format!(
        "\nVerification passed at t={} ms (receipt-backed). \
         A model's self-claim is **not** evidence; only the verifier's run is.\n",
        patch.passed_at().as_millis()
    ));
    s
}

fn hex32(bytes: &[u8; 32]) -> String {
    use core::fmt::Write as _;

    let mut out = String::with_capacity(64);
    for byte in bytes {
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crustcore_policy::{AuthorizedUser, GitHubWriteCap};
    use crustcore_receipts::{MacKey, ReceiptChain, ReceiptParams};
    use crustcore_types::{
        BoundedText, BranchPrefix, EventSeq, JobId, ScopeId, TaskId, ToolCallId,
    };

    use crate::{CommandEvidence, PatchRef, VerifierName};

    fn verified_patch() -> VerifiedPatch {
        let mut chain = ReceiptChain::new(MacKey::new([0x21; 32]));
        let receipt = chain.mint(&ReceiptParams {
            task_id: TaskId(1),
            job_id: JobId(1),
            tool_call_id: ToolCallId(1),
            tool_name: b"verify",
            args: b"cargo test",
            result: b"ok",
            artifacts: &[],
            event_seq: EventSeq(1),
        });
        VerifiedPatch::from_verifier(
            PatchRef {
                diff_hash: [9u8; 32],
            },
            VerifierName::new("cargo test"),
            vec![CommandEvidence {
                command: BoundedText::truncated("cargo test", 64),
                passed: true,
            }],
            Timestamp::from_millis(123),
            receipt,
        )
    }

    fn cap() -> GitHubWriteCap {
        GitHubWriteCap {
            repo: RepoRef(BoundedText::truncated("RNT56/CrustCore", 64)),
            branch_prefix: BranchPrefix(BoundedText::truncated("crustcore/", 64)),
            scope: ScopeId(1),
        }
    }

    fn approved(cap: GitHubWriteCap, expires_ms: u64) -> Approved<GitHubWriteCap> {
        AuthorizedUser::bind(1).approve(cap, ApprovalId(7), Timestamp::from_millis(expires_ms))
    }

    #[test]
    fn open_pr_from_verified_patch_is_a_draft_with_evidence() {
        let appr = approved(cap(), 10_000);
        let intent = open_pr(
            &appr,
            verified_patch(),
            "crustcore/p10-fix",
            "main",
            Timestamp::from_millis(1_000),
        )
        .unwrap();
        assert!(intent.draft, "CrustCore opens DRAFT PRs");
        assert_eq!(intent.repo.0.as_str(), "RNT56/CrustCore");
        assert_eq!(intent.base_branch, "main");
        // The body is verifier evidence, not a self-claim.
        assert!(intent.body.contains("Verifier:"));
        assert!(intent.body.contains("cargo test"));
        assert!(intent.body.contains("Human review required before merge"));
        assert!(intent.body.contains("Patch hash:"));
        assert!(intent.body.contains("Receipt event seq: `1`"));
        assert!(intent.body.contains("Receipt result hash:"));
        assert!(intent.body.contains("Risk notes"));
        assert!(intent.body.contains("self-claim is **not** evidence"));
        assert!(!intent
            .body
            .to_lowercase()
            .contains("self_claimed_done: true"));
    }

    #[test]
    fn open_pr_rejects_expired_approval() {
        let appr = approved(cap(), 100);
        let err = open_pr(
            &appr,
            verified_patch(),
            "crustcore/x",
            "main",
            Timestamp::from_millis(500), // > expires_at
        )
        .unwrap_err();
        assert_eq!(err, IntegrateError::ApprovalExpired);
    }

    #[test]
    fn open_pr_rejects_branch_outside_prefix() {
        let appr = approved(cap(), 10_000);
        let err = open_pr(
            &appr,
            verified_patch(),
            "main", // not under "crustcore/"
            "main",
            Timestamp::from_millis(1),
        )
        .unwrap_err();
        assert!(matches!(err, IntegrateError::BranchNotUnderPrefix(_)));
    }

    #[test]
    fn branch_under_prefix_matches_at_a_segment_boundary_and_fails_closed() {
        // In-prefix branches (with or without the trailing slash on the prefix) match.
        assert!(branch_under_prefix("crustcore/ok", "crustcore"));
        assert!(branch_under_prefix("crustcore/ok", "crustcore/"));
        assert!(branch_under_prefix("crustcore", "crustcore")); // the prefix itself
                                                                // A sibling that merely shares a textual prefix does NOT match (segment boundary).
        assert!(!branch_under_prefix("crustcore-evil/x", "crustcore"));
        // `.`/`..` traversal in any segment is rejected.
        assert!(!branch_under_prefix("crustcore/../etc", "crustcore"));
        assert!(!branch_under_prefix("crustcore/./x", "crustcore"));
        // An empty prefix fails closed (never matches everything).
        assert!(!branch_under_prefix("anything/x", ""));
        assert!(!branch_under_prefix("anything/x", "/"));
    }

    // The type-13 gate is structural: `open_pr` takes a `VerifiedPatch` by value,
    // and there is no public constructor of `VerifiedPatch` outside the verifier —
    // so an `UnverifiedPatch`/`BackendResult` cannot reach this function at all.
}
