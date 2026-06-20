// SPDX-License-Identifier: Apache-2.0
//! GitHub REST wire layer (P10-net): the live HTTP execution of the GitHub decision
//! cores that already live in `crustcore-backend::integrate` (`open_pr` → `PrIntent`,
//! `format_pr_body`) and `crustcore-daemon::github` (`validate_push`, `decide_merge`,
//! `repair_decision`, `ingest_comment`). Those decide *whether* and *what*; this
//! executes the approved REST call.
//!
//! Like the model adapters, this client goes through the [`HttpClient`] transport so
//! its build/parse/error logic is **fully CI-testable with a canned `ReplayClient`**
//! (no network); the real socket is the `live`-gated `UreqClient`. It takes
//! **primitive** inputs (owner/repo strings, branch names, body text) rather than the
//! backend's `PrIntent`/`VerifiedPatch` types, so the model-transport sidecar stays
//! dependency-light — the daemon maps a `PrIntent` (which it already holds) onto a
//! [`CreatePrRequest`] field-for-field and calls this.
//!
//! Trust posture: a GitHub response is **untrusted data** (invariant 7) — only the
//! few fields we need are extracted (number / url / id / conclusion); nothing in a
//! response is ever interpreted as a command. A non-2xx **never** fabricates a
//! success ([`GitHubError`], not a fake [`PrCreated`]). The token is resolved per call
//! via [`CredentialSource`] and never reaches the model, a log, or an error string
//! (errors are status-mapped, never the verbatim body).

use std::rc::Rc;

use crate::credsource::{AuthStyle, CredentialSource};
use crate::transport::HttpClient;

/// Default GitHub REST base URL.
pub const GITHUB_API: &str = "https://api.github.com";
/// The GitHub REST API version this client targets.
pub const GITHUB_API_VERSION: &str = "2022-11-28";

/// A request to open a pull request (primitive fields the daemon maps a `PrIntent`
/// onto). Always opened as a **draft** by the gate; `draft` is carried explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreatePrRequest {
    /// `owner/name`.
    pub repo: String,
    /// Head branch (the change).
    pub head: String,
    /// Base branch (the target).
    pub base: String,
    /// PR title.
    pub title: String,
    /// PR body (built from verifier evidence by `format_pr_body`, not a model claim).
    pub body: String,
    /// Open as a draft (the gate sets this true).
    pub draft: bool,
}

/// The result of creating a PR — only the fields CrustCore needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrCreated {
    /// The PR number.
    pub number: u64,
    /// The PR's web URL (opaque data — stored, never acted on).
    pub html_url: String,
}

/// A request to comment on an issue/PR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateCommentRequest {
    /// `owner/name`.
    pub repo: String,
    /// The issue/PR number.
    pub issue_number: u64,
    /// The comment body.
    pub body: String,
}

/// The distilled state of a ref's check runs (the daemon maps this onto its
/// `CheckOutcome` + `repair_decision`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckState {
    /// At least one check is still queued/running, or none have registered yet.
    Pending,
    /// All checks completed successfully.
    Passed,
    /// At least one check concluded in failure/cancelled/timed-out.
    Failed,
}

/// Why a GitHub call failed. A non-2xx maps here — it never becomes a fake success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitHubError {
    /// 401/403 — bad or insufficiently-scoped credential (or forbidden).
    Unauthorized,
    /// 404 — repo/resource not found (or not visible to the token).
    NotFound,
    /// 422 — validation failed (e.g. a PR for that head already exists).
    Unprocessable(String),
    /// 429 / secondary rate limit.
    RateLimited,
    /// 5xx — GitHub server error.
    ServerError(u16),
    /// A transport-level failure (connect/timeout/io).
    Transport(String),
    /// A 2xx whose body could not be parsed for the expected fields.
    BadResponse(String),
}

impl core::fmt::Display for GitHubError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            GitHubError::Unauthorized => write!(f, "unauthorized"),
            GitHubError::NotFound => write!(f, "not found"),
            GitHubError::Unprocessable(m) => write!(f, "unprocessable: {m}"),
            GitHubError::RateLimited => write!(f, "rate limited"),
            GitHubError::ServerError(s) => write!(f, "server error {s}"),
            GitHubError::Transport(e) => write!(f, "transport: {e}"),
            GitHubError::BadResponse(m) => write!(f, "bad response: {m}"),
        }
    }
}

/// The GitHub operations CrustCore needs. A `RestGitHub` implements it over HTTP; a
/// mock implements it for the daemon's tests.
pub trait GitHubApi {
    /// Opens a (draft) pull request.
    ///
    /// # Errors
    /// [`GitHubError`] on any non-success or unparseable response.
    fn create_pull(&self, req: &CreatePrRequest) -> Result<PrCreated, GitHubError>;

    /// The distilled check state for a ref (commit SHA or branch).
    ///
    /// # Errors
    /// [`GitHubError`] on any non-success or unparseable response.
    fn check_state(&self, repo: &str, git_ref: &str) -> Result<CheckState, GitHubError>;

    /// Posts a comment to an issue/PR; returns the new comment id.
    ///
    /// # Errors
    /// [`GitHubError`] on any non-success or unparseable response.
    fn create_comment(&self, req: &CreateCommentRequest) -> Result<u64, GitHubError>;
}

/// The live GitHub REST client over an [`HttpClient`] transport + a credential source.
pub struct RestGitHub {
    base_url: String,
    secret_label: String,
    http: Rc<dyn HttpClient>,
    creds: Rc<dyn CredentialSource>,
}

impl RestGitHub {
    /// A client against `base_url` authenticating with the secret under `secret_label`.
    #[must_use]
    pub fn new(
        base_url: impl Into<String>,
        secret_label: impl Into<String>,
        http: Rc<dyn HttpClient>,
        creds: Rc<dyn CredentialSource>,
    ) -> Self {
        RestGitHub {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            secret_label: secret_label.into(),
            http,
            creds,
        }
    }

    fn headers(&self) -> Vec<(String, String)> {
        let mut h = vec![
            (
                "Accept".to_string(),
                "application/vnd.github+json".to_string(),
            ),
            (
                "X-GitHub-Api-Version".to_string(),
                GITHUB_API_VERSION.to_string(),
            ),
            ("User-Agent".to_string(), "crustcore".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];
        if let Some(auth) = self.creds.header_for(&self.secret_label, AuthStyle::Bearer) {
            h.push((auth.name.to_string(), auth.value.clone()));
        }
        h
    }
}

/// Builds the create-pull request body (testable independently of the transport).
#[must_use]
pub fn create_pull_body(req: &CreatePrRequest) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "title": req.title,
        "head": req.head,
        "base": req.base,
        "body": req.body,
        "draft": req.draft,
    }))
    .unwrap_or_default()
}

/// Maps a non-2xx status + body to a typed [`GitHubError`].
fn map_status(status: u16, body: &str) -> GitHubError {
    match status {
        401 | 403 if body.to_ascii_lowercase().contains("rate limit") => GitHubError::RateLimited,
        401 | 403 => GitHubError::Unauthorized,
        404 => GitHubError::NotFound,
        422 => {
            // Carry only GitHub's bounded `message` field (e.g. "a PR already
            // exists"), not the whole error body. It is still **untrusted** GitHub
            // content (invariant 7) — this surfaces to the operator/daemon, which
            // redacts it through the `Redactor` before any model visibility; it never
            // contains CrustCore's own token (GitHub does not echo request headers).
            let msg = serde_json::from_str::<serde_json::Value>(body)
                .ok()
                .and_then(|v| v["message"].as_str().map(str::to_string))
                .unwrap_or_else(|| "validation failed".to_string());
            GitHubError::Unprocessable(msg)
        }
        429 => GitHubError::RateLimited,
        500..=599 => GitHubError::ServerError(status),
        _ => GitHubError::Unprocessable(format!("http {status}")),
    }
}

impl GitHubApi for RestGitHub {
    fn create_pull(&self, req: &CreatePrRequest) -> Result<PrCreated, GitHubError> {
        let url = format!("{}/repos/{}/pulls", self.base_url, req.repo);
        let body = create_pull_body(req);
        let resp = self
            .http
            .post_json(&url, &self.headers(), &body)
            .map_err(|e| GitHubError::Transport(e.to_string()))?;
        if !resp.is_success() {
            return Err(map_status(resp.status, &resp.body));
        }
        let v: serde_json::Value = serde_json::from_str(&resp.body)
            .map_err(|e| GitHubError::BadResponse(e.to_string()))?;
        let number = v["number"]
            .as_u64()
            .ok_or_else(|| GitHubError::BadResponse("missing PR number".into()))?;
        let html_url = v["html_url"].as_str().unwrap_or_default().to_string();
        Ok(PrCreated { number, html_url })
    }

    fn check_state(&self, repo: &str, git_ref: &str) -> Result<CheckState, GitHubError> {
        let url = format!(
            "{}/repos/{repo}/commits/{git_ref}/check-runs",
            self.base_url
        );
        let resp = self
            .http
            .get(&url, &self.headers())
            .map_err(|e| GitHubError::Transport(e.to_string()))?;
        if !resp.is_success() {
            return Err(map_status(resp.status, &resp.body));
        }
        let v: serde_json::Value = serde_json::from_str(&resp.body)
            .map_err(|e| GitHubError::BadResponse(e.to_string()))?;
        Ok(aggregate_checks(&v))
    }

    fn create_comment(&self, req: &CreateCommentRequest) -> Result<u64, GitHubError> {
        let url = format!(
            "{}/repos/{}/issues/{}/comments",
            self.base_url, req.repo, req.issue_number
        );
        let body = serde_json::to_vec(&serde_json::json!({ "body": req.body })).unwrap_or_default();
        let resp = self
            .http
            .post_json(&url, &self.headers(), &body)
            .map_err(|e| GitHubError::Transport(e.to_string()))?;
        if !resp.is_success() {
            return Err(map_status(resp.status, &resp.body));
        }
        let v: serde_json::Value = serde_json::from_str(&resp.body)
            .map_err(|e| GitHubError::BadResponse(e.to_string()))?;
        v["id"]
            .as_u64()
            .ok_or_else(|| GitHubError::BadResponse("missing comment id".into()))
    }
}

/// Distills a `check-runs` response into a [`CheckState`]. Any not-completed run (or
/// none at all) → `Pending`; any failure-class conclusion → `Failed`; else `Passed`.
fn aggregate_checks(v: &serde_json::Value) -> CheckState {
    let runs = match v["check_runs"].as_array() {
        Some(r) => r,
        None => return CheckState::Pending,
    };
    if runs.is_empty() {
        // No checks registered yet → not safe to call it passed (a repair loop keeps
        // waiting); the daemon decides what an empty set means for *its* gate.
        return CheckState::Pending;
    }
    let mut any_failed = false;
    for run in runs {
        if run["status"].as_str() != Some("completed") {
            return CheckState::Pending;
        }
        match run["conclusion"].as_str() {
            Some("success" | "neutral" | "skipped") => {}
            Some(_) | None => any_failed = true,
        }
    }
    if any_failed {
        CheckState::Failed
    } else {
        CheckState::Passed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credsource::StaticCredentials;
    use crate::transport::{Canned, ReplayClient};

    fn client(responses: Vec<Canned>) -> RestGitHub {
        RestGitHub::new(
            GITHUB_API,
            "gh",
            Rc::new(ReplayClient::new(responses)),
            Rc::new(StaticCredentials::new().with("gh", "ghp_SECRET")),
        )
    }

    fn pr_req() -> CreatePrRequest {
        CreatePrRequest {
            repo: "owner/name".into(),
            head: "claude/fix".into(),
            base: "main".into(),
            title: "Fix the thing".into(),
            body: "verified by `cargo test`".into(),
            draft: true,
        }
    }

    #[test]
    fn create_pull_body_carries_draft_and_branches() {
        let body = create_pull_body(&pr_req());
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["draft"], serde_json::Value::Bool(true));
        assert_eq!(v["head"], "claude/fix");
        assert_eq!(v["base"], "main");
    }

    #[test]
    fn create_pull_parses_number_and_url() {
        let gh = client(vec![Canned::with_body(
            201,
            r#"{"number":42,"html_url":"https://github.com/owner/name/pull/42"}"#,
        )]);
        let pr = gh.create_pull(&pr_req()).unwrap();
        assert_eq!(pr.number, 42);
        assert_eq!(pr.html_url, "https://github.com/owner/name/pull/42");
    }

    #[test]
    fn non_2xx_never_fabricates_a_pr() {
        // 422 (e.g. PR already exists) → Unprocessable with the message, no fake PR.
        let gh = client(vec![Canned::with_body(
            422,
            r#"{"message":"A pull request already exists for owner:claude/fix."}"#,
        )]);
        match gh.create_pull(&pr_req()) {
            Err(GitHubError::Unprocessable(m)) => assert!(m.contains("already exists")),
            other => panic!("expected Unprocessable, got {other:?}"),
        }
        // 401 → Unauthorized.
        assert_eq!(
            client(vec![Canned::with_body(401, "Bad credentials")])
                .create_pull(&pr_req())
                .unwrap_err(),
            GitHubError::Unauthorized
        );
        // 404 → NotFound.
        assert_eq!(
            client(vec![Canned::with_body(404, "Not Found")])
                .create_pull(&pr_req())
                .unwrap_err(),
            GitHubError::NotFound
        );
        // A 2xx with a junk body → BadResponse, NOT a fabricated success.
        assert!(matches!(
            client(vec![Canned::with_body(201, "not json")])
                .create_pull(&pr_req())
                .unwrap_err(),
            GitHubError::BadResponse(_)
        ));
    }

    #[test]
    fn check_state_aggregates_runs() {
        let passed = client(vec![Canned::with_body(
            200,
            r#"{"total_count":2,"check_runs":[{"status":"completed","conclusion":"success"},{"status":"completed","conclusion":"skipped"}]}"#,
        )]);
        assert_eq!(
            passed.check_state("o/n", "abc").unwrap(),
            CheckState::Passed
        );

        let failed = client(vec![Canned::with_body(
            200,
            r#"{"total_count":1,"check_runs":[{"status":"completed","conclusion":"failure"}]}"#,
        )]);
        assert_eq!(
            failed.check_state("o/n", "abc").unwrap(),
            CheckState::Failed
        );

        let pending = client(vec![Canned::with_body(
            200,
            r#"{"total_count":1,"check_runs":[{"status":"in_progress","conclusion":null}]}"#,
        )]);
        assert_eq!(
            pending.check_state("o/n", "abc").unwrap(),
            CheckState::Pending
        );

        // No checks registered yet → Pending (a repair loop keeps waiting).
        let empty = client(vec![Canned::with_body(
            200,
            r#"{"total_count":0,"check_runs":[]}"#,
        )]);
        assert_eq!(
            empty.check_state("o/n", "abc").unwrap(),
            CheckState::Pending
        );
    }

    #[test]
    fn create_comment_parses_id() {
        let gh = client(vec![Canned::with_body(201, r#"{"id":987}"#)]);
        let id = gh
            .create_comment(&CreateCommentRequest {
                repo: "o/n".into(),
                issue_number: 5,
                body: "checks passed".into(),
            })
            .unwrap();
        assert_eq!(id, 987);
    }

    #[test]
    fn token_never_leaks_into_a_routed_error() {
        // A 401 whose body echoes the token must not surface it in the GitHubError.
        let gh = client(vec![Canned::with_body(
            401,
            r#"{"message":"Bad credentials for ghp_SECRET"}"#,
        )]);
        let err = gh.create_pull(&pr_req()).unwrap_err();
        assert!(!format!("{err}").contains("ghp_SECRET"));
        assert_eq!(err, GitHubError::Unauthorized); // status-mapped, body not echoed
    }
}
