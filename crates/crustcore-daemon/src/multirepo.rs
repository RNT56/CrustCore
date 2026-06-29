// SPDX-License-Identifier: Apache-2.0
//! Multi-repo orchestration (roadmap-v0.6 F.3).
//!
//! The `TaskRegistry` is already repo-agnostic. This module adds the **pure routing
//! decision**: bind several repos at startup (distinct paths / verify / PR targets) and
//! classify a chat launch to the right one. Repo bindings come from **config/CLI only,
//! never from model or user message text** (invariant 7); the global concurrency cap is
//! unchanged (invariant 11). The live multi-repo CLI startup + a simultaneous-task smoke
//! is the `TODO(P10-multi-repo-live)` seam.

/// Stable id for a bound repo (operator-chosen, e.g. `app` / `infra`). From config/CLI.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RepoId(pub String);

/// A repo CrustCore is bound to: its on-disk path, verify command, PR target, and the
/// keywords that route a launch to it. **Trusted setup data** — paths/commands are
/// supplied by the operator (config/CLI), not derived from untrusted input (invariant 7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoBinding {
    /// Operator-chosen id.
    pub id: RepoId,
    /// On-disk worktree path (from config/CLI).
    pub path: String,
    /// Verify command tokens.
    pub verify: Vec<String>,
    /// PR base branch.
    pub base_branch: String,
    /// Lower-cased keywords that route an intent to this repo (id is always a keyword).
    pub keywords: Vec<String>,
}

impl RepoBinding {
    /// Builds a binding; the id is automatically a routing keyword.
    #[must_use]
    pub fn new(id: impl Into<String>, path: impl Into<String>) -> Self {
        let id = id.into();
        RepoBinding {
            keywords: vec![id.to_lowercase()],
            id: RepoId(id),
            path: path.into(),
            verify: Vec::new(),
            base_branch: "main".to_string(),
        }
    }

    /// Adds routing keywords (lower-cased).
    #[must_use]
    pub fn with_keywords<I, S>(mut self, kws: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        for k in kws {
            self.keywords.push(k.into().to_lowercase());
        }
        self
    }

    fn matches(&self, intent_lower: &str) -> bool {
        self.keywords
            .iter()
            .any(|k| !k.is_empty() && intent_lower.contains(k.as_str()))
    }
}

/// Classifies a launch intent to a bound repo:
/// 1. If exactly **one** repo's keyword appears in the intent → that repo (an explicit hint).
/// 2. Else if exactly **one** repo is bound → it (the sole-repo default).
/// 3. Else → `None` — ambiguous or unhinted with multiple repos; the dispatcher asks the
///    operator "which repo?" rather than guessing (a helpful failure, not a silent pick).
///
/// Pure: the intent text is untrusted but only *matched against operator keywords* — it
/// never supplies a path (invariant 7).
#[must_use]
pub fn classify_repo(intent: &str, repos: &[RepoBinding]) -> Option<RepoId> {
    let lower = intent.to_lowercase();
    let mut hinted = repos.iter().filter(|r| r.matches(&lower));
    match (hinted.next(), hinted.next()) {
        (Some(only), None) => Some(only.id.clone()), // exactly one hint
        (Some(_), Some(_)) => None,                  // ambiguous hint → ask
        (None, _) => {
            if repos.len() == 1 {
                Some(repos[0].id.clone()) // sole-repo default
            } else {
                None // no hint, multiple repos → ask
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repos() -> Vec<RepoBinding> {
        vec![
            RepoBinding::new("app", "/src/app").with_keywords(["frontend", "ui"]),
            RepoBinding::new("infra", "/src/infra").with_keywords(["terraform", "deploy"]),
        ]
    }

    #[test]
    fn an_explicit_hint_routes_to_that_repo() {
        assert_eq!(
            classify_repo("fix the frontend button", &repos()),
            Some(RepoId("app".to_string()))
        );
        assert_eq!(
            classify_repo("update the terraform module", &repos()),
            Some(RepoId("infra".to_string()))
        );
        // The id itself is a keyword.
        assert_eq!(
            classify_repo("run tests in infra", &repos()),
            Some(RepoId("infra".to_string()))
        );
    }

    #[test]
    fn a_sole_repo_is_the_default_without_a_hint() {
        let one = vec![RepoBinding::new("only", "/src/only")];
        assert_eq!(
            classify_repo("do something vague", &one),
            Some(RepoId("only".to_string()))
        );
    }

    #[test]
    fn ambiguous_or_unhinted_with_multiple_repos_is_none() {
        // No keyword present → None (ask which repo).
        assert_eq!(classify_repo("do something vague", &repos()), None);
        // Two repos hinted → None (ambiguous).
        assert_eq!(classify_repo("wire the frontend deploy", &repos()), None);
        // No repos bound at all → None.
        assert_eq!(classify_repo("anything", &[]), None);
    }

    #[test]
    fn classification_is_case_insensitive_and_path_free() {
        assert_eq!(
            classify_repo("FIX THE UI", &repos()),
            Some(RepoId("app".to_string()))
        );
        // The intent never supplies a path — only matches operator keywords.
        assert_eq!(
            classify_repo("/etc/passwd frontend", &repos()).unwrap().0,
            "app"
        );
    }

    // Live seam: multi-repo CLI startup (`--repo id=/path`) + a simultaneous-task smoke.
    #[test]
    #[ignore = "live: bind multiple repos via CLI and run simultaneous tasks (TODO(P10-multi-repo-live))"]
    fn multi_repo_live_smoke() {
        // See docs/live-socket-validation.md §F.5. Needs real repos + the daemon loop.
        panic!("live seam: run manually with --repo bindings (see runbook §F.5)");
    }
}
