// SPDX-License-Identifier: Apache-2.0
//! GitHub App onboarding (roadmap-v0.6 A.1).
//!
//! Turns a GitHub App **install redirect** into a registered, write-capable repo,
//! entirely through the existing typed primitives:
//!
//! ```text
//! InstallRedirect (untrusted)              -- invariant 7: validated, never trusted as-is
//!   -> cap_from_redirect  -> GitHubWriteCap   (scoped to repo + "crustcore/" prefix)
//!   -> RepoRegistry::register                 -- the repo becomes push-validatable (A.2)
//!   -> AuthorizedUser::approve                 -- mints Approved<GitHubWriteCap> (inv. 4/14)
//!   -> RepoProfile::parse(crustcore.yml)       -- bounds the untrusted config (existing parser)
//! ```
//!
//! Everything here is a **pure decision core** — no network, no clock, no secret
//! material. The two live inches (confirm `GET /app/installations/{id}` and mint
//! the installation token against a real App) are the `TODO(app-onboarding-live)`
//! seam, exercised only by the `#[ignore]`d `app_onboarding_live_smoke` (see
//! `docs/live-socket-validation.md` §B.1).
//!
//! Trust boundary (unchanged): the App private key is `SecretMaterial` brokered to
//! the net layer (invariant 1); the minted installation token is short-lived
//! (invariant 3) and is the *only* credential a push/PR may use; only the
//! `Approved<GitHubWriteCap>` minted here authorizes opening a PR (invariants 13/14).
//! The onboarding `AuthorizedUser` is the operator who installed the App, bound at
//! the trusted setup boundary — never model, worker, or comment data (invariant 4).

use crustcore_policy::{Approved, AuthorizedUser, GitHubWriteCap};
use crustcore_types::{ApprovalId, BoundedText, BranchPrefix, RepoRef, ScopeId, Timestamp};

use crate::github::RepoRegistry;
use crate::product::{ProfileError, RepoProfile};

/// The branch prefix every CrustCore write is confined to (the `GitHubWriteCap`
/// scope). A push outside this prefix is rejected by `validate_push` (A.2).
pub const DEFAULT_BRANCH_PREFIX: &str = "crustcore/";

/// Defensive cap on a `owner/repo` slug we will register (GitHub's own limits are
/// far smaller; this just keeps a bogus redirect from registering a giant key).
pub const MAX_REPO_SLUG: usize = 256;

/// The parameters GitHub appends to the post-install redirect (`installation_id`,
/// the `setup_action` id, and the repo the App was installed on). This is
/// **untrusted input** (invariant 7): [`cap_from_redirect`] validates it before it
/// can register anything.
#[derive(Debug, Clone)]
pub struct InstallRedirect {
    /// The `installation_id` query parameter (identifies the App installation).
    pub installation_id: u64,
    /// The optional `setup_action`-associated id (`setup_id`); informational only.
    pub setup_id: Option<u64>,
    /// The `owner/repo` slug the App was installed on.
    pub repo: String,
}

/// Why onboarding refused. Every variant is a *guided* failure — the operator is
/// told what to fix; onboarding never silently defaults (fail-closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnboardingError {
    /// `installation_id` was zero/absent — the install redirect did not complete.
    MissingInstallationId,
    /// The repo slug was not a well-formed `owner/repo`.
    InvalidRepo,
    /// The repo slug exceeded [`MAX_REPO_SLUG`].
    RepoSlugTooLong,
    /// No `crustcore.yml` on the default branch — guide the user to add one.
    MissingConfig,
    /// `crustcore.yml` was present but failed the bounded parser.
    InvalidConfig(ProfileError),
}

impl core::fmt::Display for OnboardingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            OnboardingError::MissingInstallationId => write!(
                f,
                "install redirect did not carry an installation_id — re-run the GitHub App install \
                 and let it redirect back to CrustCore"
            ),
            OnboardingError::InvalidRepo => write!(
                f,
                "repository must be a well-formed \"owner/repo\" slug"
            ),
            OnboardingError::RepoSlugTooLong => {
                write!(f, "repository slug exceeds {MAX_REPO_SLUG} bytes")
            }
            OnboardingError::MissingConfig => write!(
                f,
                "no crustcore.yml found on the default branch — add one (see docs/product-stack.md) \
                 so CrustCore knows your verify command and executors"
            ),
            OnboardingError::InvalidConfig(e) => write!(f, "invalid crustcore.yml: {e}"),
        }
    }
}

impl std::error::Error for OnboardingError {}

/// Validates a `owner/repo` slug: non-empty owner + name, a single `/`, and only
/// the characters GitHub permits (`[A-Za-z0-9._-]`). Rejecting whitespace/control
/// keeps the slug safe as a registry key and a URL path segment (invariant 7).
fn validate_repo_slug(slug: &str) -> Result<(), OnboardingError> {
    if slug.len() > MAX_REPO_SLUG {
        return Err(OnboardingError::RepoSlugTooLong);
    }
    let (owner, name) = slug.split_once('/').ok_or(OnboardingError::InvalidRepo)?;
    if owner.is_empty() || name.is_empty() || name.contains('/') {
        return Err(OnboardingError::InvalidRepo);
    }
    // Reject a `.`/`..` segment: the slug is later interpolated into a REST path
    // (`/repos/{owner}/{name}/pulls`, A.3), where `..` would cause path confusion.
    if matches!(owner, "." | "..") || matches!(name, "." | "..") {
        return Err(OnboardingError::InvalidRepo);
    }
    let ok = |s: &str| {
        s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    };
    if !ok(owner) || !ok(name) {
        return Err(OnboardingError::InvalidRepo);
    }
    Ok(())
}

/// Validates an [`InstallRedirect`] and builds the scoped [`GitHubWriteCap`].
/// Pure — no network. Rejects a malformed slug or an absent installation id so a
/// bogus redirect can never register a writable repo (invariant 7).
///
/// # Errors
/// [`OnboardingError::MissingInstallationId`] / [`OnboardingError::InvalidRepo`] /
/// [`OnboardingError::RepoSlugTooLong`].
pub fn cap_from_redirect(
    redirect: &InstallRedirect,
    scope: ScopeId,
) -> Result<GitHubWriteCap, OnboardingError> {
    if redirect.installation_id == 0 {
        return Err(OnboardingError::MissingInstallationId);
    }
    validate_repo_slug(&redirect.repo)?;
    let repo = RepoRef(
        BoundedText::with_max(redirect.repo.clone(), MAX_REPO_SLUG)
            .map_err(|_| OnboardingError::RepoSlugTooLong)?,
    );
    let branch_prefix = BranchPrefix(
        BoundedText::new(DEFAULT_BRANCH_PREFIX).expect("static branch prefix is within bounds"),
    );
    Ok(GitHubWriteCap {
        repo,
        branch_prefix,
        scope,
    })
}

/// The result of onboarding a repo: the write approval bound to the onboarding
/// operator. The `GitHubWriteCap` itself is now in the [`RepoRegistry`] (for push
/// validation, A.2); this `Approved` is what authorizes *opening a PR* (invariant 14).
#[derive(Debug)]
pub struct Onboarded {
    /// The minted write approval — the only thing that authorizes a PR.
    pub approval: Approved<GitHubWriteCap>,
    /// The installation whose short-lived token will carry the writes.
    pub installation_id: u64,
    /// The registered repo slug.
    pub repo: String,
}

/// Registers the repo and mints the write approval. This is the **trusted setup
/// boundary**: `operator` is the [`AuthorizedUser`] who installed the App, bound
/// out-of-band — never derived from model/worker/comment data (invariant 4).
///
/// Builds the capability twice (once for the registry's push validator, once
/// wrapped in the `Approved` for PR authorization) because a `GitHubWriteCap` is
/// intentionally non-`Clone`: capabilities are not silently duplicated.
///
/// # Errors
/// Propagates [`cap_from_redirect`] validation failures (the redirect is untrusted).
pub fn onboard(
    registry: &mut RepoRegistry,
    operator: AuthorizedUser,
    redirect: &InstallRedirect,
    scope: ScopeId,
    approval_id: ApprovalId,
    approval_expires_at: Timestamp,
) -> Result<Onboarded, OnboardingError> {
    // Validate once up front so a bad redirect registers nothing.
    let cap_for_registry = cap_from_redirect(redirect, scope)?;
    let cap_for_approval = cap_from_redirect(redirect, scope)?;
    registry.register(cap_for_registry);
    let approval = operator.approve(cap_for_approval, approval_id, approval_expires_at);
    Ok(Onboarded {
        approval,
        installation_id: redirect.installation_id,
        repo: redirect.repo.clone(),
    })
}

/// A cached installation token's expiry window. The token itself is secret-bearing
/// and minted at the live seam; here we model only the **refresh decision** so a
/// late task never tries to push with an expired token (invariant 3; the A.1 risk
/// "token expiry can strand late tasks").
#[derive(Debug, Clone, Copy)]
pub struct TokenLease {
    /// The installation the token belongs to.
    pub installation_id: u64,
    /// When GitHub says the token expires.
    pub expires_at: Timestamp,
}

impl TokenLease {
    /// Whether the token must be refreshed before use at `now`, refreshing
    /// `skew_ms` early so a token that would expire mid-operation is never handed
    /// out. Saturating arithmetic keeps a near-`u64::MAX` `now` from wrapping.
    #[must_use]
    pub fn needs_refresh(&self, now: Timestamp, skew_ms: u64) -> bool {
        now.as_millis().saturating_add(skew_ms) >= self.expires_at.as_millis()
    }
}

/// Loads the repo profile from a fetched `crustcore.yml` body. An empty/whitespace
/// body means the file was absent on the default branch — guide the operator to add
/// one rather than silently defaulting (A.1 risk: "missing crustcore.yml must guide
/// the user"). A present-but-invalid file surfaces the bounded parser's error.
///
/// # Errors
/// [`OnboardingError::MissingConfig`] for an absent file;
/// [`OnboardingError::InvalidConfig`] wrapping the bounded parser error otherwise.
pub fn load_profile(yaml: &str) -> Result<RepoProfile, OnboardingError> {
    if yaml.trim().is_empty() {
        return Err(OnboardingError::MissingConfig);
    }
    RepoProfile::parse(yaml).map_err(OnboardingError::InvalidConfig)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redirect(repo: &str) -> InstallRedirect {
        InstallRedirect {
            installation_id: 42,
            setup_id: Some(7),
            repo: repo.to_string(),
        }
    }

    #[test]
    fn cap_from_a_good_redirect_is_scoped_to_repo_and_prefix() {
        let cap = cap_from_redirect(&redirect("RNT56/CrustCore"), ScopeId(1)).unwrap();
        assert_eq!(cap.repo.0.as_str(), "RNT56/CrustCore");
        assert_eq!(cap.branch_prefix.0.as_str(), DEFAULT_BRANCH_PREFIX);
    }

    #[test]
    fn a_zero_installation_id_is_refused() {
        let mut r = redirect("RNT56/CrustCore");
        r.installation_id = 0;
        assert_eq!(
            cap_from_redirect(&r, ScopeId(1)).unwrap_err(),
            OnboardingError::MissingInstallationId
        );
    }

    #[test]
    fn malformed_slugs_are_refused() {
        for bad in [
            "noslash",
            "/CrustCore",
            "RNT56/",
            "a/b/c",
            "RNT56/Crust Core",
            "RNT56/Crust\nCore",
            "RNT56/Crust;rm",
            "RNT56/..",
            "../CrustCore",
            ".//CrustCore",
            "RNT56/.",
        ] {
            assert_eq!(
                cap_from_redirect(&redirect(bad), ScopeId(1)).unwrap_err(),
                OnboardingError::InvalidRepo,
                "slug {bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn an_overlong_slug_is_refused() {
        let big = format!("owner/{}", "n".repeat(MAX_REPO_SLUG));
        assert_eq!(
            cap_from_redirect(&redirect(&big), ScopeId(1)).unwrap_err(),
            OnboardingError::RepoSlugTooLong
        );
    }

    #[test]
    fn onboard_registers_the_repo_and_mints_an_approval() {
        let mut reg = RepoRegistry::new();
        let operator = AuthorizedUser::bind(1001);
        let out = onboard(
            &mut reg,
            operator,
            &redirect("RNT56/CrustCore"),
            ScopeId(1),
            ApprovalId(9),
            Timestamp::from_millis(10_000),
        )
        .unwrap();

        // The repo is now push-validatable (A.2 will consume `cap_for`).
        assert!(reg.is_registered("RNT56/CrustCore"));
        // The approval authorizes a PR and is bound to the onboarding operator.
        assert_eq!(out.approval.approved_by(), operator);
        assert_eq!(out.installation_id, 42);
        // Only a *valid* approval authorizes a PR (invariant 14): it is valid before
        // expiry and refused after.
        assert!(out.approval.is_valid_at(Timestamp::from_millis(5_000)));
        assert!(!out.approval.is_valid_at(Timestamp::from_millis(20_000)));
    }

    #[test]
    fn onboard_propagates_a_bad_redirect_and_registers_nothing() {
        let mut reg = RepoRegistry::new();
        let err = onboard(
            &mut reg,
            AuthorizedUser::bind(1),
            &redirect("noslash"),
            ScopeId(1),
            ApprovalId(1),
            Timestamp::from_millis(1),
        )
        .unwrap_err();
        assert_eq!(err, OnboardingError::InvalidRepo);
        assert!(!reg.is_registered("noslash"));
    }

    #[test]
    fn token_lease_refreshes_early_within_skew() {
        let lease = TokenLease {
            installation_id: 42,
            expires_at: Timestamp::from_millis(60_000),
        };
        // Comfortably before expiry, with a 5s skew: no refresh.
        assert!(!lease.needs_refresh(Timestamp::from_millis(50_000), 5_000));
        // Inside the skew window before expiry: refresh now (don't strand a late task).
        assert!(lease.needs_refresh(Timestamp::from_millis(56_000), 5_000));
        // At/after expiry: refresh.
        assert!(lease.needs_refresh(Timestamp::from_millis(60_000), 0));
        // Saturating: a near-max `now` does not wrap.
        assert!(lease.needs_refresh(Timestamp::from_millis(u64::MAX), 5_000));
    }

    #[test]
    fn load_profile_guides_on_missing_config() {
        assert_eq!(load_profile("   \n  "), Err(OnboardingError::MissingConfig));
        let msg = load_profile("").unwrap_err().to_string();
        assert!(msg.contains("crustcore.yml"), "got: {msg}");
    }

    #[test]
    fn load_profile_parses_a_real_config() {
        // A minimal, valid crustcore.yml — the bounded parser owns the grammar; here
        // we only assert onboarding threads it through.
        let yaml = "verify:\n  - cargo test\n";
        let profile = load_profile(yaml).expect("valid config parses");
        let _ = profile; // shape owned by RepoProfile's own tests
    }

    // ----- live seam (TODO(app-onboarding-live)) -----------------------------
    // The real install redirect + `GET /app/installations/{id}` confirm + token
    // mint against a test App. The pure onboarding core above is CI-tested; this is
    // the irreducible network inch. See docs/live-socket-validation.md §B.1.
    #[cfg(feature = "live")]
    #[test]
    #[ignore = "live: real GitHub App install redirect + GET /app/installations/{id} + token mint (TODO(app-onboarding-live))"]
    fn app_onboarding_live_smoke() {
        use crate::github::mint_installation_token;
        use crustcore_net::github::GITHUB_API;
        use crustcore_net::transport::UreqClient;
        use std::rc::Rc;

        let app_id = std::env::var("CRUSTCORE_GH_APP_ID").expect("set CRUSTCORE_GH_APP_ID");
        let pem_path =
            std::env::var("CRUSTCORE_GH_APP_KEY_PEM").expect("set CRUSTCORE_GH_APP_KEY_PEM");
        let inst: u64 = std::env::var("CRUSTCORE_GH_INSTALLATION_ID")
            .expect("set CRUSTCORE_GH_INSTALLATION_ID")
            .parse()
            .expect("installation id");
        let repo = std::env::var("CRUSTCORE_GH_REPO").expect("set CRUSTCORE_GH_REPO (owner/repo)");
        let pem = std::fs::read_to_string(pem_path).expect("read PEM");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // 1. The redirect-driven pure core registers the repo + mints the approval.
        let mut reg = RepoRegistry::new();
        let onboarded = onboard(
            &mut reg,
            AuthorizedUser::bind(1),
            &InstallRedirect {
                installation_id: inst,
                setup_id: None,
                repo: repo.clone(),
            },
            ScopeId(1),
            ApprovalId(1),
            Timestamp::from_millis((now + 3600) * 1000),
        )
        .expect("onboard the test repo");
        assert!(reg.is_registered(&repo));

        // 2. The live inch: mint the installation token the writes will carry.
        match mint_installation_token(
            GITHUB_API,
            &app_id,
            &pem,
            onboarded.installation_id,
            now,
            Rc::new(UreqClient::new()),
        ) {
            Ok(tok) => assert!(tok.token.starts_with("ghs_")),
            Err(e) => panic!("installation token exchange failed: {e}"),
        }
    }
}
