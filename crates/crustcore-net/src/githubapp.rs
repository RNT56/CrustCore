// SPDX-License-Identifier: Apache-2.0
//! GitHub App authentication: RS256 JWT minting + installation-token exchange
//! (P10/B2-gh-app). The decision core — *which* auth mode, *whether* a push is in
//! scope — already lives in `crustcore-daemon::github` (`AuthMode::GitHubApp`,
//! `validate_push`, the merge gate). This module is the **live credential mint** for
//! the preferred (`AuthMode::GitHubApp`) posture: a short-lived installation token the
//! [`RestGitHub`](crate::github::RestGitHub) client then carries.
//!
//! The flow (GitHub's documented App auth):
//!
//! 1. Build a signed **RS256 JWT** asserting the App's identity: header
//!    `{"alg":"RS256","typ":"JWT"}`, claims `{iat, exp, iss: <app_id>}` with `exp`
//!    at most 10 minutes out (GitHub's hard cap), signed with the App's RSA private
//!    key ([`mint_app_jwt`]).
//! 2. Exchange that JWT for an **installation access token** via
//!    `POST /app/installations/<id>/access_tokens`, authenticating with
//!    `Authorization: Bearer <jwt>` ([`AppTokenMinter::installation_token`]).
//!
//! **Feature-gated (`github-app`), never nano.** The RSA + SHA-256 + base64 crates
//! this needs are *optional* dependencies behind the `github-app` feature, so the
//! default `crustcore-net` build (and the whole workspace/CI build, and the spawned
//! mock helper) links none of them — `forbidden-deps` proves the default tree is
//! HTTP/TLS- and crypto-clean.
//!
//! **Key handling (invariants 1–3).** The RSA private key is resolved through the
//! credential proxy/broker by the operator and passed in as PEM bytes to
//! [`AppRsaKey::from_pem`]; it is parsed once into a signing key held only for the life
//! of that value, never serialized, never logged, and **never** placed into an error
//! string. The minted JWT *is* a bearer credential too: it rides in the `Authorization`
//! header for the one exchange call and is dropped — never logged, never echoed into a
//! `GitHubError` (the token exchange reuses the providers' status-only error mapping).

use std::rc::Rc;

use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::RsaPrivateKey;
use sha2::Sha256;

use crate::github::GitHubError;
use crate::transport::HttpClient;

/// The `exp - iat` window for an App JWT. GitHub rejects a JWT whose `exp` is more
/// than 10 minutes after `iat` (and recommends a small backdated `iat` for clock
/// skew); we use a conservative window strictly under the cap.
pub const JWT_TTL_SECS: u64 = 9 * 60;

/// A small backdate applied to `iat` to tolerate clock skew between us and GitHub
/// (GitHub's own recommendation). Kept well within the 10-minute `exp` cap.
pub const JWT_IAT_BACKDATE_SECS: u64 = 30;

/// A GitHub App's RSA private signing key, parsed from PEM. Holds the parsed
/// [`SigningKey`] only — the PEM bytes are consumed by [`AppRsaKey::from_pem`] and not
/// retained. Deliberately not `Debug`/`Clone`/`Serialize`: it is secret material
/// (invariant 3) built just before signing and dropped.
pub struct AppRsaKey {
    signing_key: SigningKey<Sha256>,
}

impl AppRsaKey {
    /// Parses a PKCS#8 PEM RSA private key (GitHub Apps issue PKCS#1 `.pem`; callers
    /// holding a PKCS#1 key can convert once at setup). The bytes are parsed and
    /// dropped; only the signing key is retained.
    ///
    /// # Errors
    /// [`JwtError::Key`] if the PEM is not a valid RSA private key. The error carries a
    /// fixed reason, **never** the key bytes.
    pub fn from_pem(pem: &str) -> Result<Self, JwtError> {
        let key = RsaPrivateKey::from_pkcs8_pem(pem).map_err(|_| JwtError::Key)?;
        Ok(AppRsaKey {
            signing_key: SigningKey::<Sha256>::new(key),
        })
    }

    /// Builds the parsed key directly from an [`RsaPrivateKey`] (used by tests that
    /// generate an ephemeral keypair, and by callers that already hold a parsed key).
    #[must_use]
    pub fn from_rsa(key: RsaPrivateKey) -> Self {
        AppRsaKey {
            signing_key: SigningKey::<Sha256>::new(key),
        }
    }
}

/// Why minting an App JWT failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwtError {
    /// The provided PEM was not a valid RSA private key (no key bytes are carried).
    Key,
}

impl core::fmt::Display for JwtError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            // Fixed message — never the key material.
            JwtError::Key => write!(f, "invalid RSA private key"),
        }
    }
}

/// URL-safe base64 **without** padding, the JWT (JWS) encoding (RFC 7515 §2).
fn b64url(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Mints a signed **RS256** GitHub App JWT for `app_id`, valid from `now_unix`
/// (backdated by [`JWT_IAT_BACKDATE_SECS`]) for [`JWT_TTL_SECS`]. `now_unix` is the
/// caller-supplied wall-clock time in seconds (the kernel owns time; this sidecar
/// takes it as a parameter so the build is deterministic + testable).
///
/// The returned string is `base64url(header).base64url(claims).base64url(signature)`
/// where the signature is `RSASSA-PKCS1-v1_5` over SHA-256 of the signing input. It is
/// a **bearer credential** (it authenticates as the App) — pass it straight to the
/// token exchange and drop it; never log it.
#[must_use]
pub fn mint_app_jwt(key: &AppRsaKey, app_id: &str, now_unix: u64) -> String {
    let iat = now_unix.saturating_sub(JWT_IAT_BACKDATE_SECS);
    let exp = iat.saturating_add(JWT_TTL_SECS);

    // Compact, fixed-shape header/claims so the signing input is exactly what GitHub
    // verifies. `iss` is the App id (a string, per GitHub's examples).
    let header = serde_json::json!({ "alg": "RS256", "typ": "JWT" });
    let claims = serde_json::json!({ "iat": iat, "exp": exp, "iss": app_id });

    let header_b64 = b64url(&serde_json::to_vec(&header).unwrap_or_default());
    let claims_b64 = b64url(&serde_json::to_vec(&claims).unwrap_or_default());
    let signing_input = format!("{header_b64}.{claims_b64}");

    // RS256 = RSASSA-PKCS1-v1_5 with SHA-256. The SigningKey<Sha256> hashes + signs.
    let signature = key.signing_key.sign(signing_input.as_bytes());
    let sig_b64 = b64url(&signature.to_bytes());

    format!("{signing_input}.{sig_b64}")
}

/// Builds the body for `POST /app/installations/<id>/access_tokens`. GitHub accepts an
/// empty body (the installation is in the path); we send `{}` for an explicit
/// content-type. Testable independently of the transport.
#[must_use]
pub fn installation_token_body() -> Vec<u8> {
    b"{}".to_vec()
}

/// The result of an installation-token exchange — the short-lived token the
/// [`RestGitHub`](crate::github::RestGitHub) client carries, plus its expiry (opaque
/// string GitHub returns; stored for the daemon's refresh scheduling, never parsed for
/// control). The token is secret-bearing: this type is not `Debug`/`Serialize`.
pub struct InstallationToken {
    /// The installation access token (a `ghs_…` bearer credential).
    pub token: String,
    /// GitHub's ISO-8601 `expires_at` (informational; the daemon refreshes before it).
    pub expires_at: String,
}

/// Mints installation tokens for a GitHub App over an [`HttpClient`] transport. Build
/// it from the App id, the parsed [`AppRsaKey`], and the shared transport; call
/// [`AppTokenMinter::installation_token`] per installation as the token nears expiry.
pub struct AppTokenMinter {
    base_url: String,
    app_id: String,
    key: AppRsaKey,
    http: Rc<dyn HttpClient>,
}

impl AppTokenMinter {
    /// A minter against `base_url` (normally [`crate::github::GITHUB_API`]) for the App
    /// `app_id`, signing with `key`.
    #[must_use]
    pub fn new(
        base_url: impl Into<String>,
        app_id: impl Into<String>,
        key: AppRsaKey,
        http: Rc<dyn HttpClient>,
    ) -> Self {
        AppTokenMinter {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            app_id: app_id.into(),
            key,
            http,
        }
    }

    /// Exchanges a freshly minted App JWT for an installation access token for
    /// `installation_id`. `now_unix` is the wall-clock time (seconds) the JWT is
    /// stamped with.
    ///
    /// # Errors
    /// [`GitHubError`] on any non-success or unparseable response (status-mapped — the
    /// body, JWT, and key never appear in the error).
    pub fn installation_token(
        &self,
        installation_id: u64,
        now_unix: u64,
    ) -> Result<InstallationToken, GitHubError> {
        let jwt = mint_app_jwt(&self.key, &self.app_id, now_unix);
        let url = format!(
            "{}/app/installations/{installation_id}/access_tokens",
            self.base_url
        );
        // The JWT is the bearer credential for THIS exchange only; it is built here,
        // consumed into the header, and dropped — never logged, never in an error.
        let headers = vec![
            ("Authorization".to_string(), format!("Bearer {jwt}")),
            (
                "Accept".to_string(),
                "application/vnd.github+json".to_string(),
            ),
            (
                "X-GitHub-Api-Version".to_string(),
                crate::github::GITHUB_API_VERSION.to_string(),
            ),
            ("User-Agent".to_string(), "crustcore".to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ];
        let resp = self
            .http
            .post_json(&url, &headers, &installation_token_body())
            .map_err(|e| GitHubError::Transport(e.to_string()))?;
        if !resp.is_success() {
            return Err(map_token_status(resp.status));
        }
        let v: serde_json::Value = serde_json::from_str(&resp.body)
            .map_err(|e| GitHubError::BadResponse(e.to_string()))?;
        let token = v["token"]
            .as_str()
            .ok_or_else(|| GitHubError::BadResponse("missing token".into()))?
            .to_string();
        let expires_at = v["expires_at"].as_str().unwrap_or_default().to_string();
        Ok(InstallationToken { token, expires_at })
    }
}

/// Maps a non-2xx token-exchange status to a typed [`GitHubError`]. Status-only — the
/// body (which on a 401 may echo the JWT) is **never** embedded.
fn map_token_status(status: u16) -> GitHubError {
    match status {
        401 | 403 => GitHubError::Unauthorized,
        404 => GitHubError::NotFound,
        429 => GitHubError::RateLimited,
        500..=599 => GitHubError::ServerError(status),
        _ => GitHubError::Unprocessable(format!("http {status}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{Canned, ReplayClient};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use rsa::pkcs1v15::VerifyingKey;
    use rsa::signature::Verifier;
    use rsa::RsaPublicKey;

    /// A small (1024-bit) RSA keypair generated fresh in the test — fast to generate,
    /// never committed. Production keys are 2048-bit+, resolved via the broker.
    fn test_keypair() -> (AppRsaKey, RsaPublicKey) {
        let mut rng = rand_for_test();
        let private = RsaPrivateKey::new(&mut rng, 1024).expect("generate test RSA key");
        let public = RsaPublicKey::from(&private);
        (AppRsaKey::from_rsa(private), public)
    }

    // The `rsa` crate re-exports a compatible RNG via `rand_core`; generate with a
    // seeded OS RNG so the test is self-contained.
    fn rand_for_test() -> impl rsa::rand_core::CryptoRngCore {
        rsa::rand_core::OsRng
    }

    fn split_jwt(jwt: &str) -> (String, String, Vec<u8>) {
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "a JWT has three dot-separated parts");
        let header = String::from_utf8(URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        let claims = String::from_utf8(URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        let sig = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        (header, claims, sig)
    }

    #[test]
    fn jwt_header_and_claims_are_rs256_and_within_the_cap() {
        let (key, _pub) = test_keypair();
        let now = 1_700_000_000u64;
        let jwt = mint_app_jwt(&key, "123456", now);
        let (header, claims, _sig) = split_jwt(&jwt);

        // Header: RS256 / JWT.
        let h: serde_json::Value = serde_json::from_str(&header).unwrap();
        assert_eq!(h["alg"], "RS256");
        assert_eq!(h["typ"], "JWT");

        // Claims: iss == app_id, iat backdated, exp within GitHub's 10-minute cap.
        let c: serde_json::Value = serde_json::from_str(&claims).unwrap();
        assert_eq!(c["iss"], "123456");
        let iat = c["iat"].as_u64().unwrap();
        let exp = c["exp"].as_u64().unwrap();
        assert_eq!(iat, now - JWT_IAT_BACKDATE_SECS);
        assert!(exp > iat, "exp must be after iat");
        assert!(
            exp - iat <= 600,
            "exp must be at most 10 minutes after iat (GitHub's cap)"
        );
    }

    #[test]
    fn jwt_signature_verifies_against_the_public_key() {
        // The load-bearing crypto assertion: an independently-derived verifying key
        // (from the public half of the keypair) accepts the signature over the exact
        // signing input `base64url(header).base64url(claims)`.
        let (key, public) = test_keypair();
        let jwt = mint_app_jwt(&key, "987654", 1_700_000_000);

        let parts: Vec<&str> = jwt.split('.').collect();
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();

        let verifying = VerifyingKey::<Sha256>::new(public);
        let signature = rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice()).unwrap();
        verifying
            .verify(signing_input.as_bytes(), &signature)
            .expect("the minted RS256 signature must verify against the App's public key");
    }

    #[test]
    fn a_tampered_signing_input_fails_verification() {
        // Flipping a claim must invalidate the signature (the signature binds header +
        // claims, so a forged `iss`/`exp` is rejected).
        let (key, public) = test_keypair();
        let jwt = mint_app_jwt(&key, "111", 1_700_000_000);
        let parts: Vec<&str> = jwt.split('.').collect();
        let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();

        let verifying = VerifyingKey::<Sha256>::new(public);
        let signature = rsa::pkcs1v15::Signature::try_from(sig_bytes.as_slice()).unwrap();
        // Tamper: claim a different App id in the signing input.
        let forged_claims = b64url(
            &serde_json::to_vec(
                &serde_json::json!({ "iat": 0, "exp": 540, "iss": "999-attacker" }),
            )
            .unwrap(),
        );
        let forged_input = format!("{}.{forged_claims}", parts[0]);
        assert!(
            verifying
                .verify(forged_input.as_bytes(), &signature)
                .is_err(),
            "a tampered signing input must NOT verify"
        );
    }

    #[test]
    fn invalid_pem_is_a_keyerror_not_a_panic_and_carries_no_bytes() {
        // `AppRsaKey` is intentionally not `Debug` (secret material), so match rather
        // than `unwrap_err()`.
        match AppRsaKey::from_pem(
            "-----BEGIN PRIVATE KEY-----\nnot a key\n-----END PRIVATE KEY-----",
        ) {
            Err(err) => {
                assert_eq!(err, JwtError::Key);
                // The error message is fixed — never the (attempted) key bytes.
                assert!(!format!("{err}").contains("not a key"));
            }
            Ok(_) => panic!("invalid PEM must not parse"),
        }
    }

    #[test]
    fn installation_token_parses_token_and_expiry() {
        let (key, _pub) = test_keypair();
        let minter = AppTokenMinter::new(
            crate::github::GITHUB_API,
            "123456",
            key,
            Rc::new(ReplayClient::new(vec![Canned::with_body(
                201,
                r#"{"token":"ghs_INSTALLTOKEN","expires_at":"2026-06-26T01:00:00Z"}"#,
            )])),
        );
        let tok = minter.installation_token(42, 1_700_000_000).unwrap();
        assert_eq!(tok.token, "ghs_INSTALLTOKEN");
        assert_eq!(tok.expires_at, "2026-06-26T01:00:00Z");
    }

    #[test]
    fn installation_token_non_2xx_never_fabricates_a_token() {
        let (key, _pub) = test_keypair();
        let minter = AppTokenMinter::new(
            crate::github::GITHUB_API,
            "123456",
            key,
            // A 401 whose body echoes the JWT must not surface it in the error.
            Rc::new(ReplayClient::new(vec![Canned::with_body(
                401,
                r#"{"message":"A JWT could not be decoded: eyJhbGci..."}"#,
            )])),
        );
        // `InstallationToken` is intentionally not `Debug` (secret material), so match
        // rather than `unwrap_err()`.
        match minter.installation_token(42, 1_700_000_000) {
            Err(err) => {
                assert_eq!(err, GitHubError::Unauthorized);
                assert!(!format!("{err}").contains("eyJhbGci"));
            }
            Ok(_) => panic!("a 401 must not mint a token"),
        }
    }

    // The real token exchange against api.github.com is `#[ignore]`d — it needs a real
    // App id + private key + installation id and never runs in CI. Only the JWT
    // build/sign/verify + the response parse above are CI-tested.
    #[test]
    #[ignore = "live: requires a real GitHub App key + installation (TODO B2-gh-app-live)"]
    fn live_installation_token_smoke() {
        // To run: provide the App id, PEM key path, and installation id via env, then
        // `cargo test --features "live,github-app" -- --ignored`.
        #[cfg(feature = "live")]
        {
            let app_id = std::env::var("CRUSTCORE_GH_APP_ID").expect("set CRUSTCORE_GH_APP_ID");
            let pem_path =
                std::env::var("CRUSTCORE_GH_APP_KEY_PEM").expect("set CRUSTCORE_GH_APP_KEY_PEM");
            let inst: u64 = std::env::var("CRUSTCORE_GH_INSTALLATION_ID")
                .expect("set CRUSTCORE_GH_INSTALLATION_ID")
                .parse()
                .expect("installation id");
            let pem = std::fs::read_to_string(pem_path).expect("read PEM");
            let key = AppRsaKey::from_pem(&pem).expect("parse PEM");
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let minter = AppTokenMinter::new(
                crate::github::GITHUB_API,
                app_id,
                key,
                Rc::new(crate::transport::UreqClient::new()),
            );
            let tok = minter
                .installation_token(inst, now)
                .expect("installation token exchange");
            assert!(tok.token.starts_with("ghs_"));
        }
    }
}
