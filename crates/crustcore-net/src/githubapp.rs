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
//! **Feature-gated (`github-app`), never nano.** The AWS-LC-backed JWT implementation
//! is an *optional* dependency behind the `github-app` feature, so the
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

use jsonwebtoken::{Algorithm, EncodingKey, Header};

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
/// [`EncodingKey`] only — the PEM bytes are consumed by [`AppRsaKey::from_pem`] and not
/// retained. Deliberately not `Debug`/`Clone`/`Serialize`: it is secret material
/// (invariant 3) built just before signing and dropped.
pub struct AppRsaKey {
    signing_key: EncodingKey,
}

impl AppRsaKey {
    /// Parses a PKCS#1 or PKCS#8 PEM RSA private key. The bytes are parsed and
    /// dropped; only the AWS-LC-backed signing key is retained.
    ///
    /// # Errors
    /// [`JwtError::Key`] if the PEM is not a valid RSA private key. The error carries a
    /// fixed reason, **never** the key bytes.
    pub fn from_pem(pem: &str) -> Result<Self, JwtError> {
        let signing_key = EncodingKey::from_rsa_pem(pem.as_bytes()).map_err(|_| JwtError::Key)?;
        Ok(AppRsaKey { signing_key })
    }
}

/// Why minting an App JWT failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JwtError {
    /// The provided PEM was not a valid RSA private key (no key bytes are carried).
    Key,
    /// AWS-LC refused to sign the fixed RS256 token.
    Sign,
}

impl core::fmt::Display for JwtError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            // Fixed message — never the key material.
            JwtError::Key => write!(f, "invalid RSA private key"),
            JwtError::Sign => write!(f, "RSA signing failed"),
        }
    }
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
pub fn mint_app_jwt(key: &AppRsaKey, app_id: &str, now_unix: u64) -> Result<String, JwtError> {
    let iat = now_unix.saturating_sub(JWT_IAT_BACKDATE_SECS);
    let exp = iat.saturating_add(JWT_TTL_SECS);

    let header = Header::new(Algorithm::RS256);
    let claims = serde_json::json!({ "iat": iat, "exp": exp, "iss": app_id });
    jsonwebtoken::encode(&header, &claims, &key.signing_key).map_err(|_| JwtError::Sign)
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

impl Drop for InstallationToken {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.token.zeroize();
    }
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
        let jwt = mint_app_jwt(&self.key, &self.app_id, now_unix)
            .map_err(|_| GitHubError::Unauthorized)?;
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
    use jsonwebtoken::{dangerous, decode, DecodingKey, Validation};

    const TEST_RSA_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCUlqZHa4Ow8v8a
o+LneBZ4dbUNHGmvQ+GOe+bb9Co+gxOQ65zI3S5AgV4UItDVNVa2GbpFV+2vslCK
L0zGslXtas5g/u8IEfTyiAc4mwi5ePkPWkHPltLu1AhEFkCM3ah7ArRdTXp2Uu67
M3FAJpWZnhXRzD4GdMXVVTdML4U8CDerhZke1wx1RvLOSTlGaG2LD5Svc9+RtKjr
bcPatiOcut7IfwRSi42kDmNf5qB/5cMiGzbA0ATh0bTDPzJ6U0kfGiRaUxyLlVcD
W2a8TskP0UQGi9um1wk+OiFocm3O9UhdosdNFn2nirb4zo4BkMR9quEBMMaex7b9
mPZNA/W/AgMBAAECggEAGLFMYrQIR4CqSjgP/h1jxpLxCoO9QGYMdsw6WjUiTA8m
UkAFZw/ynr+g7cG3aKcbiNmPrfRlyHvejIg9vwtl4jWMpGvZN0McrK1UXeDNu1zS
Lu3139SVqyDLWt1DzuULGZ4icRruDfnMOInc+ScwVz4BLEM/z3zaX5BwxxVik84c
0U8K8axt8i2eUfmk+PO+qOh1bsW7+TVbDMm7Pd9dmtQVnjKjJWomdm4S+S1sgsMT
6AWKNK5Rp0g5mwcs2sfQxDvSR6vY2fR78yNXceQfBetTQbZt+Wot7Pd2uMQwSPgq
TjXLMeQSgYZCUq2hfO2n6Xwqg91r6d+6yRGC9ksVAQKBgQDQuh1ePxEW+oxMqhpJ
21V1NTNLXL5u4YyQwzbHiSisF2nvFXO+JA+Lx5zdK8GzCN1gk3j8esyQp5ltFjui
PQc+jKI8Y/k1ZISEFWf7fMU8Nn8ysA9dXdlMqOCn23TISfysM78F5Z5q4Huzu8K6
ZhQjUPEm6Crrh/cYCdh1zIWggQKBgQC2Pbu3UdZf8hnb0HUBvReKDhhP1CaCIXIz
m7oHZiccsL0HPtN8tqVJO+8tCnWbNt88AWy/N1ttg6F+cCOyyzVYcfhCJFNDFnyB
a7kEZ9ALrza5/W5HnVlslxpwov6D2wnJQxvgoIjS1AQKAnKc5Ya3nom6eR2OAdUw
Yuc3DSZ2PwKBgAOWDwcdgkeoylxO1+DI+fDnlxgGYec5zNZ35CsNejtqs5E+Bx0P
NY0rQtCx/cP7tQIBxqRf37/kgUhUh3XEIqm6dNcgyJlYPsaeL4ksnZ7pOMpAKCNs
h10/0YxQwvLmAoda5D9PsKcZcEaoRTI6qsHolBwdBQ/C6EXrdWKgvvMBAoGAPP1q
Dk8ALLoMd2lLT1qmPxi6gDTi8lgZLTZnysQgQNTRXlRjWPCTXnAFepBujZSOnzlm
2JPBMGSGLpd/Cv5BCymRSSl5CBHFd1bC47uOf+qSqSostyDs5Y+oVJvoC97JZqbj
9IglYlF8TJFHJEUYkekn9NVF09m/LGNdOCpZfecCgYAJWSW+n1cZnMGm/2ivnnst
0DD5CicHngCF0sGKLZGAk0Nm15SHKoYLbQ+v8I7rU//TH8hJxq/CT4jTCiFyRgt7
0RMel1B6ixq6DhUE9Ze10aUi7jU0QX58s96t6bgmhD/lHy41I8casXppbZ5No7s+
XverGQjJluKLrhI/yNqINA==
-----END PRIVATE KEY-----"#;

    const TEST_RSA_PUBLIC_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlJamR2uDsPL/GqPi53gW
eHW1DRxpr0Phjnvm2/QqPoMTkOucyN0uQIFeFCLQ1TVWthm6RVftr7JQii9MxrJV
7WrOYP7vCBH08ogHOJsIuXj5D1pBz5bS7tQIRBZAjN2oewK0XU16dlLuuzNxQCaV
mZ4V0cw+BnTF1VU3TC+FPAg3q4WZHtcMdUbyzkk5Rmhtiw+Ur3PfkbSo623D2rYj
nLreyH8EUouNpA5jX+agf+XDIhs2wNAE4dG0wz8yelNJHxokWlMci5VXA1tmvE7J
D9FEBovbptcJPjohaHJtzvVIXaLHTRZ9p4q2+M6OAZDEfarhATDGnse2/Zj2TQP1
vwIDAQAB
-----END PUBLIC KEY-----"#;

    fn test_key() -> AppRsaKey {
        AppRsaKey::from_pem(TEST_RSA_KEY).expect("parse committed test-only RSA key")
    }

    #[test]
    fn jwt_header_and_claims_are_rs256_and_within_the_cap() {
        let key = test_key();
        let now = 1_700_000_000u64;
        let jwt = mint_app_jwt(&key, "123456", now).unwrap();
        let decoded = dangerous::insecure_decode::<serde_json::Value>(&jwt).unwrap();

        // Header: RS256 / JWT.
        assert_eq!(decoded.header.alg, Algorithm::RS256);
        assert_eq!(decoded.header.typ.as_deref(), Some("JWT"));

        // Claims: iss == app_id, iat backdated, exp within GitHub's 10-minute cap.
        let c = decoded.claims;
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
        let key = test_key();
        let jwt = mint_app_jwt(&key, "987654", 1_700_000_000).unwrap();
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = false;
        validation.required_spec_claims.clear();
        decode::<serde_json::Value>(
            &jwt,
            &DecodingKey::from_rsa_pem(TEST_RSA_PUBLIC_KEY.as_bytes()).unwrap(),
            &validation,
        )
        .expect("the minted RS256 signature must verify through AWS-LC");
    }

    #[test]
    fn a_tampered_signing_input_fails_verification() {
        // Flipping a claim must invalidate the signature (the signature binds header +
        // claims, so a forged `iss`/`exp` is rejected).
        let key = test_key();
        let jwt = mint_app_jwt(&key, "111", 1_700_000_000).unwrap();
        let mut forged = jwt.into_bytes();
        let first_dot = forged.iter().position(|byte| *byte == b'.').unwrap();
        let claim_byte = first_dot + 2;
        forged[claim_byte] = if forged[claim_byte] == b'A' {
            b'B'
        } else {
            b'A'
        };
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = false;
        validation.required_spec_claims.clear();
        assert!(
            decode::<serde_json::Value>(
                String::from_utf8(forged).unwrap(),
                &DecodingKey::from_rsa_pem(TEST_RSA_PUBLIC_KEY.as_bytes()).unwrap(),
                &validation,
            )
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
        let key = test_key();
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
        let key = test_key();
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
