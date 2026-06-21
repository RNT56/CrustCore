// SPDX-License-Identifier: Apache-2.0
//! Live embedding adapter (Track C C1-providers): an OpenAI-compatible
//! `/v1/embeddings` [`EmbedProvider`] over the [`HttpClient`] transport boundary.
//!
//! All parse / map logic here is **transport-agnostic** and fully tested in CI with
//! [`ReplayClient`](crate::transport::ReplayClient) — no network. The real socket
//! lives only in `UreqClient` (the `live` feature). The three load-bearing properties
//! the completion adapters establish are preserved exactly:
//!
//! 1. **No-secret-to-anywhere-but-the-request.** The credential is resolved per call
//!    via [`CredentialSource`], assembled into a header, and consumed into the
//!    request — never stored on the adapter, never in an error string, never logged.
//! 2. **Bounded + no-panic.** Every response is bounded; malformed / truncated /
//!    non-UTF8 JSON is mapped to a typed error or sanitized, never panicked on
//!    (invariant 7: provider output is untrusted data).
//! 3. **Status-only errors.** A non-2xx maps to a typed [`ProviderError`] via
//!    [`map_status_error`](crate::providers::map_status_error) — the provider body
//!    (which could echo a credential) is never surfaced verbatim.

use std::rc::Rc;

use crustcore_netproto::Usage;

use crate::credsource::{AuthStyle, CredentialSource};
use crate::modality::{EmbedProvider, EmbeddingRequest, EmbeddingResponse};
use crate::providers::map_status_error;
use crate::transport::HttpClient;
use crate::{ModelCard, ProviderError};

/// An OpenAI-compatible embedding provider (`/v1/embeddings`). Serves OpenAI and any
/// OpenAI-compatible embeddings endpoint (e.g. local servers, OpenRouter).
pub struct OpenAiEmbedProvider {
    id: String,
    base_url: String,
    secret_label: Option<String>,
    extra_headers: Vec<(String, String)>,
    cards: Vec<ModelCard>,
    http: Rc<dyn HttpClient>,
    creds: Rc<dyn CredentialSource>,
}

impl OpenAiEmbedProvider {
    /// Builds an adapter from its config pieces + shared transport/credential source.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: impl Into<String>,
        base_url: impl Into<String>,
        secret_label: Option<String>,
        extra_headers: Vec<(String, String)>,
        cards: Vec<ModelCard>,
        http: Rc<dyn HttpClient>,
        creds: Rc<dyn CredentialSource>,
    ) -> Self {
        OpenAiEmbedProvider {
            id: id.into(),
            base_url: base_url.into(),
            secret_label,
            extra_headers,
            cards,
            http,
            creds,
        }
    }

    /// Base headers + a freshly resolved auth header (per call, never stored).
    fn headers(&self) -> Vec<(String, String)> {
        let mut h = vec![("Content-Type".to_string(), "application/json".to_string())];
        h.extend(self.extra_headers.iter().cloned());
        if let Some(label) = &self.secret_label {
            if let Some(auth) = self.creds.header_for(label, AuthStyle::Bearer) {
                h.push((auth.name.to_string(), auth.value.clone()));
            }
        }
        h
    }

    fn card_cost(&self, model: &str) -> u64 {
        self.cards
            .iter()
            .find(|c| c.model == model)
            .map_or(0, |c| c.cost_per_1k_micros)
    }
}

/// Builds the `/v1/embeddings` request body (`{"model":..,"input":[..]}`).
fn embed_body(model: &str, req: &EmbeddingRequest) -> Vec<u8> {
    let body = serde_json::json!({
        "model": model,
        "input": req.inputs,
    });
    serde_json::to_vec(&body).unwrap_or_default()
}

/// Parse the OpenAI embeddings response: `{"data":[{"embedding":[..]}..],"usage":{..}}`.
/// Every field is treated as untrusted — missing/garbage yields an empty vector for
/// that slot rather than a panic; non-finite floats are sanitized downstream by the
/// engine. Returns `None` if the body is not valid JSON (a no-panic skip).
fn parse_embed_response(body: &str) -> Option<(Vec<Vec<f32>>, Usage)> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let data = v.get("data").and_then(|d| d.as_array());
    let vectors: Vec<Vec<f32>> = match data {
        Some(arr) => arr
            .iter()
            .map(|item| {
                item.get("embedding")
                    .and_then(|e| e.as_array())
                    .map(|nums| {
                        nums.iter()
                            .map(|n| n.as_f64().unwrap_or(0.0) as f32)
                            .collect()
                    })
                    .unwrap_or_default()
            })
            .collect(),
        None => Vec::new(),
    };
    let usage = Usage {
        input_tokens: v["usage"]["prompt_tokens"].as_u64().unwrap_or(0) as u32,
        output_tokens: 0,
        cost_micros: 0,
    };
    Some((vectors, usage))
}

impl EmbedProvider for OpenAiEmbedProvider {
    fn id(&self) -> &str {
        &self.id
    }

    fn probe(&self) -> Vec<ModelCard> {
        // The configured allowlist is the dynamic registry (invariant 17). Only cards
        // the operator marked as embeddings-capable should be here; we filter
        // defensively so a misconfigured non-embedding card is never offered.
        self.cards
            .iter()
            .filter(|c| c.embeddings)
            .cloned()
            .collect()
    }

    fn embed(
        &self,
        model: &str,
        req: &EmbeddingRequest,
    ) -> Result<EmbeddingResponse, ProviderError> {
        let url = format!("{}/v1/embeddings", self.base_url);
        let headers = self.headers();
        let body = embed_body(model, req);

        // Embeddings are a non-streaming JSON API: use post_json (full body back).
        let resp = self
            .http
            .post_json(&url, &headers, &body)
            .map_err(|e| ProviderError::Unavailable(e.to_string()))?;

        if !resp.is_success() {
            // Status-only mapping — the body (which could echo a credential) is never
            // surfaced verbatim (mirrors the completion adapters).
            return Err(map_status_error(resp.status, &resp.body));
        }

        let (vectors, mut usage) = parse_embed_response(&resp.body)
            .ok_or_else(|| ProviderError::Other("malformed embeddings response".to_string()))?;

        if vectors.is_empty() {
            return Err(ProviderError::Other(
                "embeddings response carried no vectors".to_string(),
            ));
        }

        // Estimate input tokens if the provider omitted them, and price from the card.
        if usage.input_tokens == 0 {
            let bytes: usize = req.inputs.iter().map(String::len).sum();
            usage.input_tokens = (bytes / 4 + 1) as u32;
        }
        usage.cost_micros = self
            .card_cost(model)
            .saturating_mul(u64::from(usage.input_tokens))
            / 1000;

        Ok(EmbeddingResponse { vectors, usage })
    }
}

/// Builds the live [`EmbedProvider`] set from a provider config over a shared
/// transport + credential source. Only providers whose config carries at least one
/// embeddings-capable model become an embed adapter. Always compiled (the transport
/// is injected), so the routing + fallback are testable in CI with a
/// [`ReplayClient`](crate::transport::ReplayClient); the `live` helper passes a real
/// `UreqClient`.
#[must_use]
pub fn build_embed_providers(
    configs: &[crate::config::ProviderConfig],
    http: Rc<dyn HttpClient>,
    creds: Rc<dyn CredentialSource>,
) -> Vec<Box<dyn EmbedProvider>> {
    let mut out: Vec<Box<dyn EmbedProvider>> = Vec::new();
    for cfg in configs {
        let embed_cards: Vec<ModelCard> = cfg
            .models
            .iter()
            .filter(|c| c.embeddings)
            .cloned()
            .collect();
        if embed_cards.is_empty() {
            continue;
        }
        // Every OpenAI-compatible embeddings endpoint uses the same shape; Anthropic
        // has no embeddings API, so an Anthropic-kind config contributes no embedder.
        if matches!(cfg.kind, crate::config::ProviderKind::OpenAiCompatible) {
            out.push(Box::new(OpenAiEmbedProvider::new(
                format!("{}-embed", cfg.id),
                cfg.base_url.clone(),
                cfg.secret_label.clone(),
                cfg.extra_headers.clone(),
                embed_cards,
                http.clone(),
                creds.clone(),
            )));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credsource::StaticCredentials;
    use crate::transport::{Canned, ReplayClient};
    use crustcore_netproto::Role;

    fn creds() -> Rc<dyn CredentialSource> {
        Rc::new(StaticCredentials::new().with("k", "sk-SECRET"))
    }

    fn card(model: &str, dims: u32, cost: u64) -> ModelCard {
        ModelCard {
            model: model.into(),
            healthy: true,
            context: 8192,
            tools: false,
            structured: false,
            streaming: false,
            cost_per_1k_micros: cost,
            local: false,
            embeddings: true,
            rerank: false,
            embedding_dims: dims,
        }
    }

    fn provider(http: ReplayClient) -> OpenAiEmbedProvider {
        OpenAiEmbedProvider::new(
            "openai-embed",
            "https://api.openai.com",
            Some("k".into()),
            vec![],
            vec![card("text-embedding-3-small", 1536, 200)],
            Rc::new(http),
            creds(),
        )
    }

    fn req(inputs: &[&str]) -> EmbeddingRequest {
        EmbeddingRequest::new(
            Role::Research,
            inputs.iter().map(|s| (*s).to_string()).collect(),
            0,
        )
    }

    #[test]
    fn parses_embeddings_and_usage_and_cost() {
        let http = ReplayClient::new(vec![Canned::with_body(
            200,
            r#"{"data":[{"embedding":[0.1,0.2,0.3]},{"embedding":[0.4,0.5,0.6]}],"usage":{"prompt_tokens":2000}}"#,
        )]);
        let out = provider(http)
            .embed("text-embedding-3-small", &req(&["a", "b"]))
            .unwrap();
        assert_eq!(out.vectors.len(), 2);
        assert_eq!(out.vectors[0], vec![0.1, 0.2, 0.3]);
        assert_eq!(out.usage.input_tokens, 2000);
        // cost = 200/1k * 2000 = 400 micros
        assert_eq!(out.usage.cost_micros, 400);
    }

    #[test]
    fn missing_usage_is_estimated() {
        let http = ReplayClient::new(vec![Canned::with_body(
            200,
            r#"{"data":[{"embedding":[0.1,0.2]}]}"#,
        )]);
        let out = provider(http)
            .embed("text-embedding-3-small", &req(&["hello world"]))
            .unwrap();
        assert!(out.usage.input_tokens > 0);
    }

    #[test]
    fn rate_limit_is_unavailable() {
        let http = ReplayClient::new(vec![Canned::with_body(429, "rate limited")]);
        let err = provider(http)
            .embed("text-embedding-3-small", &req(&["a"]))
            .unwrap_err();
        assert!(matches!(err, ProviderError::Unavailable(_)));
    }

    #[test]
    fn context_overflow_is_capability() {
        let http = ReplayClient::new(vec![Canned::with_body(
            400,
            r#"{"error":{"message":"maximum context length exceeded"}}"#,
        )]);
        let err = provider(http)
            .embed("text-embedding-3-small", &req(&["a"]))
            .unwrap_err();
        assert!(matches!(err, ProviderError::Capability(_)));
    }

    #[test]
    fn malformed_json_is_an_error_not_a_panic() {
        let http = ReplayClient::new(vec![Canned::with_body(200, "{not json")]);
        let err = provider(http)
            .embed("text-embedding-3-small", &req(&["a"]))
            .unwrap_err();
        assert!(matches!(err, ProviderError::Other(_)));
    }

    #[test]
    fn empty_data_is_an_error_not_silent_success() {
        let http = ReplayClient::new(vec![Canned::with_body(200, r#"{"data":[]}"#)]);
        let err = provider(http)
            .embed("text-embedding-3-small", &req(&["a"]))
            .unwrap_err();
        assert!(matches!(err, ProviderError::Other(_)));
    }

    #[test]
    fn key_never_appears_in_vectors_or_errors() {
        // Success path: a body that echoes the key in a string field must not leak it
        // into the parsed vectors (they are numeric); and the error path is status-only.
        let http = ReplayClient::new(vec![Canned::with_body(
            401,
            r#"{"error":"invalid key sk-SECRET"}"#,
        )]);
        let err = provider(http)
            .embed("text-embedding-3-small", &req(&["a"]))
            .unwrap_err();
        assert!(!format!("{err}").contains("sk-SECRET"));
    }
}
