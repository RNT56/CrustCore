// SPDX-License-Identifier: Apache-2.0
//! Live rerank adapter (Track C C1-providers): a Cohere/Jina-style `/v1/rerank`
//! [`RerankProvider`] over the [`HttpClient`] transport boundary.
//!
//! All parse / map logic is **transport-agnostic** and fully tested in CI with
//! [`ReplayClient`](crate::transport::ReplayClient) — no network. The real socket
//! lives only in `UreqClient` (the `live` feature). Three properties mirror the
//! completion/embedding adapters:
//!
//! 1. **No-secret-to-anywhere-but-the-request.** The credential is resolved per call
//!    via [`CredentialSource`] and never stored, logged, or surfaced in an error.
//! 2. **Bounded + no-panic.** Malformed / truncated / non-UTF8 JSON is mapped to a
//!    typed error, never panicked on (invariant 7).
//! 3. **Untrusted indices.** Scores and document indices in the response are
//!    untrusted: out-of-range and duplicate indices are dropped, non-finite scores
//!    are sanitized to `0.0`, via [`sanitize_ranking`](crate::modality::sanitize_ranking)
//!    — never propagated raw into downstream selection.

use std::rc::Rc;

use crustcore_netproto::Usage;

use crate::credsource::{AuthStyle, CredentialSource};
use crate::modality::{sanitize_ranking, RerankProvider, RerankRequest, RerankResponse};
use crate::providers::map_status_error;
use crate::transport::HttpClient;
use crate::{ModelCard, ProviderError};

/// A Cohere/Jina-style rerank provider (`/v1/rerank`). The request/response shape is
/// the widely-adopted `{query, documents}` → `{results:[{index, relevance_score}]}`.
pub struct RerankApiProvider {
    id: String,
    base_url: String,
    secret_label: Option<String>,
    extra_headers: Vec<(String, String)>,
    cards: Vec<ModelCard>,
    http: Rc<dyn HttpClient>,
    creds: Rc<dyn CredentialSource>,
}

impl RerankApiProvider {
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
        RerankApiProvider {
            id: id.into(),
            base_url: base_url.into(),
            secret_label,
            extra_headers,
            cards,
            http,
            creds,
        }
    }

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

/// Builds the `/v1/rerank` request body.
fn rerank_body(model: &str, req: &RerankRequest) -> Vec<u8> {
    let body = serde_json::json!({
        "model": model,
        "query": req.query,
        "documents": req.documents,
        "top_n": req.documents.len(),
    });
    serde_json::to_vec(&body).unwrap_or_default()
}

/// Parse a rerank response into RAW `(index, score)` pairs, BEFORE validation. Accepts
/// the Cohere/Jina `{"results":[{"index":i,"relevance_score":s}..]}` shape and the
/// OpenAI-compatible `{"data":[{"index":i,"relevance_score":s}..]}` shape; `score`
/// also reads `score` as a fallback key. Returns `None` if the body is not valid JSON.
/// Every value is untrusted: the indices are read as raw `i64` (validated by the
/// caller via [`sanitize_ranking`]); missing scores default to `0.0`.
fn parse_rerank_response(body: &str) -> Option<(Vec<(i64, f32)>, Usage)> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let results = v
        .get("results")
        .and_then(|r| r.as_array())
        .or_else(|| v.get("data").and_then(|d| d.as_array()))?;
    let raw: Vec<(i64, f32)> = results
        .iter()
        .map(|item| {
            // Read the index as a raw i64 (could be out of range / negative — that is
            // the point; sanitize_ranking rejects bad ones). Absent → -1 (dropped).
            let idx = item
                .get("index")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(-1);
            let score = item
                .get("relevance_score")
                .or_else(|| item.get("score"))
                .and_then(serde_json::Value::as_f64)
                .unwrap_or(0.0) as f32;
            (idx, score)
        })
        .collect();
    let usage = Usage {
        input_tokens: v["usage"]["prompt_tokens"]
            .as_u64()
            .or_else(|| v["meta"]["billed_units"]["search_units"].as_u64())
            .unwrap_or(0) as u32,
        output_tokens: 0,
        cost_micros: 0,
    };
    Some((raw, usage))
}

impl RerankProvider for RerankApiProvider {
    fn id(&self) -> &str {
        &self.id
    }

    fn probe(&self) -> Vec<ModelCard> {
        // The configured allowlist is the dynamic registry (invariant 17); offer only
        // rerank-capable cards defensively.
        self.cards.iter().filter(|c| c.rerank).cloned().collect()
    }

    fn rerank(&self, model: &str, req: &RerankRequest) -> Result<RerankResponse, ProviderError> {
        let url = format!("{}/v1/rerank", self.base_url);
        let headers = self.headers();
        let body = rerank_body(model, req);

        let resp = self
            .http
            .post_json(&url, &headers, &body)
            .map_err(|e| ProviderError::Unavailable(e.to_string()))?;

        if !resp.is_success() {
            return Err(map_status_error(resp.status, &resp.body));
        }

        let (raw, mut usage) = parse_rerank_response(&resp.body)
            .ok_or_else(|| ProviderError::Other("malformed rerank response".to_string()))?;

        // Validate indices against the request's document count: drop out-of-range /
        // duplicate indices, sanitize non-finite scores, sort by descending score.
        // A hostile provider cannot corrupt downstream selection (invariant 7).
        let ranking = sanitize_ranking(&raw, req.doc_count());
        if ranking.is_empty() && !req.documents.is_empty() {
            return Err(ProviderError::Other(
                "rerank response carried no valid results".to_string(),
            ));
        }

        if usage.input_tokens == 0 {
            let bytes: usize =
                req.documents.iter().map(String::len).sum::<usize>() + req.query.len();
            usage.input_tokens = (bytes / 4 + 1) as u32;
        }
        usage.cost_micros = self
            .card_cost(model)
            .saturating_mul(u64::from(usage.input_tokens))
            / 1000;

        Ok(RerankResponse { ranking, usage })
    }
}

/// Builds the live [`RerankProvider`] set from a provider config over a shared
/// transport + credential source. Only providers whose config carries at least one
/// rerank-capable model become a rerank adapter. Always compiled (the transport is
/// injected) so routing + fallback are CI-testable with a
/// [`ReplayClient`](crate::transport::ReplayClient).
#[must_use]
pub fn build_rerankers(
    configs: &[crate::config::ProviderConfig],
    http: Rc<dyn HttpClient>,
    creds: Rc<dyn CredentialSource>,
) -> Vec<Box<dyn RerankProvider>> {
    let mut out: Vec<Box<dyn RerankProvider>> = Vec::new();
    for cfg in configs {
        let rerank_cards: Vec<ModelCard> =
            cfg.models.iter().filter(|c| c.rerank).cloned().collect();
        if rerank_cards.is_empty() {
            continue;
        }
        out.push(Box::new(RerankApiProvider::new(
            format!("{}-rerank", cfg.id),
            cfg.base_url.clone(),
            cfg.secret_label.clone(),
            cfg.extra_headers.clone(),
            rerank_cards,
            http.clone(),
            creds.clone(),
        )));
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

    fn card(model: &str, cost: u64) -> ModelCard {
        ModelCard {
            model: model.into(),
            healthy: true,
            context: 8192,
            tools: false,
            structured: false,
            streaming: false,
            cost_per_1k_micros: cost,
            local: false,
            embeddings: false,
            rerank: true,
            embedding_dims: 0,
        }
    }

    fn provider(http: ReplayClient) -> RerankApiProvider {
        RerankApiProvider::new(
            "cohere-rerank",
            "https://api.cohere.ai",
            Some("k".into()),
            vec![],
            vec![card("rerank-3", 300)],
            Rc::new(http),
            creds(),
        )
    }

    fn req(docs: &[&str]) -> RerankRequest {
        RerankRequest::new(
            Role::Review,
            "the query".into(),
            docs.iter().map(|s| (*s).to_string()).collect(),
            0,
        )
    }

    #[test]
    fn parses_results_and_sorts_by_score() {
        let http = ReplayClient::new(vec![Canned::with_body(
            200,
            r#"{"results":[{"index":0,"relevance_score":0.2},{"index":2,"relevance_score":0.9},{"index":1,"relevance_score":0.5}],"usage":{"prompt_tokens":100}}"#,
        )]);
        let out = provider(http)
            .rerank("rerank-3", &req(&["a", "b", "c"]))
            .unwrap();
        // Sorted by descending score: 2 (0.9), 1 (0.5), 0 (0.2).
        assert_eq!(out.ranking, vec![(2, 0.9), (1, 0.5), (0, 0.2)]);
        assert_eq!(out.usage.input_tokens, 100);
        // cost = 300/1k * 100 = 30
        assert_eq!(out.usage.cost_micros, 30);
    }

    #[test]
    fn out_of_range_and_duplicate_indices_are_dropped_not_propagated() {
        // doc_count = 2, but the provider returns index 5 (out of range) and index 0
        // twice (duplicate) — both sanitized so downstream selection is never
        // corrupted (invariant 7).
        let http = ReplayClient::new(vec![Canned::with_body(
            200,
            r#"{"results":[{"index":5,"relevance_score":0.99},{"index":0,"relevance_score":0.8},{"index":0,"relevance_score":0.7},{"index":1,"relevance_score":0.3}]}"#,
        )]);
        let out = provider(http)
            .rerank("rerank-3", &req(&["a", "b"]))
            .unwrap();
        // Only valid unique indices 0 and 1 survive; index 5 dropped; dup 0 dropped.
        assert_eq!(out.ranking.len(), 2);
        assert!(out.ranking.iter().all(|(i, _)| *i < 2));
        assert!(out.ranking.iter().all(|(_, s)| s.is_finite()));
        // index 0 keeps its FIRST score (0.8); index 1 has 0.3 → 0 ranks first.
        assert_eq!(out.ranking[0], (0, 0.8));
        assert_eq!(out.ranking[1], (1, 0.3));
    }

    #[test]
    fn openai_compatible_data_shape_also_parses() {
        let http = ReplayClient::new(vec![Canned::with_body(
            200,
            r#"{"data":[{"index":1,"relevance_score":0.6},{"index":0,"relevance_score":0.4}]}"#,
        )]);
        let out = provider(http)
            .rerank("rerank-3", &req(&["a", "b"]))
            .unwrap();
        assert_eq!(out.ranking, vec![(1, 0.6), (0, 0.4)]);
    }

    #[test]
    fn rate_limit_is_unavailable() {
        let http = ReplayClient::new(vec![Canned::with_body(503, "overloaded")]);
        let err = provider(http).rerank("rerank-3", &req(&["a"])).unwrap_err();
        assert!(matches!(err, ProviderError::Unavailable(_)));
    }

    #[test]
    fn malformed_json_is_an_error_not_a_panic() {
        let http = ReplayClient::new(vec![Canned::with_body(200, "}{garbage")]);
        let err = provider(http).rerank("rerank-3", &req(&["a"])).unwrap_err();
        assert!(matches!(err, ProviderError::Other(_)));
    }

    #[test]
    fn no_valid_results_is_an_error_not_silent_success() {
        // doc_count = 2 but every returned index is out of range → no valid results.
        let http = ReplayClient::new(vec![Canned::with_body(
            200,
            r#"{"results":[{"index":7,"relevance_score":0.9},{"index":9,"relevance_score":0.8}]}"#,
        )]);
        let err = provider(http)
            .rerank("rerank-3", &req(&["a", "b"]))
            .unwrap_err();
        assert!(matches!(err, ProviderError::Other(_)));
    }

    #[test]
    fn key_never_appears_in_errors() {
        let http = ReplayClient::new(vec![Canned::with_body(
            401,
            r#"{"error":"invalid key sk-SECRET"}"#,
        )]);
        let err = provider(http).rerank("rerank-3", &req(&["a"])).unwrap_err();
        assert!(!format!("{err}").contains("sk-SECRET"));
    }
}
