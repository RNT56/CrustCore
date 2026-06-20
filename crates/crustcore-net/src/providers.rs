// SPDX-License-Identifier: Apache-2.0
//! Live provider adapters (P7-live): real `Provider` impls over the [`HttpClient`]
//! transport boundary. One [`OpenAiProvider`] shape serves OpenAI, OpenRouter, and
//! local OpenAI-compatible endpoints (Ollama / vLLM / LM Studio); [`AnthropicProvider`]
//! serves the Anthropic Messages API.
//!
//! All parse / map / stream logic here is **transport-agnostic** and fully tested in
//! CI with [`ReplayClient`](crate::transport::ReplayClient) — no network. The real
//! socket lives only in `UreqClient` (the `live` feature). Three properties are
//! load-bearing and preserved exactly as `MockProvider` establishes them:
//!
//! 1. **Success-path-only streaming.** A request that fails emits **zero** chunks to
//!    the `sink` (the transport never calls `on_line` for a non-2xx response), so
//!    `run_reliable` never leaks a failed provider's partial output before falling
//!    back.
//! 2. **No-secret-to-anywhere-but-the-request.** The credential is resolved per call
//!    via [`CredentialSource`], assembled into a header, and consumed into the
//!    request — never stored on the adapter, never in an error string, never logged.
//! 3. **Bounded + no-panic.** Every response is bounded; malformed / truncated /
//!    non-UTF8 SSE is skipped, never panicked on (invariant 7: provider output is
//!    untrusted data).

use std::rc::Rc;

use crustcore_netproto::{CompleteRequest, Usage};

use crate::credsource::{AuthStyle, CredentialSource};
use crate::transport::HttpClient;
use crate::{Completion, ModelCard, Provider, ProviderError};

/// Extracts the payload of an SSE `data:` line, or `None` for a non-data /
/// terminator line. `data: [DONE]` and blank payloads return `None`.
fn sse_data(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("data:")?.trim_start();
    if rest.is_empty() || rest == "[DONE]" {
        None
    } else {
        Some(rest)
    }
}

/// Maps a non-2xx HTTP status + error body to a typed [`ProviderError`]. Rate limits
/// / server errors / overload → `Unavailable` (drives fallback); a context-length
/// rejection → `Capability`; everything else → `Other`.
fn map_status_error(status: u16, body: &str) -> ProviderError {
    let lower = body.to_ascii_lowercase();
    let context_overflow = lower.contains("context")
        || lower.contains("maximum context")
        || lower.contains("too long")
        || lower.contains("too many tokens")
        || lower.contains("max_tokens");
    if status == 429 || (500..600).contains(&status) || lower.contains("overloaded") {
        ProviderError::Unavailable(format!("http {status}"))
    } else if (status == 400 || status == 413) && context_overflow {
        ProviderError::Capability(format!("http {status}: context"))
    } else {
        ProviderError::Other(format!("http {status}"))
    }
}

/// Rough token estimate (~4 chars/token) for when a provider omits usage.
fn est_tokens(s: &str) -> u32 {
    (s.len() / 4 + 1) as u32
}

/// Builds the JSON request `messages`/`content` shared by the OpenAI shape.
fn openai_body(model: &str, req: &CompleteRequest) -> Vec<u8> {
    let mut messages = Vec::new();
    let system = req.system.as_str();
    if !system.is_empty() {
        messages.push(serde_json::json!({ "role": "system", "content": system }));
    }
    messages.push(serde_json::json!({ "role": "user", "content": req.prompt.as_str() }));
    let body = serde_json::json!({
        "model": model,
        "messages": messages,
        "max_tokens": req.max_tokens,
        "stream": true,
        "stream_options": { "include_usage": true },
    });
    serde_json::to_vec(&body).unwrap_or_default()
}

/// Shared per-adapter fields.
struct Common {
    id: String,
    base_url: String,
    secret_label: Option<String>,
    extra_headers: Vec<(String, String)>,
    cards: Vec<ModelCard>,
    http: Rc<dyn HttpClient>,
    creds: Rc<dyn CredentialSource>,
}

impl Common {
    /// The base headers for a request: content-type, extras, and (if a secret label
    /// is configured) a freshly resolved auth header. The auth header is built per
    /// call and dropped with the returned Vec — never stored.
    fn headers(&self, style: AuthStyle) -> Vec<(String, String)> {
        let mut h = vec![("Content-Type".to_string(), "application/json".to_string())];
        h.extend(self.extra_headers.iter().cloned());
        if let Some(label) = &self.secret_label {
            if let Some(auth) = self.creds.header_for(label, style) {
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

// ---------------------------------------------------------------------------
// OpenAI-compatible adapter (OpenAI / OpenRouter / local)
// ---------------------------------------------------------------------------

/// An OpenAI-compatible provider (`/v1/chat/completions`).
pub struct OpenAiProvider {
    common: Common,
}

impl OpenAiProvider {
    /// Builds an adapter from its config pieces + shared transport/credential source.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        base_url: impl Into<String>,
        secret_label: Option<String>,
        extra_headers: Vec<(String, String)>,
        cards: Vec<ModelCard>,
        http: Rc<dyn HttpClient>,
        creds: Rc<dyn CredentialSource>,
    ) -> Self {
        OpenAiProvider {
            common: Common {
                id: id.into(),
                base_url: base_url.into(),
                secret_label,
                extra_headers,
                cards,
                http,
                creds,
            },
        }
    }
}

impl Provider for OpenAiProvider {
    fn id(&self) -> &str {
        &self.common.id
    }

    fn probe(&self) -> Vec<ModelCard> {
        // The configured allowlist is the dynamic registry (invariant 17): a model
        // the operator removes simply stops being offered. (A live `/v1/models`
        // reachability filter is a refinement; the allowlist is the source of truth.)
        self.common.cards.clone()
    }

    fn complete(
        &self,
        model: &str,
        req: &CompleteRequest,
        sink: &mut dyn FnMut(&str),
    ) -> Result<Completion, ProviderError> {
        let url = format!("{}/v1/chat/completions", self.common.base_url);
        let headers = self.common.headers(AuthStyle::Bearer);
        let body = openai_body(model, req);

        let mut text = String::new();
        let mut usage: Option<Usage> = None;
        let mut on_line = |line: &str| {
            let Some(data) = sse_data(line) else { return };
            let Ok(v) = serde_json::from_str::<serde_json::Value>(data) else {
                return; // malformed SSE chunk → skip (untrusted data, no panic)
            };
            if let Some(delta) = v["choices"][0]["delta"]["content"].as_str() {
                if !delta.is_empty() {
                    text.push_str(delta);
                    sink(delta);
                }
            }
            if let Some(u) = v.get("usage").filter(|u| !u.is_null()) {
                usage = Some(Usage {
                    input_tokens: u["prompt_tokens"].as_u64().unwrap_or(0) as u32,
                    output_tokens: u["completion_tokens"].as_u64().unwrap_or(0) as u32,
                    cost_micros: 0,
                });
            }
        };

        let resp = self
            .common
            .http
            .post_lines(&url, &headers, &body, &mut on_line)
            .map_err(|e| ProviderError::Unavailable(e.to_string()))?;

        if !resp.is_success() {
            // on_line was never called for a non-2xx response → nothing was emitted.
            return Err(map_status_error(resp.status, &resp.body));
        }

        Ok(self.common.finish(model, req, text, usage))
    }
}

// ---------------------------------------------------------------------------
// Anthropic adapter (Messages API)
// ---------------------------------------------------------------------------

/// The Anthropic Messages provider (`/v1/messages`).
pub struct AnthropicProvider {
    common: Common,
    version: String,
}

impl AnthropicProvider {
    /// Builds an Anthropic adapter. `version` is the `anthropic-version` header.
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        base_url: impl Into<String>,
        secret_label: Option<String>,
        version: impl Into<String>,
        cards: Vec<ModelCard>,
        http: Rc<dyn HttpClient>,
        creds: Rc<dyn CredentialSource>,
    ) -> Self {
        AnthropicProvider {
            common: Common {
                id: id.into(),
                base_url: base_url.into(),
                secret_label,
                extra_headers: Vec::new(),
                cards,
                http,
                creds,
            },
            version: version.into(),
        }
    }
}

impl Provider for AnthropicProvider {
    fn id(&self) -> &str {
        &self.common.id
    }

    fn probe(&self) -> Vec<ModelCard> {
        self.common.cards.clone()
    }

    fn complete(
        &self,
        model: &str,
        req: &CompleteRequest,
        sink: &mut dyn FnMut(&str),
    ) -> Result<Completion, ProviderError> {
        let url = format!("{}/v1/messages", self.common.base_url);
        let mut headers = self.common.headers(AuthStyle::XApiKey);
        headers.push(("anthropic-version".to_string(), self.version.clone()));

        let body = serde_json::to_vec(&serde_json::json!({
            "model": model,
            "system": req.system.as_str(),
            "messages": [{ "role": "user", "content": req.prompt.as_str() }],
            "max_tokens": req.max_tokens,
            "stream": true,
        }))
        .unwrap_or_default();

        let mut text = String::new();
        let mut input_tokens = 0u32;
        let mut output_tokens = 0u32;
        let mut on_line = |line: &str| {
            let Some(data) = sse_data(line) else { return };
            let Ok(v) = serde_json::from_str::<serde_json::Value>(data) else {
                return;
            };
            match v["type"].as_str() {
                Some("content_block_delta") => {
                    if let Some(delta) = v["delta"]["text"].as_str() {
                        if !delta.is_empty() {
                            text.push_str(delta);
                            sink(delta);
                        }
                    }
                }
                Some("message_start") => {
                    if let Some(n) = v["message"]["usage"]["input_tokens"].as_u64() {
                        input_tokens = n as u32;
                    }
                }
                Some("message_delta") => {
                    if let Some(n) = v["usage"]["output_tokens"].as_u64() {
                        output_tokens = n as u32;
                    }
                }
                _ => {}
            }
        };

        let resp = self
            .common
            .http
            .post_lines(&url, &headers, &body, &mut on_line)
            .map_err(|e| ProviderError::Unavailable(e.to_string()))?;

        if !resp.is_success() {
            return Err(map_status_error(resp.status, &resp.body));
        }

        // If the provider reported no output usage but text WAS produced — e.g. a
        // stream truncated (network drop or `MAX_BODY_BYTES` cap) after some
        // `content_block_delta`s but before the `message_delta` that carries output
        // usage — estimate the output from the text so a produced completion is never
        // recorded as zero cost (invariant 11). Mirrors the OpenAI missing-usage path.
        let output_tokens = if output_tokens == 0 && !text.is_empty() {
            est_tokens(&text)
        } else {
            output_tokens
        };
        let usage = if input_tokens > 0 || output_tokens > 0 {
            Some(Usage {
                input_tokens,
                output_tokens,
                cost_micros: 0,
            })
        } else {
            None
        };
        Ok(self.common.finish(model, req, text, usage))
    }
}

impl Common {
    /// Assembles the final [`Completion`]: fills/estimates usage and computes cost
    /// from the model's configured price.
    fn finish(
        &self,
        model: &str,
        req: &CompleteRequest,
        text: String,
        usage: Option<Usage>,
    ) -> Completion {
        let mut usage = usage.unwrap_or(Usage {
            input_tokens: est_tokens(req.prompt.as_str()) + est_tokens(req.system.as_str()),
            output_tokens: est_tokens(&text),
            cost_micros: 0,
        });
        usage.cost_micros = self
            .card_cost(model)
            .saturating_mul(u64::from(usage.output_tokens))
            / 1000;
        Completion { text, usage }
    }
}

/// Builds the live `Provider` set from a config over a shared transport + credential
/// source. Always compiled (the transport is injected), so the engine-level routing
/// and cross-adapter fallback are testable in CI with a
/// [`ReplayClient`](crate::transport::ReplayClient); the `live` helper passes a real
/// `UreqClient` instead (see [`crate::live_engine`], `live` feature).
#[must_use]
pub fn build_providers(
    configs: &[crate::config::ProviderConfig],
    http: Rc<dyn HttpClient>,
    creds: Rc<dyn CredentialSource>,
) -> Vec<Box<dyn Provider>> {
    use crate::config::ProviderKind;
    let mut providers: Vec<Box<dyn Provider>> = Vec::new();
    for cfg in configs {
        match cfg.kind {
            ProviderKind::OpenAiCompatible => providers.push(Box::new(OpenAiProvider::new(
                cfg.id.clone(),
                cfg.base_url.clone(),
                cfg.secret_label.clone(),
                cfg.extra_headers.clone(),
                cfg.models.clone(),
                http.clone(),
                creds.clone(),
            ))),
            ProviderKind::Anthropic => providers.push(Box::new(AnthropicProvider::new(
                cfg.id.clone(),
                cfg.base_url.clone(),
                cfg.secret_label.clone(),
                "2023-06-01",
                cfg.models.clone(),
                http.clone(),
                creds.clone(),
            ))),
        }
    }
    providers
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{Canned, ReplayClient};
    use crustcore_netproto::{Require, Role, MAX_TEXT_BYTES};
    use crustcore_types::BoundedText;

    fn req(prompt: &str) -> CompleteRequest {
        CompleteRequest {
            role: Role::Implementation,
            system: BoundedText::truncated("be terse", MAX_TEXT_BYTES),
            prompt: BoundedText::truncated(prompt, MAX_TEXT_BYTES),
            max_tokens: 64,
            stream: true,
            max_cost_micros: 0,
            require: Require::default(),
        }
    }

    fn card(model: &str, cost: u64) -> ModelCard {
        ModelCard {
            model: model.into(),
            healthy: true,
            context: 128_000,
            tools: true,
            structured: false,
            streaming: true,
            cost_per_1k_micros: cost,
            local: false,
        }
    }

    fn creds() -> Rc<dyn CredentialSource> {
        Rc::new(crate::credsource::StaticCredentials::new().with("k", "sk-SECRET"))
    }

    fn openai(http: ReplayClient) -> OpenAiProvider {
        OpenAiProvider::new(
            "openai",
            "https://api.openai.com",
            Some("k".into()),
            vec![],
            vec![card("gpt-x", 15_000)],
            Rc::new(http),
            creds(),
        )
    }

    #[test]
    fn openai_streams_concatenates_and_parses_usage_and_cost() {
        let http = ReplayClient::new(vec![Canned::streaming(&[
            r#"data: {"choices":[{"delta":{"content":"Hel"}}]}"#,
            r#"data: {"choices":[{"delta":{"content":"lo"}}]}"#,
            r#"data: {"choices":[{"delta":{}}],"usage":{"prompt_tokens":10,"completion_tokens":2000}}"#,
            "data: [DONE]",
        ])]);
        let p = openai(http);
        let mut streamed = String::new();
        let out = p
            .complete("gpt-x", &req("hi"), &mut |c| streamed.push_str(c))
            .unwrap();
        // Streamed chunks concatenate to the final text.
        assert_eq!(out.text, "Hello");
        assert_eq!(streamed, "Hello");
        // Usage parsed; cost = 15000/1k * 2000 = 30000 micros.
        assert_eq!(out.usage.input_tokens, 10);
        assert_eq!(out.usage.output_tokens, 2000);
        assert_eq!(out.usage.cost_micros, 30_000);
    }

    #[test]
    fn openai_429_is_unavailable_and_emits_nothing() {
        let http = ReplayClient::new(vec![Canned::with_body(429, "rate limited")]);
        let p = openai(http);
        let mut streamed = String::new();
        let err = p
            .complete("gpt-x", &req("hi"), &mut |c| streamed.push_str(c))
            .unwrap_err();
        assert!(matches!(err, ProviderError::Unavailable(_)));
        assert!(streamed.is_empty(), "a failing request must emit no chunks");
    }

    #[test]
    fn openai_context_overflow_is_capability() {
        let http = ReplayClient::new(vec![Canned::with_body(
            400,
            r#"{"error":{"message":"maximum context length exceeded"}}"#,
        )]);
        let err = openai(http)
            .complete("gpt-x", &req("hi"), &mut |_| {})
            .unwrap_err();
        assert!(matches!(err, ProviderError::Capability(_)));
    }

    #[test]
    fn openai_skips_malformed_sse_without_panic() {
        let http = ReplayClient::new(vec![Canned::streaming(&[
            "garbage not sse",
            "data: {not json",
            r#"data: {"choices":[{"delta":{"content":"ok"}}]}"#,
            "data:",
        ])]);
        let out = openai(http)
            .complete("gpt-x", &req("hi"), &mut |_| {})
            .unwrap();
        assert_eq!(out.text, "ok"); // only the valid delta survives; no panic
    }

    #[test]
    fn openai_missing_usage_is_estimated() {
        let http = ReplayClient::new(vec![Canned::streaming(&[
            r#"data: {"choices":[{"delta":{"content":"hello world"}}]}"#,
            "data: [DONE]",
        ])]);
        let out = openai(http)
            .complete("gpt-x", &req("hi"), &mut |_| {})
            .unwrap();
        assert!(out.usage.output_tokens > 0); // estimated, not zero
    }

    #[test]
    fn anthropic_streams_and_parses_usage() {
        let http = ReplayClient::new(vec![Canned::streaming(&[
            r#"data: {"type":"message_start","message":{"usage":{"input_tokens":12}}}"#,
            r#"data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Hi "}}"#,
            r#"data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"there"}}"#,
            r#"data: {"type":"message_delta","usage":{"output_tokens":3000}}"#,
        ])]);
        let p = AnthropicProvider::new(
            "anthropic",
            "https://api.anthropic.com",
            Some("k".into()),
            "2023-06-01",
            vec![card("claude-x", 12_000)],
            Rc::new(http),
            creds(),
        );
        let mut streamed = String::new();
        let out = p
            .complete("claude-x", &req("hi"), &mut |c| streamed.push_str(c))
            .unwrap();
        assert_eq!(out.text, "Hi there");
        assert_eq!(streamed, "Hi there");
        assert_eq!(out.usage.input_tokens, 12);
        assert_eq!(out.usage.output_tokens, 3000);
        assert_eq!(out.usage.cost_micros, 36_000); // 12000/1k * 3000
    }

    #[test]
    fn anthropic_truncated_stream_estimates_output_so_cost_is_not_zero() {
        // A stream cut off after content deltas but BEFORE `message_delta` (the
        // output-usage event): text was produced but no output usage arrived. The
        // adapter must estimate the output, never charge zero for produced text.
        let http = ReplayClient::new(vec![Canned::streaming(&[
            r#"data: {"type":"message_start","message":{"usage":{"input_tokens":7}}}"#,
            r#"data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"some real output text"}}"#,
            // ... stream truncated here: no message_delta with output_tokens.
        ])]);
        let p = AnthropicProvider::new(
            "anthropic",
            "https://api.anthropic.com",
            Some("k".into()),
            "2023-06-01",
            vec![card("claude-x", 12_000)],
            Rc::new(http),
            creds(),
        );
        let out = p.complete("claude-x", &req("hi"), &mut |_| {}).unwrap();
        assert_eq!(out.text, "some real output text");
        assert!(
            out.usage.output_tokens > 0,
            "produced output must be estimated"
        );
        assert!(
            out.usage.cost_micros > 0,
            "produced output must not be billed as zero"
        );
    }

    #[test]
    fn anthropic_overloaded_is_unavailable() {
        let http = ReplayClient::new(vec![Canned::with_body(
            529,
            r#"{"type":"error","error":{"type":"overloaded_error"}}"#,
        )]);
        let p = AnthropicProvider::new(
            "anthropic",
            "https://api.anthropic.com",
            Some("k".into()),
            "2023-06-01",
            vec![card("claude-x", 12_000)],
            Rc::new(http),
            creds(),
        );
        assert!(matches!(
            p.complete("claude-x", &req("hi"), &mut |_| {}).unwrap_err(),
            ProviderError::Unavailable(_)
        ));
    }

    #[test]
    fn auth_header_is_sent_but_key_never_appears_in_text_or_errors() {
        // Success path: the key is used for auth but never echoed into the output.
        let http = ReplayClient::new(vec![Canned::streaming(&[
            r#"data: {"choices":[{"delta":{"content":"ok"}}]}"#,
        ])]);
        let out = openai(http)
            .complete("gpt-x", &req("hi"), &mut |_| {})
            .unwrap();
        assert!(!out.text.contains("sk-SECRET"));
        // Error path: a 401 body echoing the key must not surface it in ProviderError.
        let http = ReplayClient::new(vec![Canned::with_body(
            401,
            r#"{"error":"invalid key sk-SECRET"}"#,
        )]);
        let err = openai(http)
            .complete("gpt-x", &req("hi"), &mut |_| {})
            .unwrap_err();
        // We map to a status-only error; we do not include the provider body verbatim.
        assert!(!format!("{err}").contains("sk-SECRET"));
    }
}
