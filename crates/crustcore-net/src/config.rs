// SPDX-License-Identifier: Apache-2.0
//! Provider configuration the live helper reads at startup (P7-live).
//!
//! The helper learns which providers to instantiate, their base URLs, the
//! **secret-handle label** that authenticates each (never a raw key — only a
//! `secret://`-style handle, resolved by the broker at call time, `docs/secrets.md`),
//! and the model allowlist. The allowlist drives the dynamic registry: a model the
//! operator removes simply stops being offered (invariant 17 — availability is
//! configured/probed, never a permanent hard-coded table).

use crate::ModelCard;

/// Which wire shape a provider speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    /// OpenAI's `/v1/chat/completions` (also serves OpenRouter and local
    /// OpenAI-compatible endpoints like Ollama/vLLM/LM Studio).
    OpenAiCompatible,
    /// Anthropic's `/v1/messages`.
    Anthropic,
}

impl ProviderKind {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "openai" | "openrouter" | "local" | "openai-compatible" => {
                Some(ProviderKind::OpenAiCompatible)
            }
            "anthropic" => Some(ProviderKind::Anthropic),
            _ => None,
        }
    }
}

/// One configured provider.
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    /// Stable provider id (e.g. `openai`, `openrouter`, `anthropic`, `local`).
    pub id: String,
    /// Wire shape.
    pub kind: ProviderKind,
    /// API base URL (no trailing slash), e.g. `https://api.openai.com`.
    pub base_url: String,
    /// The secret-handle label that authenticates this provider, or `None` for a
    /// local endpoint that needs no credential. **Never a raw key.**
    pub secret_label: Option<String>,
    /// Extra static headers (e.g. OpenRouter's `HTTP-Referer` / `X-Title`).
    pub extra_headers: Vec<(String, String)>,
    /// The model allowlist (each becomes a registry [`ModelCard`]).
    pub models: Vec<ModelCard>,
}

/// Parses a provider config from JSON: an array of provider objects. Example:
/// ```json
/// [{ "id":"openai", "kind":"openai", "base_url":"https://api.openai.com",
///    "secret_label":"openai-key",
///    "models":[{"model":"gpt-x","context":128000,"tools":true,"streaming":true,
///               "cost_per_1k_micros":15000}] }]
/// ```
/// Missing optional fields take conservative defaults (invariant 17: unknown
/// capabilities default to *off*, never optimistically assumed).
///
/// # Errors
/// A human-readable message if the JSON is malformed or a required field is missing.
pub fn parse_providers(json: &str) -> Result<Vec<ProviderConfig>, String> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("invalid provider config JSON: {e}"))?;
    let arr = value
        .as_array()
        .ok_or_else(|| "provider config must be a JSON array".to_string())?;

    let mut out = Vec::new();
    for (i, p) in arr.iter().enumerate() {
        let id = str_field(p, "id").ok_or_else(|| format!("provider[{i}]: missing `id`"))?;
        let kind_s =
            str_field(p, "kind").ok_or_else(|| format!("provider[{i}] ({id}): missing `kind`"))?;
        let kind = ProviderKind::parse(&kind_s)
            .ok_or_else(|| format!("provider[{i}] ({id}): unknown kind `{kind_s}`"))?;
        let base_url = str_field(p, "base_url")
            .ok_or_else(|| format!("provider[{i}] ({id}): missing `base_url`"))?;
        let base_url = base_url.trim_end_matches('/').to_string();
        let secret_label = str_field(p, "secret_label");
        let local = kind == ProviderKind::OpenAiCompatible && secret_label.is_none();

        let extra_headers = p
            .get("extra_headers")
            .and_then(|h| h.as_object())
            .map(|obj| {
                obj.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();

        let models_v = p
            .get("models")
            .and_then(|m| m.as_array())
            .ok_or_else(|| format!("provider[{i}] ({id}): missing `models` array"))?;
        let mut models = Vec::new();
        for (j, m) in models_v.iter().enumerate() {
            let model = str_field(m, "model")
                .ok_or_else(|| format!("provider[{i}] ({id}) model[{j}]: missing `model`"))?;
            models.push(ModelCard {
                model,
                healthy: true,
                context: u32_field(m, "context", 8_000),
                tools: bool_field(m, "tools", false),
                structured: bool_field(m, "structured", false),
                streaming: bool_field(m, "streaming", true),
                cost_per_1k_micros: u64_field(m, "cost_per_1k_micros", 0),
                local,
            });
        }
        if models.is_empty() {
            return Err(format!("provider[{i}] ({id}): empty `models` allowlist"));
        }

        out.push(ProviderConfig {
            id,
            kind,
            base_url,
            secret_label,
            extra_headers,
            models,
        });
    }
    Ok(out)
}

fn str_field(v: &serde_json::Value, key: &str) -> Option<String> {
    v.get(key).and_then(|x| x.as_str()).map(str::to_string)
}
fn u32_field(v: &serde_json::Value, key: &str, default: u32) -> u32 {
    v.get(key)
        .and_then(serde_json::Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or(default)
}
fn u64_field(v: &serde_json::Value, key: &str, default: u64) -> u64 {
    v.get(key)
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(default)
}
fn bool_field(v: &serde_json::Value, key: &str, default: bool) -> bool {
    v.get(key)
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_mixed_provider_config() {
        let json = r#"[
          { "id":"openai", "kind":"openai", "base_url":"https://api.openai.com/",
            "secret_label":"openai-key",
            "models":[{"model":"gpt-x","context":128000,"tools":true,"streaming":true,"cost_per_1k_micros":15000}] },
          { "id":"anthropic", "kind":"anthropic", "base_url":"https://api.anthropic.com",
            "secret_label":"anthropic-key",
            "models":[{"model":"claude-x","context":200000,"tools":true,"streaming":true,"cost_per_1k_micros":12000}] },
          { "id":"local", "kind":"local", "base_url":"http://localhost:11434",
            "models":[{"model":"llama","context":16000}] }
        ]"#;
        let cfg = parse_providers(json).unwrap();
        assert_eq!(cfg.len(), 3);
        assert_eq!(cfg[0].kind, ProviderKind::OpenAiCompatible);
        assert_eq!(cfg[0].base_url, "https://api.openai.com"); // trailing slash trimmed
        assert_eq!(cfg[0].secret_label.as_deref(), Some("openai-key"));
        assert_eq!(cfg[1].kind, ProviderKind::Anthropic);
        // The local endpoint has no secret and its model is marked local.
        assert!(cfg[2].secret_label.is_none());
        assert!(cfg[2].models[0].local);
        // Unspecified caps default conservatively (tools off).
        assert!(!cfg[2].models[0].tools);
    }

    #[test]
    fn rejects_malformed_or_incomplete_config() {
        assert!(parse_providers("not json").is_err());
        assert!(parse_providers("{}").is_err()); // not an array
        assert!(parse_providers(r#"[{"id":"x"}]"#).is_err()); // missing kind
        assert!(parse_providers(
            r#"[{"id":"x","kind":"bogus","base_url":"u","models":[{"model":"m"}]}]"#
        )
        .is_err());
        assert!(
            parse_providers(r#"[{"id":"x","kind":"openai","base_url":"u","models":[]}]"#).is_err()
        );
    }
}
