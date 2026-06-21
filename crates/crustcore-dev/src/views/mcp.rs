// SPDX-License-Identifier: Apache-2.0
//! MCP registry UI (`C7.5`). Read-only over the registry.
//!
//! Lists registered servers, their `tool_policies`-derived gate decisions, and their
//! `manifest_hash`-drift status. The gate decision comes from the registry's
//! [`gateway_check`](crustcore_mcp::gateway_check) over the server's
//! [`McpToolPolicy`](crustcore_mcp::McpToolPolicy) entries — **never** the server's own
//! self-description. Every string is redacted before render (dimension (e)).

use crate::backend::McpServerView;
use crustcore_mcp::{gateway_check, GatewayDecision, McpRegistry, McpServerRecord};
use crustcore_secrets::Redactor;

/// Pass-through redaction of pre-built MCP views (the mock path supplies these).
#[must_use]
pub fn render(servers: &[McpServerView], redactor: &Redactor) -> Vec<McpServerView> {
    servers
        .iter()
        .map(|s| McpServerView {
            server_id: s.server_id,
            source: redactor.redact(&s.source),
            manifest_intact: s.manifest_intact,
            tool_decisions: s
                .tool_decisions
                .iter()
                .map(|(t, d)| (redactor.redact(t), d.clone()))
                .collect(),
        })
        .collect()
}

/// Build a view from a real [`McpServerRecord`] in a [`McpRegistry`]. The gate decision
/// for each policied tool is computed by [`gateway_check`] against the registry — driven
/// by `tool_policies` and the manifest-drift check, never the server's self-description.
/// `live_manifest_hash` is the hash observed from the live transport (the drift input);
/// `repo` is the repo the decisions are evaluated for.
#[must_use]
pub fn from_record(
    registry: &McpRegistry,
    record: &McpServerRecord,
    repo: &str,
    live_manifest_hash: Option<[u8; 32]>,
    redactor: &Redactor,
) -> McpServerView {
    let manifest_intact = match (record.manifest_hash, live_manifest_hash) {
        (Some(registered), Some(live)) => registered == live,
        // No live observation yet (or none registered): treat as not-yet-drifted.
        _ => true,
    };

    let tool_decisions = record
        .tool_policies
        .iter()
        .map(|policy| {
            // The decision is the registry's gateway verdict — NOT the server's claim.
            let decision =
                gateway_check(registry, record.id, &policy.tool, repo, live_manifest_hash);
            (redactor.redact(&policy.tool), decision_label(&decision))
        })
        .collect();

    McpServerView {
        server_id: record.id.0,
        source: redactor.redact(&source_label(record)),
        manifest_intact,
        tool_decisions,
    }
}

fn decision_label(d: &GatewayDecision) -> String {
    match d {
        GatewayDecision::Allow => "allow".to_string(),
        GatewayDecision::Ask => "ask".to_string(),
        GatewayDecision::Deny(reason) => format!("deny ({reason:?})"),
    }
}

fn source_label(record: &McpServerRecord) -> String {
    use crustcore_mcp::McpServerSource;
    match &record.source {
        McpServerSource::LocalBinary(p) => format!("local:{p}"),
        McpServerSource::RemoteUrl(u) => format!("remote:{u}"),
        McpServerSource::Package(p) => format!("package:{p}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crustcore_mcp::{
        McpAuthMode, McpServerId, McpServerSource, McpToolPolicy, McpTransport, ToolDecision,
        TrustLevel,
    };
    use crustcore_types::{sha256, BoundedText, RepoRef};

    fn record() -> McpServerRecord {
        McpServerRecord {
            id: McpServerId(1),
            source: McpServerSource::LocalBinary("/usr/bin/some-mcp".into()),
            transport: McpTransport::Stdio,
            version: Some("1.0".into()),
            manifest_hash: Some(sha256(b"tool surface v1")),
            auth: McpAuthMode::None,
            trust_level: TrustLevel::SemiTrusted,
            allowed_repos: vec![RepoRef(BoundedText::truncated("RNT56/CrustCore", 64))],
            tool_policies: vec![
                McpToolPolicy {
                    tool: "search".into(),
                    decision: ToolDecision::Allow,
                },
                McpToolPolicy {
                    tool: "write_file".into(),
                    decision: ToolDecision::Ask,
                },
                McpToolPolicy {
                    tool: "rm_rf".into(),
                    decision: ToolDecision::Deny,
                },
            ],
        }
    }

    #[test]
    fn gate_decisions_come_from_tool_policies() {
        let rec = record();
        let mut registry = McpRegistry::new();
        registry.register(rec.clone());
        let redactor = Redactor::new();
        let view = from_record(
            &registry,
            &rec,
            "RNT56/CrustCore",
            Some(sha256(b"tool surface v1")),
            &redactor,
        );
        assert!(view.manifest_intact);
        let map: std::collections::BTreeMap<_, _> = view.tool_decisions.into_iter().collect();
        assert_eq!(map.get("search").map(String::as_str), Some("allow"));
        assert_eq!(map.get("write_file").map(String::as_str), Some("ask"));
        assert!(map.get("rm_rf").unwrap().starts_with("deny"));
    }

    #[test]
    fn manifest_drift_is_detected_and_denies_all() {
        let rec = record();
        let mut registry = McpRegistry::new();
        registry.register(rec.clone());
        let redactor = Redactor::new();
        // Live hash differs -> drift -> the gateway denies regardless of tool policy.
        let view = from_record(
            &registry,
            &rec,
            "RNT56/CrustCore",
            Some(sha256(b"DRIFTED surface")),
            &redactor,
        );
        assert!(!view.manifest_intact);
        for (_tool, decision) in &view.tool_decisions {
            assert!(
                decision.starts_with("deny"),
                "drift must force deny, got {decision}"
            );
        }
    }
}
