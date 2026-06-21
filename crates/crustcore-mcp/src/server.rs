// SPDX-License-Identifier: Apache-2.0
//! MCP **server** mode (B1-mcp-modes): CrustCore exposes a *curated* set of its own
//! capabilities to other MCP clients — the inverse of the gateway, which gates CrustCore
//! *calling* other servers (`crate::call_tool`).
//!
//! Trust direction flips, but the posture is the same. Here an **inbound request is
//! untrusted** (invariant 7): a client can invoke only a tool CrustCore explicitly
//! [`expose`](McpServer::expose)d, and only when its policy is `Allow` — there is
//! deliberately **no** exposed-tool variant for a secret, an approval, or a kernel
//! mutation, so a hostile client cannot escalate to one (invariants 4, 8). The
//! capability's output is **redacted** before it leaves CrustCore (invariant 2 — a
//! client never receives a CrustCore secret), **bounded** (invariant 11), and
//! **receipted** (invariant 10 — every served call is an auditable record).
//!
//! This module is the std-only request/policy/redaction/receipt core, CI-tested by
//! feeding it canned JSON-RPC requests (a "mock peer"). The live serving transport
//! (listening on stdio/HTTP, reusing the P13 [`crate::transport`]) is
//! `TODO(B1-mcp-modes-live)`.

use std::collections::BTreeMap;

use crustcore_receipts::{ReceiptChain, ReceiptParams};
use crustcore_secrets::Redactor;
use crustcore_types::hash::sha256;
use crustcore_types::{ArtifactId, BoundedText};

use crate::{McpCallIds, ToolDecision, MAX_MCP_SUMMARY};

/// JSON-RPC error code: the requested method is not supported by the server.
pub const ERR_METHOD_NOT_FOUND: i64 = -32601;
/// JSON-RPC error code (server-defined): the tool is not in the exposed, curated set.
pub const ERR_TOOL_NOT_EXPOSED: i64 = -32001;
/// JSON-RPC error code (server-defined): the tool's policy is `Deny`.
pub const ERR_TOOL_DENIED: i64 = -32002;
/// JSON-RPC error code (server-defined): the tool's policy is `Ask` — a CrustCore
/// approval is required out of band before the client may call it.
pub const ERR_TOOL_NEEDS_APPROVAL: i64 = -32003;
/// JSON-RPC error code (server-defined): the curated tool's handler failed.
pub const ERR_TOOL_FAILED: i64 = -32004;

/// One capability CrustCore exposes to MCP clients. The exposed **set** is curated and
/// typed: a tool is just a name + (bounded) description + a [`ToolDecision`]. There is no
/// field by which a client could reach a secret, an approval, or a kernel internal — the
/// only things callable are the ones CrustCore deliberately added.
#[derive(Debug, Clone)]
pub struct ExposedTool {
    /// The tool name clients call.
    pub name: String,
    /// A bounded description shown to clients (`tools/list`).
    pub description: String,
    /// The policy for this tool (`Allow` runs; `Ask` needs approval; `Deny` refuses).
    pub decision: ToolDecision,
}

/// Executes a curated, already-policy-checked tool. The live implementation runs a
/// CrustCore capability (e.g. `verify`, `inspect`); a mock drives CI. The output is
/// CrustCore's own, but is still redacted + bounded by [`McpServer`] before it reaches
/// the client — the handler need not redact.
///
/// The handler is only ever invoked for a tool that is **exposed and `Allow`** — the
/// server gates first, so a handler never sees a denied or non-curated request.
pub trait ToolHandler {
    /// Runs `tool` with the (untrusted, canonical) `args` bytes, returning raw output.
    ///
    /// # Errors
    /// A bounded reason string if the capability could not run.
    fn execute(&self, tool: &str, args: &[u8]) -> Result<Vec<u8>, String>;
}

/// The MCP server: a curated tool surface plus a JSON-RPC request handler. Empty by
/// default — nothing is exposed until [`expose`](Self::expose) adds it.
#[derive(Debug, Default)]
pub struct McpServer {
    tools: BTreeMap<String, ExposedTool>,
}

impl McpServer {
    /// A server exposing nothing.
    #[must_use]
    pub fn new() -> Self {
        McpServer {
            tools: BTreeMap::new(),
        }
    }

    /// Adds a curated tool to the exposed surface.
    pub fn expose(&mut self, tool: ExposedTool) {
        self.tools.insert(tool.name.clone(), tool);
    }

    /// The policy decision for `tool`, or `None` if it is not exposed (an unexposed tool
    /// is **refused** — there is no implicit exposure).
    #[must_use]
    pub fn decision(&self, tool: &str) -> Option<ToolDecision> {
        self.tools.get(tool).map(|t| t.decision)
    }

    /// Handles one (untrusted) inbound JSON-RPC request, returning the response value.
    /// Dispatches `initialize` / `tools/list` / `tools/call`; any other method is a
    /// `method not found` error. A `tools/call` is gated against the curated set + policy
    /// before the handler runs, then its output is redacted, bounded, and receipted.
    #[must_use]
    pub fn handle_request(
        &self,
        request: &serde_json::Value,
        handler: &dyn ToolHandler,
        redactor: &Redactor,
        receipts: &mut ReceiptChain,
        ids: &McpCallIds,
    ) -> serde_json::Value {
        let id = request
            .get("id")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");
        match method {
            "initialize" => rpc_result(
                id,
                serde_json::json!({
                    "protocolVersion": "2024-11-05",
                    "serverInfo": { "name": "crustcore", "version": env!("CARGO_PKG_VERSION") },
                    "capabilities": { "tools": {} }
                }),
            ),
            "tools/list" => rpc_result(id, self.tools_list()),
            "tools/call" => self.handle_call(id, request, handler, redactor, receipts, ids),
            _ => rpc_error(id, ERR_METHOD_NOT_FOUND, "method not found"),
        }
    }

    fn tools_list(&self) -> serde_json::Value {
        let tools: Vec<serde_json::Value> = self
            .tools
            .values()
            .map(|t| {
                serde_json::json!({
                    "name": t.name,
                    // Bound the description so the server's own surface stays bounded too.
                    "description": BoundedText::truncated(t.description.as_str(), MAX_MCP_SUMMARY)
                        .as_str(),
                })
            })
            .collect();
        serde_json::json!({ "tools": tools })
    }

    fn handle_call(
        &self,
        id: serde_json::Value,
        request: &serde_json::Value,
        handler: &dyn ToolHandler,
        redactor: &Redactor,
        receipts: &mut ReceiptChain,
        ids: &McpCallIds,
    ) -> serde_json::Value {
        let params = request.get("params");
        let Some(tool) = params.and_then(|p| p.get("name")).and_then(|n| n.as_str()) else {
            return rpc_error(id, ERR_TOOL_NOT_EXPOSED, "missing tool name");
        };
        // Gate FIRST: the request is untrusted (invariant 7). Only a curated, Allow tool
        // ever reaches the handler — Deny/Ask/unknown short-circuit here.
        match self.decision(tool) {
            None => return rpc_error(id, ERR_TOOL_NOT_EXPOSED, "tool not exposed"),
            Some(ToolDecision::Deny) => return rpc_error(id, ERR_TOOL_DENIED, "tool denied"),
            Some(ToolDecision::Ask) => {
                return rpc_error(id, ERR_TOOL_NEEDS_APPROVAL, "tool requires approval")
            }
            Some(ToolDecision::Allow) => {}
        }

        let args_val = params
            .and_then(|p| p.get("arguments"))
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let args_bytes = serde_json::to_vec(&args_val).unwrap_or_default();

        let output = match handler.execute(tool, &args_bytes) {
            Ok(o) => o,
            // The error is CrustCore-internal; redact + bound it so a path or secret never
            // leaks to the client through an error string.
            Err(e) => {
                let safe = redactor.to_model_visible(&e);
                let bounded = BoundedText::truncated(safe.as_str(), MAX_MCP_SUMMARY);
                return rpc_error(id, ERR_TOOL_FAILED, bounded.as_str());
            }
        };

        // Redact (no CrustCore secret leaves) → bound → receipt (invariants 2, 11, 10).
        let artifact_hash = sha256(&output);
        let redacted = redactor.to_model_visible(&String::from_utf8_lossy(&output));
        let summary = BoundedText::truncated(redacted.as_str(), MAX_MCP_SUMMARY);
        let tool_name = format!("mcp-server:{tool}");
        let _receipt = receipts.mint(&ReceiptParams {
            task_id: ids.task_id,
            job_id: ids.job_id,
            tool_call_id: ids.tool_call_id,
            tool_name: tool_name.as_bytes(),
            args: &args_bytes,
            result: summary.as_str().as_bytes(),
            artifacts: &[ArtifactId(artifact_hash)],
            event_seq: ids.event_seq,
        });

        rpc_result(
            id,
            serde_json::json!({ "content": [{ "type": "text", "text": summary.as_str() }] }),
        )
    }
}

fn rpc_result(id: serde_json::Value, result: serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn rpc_error(id: serde_json::Value, code: i64, message: &str) -> serde_json::Value {
    serde_json::json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crustcore_receipts::MacKey;
    use crustcore_types::{EventSeq, JobId, TaskId, ToolCallId};

    struct EchoHandler;
    impl ToolHandler for EchoHandler {
        fn execute(&self, tool: &str, args: &[u8]) -> Result<Vec<u8>, String> {
            Ok(format!("{tool} ran with {}", String::from_utf8_lossy(args)).into_bytes())
        }
    }

    /// A handler whose output quotes a secret — the server must redact it before the
    /// client ever sees the response.
    struct LeakyHandler;
    impl ToolHandler for LeakyHandler {
        fn execute(&self, _tool: &str, _args: &[u8]) -> Result<Vec<u8>, String> {
            Ok(b"verify passed; internal token sk-SERVERLEAK".to_vec())
        }
    }

    fn server() -> McpServer {
        let mut s = McpServer::new();
        s.expose(ExposedTool {
            name: "verify".into(),
            description: "Run the verifier on a worktree".into(),
            decision: ToolDecision::Allow,
        });
        s.expose(ExposedTool {
            name: "inspect".into(),
            description: "Inspect the event log".into(),
            decision: ToolDecision::Ask,
        });
        s.expose(ExposedTool {
            name: "danger".into(),
            description: "explicitly denied".into(),
            decision: ToolDecision::Deny,
        });
        s
    }

    fn ids() -> McpCallIds {
        McpCallIds {
            task_id: TaskId(1),
            job_id: JobId(1),
            tool_call_id: ToolCallId(1),
            event_seq: EventSeq(1),
        }
    }

    fn call(name: &str) -> serde_json::Value {
        serde_json::json!({
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": { "name": name, "arguments": { "dir": "x" } }
        })
    }

    #[test]
    fn tools_list_returns_the_curated_surface() {
        let s = server();
        let mut receipts = ReceiptChain::new(MacKey::new([0x11; 32]));
        let resp = s.handle_request(
            &serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}),
            &EchoHandler,
            &Redactor::new(),
            &mut receipts,
            &ids(),
        );
        let names: Vec<&str> = resp["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"verify") && names.contains(&"inspect"));
    }

    #[test]
    fn allowed_tool_runs_redacts_and_receipts() {
        let s = server();
        let mut receipts = ReceiptChain::new(MacKey::new([0x11; 32]));
        let before = receipts.len();
        let resp = s.handle_request(
            &call("verify"),
            &EchoHandler,
            &Redactor::new(),
            &mut receipts,
            &ids(),
        );
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("verify ran"));
        // A receipt was minted for the served call (invariant 10).
        assert_eq!(receipts.len(), before + 1);
    }

    #[test]
    fn hostile_client_cannot_call_an_uncurated_tool() {
        // The classic escalation attempt: a client asks for a tool CrustCore never
        // exposed (a secret read, an approval, a kernel op). Default-deny.
        let s = server();
        let mut receipts = ReceiptChain::new(MacKey::new([0x11; 32]));
        for evil in [
            "read_secret",
            "approve_merge",
            "kernel_step",
            "../../etc/passwd",
        ] {
            let resp = s.handle_request(
                &call(evil),
                &EchoHandler,
                &Redactor::new(),
                &mut receipts,
                &ids(),
            );
            assert_eq!(
                resp["error"]["code"].as_i64().unwrap(),
                ERR_TOOL_NOT_EXPOSED
            );
        }
        // A curated-but-denied tool is refused too; an Ask tool needs approval.
        let denied = s.handle_request(
            &call("danger"),
            &EchoHandler,
            &Redactor::new(),
            &mut receipts,
            &ids(),
        );
        assert_eq!(denied["error"]["code"].as_i64().unwrap(), ERR_TOOL_DENIED);
        let ask = s.handle_request(
            &call("inspect"),
            &EchoHandler,
            &Redactor::new(),
            &mut receipts,
            &ids(),
        );
        assert_eq!(
            ask["error"]["code"].as_i64().unwrap(),
            ERR_TOOL_NEEDS_APPROVAL
        );
        // Nothing was executed → no receipt minted for any refused call.
        assert_eq!(receipts.len(), 0);
    }

    #[test]
    fn server_output_is_redacted_before_it_reaches_the_client() {
        let s = server();
        let mut redactor = Redactor::new();
        redactor.register("srv", b"sk-SERVERLEAK");
        let mut receipts = ReceiptChain::new(MacKey::new([0x11; 32]));
        let resp = s.handle_request(
            &call("verify"),
            &LeakyHandler,
            &redactor,
            &mut receipts,
            &ids(),
        );
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(!text.contains("SERVERLEAK")); // secret never reaches the client (inv 2)
        assert!(text.contains("[REDACTED:srv]"));
    }

    #[test]
    fn unknown_method_is_a_clean_error_not_a_panic() {
        let s = server();
        let mut receipts = ReceiptChain::new(MacKey::new([0x11; 32]));
        let resp = s.handle_request(
            &serde_json::json!({"jsonrpc":"2.0","id":1,"method":"resources/read"}),
            &EchoHandler,
            &Redactor::new(),
            &mut receipts,
            &ids(),
        );
        assert_eq!(
            resp["error"]["code"].as_i64().unwrap(),
            ERR_METHOD_NOT_FOUND
        );
        // A request missing params/name is a clean error, not a panic.
        let bad = s.handle_request(
            &serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call"}),
            &EchoHandler,
            &Redactor::new(),
            &mut receipts,
            &ids(),
        );
        assert_eq!(bad["error"]["code"].as_i64().unwrap(), ERR_TOOL_NOT_EXPOSED);
    }
}
