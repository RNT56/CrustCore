// SPDX-License-Identifier: Apache-2.0
//! MCP JSON-RPC transport (P13-net): the live execution layer beneath the gateway.
//!
//! The gateway ([`crate::gateway_check`], [`crate::filter_result`]) decides *whether*
//! a tool call may proceed and turns its result into a redacted, bounded, receipted
//! [`crate::McpResult`]. This module *performs* the JSON-RPC request — over an
//! [`McpTransport`] so the protocol + the gateway call flow ([`crate::call_tool`]) are
//! **fully CI-testable with an in-process [`MockMcp`]** (no network, no subprocess).
//! The real local transport ([`StdioMcp`]) is std `process` + Content-Length-framed
//! JSON-RPC; a remote HTTP transport would reuse `crustcore-net` (`TODO(P13-net-http)`).
//!
//! Trust posture (invariant 7): an MCP server's responses are **untrusted data** —
//! nothing here interprets a response as a command; the gateway decides from the
//! registry's `tool_policies`, never the server's self-description, and all output is
//! redacted before it can be model-visible.

use crustcore_types::hash::sha256;

/// Cap on a single framed JSON-RPC message **body** read from a server (bounded — a
/// hostile server cannot force an unbounded allocation; invariant 11, §6.5).
pub const MAX_MESSAGE_BYTES: usize = 8 * 1024 * 1024;

/// Cap on the **header** section of a framed message (the `Content-Length` line plus
/// the terminating blank line). Headers are tiny in practice; bounding them stops a
/// hostile server from forcing an unbounded allocation via one enormous header line or
/// an endless stream of header lines *before* the body cap could ever apply (invariant
/// 11, §6.5).
const MAX_HEADER_BYTES: usize = 8 * 1024;

/// Why an MCP transport call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum McpError {
    /// A transport-level failure (spawn / io / connection).
    Transport(String),
    /// The server returned a JSON-RPC `error` object.
    Rpc {
        /// JSON-RPC error code.
        code: i64,
        /// JSON-RPC error message (untrusted server text — redact before showing).
        message: String,
    },
    /// The response was not a well-formed JSON-RPC result.
    BadResponse(String),
}

impl core::fmt::Display for McpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            McpError::Transport(e) => write!(f, "mcp transport: {e}"),
            McpError::Rpc { code, message } => write!(f, "mcp rpc {code}: {message}"),
            McpError::BadResponse(e) => write!(f, "mcp bad response: {e}"),
        }
    }
}

/// A JSON-RPC transport to one MCP server. `call` issues a single request and returns
/// the `result` value (or a typed error). The session lifecycle (`initialize` →
/// `tools/list` → `tools/call`) is orchestrated by the caller over this primitive.
pub trait McpTransport {
    /// Issues a JSON-RPC `method` call with `params`, returning the `result` value.
    ///
    /// # Errors
    /// [`McpError`] on a transport failure, a JSON-RPC `error`, or a malformed reply.
    fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, McpError>;
}

/// Extracts the `result` from a JSON-RPC response object, mapping an `error` member
/// to [`McpError::Rpc`]. Defends against a response that is not an object or omits
/// both members.
pub fn parse_rpc_result(v: &serde_json::Value) -> Result<serde_json::Value, McpError> {
    if let Some(err) = v.get("error").filter(|e| !e.is_null()) {
        let code = err
            .get("code")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0);
        let message = err
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("error")
            .to_string();
        return Err(McpError::Rpc { code, message });
    }
    v.get("result")
        .cloned()
        .ok_or_else(|| McpError::BadResponse("no result/error member".into()))
}

/// A described tool from `tools/list` — its name + description (both untrusted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolDescriptor {
    /// The tool name (the gateway keys policy on this).
    pub name: String,
    /// The server's self-description — **untrusted**, never consulted by the gate.
    pub description: String,
}

/// Lists a server's tools via `tools/list`. The returned descriptions are untrusted.
///
/// # Errors
/// [`McpError`] on a transport/RPC/parse failure.
pub fn list_tools(transport: &dyn McpTransport) -> Result<Vec<ToolDescriptor>, McpError> {
    let result = transport.call("tools/list", serde_json::json!({}))?;
    let tools = result
        .get("tools")
        .and_then(|t| t.as_array())
        .ok_or_else(|| McpError::BadResponse("tools/list: no tools array".into()))?;
    Ok(tools
        .iter()
        .filter_map(|t| {
            t.get("name")
                .and_then(|n| n.as_str())
                .map(|name| ToolDescriptor {
                    name: name.to_string(),
                    description: t
                        .get("description")
                        .and_then(|d| d.as_str())
                        .unwrap_or("")
                        .to_string(),
                })
        })
        .collect())
}

/// Hashes a server's **tool surface** (the sorted set of tool names) into the
/// manifest hash [`crate::gateway_check`] compares against the pinned
/// `manifest_hash` for drift detection. Only names — never the untrusted
/// descriptions — define the admitted surface, so a server cannot dodge drift
/// detection by changing only a description, nor trip it by reordering.
#[must_use]
pub fn manifest_hash(tools: &[ToolDescriptor]) -> [u8; 32] {
    let mut names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    let mut buf = Vec::new();
    for n in names {
        buf.extend_from_slice(n.as_bytes());
        buf.push(0); // unambiguous separator
    }
    sha256(&buf)
}

// ---------------------------------------------------------------------------
// MockMcp — in-process canned transport (always compiled; the CI-testable path)
// ---------------------------------------------------------------------------

/// A deterministic in-process [`McpTransport`] that returns canned results keyed by
/// method — the transport the gateway-flow tests and the hidden-instructions red-team
/// use. Makes no network/subprocess calls, so it runs in CI.
#[derive(Default)]
pub struct MockMcp {
    responses: std::collections::BTreeMap<String, Result<serde_json::Value, McpError>>,
}

impl MockMcp {
    /// An empty mock.
    #[must_use]
    pub fn new() -> Self {
        MockMcp::default()
    }

    /// Canned success `result` for `method`.
    #[must_use]
    pub fn on(mut self, method: &str, result: serde_json::Value) -> Self {
        self.responses.insert(method.to_string(), Ok(result));
        self
    }

    /// Canned error for `method`.
    #[must_use]
    pub fn on_error(mut self, method: &str, err: McpError) -> Self {
        self.responses.insert(method.to_string(), Err(err));
        self
    }
}

impl McpTransport for MockMcp {
    fn call(
        &self,
        method: &str,
        _params: serde_json::Value,
    ) -> Result<serde_json::Value, McpError> {
        match self.responses.get(method) {
            Some(Ok(v)) => Ok(v.clone()),
            Some(Err(e)) => Err(e.clone()),
            None => Err(McpError::Transport(format!(
                "mock: no response for {method}"
            ))),
        }
    }
}

// ---------------------------------------------------------------------------
// StdioMcp — a local MCP server subprocess, Content-Length-framed JSON-RPC
// ---------------------------------------------------------------------------

/// A local MCP server over stdio: spawns the server process and speaks
/// Content-Length-framed JSON-RPC over its stdin/stdout (the MCP stdio transport).
/// std-only (`process` + serde_json). The framing read is bounded against a hostile
/// server — the header section by [`MAX_HEADER_BYTES`] and the body by
/// [`MAX_MESSAGE_BYTES`] — and lives in [`read_framed_message`], which is pure over any
/// [`std::io::BufRead`] and therefore exercised in CI with an in-memory reader; the
/// full subprocess round-trip is covered by an `#[ignore]`d integration test.
pub struct StdioMcp {
    child: std::cell::RefCell<std::process::Child>,
    stdin: std::cell::RefCell<std::process::ChildStdin>,
    stdout: std::cell::RefCell<std::io::BufReader<std::process::ChildStdout>>,
    next_id: std::cell::Cell<i64>,
}

impl StdioMcp {
    /// Spawns `program args...` as a local MCP server speaking stdio JSON-RPC.
    ///
    /// # Errors
    /// [`McpError::Transport`] if the process cannot be spawned or its pipes are not
    /// available.
    pub fn spawn(program: &str, args: &[&str]) -> Result<Self, McpError> {
        use std::process::{Command, Stdio};
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| McpError::Transport(format!("spawn {program}: {e}")))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| McpError::Transport("no stdin pipe".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| McpError::Transport("no stdout pipe".into()))?;
        Ok(StdioMcp {
            child: std::cell::RefCell::new(child),
            stdin: std::cell::RefCell::new(stdin),
            stdout: std::cell::RefCell::new(std::io::BufReader::new(stdout)),
            next_id: std::cell::Cell::new(1),
        })
    }

    fn read_framed(&self) -> Result<serde_json::Value, McpError> {
        read_framed_message(&mut *self.stdout.borrow_mut())
    }
}

/// Reads one Content-Length-framed JSON-RPC message from `reader`, **bounded** against a
/// hostile or buggy server (invariant 11, §6.5): the header section is capped at
/// [`MAX_HEADER_BYTES`] — so neither one enormous header line nor an endless stream of
/// header lines can force an unbounded allocation — and the body at [`MAX_MESSAGE_BYTES`],
/// checked before the buffer is allocated. Pure over any [`std::io::BufRead`], so it is
/// exercised directly in CI with an in-memory reader (no subprocess).
///
/// # Errors
/// [`McpError::Transport`] if the stream closes early; [`McpError::BadResponse`] if the
/// headers/body exceed their caps, the `Content-Length` is absent, or the body is not
/// valid JSON.
fn read_framed_message<R: std::io::BufRead>(reader: &mut R) -> Result<serde_json::Value, McpError> {
    use std::io::{BufRead, Read};
    let mut content_len: Option<usize> = None;
    let mut header_total: usize = 0;
    loop {
        if header_total >= MAX_HEADER_BYTES {
            return Err(McpError::BadResponse("headers exceed size cap".into()));
        }
        // `take` bounds this single line to the remaining header budget, so even a line
        // with no newline cannot grow `line` past the cap; the running total then bounds
        // the number of lines. Either way the header section is bounded.
        let remaining = MAX_HEADER_BYTES - header_total;
        let mut line = Vec::new();
        let n = (&mut *reader)
            .take(remaining as u64)
            .read_until(b'\n', &mut line)
            .map_err(|e| McpError::Transport(e.to_string()))?;
        if n == 0 {
            return Err(McpError::Transport("server closed the connection".into()));
        }
        header_total += n;
        let text = String::from_utf8_lossy(&line);
        let trimmed = text.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break; // end of headers
        }
        if let Some(v) = trimmed.strip_prefix("Content-Length:") {
            content_len = v.trim().parse::<usize>().ok();
        }
    }
    let len = content_len.ok_or_else(|| McpError::BadResponse("no Content-Length".into()))?;
    if len > MAX_MESSAGE_BYTES {
        return Err(McpError::BadResponse("message exceeds size cap".into()));
    }
    let mut buf = vec![0u8; len];
    reader
        .read_exact(&mut buf)
        .map_err(|e| McpError::Transport(e.to_string()))?;
    serde_json::from_slice(&buf).map_err(|e| McpError::BadResponse(e.to_string()))
}

impl Drop for StdioMcp {
    fn drop(&mut self) {
        // Best-effort teardown so a server subprocess never leaks.
        let _ = self.child.borrow_mut().kill();
        let _ = self.child.borrow_mut().wait();
    }
}

impl McpTransport for StdioMcp {
    fn call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value, McpError> {
        use std::io::Write;
        let id = self.next_id.get();
        self.next_id.set(id.saturating_add(1));
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        let body =
            serde_json::to_vec(&request).map_err(|e| McpError::BadResponse(e.to_string()))?;
        {
            let mut stdin = self.stdin.borrow_mut();
            write!(stdin, "Content-Length: {}\r\n\r\n", body.len())
                .and_then(|()| stdin.write_all(&body))
                .and_then(|()| stdin.flush())
                .map_err(|e| McpError::Transport(e.to_string()))?;
        }
        let response = self.read_framed()?;
        parse_rpc_result(&response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rpc_result_extracts_result_and_maps_errors() {
        let ok = serde_json::json!({"jsonrpc":"2.0","id":1,"result":{"x":1}});
        assert_eq!(parse_rpc_result(&ok).unwrap(), serde_json::json!({"x":1}));

        let err = serde_json::json!({"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"no method"}});
        assert_eq!(
            parse_rpc_result(&err).unwrap_err(),
            McpError::Rpc {
                code: -32601,
                message: "no method".into()
            }
        );

        // Neither result nor error → BadResponse, not a panic.
        assert!(matches!(
            parse_rpc_result(&serde_json::json!({"jsonrpc":"2.0"})).unwrap_err(),
            McpError::BadResponse(_)
        ));
    }

    #[test]
    fn list_tools_and_manifest_hash_are_order_independent_on_names() {
        let mock = MockMcp::new().on(
            "tools/list",
            serde_json::json!({"tools":[
                {"name":"search","description":"find things"},
                {"name":"write","description":"write a file"}
            ]}),
        );
        let tools = list_tools(&mock).unwrap();
        assert_eq!(tools.len(), 2);
        // Manifest hash depends only on the (sorted) name set, not order/description.
        let reordered = vec![
            ToolDescriptor {
                name: "write".into(),
                description: "DIFFERENT".into(),
            },
            ToolDescriptor {
                name: "search".into(),
                description: "x".into(),
            },
        ];
        assert_eq!(manifest_hash(&tools), manifest_hash(&reordered));
        // Adding a tool changes the surface hash (drift).
        let mut more = reordered.clone();
        more.push(ToolDescriptor {
            name: "exec".into(),
            description: String::new(),
        });
        assert_ne!(manifest_hash(&tools), manifest_hash(&more));
    }

    #[test]
    fn mock_returns_canned_and_errors_for_unknown() {
        let mock = MockMcp::new().on(
            "tools/call",
            serde_json::json!({"content":[{"type":"text","text":"hi"}]}),
        );
        assert!(mock.call("tools/call", serde_json::json!({})).is_ok());
        assert!(matches!(
            mock.call("unknown", serde_json::json!({})).unwrap_err(),
            McpError::Transport(_)
        ));
    }

    /// A genuine round-trip through [`StdioMcp`] against a *real* subprocess: a
    /// pre-built Content-Length frame is served by `cat`, and the transport reads,
    /// parses, and unwraps the JSON-RPC `result`. Exercises the framing read, the
    /// pipe wiring, and `Drop` teardown end to end. `#[ignore]`d (not CI): it spawns
    /// a process and assumes a POSIX shell + `cat` — run locally with `--ignored`.
    /// The CI-covered protocol logic lives in the [`MockMcp`] tests above.
    #[test]
    #[ignore = "spawns a subprocess (POSIX shell + cat); run locally with --ignored"]
    fn stdio_round_trips_a_framed_response() {
        use std::io::Write;
        // Build a correctly-framed JSON-RPC response and have `cat` serve it verbatim.
        let body = br#"{"jsonrpc":"2.0","id":1,"result":{"pong":true}}"#;
        let mut frame = Vec::new();
        write!(frame, "Content-Length: {}\r\n\r\n", body.len()).unwrap();
        frame.extend_from_slice(body);
        let path = std::env::temp_dir().join("cc_mcp_stdio_frame.bin");
        std::fs::write(&path, &frame).unwrap();

        let server = StdioMcp::spawn("sh", &["-c", &format!("cat {}", path.display())]).unwrap();
        let result = server.call("ping", serde_json::json!({})).unwrap();
        assert_eq!(result, serde_json::json!({"pong": true}));

        let _ = std::fs::remove_file(&path);
    }

    // --- Framing bounds: exercised in CI over an in-memory reader, no subprocess. ---

    fn framed(body: &[u8]) -> Vec<u8> {
        let mut f = format!("Content-Length: {}\r\n\r\n", body.len()).into_bytes();
        f.extend_from_slice(body);
        f
    }

    #[test]
    fn read_framed_message_round_trips_a_valid_frame() {
        let frame = framed(br#"{"jsonrpc":"2.0","id":1,"result":{"pong":true}}"#);
        let mut r: &[u8] = &frame;
        let v = read_framed_message(&mut r).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"jsonrpc":"2.0","id":1,"result":{"pong":true}})
        );
    }

    #[test]
    fn read_framed_message_bounds_one_giant_header_line() {
        // A single header line far larger than the cap, with no newline anywhere.
        let frame = vec![b'X'; MAX_HEADER_BYTES + 1000];
        let mut r: &[u8] = &frame;
        assert!(matches!(
            read_framed_message(&mut r).unwrap_err(),
            McpError::BadResponse(_)
        ));
    }

    #[test]
    fn read_framed_message_bounds_endless_header_lines() {
        // A flood of short, newline-terminated, non-blank lines that never terminate
        // the header section — bounded by the running total, not the per-line cap.
        let mut frame = Vec::new();
        for _ in 0..4000 {
            frame.extend_from_slice(b"h\r\n");
        }
        let mut r: &[u8] = &frame;
        assert!(matches!(
            read_framed_message(&mut r).unwrap_err(),
            McpError::BadResponse(_)
        ));
    }

    #[test]
    fn read_framed_message_rejects_an_oversized_body() {
        let frame = format!("Content-Length: {}\r\n\r\n", MAX_MESSAGE_BYTES + 1).into_bytes();
        let mut r: &[u8] = &frame;
        assert!(matches!(
            read_framed_message(&mut r).unwrap_err(),
            McpError::BadResponse(_)
        ));
    }

    #[test]
    fn read_framed_message_requires_content_length() {
        let mut r: &[u8] = b"\r\n"; // immediate blank line, no Content-Length
        assert!(matches!(
            read_framed_message(&mut r).unwrap_err(),
            McpError::BadResponse(_)
        ));
    }

    #[test]
    fn read_framed_message_errors_on_truncated_body_or_closed_stream() {
        // Declares 100 bytes, only 4 present → early EOF, not a panic.
        let mut frame = b"Content-Length: 100\r\n\r\n".to_vec();
        frame.extend_from_slice(b"abcd");
        let mut r: &[u8] = &frame;
        assert!(matches!(
            read_framed_message(&mut r).unwrap_err(),
            McpError::Transport(_)
        ));
        // A closed/empty stream is a transport error, not a hang or panic.
        let mut empty: &[u8] = b"";
        assert!(matches!(
            read_framed_message(&mut empty).unwrap_err(),
            McpError::Transport(_)
        ));
    }
}
