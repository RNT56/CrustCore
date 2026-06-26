// SPDX-License-Identifier: Apache-2.0
//! MCP JSON-RPC transport (P13-net): the live execution layer beneath the gateway.
//!
//! The gateway ([`crate::gateway_check`], [`crate::filter_result`]) decides *whether*
//! a tool call may proceed and turns its result into a redacted, bounded, receipted
//! [`crate::McpResult`]. This module *performs* the JSON-RPC request — over an
//! [`McpTransport`] so the protocol + the gateway call flow ([`crate::call_tool`]) are
//! **fully CI-testable with an in-process [`MockMcp`]** (no network, no subprocess).
//! The real local transport ([`StdioMcp`]) is std `process` + Content-Length-framed
//! JSON-RPC; the remote HTTP transport ([`HttpMcp`], `http` feature, P13-net-http) POSTs
//! the same JSON-RPC envelope over `ureq` and is where `BrokerSecret` auth applies.
//!
//! Trust posture (invariant 7): an MCP server's responses are **untrusted data** —
//! nothing here interprets a response as a command; the gateway decides from the
//! registry's `tool_policies`, never the server's self-description, and all output is
//! redacted before it can be model-visible.
//!
//! Credential injection (P13-net): a request may carry an optional broker-resolved
//! [`HeaderInjection`] (e.g. `Authorization: Bearer …`). The secret bytes live only
//! inside that injection and are read through [`HeaderInjection::reveal`] *here at the
//! transport boundary* — never placed in `params`, the response, the model context, or
//! a log (invariants 1–3). An HTTP transport sends the header on the wire; a stdio
//! transport (which has no HTTP header channel) simply does not forward it — see
//! [`StdioMcp::call`] and [`crate::McpAuthMode`].

use crustcore_secrets::HeaderInjection;
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
///
/// `auth` carries an optional broker-resolved credential (P13-net): when present the
/// transport injects it at the wire boundary (an HTTP `Authorization` header), reading
/// the secret bytes via [`HeaderInjection::reveal`] **only here** — they never enter
/// `params`, the returned `result`, the model context, or a log (invariants 1–3). A
/// transport with no header channel (stdio) ignores `auth` by construction; see
/// [`crate::McpAuthMode`].
pub trait McpTransport {
    /// Issues a JSON-RPC `method` call with `params`, returning the `result` value.
    /// `auth`, if any, is the broker-resolved credential injected at the transport.
    ///
    /// # Errors
    /// [`McpError`] on a transport failure, a JSON-RPC `error`, or a malformed reply.
    fn call(
        &self,
        method: &str,
        params: serde_json::Value,
        auth: Option<&HeaderInjection>,
    ) -> Result<serde_json::Value, McpError>;
}

/// Builds a JSON-RPC 2.0 request envelope (`{jsonrpc:"2.0", id, method, params}`) — the
/// single canonical shape every transport puts on the wire. Pure and side-effect-free,
/// so the envelope is asserted directly in CI (no network/subprocess); the stdio and
/// HTTP transports both serialize exactly this. `auth` is intentionally **not** part of
/// the envelope: a credential is a wire-level transport header, never a body field —
/// putting it in `params` would place the secret in the model-visible JSON-RPC body and
/// break invariants 1–3.
#[must_use]
pub fn build_request_envelope(
    id: i64,
    method: &str,
    params: serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": method,
        "params": params,
    })
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
    let result = transport.call("tools/list", serde_json::json!({}), None)?;
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
///
/// It also **records** the credential it was handed on the most recent call (its
/// header name + the *revealed* bytes), so a test can assert that `call_tool` resolved
/// a `BrokerSecret` and injected it at the transport — without that ever appearing in
/// the model-visible result (P13-net). The recorded bytes stay inside the mock and are
/// read only by the test that built it; they never flow into a receipt or `McpResult`.
#[derive(Default)]
pub struct MockMcp {
    responses: std::collections::BTreeMap<String, Result<serde_json::Value, McpError>>,
    /// The `(header_name, revealed_value_bytes)` handed to the most recent `call`, or
    /// `None` if the last call carried no credential. Interior-mutable so `&self`
    /// `call` can record it (the trait takes `&self`).
    last_auth: std::cell::RefCell<Option<(String, Vec<u8>)>>,
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

    /// The `(header_name, revealed_bytes)` the transport was handed on the most recent
    /// call, for test assertions that a broker credential was injected at the transport
    /// boundary. `None` if no credential was passed. **Test-only introspection** — real
    /// transports do not expose what they injected.
    #[must_use]
    pub fn last_auth(&self) -> Option<(String, Vec<u8>)> {
        self.last_auth.borrow().clone()
    }
}

impl McpTransport for MockMcp {
    fn call(
        &self,
        method: &str,
        _params: serde_json::Value,
        auth: Option<&HeaderInjection>,
    ) -> Result<serde_json::Value, McpError> {
        // Record the injected credential (if any) so a test can prove it reached the
        // transport. `reveal()` is the trusted-outbound byte accessor; here it is the
        // simulated wire. This stays inside the mock — never returned to the caller.
        *self.last_auth.borrow_mut() =
            auth.map(|h| (h.header_name().to_string(), h.reveal().to_vec()));
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
    /// `auth` is accepted for trait uniformity but **not forwarded**: the MCP stdio
    /// transport is a local subprocess speaking framed JSON-RPC over pipes — it has no
    /// HTTP header channel, so an `Authorization` header has nowhere to go. By contract
    /// (`docs/mcp.md`; [`crate::McpAuthMode`]) `BrokerSecret` auth applies to the
    /// HTTP transport ([`HttpMcp`]); a stdio server uses [`crate::McpAuthMode::None`]. The
    /// credential is deliberately **not** smuggled into `params` — that would put the
    /// secret in the model-visible JSON-RPC body, violating invariants 1–3. The
    /// resolution path still runs in [`crate::call_tool`]; this transport simply elects
    /// not to use the resolved header.
    fn call(
        &self,
        method: &str,
        params: serde_json::Value,
        _auth: Option<&HeaderInjection>,
    ) -> Result<serde_json::Value, McpError> {
        use std::io::Write;
        let id = self.next_id.get();
        self.next_id.set(id.saturating_add(1));
        let request = build_request_envelope(id, method, params);
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

// ---------------------------------------------------------------------------
// HttpMcp — a remote MCP server over HTTP, JSON-RPC in the request/response body
// ---------------------------------------------------------------------------

/// A remote MCP server over HTTP (`http` feature, P13-net-http): POSTs a JSON-RPC 2.0
/// request envelope to the configured server URL and parses the JSON-RPC response from
/// the (bounded) body. Backed by `ureq` (a small, blocking, rustls HTTP/1.1 client — no
/// Tokio); a default `crustcore-mcp` build links none of it.
///
/// **This is where `BrokerSecret` auth actually applies.** Unlike stdio (no header
/// channel), HTTP has one: when `call` is handed a broker-resolved [`HeaderInjection`]
/// it sets that header on the request, reading the secret bytes via
/// [`HeaderInjection::reveal`] **only** at the `ureq` boundary. The bytes never enter
/// the envelope `params`, the returned `result`, the model context, or any error/log —
/// errors here carry only the header *name* and the transport's own message, never the
/// value (invariants 1–3).
///
/// The envelope build ([`build_request_envelope`]) and response parse ([`parse_rpc_result`])
/// are pure and CI-tested without network; the live POST round-trip is `#[ignore]`d (it
/// needs a running MCP HTTP server).
#[cfg(feature = "http")]
pub struct HttpMcp {
    agent: ureq::Agent,
    url: String,
    next_id: std::cell::Cell<i64>,
}

#[cfg(feature = "http")]
impl HttpMcp {
    /// A remote MCP transport posting to `url`, with a bounded request timeout.
    #[must_use]
    pub fn new(url: impl Into<String>) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(120))
            .build();
        HttpMcp {
            agent,
            url: url.into(),
            next_id: std::cell::Cell::new(1),
        }
    }

    /// Reads the response body bounded by [`MAX_MESSAGE_BYTES`] (a hostile server cannot
    /// force an unbounded allocation; invariant 11, §6.5) and parses it as a JSON-RPC
    /// response, mapping `result`/`error` via [`parse_rpc_result`].
    fn parse_response(reader: impl std::io::Read) -> Result<serde_json::Value, McpError> {
        use std::io::Read;
        // `take` caps the read at the body limit *before* the buffer can grow past it.
        let mut buf = Vec::new();
        reader
            .take(MAX_MESSAGE_BYTES as u64 + 1)
            .read_to_end(&mut buf)
            .map_err(|e| McpError::Transport(e.to_string()))?;
        if buf.len() > MAX_MESSAGE_BYTES {
            return Err(McpError::BadResponse("response exceeds size cap".into()));
        }
        let response: serde_json::Value =
            serde_json::from_slice(&buf).map_err(|e| McpError::BadResponse(e.to_string()))?;
        parse_rpc_result(&response)
    }
}

#[cfg(feature = "http")]
impl McpTransport for HttpMcp {
    /// POSTs the JSON-RPC envelope to the server URL with `Content-Type: application/json`
    /// and, when present, the broker-resolved `auth` header. The secret bytes are read
    /// (via [`HeaderInjection::reveal`]) only to set the header on the wire and are never
    /// echoed into the error path.
    fn call(
        &self,
        method: &str,
        params: serde_json::Value,
        auth: Option<&HeaderInjection>,
    ) -> Result<serde_json::Value, McpError> {
        let id = self.next_id.get();
        self.next_id.set(id.saturating_add(1));
        let request = build_request_envelope(id, method, params);
        let body =
            serde_json::to_vec(&request).map_err(|e| McpError::BadResponse(e.to_string()))?;

        let mut req = self
            .agent
            .post(&self.url)
            .set("Content-Type", "application/json");
        if let Some(h) = auth {
            // The ONLY place the secret bytes touch the wire. `reveal()` yields the full
            // header value (e.g. `Bearer <token>`); it is set on the request and never
            // captured into a variable that could reach an error/log (invariants 1–3).
            let value = std::str::from_utf8(h.reveal())
                .map_err(|_| McpError::Transport("auth header is not valid UTF-8".into()))?;
            req = req.set(h.header_name(), value);
        }

        match req.send_bytes(&body) {
            // 2xx (and ureq's non-2xx `Err(Status)` below) are both round-trips: the
            // JSON-RPC layer carries success *and* application errors in a 200 body, so
            // we parse the body either way. Error mapping never references `auth`.
            Ok(resp) => Self::parse_response(resp.into_reader()),
            Err(ureq::Error::Status(_status, resp)) => Self::parse_response(resp.into_reader()),
            Err(ureq::Error::Transport(t)) => Err(McpError::Transport(t.to_string())),
        }
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
        assert!(mock.call("tools/call", serde_json::json!({}), None).is_ok());
        assert!(matches!(
            mock.call("unknown", serde_json::json!({}), None)
                .unwrap_err(),
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
        let result = server.call("ping", serde_json::json!({}), None).unwrap();
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

    // --- JSON-RPC envelope: the shape every transport (stdio + HTTP) puts on the wire. ---

    #[test]
    fn build_request_envelope_is_a_jsonrpc_2_0_request() {
        let env = build_request_envelope(7, "tools/call", serde_json::json!({"name": "search"}));
        assert_eq!(
            env,
            serde_json::json!({
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {"name": "search"},
            })
        );
        // The credential is never an envelope field — it is a wire header only (inv. 1–3).
        assert!(env.get("auth").is_none());
        assert!(env.get("authorization").is_none());
    }

    // --- HttpMcp response parse: bounded, parses a canned result and a canned error. ---

    #[cfg(feature = "http")]
    #[test]
    fn http_parse_response_unwraps_result_and_maps_error_and_bounds_body() {
        // A canned JSON-RPC success body → unwrapped `result`.
        let ok = br#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hi"}]}}"#;
        assert_eq!(
            HttpMcp::parse_response(&ok[..]).unwrap(),
            serde_json::json!({"content":[{"type":"text","text":"hi"}]})
        );

        // A canned JSON-RPC error body → McpError::Rpc, not a panic.
        let err = br#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"no method"}}"#;
        assert_eq!(
            HttpMcp::parse_response(&err[..]).unwrap_err(),
            McpError::Rpc {
                code: -32601,
                message: "no method".into()
            }
        );

        // Non-JSON body → BadResponse.
        assert!(matches!(
            HttpMcp::parse_response(&b"not json"[..]).unwrap_err(),
            McpError::BadResponse(_)
        ));

        // A body one byte over the cap → BadResponse, no unbounded allocation.
        let oversized = vec![b'x'; MAX_MESSAGE_BYTES + 1];
        assert!(matches!(
            HttpMcp::parse_response(&oversized[..]).unwrap_err(),
            McpError::BadResponse(_)
        ));
    }

    /// A genuine HTTP round-trip through [`HttpMcp`] against a *real* MCP HTTP server.
    /// `#[ignore]`d (not CI): it opens a socket and needs a server speaking JSON-RPC at
    /// `$CRUSTCORE_MCP_HTTP_URL`. The CI-covered logic (envelope build, response parse,
    /// bounding, auth-header injection) lives in the helper tests above and the
    /// `call_tool` gateway-flow tests in `lib.rs`.
    #[cfg(feature = "http")]
    #[test]
    #[ignore = "opens a socket; needs a running MCP HTTP server at $CRUSTCORE_MCP_HTTP_URL"]
    fn http_round_trips_against_a_live_server() {
        let url = std::env::var("CRUSTCORE_MCP_HTTP_URL")
            .expect("set CRUSTCORE_MCP_HTTP_URL to a running MCP HTTP server");
        let transport = HttpMcp::new(url);
        let tools = list_tools(&transport).expect("tools/list over HTTP");
        assert!(!tools.is_empty(), "server advertised no tools");
    }
}
