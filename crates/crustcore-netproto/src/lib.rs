// SPDX-License-Identifier: Apache-2.0
//! The local helper protocol nano speaks to the `crustcore-net` sidecar
//! (`ROADMAP.md` §2.1, §7.1; `docs/model-routing.md` §6; Phase 7, task P7.1).
//!
//! This crate is **std-only** and links **no HTTP/TLS/provider stack** — it is the
//! one piece the trusted caller (the `net` feature of the `crustcore` binary)
//! links. The heavy network stack lives behind the helper *process*
//! (`crustcore-net`), which the caller spawns and talks to over a pipe, exactly
//! as it spawns `git`/`codex`/`claude` (invariants 19, 20). So the sub-800kB
//! binary can call the model transport without embedding Tokio/Reqwest/Rustls.
//!
//! Wire format: **newline-delimited flat JSON objects** (one message per line).
//! Each object's values are scalars only (string / integer / bool) — no nested
//! objects or arrays — so the parser is small, allocation-light, and easy to audit
//! (no serde, matching the kernel/nano dependency ban). Lists (the dynamic model
//! registry, fallback chains) are modeled as repeated lines or delimited strings
//! rather than nested arrays.
#![forbid(unsafe_code)]

use std::io::{BufRead, Write};

pub use crustcore_types::BoundedText;

mod json;
pub use json::{Fields, JsonError, Scalar};

/// The helper-protocol version the caller and sidecar agree on.
pub const PROTOCOL_VERSION: u16 = 1;

/// Cap on a single wire line (bounded everything; a hostile/buggy helper cannot
/// make the caller read an unbounded line).
pub const MAX_LINE_BYTES: usize = 1024 * 1024;

/// Cap on text fields carried over the protocol (prompts, chunks, final text).
pub const MAX_TEXT_BYTES: usize = 256 * 1024;

/// An abstract model role — a *requirement*, resolved against the dynamic registry
/// at request time, never a hard-coded model name (invariant 17;
/// `docs/model-routing.md` §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Strongest available reasoning model (advisor).
    Advisor,
    /// Strong coding model.
    Implementation,
    /// High-reasoning model for review/security.
    Review,
    /// Cheaper, fast model for research/summarization.
    Research,
    /// A local endpoint (privacy/offline fallback).
    LocalFallback,
}

impl Role {
    /// The wire token for this role.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Advisor => "advisor",
            Role::Implementation => "implementation",
            Role::Review => "review",
            Role::Research => "research",
            Role::LocalFallback => "local_fallback",
        }
    }

    /// Parses a role token, defaulting unknown tokens to [`Role::Implementation`]
    /// (a safe, capable default rather than an error — forward compatible). Named
    /// `from_token` (not `from_str`) so it is not confused with `FromStr`.
    #[must_use]
    pub fn from_token(s: &str) -> Role {
        match s {
            "advisor" => Role::Advisor,
            "review" => Role::Review,
            "research" => Role::Research,
            "local_fallback" => Role::LocalFallback,
            _ => Role::Implementation,
        }
    }
}

/// Hard constraints a request requires (the router must satisfy all of these or
/// fail explicitly — never silently downgrade past one; `docs/model-routing.md`
/// §3).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Require {
    /// The model must support tool/function calls.
    pub tools: bool,
    /// The model must offer at least this context length (0 = no requirement).
    pub min_context: u32,
    /// The request must stay on a local provider (privacy); never route remote.
    pub local_only: bool,
}

/// A completion request (a single-prompt shape for v0.1; multi-message breadth
/// extends the same record later).
#[derive(Debug, Clone)]
pub struct CompleteRequest {
    /// The abstract role to route for.
    pub role: Role,
    /// Optional system preamble (bounded).
    pub system: BoundedText,
    /// The user prompt (bounded).
    pub prompt: BoundedText,
    /// Maximum output tokens to request.
    pub max_tokens: u32,
    /// Whether to stream chunks (invariant: progress is visible, not hidden CoT).
    pub stream: bool,
    /// Hard cost ceiling in micros for this request (0 = unlimited). The
    /// `BudgetProvider` refuses/degrades rather than breach it (invariant 11).
    pub max_cost_micros: u64,
    /// Hard capability/privacy constraints.
    pub require: Require,
}

/// A request from the caller to the sidecar.
#[derive(Debug, Clone)]
pub enum Request {
    /// Probe the dynamic registry: respond with one [`Response::Model`] per
    /// available model, then [`Response::RegistryEnd`].
    Probe,
    /// Run a completion; respond with [`Response::Chunk`]s (if streaming) then a
    /// [`Response::Final`], or a [`Response::Error`].
    Complete(CompleteRequest),
}

/// One model entry in the dynamic registry (`docs/model-routing.md` §1.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelInfo {
    /// Provider id (e.g. `openai`, `anthropic`, `mock-a`).
    pub provider: String,
    /// Model id within the provider.
    pub model: String,
    /// Whether the last probe found it healthy.
    pub healthy: bool,
    /// Context length in tokens.
    pub context: u32,
    /// Tool/function-call support.
    pub tools: bool,
    /// Structured-output support.
    pub structured: bool,
    /// Streaming support.
    pub streaming: bool,
    /// Rough cost in micros per 1000 output tokens (for budget ordering).
    pub cost_per_1k_micros: u64,
}

/// Token/cost usage for a completed request (`docs/model-routing.md` §5).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    /// Input tokens billed.
    pub input_tokens: u32,
    /// Output tokens billed.
    pub output_tokens: u32,
    /// Actual cost in micros.
    pub cost_micros: u64,
}

/// The final result of a completion.
#[derive(Debug, Clone)]
pub struct Final {
    /// The full completion text (bounded).
    pub text: BoundedText,
    /// The provider that ultimately served it.
    pub provider: String,
    /// The model that ultimately served it.
    pub model: String,
    /// Usage/cost for the served request.
    pub usage: Usage,
    /// Providers tried (and failed) before this one succeeded — the fallback path
    /// taken, for the audit story (`docs/model-routing.md` §5).
    pub fallbacks: Vec<String>,
}

/// A response from the sidecar to the caller.
#[derive(Debug, Clone)]
pub enum Response {
    /// One registry entry (in reply to [`Request::Probe`]).
    Model(ModelInfo),
    /// End of the registry stream.
    RegistryEnd,
    /// A streaming completion chunk.
    Chunk(BoundedText),
    /// The completed result.
    Final(Final),
    /// A typed failure (no model satisfied the constraints, all providers down,
    /// budget exceeded, etc.). The caller never treats a partial/garbage line as
    /// success.
    Error(String),
}

/// Protocol-level errors.
#[derive(Debug)]
pub enum ProtoError {
    /// An I/O error on the pipe.
    Io(String),
    /// A malformed or unexpected message.
    Decode(String),
    /// The helper closed the stream before completing the exchange.
    UnexpectedEof,
}

impl core::fmt::Display for ProtoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProtoError::Io(e) => write!(f, "helper protocol io error: {e}"),
            ProtoError::Decode(e) => write!(f, "helper protocol decode error: {e}"),
            ProtoError::UnexpectedEof => write!(f, "helper closed the stream unexpectedly"),
        }
    }
}

impl std::error::Error for ProtoError {}

impl From<std::io::Error> for ProtoError {
    fn from(e: std::io::Error) -> Self {
        ProtoError::Io(e.to_string())
    }
}

impl From<JsonError> for ProtoError {
    fn from(e: JsonError) -> Self {
        ProtoError::Decode(e.0)
    }
}

// ---------------------------------------------------------------------------
// Encoding (flat JSON object per line)
// ---------------------------------------------------------------------------

/// Encodes a [`Request`] as a single wire line (no trailing newline).
#[must_use]
pub fn encode_request(req: &Request) -> String {
    let mut o = json::Obj::new();
    o.int("v", i64::from(PROTOCOL_VERSION));
    match req {
        Request::Probe => {
            o.str("kind", "probe");
        }
        Request::Complete(c) => {
            o.str("kind", "complete");
            o.str("role", c.role.as_str());
            o.str("system", c.system.as_str());
            o.str("prompt", c.prompt.as_str());
            o.int("max_tokens", i64::from(c.max_tokens));
            o.bool("stream", c.stream);
            o.uint("max_cost_micros", c.max_cost_micros);
            o.bool("req_tools", c.require.tools);
            o.int("req_min_context", i64::from(c.require.min_context));
            o.bool("req_local_only", c.require.local_only);
        }
    }
    o.finish()
}

/// Encodes a [`Response`] as a single wire line (no trailing newline).
#[must_use]
pub fn encode_response(resp: &Response) -> String {
    let mut o = json::Obj::new();
    match resp {
        Response::Model(m) => {
            o.str("kind", "model");
            o.str("provider", &m.provider);
            o.str("model", &m.model);
            o.bool("healthy", m.healthy);
            o.int("context", i64::from(m.context));
            o.bool("tools", m.tools);
            o.bool("structured", m.structured);
            o.bool("streaming", m.streaming);
            o.uint("cost_per_1k_micros", m.cost_per_1k_micros);
        }
        Response::RegistryEnd => {
            o.str("kind", "registry_end");
        }
        Response::Chunk(t) => {
            o.str("kind", "chunk");
            o.str("text", t.as_str());
        }
        Response::Final(fin) => {
            o.str("kind", "final");
            o.str("text", fin.text.as_str());
            o.str("provider", &fin.provider);
            o.str("model", &fin.model);
            o.int("input_tokens", i64::from(fin.usage.input_tokens));
            o.int("output_tokens", i64::from(fin.usage.output_tokens));
            o.uint("cost_micros", fin.usage.cost_micros);
            o.str("fallbacks", &fin.fallbacks.join(","));
        }
        Response::Error(reason) => {
            o.str("kind", "error");
            o.str("reason", reason);
        }
    }
    o.finish()
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Reads one line from `r` (bounded by [`MAX_LINE_BYTES`]) and returns its parsed
/// fields, or `None` at clean EOF.
fn read_fields<R: BufRead>(r: &mut R) -> Result<Option<Fields>, ProtoError> {
    let mut line = Vec::new();
    let n = read_line_bounded(r, &mut line, MAX_LINE_BYTES)?;
    if n == 0 {
        return Ok(None);
    }
    let text = String::from_utf8_lossy(&line);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        // A blank line carries no message; treat as EOF-equivalent to avoid loops.
        return Ok(None);
    }
    Ok(Some(json::parse_flat_object(trimmed)?))
}

/// Reads a line into `buf` (without the newline) up to `max` bytes; returns bytes
/// read (0 at EOF). Refuses an over-long line rather than allocating unboundedly.
fn read_line_bounded<R: BufRead>(
    r: &mut R,
    buf: &mut Vec<u8>,
    max: usize,
) -> Result<usize, ProtoError> {
    let mut total = 0;
    loop {
        let available = r.fill_buf().map_err(ProtoError::from)?;
        if available.is_empty() {
            break; // EOF
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            buf.extend_from_slice(&available[..pos]);
            total += pos;
            r.consume(pos + 1);
            break;
        }
        let take = available.len();
        if total + take > max {
            return Err(ProtoError::Decode(
                "protocol line exceeds the byte cap".into(),
            ));
        }
        buf.extend_from_slice(available);
        total += take;
        r.consume(take);
    }
    Ok(total)
}

/// Decodes a [`Request`] from a parsed object (the sidecar's read side).
fn request_from_fields(f: &Fields) -> Result<Request, ProtoError> {
    match f.str("kind") {
        Some("probe") => Ok(Request::Probe),
        Some("complete") => Ok(Request::Complete(CompleteRequest {
            role: Role::from_token(f.str("role").unwrap_or("implementation")),
            system: BoundedText::truncated(f.str("system").unwrap_or(""), MAX_TEXT_BYTES),
            prompt: BoundedText::truncated(f.str("prompt").unwrap_or(""), MAX_TEXT_BYTES),
            max_tokens: f.uint("max_tokens").unwrap_or(0) as u32,
            stream: f.bool("stream").unwrap_or(false),
            max_cost_micros: f.uint("max_cost_micros").unwrap_or(0),
            require: Require {
                tools: f.bool("req_tools").unwrap_or(false),
                min_context: f.uint("req_min_context").unwrap_or(0) as u32,
                local_only: f.bool("req_local_only").unwrap_or(false),
            },
        })),
        other => Err(ProtoError::Decode(format!(
            "unknown request kind {other:?}"
        ))),
    }
}

/// Decodes a [`Response`] from a parsed object (the caller's read side).
fn response_from_fields(f: &Fields) -> Result<Response, ProtoError> {
    match f.str("kind") {
        Some("model") => Ok(Response::Model(ModelInfo {
            provider: f.str("provider").unwrap_or("").to_string(),
            model: f.str("model").unwrap_or("").to_string(),
            healthy: f.bool("healthy").unwrap_or(false),
            context: f.uint("context").unwrap_or(0) as u32,
            tools: f.bool("tools").unwrap_or(false),
            structured: f.bool("structured").unwrap_or(false),
            streaming: f.bool("streaming").unwrap_or(false),
            cost_per_1k_micros: f.uint("cost_per_1k_micros").unwrap_or(0),
        })),
        Some("registry_end") => Ok(Response::RegistryEnd),
        Some("chunk") => Ok(Response::Chunk(BoundedText::truncated(
            f.str("text").unwrap_or(""),
            MAX_TEXT_BYTES,
        ))),
        Some("final") => Ok(Response::Final(Final {
            text: BoundedText::truncated(f.str("text").unwrap_or(""), MAX_TEXT_BYTES),
            provider: f.str("provider").unwrap_or("").to_string(),
            model: f.str("model").unwrap_or("").to_string(),
            usage: Usage {
                input_tokens: f.uint("input_tokens").unwrap_or(0) as u32,
                output_tokens: f.uint("output_tokens").unwrap_or(0) as u32,
                cost_micros: f.uint("cost_micros").unwrap_or(0),
            },
            fallbacks: split_csv(f.str("fallbacks").unwrap_or("")),
        })),
        Some("error") => Ok(Response::Error(f.str("reason").unwrap_or("").to_string())),
        other => Err(ProtoError::Decode(format!(
            "unknown response kind {other:?}"
        ))),
    }
}

fn split_csv(s: &str) -> Vec<String> {
    if s.is_empty() {
        Vec::new()
    } else {
        s.split(',').map(str::to_string).collect()
    }
}

/// Reads one [`Request`] from `r`, or `None` at clean EOF (the sidecar's loop).
///
/// # Errors
/// [`ProtoError`] on a malformed/over-long line or I/O failure.
pub fn read_request<R: BufRead>(r: &mut R) -> Result<Option<Request>, ProtoError> {
    match read_fields(r)? {
        Some(f) => request_from_fields(&f).map(Some),
        None => Ok(None),
    }
}

/// Reads one [`Response`] from `r`, or `None` at clean EOF (the caller's loop).
///
/// # Errors
/// [`ProtoError`] on a malformed/over-long line or I/O failure.
pub fn read_response<R: BufRead>(r: &mut R) -> Result<Option<Response>, ProtoError> {
    match read_fields(r)? {
        Some(f) => response_from_fields(&f).map(Some),
        None => Ok(None),
    }
}

/// Writes a [`Request`] line (with newline) and flushes.
///
/// # Errors
/// [`ProtoError::Io`] on a write failure.
pub fn write_request<W: Write>(w: &mut W, req: &Request) -> Result<(), ProtoError> {
    w.write_all(encode_request(req).as_bytes())?;
    w.write_all(b"\n")?;
    w.flush()?;
    Ok(())
}

/// Writes a [`Response`] line (with newline) and flushes.
///
/// # Errors
/// [`ProtoError::Io`] on a write failure.
pub fn write_response<W: Write>(w: &mut W, resp: &Response) -> Result<(), ProtoError> {
    w.write_all(encode_response(resp).as_bytes())?;
    w.write_all(b"\n")?;
    w.flush()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Caller-side client
// ---------------------------------------------------------------------------

/// The caller-side client: writes requests to and reads responses from a helper
/// over any byte channel (the spawned sidecar's stdio in production, an in-memory
/// pipe in tests). **This is the only model-transport code the trusted caller
/// links — std-only, no HTTP/TLS** (`docs/model-routing.md` §6).
pub struct NetHelper<W: Write, R: BufRead> {
    w: W,
    r: R,
}

impl<W: Write, R: BufRead> NetHelper<W, R> {
    /// Builds a client over an explicit writer (to the helper) and reader (from
    /// the helper).
    pub fn new(w: W, r: R) -> Self {
        NetHelper { w, r }
    }

    /// Probes the dynamic registry, returning the models the sidecar currently
    /// offers. The result reflects *live* availability (invariant 17): a model
    /// dropped from a provider simply does not appear.
    ///
    /// # Errors
    /// [`ProtoError`] on a transport/decode failure.
    pub fn probe(&mut self) -> Result<Vec<ModelInfo>, ProtoError> {
        write_request(&mut self.w, &Request::Probe)?;
        let mut models = Vec::new();
        loop {
            match read_response(&mut self.r)? {
                Some(Response::Model(m)) => models.push(m),
                Some(Response::RegistryEnd) => return Ok(models),
                Some(Response::Error(e)) => return Err(ProtoError::Decode(e)),
                Some(other) => {
                    return Err(ProtoError::Decode(format!(
                        "unexpected response to probe: {other:?}"
                    )))
                }
                None => return Err(ProtoError::UnexpectedEof),
            }
        }
    }

    /// Runs a completion, delivering streaming chunks to `on_chunk` as they
    /// arrive, and returning the [`Final`] result. A [`Response::Error`] becomes a
    /// typed `Err` — a failed request never looks like a successful completion.
    ///
    /// # Errors
    /// [`ProtoError`] on a transport/decode failure or a sidecar-reported error.
    pub fn complete(
        &mut self,
        req: &CompleteRequest,
        mut on_chunk: impl FnMut(&str),
    ) -> Result<Final, ProtoError> {
        write_request(&mut self.w, &Request::Complete(req.clone()))?;
        loop {
            match read_response(&mut self.r)? {
                Some(Response::Chunk(t)) => on_chunk(t.as_str()),
                Some(Response::Final(f)) => return Ok(f),
                Some(Response::Error(e)) => return Err(ProtoError::Decode(e)),
                Some(other) => {
                    return Err(ProtoError::Decode(format!(
                        "unexpected response to complete: {other:?}"
                    )))
                }
                None => return Err(ProtoError::UnexpectedEof),
            }
        }
    }
}

/// A spawned `crustcore-net` helper process plus a client over its stdio. This is
/// how the trusted caller (the `net` feature of `crustcore`) reaches the model
/// transport: spawn the sidecar binary and talk the protocol over a pipe — the
/// same pattern as spawning `git`/`codex`/`claude`, linking **no HTTP/TLS**
/// (`docs/model-routing.md` §6).
pub struct SpawnedHelper {
    child: std::process::Child,
    helper: NetHelper<std::process::ChildStdin, std::io::BufReader<std::process::ChildStdout>>,
}

impl SpawnedHelper {
    /// Spawns `program args…` with piped stdin/stdout and returns a handle whose
    /// [`helper`](Self::helper) speaks the protocol to it. The child's stderr is
    /// inherited (diagnostics), never parsed as protocol.
    ///
    /// # Errors
    /// [`std::io::Error`] if the helper could not be spawned or its pipes taken.
    pub fn spawn(program: &str, args: &[&str]) -> std::io::Result<SpawnedHelper> {
        use std::process::{Command, Stdio};
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| std::io::Error::other("helper stdin unavailable"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::other("helper stdout unavailable"))?;
        Ok(SpawnedHelper {
            child,
            helper: NetHelper::new(stdin, std::io::BufReader::new(stdout)),
        })
    }

    /// The protocol client over the spawned helper's stdio.
    pub fn helper(
        &mut self,
    ) -> &mut NetHelper<std::process::ChildStdin, std::io::BufReader<std::process::ChildStdout>>
    {
        &mut self.helper
    }
}

impl Drop for SpawnedHelper {
    fn drop(&mut self) {
        // Best-effort teardown: kill and reap so the helper never lingers (the
        // sidecar would also exit on its stdin closing, but we do not depend on it).
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bt(s: &str) -> BoundedText {
        BoundedText::truncated(s, MAX_TEXT_BYTES)
    }

    #[test]
    fn complete_request_roundtrips_through_the_wire() {
        let req = Request::Complete(CompleteRequest {
            role: Role::Review,
            system: bt("be terse"),
            prompt: bt("fix the \"bug\"\nnow"),
            max_tokens: 256,
            stream: true,
            max_cost_micros: 50_000,
            require: Require {
                tools: true,
                min_context: 8192,
                local_only: false,
            },
        });
        let line = encode_request(&req);
        // Round-trips back to an equal request.
        let mut cur = std::io::Cursor::new(format!("{line}\n").into_bytes());
        let got = read_request(&mut cur).unwrap().unwrap();
        match got {
            Request::Complete(c) => {
                assert_eq!(c.role, Role::Review);
                assert_eq!(c.system.as_str(), "be terse");
                assert_eq!(c.prompt.as_str(), "fix the \"bug\"\nnow");
                assert_eq!(c.max_tokens, 256);
                assert!(c.stream);
                assert_eq!(c.max_cost_micros, 50_000);
                assert!(c.require.tools);
                assert_eq!(c.require.min_context, 8192);
                assert!(!c.require.local_only);
            }
            other => panic!("expected Complete, got {other:?}"),
        }
    }

    #[test]
    fn final_and_error_responses_roundtrip() {
        let fin = Response::Final(Final {
            text: bt("answer"),
            provider: "mock-a".into(),
            model: "m1".into(),
            usage: Usage {
                input_tokens: 12,
                output_tokens: 34,
                cost_micros: 120,
            },
            fallbacks: vec!["mock-b".into(), "mock-c".into()],
        });
        let mut cur = std::io::Cursor::new(format!("{}\n", encode_response(&fin)).into_bytes());
        match read_response(&mut cur).unwrap().unwrap() {
            Response::Final(f) => {
                assert_eq!(f.text.as_str(), "answer");
                assert_eq!(f.provider, "mock-a");
                assert_eq!(f.usage.output_tokens, 34);
                assert_eq!(f.fallbacks, vec!["mock-b", "mock-c"]);
            }
            other => panic!("expected Final, got {other:?}"),
        }

        let err = Response::Error("no model satisfies: local_only".into());
        let mut cur = std::io::Cursor::new(format!("{}\n", encode_response(&err)).into_bytes());
        match read_response(&mut cur).unwrap().unwrap() {
            Response::Error(e) => assert!(e.contains("local_only")),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn over_long_line_is_rejected_not_unbounded() {
        // A line with no newline, longer than the cap, is refused (bounded read).
        let big = vec![b'a'; MAX_LINE_BYTES + 10];
        let mut cur = std::io::Cursor::new(big);
        assert!(matches!(
            read_response(&mut cur),
            Err(ProtoError::Decode(_))
        ));
    }

    #[test]
    fn client_probe_reads_registry_until_end() {
        // Canned sidecar output: two models then registry_end.
        let mut out = String::new();
        out.push_str(&encode_response(&Response::Model(ModelInfo {
            provider: "mock-a".into(),
            model: "m1".into(),
            healthy: true,
            context: 8192,
            tools: true,
            structured: true,
            streaming: true,
            cost_per_1k_micros: 100,
        })));
        out.push('\n');
        out.push_str(&encode_response(&Response::RegistryEnd));
        out.push('\n');

        let sink: Vec<u8> = Vec::new();
        let reader = std::io::BufReader::new(std::io::Cursor::new(out.into_bytes()));
        let mut client = NetHelper::new(sink, reader);
        let models = client.probe().unwrap();
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].provider, "mock-a");
        assert!(models[0].healthy);
    }
}
