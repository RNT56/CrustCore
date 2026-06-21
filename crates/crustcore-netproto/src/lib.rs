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

/// Cap on registry entries a [`probe`](NetHelper::probe) will accept before
/// requiring `RegistryEnd`. A buggy/compromised helper streaming `Model` lines
/// forever must not OOM/hang the trusted caller (invariant 7; "bounded
/// everything"). Far above any realistic model count.
pub const MAX_REGISTRY_MODELS: usize = 4096;

/// Cap on the total streamed completion bytes a [`complete`](NetHelper::complete)
/// will accept before giving up. A helper streaming chunks forever must not hang
/// the caller. Bounds the *number* of reads, the same way [`MAX_LINE_BYTES`]
/// bounds a single read.
pub const MAX_STREAM_BYTES: usize = 8 * 1024 * 1024;

/// Cap on the number of inputs in a single embedding batch (`Request::Embed`) and
/// on the number of returned vectors (`Response::Embedding`). A hostile/buggy peer
/// cannot force unbounded allocation by sending a giant batch (invariant 7, 11;
/// "bounded everything"). Track C C1-providers.
pub const MAX_BATCH: usize = 256;

/// Cap on the number of documents in a single rerank request (`Request::Rerank`)
/// and on the number of returned ranking entries (`Response::Ranking`). Bounds the
/// rerank fan-out (invariant 7, 11). Track C C1-providers.
pub const MAX_DOCS: usize = 1024;

/// Cap on the dimensionality of a single embedding vector accepted on the wire. A
/// vector longer than this is truncated rather than read unbounded (invariant 11).
/// Comfortably above any realistic embedding size. Track C C1-providers.
pub const MAX_EMBEDDING_DIMS: usize = 16_384;

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

/// An embedding request (Track C C1-providers): embed a bounded batch of inputs.
/// The inputs are modeled as a `\n`-delimited string on the wire (the flat-JSON
/// codec carries scalars only), bounded by [`MAX_BATCH`] and [`MAX_TEXT_BYTES`].
#[derive(Debug, Clone)]
pub struct EmbedRequest {
    /// The abstract role to route for (resolved against embedding-capable models).
    pub role: Role,
    /// The inputs to embed (already bounded: at most [`MAX_BATCH`] entries, each at
    /// most [`MAX_TEXT_BYTES`]).
    pub inputs: Vec<String>,
    /// Hard cost ceiling in micros for this request (0 = unlimited).
    pub max_cost_micros: u64,
}

/// A rerank request (Track C C1-providers): score `documents` against `query`. The
/// documents are a `\n`-delimited string on the wire, bounded by [`MAX_DOCS`] and
/// [`MAX_TEXT_BYTES`].
#[derive(Debug, Clone)]
pub struct RerankRequest {
    /// The abstract role to route for (resolved against rerank-capable models).
    pub role: Role,
    /// The query to rank documents against (bounded).
    pub query: String,
    /// The candidate documents (already bounded: at most [`MAX_DOCS`] entries, each
    /// at most [`MAX_TEXT_BYTES`]).
    pub documents: Vec<String>,
    /// Hard cost ceiling in micros for this request (0 = unlimited).
    pub max_cost_micros: u64,
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
    /// Embed a batch; respond with a [`Response::Embedding`] or a
    /// [`Response::Error`] (Track C C1-providers).
    Embed(EmbedRequest),
    /// Rerank documents; respond with a [`Response::Ranking`] or a
    /// [`Response::Error`] (Track C C1-providers).
    Rerank(RerankRequest),
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
    /// Embedding support (additive, default off — Track C C1-providers). A model
    /// that does not declare it is never routed an embedding request (invariant 17:
    /// capability fails closed, never on by omission).
    pub embeddings: bool,
    /// Rerank support (additive, default off — Track C C1-providers). Fails closed
    /// the same way `embeddings` does.
    pub rerank: bool,
    /// Embedding dimensionality, or `0` when unknown / not an embedding model
    /// (additive, default `0` — Track C C1-providers).
    pub embedding_dims: u32,
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

/// The result of an embedding request (Track C C1-providers). One vector per input,
/// each a bounded `Vec<f32>` (at most [`MAX_BATCH`] vectors, each at most
/// [`MAX_EMBEDDING_DIMS`] elements). Non-finite floats are sanitized to `0.0` on the
/// wire so a hostile provider cannot smuggle NaN/Inf into downstream selection.
#[derive(Debug, Clone, PartialEq)]
pub struct EmbeddingResult {
    /// One embedding vector per input.
    pub vectors: Vec<Vec<f32>>,
    /// Usage/cost for the served request.
    pub usage: Usage,
    /// The provider that served it.
    pub provider: String,
    /// The model that served it.
    pub model: String,
    /// Providers tried (and failed) before this one succeeded.
    pub fallbacks: Vec<String>,
}

/// The result of a rerank request (Track C C1-providers): document indices paired
/// with scores, highest-relevance first. Indices are validated against the request's
/// document count by the adapter; out-of-range/duplicate indices are clamped or
/// dropped, never propagated raw. Bounded by [`MAX_DOCS`].
#[derive(Debug, Clone, PartialEq)]
pub struct RankingResult {
    /// `(document_index, score)` pairs (typically sorted by descending score).
    pub ranking: Vec<(u32, f32)>,
    /// Usage/cost for the served request.
    pub usage: Usage,
    /// The provider that served it.
    pub provider: String,
    /// The model that served it.
    pub model: String,
    /// Providers tried (and failed) before this one succeeded.
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
    /// An embedding result (in reply to [`Request::Embed`]) — Track C C1-providers.
    Embedding(EmbeddingResult),
    /// A rerank result (in reply to [`Request::Rerank`]) — Track C C1-providers.
    Ranking(RankingResult),
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
        Request::Embed(e) => {
            o.str("kind", "embed");
            o.str("role", e.role.as_str());
            o.int("count", clamp_count(e.inputs.len(), MAX_BATCH));
            o.str("inputs", &encode_texts(&e.inputs, MAX_BATCH));
            o.uint("max_cost_micros", e.max_cost_micros);
        }
        Request::Rerank(r) => {
            o.str("kind", "rerank");
            o.str("role", r.role.as_str());
            o.str("query", &r.query);
            o.int("count", clamp_count(r.documents.len(), MAX_DOCS));
            o.str("documents", &encode_texts(&r.documents, MAX_DOCS));
            o.uint("max_cost_micros", r.max_cost_micros);
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
            // Additive capability flags (Track C C1-providers). Always emitted; the
            // decoder defaults them off when absent (forward/backward compatible).
            o.bool("embeddings", m.embeddings);
            o.bool("rerank", m.rerank);
            o.int("embedding_dims", i64::from(m.embedding_dims));
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
        Response::Embedding(e) => {
            o.str("kind", "embedding");
            o.int("count", clamp_count(e.vectors.len(), MAX_BATCH));
            o.str("vectors", &encode_vectors(&e.vectors));
            o.str("provider", &e.provider);
            o.str("model", &e.model);
            o.int("input_tokens", i64::from(e.usage.input_tokens));
            o.int("output_tokens", i64::from(e.usage.output_tokens));
            o.uint("cost_micros", e.usage.cost_micros);
            o.str("fallbacks", &e.fallbacks.join(","));
        }
        Response::Ranking(r) => {
            o.str("kind", "ranking");
            o.int("count", clamp_count(r.ranking.len(), MAX_DOCS));
            o.str("ranking", &encode_ranking(&r.ranking));
            o.str("provider", &r.provider);
            o.str("model", &r.model);
            o.int("input_tokens", i64::from(r.usage.input_tokens));
            o.int("output_tokens", i64::from(r.usage.output_tokens));
            o.uint("cost_micros", r.usage.cost_micros);
            o.str("fallbacks", &r.fallbacks.join(","));
        }
        Response::Error(reason) => {
            o.str("kind", "error");
            o.str("reason", reason);
        }
    }
    o.finish()
}

// ---------------------------------------------------------------------------
// Multi-modal payload codec (delimited strings — Track C C1-providers)
//
// The flat-JSON codec carries scalars only, so list-of-list / list-of-pair
// payloads are encoded as bounded delimited strings (the same approach `fallbacks`
// uses for `Vec<String>`). All counts/dims are clamped on encode, and every value
// is bounded + sanitized on decode so a hostile peer cannot over-allocate, panic,
// or smuggle a non-finite float into downstream selection (invariants 7, 11).
// ---------------------------------------------------------------------------

/// Clamp a length to an `i64` count field, never above `max`.
fn clamp_count(len: usize, max: usize) -> i64 {
    len.min(max) as i64
}

/// Format a single `f32` so it round-trips exactly for finite values; non-finite
/// (NaN/±Inf) is sanitized to `0`.
fn fmt_f32(x: f32) -> String {
    if x.is_finite() {
        x.to_string()
    } else {
        "0".to_string()
    }
}

/// Parse a single `f32`; a malformed or non-finite token decodes to `0.0` (untrusted
/// data — skip, never panic).
fn parse_f32(s: &str) -> f32 {
    match s.parse::<f32>() {
        Ok(x) if x.is_finite() => x,
        _ => 0.0,
    }
}

/// Encode a bounded batch of texts as a `\n`-delimited string (each text already
/// bounded by the caller); at most `max` entries are emitted. A `\n` inside an entry
/// is escaped to keep the delimiter unambiguous; the matching decoder unescapes it.
fn encode_texts(texts: &[String], max: usize) -> String {
    let mut out = String::new();
    for (i, t) in texts.iter().take(max).enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&escape_delim(t));
    }
    out
}

/// Decode a `\n`-delimited batch of texts, bounded by `max` entries and
/// [`MAX_TEXT_BYTES`] per entry. An empty string decodes to an empty batch.
fn decode_texts(s: &str, max: usize) -> Vec<String> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split('\n')
        .take(max)
        .map(|t| {
            let un = unescape_delim(t);
            bound_text(&un)
        })
        .collect()
}

/// Escape `\` and `\n` so a multi-line text survives `\n`-joining.
fn escape_delim(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

/// Inverse of [`escape_delim`].
fn unescape_delim(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('\\') => out.push('\\'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Bound a text to [`MAX_TEXT_BYTES`] on a char boundary.
fn bound_text(s: &str) -> String {
    if s.len() <= MAX_TEXT_BYTES {
        return s.to_string();
    }
    let mut end = MAX_TEXT_BYTES;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Encode `Vec<Vec<f32>>` as `;`-separated vectors, each `,`-separated f32, bounded
/// by [`MAX_BATCH`] vectors and [`MAX_EMBEDDING_DIMS`] dims.
fn encode_vectors(vectors: &[Vec<f32>]) -> String {
    let mut out = String::new();
    for (i, v) in vectors.iter().take(MAX_BATCH).enumerate() {
        if i > 0 {
            out.push(';');
        }
        for (j, x) in v.iter().take(MAX_EMBEDDING_DIMS).enumerate() {
            if j > 0 {
                out.push(',');
            }
            out.push_str(&fmt_f32(*x));
        }
    }
    out
}

/// Decode the [`encode_vectors`] format, bounded the same way on the way back in.
fn decode_vectors(s: &str) -> Vec<Vec<f32>> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split(';')
        .take(MAX_BATCH)
        .map(|v| {
            if v.is_empty() {
                Vec::new()
            } else {
                v.split(',')
                    .take(MAX_EMBEDDING_DIMS)
                    .map(parse_f32)
                    .collect()
            }
        })
        .collect()
}

/// Encode `Vec<(u32, f32)>` as `;`-separated `index,score` pairs, bounded by
/// [`MAX_DOCS`].
fn encode_ranking(ranking: &[(u32, f32)]) -> String {
    let mut out = String::new();
    for (i, (idx, score)) in ranking.iter().take(MAX_DOCS).enumerate() {
        if i > 0 {
            out.push(';');
        }
        out.push_str(&idx.to_string());
        out.push(',');
        out.push_str(&fmt_f32(*score));
    }
    out
}

/// Decode the [`encode_ranking`] format. A malformed pair (missing score, bad index)
/// is skipped, never panicked on; bounded by [`MAX_DOCS`].
fn decode_ranking(s: &str) -> Vec<(u32, f32)> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split(';')
        .take(MAX_DOCS)
        .filter_map(|pair| {
            let (idx_s, score_s) = pair.split_once(',')?;
            let idx = idx_s.trim().parse::<u32>().ok()?;
            Some((idx, parse_f32(score_s.trim())))
        })
        .collect()
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
            // Enforce the cap on the newline branch too: a `BufRead` that returns
            // the whole remainder in one `fill_buf` (e.g. a `Cursor`) would
            // otherwise let a giant newline-terminated line slip past the cap.
            if total + pos > max {
                return Err(ProtoError::Decode(
                    "protocol line exceeds the byte cap".into(),
                ));
            }
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
        Some("embed") => Ok(Request::Embed(EmbedRequest {
            role: Role::from_token(f.str("role").unwrap_or("implementation")),
            inputs: decode_texts(f.str("inputs").unwrap_or(""), MAX_BATCH),
            max_cost_micros: f.uint("max_cost_micros").unwrap_or(0),
        })),
        Some("rerank") => Ok(Request::Rerank(RerankRequest {
            role: Role::from_token(f.str("role").unwrap_or("implementation")),
            query: bound_text(f.str("query").unwrap_or("")),
            documents: decode_texts(f.str("documents").unwrap_or(""), MAX_DOCS),
            max_cost_micros: f.uint("max_cost_micros").unwrap_or(0),
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
            // Additive capability fields default OFF when the key is absent — a
            // probe from an older/forgetful helper fails closed, never flips a
            // capability on by omission (invariant 17; Track C C1-providers).
            embeddings: f.bool("embeddings").unwrap_or(false),
            rerank: f.bool("rerank").unwrap_or(false),
            embedding_dims: f.uint("embedding_dims").unwrap_or(0) as u32,
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
        Some("embedding") => Ok(Response::Embedding(EmbeddingResult {
            vectors: decode_vectors(f.str("vectors").unwrap_or("")),
            usage: Usage {
                input_tokens: f.uint("input_tokens").unwrap_or(0) as u32,
                output_tokens: f.uint("output_tokens").unwrap_or(0) as u32,
                cost_micros: f.uint("cost_micros").unwrap_or(0),
            },
            provider: f.str("provider").unwrap_or("").to_string(),
            model: f.str("model").unwrap_or("").to_string(),
            fallbacks: split_csv(f.str("fallbacks").unwrap_or("")),
        })),
        Some("ranking") => Ok(Response::Ranking(RankingResult {
            ranking: decode_ranking(f.str("ranking").unwrap_or("")),
            usage: Usage {
                input_tokens: f.uint("input_tokens").unwrap_or(0) as u32,
                output_tokens: f.uint("output_tokens").unwrap_or(0) as u32,
                cost_micros: f.uint("cost_micros").unwrap_or(0),
            },
            provider: f.str("provider").unwrap_or("").to_string(),
            model: f.str("model").unwrap_or("").to_string(),
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
                Some(Response::Model(m)) => {
                    // Bound the registry: a helper that never sends RegistryEnd
                    // must not grow this unboundedly (invariant 7).
                    if models.len() >= MAX_REGISTRY_MODELS {
                        return Err(ProtoError::Decode(
                            "registry exceeded the model cap before RegistryEnd".into(),
                        ));
                    }
                    models.push(m);
                }
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
        let mut streamed: usize = 0;
        loop {
            match read_response(&mut self.r)? {
                Some(Response::Chunk(t)) => {
                    // Bound the total stream: a helper streaming chunks forever
                    // must not hang the caller (invariant 7).
                    streamed = streamed.saturating_add(t.len());
                    if streamed > MAX_STREAM_BYTES {
                        return Err(ProtoError::Decode(
                            "completion stream exceeded the byte cap before Final".into(),
                        ));
                    }
                    on_chunk(t.as_str());
                }
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

    /// Embeds a batch of inputs, returning the [`EmbeddingResult`]. A
    /// [`Response::Error`] becomes a typed `Err` — a failed request never looks like
    /// success. The reply is single-shot (no streaming), so this reads exactly one
    /// response line (Track C C1-providers).
    ///
    /// # Errors
    /// [`ProtoError`] on a transport/decode failure or a sidecar-reported error.
    pub fn embed(&mut self, req: &EmbedRequest) -> Result<EmbeddingResult, ProtoError> {
        write_request(&mut self.w, &Request::Embed(req.clone()))?;
        match read_response(&mut self.r)? {
            Some(Response::Embedding(e)) => Ok(e),
            Some(Response::Error(e)) => Err(ProtoError::Decode(e)),
            Some(other) => Err(ProtoError::Decode(format!(
                "unexpected response to embed: {other:?}"
            ))),
            None => Err(ProtoError::UnexpectedEof),
        }
    }

    /// Reranks `documents` against `query`, returning the [`RankingResult`]. A
    /// [`Response::Error`] becomes a typed `Err`. Single-shot reply (Track C
    /// C1-providers).
    ///
    /// # Errors
    /// [`ProtoError`] on a transport/decode failure or a sidecar-reported error.
    pub fn rerank(&mut self, req: &RerankRequest) -> Result<RankingResult, ProtoError> {
        write_request(&mut self.w, &Request::Rerank(req.clone()))?;
        match read_response(&mut self.r)? {
            Some(Response::Ranking(r)) => Ok(r),
            Some(Response::Error(e)) => Err(ProtoError::Decode(e)),
            Some(other) => Err(ProtoError::Decode(format!(
                "unexpected response to rerank: {other:?}"
            ))),
            None => Err(ProtoError::UnexpectedEof),
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
    fn over_long_newline_terminated_line_is_rejected() {
        // The newline branch must enforce the cap too: a `Cursor` returns the whole
        // slice from one fill_buf, so a giant newline-terminated line would slip
        // past a cap that only guards the no-newline branch.
        let mut big = vec![b'a'; MAX_LINE_BYTES + 10];
        big.push(b'\n');
        let mut cur = std::io::Cursor::new(big);
        assert!(matches!(
            read_response(&mut cur),
            Err(ProtoError::Decode(_))
        ));
    }

    #[test]
    fn probe_rejects_a_helper_that_never_ends_the_registry() {
        // A misbehaving helper streams Model lines past the cap without RegistryEnd:
        // the caller must reject, not grow unboundedly (invariant 7).
        let one = encode_response(&Response::Model(ModelInfo {
            provider: "p".into(),
            model: "m".into(),
            healthy: true,
            context: 1,
            tools: false,
            structured: false,
            streaming: false,
            cost_per_1k_micros: 0,
            embeddings: false,
            rerank: false,
            embedding_dims: 0,
        }));
        let mut out = String::with_capacity((one.len() + 1) * (MAX_REGISTRY_MODELS + 8));
        for _ in 0..MAX_REGISTRY_MODELS + 5 {
            out.push_str(&one);
            out.push('\n');
        }
        let reader = std::io::BufReader::new(std::io::Cursor::new(out.into_bytes()));
        let mut client = NetHelper::new(Vec::new(), reader);
        assert!(matches!(client.probe(), Err(ProtoError::Decode(_))));
    }

    #[test]
    fn complete_rejects_an_unbounded_chunk_stream() {
        // A helper streaming chunks past the total cap without Final is rejected.
        let chunk = encode_response(&Response::Chunk(bt(&"a".repeat(MAX_TEXT_BYTES))));
        let n = MAX_STREAM_BYTES / MAX_TEXT_BYTES + 2;
        let mut out = String::with_capacity((chunk.len() + 1) * n);
        for _ in 0..n {
            out.push_str(&chunk);
            out.push('\n');
        }
        let reader = std::io::BufReader::new(std::io::Cursor::new(out.into_bytes()));
        let mut client = NetHelper::new(Vec::new(), reader);
        let req = CompleteRequest {
            role: Role::Implementation,
            system: bt(""),
            prompt: bt("x"),
            max_tokens: 1,
            stream: true,
            max_cost_micros: 0,
            require: Require::default(),
        };
        let mut seen = 0usize;
        let r = client.complete(&req, |c| seen += c.len());
        assert!(matches!(r, Err(ProtoError::Decode(_))));
        // It stopped near the cap, not after consuming everything unboundedly.
        assert!(seen <= MAX_STREAM_BYTES + MAX_TEXT_BYTES);
    }

    // ---- Track C C1-providers: additive ModelInfo + multi-modal wire ----

    fn model_info_full() -> ModelInfo {
        ModelInfo {
            provider: "p".into(),
            model: "m".into(),
            healthy: true,
            context: 8192,
            tools: true,
            structured: true,
            streaming: true,
            cost_per_1k_micros: 100,
            embeddings: true,
            rerank: true,
            embedding_dims: 1536,
        }
    }

    #[test]
    fn model_info_with_capability_flags_roundtrips() {
        let m = Response::Model(model_info_full());
        let mut cur = std::io::Cursor::new(format!("{}\n", encode_response(&m)).into_bytes());
        match read_response(&mut cur).unwrap().unwrap() {
            Response::Model(got) => assert_eq!(got, model_info_full()),
            other => panic!("expected Model, got {other:?}"),
        }
    }

    #[test]
    fn model_decode_defaults_capability_keys_off_when_absent() {
        // A `model` line lacking the new keys (an older/forgetful helper) must decode
        // with embeddings=false / rerank=false / embedding_dims=0 (invariant 17:
        // capability fails closed, never on by omission).
        let line = r#"{"kind":"model","provider":"p","model":"m","healthy":true,"context":8192,"tools":true,"structured":true,"streaming":true,"cost_per_1k_micros":100}"#;
        let mut cur = std::io::Cursor::new(format!("{line}\n").into_bytes());
        match read_response(&mut cur).unwrap().unwrap() {
            Response::Model(m) => {
                assert!(!m.embeddings);
                assert!(!m.rerank);
                assert_eq!(m.embedding_dims, 0);
                // Existing fields still decode unchanged.
                assert_eq!(m.context, 8192);
                assert!(m.tools);
            }
            other => panic!("expected Model, got {other:?}"),
        }
    }

    #[test]
    fn embed_request_and_embedding_response_roundtrip() {
        let req = Request::Embed(EmbedRequest {
            role: Role::Research,
            inputs: vec!["hello".into(), "line\none\\two".into(), "café π".into()],
            max_cost_micros: 9_000,
        });
        let mut cur = std::io::Cursor::new(format!("{}\n", encode_request(&req)).into_bytes());
        match read_request(&mut cur).unwrap().unwrap() {
            Request::Embed(e) => {
                assert_eq!(e.role, Role::Research);
                assert_eq!(e.inputs, vec!["hello", "line\none\\two", "café π"]);
                assert_eq!(e.max_cost_micros, 9_000);
            }
            other => panic!("expected Embed, got {other:?}"),
        }

        let resp = Response::Embedding(EmbeddingResult {
            vectors: vec![vec![0.5, -1.25, 0.0], vec![3.0]],
            usage: Usage {
                input_tokens: 7,
                output_tokens: 0,
                cost_micros: 42,
            },
            provider: "emb-a".into(),
            model: "e1".into(),
            fallbacks: vec!["emb-b".into()],
        });
        let mut cur = std::io::Cursor::new(format!("{}\n", encode_response(&resp)).into_bytes());
        match read_response(&mut cur).unwrap().unwrap() {
            Response::Embedding(e) => {
                assert_eq!(e.vectors, vec![vec![0.5, -1.25, 0.0], vec![3.0]]);
                assert_eq!(e.usage.input_tokens, 7);
                assert_eq!(e.usage.cost_micros, 42);
                assert_eq!(e.provider, "emb-a");
                assert_eq!(e.fallbacks, vec!["emb-b"]);
            }
            other => panic!("expected Embedding, got {other:?}"),
        }
    }

    #[test]
    fn rerank_request_and_ranking_response_roundtrip() {
        let req = Request::Rerank(RerankRequest {
            role: Role::Review,
            query: "find the bug".into(),
            documents: vec!["doc a".into(), "doc, b".into(), "doc;c".into()],
            max_cost_micros: 0,
        });
        let mut cur = std::io::Cursor::new(format!("{}\n", encode_request(&req)).into_bytes());
        match read_request(&mut cur).unwrap().unwrap() {
            Request::Rerank(r) => {
                assert_eq!(r.query, "find the bug");
                assert_eq!(r.documents, vec!["doc a", "doc, b", "doc;c"]);
            }
            other => panic!("expected Rerank, got {other:?}"),
        }

        let resp = Response::Ranking(RankingResult {
            ranking: vec![(2, 0.99), (0, 0.5), (1, -0.1)],
            usage: Usage::default(),
            provider: "rr-a".into(),
            model: "r1".into(),
            fallbacks: vec![],
        });
        let mut cur = std::io::Cursor::new(format!("{}\n", encode_response(&resp)).into_bytes());
        match read_response(&mut cur).unwrap().unwrap() {
            Response::Ranking(r) => {
                assert_eq!(r.ranking, vec![(2, 0.99), (0, 0.5), (1, -0.1)]);
                assert_eq!(r.provider, "rr-a");
            }
            other => panic!("expected Ranking, got {other:?}"),
        }
    }

    #[test]
    fn embedding_codec_sanitizes_non_finite_floats() {
        let resp = Response::Embedding(EmbeddingResult {
            vectors: vec![vec![f32::NAN, f32::INFINITY, f32::NEG_INFINITY, 1.0]],
            usage: Usage::default(),
            provider: "p".into(),
            model: "m".into(),
            fallbacks: vec![],
        });
        let mut cur = std::io::Cursor::new(format!("{}\n", encode_response(&resp)).into_bytes());
        match read_response(&mut cur).unwrap().unwrap() {
            Response::Embedding(e) => {
                // NaN/±Inf are sanitized to 0.0; the finite value survives.
                assert_eq!(e.vectors, vec![vec![0.0, 0.0, 0.0, 1.0]]);
                assert!(e.vectors[0].iter().all(|x| x.is_finite()));
            }
            other => panic!("expected Embedding, got {other:?}"),
        }
    }

    #[test]
    fn embed_batch_is_bounded_on_the_wire() {
        // An over-MAX_BATCH batch is clamped to MAX_BATCH on encode, and the decoder
        // also caps at MAX_BATCH — no unbounded allocation (invariant 11).
        let inputs: Vec<String> = (0..MAX_BATCH + 50).map(|i| format!("t{i}")).collect();
        let req = Request::Embed(EmbedRequest {
            role: Role::Research,
            inputs,
            max_cost_micros: 0,
        });
        let mut cur = std::io::Cursor::new(format!("{}\n", encode_request(&req)).into_bytes());
        match read_request(&mut cur).unwrap().unwrap() {
            Request::Embed(e) => assert_eq!(e.inputs.len(), MAX_BATCH),
            other => panic!("expected Embed, got {other:?}"),
        }
    }

    #[test]
    fn malformed_ranking_pairs_are_skipped_not_panicked() {
        // Hand-crafted ranking string with garbage entries; the decoder drops the bad
        // ones and keeps the valid pair (untrusted data — no panic).
        let line = r#"{"kind":"ranking","count":3,"ranking":"notapair;5,0.7;bad,score","provider":"p","model":"m","input_tokens":0,"output_tokens":0,"cost_micros":0,"fallbacks":""}"#;
        let mut cur = std::io::Cursor::new(format!("{line}\n").into_bytes());
        match read_response(&mut cur).unwrap().unwrap() {
            Response::Ranking(r) => assert_eq!(r.ranking, vec![(5, 0.7)]),
            other => panic!("expected Ranking, got {other:?}"),
        }
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
            embeddings: false,
            rerank: false,
            embedding_dims: 0,
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
