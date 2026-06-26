// SPDX-License-Identifier: Apache-2.0
//! The repo [`Chunker`] (C5.4): splits in-memory `(path, content)` into **bounded**
//! fragments, each tagged with a pure-data [`ChunkMeta`].
//!
//! **The safe path is the easy path.** With no symbol info the chunker defaults to
//! whole-line, bounded, deny-large chunking (fail-safe; adversarial dimension (d)):
//! - every fragment is bounded to [`MAX_CHUNK_BYTES`] — a hostile file with one giant line
//!   cannot produce an unbounded chunk (it is split mid-line at a UTF-8 boundary);
//! - chunks never split a line across two fragments unless a single line alone exceeds the
//!   cap;
//! - `ChunkMeta.redact_required` defaults to `true` and `symbol` to `None`.
//!
//! It operates on in-memory `(path, content)` so it is fully testable; the live indexer
//! reads the content via confined paths (`index.rs`).

use crustcore_index::MemorySource;

use crate::store::{ByteSpan, ChunkId, ChunkMeta};

/// Maximum bytes in a single chunk's content (bounded; invariant 11). A line longer than
/// this is split at a UTF-8 char boundary so no fragment is ever unbounded.
pub const MAX_CHUNK_BYTES: usize = 2 * 1024;

/// Default target chunk size (lines are accumulated until adding the next would exceed
/// this). Must be `<= MAX_CHUNK_BYTES`.
pub const DEFAULT_TARGET_BYTES: usize = 1024;

/// Default overlap in bytes carried from the end of one chunk into the next, improving
/// retrieval recall across chunk boundaries. Bounded well below the target.
pub const DEFAULT_OVERLAP_BYTES: usize = 128;

/// Maximum number of chunks produced from a single file (bounded fan-out; a hostile huge
/// file cannot blow up the index). Excess content is dropped (deny-large).
pub const MAX_CHUNKS_PER_FILE: usize = 4 * 1024;

/// A produced chunk: its id, its content (untrusted; NOT yet redacted — redaction happens
/// at the model boundary in the planner), and its pure-data metadata tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    /// Stable id (derived from path + byte span; bounded).
    pub id: ChunkId,
    /// The raw chunk content (untrusted data; bounded to [`MAX_CHUNK_BYTES`]).
    pub content: String,
    /// Pure-data metadata (no capability/approval field).
    pub meta: ChunkMeta,
}

/// Bounded, fail-safe repo chunker.
#[derive(Debug, Clone)]
pub struct Chunker {
    target_bytes: usize,
    overlap_bytes: usize,
    max_chunk_bytes: usize,
}

impl Default for Chunker {
    fn default() -> Self {
        Chunker::new()
    }
}

impl Chunker {
    /// A chunker with the conservative defaults (target [`DEFAULT_TARGET_BYTES`], overlap
    /// [`DEFAULT_OVERLAP_BYTES`], hard cap [`MAX_CHUNK_BYTES`]).
    #[must_use]
    pub fn new() -> Self {
        Chunker {
            target_bytes: DEFAULT_TARGET_BYTES,
            overlap_bytes: DEFAULT_OVERLAP_BYTES,
            max_chunk_bytes: MAX_CHUNK_BYTES,
        }
    }

    /// Sets the target chunk size, clamped to `[1, MAX_CHUNK_BYTES]` (so a caller can
    /// never widen past the hard cap — fail-safe).
    #[must_use]
    pub fn with_target_bytes(mut self, target: usize) -> Self {
        self.target_bytes = target.clamp(1, self.max_chunk_bytes);
        self
    }

    /// Sets the overlap, clamped to `[0, target_bytes - 1]` so it can never starve forward
    /// progress (overlap < target guarantees termination).
    #[must_use]
    pub fn with_overlap_bytes(mut self, overlap: usize) -> Self {
        self.overlap_bytes = overlap.min(self.target_bytes.saturating_sub(1));
        self
    }

    /// The hard per-chunk byte cap.
    #[must_use]
    pub fn max_chunk_bytes(&self) -> usize {
        self.max_chunk_bytes
    }

    /// Chunks `content` (from `path`) into bounded, line-oriented fragments — the
    /// **default fail-safe** strategy used whenever no symbol info is available. Every
    /// returned chunk's content is `<= MAX_CHUNK_BYTES`; `ChunkMeta` defaults to
    /// `redact_required = true`, `symbol = None`, `source = source`.
    #[must_use]
    pub fn chunk(&self, path: &str, content: &str, source: MemorySource) -> Vec<Chunk> {
        let units = self.line_units(content);
        self.assemble(path, content, &units, source, None)
    }

    /// Shared assembler: given byte-span "units" (lines, or symbol spans) over `content`,
    /// pack them into bounded chunks with overlap. `symbol` is applied to every chunk's
    /// meta when present (symbol-aware mode); `None` is the line-chunk fallback.
    ///
    /// Each unit is itself bounded to the hard cap first (a single oversized line/span is
    /// split at UTF-8 boundaries), so the output is unconditionally bounded regardless of
    /// the input — the deny-large guarantee (dimension (d)).
    pub(crate) fn assemble(
        &self,
        path: &str,
        content: &str,
        units: &[(usize, usize)],
        source: MemorySource,
        symbol: Option<&str>,
    ) -> Vec<Chunk> {
        let mut chunks = Vec::new();
        let bytes = content.as_bytes();

        // Flatten units into bounded sub-units so no single piece exceeds the hard cap.
        let mut bounded: Vec<(usize, usize)> = Vec::new();
        for &(start, end) in units {
            let (start, end) = (start.min(bytes.len()), end.min(bytes.len()));
            if end <= start {
                continue;
            }
            let mut s = start;
            while s < end {
                let mut e = (s + self.max_chunk_bytes).min(end);
                e = floor_char_boundary(content, e).max(s + 1).min(end);
                e = floor_char_boundary(content, e);
                if e <= s {
                    // Cannot make progress on a char boundary within the cap; advance past
                    // the next boundary to avoid an infinite loop (still bounded above).
                    e = next_char_boundary(content, s).min(end);
                }
                bounded.push((s, e));
                s = e;
            }
        }

        // Greedily pack bounded sub-units into chunks up to `target_bytes`, carrying a
        // bounded overlap (in units) into the next chunk for recall across boundaries.
        let mut i = 0;
        while i < bounded.len() {
            if chunks.len() >= MAX_CHUNKS_PER_FILE {
                break; // deny-large: bounded fan-out.
            }
            let chunk_start = bounded[i].0;
            let mut chunk_end = bounded[i].1;
            let mut j = i + 1;
            while j < bounded.len() {
                let candidate_end = bounded[j].1;
                if candidate_end - chunk_start > self.target_bytes {
                    break;
                }
                chunk_end = candidate_end;
                j += 1;
            }
            // Safety net: never exceed the hard cap even after packing.
            if chunk_end - chunk_start > self.max_chunk_bytes {
                chunk_end = floor_char_boundary(content, chunk_start + self.max_chunk_bytes)
                    .max(chunk_start + 1);
                chunk_end = floor_char_boundary(content, chunk_end);
            }
            let span = ByteSpan::new(chunk_start, chunk_end);
            let text = &content[span.start..span.end];
            let mut meta = ChunkMeta::new(path, span, source);
            if let Some(sym) = symbol {
                meta = meta.with_symbol(sym);
            }
            chunks.push(Chunk {
                id: ChunkId::new(format!("{path}#{}-{}", span.start, span.end)),
                content: text.to_string(),
                meta,
            });

            // Advance with overlap: step back so the next chunk re-includes up to
            // `overlap_bytes` of the previous one (clamped to make forward progress).
            let consumed_end = chunk_end;
            let next_start = consumed_end.saturating_sub(self.overlap_bytes);
            // Find the first bounded sub-unit that starts at or after next_start but
            // strictly after chunk_start (guarantees progress).
            let mut next_i = j;
            for (k, &(s, _)) in bounded.iter().enumerate().take(j).skip(i) {
                if s >= next_start && s > chunk_start {
                    next_i = k;
                    break;
                }
            }
            i = next_i.max(i + 1);
        }
        chunks
    }

    /// Byte spans of each line (including its trailing newline) over `content`. A trailing
    /// non-newline-terminated segment is its own unit.
    fn line_units(&self, content: &str) -> Vec<(usize, usize)> {
        let mut units = Vec::new();
        let bytes = content.as_bytes();
        let mut start = 0;
        for (i, &b) in bytes.iter().enumerate() {
            if b == b'\n' {
                units.push((start, i + 1));
                start = i + 1;
            }
        }
        if start < bytes.len() {
            units.push((start, bytes.len()));
        }
        units
    }
}

/// The greatest char-boundary index `<= i` (`i` is clamped to the string length).
fn floor_char_boundary(s: &str, i: usize) -> usize {
    let mut i = i.min(s.len());
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

/// The least char-boundary index `> i` (or the string length).
fn next_char_boundary(s: &str, i: usize) -> usize {
    let mut i = (i + 1).min(s.len());
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

#[cfg(feature = "ast")]
pub mod ast;
pub mod symbol;

impl Chunker {
    /// **AST-aware chunking (C5-ast; `ast` feature only).** Parses `content` with
    /// tree-sitter (grammar chosen from `path`'s extension), aligns chunk boundaries to the
    /// precise byte spans of top-level items, and tags each with its symbol name. On any
    /// failure — unsupported extension, oversize input, parse error, or no recognized items
    /// — it falls back to the conservative line-chunking of
    /// [`Chunker::chunk`](Self::chunk). It never relaxes a bound and never panics on hostile
    /// input. The default (non-`ast`) behavior is unaffected; callers without the feature
    /// keep using `chunk` / [`chunk_with_symbols`](Self::chunk_with_symbols).
    #[cfg(feature = "ast")]
    #[must_use]
    pub fn chunk_with_ast_symbols(
        &self,
        path: &str,
        content: &str,
        source: crustcore_index::MemorySource,
    ) -> Vec<Chunk> {
        let spans = ast::ast_symbol_spans(path, content);
        // `chunk_with_symbols` already falls back to `chunk` when `spans` is empty, so an
        // unsupported/failed parse degrades to the exact line-chunk default.
        self.chunk_with_symbols(path, content, source, &spans)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_fragment_is_bounded_to_max_chunk_bytes() {
        // A hostile file: one enormous line with no newline, far over the cap.
        let giant_line = "x".repeat(MAX_CHUNK_BYTES * 5 + 17);
        let chunker = Chunker::new();
        let chunks = chunker.chunk("hostile.txt", &giant_line, MemorySource::RepoFile);
        assert!(!chunks.is_empty());
        for c in &chunks {
            assert!(
                c.content.len() <= MAX_CHUNK_BYTES,
                "fragment exceeded the hard cap: {} > {}",
                c.content.len(),
                MAX_CHUNK_BYTES
            );
            // Fail-safe defaults on every chunk (dimension (d)).
            assert!(
                c.meta.redact_required,
                "redact_required must default to true"
            );
            assert!(c.meta.symbol.is_none(), "line-chunk fallback has no symbol");
            assert_eq!(c.meta.source, MemorySource::RepoFile);
        }
    }

    #[test]
    fn line_chunk_fallback_is_the_default_and_covers_content() {
        let content = "fn a() {}\nfn b() {}\nfn c() {}\n";
        let chunker = Chunker::new();
        let chunks = chunker.chunk("src/lib.rs", content, MemorySource::RepoFile);
        assert!(!chunks.is_empty());
        // Concatenating chunk spans (accounting for overlap) covers the file: the union of
        // spans reaches the end of the content.
        let max_end = chunks.iter().map(|c| c.meta.byte_span.end).max().unwrap();
        assert_eq!(max_end, content.len());
        // Char-boundary safety on multibyte content.
        let utf8 = "café\nnaïve\nrésumé\n".repeat(200);
        let cs = chunker.chunk("u.txt", &utf8, MemorySource::RepoFile);
        for c in &cs {
            assert!(utf8.is_char_boundary(c.meta.byte_span.start));
            assert!(utf8.is_char_boundary(c.meta.byte_span.end));
            assert!(c.content.len() <= MAX_CHUNK_BYTES);
        }
    }

    #[test]
    fn chunk_ids_are_stable_and_span_derived() {
        let content = "line one\nline two\n";
        let chunker = Chunker::new();
        let a = chunker.chunk("p.rs", content, MemorySource::RepoFile);
        let b = chunker.chunk("p.rs", content, MemorySource::RepoFile);
        assert_eq!(a, b, "chunking is deterministic");
        for c in &a {
            assert!(c.id.as_str().starts_with("p.rs#"));
        }
    }

    #[test]
    fn empty_and_whitespace_content_are_safe() {
        let chunker = Chunker::new();
        assert!(chunker.chunk("e.rs", "", MemorySource::RepoFile).is_empty());
        let only_nl = chunker.chunk("n.rs", "\n\n\n", MemorySource::RepoFile);
        for c in &only_nl {
            assert!(c.content.len() <= MAX_CHUNK_BYTES);
        }
    }
}
