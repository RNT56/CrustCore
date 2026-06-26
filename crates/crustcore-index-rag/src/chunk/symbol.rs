// SPDX-License-Identifier: Apache-2.0
//! Symbol-aware chunk metadata (C5.5): align chunk boundaries to symbol spans and tag
//! `ChunkMeta.symbol`, using the **existing** [`crustcore_index::CodeIntel`] trait (backed
//! by the real [`crustcore_index::GrepCodeIntel`]).
//!
//! **Fail-closed default.** Whenever symbol info is absent — the `ast` feature is off, the
//! file has no recognized symbols, or a symbol's line is out of range — this falls back to
//! the conservative bounded line-chunking from [`Chunker::chunk`](super::Chunker::chunk)
//! (adversarial dimension (d)). Precise spans come from one of two sources, both feeding the
//! same fail-closed machinery here:
//! - the default grep-located symbol lines ([`symbol_spans_from_intel`]), or
//! - **C5-ast (done for Rust):** tree-sitter byte-exact item spans behind the off-by-default
//!   `ast` feature (`super::ast::ast_symbol_spans` / `Chunker::chunk_with_ast_symbols`).
//!   Additional grammars are an additive follow-on. When the AST backend can't parse a file
//!   it yields no spans, so this line-chunk fallback is always the safe path.

use crustcore_index::{CodeIntel, MemorySource};

use super::{Chunk, Chunker};

/// A symbol with the byte span it encloses in the file, plus its name. Pure data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolSpan {
    /// Symbol name (untrusted; provenance only).
    pub name: String,
    /// Byte span `[start, end)` of the symbol's region in the file.
    pub start: usize,
    /// Exclusive end byte offset.
    pub end: usize,
}

impl Chunker {
    /// Chunks `content` aligning chunk boundaries to `symbols`' byte spans and tagging each
    /// chunk with its enclosing symbol. Content **outside** any symbol span (imports,
    /// module headers, gaps) is line-chunked with no symbol tag — so nothing is dropped and
    /// the bounded guarantee still holds. If `symbols` is empty this is exactly
    /// [`Chunker::chunk`](super::Chunker::chunk) (the fail-closed default).
    #[must_use]
    pub fn chunk_with_symbols(
        &self,
        path: &str,
        content: &str,
        source: MemorySource,
        symbols: &[SymbolSpan],
    ) -> Vec<Chunk> {
        if symbols.is_empty() {
            return self.chunk(path, content, source);
        }
        // Normalize + clamp spans, sort by start, and clip to the content length. A
        // hostile/buggy symbol span (inverted, out-of-range, overlapping) is sanitized
        // here — never trusted to be well-formed.
        let len = content.len();
        let mut spans: Vec<SymbolSpan> = symbols
            .iter()
            .map(|s| SymbolSpan {
                name: s.name.clone(),
                start: s.start.min(len),
                end: s.end.min(len).max(s.start.min(len)),
            })
            .filter(|s| s.end > s.start)
            .collect();
        spans.sort_by_key(|s| (s.start, s.end));

        let mut chunks = Vec::new();
        let mut cursor = 0usize;
        for s in &spans {
            // Skip a span that starts before the cursor (overlap) — already covered.
            if s.start < cursor {
                continue;
            }
            // Line-chunk the gap before this symbol (no symbol tag), aligned to lines.
            if s.start > cursor {
                let gap = self.bounded_line_units(content, cursor, s.start);
                chunks.extend(self.assemble(path, content, &gap, source, None));
            }
            // Chunk the symbol region itself, tagged with the symbol name. The region is
            // treated as a single unit, then bounded/packed by `assemble` (so a huge symbol
            // still yields only bounded chunks).
            let region = vec![(s.start, s.end)];
            chunks.extend(self.assemble(path, content, &region, source, Some(&s.name)));
            cursor = s.end;
        }
        // Trailing gap after the last symbol.
        if cursor < len {
            let gap = self.bounded_line_units(content, cursor, len);
            chunks.extend(self.assemble(path, content, &gap, source, None));
        }
        chunks
    }

    /// Line spans within `[from, to)` of `content`, snapped to line starts so a gap chunk
    /// never splits a line mid-way (except via the hard cap, handled in `assemble`).
    fn bounded_line_units(&self, content: &str, from: usize, to: usize) -> Vec<(usize, usize)> {
        let bytes = content.as_bytes();
        let (from, to) = (from.min(bytes.len()), to.min(bytes.len()));
        if to <= from {
            return Vec::new();
        }
        let mut units = Vec::new();
        let mut start = from;
        for (i, &b) in bytes.iter().enumerate().take(to).skip(from) {
            if b == b'\n' {
                units.push((start, i + 1));
                start = i + 1;
            }
        }
        if start < to {
            units.push((start, to));
        }
        units
    }
}

/// Derives [`SymbolSpan`]s for `content` using a [`CodeIntel`] backend (the real
/// [`GrepCodeIntel`](crustcore_index::GrepCodeIntel)). For each `name` in `symbol_names`,
/// the backend's located line is treated as the symbol's start; the span runs to the next
/// located symbol's start (or end of file) — a cheap, bounded approximation of an enclosing
/// region. **This is grep-grade, not AST-grade**: precise tree-sitter spans are produced by
/// the C5-ast backend (`super::ast::ast_symbol_spans`, `ast` feature; Rust today). When no
/// symbol is located the result is empty and the caller falls back to line-chunking
/// (fail-closed).
///
/// `content` and the located line numbers must be consistent (same file). Line numbers are
/// 1-based (as `GrepCodeIntel` produces). Out-of-range lines are dropped.
#[must_use]
pub fn symbol_spans_from_intel(
    content: &str,
    intel: &dyn CodeIntel,
    symbol_names: &[&str],
) -> Vec<SymbolSpan> {
    // Map 1-based line number -> byte offset of that line's start.
    let line_starts = line_start_offsets(content);
    let mut located: Vec<(usize, String)> = Vec::new(); // (byte_start, name)
    for name in symbol_names {
        for sref in intel.lookup(name) {
            let line = sref.line as usize;
            if line == 0 || line > line_starts.len() {
                continue;
            }
            located.push((line_starts[line - 1], (*name).to_string()));
        }
    }
    located.sort_by_key(|(off, _)| *off);
    located.dedup_by_key(|(off, _)| *off);

    let len = content.len();
    let mut spans = Vec::new();
    for k in 0..located.len() {
        let start = located[k].0;
        let end = located.get(k + 1).map_or(len, |(o, _)| *o);
        if end > start {
            spans.push(SymbolSpan {
                name: located[k].1.clone(),
                start,
                end,
            });
        }
    }
    spans
}

/// Byte offset where each line begins (index 0 = line 1).
fn line_start_offsets(content: &str) -> Vec<usize> {
    let mut starts = vec![0usize];
    for (i, &b) in content.as_bytes().iter().enumerate() {
        if b == b'\n' {
            starts.push(i + 1);
        }
    }
    starts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk::MAX_CHUNK_BYTES;
    use crustcore_index::{GrepCodeIntel, SourceLine};

    const SRC: &str = "use std::fmt;\nfn alpha() {\n    1\n}\nfn beta() {\n    2\n}\n";

    #[test]
    fn symbol_metadata_aligns_to_codeintel_spans() {
        // GrepCodeIntel located lines, consistent with SRC (1-based lines).
        let intel = GrepCodeIntel::new(vec![
            SourceLine {
                path: "src/lib.rs".into(),
                line: 2,
                text: "fn alpha() {".into(),
            },
            SourceLine {
                path: "src/lib.rs".into(),
                line: 5,
                text: "fn beta() {".into(),
            },
        ]);
        let spans = symbol_spans_from_intel(SRC, &intel, &["fn alpha", "fn beta"]);
        assert_eq!(spans.len(), 2);
        let chunker = Chunker::new();
        let chunks = chunker.chunk_with_symbols("src/lib.rs", SRC, MemorySource::RepoFile, &spans);
        // The `use` header before the first symbol is line-chunked with NO symbol tag.
        let header = chunks.iter().find(|c| c.content.contains("use std::fmt"));
        assert!(header.is_some());
        assert!(header.unwrap().meta.symbol.is_none());
        // The alpha region is tagged with the symbol name.
        let alpha = chunks
            .iter()
            .find(|c| c.content.contains("alpha"))
            .expect("alpha chunk");
        assert_eq!(alpha.meta.symbol.as_deref(), Some("fn alpha"));
        // Every chunk stays bounded regardless of symbol alignment.
        for c in &chunks {
            assert!(c.content.len() <= MAX_CHUNK_BYTES);
            assert!(c.meta.redact_required);
        }
    }

    #[test]
    fn falls_back_to_line_chunking_when_no_symbols() {
        // ast-off / symbol-absent path — the DEFAULT (fail-closed): identical to `chunk`.
        let chunker = Chunker::new();
        let with_empty = chunker.chunk_with_symbols("p.rs", SRC, MemorySource::RepoFile, &[]);
        let plain = chunker.chunk("p.rs", SRC, MemorySource::RepoFile);
        assert_eq!(with_empty, plain);
        for c in &with_empty {
            assert!(c.meta.symbol.is_none());
        }
    }

    #[test]
    fn malformed_symbol_spans_are_sanitized_not_trusted() {
        // Inverted, out-of-range, and overlapping spans must not panic or exceed bounds.
        let chunker = Chunker::new();
        let bad = vec![
            SymbolSpan {
                name: "inverted".into(),
                start: 40,
                end: 10,
            },
            SymbolSpan {
                name: "oob".into(),
                start: SRC.len() + 100,
                end: SRC.len() + 200,
            },
            SymbolSpan {
                name: "ok".into(),
                start: 0,
                end: 12,
            },
        ];
        let chunks = chunker.chunk_with_symbols("p.rs", SRC, MemorySource::RepoFile, &bad);
        for c in &chunks {
            assert!(c.content.len() <= MAX_CHUNK_BYTES);
            assert!(c.meta.byte_span.end <= SRC.len());
        }
    }

    #[test]
    fn empty_intel_yields_no_spans_so_caller_falls_back() {
        let intel = GrepCodeIntel::new(vec![]);
        let spans = symbol_spans_from_intel(SRC, &intel, &["fn alpha"]);
        assert!(spans.is_empty());
    }
}
