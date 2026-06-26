// SPDX-License-Identifier: Apache-2.0
//! AST-precise symbol spans via tree-sitter (C5-ast), behind the off-by-default `ast`
//! feature. Implemented for **Rust** to start; more grammars are an additive follow-on
//! (one optional `dep:tree-sitter-<lang>` + one match arm in [`language_for_path`]).
//!
//! **Fail closed, never panic.** This module is a *better source of spans* for the same
//! [`chunk_with_symbols`](super::Chunker::chunk_with_symbols) machinery — it does not relax
//! any bound. On any of:
//! - an unrecognized extension,
//! - oversize source (`> MAX_AST_SOURCE_BYTES`),
//! - a parser/language load failure,
//! - a parse that yields no recognized top-level items,
//!
//! it returns an **empty** `Vec<SymbolSpan>`, and the caller falls back to the conservative
//! grep/line-chunk path exactly as before. Every output is bounded: at most
//! [`MAX_AST_SYMBOLS`] spans, names truncated to [`MAX_SYMBOL_NAME_BYTES`]. Hostile input
//! (deeply nested, malformed, adversarial bytes) is handled by tree-sitter's error recovery
//! plus our own caps; we only *walk* the resulting tree (no `unsafe`, the crate stays
//! `#![forbid(unsafe_code)]`).

use tree_sitter::{Node, Parser};

use super::symbol::SymbolSpan;

/// Largest source we will hand to the parser (deny-large: invariant 11). Anything larger
/// fails closed to the line/grep fallback rather than spending parse time on a hostile file.
pub const MAX_AST_SOURCE_BYTES: usize = 2 * 1024 * 1024;

/// Maximum number of symbol spans returned from one file (bounded fan-out). Excess
/// top-level items beyond this cap are dropped (the line-chunk fallback still covers the
/// trailing content, so nothing is lost — it is just not symbol-tagged).
pub const MAX_AST_SYMBOLS: usize = 4 * 1024;

/// Maximum bytes kept for a symbol name (the name is untrusted provenance data only).
pub const MAX_SYMBOL_NAME_BYTES: usize = 256;

/// A grammar this AST backend can parse. Extend this enum (and [`language_for_path`] +
/// [`Language::ts_language`]) to add a grammar; everything else is grammar-agnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Language {
    Rust,
}

impl Language {
    /// The tree-sitter `Language` for this grammar.
    fn ts_language(self) -> tree_sitter::Language {
        match self {
            Language::Rust => tree_sitter_rust::LANGUAGE.into(),
        }
    }

    /// Whether a tree-sitter node `kind` is a top-level item we tag as a symbol.
    fn is_item_kind(self, kind: &str) -> bool {
        match self {
            Language::Rust => matches!(
                kind,
                "function_item"
                    | "struct_item"
                    | "enum_item"
                    | "impl_item"
                    | "mod_item"
                    | "trait_item"
            ),
        }
    }
}

/// Picks a grammar from a path's extension. Unknown extensions return `None`, which makes
/// the caller fall back to the line/grep path. Case-insensitive on the extension.
fn language_for_path(path: &str) -> Option<Language> {
    // Take the substring after the last '.' in the final path component.
    let file = path.rsplit(['/', '\\']).next().unwrap_or(path);
    let ext = file.rsplit_once('.').map(|(_, e)| e)?;
    match ext.to_ascii_lowercase().as_str() {
        "rs" => Some(Language::Rust),
        _ => None,
    }
}

/// Returns AST-precise [`SymbolSpan`]s for `content` if `path`'s extension maps to a
/// supported grammar and the parse succeeds; otherwise an **empty** vec (fail-closed: the
/// caller falls back to the line/grep path). Never panics on hostile input.
///
/// Spans are byte ranges `[start, end)` over `content` for each top-level item, named by the
/// item's identifier (or a derived label for `impl` blocks, which have no single name).
/// Output is bounded: at most [`MAX_AST_SYMBOLS`] spans; names truncated to
/// [`MAX_SYMBOL_NAME_BYTES`].
#[must_use]
pub fn ast_symbol_spans(path: &str, content: &str) -> Vec<SymbolSpan> {
    // Deny-large: refuse oversize input before touching the parser.
    if content.is_empty() || content.len() > MAX_AST_SOURCE_BYTES {
        return Vec::new();
    }
    let Some(lang) = language_for_path(path) else {
        return Vec::new();
    };

    let mut parser = Parser::new();
    if parser.set_language(&lang.ts_language()).is_err() {
        return Vec::new();
    }
    // `parse` returns `None` if the language was unset or parsing was cancelled; treat that
    // as fail-closed. It does not panic on malformed input — tree-sitter recovers errors.
    let Some(tree) = parser.parse(content, None) else {
        return Vec::new();
    };

    let src = content.as_bytes();
    let root = tree.root_node();
    let mut spans = Vec::new();

    // Walk only the *direct* named children of the root (top-level items). We use an
    // explicit cursor (no recursion) so depth cannot blow the stack on adversarial input.
    let mut cursor = root.walk();
    for node in root.named_children(&mut cursor) {
        if spans.len() >= MAX_AST_SYMBOLS {
            break;
        }
        if !lang.is_item_kind(node.kind()) {
            continue;
        }
        let start = node.start_byte();
        let end = node.end_byte();
        // Sanitize the span against the source length and ordering before trusting it.
        if end <= start || end > src.len() {
            continue;
        }
        let name = item_name(lang, &node, src);
        spans.push(SymbolSpan { name, start, end });
    }

    spans
}

/// Derives a bounded, human-readable symbol name for an item node. For most items this is
/// the `name` field's text; `impl` blocks (which have no single name) get an `impl <type>`
/// (or `impl <trait> for <type>`) label. Falls back to the node kind if no name is present.
fn item_name(lang: Language, node: &Node, src: &[u8]) -> String {
    match lang {
        Language::Rust => rust_item_name(node, src),
    }
}

/// Rust-specific item naming. Untrusted text — used only as a provenance label.
fn rust_item_name(node: &Node, src: &[u8]) -> String {
    let kind = node.kind();
    if kind == "impl_item" {
        let ty = field_text(node, "type", src);
        let tr = field_text(node, "trait", src);
        let label = match (tr, ty) {
            (Some(t), Some(y)) => format!("impl {t} for {y}"),
            (None, Some(y)) => format!("impl {y}"),
            _ => "impl".to_string(),
        };
        return truncate_name(&label);
    }
    match field_text(node, "name", src) {
        Some(name) => truncate_name(&name),
        None => truncate_name(kind),
    }
}

/// Reads the UTF-8 text of a named child field, if present and valid UTF-8.
fn field_text(node: &Node, field: &str, src: &[u8]) -> Option<String> {
    let child = node.child_by_field_name(field)?;
    child.utf8_text(src).ok().map(|s| s.to_string())
}

/// Truncates a name to [`MAX_SYMBOL_NAME_BYTES`] on a char boundary (never panics).
fn truncate_name(name: &str) -> String {
    if name.len() <= MAX_SYMBOL_NAME_BYTES {
        return name.to_string();
    }
    let mut end = MAX_SYMBOL_NAME_BYTES;
    while end > 0 && !name.is_char_boundary(end) {
        end -= 1;
    }
    name[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: &str = "\
use std::fmt;

const K: u32 = 1;

fn alpha() -> u32 {
    1
}

struct Point {
    x: i32,
    y: i32,
}

enum Color {
    Red,
    Green,
}

trait Greet {
    fn hi(&self);
}

impl Greet for Point {
    fn hi(&self) {}
}

mod inner {
    pub fn nested() {}
}
";

    #[test]
    fn rust_items_become_aligned_spans() {
        let spans = ast_symbol_spans("src/lib.rs", SRC);
        // fn, struct, enum, trait, impl, mod = 6 top-level items (const is intentionally not
        // tagged per the C5-ast item set).
        let names: Vec<&str> = spans.iter().map(|s| s.name.as_str()).collect();
        assert!(names.contains(&"alpha"), "fn alpha tagged: {names:?}");
        assert!(names.contains(&"Point"), "struct Point tagged: {names:?}");
        assert!(names.contains(&"Color"), "enum Color tagged: {names:?}");
        assert!(names.contains(&"Greet"), "trait Greet tagged: {names:?}");
        assert!(names.contains(&"inner"), "mod inner tagged: {names:?}");
        assert!(
            names.iter().any(|n| n.starts_with("impl Greet for Point")),
            "impl labeled: {names:?}"
        );

        // Each span is exactly the bytes of its item, and `alpha`'s span starts at `fn`.
        let alpha = spans.iter().find(|s| s.name == "alpha").unwrap();
        assert_eq!(
            &SRC[alpha.start..alpha.end],
            "fn alpha() -> u32 {\n    1\n}"
        );

        let point = spans.iter().find(|s| s.name == "Point").unwrap();
        assert!(SRC[point.start..point.end].starts_with("struct Point"));

        // Spans are well-formed: ordered, in-range, non-empty.
        for s in &spans {
            assert!(s.start < s.end);
            assert!(s.end <= SRC.len());
        }
    }

    #[test]
    fn spans_feed_chunk_with_symbols_and_tag_chunks() {
        use crate::chunk::{Chunker, MAX_CHUNK_BYTES};
        use crustcore_index::MemorySource;

        let spans = ast_symbol_spans("src/lib.rs", SRC);
        assert!(!spans.is_empty());
        let chunker = Chunker::new();
        let chunks = chunker.chunk_with_symbols("src/lib.rs", SRC, MemorySource::RepoFile, &spans);

        // The struct ends up tagged with its symbol name and stays bounded.
        let point = chunks
            .iter()
            .find(|c| c.content.contains("struct Point"))
            .expect("Point chunk");
        assert_eq!(point.meta.symbol.as_deref(), Some("Point"));
        for c in &chunks {
            assert!(c.content.len() <= MAX_CHUNK_BYTES);
            assert!(c.meta.redact_required);
        }
    }

    #[test]
    fn malformed_rust_does_not_panic_and_is_bounded() {
        // Deeply unbalanced / garbage input: tree-sitter recovers; we must not panic and
        // must stay bounded. We accept any (possibly empty) result.
        let hostile = "fn (((((( {{{{{{ impl impl impl <<<<<<<< \0\0\0 \u{1f4a9}".repeat(64);
        let spans = ast_symbol_spans("evil.rs", &hostile);
        assert!(spans.len() <= MAX_AST_SYMBOLS);
        for s in &spans {
            assert!(s.start < s.end);
            assert!(s.end <= hostile.len());
            assert!(s.name.len() <= MAX_SYMBOL_NAME_BYTES);
        }
    }

    #[test]
    fn unknown_extension_falls_back_empty() {
        // No grammar for these extensions -> empty (caller falls back to line/grep).
        assert!(ast_symbol_spans("notes.txt", SRC).is_empty());
        assert!(ast_symbol_spans("README", SRC).is_empty());
        assert!(ast_symbol_spans("data.json", "{\"a\":1}").is_empty());
    }

    #[test]
    fn oversize_source_is_refused() {
        // One byte over the cap -> fail closed (empty), before the parser runs.
        let big = "a".repeat(MAX_AST_SOURCE_BYTES + 1);
        assert!(ast_symbol_spans("big.rs", &big).is_empty());
    }

    #[test]
    fn empty_source_is_safe() {
        assert!(ast_symbol_spans("empty.rs", "").is_empty());
    }

    #[test]
    fn long_symbol_name_is_truncated() {
        let long = "x".repeat(MAX_SYMBOL_NAME_BYTES * 4);
        let src = format!("fn {long}() {{}}\n");
        let spans = ast_symbol_spans("long.rs", &src);
        let f = spans.first().expect("one fn");
        assert!(f.name.len() <= MAX_SYMBOL_NAME_BYTES);
        assert!(f.name.starts_with("xxxx"));
    }
}
