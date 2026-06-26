// SPDX-License-Identifier: Apache-2.0
//! P14-intel: a tree-sitter-backed [`CodeIntel`] for Rust, behind the off-by-default `ast`
//! cargo feature. Extracts **precise symbol definitions** (`fn`/`struct`/`enum`/`impl`/
//! `mod`/`trait`) so a `find_symbol`-style query resolves to the *definition site* — not
//! every textual mention `git grep` would return.
//!
//! **Fail closed → grep fallback, never panic.** This is a *better* [`CodeIntel`] for the
//! same lookup contract, not a looser one. [`AstCodeIntel`] holds the same pre-collected
//! [`SourceLine`]s a [`GrepCodeIntel`] would, plus per-file source text for the files it can
//! parse. On any of:
//! - the `ast` feature being **off** (this whole module is `#[cfg(feature = "ast")]`; the
//!   public constructor degrades to a plain [`GrepCodeIntel`] otherwise),
//! - an unrecognized extension,
//! - oversize source (`> MAX_AST_SOURCE_BYTES`),
//! - a parser/language load failure, or
//! - a parse that yields no matching definition for the queried name,
//!
//! it **falls back to the [`GrepCodeIntel`] substring lookup** for that query, so behavior is
//! never worse than grep. Every output is bounded: at most [`crate::MAX_CONTEXT_FRAGMENTS`]
//! hits, snippets truncated to [`crate::MAX_FRAGMENT_BYTES`]. Hostile input (deeply nested,
//! malformed, adversarial bytes) is handled by tree-sitter's error recovery plus our own caps;
//! we only *walk* the resulting tree with an explicit cursor (no recursion → no stack blow-up,
//! no `unsafe` → the crate stays `#![forbid(unsafe_code)]`).

use crate::{CodeIntel, GrepCodeIntel, SourceLine, SymbolRef};
use crate::{MAX_CONTEXT_FRAGMENTS, MAX_FRAGMENT_BYTES};
use crustcore_types::BoundedText;

#[cfg(feature = "ast")]
use tree_sitter::{Node, Parser};

/// Largest source we will hand to the parser (deny-large: invariant 11). Anything larger
/// falls back to grep rather than spending parse time on a hostile file.
pub const MAX_AST_SOURCE_BYTES: usize = 2 * 1024 * 1024;

/// Maximum number of symbol definitions tracked from one file (bounded fan-out). Excess
/// top-level items beyond this cap are dropped (grep still covers the trailing content).
pub const MAX_AST_DEFS_PER_FILE: usize = 4 * 1024;

/// Maximum bytes kept for a symbol name extracted from the tree (untrusted provenance data).
pub const MAX_SYMBOL_NAME_BYTES: usize = 256;

/// A precise symbol definition located by the AST backend: the defining file, the 1-based
/// line where the item begins, and the bounded item name. Untrusted repo data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolDef {
    /// Repo-relative path of the defining file.
    pub path: String,
    /// 1-based line where the item begins.
    pub line: u32,
    /// The defined symbol's name (bounded; `impl <type>` for impl blocks).
    pub name: String,
}

/// A code-intel backend that prefers **AST-precise symbol definitions** and **falls back to
/// substring grep** whenever the AST path can't help (feature off, unknown extension, parse
/// failure, or no matching definition). Construct it with [`AstCodeIntel::new`].
///
/// It is a drop-in [`CodeIntel`]: the same `lookup(name)` contract as [`GrepCodeIntel`], but
/// for a name that *is* a defined Rust item it returns the **definition site(s)** rather than
/// every mention.
#[derive(Debug)]
pub struct AstCodeIntel {
    grep: GrepCodeIntel,
    /// Precise definitions extracted from parseable files (empty when the feature is off).
    defs: Vec<SymbolDef>,
}

impl AstCodeIntel {
    /// Builds an AST-aware backend.
    ///
    /// `lines` are the same `git grep -n`-style [`SourceLine`]s a [`GrepCodeIntel`] consumes
    /// (the always-available fallback). `sources` are `(path, content)` pairs for files whose
    /// definitions should be parsed precisely; a path whose extension has no grammar, or whose
    /// source is empty / oversize / unparseable, simply contributes no precise defs (grep
    /// still covers it). When the `ast` feature is **off**, `sources` is ignored and this is
    /// exactly a [`GrepCodeIntel`].
    #[must_use]
    pub fn new(lines: Vec<SourceLine>, sources: &[(&str, &str)]) -> Self {
        let grep = GrepCodeIntel::new(lines);
        let defs = extract_defs(sources);
        AstCodeIntel { grep, defs }
    }

    /// All precise definitions extracted (for tests / introspection).
    #[must_use]
    pub fn defs(&self) -> &[SymbolDef] {
        &self.defs
    }
}

impl CodeIntel for AstCodeIntel {
    fn lookup(&self, name: &str) -> Vec<SymbolRef> {
        if name.is_empty() {
            return Vec::new();
        }
        // Prefer precise definition sites for an exact-name match.
        let precise: Vec<SymbolRef> = self
            .defs
            .iter()
            .filter(|d| d.name == name)
            .take(MAX_CONTEXT_FRAGMENTS)
            .map(|d| SymbolRef {
                path: d.path.clone(),
                line: d.line,
                snippet: BoundedText::truncated(
                    format!("definition: {}", d.name),
                    MAX_FRAGMENT_BYTES,
                ),
            })
            .collect();
        if !precise.is_empty() {
            return precise;
        }
        // Fail closed: no precise definition → behave exactly like grep.
        self.grep.lookup(name)
    }
}

/// Extracts precise symbol definitions from `(path, content)` pairs. With the `ast` feature
/// on, parseable Rust files contribute their top-level item definitions; otherwise (or for an
/// unparseable file) the pair contributes nothing. Always bounded and panic-free.
#[cfg(feature = "ast")]
fn extract_defs(sources: &[(&str, &str)]) -> Vec<SymbolDef> {
    let mut out = Vec::new();
    for (path, content) in sources {
        if out.len() >= MAX_AST_DEFS_PER_FILE {
            break;
        }
        out.extend(rust_defs(path, content));
    }
    out
}

/// Without the `ast` feature, no precise defs are extracted — every lookup falls back to grep.
#[cfg(not(feature = "ast"))]
fn extract_defs(_sources: &[(&str, &str)]) -> Vec<SymbolDef> {
    Vec::new()
}

/// Parses one Rust file (if `path` has a `.rs` extension and the source is in-bounds) and
/// returns its top-level item definitions. Fail-closed: any problem yields an empty vec.
#[cfg(feature = "ast")]
fn rust_defs(path: &str, content: &str) -> Vec<SymbolDef> {
    // Deny-large + only handle .rs; everything else falls back to grep.
    if content.is_empty() || content.len() > MAX_AST_SOURCE_BYTES || !is_rust_path(path) {
        return Vec::new();
    }
    let mut parser = Parser::new();
    let language: tree_sitter::Language = tree_sitter_rust::LANGUAGE.into();
    if parser.set_language(&language).is_err() {
        return Vec::new();
    }
    // `parse` returns None if cancelled / language unset; never panics on malformed input
    // (tree-sitter recovers errors). Treat None as fail-closed.
    let Some(tree) = parser.parse(content, None) else {
        return Vec::new();
    };

    let src = content.as_bytes();
    let root = tree.root_node();
    let mut defs = Vec::new();

    // Walk only the *direct* named children of the root (top-level items) with an explicit
    // cursor — no recursion, so adversarial nesting cannot blow the stack.
    let mut cursor = root.walk();
    for node in root.named_children(&mut cursor) {
        if defs.len() >= MAX_AST_DEFS_PER_FILE {
            break;
        }
        if !is_item_kind(node.kind()) {
            continue;
        }
        // 1-based line of the item's start (tree-sitter rows are 0-based).
        let line = node.start_position().row.saturating_add(1);
        let Ok(line) = u32::try_from(line) else {
            continue;
        };
        let name = rust_item_name(&node, src);
        defs.push(SymbolDef {
            path: path.to_string(),
            line,
            name,
        });
    }
    defs
}

/// Whether a tree-sitter node `kind` is a top-level Rust item we tag as a definition.
#[cfg(feature = "ast")]
fn is_item_kind(kind: &str) -> bool {
    matches!(
        kind,
        "function_item" | "struct_item" | "enum_item" | "impl_item" | "mod_item" | "trait_item"
    )
}

/// Case-insensitive check that a path's final component ends in `.rs`.
#[cfg(feature = "ast")]
fn is_rust_path(path: &str) -> bool {
    let file = path.rsplit(['/', '\\']).next().unwrap_or(path);
    file.rsplit_once('.')
        .is_some_and(|(_, e)| e.eq_ignore_ascii_case("rs"))
}

/// Rust-specific item naming. `impl` blocks (no single name) get an `impl <type>` (or
/// `impl <trait> for <type>`) label; everything else uses the `name` field, falling back to
/// the node kind. Untrusted text — bounded, used only as a provenance label.
#[cfg(feature = "ast")]
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
#[cfg(feature = "ast")]
fn field_text(node: &Node, field: &str, src: &[u8]) -> Option<String> {
    let child = node.child_by_field_name(field)?;
    child.utf8_text(src).ok().map(ToString::to_string)
}

/// Truncates a name to [`MAX_SYMBOL_NAME_BYTES`] on a char boundary (never panics).
#[cfg(feature = "ast")]
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

    fn grep_lines() -> Vec<SourceLine> {
        vec![
            SourceLine {
                path: "src/lib.rs".into(),
                line: 5,
                text: "pub fn alpha() -> u32 { 1 }".into(),
            },
            // A *mention* of alpha that is not its definition.
            SourceLine {
                path: "src/main.rs".into(),
                line: 9,
                text: "    let _ = alpha();".into(),
            },
        ]
    }

    // --- fallback path: always works, feature on or off ---

    #[test]
    fn unknown_or_missing_def_falls_back_to_grep() {
        // No sources to parse → behaves exactly like GrepCodeIntel for every name.
        let intel = AstCodeIntel::new(grep_lines(), &[]);
        let hits = intel.lookup("alpha");
        // Grep finds BOTH the def line and the mention.
        assert_eq!(hits.len(), 2);
        assert!(intel.lookup("").is_empty());
        assert!(intel.lookup("nonexistent").is_empty());
    }

    #[test]
    fn empty_name_is_empty() {
        let intel = AstCodeIntel::new(grep_lines(), &[]);
        assert!(intel.lookup("").is_empty());
    }

    // --- precise path: only meaningful with the `ast` feature ---

    #[cfg(feature = "ast")]
    const SRC: &str = "\
use std::fmt;

const K: u32 = 1;

pub fn alpha() -> u32 {
    1
}

struct Point {
    x: i32,
}

enum Color {
    Red,
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

    #[cfg(feature = "ast")]
    #[test]
    fn extracts_rust_definitions() {
        let intel = AstCodeIntel::new(vec![], &[("src/lib.rs", SRC)]);
        let names: Vec<&str> = intel.defs().iter().map(|d| d.name.as_str()).collect();
        assert!(names.contains(&"alpha"), "{names:?}");
        assert!(names.contains(&"Point"), "{names:?}");
        assert!(names.contains(&"Color"), "{names:?}");
        assert!(names.contains(&"Greet"), "{names:?}");
        assert!(names.contains(&"inner"), "{names:?}");
        assert!(
            names.iter().any(|n| n.starts_with("impl Greet for Point")),
            "{names:?}"
        );
        // `const` is intentionally not in the item set.
        assert!(!names.contains(&"K"), "{names:?}");
    }

    #[cfg(feature = "ast")]
    #[test]
    fn lookup_returns_precise_definition_not_mentions() {
        // grep would return both the def AND the mention; the AST def resolves to the
        // definition site only.
        let intel = AstCodeIntel::new(grep_lines(), &[("src/lib.rs", SRC)]);
        let hits = intel.lookup("alpha");
        assert_eq!(hits.len(), 1, "precise def, not the mention: {hits:?}");
        assert_eq!(hits[0].path, "src/lib.rs");
        assert_eq!(hits[0].line, 5); // `pub fn alpha` is on line 5 of SRC.
        assert!(hits[0].snippet.as_str().contains("alpha"));
    }

    #[cfg(feature = "ast")]
    #[test]
    fn non_definition_name_still_falls_back_to_grep() {
        // `let` is not a top-level item, so no precise def → grep fallback finds the mention.
        let intel = AstCodeIntel::new(grep_lines(), &[("src/lib.rs", SRC)]);
        let hits = intel.lookup("let");
        assert!(hits.iter().any(|h| h.path == "src/main.rs"));
    }

    #[cfg(feature = "ast")]
    #[test]
    fn unknown_extension_yields_no_precise_defs() {
        let intel = AstCodeIntel::new(vec![], &[("notes.txt", SRC), ("README", SRC)]);
        assert!(intel.defs().is_empty());
    }

    #[cfg(feature = "ast")]
    #[test]
    fn oversize_and_empty_sources_are_refused() {
        let big = "a".repeat(MAX_AST_SOURCE_BYTES + 1);
        let intel = AstCodeIntel::new(vec![], &[("big.rs", &big), ("empty.rs", "")]);
        assert!(intel.defs().is_empty());
    }

    #[cfg(feature = "ast")]
    #[test]
    fn malformed_rust_does_not_panic_and_is_bounded() {
        let hostile = "fn (((((( {{{{{{ impl impl impl <<<<<<<< \0\0\0 \u{1f4a9}".repeat(64);
        let intel = AstCodeIntel::new(vec![], &[("evil.rs", &hostile)]);
        assert!(intel.defs().len() <= MAX_AST_DEFS_PER_FILE);
        for d in intel.defs() {
            assert!(d.name.len() <= MAX_SYMBOL_NAME_BYTES);
            assert!(d.line >= 1);
        }
    }

    #[cfg(feature = "ast")]
    #[test]
    fn long_symbol_name_is_truncated() {
        let long = "x".repeat(MAX_SYMBOL_NAME_BYTES * 4);
        let src = format!("fn {long}() {{}}\n");
        let intel = AstCodeIntel::new(vec![], &[("long.rs", &src)]);
        let d = intel.defs().first().expect("one fn");
        assert!(d.name.len() <= MAX_SYMBOL_NAME_BYTES);
        assert!(d.name.starts_with("xxxx"));
    }

    #[cfg(feature = "ast")]
    #[test]
    fn defs_per_file_is_bounded() {
        // Many functions: bounded to MAX_AST_DEFS_PER_FILE.
        let mut src = String::new();
        for i in 0..(MAX_AST_DEFS_PER_FILE + 50) {
            src.push_str(&format!("fn f{i}() {{}}\n"));
        }
        let intel = AstCodeIntel::new(vec![], &[("many.rs", &src)]);
        assert!(intel.defs().len() <= MAX_AST_DEFS_PER_FILE);
    }
}
