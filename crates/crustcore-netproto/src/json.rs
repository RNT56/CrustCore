// SPDX-License-Identifier: Apache-2.0
//! A tiny, dependency-free codec for **flat** JSON objects (scalar values only:
//! string, integer, bool, null). This is all the helper protocol needs, and it
//! keeps `crustcore-netproto` serde-free so the trusted caller links no JSON crate
//! (`docs/model-routing.md` §6). It is deliberately *not* a general JSON library:
//! nested objects/arrays are a decode error, which is fine because the protocol
//! models lists as repeated lines or delimited strings.

use std::collections::BTreeMap;

/// A decode error (one human-readable reason).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonError(pub String);

impl core::fmt::Display for JsonError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "flat-json: {}", self.0)
    }
}

impl std::error::Error for JsonError {}

/// A scalar JSON value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scalar {
    /// A string value.
    Str(String),
    /// An integer value.
    Int(i64),
    /// A boolean value.
    Bool(bool),
    /// `null`.
    Null,
}

/// The parsed fields of a flat JSON object, keyed by name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Fields(BTreeMap<String, Scalar>);

impl Fields {
    /// The string value of `key`, if present and a string.
    #[must_use]
    pub fn str(&self, key: &str) -> Option<&str> {
        match self.0.get(key) {
            Some(Scalar::Str(s)) => Some(s.as_str()),
            _ => None,
        }
    }

    /// The integer value of `key`, if present and an integer.
    #[must_use]
    pub fn int(&self, key: &str) -> Option<i64> {
        match self.0.get(key) {
            Some(Scalar::Int(i)) => Some(*i),
            _ => None,
        }
    }

    /// The non-negative integer value of `key` as `u64` (None if absent or
    /// negative).
    #[must_use]
    pub fn uint(&self, key: &str) -> Option<u64> {
        match self.0.get(key) {
            Some(Scalar::Int(i)) if *i >= 0 => Some(*i as u64),
            _ => None,
        }
    }

    /// The boolean value of `key`, if present and a bool.
    #[must_use]
    pub fn bool(&self, key: &str) -> Option<bool> {
        match self.0.get(key) {
            Some(Scalar::Bool(b)) => Some(*b),
            _ => None,
        }
    }
}

/// Parses a flat JSON object (scalars only). Nested structures, trailing junk, or
/// malformed tokens are errors.
///
/// # Errors
/// [`JsonError`] describing the first problem.
pub fn parse_flat_object(s: &str) -> Result<Fields, JsonError> {
    let chars: Vec<char> = s.chars().collect();
    let mut p = Parser { c: &chars, i: 0 };
    p.skip_ws();
    p.expect('{')?;
    let mut map = BTreeMap::new();
    p.skip_ws();
    if p.peek() == Some('}') {
        p.i += 1;
        p.skip_ws();
        p.eof()?;
        return Ok(Fields(map));
    }
    loop {
        p.skip_ws();
        let key = p.parse_string()?;
        p.skip_ws();
        p.expect(':')?;
        p.skip_ws();
        let val = p.parse_scalar()?;
        map.insert(key, val);
        p.skip_ws();
        match p.peek() {
            Some(',') => {
                p.i += 1;
            }
            Some('}') => {
                p.i += 1;
                break;
            }
            other => return Err(JsonError(format!("expected ',' or '}}', got {other:?}"))),
        }
    }
    p.skip_ws();
    p.eof()?;
    Ok(Fields(map))
}

struct Parser<'a> {
    c: &'a [char],
    i: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<char> {
        self.c.get(self.i).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t' | '\r' | '\n')) {
            self.i += 1;
        }
    }

    fn expect(&mut self, ch: char) -> Result<(), JsonError> {
        if self.peek() == Some(ch) {
            self.i += 1;
            Ok(())
        } else {
            Err(JsonError(format!("expected '{ch}', got {:?}", self.peek())))
        }
    }

    fn eof(&self) -> Result<(), JsonError> {
        if self.i == self.c.len() {
            Ok(())
        } else {
            Err(JsonError("trailing characters after object".into()))
        }
    }

    fn parse_scalar(&mut self) -> Result<Scalar, JsonError> {
        match self.peek() {
            Some('"') => Ok(Scalar::Str(self.parse_string()?)),
            Some('t') | Some('f') => self.parse_bool(),
            Some('n') => self.parse_null(),
            Some(c) if c == '-' || c.is_ascii_digit() => self.parse_int(),
            // Nested structures are intentionally unsupported (flat protocol).
            Some('{') | Some('[') => Err(JsonError("nested values are not allowed".into())),
            other => Err(JsonError(format!("unexpected value start {other:?}"))),
        }
    }

    fn parse_string(&mut self) -> Result<String, JsonError> {
        self.expect('"')?;
        let mut out = String::new();
        loop {
            let ch = self
                .peek()
                .ok_or_else(|| JsonError("unterminated string".into()))?;
            self.i += 1;
            match ch {
                '"' => return Ok(out),
                '\\' => {
                    let esc = self
                        .peek()
                        .ok_or_else(|| JsonError("dangling escape".into()))?;
                    self.i += 1;
                    match esc {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        '/' => out.push('/'),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        'b' => out.push('\u{0008}'),
                        'f' => out.push('\u{000C}'),
                        'u' => out.push(self.parse_unicode_escape()?),
                        other => return Err(JsonError(format!("invalid escape \\{other}"))),
                    }
                }
                c => out.push(c),
            }
        }
    }

    /// Parses the 4 hex digits after `\u`, combining a surrogate pair if a low
    /// surrogate follows a high surrogate. A lone/invalid surrogate becomes U+FFFD
    /// rather than an error (robust against odd input; our encoder never emits
    /// surrogates).
    fn parse_unicode_escape(&mut self) -> Result<char, JsonError> {
        let hi = self.read_hex4()?;
        if (0xD800..=0xDBFF).contains(&hi) {
            // Expect a following \u low surrogate.
            if self.peek() == Some('\\') && self.c.get(self.i + 1).copied() == Some('u') {
                self.i += 2;
                let lo = self.read_hex4()?;
                if (0xDC00..=0xDFFF).contains(&lo) {
                    let cp = 0x1_0000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
                    return Ok(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                }
                return Ok('\u{FFFD}');
            }
            return Ok('\u{FFFD}');
        }
        Ok(char::from_u32(hi).unwrap_or('\u{FFFD}'))
    }

    fn read_hex4(&mut self) -> Result<u32, JsonError> {
        let mut v = 0u32;
        for _ in 0..4 {
            let ch = self
                .peek()
                .ok_or_else(|| JsonError("short \\u escape".into()))?;
            let d = ch
                .to_digit(16)
                .ok_or_else(|| JsonError(format!("bad hex digit {ch:?}")))?;
            v = (v << 4) | d;
            self.i += 1;
        }
        Ok(v)
    }

    fn parse_int(&mut self) -> Result<Scalar, JsonError> {
        let start = self.i;
        if self.peek() == Some('-') {
            self.i += 1;
        }
        let digit_start = self.i;
        while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
            self.i += 1;
        }
        if self.i == digit_start {
            return Err(JsonError("expected digits".into()));
        }
        // Reject fractions/exponents explicitly (we model only integers).
        if matches!(self.peek(), Some('.') | Some('e') | Some('E')) {
            return Err(JsonError("non-integer numbers are not supported".into()));
        }
        let text: String = self.c[start..self.i].iter().collect();
        text.parse::<i64>()
            .map(Scalar::Int)
            .map_err(|_| JsonError(format!("integer out of range: {text}")))
    }

    fn parse_bool(&mut self) -> Result<Scalar, JsonError> {
        if self.matches_keyword("true") {
            Ok(Scalar::Bool(true))
        } else if self.matches_keyword("false") {
            Ok(Scalar::Bool(false))
        } else {
            Err(JsonError("invalid token (expected true/false)".into()))
        }
    }

    fn parse_null(&mut self) -> Result<Scalar, JsonError> {
        if self.matches_keyword("null") {
            Ok(Scalar::Null)
        } else {
            Err(JsonError("invalid token (expected null)".into()))
        }
    }

    fn matches_keyword(&mut self, kw: &str) -> bool {
        let kwc: Vec<char> = kw.chars().collect();
        if self.c.len() >= self.i + kwc.len() && self.c[self.i..self.i + kwc.len()] == kwc[..] {
            self.i += kwc.len();
            true
        } else {
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// A builder for a flat JSON object line.
pub struct Obj {
    buf: String,
    first: bool,
}

impl Obj {
    /// A new, empty object builder.
    #[must_use]
    pub fn new() -> Self {
        let mut buf = String::with_capacity(128);
        buf.push('{');
        Obj { buf, first: true }
    }

    fn sep(&mut self) {
        if self.first {
            self.first = false;
        } else {
            self.buf.push(',');
        }
    }

    fn key(&mut self, k: &str) {
        self.sep();
        encode_str(&mut self.buf, k);
        self.buf.push(':');
    }

    /// Appends a string field.
    pub fn str(&mut self, k: &str, v: &str) {
        self.key(k);
        encode_str(&mut self.buf, v);
    }

    /// Appends a signed-integer field.
    pub fn int(&mut self, k: &str, v: i64) {
        self.key(k);
        self.buf.push_str(&v.to_string());
    }

    /// Appends an unsigned-integer field.
    pub fn uint(&mut self, k: &str, v: u64) {
        self.key(k);
        self.buf.push_str(&v.to_string());
    }

    /// Appends a boolean field.
    pub fn bool(&mut self, k: &str, v: bool) {
        self.key(k);
        self.buf.push_str(if v { "true" } else { "false" });
    }

    /// Finishes the object, returning the encoded line.
    #[must_use]
    pub fn finish(mut self) -> String {
        self.buf.push('}');
        self.buf
    }
}

impl Default for Obj {
    fn default() -> Self {
        Obj::new()
    }
}

/// Appends a JSON string literal (quotes included), escaping control characters
/// and the structural characters so a value can never break out of its quotes or
/// inject a newline (a wire-line separator).
fn encode_str(buf: &mut String, value: &str) {
    buf.push('"');
    for c in value.chars() {
        match c {
            '"' => buf.push_str("\\\""),
            '\\' => buf.push_str("\\\\"),
            '\n' => buf.push_str("\\n"),
            '\r' => buf.push_str("\\r"),
            '\t' => buf.push_str("\\t"),
            c if (c as u32) < 0x20 => buf.push_str(&format!("\\u{:04x}", c as u32)),
            c => buf.push(c),
        }
    }
    buf.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_flat_object_with_all_scalar_kinds() {
        let f =
            parse_flat_object(r#"{"s":"hi there","neg":-7,"n":42,"yes":true,"no":false,"z":null}"#)
                .unwrap();
        assert_eq!(f.str("s"), Some("hi there"));
        assert_eq!(f.int("neg"), Some(-7));
        assert_eq!(f.uint("neg"), None); // negative is not a uint
        assert_eq!(f.uint("n"), Some(42));
        assert_eq!(f.bool("yes"), Some(true));
        assert_eq!(f.bool("no"), Some(false));
        assert_eq!(f.str("missing"), None);
    }

    #[test]
    fn empty_object_ok() {
        assert_eq!(parse_flat_object("{}").unwrap(), Fields::default());
        assert_eq!(parse_flat_object("  { }  ").unwrap(), Fields::default());
    }

    #[test]
    fn string_escapes_roundtrip() {
        let mut o = Obj::new();
        o.str("k", "a\"b\\c\nd\te\u{0001}");
        let line = o.finish();
        let f = parse_flat_object(&line).unwrap();
        assert_eq!(f.str("k"), Some("a\"b\\c\nd\te\u{0001}"));
    }

    #[test]
    fn unicode_survives_roundtrip() {
        let mut o = Obj::new();
        o.str("k", "café — π");
        let f = parse_flat_object(&o.finish()).unwrap();
        assert_eq!(f.str("k"), Some("café — π"));
    }

    #[test]
    fn rejects_nested_and_malformed() {
        assert!(parse_flat_object(r#"{"a":{"b":1}}"#).is_err());
        assert!(parse_flat_object(r#"{"a":[1,2]}"#).is_err());
        assert!(parse_flat_object(r#"{"a":1.5}"#).is_err());
        assert!(parse_flat_object(r#"{"a":1}trailing"#).is_err());
        assert!(parse_flat_object(r#"{"a"}"#).is_err());
        assert!(parse_flat_object(r#"{"a":}"#).is_err());
        assert!(parse_flat_object("not an object").is_err());
        assert!(parse_flat_object(r#"{"a":"unterminated}"#).is_err());
    }
}
