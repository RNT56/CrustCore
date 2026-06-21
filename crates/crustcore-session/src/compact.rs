// SPDX-License-Identifier: Apache-2.0
//! History compaction policies (C4.6; invariants 7, 11).
//!
//! Compaction shapes a session's conversation history for a model context window
//! while preserving the trust posture: it is **redact-then-bound**, capped by the
//! `MAX_*` constants below (mirroring `crustcore-index`'s redact-then-bound
//! posture and bounded caps), and its output is tagged never-authority
//! [`ModelVisibleText`] — compacted history *informs* the model and never
//! authorizes (invariant 7). The chain stays intact: compaction drops bulky
//! payloads to artifact handles and never mutates the log.
//!
//! The default [`CompactionPolicy`] is the **most restrictive bounded form**
//! (`DropBulkToHandles`, keep 0 turns) so a forgotten classification compacts to
//! the smallest redacted shape (fail-safe).

use crustcore_secrets::{ModelVisibleText, Redactor};

use crate::snapshot::{Turn, TurnKind};

/// Maximum total bytes a compacted history may contain (mirrors
/// `crustcore_index::MAX_CONTEXT_BUNDLE`).
pub const MAX_COMPACT_BYTES: usize = 16 * 1024;

/// Maximum number of turns a compacted history may retain (mirrors
/// `crustcore_index::MAX_CONTEXT_FRAGMENTS`).
pub const MAX_COMPACT_TURNS: usize = 32;

/// Maximum bytes any single retained turn may contribute (mirrors
/// `crustcore_index::MAX_FRAGMENT_BYTES`).
pub const MAX_TURN_BYTES: usize = 2 * 1024;

/// How history is compacted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactionMode {
    /// Keep the last `n` turns verbatim (still redact-then-bound), drop the rest.
    KeepLastN(usize),
    /// Keep the last `n` turns; replace older turns with a single bounded summary
    /// line counting what was dropped.
    SummarizeOlder(usize),
    /// Keep no turn text; drop everything to artifact-handle references (the most
    /// restrictive, fail-safe form).
    DropBulkToHandles,
}

/// A history compaction policy: a [`CompactionMode`] plus the hard caps it is
/// always clamped to. Construct via [`CompactionPolicy::default`] (most
/// restrictive) or the named constructors; every constructor clamps `n` to
/// [`MAX_COMPACT_TURNS`] so a policy can never request more than the cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactionPolicy {
    mode: CompactionMode,
}

impl Default for CompactionPolicy {
    /// The most restrictive bounded posture (fail-safe): drop all turn text to
    /// handles.
    fn default() -> Self {
        CompactionPolicy {
            mode: CompactionMode::DropBulkToHandles,
        }
    }
}

impl CompactionPolicy {
    /// Keep the last `n` turns verbatim (clamped to [`MAX_COMPACT_TURNS`]).
    #[must_use]
    pub fn keep_last_n(n: usize) -> Self {
        CompactionPolicy {
            mode: CompactionMode::KeepLastN(n.min(MAX_COMPACT_TURNS)),
        }
    }

    /// Keep the last `n` turns and summarize older ones (clamped).
    #[must_use]
    pub fn summarize_older(n: usize) -> Self {
        CompactionPolicy {
            mode: CompactionMode::SummarizeOlder(n.min(MAX_COMPACT_TURNS)),
        }
    }

    /// Drop all turn text to artifact handles (the default, most restrictive form).
    #[must_use]
    pub fn drop_bulk_to_handles() -> Self {
        CompactionPolicy::default()
    }

    /// The configured mode.
    #[must_use]
    pub fn mode(self) -> CompactionMode {
        self.mode
    }

    /// Compacts `turns` (already-redacted [`Turn`]s from a [`Snapshot`]) under this
    /// policy. The output is re-redacted with `redactor` (defense in depth) and
    /// bounded to the `MAX_*` caps, then sealed as never-authority
    /// [`ModelVisibleText`].
    ///
    /// `turns` is expected in chain order (oldest first), matching
    /// [`crate::snapshot::Snapshot::turns`].
    #[must_use]
    pub fn compact(self, turns: &[Turn], redactor: &Redactor) -> CompactedHistory {
        let mut lines: Vec<String> = Vec::new();
        let mut dropped_artifacts = 0usize;

        match self.mode {
            CompactionMode::DropBulkToHandles => {
                for t in turns {
                    dropped_artifacts += t.artifacts.len();
                }
                if !turns.is_empty() {
                    lines.push(format!(
                        "[compacted: {} turn(s) dropped to artifact handles]",
                        turns.len()
                    ));
                }
            }
            CompactionMode::KeepLastN(n) | CompactionMode::SummarizeOlder(n) => {
                let summarize = matches!(self.mode, CompactionMode::SummarizeOlder(_));
                let keep_from = turns.len().saturating_sub(n);
                let older = &turns[..keep_from];
                let kept = &turns[keep_from..];

                if !older.is_empty() {
                    if summarize {
                        lines.push(format!(
                            "[summary: {} earlier turn(s) omitted]",
                            older.len()
                        ));
                    }
                    for t in older {
                        dropped_artifacts += t.artifacts.len();
                    }
                }
                for t in kept {
                    dropped_artifacts += t.artifacts.len();
                    lines.push(render_turn(t, redactor));
                }
            }
        }

        // Bound: cap the number of lines, then cap total bytes.
        if lines.len() > MAX_COMPACT_TURNS {
            let overflow = lines.len() - MAX_COMPACT_TURNS;
            lines.truncate(MAX_COMPACT_TURNS);
            // Replace the last kept line with an honest "+N more" marker so the cap
            // is visible rather than silent.
            if let Some(last) = lines.last_mut() {
                *last = format!("[compacted: {overflow} further line(s) omitted by turn cap]");
            }
        }

        let mut joined = lines.join("\n");
        if joined.len() > MAX_COMPACT_BYTES {
            joined = bound_str(&joined, MAX_COMPACT_BYTES);
        }

        // Seal as never-authority model-visible text (re-redacted as defense in depth).
        let text = redactor.to_model_visible(&joined);
        let retained_turns = count_lines(text.as_str());
        CompactedHistory {
            text,
            retained_turns,
            dropped_artifacts,
        }
    }
}

/// Renders one turn to a bounded, redacted line.
fn render_turn(t: &Turn, redactor: &Redactor) -> String {
    let prefix = match t.kind {
        TurnKind::User => "user",
        TurnKind::Model => "model",
        TurnKind::Tool => "tool",
    };
    let body = bound_str(&redactor.redact(&t.text), MAX_TURN_BYTES);
    format!("{prefix}: {body}")
}

/// Truncates `s` to at most `max` bytes, respecting UTF-8 char boundaries.
fn bound_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

fn count_lines(s: &str) -> usize {
    if s.is_empty() {
        0
    } else {
        s.lines().count()
    }
}

/// The bounded, redacted, never-authority result of compaction.
///
/// `text` is [`ModelVisibleText`]: it has provably passed the redactor, and the
/// type is the never-authority tag the rest of CrustCore uses for "context the
/// model may read but may never act on as instruction" (invariant 7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactedHistory {
    /// The compacted, redacted, bounded history text (never authoritative).
    pub text: ModelVisibleText,
    /// How many turn lines survived the caps.
    pub retained_turns: usize,
    /// How many artifacts were dropped to handle references.
    pub dropped_artifacts: usize,
}

impl CompactedHistory {
    /// Byte length of the compacted text (always within [`MAX_COMPACT_BYTES`]).
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.text.as_str().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crustcore_types::EventSeq;

    fn turn(seq: u64, kind: TurnKind, text: &str) -> Turn {
        Turn {
            seq: EventSeq(seq),
            kind,
            text: text.to_string(),
            artifacts: Vec::new(),
        }
    }

    #[test]
    fn default_is_most_restrictive() {
        assert_eq!(
            CompactionPolicy::default().mode(),
            CompactionMode::DropBulkToHandles
        );
    }

    #[test]
    fn drop_bulk_keeps_no_turn_text() {
        let turns = vec![
            turn(1, TurnKind::User, "hello there"),
            turn(2, TurnKind::Model, "general kenobi"),
        ];
        let out = CompactionPolicy::default().compact(&turns, &Redactor::new());
        assert!(!out.text.as_str().contains("kenobi"));
        assert!(out.text.as_str().contains("dropped to artifact handles"));
    }

    #[test]
    fn keep_last_n_keeps_only_the_tail() {
        let turns = vec![
            turn(1, TurnKind::User, "first"),
            turn(2, TurnKind::Model, "second"),
            turn(3, TurnKind::User, "third"),
        ];
        let out = CompactionPolicy::keep_last_n(1).compact(&turns, &Redactor::new());
        assert!(out.text.as_str().contains("third"));
        assert!(!out.text.as_str().contains("first"));
    }

    #[test]
    fn summarize_older_emits_a_summary_line() {
        let turns = vec![
            turn(1, TurnKind::User, "old one"),
            turn(2, TurnKind::Model, "old two"),
            turn(3, TurnKind::User, "recent"),
        ];
        let out = CompactionPolicy::summarize_older(1).compact(&turns, &Redactor::new());
        assert!(out.text.as_str().contains("earlier turn(s) omitted"));
        assert!(out.text.as_str().contains("recent"));
        assert!(!out.text.as_str().contains("old one"));
    }

    #[test]
    fn compaction_redacts_and_bounds() {
        let secret = "sk-COMPACTSENTINEL";
        let mut r = Redactor::new();
        r.register("sentinel", secret.as_bytes());
        let turns = vec![turn(
            1,
            TurnKind::Model,
            &format!("the key is {secret} keep it safe"),
        )];
        let out = CompactionPolicy::keep_last_n(1).compact(&turns, &r);
        assert!(
            !out.text.as_str().contains(secret),
            "secret survived compaction"
        );
    }

    #[test]
    fn never_exceeds_byte_cap() {
        let big = "x".repeat(MAX_TURN_BYTES * 4);
        let turns: Vec<Turn> = (0..100).map(|i| turn(i, TurnKind::Model, &big)).collect();
        let out =
            CompactionPolicy::keep_last_n(MAX_COMPACT_TURNS).compact(&turns, &Redactor::new());
        assert!(
            out.byte_len() <= MAX_COMPACT_BYTES,
            "exceeded byte cap: {}",
            out.byte_len()
        );
    }

    #[test]
    fn never_exceeds_turn_cap() {
        let turns: Vec<Turn> = (0..200)
            .map(|i| turn(i, TurnKind::Model, "short"))
            .collect();
        // Ask for more than the cap; constructor clamps and compaction bounds.
        let out = CompactionPolicy::keep_last_n(1000).compact(&turns, &Redactor::new());
        assert!(out.retained_turns <= MAX_COMPACT_TURNS, "exceeded turn cap");
    }
}
