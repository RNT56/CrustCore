// SPDX-License-Identifier: Apache-2.0
//! The **trusted recorded-usage carrier** for GenAI model attributes
//! (`C6-genai-usage`).
//!
//! GenAI semconv wants `gen_ai.request.model` / `gen_ai.response.model` and
//! `gen_ai.usage.{input,output}_tokens` on the model spans. CrustCore refuses to
//! read those from free-text **model output**: a model can write any string
//! (including a fake provider/model name), and that text is untrusted data
//! (invariants 7, 17). [`FrameMeta`] header fields are typed and trusted, but they
//! deliberately do **not** carry the `ModelCard` / token-usage capability metadata.
//!
//! So this module adds a minimal, separate carrier that **only trusted code may
//! populate**: the daemon/adapter that actually made the (mediated) model call —
//! the same code that owns the recorded `ModelCard` id and the provider-reported
//! token counts — records a [`RecordedUsage`] keyed by the frame's `seq`. The
//! read-only projection then *reads* that carrier; it never derives these values
//! from any payload, transcript, or model-authored text.
//!
//! Properties this preserves:
//! - The carrier is keyed by [`crustcore_types::EventSeq`] (a trusted header field),
//!   so a recorded usage entry can only ever attach to the exact frame it was
//!   recorded for — it cannot be smuggled onto an unrelated span.
//! - The values are plain typed data (`String` + two `u64`s). They are still
//!   **pre-redaction**: the model id passes through [`crate::redact`] (the sole
//!   emission chokepoint) like every other attribute value, and a
//!   [`crustcore_secrets::Tainted`] value is dropped there, never declassified.
//! - A frame *without* a recorded entry emits **no** GenAI model/usage attributes:
//!   absence is honest (no fabricated usage), exactly like a `ToolCallCompleted`
//!   with no joined receipt records the receipt as `absent`.
//!
//! [`FrameMeta`]: crustcore_eventlog::FrameMeta

use std::collections::BTreeMap;

use crustcore_types::EventSeq;

/// Trusted, recorded per-request GenAI usage for one model frame.
///
/// **Provenance is load-bearing.** Construct this only from *recorded capability
/// metadata* — the `ModelCard`/provider id the mediator selected and the token
/// counts the provider reported back through the mediated transport. Never build
/// it from model-authored text or decoded payload bytes (invariants 6, 7, 17).
///
/// All fields are pre-redaction; `model` still passes the [`crate::redact`]
/// chokepoint before any exporter sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedUsage {
    /// The recorded model identifier (e.g. the `ModelCard` id the mediator used).
    /// This is the *mediator's recorded selection*, not a name parsed from output.
    pub model: String,
    /// Provider-reported input (prompt) token count for this request.
    pub input_tokens: u64,
    /// Provider-reported output (completion) token count for this request.
    pub output_tokens: u64,
}

impl RecordedUsage {
    /// A recorded-usage record. The caller asserts, by calling this, that `model`
    /// and the token counts come from trusted recorded capability metadata — never
    /// from model output (invariant 17).
    #[must_use]
    pub fn new(model: impl Into<String>, input_tokens: u64, output_tokens: u64) -> Self {
        RecordedUsage {
            model: model.into(),
            input_tokens,
            output_tokens,
        }
    }
}

/// A trusted lookup of [`RecordedUsage`] keyed by frame [`EventSeq`].
///
/// Populated only by trusted code (the daemon/adapter that made the mediated model
/// call, or a test that simulates it). The projection borrows it read-only and
/// attaches a record to a model frame **only** when the keys match exactly, so a
/// recorded usage entry can never be attached to a frame it was not recorded for.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UsageBySeq {
    by_seq: BTreeMap<u64, RecordedUsage>,
}

impl UsageBySeq {
    /// An empty map.
    #[must_use]
    pub fn new() -> Self {
        UsageBySeq::default()
    }

    /// Records (trusted) usage for the frame at `seq`. Last write wins. Returns
    /// `self` for builder-style population by trusted code.
    #[must_use]
    pub fn record(mut self, seq: EventSeq, usage: RecordedUsage) -> Self {
        self.by_seq.insert(seq.0, usage);
        self
    }

    /// Records (trusted) usage for the frame at `seq`, mutating in place.
    pub fn insert(&mut self, seq: EventSeq, usage: RecordedUsage) {
        self.by_seq.insert(seq.0, usage);
    }

    /// Looks up the recorded usage for the frame at `seq`, if any. The projection
    /// uses this; a miss means "no recorded usage" and yields no GenAI usage attrs.
    #[must_use]
    pub fn get(&self, seq: EventSeq) -> Option<&RecordedUsage> {
        self.by_seq.get(&seq.0)
    }

    /// Whether any usage has been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_seq.is_empty()
    }

    /// How many frames have recorded usage.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_seq.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_get_by_exact_seq() {
        let map = UsageBySeq::new().record(EventSeq(7), RecordedUsage::new("model-x", 100, 25));
        // Hit on the exact seq.
        let u = map.get(EventSeq(7)).expect("recorded for seq 7");
        assert_eq!(u.model, "model-x");
        assert_eq!(u.input_tokens, 100);
        assert_eq!(u.output_tokens, 25);
        // Miss on any other seq: a recorded entry attaches only to its own frame.
        assert!(map.get(EventSeq(8)).is_none());
        assert!(map.get(EventSeq(6)).is_none());
    }

    #[test]
    fn empty_map_yields_nothing() {
        let map = UsageBySeq::new();
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
        assert!(map.get(EventSeq(1)).is_none());
    }

    #[test]
    fn insert_mutates_in_place_last_write_wins() {
        let mut map = UsageBySeq::new();
        map.insert(EventSeq(3), RecordedUsage::new("a", 1, 2));
        map.insert(EventSeq(3), RecordedUsage::new("b", 9, 8));
        assert_eq!(map.len(), 1);
        assert_eq!(map.get(EventSeq(3)).unwrap().model, "b");
    }
}
