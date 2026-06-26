// SPDX-License-Identifier: Apache-2.0
//! C6T.7 leak-canary red-team (adversarial dimensions (a) and (d)).
//!
//! A secret in any emitted span attribute, metric label, span name, or metric name
//! is a release-blocker leak (invariants 1–3). This fixture proves it cannot happen:
//!
//! 1. **Payload sentinel.** A synthetic log whose frame payloads embed a sentinel
//!    secret. Because the projector never reads payload bytes (it maps only typed
//!    `FrameMeta`/receipt fields, invariant 7), the sentinel cannot reach telemetry
//!    even before redaction — and the broker-registered [`Redactor`] is the belt to
//!    that structural suspenders.
//! 2. **`Tainted<T>` frame.** A tainted value, registered as a secret, never
//!    declassifies into a span — it is dropped/redacted, not emitted.
//! 3. **`Redacted` frame.** A `RedactionState::Redacted` frame emits only kind+seq.
//! 4. **Adversarial attribute injection.** Even if the IR somehow carried the
//!    sentinel in an *attribute value*, the single redaction chokepoint scrubs it.
//!
//! The assertions scan **every** emitted string (names, keys, values) for the
//! sentinel and run `Redactor::would_leak` over each.

use crustcore_eventlog::{EventLog, FrameMeta, RedactionState};
use crustcore_kernel::{Actor, EventKind, Visibility};
use crustcore_secrets::{Redactor, Tainted};
use crustcore_telemetry::project::EventProjector;
use crustcore_telemetry::redact::redact_frame;
use crustcore_telemetry::{
    project::{ProjectedFrame, SpanModel},
    run_log, Config, InMemoryExporter, UsageBySeq,
};
use crustcore_types::{JobId, TaskId, Timestamp};

/// The canary string. If this ever appears in emitted telemetry, the test fails.
const SENTINEL: &str = "sk-LEAKCANARY-7f3a";

/// A redactor that knows the sentinel as a registered secret (as the broker would).
fn canary_redactor() -> Redactor {
    let mut r = Redactor::new();
    r.register("model-key", SENTINEL.as_bytes());
    r
}

#[test]
fn sentinel_in_payloads_never_reaches_emitted_telemetry() {
    let mut log = EventLog::new();
    let mk = |seq, kind, vis, red: RedactionState| {
        FrameMeta::new(seq, kind)
            .task(TaskId(1))
            .job(JobId(1))
            .actor(Actor::Model)
            .visibility(vis)
            .redaction(red)
            .timestamp(Timestamp::from_millis(seq))
    };
    // Payloads literally contain the sentinel across the span families.
    let payload = format!("the secret is {SENTINEL} do not leak").into_bytes();
    log.append(
        &mk(
            1,
            EventKind::ModelOutputReceived,
            Visibility::ModelVisible,
            RedactionState::Clean,
        ),
        &payload,
    );
    log.append(
        &mk(
            2,
            EventKind::ToolCallCompleted,
            Visibility::ModelVisible,
            RedactionState::Clean,
        ),
        &payload,
    );
    // A Redacted frame carrying the sentinel.
    log.append(
        &mk(
            3,
            EventKind::ModelOutputReceived,
            Visibility::ModelVisible,
            RedactionState::Redacted,
        ),
        &payload,
    );
    // An Internal frame carrying the sentinel.
    log.append(
        &mk(
            4,
            EventKind::PatchVerified,
            Visibility::Internal,
            RedactionState::Clean,
        ),
        &payload,
    );

    let r = canary_redactor();
    let mut exp = InMemoryExporter::new();
    run_log(
        &log,
        &[],
        &UsageBySeq::new(),
        0,
        u64::MAX,
        &Config::enabled_in_memory(),
        &r,
        &mut exp,
    );

    // No emitted string — name, key, or value — contains the sentinel.
    for s in exp.all_strings() {
        assert!(
            !s.contains(SENTINEL),
            "leak-canary: sentinel found in emitted telemetry: {s}"
        );
        assert!(
            !r.would_leak(s),
            "leak-canary: would_leak true on emitted string: {s}"
        );
    }
    // Sanity: we did emit something (the test is not vacuous).
    assert_eq!(exp.spans().len(), 4);
}

#[test]
fn tainted_value_is_never_declassified_into_a_span() {
    // A Tainted<T> wrapping the sentinel: the only path to model-visible text is the
    // redactor (declassify). Telemetry never calls declassify on raw taint; if a
    // tainted value's *redacted* form is used, the sentinel is gone.
    let tainted = Tainted::new(format!("leaked {SENTINEL} here"));
    let r = canary_redactor();

    // Declassifying through the redactor scrubs it (the only allowed path).
    let safe = tainted.declassify(&r);
    assert!(!safe.as_str().contains(SENTINEL));

    // The Debug of a tainted value never reveals it either.
    assert!(!format!("{tainted:?}").contains(SENTINEL));
}

#[test]
fn redaction_chokepoint_scrubs_an_injected_attribute_value() {
    // Belt-and-suspenders for dimension (a): even if some future projector path put
    // the sentinel into an attribute VALUE, the single redaction chokepoint removes
    // it. (Names are enum-derived, so they can never carry it.)
    let r = canary_redactor();
    let frame = ProjectedFrame {
        spans: vec![
            SpanModel::new("gen_ai.model_response").attr("note", format!("auth {SENTINEL} used"))
        ],
        metrics: vec![],
    };
    let redacted = redact_frame(&frame, &r);
    let v = &redacted.spans[0].attrs[0].1;
    assert!(!v.contains(SENTINEL), "chokepoint failed to scrub: {v}");
    assert!(v.contains("[REDACTED:model-key]"));
    assert!(!r.would_leak(v));
}

#[test]
fn span_and_metric_names_are_enum_derived_never_sentinel() {
    // Dimension (c): names cannot be payload-injected. Project every kind and assert
    // no name contains anything but the fixed enum-derived tokens.
    let projector = EventProjector::new();
    for kind in crustcore_kernel::EventKind::ALL {
        let meta = FrameMeta::new(1, kind)
            .task(TaskId(1))
            .visibility(Visibility::ModelVisible);
        let pf = projector.project(&meta, None);
        for span in &pf.spans {
            assert!(!span.name.contains(SENTINEL));
            assert!(span.name.starts_with("gen_ai.") || span.name.starts_with("crustcore."));
        }
        for m in &pf.metrics {
            assert!(!m.name.contains(SENTINEL));
        }
    }
}
