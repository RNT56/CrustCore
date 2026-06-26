// SPDX-License-Identifier: Apache-2.0
//! Read-only OpenTelemetry / GenAI-semconv projection of CrustCore's audit log
//! (Track C, phase `C6-telemetry`; `docs/roadmap-v0.2.md` §C6-telemetry).
//!
//! CrustCore already mints a *stronger* audit trail than telemetry: the
//! hash-chained event log ([`crustcore_eventlog`]) and the MAC-chained tool
//! receipts ([`crustcore_receipts`]). This crate is a **derived, read-only
//! projection** of those frames+receipts into standard OpenTelemetry spans and
//! metrics under the GenAI semantic conventions — so model calls, tool runs,
//! verification outcomes, and budget burn become spans/metrics every
//! observability stack already speaks (Grafana/Honeycomb/Jaeger) **without
//! widening the trust boundary one inch**.
//!
//! ## What it is (and is not)
//!
//! - It **mints nothing and mutates nothing.** The projector takes a *borrowed*
//!   frame (+ its joined receipt) and emits a neutral in-crate IR. The audit log
//!   stays the single source of truth; telemetry is **never authoritative**: a
//!   deleted or altered span cannot affect a verdict, a budget, or a
//!   `VerifiedPatch` (which only `verify::run_verify` may mint).
//! - Span/metric **names derive only from the closed [`crustcore_kernel::EventKind`]
//!   enum**, never from (untrusted, invariant 7) payload content — so telemetry can
//!   never be treated as downstream-authoritative (invariant 6).
//! - **Every** emitted attribute value and metric label is scrubbed through
//!   [`crustcore_secrets::Redactor`] at a single emission chokepoint
//!   ([`redact`]); a [`crustcore_secrets::Tainted`] value is dropped, never
//!   declassified. A secret in a span is a release-blocker leak (invariants 1–3).
//! - Output is **bounded** ([`redact::MAX_ATTRS`] / [`redact::MAX_ATTR_LEN`] /
//!   [`config::Config::batch_bound`]) so a large/adversarial log cannot blow the
//!   exporter (invariant 11).
//!
//! ## Layering
//!
//! The deterministic core ([`project`] + [`semconv`] + [`redact`] +
//! [`export::InMemoryExporter`] + [`run`]) is fully CI-testable: no network, no
//! secrets, no SDK. The heavy OTel/OTLP stack and broker-mediated endpoint auth
//! live behind the `otlp` cargo feature ([`export::otlp`], [`auth`]), off by
//! default, and never enter the nano graph (invariants 19, 20).
#![forbid(unsafe_code)]

pub mod auth;
pub mod config;
pub mod export;
pub mod project;
pub mod redact;
pub mod run;
pub mod semconv;
pub mod usage;

pub use config::{Config, ExporterChoice};
pub use export::{Emitted, Exporter, InMemoryExporter};
pub use project::{EventProjector, MetricSample, ProjectedFrame, SpanModel};
pub use run::{run, run_log, FrameInput, RunReport};
pub use semconv::{budget_samples, span_name};
pub use usage::{RecordedUsage, UsageBySeq};
