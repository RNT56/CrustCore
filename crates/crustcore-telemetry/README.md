# crustcore-telemetry

> Read-only OpenTelemetry / GenAI-semconv **projection** of CrustCore's audit log.
> Non-nano sidecar. Mints nothing, mutates nothing, is never authoritative.

CrustCore already keeps a *stronger* audit trail than telemetry: the hash-chained
event log (`crustcore-eventlog`) and the MAC-chained tool receipts
(`crustcore-receipts`). This crate is a **derived, read-only projection** of those
frames+receipts into standard OpenTelemetry spans and metrics under the
[GenAI semantic conventions], so model calls, tool runs, verification outcomes, and
budget burn show up in Grafana / Honeycomb / Jaeger — *without widening the trust
boundary one inch*.

This is phase `C6-telemetry` of Track C; see
[`docs/roadmap-v0.2.md`](../../docs/roadmap-v0.2.md) §C6-telemetry.

## The read-only projection contract

- **Mints nothing, mutates nothing.** `EventProjector::project` takes a *borrowed*
  frame (+ its joined receipt) and emits a neutral IR. The audit log stays the
  single source of truth. Telemetry is **never authoritative**: a deleted or altered
  span cannot affect a verdict, a budget, or a `VerifiedPatch` (which only
  `verify::run_verify` may mint). (Invariants 6, 13.)
- **Names come only from the closed `EventKind` enum** (`semconv::span_name`), never
  from (untrusted, invariant 7) payload content — so telemetry can never be treated
  as downstream-authoritative.
- **Single redaction chokepoint.** Every emitted attribute value and metric label
  passes through `crustcore_secrets::Redactor::redact` in `redact::redact_frame` —
  the *only* path from IR to an exporter. A `Tainted<T>` value is dropped, never
  declassified. A secret in a span is a release-blocker leak. (Invariants 1–3.)
- **Bounded everything.** `MAX_ATTR_LEN` (per-value), `MAX_ATTRS` (per span/metric,
  with a dropped-count marker), and `Config::batch_bound` (frames per run) keep an
  adversarial log from blowing the exporter. (Invariant 11.)
- **Visibility/redaction aware.** An `Internal`-visibility or `RedactionState::Redacted`
  frame emits only `kind` + `seq` — no payload-derived attributes, no receipt hashes.
- **Off by default, loopback-only.** `Config::default()` has `enabled = false`; the
  default exporter is in-memory; the default collector endpoint is `127.0.0.1`.
  Fail-closed when unconfigured.

## Span / metric families

| Frame kind(s)                            | Span / metric name                  |
|------------------------------------------|-------------------------------------|
| `ModelRequestStarted`                    | `gen_ai.model_request`              |
| `ModelOutputReceived`                    | `gen_ai.model_response`            |
| `ToolCallStarted`                        | `crustcore.tool.started`           |
| `ToolCallCompleted` (+ joined receipt)   | `crustcore.tool.completed`         |
| `PatchProposed` / `Verified` / `Rejected`| `crustcore.verify.*`               |
| `JobLeased`                              | `crustcore.budget.lease`           |
| budget deltas (`semconv::budget_samples`)| `crustcore.budget.<axis>` (metric) |
| every other kind                         | `crustcore.event.<kind>`           |

GenAI model attributes are intentionally conservative: `gen_ai.system = "crustcore"`
(the *mediator*, not the provider) and `gen_ai.operation.name`. Model name and token
usage are **not** taken from untrusted model output (invariant 17); threading
recorded `ModelCard`/usage metadata into these spans is `TODO(C6-genai-usage)`.

Tool spans bind to their receipt via `crustcore_receipts::join::verify_against_log`
(P5-join, consumed not re-implemented) and carry only the receipt's hashes / MAC /
ids — never tool name, args, or result values (invariant 10).

## Layering

The deterministic core (`project` + `semconv` + `redact` + `InMemoryExporter` +
`run`) is fully CI-testable: **no network, no secrets, no SDK**. The heavy OTel/OTLP
stack and broker-mediated endpoint auth live behind the `otlp` cargo feature
(`export::otlp`, `auth`), **off by default**, and never enter the nano graph
(invariants 19, 20). The live OTLP socket and per-request broker auth injection are
`TODO(C6-otlp-live)`; the deterministic projection never needs them.

```rust
use crustcore_telemetry::{run_log, Config, InMemoryExporter};
use crustcore_secrets::Redactor;

// `log`: &EventLog, `receipts`: &[ToolReceipt], `redactor`: &Redactor (broker-loaded).
let mut exporter = InMemoryExporter::new();
let report = run_log(
    log, receipts,
    /* seq_lo */ 0, /* seq_hi */ u64::MAX,
    &Config::enabled_in_memory(),
    redactor,
    &mut exporter,
);
```

## OTLP endpoint auth (behind `otlp`)

Any collector bearer/header is resolved **per request** through the secret broker
(`SecretBroker` → `ApprovedSecretView` → `CredentialProxy::bearer`) at send time —
never from an environment variable, never placed in a span, never model-visible
(invariant 1). The exporter process holds only a `SecretHandle` (id + label), not the
bytes. See `auth::OtlpEndpointAuth`.

[GenAI semantic conventions]: https://opentelemetry.io/docs/specs/semconv/gen-ai/
