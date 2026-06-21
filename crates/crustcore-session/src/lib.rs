// SPDX-License-Identifier: Apache-2.0
//! Application-level session model for CrustCore (`docs/roadmap-v0.2.md`,
//! **C4-session**) — a redacted, **verify-or-refuse VIEW over the hash-chained
//! event log, never a competing store.**
//!
//! The `crustcore-eventlog` append-only chain ([`crustcore_eventlog::EventLog`])
//! is the single source of truth. This crate adds the application-level shape the
//! daemon, `crustcore-flow` (C3), and the dev UI (C7) lack today:
//!
//! - typed [`SessionId`] / [`ConversationId`] ([`id`]),
//! - a borrowing [`SessionView`] / [`ConversationView`] index over frames ([`view`]),
//! - derived, redacted, visibility-gated state [`Snapshot`]s ([`snapshot`]),
//! - resumable runs that **verify before they reconstruct** ([`resume`]),
//! - re-derived lease/heartbeat/cancellation/recovery status ([`lease`]),
//! - opaque, by-hash [`ArtifactHandle`]s ([`artifact`]),
//! - bounded, redact-then-bound history [`CompactionPolicy`] ([`compact`]),
//! - and a strictly read/derive/verify-only [`SessionService`] facade ([`service`]).
//!
//! ## Trust posture (the design rule, enforced structurally)
//!
//! - **The event log is the only store.** A session is an *index*; a snapshot is a
//!   *derived projection* at a known `seq`; a resumable run is a *replay-and-verify*
//!   of a frame range. Nothing here mints kernel state, mutates the chain, opens a
//!   PR, integrates a patch, or mints a [`crustcore_backend`-style] `VerifiedPatch`
//!   (invariants 13, 18). Completion remains solely
//!   `crustcore_backend::verify::run_verify`.
//! - **Secrets cannot enter a snapshot (invariant 3).** This is a *type fact*: no
//!   snapshot type contains a `SecretMaterial`/`Tainted<T>` field, and every
//!   retained text field is passed through [`crustcore_secrets::Redactor`]. Because
//!   [`crustcore_secrets::SecretMaterial`] implements none of
//!   `Debug`/`Clone`/`Serialize`, a secret captured into a `Serialize` snapshot
//!   would not even compile.
//! - **Fail-closed visibility gating (invariant 7).** A model-visible projection
//!   includes **only** frames whose [`crustcore_kernel::Visibility`] is
//!   [`ModelVisible`](crustcore_kernel::Visibility::ModelVisible). `Internal` (and,
//!   by construction, any unclassified) frame is excluded.
//! - **Resume verifies or refuses.** A resume runs
//!   [`crustcore_eventlog::EventLog::verify`] (or `verify_to_head` against a
//!   persisted head) **and** [`crustcore_receipts::join::verify_against_log`] and
//!   proceeds only when the chain `is_intact()` **and** the receipts `is_joined()`;
//!   otherwise it returns [`ResumeRefused`] carrying the break reason.
//! - **Artifacts are opaque handles (invariant 20).** Contents are referenced by
//!   `ArtifactId` only and never inlined into any view, snapshot, or projection.
//! - **Bounded everything (invariant 11).** Compaction is redact-then-bound, capped
//!   by the `MAX_*` constants in [`compact`], and emits never-authority
//!   [`crustcore_secrets::ModelVisibleText`]. The default policy is the most
//!   restrictive bounded form.
#![forbid(unsafe_code)]

pub mod artifact;
pub mod compact;
pub mod id;
pub mod lease;
pub mod resume;
pub mod service;
pub mod snapshot;
pub mod view;

mod serde_compat;

pub use artifact::ArtifactHandle;
pub use compact::{CompactedHistory, CompactionMode, CompactionPolicy};
pub use id::{ConversationId, SessionId};
pub use lease::{CancellationState, LeaseStatus, LeaseView};
pub use resume::{resume, resume_to_head, ResumeRefused};
pub use service::SessionService;
pub use snapshot::{Snapshot, SnapshotError, Turn, TurnKind};
pub use view::{ConversationView, SeqRange, SessionView};
