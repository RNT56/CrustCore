// SPDX-License-Identifier: Apache-2.0
//! `crustcore-flow` — a typed, deterministic workflow DSL over CrustCore's existing
//! supervisor/subagent/verify primitives (Track C, phase `C3-flow`;
//! `docs/roadmap-v0.2.md`).
//!
//! A [`Flow`](graph::Flow) is a directed graph of typed [`Node`](graph::Node)s —
//! `model`, `tool`, `verify`, `review`, `parallel`, `loop_until`, `route`, `join`.
//! The engine ([`FlowEngine`](engine::FlowEngine)) is a **pure deterministic
//! scheduler that owns no I/O**: every effectful node delegates to an injected
//! driver ([`FlowDrivers`](drivers::FlowDrivers)). This mirrors the closure-injection
//! seam inside `crustcore_backend::verify` and `crustcore_daemon::exec`, so the whole
//! graph is unit-testable with [`FakeDrivers`](drivers::FakeDrivers) in CI, and live
//! transports drop in behind the `live-flow` feature with the engine unchanged.
//!
//! ## A Flow is a plan, not an authority
//!
//! The trust story is preserved **structurally**, not by convention:
//!
//! - **Completion (invariant 13).** The only path to
//!   [`FlowOutcome::Completed`](outcome::FlowOutcome::Completed) is a `Verify` node
//!   whose [`VerifyDriver`](drivers::VerifyDriver) returns the
//!   `Verified`-carrying [`VerifyOutcome`] from the public
//!   `crustcore_backend::verify::run_verify` — the sole minter of a `VerifiedPatch`.
//!   `Model`/`Review`/`Tool` results are advisory/result data
//!   ([`NodeOutput`](outcome::NodeOutput)) that the type system forbids from
//!   completing a flow. No node fabricates verifier evidence — `VerifiedPatch` is
//!   type-sealed in `crustcore-backend`, so a node cannot even construct one.
//! - **Approval (invariants 4, 14).** An irreversible node halts unless an
//!   externally-minted approval token is present in [`FlowState`](graph::FlowState).
//!   No node mints, forges, or deserializes an `Approved<T>` — its only mint path is
//!   `AuthorizedUser::approve`, and `FlowState`'s approval field is non-`Serialize`.
//! - **Policy + sandbox (invariants 8, 9).** A `Tool` node is classified through
//!   `crustcore_policy::PolicySnapshot::classify` before it can run; a forgotten
//!   classification defaults to `Reversibility::Destructive` (fail closed). Live
//!   tool execution additionally passes a sandbox profile.
//! - **Untrusted data at predicates (invariant 7).** Any `model`/`tool`/`review`
//!   output feeding a `Route`/`LoopUntil` predicate is wrapped with
//!   `crustcore_secrets::Tainted::new`, redacted, and bounded before it can
//!   influence a branch. Predicates may read non-tainted typed [`FlowState`] fields
//!   directly; they can never read raw model/tool text.
//! - **No user channel, no integration (invariants 5, 6).** No node reaches the
//!   user, and the flow **never integrates** —
//!   `crustcore_daemon::supervisor::decide_integration` stays the supervisor's
//!   authority. There is no integration node and no call to it anywhere here.
//! - **Budgets (invariant 11).** Every `Parallel` has a `max_concurrency` cap, every
//!   `LoopUntil` a `max_iterations` cap, and the flow a [`FlowBudget`](budget::FlowBudget).
//!
//! ## Non-nano
//!
//! This is a sidecar crate. It is never added to the nano feature graph and links no
//! forbidden deps in its default build; the live drivers are `live-flow`-gated.
#![forbid(unsafe_code)]

pub mod budget;
pub mod builder;
pub mod drivers;
pub mod engine;
pub mod graph;
pub mod outcome;
pub mod predicate;

#[cfg(feature = "live-flow")]
pub mod live;

pub use budget::{BudgetBreach, FlowBudget, FlowUsage};
pub use builder::FlowBuilder;
pub use drivers::{
    DriverError, FakeDrivers, FlowDrivers, ModelDriver, ReviewDriver, ToolDriver, ToolInvocation,
    VerifyDriver,
};
pub use engine::{FlowEngine, RunReport};
pub use graph::{Flow, FlowError, FlowState, Node, NodeId, ToolSpec};
pub use outcome::{FlowOutcome, NodeOutput};
pub use predicate::Predicate;
