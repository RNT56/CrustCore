// SPDX-License-Identifier: Apache-2.0
//! The CrustCore nanokernel (`ROADMAP.md` §5, Phase 1).
//!
//! The kernel is a **sync, deterministic, allocation-light** state machine. It
//! consumes [`Event`]s and produces a bounded list of [`Action`]s. It has **no**
//! async runtime, network, database, or tool execution inside it — those live in
//! adapters that translate the dirty outside world into events and turn the
//! kernel's actions into real operations (`docs/architecture.md`).
//!
//! ```text
//! impl Kernel {
//!     pub fn step(&mut self, event: Event) -> Vec<Action> { ... }
//! }
//! ```
//!
//! Status: Phase 0 scaffold. The event/action vocabulary and the `step`
//! signature are in place; the full transition table, arenas, budgets, and
//! approval flow are implemented in Phase 1 (`TODO(P1.*)`).
#![forbid(unsafe_code)]

pub mod action;
pub mod event;
mod kernel;

pub use action::Action;
pub use event::{Actor, Event, EventKind, Visibility};
pub use kernel::Kernel;
