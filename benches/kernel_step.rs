// SPDX-License-Identifier: Apache-2.0
//! Microbench template: `Kernel::step(event)` (budget: sub-microsecond typical,
//! ROADMAP.md §17.2). NOT yet wired as a cargo bench target — see
//! benches/README.md.
//!
//! Intended measurement (Phase 1+):
//!   - construct a `Kernel` with a representative `PolicySnapshot`
//!   - feed a steady stream of events and time `step`
//!   - assert p50/p99 against the budget

// TODO(perf): port to the admitted bench harness (criterion or std-timer) and
// register as `[[bench]]` in crustcore-kernel with `harness = false`.
fn main() {
    eprintln!("kernel_step bench is a template; see benches/README.md");
}
