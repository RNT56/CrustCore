// SPDX-License-Identifier: Apache-2.0
//! Microbench template: policy classification (budget: < 20 µs typical,
//! ROADMAP.md §17.2). NOT yet wired as a cargo bench target — see
//! benches/README.md.

// TODO(perf): time `PolicySnapshot::classify` across reversibility/profile
// combinations and assert against the budget.
fn main() {
    eprintln!("policy_check bench is a template; see benches/README.md");
}
