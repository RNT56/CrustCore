// SPDX-License-Identifier: Apache-2.0
//! Microbench template: confined-path resolution (budget: < 100 µs for normal
//! paths, ROADMAP.md §17.2). NOT yet wired as a cargo bench target — see
//! benches/README.md.

// TODO(perf): time `WorktreeRoot::confine_read`/`confine_write` over a corpus of
// normal and adversarial paths and assert against the budget.
fn main() {
    eprintln!("path_confine bench is a template; see benches/README.md");
}
