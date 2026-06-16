// SPDX-License-Identifier: Apache-2.0
//! Microbench template: event frame encode (budget: < 50 µs excluding fsync,
//! ROADMAP.md §17.2). NOT yet wired as a cargo bench target — see
//! benches/README.md.

// TODO(perf): time encoding an `EventFrame` and updating the running hash chain
// (excluding fsync) and assert against the budget.
fn main() {
    eprintln!("event_append bench is a template; see benches/README.md");
}
