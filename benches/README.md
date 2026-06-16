# benches/

Microbenchmark templates for the kernel hot paths. They are **not yet wired as
cargo bench targets** — the bench harness (`criterion`, or a std-timer harness)
is admitted in the performance phase, which needs network to fetch the dev-dep.
Until then these files document the intended measurements and their budgets.

Hot-path budgets (`ROADMAP.md` §17.2):

| Bench | Path | Budget (typical) |
| --- | --- | --- |
| `kernel_step.rs` | `Kernel::step(event)` | sub-microsecond |
| `policy_check.rs` | policy classification | < 20 µs |
| `path_confine.rs` | confined-path resolution | < 100 µs (normal paths) |
| `event_append.rs` | event frame encode (excl. fsync) | < 50 µs |

When wired up, add `[[bench]]` targets (with `harness = false` for criterion) to
the owning crate and assert these budgets in CI's perf job.
