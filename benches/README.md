# benches/

Microbenchmarks for the kernel hot paths.

`kernel_step.rs` **is wired** (Phase 1, P1.7) as a `[[bench]]` target on
`crustcore-kernel` with `harness = false` and a **std-timer** body — deliberately
*not* `criterion`, so it adds no dependency, keeps the workspace offline/std-only
(`ROADMAP.md` §6.1), and never enters the nano dependency tree
(`cargo tree --edges normal`), so it cannot affect the size gate. Run it with:

```bash
cargo bench -p crustcore-kernel --bench kernel_step
# Tunables:
CRUSTCORE_BENCH_ITERS=200000 cargo bench -p crustcore-kernel --bench kernel_step
CRUSTCORE_BENCH_STRICT=1     cargo bench -p crustcore-kernel --bench kernel_step  # exit 1 on p50 budget breach
```

The remaining files are **templates** — their harnesses are admitted by the phase
that owns each hot path. They document the intended measurements and budgets.

Hot-path budgets (`ROADMAP.md` §17.2):

| Bench | Path | Budget (typical) | Status |
| --- | --- | --- | --- |
| `kernel_step.rs` | `Kernel::step(event)` | sub-microsecond | **wired** (std-timer) |
| `policy_check.rs` | policy classification | < 20 µs | template |
| `path_confine.rs` | confined-path resolution | < 100 µs (normal paths) | template |
| `event_append.rs` | event frame encode (excl. fsync) | < 50 µs | template |

When wiring the rest, add `[[bench]]` targets (with `harness = false`) to the
owning crate and assert these budgets in CI's perf job. If the per-step
`Vec<Action>` allocation ever dominates `kernel_step`, that is the documented
trigger to fast-track the `SmallVec<[Action; 4]>` admission (see
`crustcore_kernel::ActionVec` and `docs/architecture.md` §2.1).
