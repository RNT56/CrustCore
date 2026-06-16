// SPDX-License-Identifier: Apache-2.0
//! Microbench: `Kernel::step(event)` (budget: sub-microsecond typical,
//! `ROADMAP.md` §17.2; Phase 1 task P1.7).
//!
//! Deliberately a **std-timer** harness (`harness = false`), not `criterion`: the
//! workspace is dependency-free and builds offline (`ROADMAP.md` §6.1), and a
//! bench target with `harness = false` adds no dependency and never enters the
//! nano dependency tree (`cargo tree --edges normal`), so it cannot affect the
//! size gate. If the per-step `Vec<Action>` allocation ever dominates this
//! measurement, that is the documented trigger to fast-track the
//! `SmallVec<[Action; 4]>` admission (see `crustcore_kernel::ActionVec`).
//!
//! Run with `cargo bench -p crustcore-kernel`. Iterations default to 1,000,000
//! and can be overridden with `CRUSTCORE_BENCH_ITERS`. Set
//! `CRUSTCORE_BENCH_STRICT=1` to exit non-zero if p50 exceeds the 1µs budget
//! (CI-gateable); otherwise a breach is reported as a warning to avoid
//! environment-driven flakiness.

use std::hint::black_box;
use std::time::Instant;

use crustcore_kernel::{Actor, Event, EventKind, Kernel};
use crustcore_policy::{PolicySnapshot, RiskProfile};
use crustcore_types::{EventSeq, JobId, LeaseOwner, Reversibility, TaskId, ToolCallId};

/// The sub-microsecond p50 budget (`ROADMAP.md` §17.2).
const BUDGET_NANOS: u128 = 1_000;

fn env_iters() -> u64 {
    std::env::var("CRUSTCORE_BENCH_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1_000_000)
}

/// Drives a kernel into a `Running` task with a leased job — the steady state in
/// which most `step` calls happen.
fn running_kernel() -> (Kernel, TaskId, JobId) {
    let mut k = Kernel::new(PolicySnapshot::new(RiskProfile::Supervised));
    let tid = TaskId(1);
    let jid = JobId(1);
    k.step(Event::inbound(EventKind::TaskCreated, EventSeq(1), Actor::Adapter).with_task(tid));
    k.step(
        Event::inbound(EventKind::JobQueued, EventSeq(2), Actor::Adapter)
            .with_task(tid)
            .with_job(jid),
    );
    k.step(
        Event::inbound(EventKind::JobLeased, EventSeq(3), Actor::Adapter)
            .with_task(tid)
            .with_job(jid)
            .with_lease_owner(LeaseOwner(1)),
    );
    (k, tid, jid)
}

fn main() {
    let iters = env_iters();
    let (mut kernel, tid, jid) = running_kernel();

    // The hot path: a reversible tool-call request -> policy classify (allow) ->
    // emit RunTool. Arenas stay bounded; only the sequence advances.
    let make = |seq: u64| {
        Event::inbound(EventKind::ToolCallRequested, EventSeq(seq), Actor::Model)
            .with_task(tid)
            .with_job(jid)
            .with_tool_call(ToolCallId(1))
            .with_reversibility(Reversibility::Reversible)
    };

    // Warm up (and skip the first sequence numbers used by setup).
    let mut seq = 4u64;
    for _ in 0..10_000 {
        let actions = kernel.step(black_box(make(seq)));
        black_box(&actions);
        seq += 1;
    }

    let mut samples: Vec<u128> = Vec::with_capacity(iters as usize);
    for _ in 0..iters {
        let event = black_box(make(seq));
        let start = Instant::now();
        let actions = kernel.step(event);
        let elapsed = start.elapsed().as_nanos();
        black_box(&actions);
        samples.push(elapsed);
        seq += 1;
    }

    samples.sort_unstable();
    let n = samples.len();
    let p = |q: f64| samples[((n as f64 * q) as usize).min(n - 1)];
    let sum: u128 = samples.iter().sum();
    let mean = sum / n as u128;
    let p50 = p(0.50);
    let p99 = p(0.99);

    println!("kernel_step over {n} iters:");
    println!("  mean = {mean} ns");
    println!("  p50  = {p50} ns   (budget {BUDGET_NANOS} ns)");
    println!("  p99  = {p99} ns");

    if p50 > BUDGET_NANOS {
        let msg = format!("kernel_step p50 {p50} ns exceeds budget {BUDGET_NANOS} ns");
        if std::env::var("CRUSTCORE_BENCH_STRICT").is_ok() {
            eprintln!("FAIL: {msg}");
            std::process::exit(1);
        }
        eprintln!("WARN: {msg}");
    }
}
