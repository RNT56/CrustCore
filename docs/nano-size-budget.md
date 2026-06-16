# docs/nano-size-budget.md — Nano Size & Performance Budgets

> **Purpose:** define CrustCore's size-as-architecture discipline — per-tier size
> budgets, hot-path performance budgets, the CI size gate, release profiles, the
> forbidden-in-nano dependency list, and how to measure with `cargo-bloat` /
> `cargo-tree`.

**Cross-links:** [`ROADMAP.md` §17](../ROADMAP.md) (size & performance budgets),
[`ROADMAP.md` §2.1](../ROADMAP.md) (nano contents + forbidden deps),
[`ROADMAP.md` §1.2](../ROADMAP.md) (NullClaw lesson),
[`CLAUDE.md` §9.2](../CLAUDE.md) (nano size gate),
[`INVARIANTS.md` #19, #20](../INVARIANTS.md).
**Sibling docs:** [`architecture.md`](./architecture.md) (why the split makes
size achievable), [`policy.md`](./policy.md), [`backend-contract.md`](./backend-contract.md).

---

## 1. Size is an architecture, not a compiler flag

The flagship claim — `crustcore-nano` < 800kB stripped — is an *architectural*
property, not the output of an aggressive optimizer pass. This is the central
**NullClaw lesson** ([`ROADMAP.md` §1.2](../ROADMAP.md)):

> **Size is an architecture, not a compiler flag.** The small binary must avoid
> frameworks and heavy stacks entirely.

You cannot `opt-level="z"` your way out of linking Tokio + Rustls + a database +
a provider SDK. The ZeroClaw lesson ([`ROADMAP.md` §1.3](../ROADMAP.md)) is the
counter-example: a Rust agent runtime balloons to multiple megabytes the moment
it includes Tokio, Reqwest/Rustls, channels, tools, dashboard/gateway, browser,
MCP, database, UI, plugins, and observability. CrustCore avoids this by keeping
all of that out of the kernel and nano binary entirely (see
[`architecture.md` §7](./architecture.md) — what the kernel must never know
about). The optimizer then makes a small thing smaller; it does not make a large
thing small.

CrustCore also does **not** try to prove "everything in 800kB." It proves "the
*verifier kernel* in 800kB" ([`ROADMAP.md` §1.2](../ROADMAP.md)). Heavy
capabilities are sidecars (`crustcore-net`, `-daemon`, `-mcp`, `-index`, `-full`).

This connects directly to **invariant 20** (*unused capabilities must cost zero
model context and preferably zero linked code*): capability packs are separate,
feature-gated crates; an unused pack is not linked into nano at all.

---

## 2. Size budgets per tier

Targets ([`ROADMAP.md` §17.1](../ROADMAP.md), [`CLAUDE.md` §3](../CLAUDE.md)):

| Tier | Budget (stripped) |
| --- | --- |
| `crustcore-nano` | **hard target < 800kB**, stretch **< 600kB** |
| `crustcore-net` | target < 8MB |
| `crustcore-daemon` | target < 10MB |
| `crustcore-full` | target < 25MB |

(`crustcore-mcp` 3–10MB and `crustcore-index` 2–8MB per [`ROADMAP.md` §2](../ROADMAP.md);
the §17.1 table calls out the four headline numbers above.) The nano number is
the only one that is a *release blocker* via invariant 19. The platform of record
for the hard target is **Linux x86_64** ([`ROADMAP.md` §22](../ROADMAP.md) DoD #1).

### 2.1 What counts against the nano budget

The budget is measured on the **stripped release binary** built with the `nano`
feature set and `--no-default-features` (§4). What counts:

- every crate linked into `crustcore-nano` (kernel + the nano-allowed adapters);
- monomorphized generic code (watch generic blowup — it is a common bloat source);
- embedded data/strings, panic messages, and formatting machinery;
- any transitive dependency a nano-allowed crate drags in.

What does **not** count: code in sidecar crates that nano only *invokes as an
external command* (`git`, the sandbox backend, `codex`, `claude`,
`crustcore-net`/`crustcore-mcp` helpers — [`ROADMAP.md` §2.1](../ROADMAP.md)).
Invoking a helper binary is free against the nano budget; *linking* its stack is
not. This is the whole point of the helper-process boundary.

---

## 3. Hot-path performance budgets

Size is not the only budget. The kernel and its hot paths have time/space budgets
([`ROADMAP.md` §17.2](../ROADMAP.md)) measured by `benches/`:

| Hot path | Target |
| --- | --- |
| kernel step | sub-microsecond typical |
| policy check | < 20µs typical |
| path confinement | < 100µs typical for normal paths |
| event append encoding | < 50µs (excluding fsync) |
| CLI `--version` cold start | < 10ms on a dev machine |
| nano idle RSS | < 5MB, stretch < 2MB |

These are tracked by `benches/kernel_step.rs`, `benches/policy_check.rs`,
`benches/path_confine.rs`, and `benches/event_append.rs`
([`ROADMAP.md` §6](../ROADMAP.md)). The kernel's allocation-light, synchronous,
arena-backed design ([`architecture.md` §2](./architecture.md)) exists to hit the
sub-microsecond step target; `SmallVec<[Action; 4]>` keeps the common fan-out
allocation-free. A regression here is as real as a size regression — a step that
allocates per call, or a policy check that walks an unbounded list, fails the
budget even if the binary is small.

---

## 4. The CI size gate

Every PR must run these commands ([`ROADMAP.md` §17.3](../ROADMAP.md)):

```bash
cargo build --profile nano -p crustcore --no-default-features --features nano
cargo bloat --profile nano -p crustcore --crates -n 30
cargo tree -p crustcore --no-default-features --features nano
```

- The **build** produces the artifact whose stripped size is compared to the
  budget.
- `cargo bloat --crates -n 30` reports the 30 largest crates by code size — the
  primary tool for finding *what* grew.
- `cargo tree` (with the exact nano feature set) reveals *which* dependencies are
  linked — the primary tool for catching a forbidden dependency sneaking in
  transitively.

### 4.1 The gate rule (invariant 19)

> The size gate is a first-class CI check, not a nice-to-have. A PR that pushes
> `crustcore-nano` over budget **fails CI** unless the maintainer **explicitly**
> raises the budget in the **same PR** with justification
> ([`CLAUDE.md` §9.2](../CLAUDE.md), [`ROADMAP.md` §17.3](../ROADMAP.md)).

There is no silent budget creep. Raising the budget is a deliberate,
maintainer-owned, reviewed act recorded in the same change — never a side effect
of merging a feature. The forbidden-dependency check (§5) runs alongside the size
gate in `cargo xtask verify` ([`CLAUDE.md` §9.1](../CLAUDE.md)); a forbidden dep
in nano is an immediate failure regardless of the resulting size.

`cargo xtask verify` (and the `xtask/size_check` task — [`ROADMAP.md` §6](../ROADMAP.md))
wraps these into the standard verification loop run on every PR.

---

## 5. Forbidden-in-nano dependency list

These must **never** link into `crustcore-nano` ([`ROADMAP.md` §2.1](../ROADMAP.md),
[`CLAUDE.md` §5.1](../CLAUDE.md)):

```text
- tokio
- reqwest
- rustls
- hyper
- axum
- tower
- clap
- sqlx / rusqlite / redb (by default)
- rmcp
- provider SDKs
- GitHub SDKs
- Telegram SDKs
- tree-sitter / LSP
- rich TUI
- rich telemetry stack
- embedded webhook server
```

The `crustcore-kernel` crate has a tighter ban still ([`ROADMAP.md` §6.1](../ROADMAP.md)):
forbidden are tokio, reqwest, serde_json, clap, sqlx, rmcp, axum; allowed are
`std` plus measured `smallvec`/`arrayvec`/`thiserror`.

Nano **may invoke** these as external commands ([`ROADMAP.md` §2.1](../ROADMAP.md)) —
`git`, the sandbox backend, `codex`, `claude`, the `crustcore-net` helper, the
`crustcore-mcp` helper — because invoking a process links nothing.

The dependency-admission policy ([`CLAUDE.md` §6.4](../CLAUDE.md),
[`ROADMAP.md` §20.3](../ROADMAP.md)): a dependency may enter nano only if **all**
hold — (1) it replaces more code than it adds, (2) it pulls no second
runtime/TLS/DB stack, (3) it does not push the binary past budget, (4) it has a
clear maintenance/security story, (5) `cargo-bloat` output is attached to the PR.

---

## 6. Release profiles

The nano release profile ([`ROADMAP.md` §17.4](../ROADMAP.md)):

```toml
[profile.nano]
inherits = "release"
opt-level = "z"
lto = "fat"
codegen-units = 1
panic = "abort"
strip = "symbols"
debug = false
incremental = false
```

Rationale per setting:

- `inherits = "release"` — start from the optimized baseline.
- `opt-level = "z"` — optimize aggressively for size. **But see the note below.**
- `lto = "fat"` — whole-program link-time optimization removes cross-crate dead
  code; significant for a multi-crate workspace.
- `codegen-units = 1` — maximize optimization opportunity at the cost of compile
  parallelism; for a release artifact that trade is correct.
- `panic = "abort"` — drops landing-pad/unwinding tables. Combined with
  `#![forbid(unsafe_code)]` and bounded inputs in the kernel, abort-on-panic is
  acceptable for nano and saves meaningful size.
- `strip = "symbols"` — the budget is measured on the stripped binary; strip at
  build time.
- `debug = false`, `incremental = false` — no debug info, no incremental
  artifacts in the release.

### 6.1 Also benchmark `opt-level = "s"`

> Also benchmark `opt-level = "s"` because smaller is not guaranteed with `z`
> ([`ROADMAP.md` §17.4](../ROADMAP.md)).

`opt-level = "z"` optimizes hardest for size but sometimes produces a *larger*
binary than `"s"` (e.g., by inhibiting inlining that would have let the optimizer
delete code). Treat the choice between `"z"` and `"s"` as **empirical**: build
both, compare stripped sizes (and the hot-path benchmarks in §3 — `"s"` may be
faster), and pick the winner. Re-check periodically; the answer can flip as the
codebase and toolchain change.

---

## 7. How to measure

### 7.1 cargo-bloat — *what* is big

```bash
# largest crates linked into nano, by code size
cargo bloat --profile nano -p crustcore --no-default-features --features nano --crates -n 30

# largest individual functions (find generic monomorphization blowup)
cargo bloat --profile nano -p crustcore --no-default-features --features nano -n 50
```

Read `--crates` output first to see which crate to attack, then drop to
per-function output to find the specific offenders (often a heavily monomorphized
generic, a big `match`, or formatting machinery pulled in by `format!`/`{:?}`).

### 7.2 cargo-tree — *which* deps are linked

```bash
# exact dependency graph for the nano feature set
cargo tree -p crustcore --no-default-features --features nano

# find why a forbidden crate is present (e.g. tokio)
cargo tree -p crustcore --no-default-features --features nano --invert tokio
```

`cargo tree --invert <crate>` is the fastest way to prove *why* a forbidden
dependency appears and which path to cut. Run it whenever the forbidden-dependency
check (§5) trips.

### 7.3 The size number itself

Build with the nano profile/features, confirm `strip = "symbols"` took effect,
and measure the on-disk size of the stripped artifact. Compare against the
configured budget (the value the size gate enforces). A delta over budget fails
CI per §4.1 / invariant 19. For nano-affecting PRs, attach the `cargo bloat`
diff to the PR and record the size delta in `CHANGELOG.md`
([`CLAUDE.md` §8.2](../CLAUDE.md)).

---

## 8. Testing & acceptance notes

- **Phase 0 acceptance** ([`ROADMAP.md` §18 Phase 0](../ROADMAP.md)):
  `cargo check --workspace` passes; `crustcore --version` builds in the nano
  profile; CI fails if forbidden dependencies enter nano.
- **Phase 8 acceptance** (size gate task, [`ROADMAP.md` §20.4](../ROADMAP.md) #8):
  "Add size gate and cargo-bloat report." The gate is wired into CI and a
  cargo-bloat report is produced per PR.
- **v0.1 DoD** ([`ROADMAP.md` §22](../ROADMAP.md), [`CLAUDE.md` §2.2](../CLAUDE.md)):
  #1 `crustcore-nano` builds < 800kB stripped on Linux x86_64; #2 kernel has no
  async/network/db/rich-CLI dependencies; and the project "proves sub-800kB
  target feasibility."
- **Release hardening** ([`ROADMAP.md` §18 Phase 16](../ROADMAP.md)): "Nano
  remains under size budget" is an explicit acceptance criterion of the release
  phase, so the gate must hold through to release, not just at bootstrap.

The size budget is part of the audit story the same way the event log is. A
maintainer must be able to say "I can disable every optional surface and keep the
harness tiny" ([`CLAUDE.md` §12](../CLAUDE.md)) — and prove it with `cargo tree`.
