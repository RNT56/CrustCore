# Changelog

All notable changes to CrustCore are recorded here. This file is the
**agent/PR progress log** as well as the release changelog: every agent and
subagent records its work here so the project stays auditable across many
sessions. See [`CLAUDE.md` §8](./CLAUDE.md) for the rules.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html),
extended with a CrustCore **Agent Log** subsection that captures the
agent/PR/role/size/invariant audit trail.

## How to add an entry (read before editing)

- Put in-progress work under **[Unreleased]**, in the correct group
  (`Added` / `Changed` / `Deprecated` / `Removed` / `Fixed` / `Security`).
- Add a matching line to **Agent Log** with: phase/task id (e.g. `P1.3`),
  PR/branch, owning agent/role, nano size impact (Δ kB or `n/a`), and
  invariants touched/verified.
- Update this file in the **same PR** as the change.
- In parallel work, subagents **report** their lines to the supervisor, which
  writes the consolidated entries (avoids merge conflicts). See
  [`CLAUDE.md` §7.2](./CLAUDE.md).
- On release, move `[Unreleased]` items into a dated `[x.y.z] - YYYY-MM-DD`
  section and start a fresh `[Unreleased]`.

---

## [Unreleased]

### Added

- **Phase 4 — runner + sandbox (P4.1–P4.7).** Execution is bounded, killable, and
  sandboxed:
  - `crustcore-runner`: `run(CommandSpec) -> CommandResult` — spawns in its **own
    process group** (`process_group(0)`), captures **bounded** stdout/stderr
    (then drains so the child can't block), enforces a **timeout** with a
    **process-tree kill** (SIGTERM→SIGKILL the whole group via `kill -<sig>
    -<pgid>`), and builds the env from scratch (no ambient inheritance). Std-only,
    no `unsafe`/libc.
  - `crustcore-sandbox`: an **environment sanitizer** (strips loader/credential
    vars by list, prefix, and credential-name heuristic) and a **path-list
    validator** (component-by-component: rejects empty/relative/`.`/`..`/NUL — a
    single bad component fails the whole var); the **Linux bubblewrap backend v1**
    (read-only system, read-write worktree, `--unshare-all` = deny-all egress;
    `--share-net` only for an explicit allowlist) with backend **selection** and
    **refusal** when no backend can provide the tier (no run-unsandboxed degrade;
    Tier-3/microVM refused in v0.1); `run_command(SandboxExecCap, profile, spec)`.
  - Red-team fixture `path_env_escape_is_blocked` un-ignored (P4.7, R11):
    `LD_PRELOAD` and empty/relative `PATH` components are stripped/rejected.
- **Phase 3 — path confinement + structured tools (P3.1–P3.6).** Safe file/git
  access confined to the task worktree:
  - `crustcore-path`: real symlink-safe confinement — `WorktreeRoot::open`
    (canonicalizing), lexical `.`/`..` normalization (interior `..` allowed,
    escapes rejected), deepest-existing-ancestor canonicalization under the root,
    and no-follow on write leaves. Only the resolver mints
    `ConfinedReadPath`/`ConfinedWritePath`, so a raw path string can never reach a
    file tool. Real-fs symlink fixtures (escape-on-read, write-through-symlink,
    symlinked parent, in-root symlink OK).
  - `crustcore-worktree::tools`: capability-gated `read_file`/`write_file`/
    `search` (require an `FsReadCap`/`FsWriteCap` whose root matches the path's;
    writes refuse `.git/`; reads/searches are bounded and skip `.git`/symlinks),
    and hardened git wrappers `git_status`/`git_diff`/`git_log`/`git_apply`
    (fixed subcommands, scrubbed env, `core.hooksPath=/dev/null`,
    `GIT_CONFIG_*`/`HOME` neutered — no hooks, no model-written/system/global
    config).
  - Red-team fixture `symlink_escape_is_blocked` un-ignored (P3.6): `..`,
    absolute, and symlink-escape paths are all rejected.
- **Phase 2 — event log + receipts (P2.1–P2.6).** The audit backbone is real and
  inspectable:
  - `crustcore-types`: a vendored, dependency-free **SHA-256 / HMAC-SHA-256**
    (`hash` module) validated against the NIST (FIPS 180-4) and RFC 4231 test
    vectors — keeps the workspace std-only and offline-buildable instead of
    pulling `sha2`/`blake3`.
  - `crustcore-eventlog`: the compact binary **`EventFrame`** format + append/
    read/**verify** hash chain (`prev_hash` links each frame's `frame_hash`), so
    any modification, reorder, insertion, deletion, or truncation is detected
    (`ChainStatus`/`BreakReason`); `crustcore inspect` (chain status + per-task
    summary) and `crustcore export` (JSONL, redaction-respecting); a hostile-bytes
    no-panic fuzz over the untrusted decoder.
  - `crustcore-receipts`: **`ToolReceipt`** generation + verification — a MAC
    chain keyed by a CrustCore-held `MacKey` (the model never holds it, so
    receipts are unforgeable) plus `prev_receipt_hash` linkage; `result_matches`
    binds a shown result to its hash (invariant 10).
  - The `crustcore` nano binary wires `inspect`/`export <log>` and the selftest
    now drives the event-log pipeline; an `examples/write_demo_log` produces a
    sample log to try them.
  - Red-team fixture `fabricated_tool_result_is_rejected` un-ignored (P2.6): a
    receipt forged under the wrong key, or a swapped result, fails verification.
- **Phase 1 — kernel state machine (P1.1–P1.7).** The trusted `Kernel::step`
  reducer is now real: a synchronous, deterministic, allocation-light
  `event -> state mutation -> bounded action list` over compact `Vec`-of-records
  arenas (tasks/jobs/approvals), with **no** async/network/db and **no wall clock**
  (all time is event-carried, so replay is deterministic).
  - `crustcore-types`: a `budget` module (`Budget`/`Meter`/`BudgetDelta`/
    `BudgetCheck`/`BudgetAxis`, integer-only, saturating) modelling all eight
    invariant-11 axes; `LeaseOwner`; `EventSeq::next_saturating`;
    `ApprovalStatus`/`ApprovalResolution`; `JobStatus::is_terminal`.
  - `crustcore-kernel`: pure, **exhaustive, total** task/job transition tables
    (`state.rs`); the `step` safety-ordered gates (idempotency frontier → terminal
    absorb → budget pause → source-state effect gate → bounded ready-drain);
    typed budget pause to `Blocked` (resumable); the approval request/resolution
    flow with operation-binding, expiry-at-use, one-pending-per-task, and the
    authorized-user-only guard; lease grant/expiry and stale-worker rejection.
  - `crustcore-policy`: `Approved<T>` minting is now crate-private behind
    `AuthorizedUser::approve` — the only path to an approval token requires an
    `AuthorizedUser`, so model/worker output can never mint one (invariant 4).
  - Tests: exhaustive impossible-transition property tests, a deterministic-LCG
    no-panic fuzz, determinism/idempotency/bounded-fan-out tests, and one negative
    test per acceptance criterion and per touched invariant.
  - `kernel_step` microbench wired (`benches/kernel_step.rs`, std-timer,
    `harness = false`): ~40 ns p50, well under the 1 µs budget (P1.7).
- Project documentation foundation: single-source-of-truth `CLAUDE.md`;
  authoritative `ROADMAP.md`; product laws in `INVARIANTS.md`; `THREAT_MODEL.md`,
  `SECURITY.md`, `CONTRIBUTING.md`, and `README.md`.
- Subsystem deep-dive docs under `docs/`: `architecture.md`,
  `nano-size-budget.md`, `security-model.md`, `secrets.md`, `sandbox.md`,
  `policy.md`, `event-log.md`, `receipts.md`, `backend-contract.md`,
  `telegram.md`, `github.md`, `mcp.md`, `model-routing.md`,
  `advisor-executor.md`, `self-improvement.md`, `maintainer-agent.md`.
- This `CHANGELOG.md` with the agent-log convention.
- GitHub issue templates and a documentation map.
- `AGENTS.md` — a thin router to `CLAUDE.md` so agents that look for `AGENTS.md`
  first (e.g. Codex) get the same single source of truth. Added to the contract
  file list.
- **Phase 0 workspace bootstrap (P0.1–P0.5).** A compiling Cargo workspace with
  all 19 crates + `xtask`: the `crustcore` nano binary (`--version`, `--help`,
  hidden `selftest`); trusted-core crates with real type-true skeletons
  (`crustcore-types` IDs/status/text/refs, `crustcore-kernel` event/action/step,
  `crustcore-policy` capability + approval tokens + decision, `crustcore-secrets`
  non-exfiltratable `SecretMaterial`, `crustcore-path` confined paths,
  `crustcore-eventlog` frame/chain, `crustcore-receipts` `ToolReceipt`,
  `crustcore-backend` `Unverified`/`VerifiedPatch`, `crustcore-runner`,
  `crustcore-sandbox`, `crustcore-worktree`, `crustcore-cli`); std-only sidecar
  skeletons (`crustcore-net`/`-daemon`/`-mcp`/`-index`/`-eval`/`-full`) with
  `TODO(Pn)` markers.
- `xtask` task runner (`verify`, `size-check`, `forbidden-deps`, `fmt`, `clippy`,
  `test`, `nano-build`) wired as `cargo xtask`; release profiles incl.
  `[profile.nano]`; `rust-toolchain.toml`; `.cargo/config.toml` aliases.
- CI (`.github/workflows/ci.yml`) running `cargo xtask verify` + a separate nano
  size-gate job + a best-effort `cargo-bloat`/`cargo-tree` report; `CODEOWNERS`
  enforcing maintainer review on every contract file.
- Documented `tests/{redteam,golden,fixtures}` and `benches/` trees;
  `#[ignore]`d red-team/golden test stubs in `crustcore-eval` so the suite never
  reports false green.
- **Apache License 2.0**: `LICENSE`, `NOTICE`, SPDX headers on all source files,
  and `license = "Apache-2.0"` across the workspace.

### Changed

- Set the project license to **Apache-2.0** (was TBD): updated `README.md`,
  `CONTRIBUTING.md` (inbound=outbound contribution terms), and crate metadata.
- Updated status in `README.md` and `CLAUDE.md` from "documentation-first /
  pre-Phase-0" to "Phase 0 — workspace bootstrapped"; recorded the measured nano
  baseline (~296 KiB, 37% of budget) in `docs/nano-size-budget.md`.
- Reconciled documentation inconsistencies end to end: added `/cancel` as a

- Reconciled documentation inconsistencies end to end: added `/cancel` as a
  first-class graceful-cancellation command (distinct from `/kill`); clarified
  that `crustcore-nano` is the `crustcore` package built with `--features nano`
  (no separate crate) and added `crustcore` to the workspace/crate maps; added
  `crustcore-mcp`/`crustcore-index` to the §17.1 size-budget table; made the
  nano MCP-lite "no rmcp" constraint explicit; made "no secrets to external
  workers" an explicit `"secrets": "none"` field in the worker input contract;
  unified the contract-file list across `CLAUDE.md` §7.3 and `ROADMAP.md` §20.2
  (now including `CLAUDE.md` and `AGENTS.md`); fixed approximate roadmap
  list-item anchors in `THREAT_MODEL.md` and `docs/sandbox.md`.

### Fixed

- **Phase 4 — timeout process-tree kill on Linux CI (`crustcore-runner`).** The
  group kill shelled out to `kill -<sig> -<pgid>`; Linux `procps-ng kill`, when
  given that exact argv, silently returns success **without delivering** to the
  negative-pid process group (it needs a `--` end-of-options separator). The
  timeout therefore fired but the process tree survived and `wait()` blocked for
  the full child lifetime — `cargo xtask verify` hung the two runner timeout tests
  for 30s each and failed CI on `ubuntu-latest` while passing on macOS (BSD `kill`
  accepts the bare form). Fix: issue **both** argument forms (`-<sig> -<pgid>` and
  `-<sig> -- -<pgid>`; signals are idempotent), and additionally SIGKILL the
  leader directly via its `Child` handle — a std-only guarantee that does not
  depend on an external `kill` binary or its argv parsing. Reproduced and verified
  fixed in a faithful `ubuntu:24.04` container (the committed pre-fix code hung
  60s there; the fixed code passes in 0.3s).

### Security

- **Phase 4 review hardening (`crustcore-runner`, `crustcore-sandbox`).** Address
  confirmed findings from the Phase 4 adversarial review:
  - Removed the clean-exit process-group SIGKILL sweep (a narrow pid-reuse TOCTOU:
    it signalled `pgid` *after* `wait()` reaped the leader, so a reused pid could
    receive an errant cross-group SIGKILL); the bounded reader drain — and, in the
    real path, the bubblewrap pid namespace — already guarantee `run()` returns.
  - Env sanitizer now strips the JVM (`JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`,
    `JDK_JAVA_OPTIONS`), Go (`GOFLAGS`, `GOENV`), zsh (`ZDOTDIR`), pager
    (`LESSOPEN`, `LESSCLOSE`), and interpreter library-path
    (`RUBYLIB`, `PERLLIB`, `PYTHONHOME`) code-execution variables that previously
    passed through.
  - Env sanitizer rejects `HOME` / `XDG_CONFIG_HOME` that are relative or resolve
    inside the model-writable worktree — closing a git-config
    (`core.pager`/`alias`/`core.fsmonitor`) code-execution vector that survived
    even when no `*_OPTIONS` variable did.

### Agent Log

| Date | Phase/Task | Change | PR / Branch | Agent / Role | Nano Δ | Invariants |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-06-16 | Pre-P0 | Author CLAUDE.md single source of truth + full documentation set from approved roadmap | `claude/crustcore-project-docs-q0kr2p` | Maintainer agent (DocumentationWriter) | n/a (docs only) | Documents all 20; none weakened |
| 2026-06-16 | Pre-P0 | Add AGENTS.md router; reconcile flagged doc inconsistencies end to end | `claude/crustcore-docs-reconcile-q0kr2p` (PR) | Maintainer agent (DocumentationWriter) | n/a (docs only) | Clarifies 1–3, 13, 15, 19, 20; none weakened |
| 2026-06-16 | P0.1–P0.5 | Bootstrap compiling workspace (19 crates + xtask), CI + nano size gate + CODEOWNERS, Apache-2.0 license; `cargo xtask verify` green | `claude/crustcore-project-docs-q0kr2p` | Maintainer agent (Architect/Implementer) | +296 KiB baseline (37% of 800 KiB budget) | Enforces/encodes 8, 9, 13, 14, 16, 19, 20; embeds 1–3 in types; none weakened |
| 2026-06-17 | P1.1–P1.7 | Implement the kernel state machine: transition tables, budgets, approvals, lease/expiry; exhaustive property tests + no-panic fuzz + microbench; design & two adversarial-review passes. **Contract file touched:** `crates/crustcore-kernel/src/event.rs` (additive payload fields, reviewed). | `claude/p1-kernel` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB (295.5 KiB, 36.9% of budget; within section alignment) | Enforces 4, 8, 11, 14 in code; partial 12 (lease/expiry/stale-owner); verifies determinism/idempotency/bounded-fan-out/no-panic; none weakened |
| 2026-06-17 | P2.1–P2.6 | Implement the hash-chained event log + tool receipts: vendored SHA-256/HMAC (NIST/RFC vectors), `EventFrame` binary format + append/verify, `ToolReceipt` MAC chain, `crustcore inspect`/`export`, tamper tests + hostile-bytes decoder fuzz; un-ignore the fabricated-tool-result red-team fixture. Stacked on `claude/p1-kernel`. | `claude/p2-eventlog` (PR #4, merged) | Maintainer agent (Architect/Implementer) | +0.1 KiB (295.6 KiB, 37.0% of budget) | Enforces 10 (receipts) + the event-log half of the audit story; verifies tamper-evidence + no-panic decode; none weakened |
| 2026-06-17 | P3.1–P3.6 | Implement symlink-safe path confinement (`crustcore-path`) + capability-gated file tools and hardened git wrappers (`crustcore-worktree::tools`); real-fs symlink fixtures; un-ignore the symlink-escape red-team fixture. **Two rounds of critical git-RCE fixes** (textconv/external-diff, then clean/smudge filters via `* -filter` in info/attributes) + a no-follow neutralizer fix, across three review passes. | `claude/p3-path` (PR #5, merged) | Maintainer agent (Architect/Implementer) | +0 KiB (295.6 KiB, 37.0%; tools dead-code-eliminated until wired) | Enforces 7 (untrusted paths) + 8 (cap-gated file/git ops); verifies symlink/absolute/`..` escapes fail and git can't run hooks/model config/filters; none weakened |
| 2026-06-17 | P4.1–P4.7 | Implement the process runner (bounded capture, timeout, process-group kill, env-from-scratch) and the sandbox (env sanitizer, path-list validator, Linux bubblewrap backend v1 + selection/refusal, `run_command`); un-ignore the path-env-escape red-team fixture. | `claude/p4-sandbox` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB (295.6 KiB, 37.0%; runner/sandbox dead-code-eliminated until wired) | Enforces 9 (sandboxed execution), 11 (bounded output/timeout), 12 (kill/cancel); deny-all egress + no inherited secrets; Tier-3 microVM out of v0.1 scope; none weakened |
| 2026-06-17 | P4 hardening | Fix the Linux-CI timeout-kill hang (procps-ng needs `kill -- -<pgid>`; also SIGKILL the leader via its `Child` handle) — root-caused and verified in a faithful `ubuntu:24.04` container. Address Phase-4 review findings: drop the pid-reuse-TOCTOU clean-exit group sweep; strip JVM/Go/zsh/pager/interpreter-lib exec env vars; reject `HOME`/`XDG_CONFIG_HOME` inside the worktree. | `claude/p4-sandbox` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB (295.6 KiB, 37.0%) | Strengthens 9 (sandbox env), 12 (reliable process-tree kill); none weakened |

---

## Release history

_No releases yet. CrustCore v0.1 targets the definition of done in
[`ROADMAP.md` §22](./ROADMAP.md) and [`CLAUDE.md` §2.2](./CLAUDE.md)._

<!--
Template for a future release section:

## [0.1.0] - YYYY-MM-DD

### Added
### Changed
### Fixed
### Security

### Agent Log
| Date | Phase/Task | Change | PR / Branch | Agent / Role | Nano Δ | Invariants |
| --- | --- | --- | --- | --- | --- | --- |
-->
