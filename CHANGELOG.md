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

- **Phase 8 — secret broker + typed secrets (P8.1–P8.6).** Secret leakage made
  *unrepresentable* (invariants 1–3; `docs/secrets.md`). **Contract file**
  `crates/crustcore-secrets/src/lib.rs` (serialized + reviewed):
  - **Typed secrets (P8.1):** `SecretMaterial` holds raw bytes and implements
    **none** of `Debug`/`Display`/`Clone`/`Serialize`, with **no** conversion to
    model-visible text, and zeroizes on drop (dep-free, no-`unsafe`,
    `black_box`-guarded against dead-store elision). Each forbidden impl is proven
    by a **compile-fail doctest** (the gold-standard invariant-3 proof, no
    `trybuild` dep) — so S1/S5 are *structural*, not runtime hopes. `SecretHandle`
    (id + label) is the only secret-related thing the model sees.
  - **Redactor / taint (P8.5):** `Redactor` scrubs registered secret values out of
    any text (longest-match-first); `ModelVisibleText` can be built **only** by the
    redactor (the model/log/Telegram/GitHub boundary is sealed by construction);
    `Tainted<T>` declassifies only through the redactor.
  - **Broker request flow (P8.4):** `SecretBroker` over a `SecretStore` mints a
    one-shot, scoped, **expiring**, broker-borrowed `ApprovedSecretView` — the only
    path bytes leave the broker; reuse/expiry are rejected.
  - **Credential proxy (P8.6):** `CredentialProxy::bearer` consumes a view and
    yields a non-model-visible `HeaderInjection` (trusted outbound code reads it;
    logs/model see only the `[REDACTED:label]` form) — the pattern that lets the
    net/GitHub sidecars authenticate without the key ever entering nano, the
    sandbox, or model context (unblocks Phase 7's live providers).
  - **Deferred (`TODO(P8-store)`):** the native OS keychain (P8.2) and encrypted
    -file vault (P8.3) `SecretStore` backends live **outside nano** (platform/crypto
    code) and aren't CI-testable cross-platform; the `SecretStore` trait +
    `InMemoryStore` stand in. Nano stores only `secret://` handles.
  - **Tests:** broker one-shot/expiry/missing-secret, handles-only, proxy
    no-leak, the runtime **leak matrix S2–S10** through the redactor, overlapping
    /empty-secret redaction, `ModelVisibleText`-only-via-redactor, plus the four
    compile-fail doctests; **un-ignored the red-team fixture**
    `secret_never_leaks_to_model` (S1–S10, including the sandbox env-strip for S4).
  - **Nano size impact: +0 KiB** (411.9 KiB, 51.5%) — the broker is dead-code
    -eliminated in nano (the binary references only handles), invariant 20.
  - **Hardened per a 6-dimension adversarial review (7 confirmed findings fixed;
    7 refuted/out-of-scope):**
    - **(redactor correctness — real leak paths)** the per-needle sequential
      `replace()` could leave a secret *fragment* when two distinct secrets shared
      an edge substring (`TOKENONE99` + `99TOKENTWO`), and could re-scan/reintroduce
      a secret via an emitted marker. Replaced with a **collect-all-spans →
      merge-overlaps → splice-markers** pass over the *original* text: every byte of
      any secret occurrence is covered, no fragment survives, and redaction is a
      fixed point (markers are never re-scanned). `would_leak` is now the exact dual.
    - **`Redactor` held un-zeroized, `Clone`-able plaintext copies** of every
      secret → it is now **not `Clone`** and **zeroizes each needle on drop**
      (shared `scrub` helper); callers take `&Redactor`.
    - **`Tainted<T>` derived `Debug`/`Clone`**, reopening the secret-Debug leak
      class (S5) → it is now **not `Clone`** and its `Debug` is a non-revealing
      `Tainted(<redacted>)` placeholder; a `compile_fail` doctest pins no-`Clone`.
    - the dead/mismatched `REDACTION_MARKER` constant → a single-source
      `redaction_marker(label)` helper used everywhere.
    Regression tests added for each (overlapping-edge no-fragment, fixed-point,
    `Tainted` Debug-safe).
- **Phase 7 — `crustcore-net` model-transport protocol + routing engine (P7.1–P7.7).**
  The sidecar architecture that lets nano call the model transport **without
  linking HTTP/TLS** (invariants 17, 11, 19, 20; `docs/model-routing.md`):
  - **`crustcore-netproto`** (new crate, **std-only, no serde/HTTP/TLS**): the
    local helper protocol (P7.1) — newline-delimited *flat* JSON messages
    (`Request`/`Response`: probe, complete, model/registry_end, chunk, final,
    error), a small audited flat-JSON codec, bounded line reads, and the
    caller-side `NetHelper` client + `SpawnedHelper` (spawn the sidecar, talk over
    a pipe). **This is the only model-transport code the trusted caller links.**
  - **`crustcore-net`** routing engine: a `Provider` trait (provider-agnostic
    request/response model — P7.2); a **dynamic registry** built by probing
    providers (invariant 17 — P7.4); the three meta-provider behaviors —
    `select_candidates` (RouterProvider: role + hard-constraint filter + soft
    order — P7.6), `apply_budget` (BudgetProvider: cost ceiling, refuses rather
    than breaches — P7.7), `run_reliable` (ReliableProvider: fallback chain that
    never crosses a hard constraint — P7.5) — composed by `Engine::complete`;
    **streaming** chunks through a sink (P7.3); **budget accounting**
    (`BudgetLedger` — P7.7); and the `serve` loop the helper binary runs. A
    deterministic `MockProvider` + `default_mock_engine` make routing/fallback/
    budget/registry observable with **no network**.
  - The **`crustcore-net` helper binary** (`src/bin/helper.rs`) serves the engine
    over stdin/stdout; `crustcore net probe|complete` (gated behind the `net`
    feature) spawns it and round-trips. The `net` feature now links only
    `crustcore-netproto` (the HTTP-bearing `crustcore-net` is a *spawned* binary,
    not a linked dep), so even the net build embeds no HTTP/TLS.
  - **Deferred (`TODO(P7-live)`):** the concrete OpenAI/Anthropic/OpenRouter/local
    wire adapters + the Tokio/HTTP/TLS transport. They need credentials from the
    **secret broker (Phase 8)** — a worker/provider never receives a raw key
    (invariant 1) — and real network (unavailable in CI). The engine is
    transport-agnostic, so a live `Provider` drops in without touching the
    router/registry/budget logic; `docs/model-routing.md`'s own testing notes are
    mock-based.
  - **Tests:** flat-JSON codec round-trips + malformed/nested/over-long rejection;
    protocol request/response round-trips; router constraint+ordering, budget
    ceiling, reliable fallback (no partial-output leak), dynamic registry,
    local-only-never-remote, end-to-end `serve`↔caller over an in-memory pipe; and
    an **integration test that spawns the real helper binary** and probes/completes
    over a pipe (the boundary proof). Acceptance met: nano calls the helper without
    linking HTTP/TLS; provider failures fall back safely; the registry is dynamic.
  - **Nano size impact: +0 KiB** (411.9 KiB, 51.5%) — all net code is cfg-gated or
    in the sidecar; the nano size-gate build links neither `crustcore-netproto` nor
    `crustcore-net`.
  - **Hardened per a 7-dimension adversarial review (3 confirmed findings fixed;
    14 refuted/out-of-scope):**
    - **(med) unbounded reads from a misbehaving helper.** `NetHelper::probe`
      accepted an unbounded number of registry lines before `RegistryEnd`, and
      `complete` an unbounded chunk stream before `Final` — a buggy/compromised
      sidecar could OOM/hang the trusted caller (invariant 7; "bounded
      everything"). Added `MAX_REGISTRY_MODELS` / `MAX_STREAM_BYTES` caps that
      reject rather than grow, with regression tests.
    - **(low) line-byte cap skipped on the newline branch.** `read_line_bounded`
      enforced `MAX_LINE_BYTES` only between `fill_buf` chunks, so a `BufRead` that
      returns the whole remainder at once (e.g. a `Cursor`) could buffer a giant
      newline-terminated line. The cap now guards the newline branch too.
    - **(low) the `net` boundary was un-gated in CI.** `cargo xtask forbidden-deps`
      now *also* checks the `--features net` tree — asserting it links neither
      `crustcore-net` (the HTTP-bearing helper, which must be spawned) nor any
      forbidden stack — so a future repoint or a heavy dep in `crustcore-netproto`
      fails `verify` (invariant 20).
- **Phase 6 — external backend protocol (P6.1–P6.6).** The one backend contract
  plus an external-command worker that runs `codex`/`claude` (or any worker) under
  the sandbox/worktree and proves *workers are patch producers, not truth
  authorities* (invariants 6, 7, 13):
  - `crustcore-backend::worker`: the `CodingBackend` contract and three backends —
    a generic `ExternalCommandBackend` (P6.2), `CodexBackend` (P6.3), and
    `ClaudeCodeBackend` (P6.4) — all returning the one `BackendResult` shape. The
    worker input contract (`WorkerInput::to_json`, `docs/backend-contract.md` §4.1)
    pins `"secrets":"none"` / `"network":"deny"` **by type**: `WorkerSecrets` /
    `WorkerNetwork` have a single inhabitant, so handing a worker a secret or raw
    network is *unrepresentable* (invariants 1–3, 9).
  - **Supervisor validation** (`run_external_worker`, §4.2): runs the worker in a
    clean sandbox with a built-from-scratch, secret-free environment (only a safe
    `PATH`); captures a **bounded** transcript (untrusted; `self_claimed_done` is
    parsed but advisory — invariant 6); **detects out-of-root writes** with a
    `GuardManifest` over the worktree's sibling space (defense in depth that holds
    even where the OS sandbox is non-functional); **extracts the actual diff from
    the worktree** with the hardened git wrappers (never the worker's claim) and
    **confines every changed path** (`..`/absolute/symlink escapes reject the
    result); and classifies changed files (CI workflows, dependency manifests,
    credential-ish names) for the later reviewer pass. The product is an
    `UnverifiedPatch` — nothing here mints a `VerifiedPatch`; completion still flows
    only through `verify::run_verify` (invariant 13). Like the verify loop, the
    orchestrator is parameterized over a command executor so the validation logic
    is unit-tested deterministically on every platform.
  - **Transcript capture & diff extraction (P6.5):** added a hardened
    `git status --porcelain --untracked-files=all --no-renames` wrapper
    (`crustcore-worktree::git_status_all`) so untracked files are enumerated
    individually (a new directory is not collapsed to one entry) — each is
    independently confined and classified. The patch is content-addressed over the
    worktree's own status+diff.
  - **Worker input on stdin:** `crustcore-runner::CommandSpec` gained a bounded
    `stdin` field; `run` writes it *after* the output readers start (no pipe
    deadlock) and bubblewrap forwards it — so a worker receives its input-contract
    JSON as data.
  - `crustcore run` gained `-backend native|codex|claude|cmd` and `-worker-cmd`:
    an external worker first produces a candidate change in the worktree, which is
    re-derived, confined, and then verified end to end. A worker that wrote outside
    the worktree, produced an escaping change, or could not run sandboxed is
    rejected with a clear non-zero state — nothing completes without confined,
    verified evidence.
  - **Tests:** worker contract tests (P6.6) — secret-free spec env, JSON contract
    pins, advisory done-marker, guard-manifest out-of-root detection, porcelain
    parse/classify, and end-to-end executor-seam tests (diff comes from the
    worktree not the worker's claim; out-of-root write rejected; sandbox-error
    surfaced; sensitive file flagged); runner stdin round-trip + no-hang;
    **un-ignored the red-team fixture** `worker_write_outside_worktree_is_rejected`
    (guard-manifest + path-confinement arms); and the golden
    `golden_add_small_feature` (external worker → re-derived diff → verify →
    complete), gated like `golden_fix_failing_test` on a functional sandbox.
  - **Hardened per a 7-dimension adversarial review (5 confirmed findings fixed;
    7 refuted/out-of-scope):**
    - **(high) stdin write could defeat the timeout.** The runner wrote
      `CommandSpec.stdin` with a blocking `write_all` *before* the timeout loop, so
      a worker that never drained its stdin (payload > the ~64 KiB pipe buffer)
      could hang `run()` forever — bypassing the very timeout the runner enforces
      (invariants 11, 12). Now written from a **dedicated thread**, so the timeout
      arms immediately and the process-group kill unblocks the writer; regression
      test pipes 512 KiB to a live non-reading child and asserts `TimedOut`.
    - **(med) `git status` parsed without `-z`.** Git C-quotes paths with spaces /
      control / non-ASCII bytes, which slipped past per-path confinement and the
      credential/CI classifier under a bogus name (and the "fails closed" comment
      was wrong). `git_status_all` now uses `-z` (NUL records, verbatim paths).
    - **(med) extracted diff omitted new-file content.** Plain `git diff` shows no
      untracked content, so a worker that *adds* files (the common case) had its new
      code absent from the diff and patch content-address. New `git_worktree_diff`
      marks untracked files intent-to-add and diffs against `HEAD`, capturing
      additions, modifications, deletions, and staged changes.
    - **(med) unbounded git output OOM.** `run_git` used `wait_with_output`, fully
      buffering a hostile worktree's git output before truncating. It now streams
      both pipes into capped buffers (bounded supervisor memory, no pipe-block).
- **Phase 5 — worktree + verify loop (P5.1–P5.6).** The local single-task harness
  with verifier-owned completion:
  - `crustcore-worktree::WorktreeManager`: create/reuse/remove a **disposable git
    worktree** per task (`git worktree add --detach … HEAD` under the hardened git
    invocation — no hooks, no pager, scrubbed env, no global/system config), plus
    `head_commit` to reference the verified state without mutating the canonical
    repo. Phase 5 targets the user's *own* (trusted) repo, so repo-local filters
    (e.g. Git LFS) keep working — CrustCore does not touch `.git/info/attributes`.
  - `crustcore-backend::verify`: the **verify loop** — `VerifySpec` (explicit
    program+args, no shell interpretation; best-effort `detect` of
    cargo/npm/make), and `run_verify`, which reruns the verify command **in a
    clean sandbox** (`crustcore_sandbox::run_command`, invariant 9) and, **only**
    on a zero exit, mints a `VerifiedPatch` carrying a `ToolReceipt` over the real
    run (invariant 10). A failing verify → `Failed`; no sandbox backend →
    `Refused`; neither mints anything.
  - **Verifier-owned completion sealed (invariant 13):** `VerifiedPatch::from_verifier`
    is now crate-private — `run_verify` is its sole constructor — and a new
    `complete_task(VerifiedPatch)` takes a verified patch *by value*, so a task can
    only complete from real verifier evidence (a self-claimed-done backend, a
    failing verify, or a missing sandbox can never complete it).
  - `crustcore run -dir <repo> -goal <text> -verify <command>` is wired end to
    end: it creates a worktree, reruns the verify command sandboxed, and completes
    only on a `VerifiedPatch` — otherwise it exits non-zero with a clear
    Failed/Refused state.
  - Tests: worktree create/reuse/remove/head-commit; the **golden "fix failing
    test"** task — a failing `test -f FIXED` does not complete; after the fix it
    verifies and completes — which exercises the real sandbox where one is
    functional and otherwise asserts the completion gate (never falsely
    `Verified`); plus `VerifySpec` detect/display unit tests.
  - **Hardened per adversarial review** (8 confirmed findings fixed):
    - `create_for` now **neutralizes attribute-driven git filters during the
      `git worktree add` checkout** (writing `* -filter`, then restoring the repo's
      attributes file) so a repo-local `filter.*.smudge`/`process` driver mapped by
      a committed `.gitattributes` cannot execute host code (invariant 7) —
      mirroring the `git_diff`/`git_apply` wrappers; an RCE regression test plants
      such a filter and asserts it does not run.
    - Worktree **reuse only adopts a worktree this repo has registered** (`git
      worktree list`), never a bare `.git` at the predictable temp path, and the
      base dir is created `0700` — so a directory pre-planted by another local user
      cannot be adopted as the task tree.
    - `run_verify` gained a test-only executor seam, so the **mint→complete→receipt
      and Failed/Refused paths are unit-tested deterministically on every
      platform** (not skipped when no sandbox is present); CI now installs
      bubblewrap so the full sandboxed path runs there too.
    - `crustcore run` **removes the disposable worktree on every exit path**;
      verify-spec resolution and the completion decision are extracted into tested
      functions (no-shell-split asserted); added the `VerifierName` contract type.
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
| 2026-06-17 | P5.1–P5.6 | Implement the worktree + verify loop: `WorktreeManager` (disposable `git worktree` create/reuse/remove, hardened), `crustcore-backend::verify` (`VerifySpec`/`run_verify` rerun-in-sandbox → mint `VerifiedPatch`+receipt only on pass), seal `VerifiedPatch::from_verifier` crate-private + `complete_task` by value, wire `crustcore run -dir/-goal/-verify`; golden "fix failing test" + worktree lifecycle tests. **Hardened per a 7-dimension adversarial review (8 confirmed findings fixed):** worktree-add filter neutralization+restore (RCE), registered-only worktree reuse + 0700 base, executor-seam unit tests for the mint/Failed/Refused paths, worktree teardown on all `run` paths, `VerifierName` type, extracted+tested verify-spec/exit logic. CI now installs bubblewrap so the real sandbox path runs. Full sandbox path validated in a privileged `ubuntu:24.04` container. | `claude/p5-verify` (PR) | Maintainer agent (Architect/Implementer) | +99.9 KiB (395.5 KiB, 49.4%; runner/sandbox/verify now reachable via `run`) | Enforces 13 (verifier-owned completion, type-sealed), 9 (verify in sandbox), 10 (receipt over the real run), 7 (worktree-add RCE neutralized); none weakened |
| 2026-06-17 | P6.1–P6.6 | Implement the external backend protocol: the `CodingBackend` contract + `ExternalCommandBackend`/`CodexBackend`/`ClaudeCodeBackend`; `WorkerInput` (type-pinned `secrets:none`/`network:deny`) and JSON contract; `run_external_worker` supervisor validation (sandboxed secret-free run, bounded transcript, `GuardManifest` out-of-root detection, worktree-confined diff extraction via new `git_status_all`, per-path confinement, sensitive-file classification) → `UnverifiedPatch` only; `CommandSpec.stdin` delivery through runner+bwrap; wire `crustcore run -backend/-worker-cmd` (produce → re-derive → confine → verify). Worker-contract tests + runner stdin tests; **un-ignore the `worker_write_outside_worktree_is_rejected` red-team fixture**; implement the `golden_add_small_feature` golden. Full sandboxed worker→verify→complete path validated in a privileged container. | `claude/p6-backend` (PR) | Maintainer agent (Architect/Implementer) | +16.4 KiB (411.9 KiB, 51.5%; worker module + CLI wiring) | Enforces 6 (workers are patch producers, not authorities), 7 (out-of-root/escape rejection), 1–3 + 9 (no-secret, deny-net, sandboxed worker), 13 (only the verifier completes); none weakened |
| 2026-06-17 | P8.1–P8.6 | Implement the secret broker + typed secrets: `SecretMaterial` (no Debug/Display/Clone/Serialize, no model-visible conversion, zeroize-on-drop; forbidden impls proven by compile-fail doctests), `SecretHandle`, `Redactor`/`ModelVisibleText`/`Tainted` (the taint boundary, S2–S10), `SecretBroker`/`SecretStore`/`InMemoryStore` + one-shot/expiring/borrowed `ApprovedSecretView` (P8.4), `CredentialProxy`→`HeaderInjection` (P8.6). Native keychain (P8.2) + encrypted vault (P8.3) deferred to `TODO(P8-store)` outside nano. Un-ignored the `secret_never_leaks_to_model` red-team fixture (full S1–S10 matrix). **Contract file touched:** `crates/crustcore-secrets/src/lib.rs` (this is the phase that implements it; flagged for review). | `claude/p8-secrets` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB (411.9 KiB, 51.5%; broker dead-code-eliminated in nano) | Enforces 1 (no raw creds to LLM), 2 (no unredacted secret logs), 3 (SecretMaterial not Debug/Serialize/Clone/model-visible — compile-fail-proven); credential proxy unblocks P7-live; none weakened |
| 2026-06-17 | P7.1–P7.7 | Implement the `crustcore-net` model-transport protocol + routing engine: new **std-only `crustcore-netproto`** (flat-JSON helper protocol + codec + `NetHelper`/`SpawnedHelper` client — the only transport code the caller links, no HTTP/TLS); `crustcore-net` engine (`Provider` trait, dynamic registry/probe, `select_candidates`/`apply_budget`/`run_reliable` = Router/Budget/Reliable meta-providers, streaming, `BudgetLedger`, `serve`); `MockProvider`/`default_mock_engine` + helper binary; `crustcore net probe\|complete` gated behind the `net` feature (links only netproto). Live HTTP adapters deferred to `TODO(P7-live)` (need the Phase 8 secret broker + network). Unit + protocol + end-to-end + real-subprocess integration tests. **Contract files touched:** `Cargo.toml`/`Cargo.lock` (add the `crustcore-netproto` workspace member; repoint the `net` feature). | `claude/p7-net` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB (411.9 KiB, 51.5%; all net code cfg-gated/sidecar) | Enforces 17 (dynamic registry, no hard-coded models), 11 (budget ceiling + accounting), 19/20 (nano links no HTTP/TLS; net is a spawned helper); pin-by-construction for the no-secret-to-worker path (live providers gated on Phase 8); none weakened |
| 2026-06-17 | P8 hardening | Fix the 7 confirmed findings from a 6-dimension adversarial review (7 refuted/out-of-scope): rewrite `Redactor::redact` as collect-spans→merge-overlaps→splice (fixes a real fragment-leak when two secrets share an edge substring + makes redaction a fixed point, RC-1/RC-2/ROB-1); make `Redactor` non-`Clone` + zeroize needles on drop (SC-1); make `Tainted<T>` non-`Clone` with a non-revealing `Debug` placeholder (LTS-1/CDF-1, S5); single-source the redaction marker (CDF-2). Regression tests added. | `claude/p8-secrets` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB (411.9 KiB, 51.5%) | Strengthens 1/2 (no secret fragment crosses a boundary), 3 (taint carrier no longer Debug-leaks); none weakened |
| 2026-06-17 | P7 hardening | Fix the 3 confirmed findings from a 7-dimension adversarial review (14 refuted/out-of-scope): (med) cap `NetHelper::probe`/`complete` reads from a misbehaving helper (`MAX_REGISTRY_MODELS`/`MAX_STREAM_BYTES`) so it cannot OOM/hang the caller; (low) enforce `MAX_LINE_BYTES` on the newline branch of `read_line_bounded`; (low) `xtask forbidden-deps` now also gates the `--features net` tree (no `crustcore-net`/HTTP-TLS linked). Regression tests added. | `claude/p7-net` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB (411.9 KiB, 51.5%) | Strengthens 7 (bounded untrusted helper output), 20 (net-boundary now CI-gated); none weakened |
| 2026-06-17 | P6 hardening | Fix the 5 confirmed findings from a 7-dimension adversarial review (7 refuted/out-of-scope): (high) move the runner stdin write to a dedicated thread so a non-draining worker can't hang `run()` past the timeout (invariants 11/12); (med) parse `git status -z` so quoted/space/non-ASCII paths reach confinement+classification verbatim; (med) new `git_worktree_diff` (intent-to-add + `diff HEAD`) so new-file content is in the diff and patch content-address; (med) stream `run_git` output into capped buffers (no unbounded-output OOM from a hostile worktree). Added regression tests for each. Full sandboxed path re-validated in a privileged container. | `claude/p6-backend` (PR) | Maintainer agent (Architect/Implementer) | +0 KiB (411.9 KiB, 51.5%) | Strengthens 11/12 (bounded/killable execution), 7 (verbatim-path confinement), 6 (faithful re-derived diff); none weakened |

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
