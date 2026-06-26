# CrustCore v0.5.0 — "Light It Up"

> **Draft** — for the maintainer to use when cutting/tagging the release. Re-confirm the
> exact test/size counts at tag time (they move as the tree changes).

v0.5.0 opens CrustCore's **conversational front door** and completes its **multi-task
supervised runtime**, all on top of the v0.4 verifier core. `crustcore chat` is now a
runnable, redacted, principal-authenticated REPL; `crustcore-daemon serve` is a real
Telegram bot that launches verified tasks; the supervisor can race multiple proposers and
let the verifier pick the winner; and the daemon supervises many concurrent tasks under
per-task lease, heartbeat, budget, and kill. Every Tier A/B live seam is wired to its
irreducible socket, the whole capability matrix composes under `--all-features`, and **none
of it touches nano: the trusted kernel is byte-identical to v0.4.** All 20 invariants hold
(two were amended, owner-authorized, to sanction the chat front door).

---

## Highlights

- **`crustcore chat` — the conversational front door.** A feature-complete terminal REPL: a
  non-authoritative intent classifier, a persona layer scoped *below* the safety core,
  redacted + bounded converse turns re-sealed as `ModelVisibleText`, and a queue/steer state
  machine (`!`/`/steer` cancels in-flight model calls, `/cancel` aborts). Routes select kernel
  flow; they grant nothing. Std-only decision core, optional terminal I/O, **zero nano impact**.
- **`crustcore-daemon serve` — a runnable Telegram bot.** Long-poll → dispatch → reply, with
  chat-launched verified tasks, inline approve/deny/steer keyboards (nonce- and op-bound),
  `serve --pair` chat-id discovery, and a bot token sourced only from `CRUSTCORE_TELEGRAM_TOKEN`
  (never an argv).
- **Multi-task supervised runtime.** A pure, deterministic `TaskRegistry` bounds concurrency
  and enforces per-task lease / heartbeat / budget / kill (invariants 11, 12). `/tasks`,
  `/task <id>`, `/cancel <id>`, `/kill <id>` are typed-verb dispatch — never a model prompt, and
  owner-scoped. Tasks never touch the user directly; all output is redacted.
- **Supervisor fan-out.** `run_fanout` races multiple proposers at the same goal and stops at
  the first **verifier-accepted** patch — never a worker's `self_claimed_done`. Completes the
  P11 supervisor control plane.
- **Chat → draft PR, approval-gated.** `--open-pr --repo <owner/name>` gates each launch on a
  human ✅/🚫 button; only on approval does the task run → verify → mint
  `Approved<GitHubWriteCap>` → open the draft PR. The `VerifiedPatch` never crosses the approval
  boundary unminted.
- **All Tier A/B live seams wired.** Telegram Bot API, GitHub-App RS256 auth,
  Firecracker/Windows sandbox backends, Qdrant/LanceDB vector stores, OTLP/HTTP+JSON export,
  MCP-over-HTTP, tree-sitter AST intel, OS keychain loaders — each behind its feature flag, each
  proven to compose. Only the irreducible sockets remain `#[ignore]`d.
- **Full-binary size tracking.** `crustcore --features full` — *every* capability pack linked —
  is **576.7 KiB** on Linux x86_64, only +98 KiB over nano and **under the 600 KiB stretch
  goal**, because the heavy I/O (HTTP/TLS, DBs, tree-sitter) runs in spawned sidecars. CI
  measures it on every push (`cargo xtask full-size`).
- **`crustcore-full` — a one-binary casual-user front door.** The trusted core is multi-binary
  by design; for casual use there is now a convenience all-in-one (`--features all`) that
  bundles chat + Telegram bot + model helper into **one executable that spawns itself** as the
  helper — nothing to put on PATH (`crustcore-full setup` / `chat` / `serve --pair`), with a
  `KEY=VALUE` config file instead of shell-env juggling; offline mock by default, live when a
  provider config is set. It only *wires* the existing tested components, so the trust boundary
  is unchanged. Zero nano impact.

---

## Added

**Conversational & runtime**

- **`crustcore-chat` pack** (`route` / `persona` / `converse` / `steer` / `session` /
  `terminal`): non-authoritative classifier (model path + heuristic fallback); a fixed safety
  preamble over owner-authorized persona/steering; converse answers redacted → bounded →
  re-sealed as `ModelVisibleText`; a bounded-FIFO queue/steer machine; a runnable `crustcore
  chat` subcommand that loads optional `persona.md` + steering from the repo root.
- **`crustcore-daemon serve`**: a pure, CI-tested `dispatch_event` core; `run_serve_loop` over
  real transports (`RestTelegram` on `UreqClient` + the spawned net helper); `serve --pair`
  chat-id discovery; chat-launched `TaskHandle`/`TaskSpec` running the **same** worktree →
  sandbox → verifier flow as `crustcore run`; bounded inline keyboards carrying only labels +
  op-bound callback ids, never secrets.
- **Chat → draft PR**: `--open-pr / --repo / --base / --branch-prefix`; per-launch approval;
  `runtime::mint_github_write_cap` (the only chat path to GitHub write authority,
  allowlisted-chat-gated) + `runtime::pr_approval_match`; the git push + REST `create_pull`
  remain the reduced live socket.
- **`TaskRegistry`** (P10-net, invariant 12): pure state machine over injected `now`;
  `admit` / `observe_progress` / `heartbeat` / `tick` reserve scheduler slots, refresh leases,
  charge `AgentBudget`/`AgentUsage`, reclaim expired/orphaned leases, and kill runaway or
  over-budget tasks — returning a bounded `RegistryAction` list. Reuses the existing
  scheduler/budget primitives verbatim.
- **`run_fanout`** (P11): extends `run_subagent` to race proposers at one goal under bounded
  concurrency and per-agent budget; stops at the first verifier accept; typed `RunRefused` for
  unknown / over-budget / errored proposers.
- **Dev-UI `/ws` snapshot streaming** (`C7-serve-live`): a pure, always-compiled
  `stream::next_snapshot` core (bounded, debounced, redacted) + a `serve`-gated SSE handler
  through the same auth + loopback gate; strictly server→client.

**Live seams (Tier A/B)** — `LiveTelegramApi` (P9), GitHub-App token mint + hardened webhook
ingestion (P10/B2), `WorktreeSubagentExecutor` (P11-exec-live), advisor-via-net-helper
(P12-native-live), `LiveEvalRunner` + draft-self-PR (B5-autoloop-live).

**Capability packs & infrastructure** — `RestTelegram` + GitHub-App RS256 (crustcore-net);
hardened git enumeration + off-by-default tree-sitter AST intel (crustcore-index);
dependency-free Firecracker + Windows sandbox backends (crustcore-sandbox); Qdrant/LanceDB +
versioned persistence + AST chunking (crustcore-index-rag); MCP-over-HTTP (crustcore-mcp);
real OTLP/HTTP+JSON exporter (crustcore-telemetry); `NetEmbedder` + LSH ANN (crustcore-index);
macOS Keychain / Linux Secret-Service loaders (crustcore-secrets); the loopback single-page
inspector (crustcore-dev); the `crustcore-full --features all` "build everything" switch;
`cargo xtask full-size` + the `--all-features` composition gate.

## Changed

- **Invariants 15 & 16 amended (owner-authorized)** to sanction the chat front door. 15
  broadens its *channels* ("Telegram by default; the `crustcore chat` front door"); 16 names
  `crustcore chat` as the only **explicit, redacted, policy-gated** conversational surface —
  no ungoverned parallel control plane. The security boundary is unchanged; specs added
  (`docs/chat.md`, `docs/persona.md`).
- **CI runs Linux + macOS** as a matrix; `cargo xtask verify` runs on both, with macOS
  `sandbox-exec` confinement tests live in CI.

## Fixed

- **Corrected the nano size figures + test count.** The docs cited 412.0 KiB / 51.5% as the
  flagship "Linux x86_64" figure, but that is the **macOS** number; the Linux x86_64 CI gate
  reports **478.7 KiB (490,184 bytes), 59.8%** of budget (still within the < 600 KiB stretch).
  Corrected across `CLAUDE.md`, `README.md`, `docs/roadmap-v0.2.md`; refreshed the stale test
  count (~663 → ~834). No code change — nano is byte-identical.
- **Chat front-door polish (end-to-end audit).** Route-aware budgets (the classifier's four
  routes were threaded but discarded; `budget_for_route` now applies tiered budgets) and a
  bounded per-chat `AbuseSuppressor` (rate-limits surfacing of not-allowlisted rejections). The
  audit refuted a false high-severity finding and confirmed all 20 invariants enforced + tested.

## Security

No new vulnerabilities; all 20 invariants verified structurally and by test across every new
surface — secrets/redaction (1–3), approval & verifier-owned authority (4, 5, 6, 13, 14),
untrusted-data inertness (7, 8), sandbox + budgets + lease (9, 11, 12), MAC-chained receipts
(10), the single redacted conversational surface (15, 16), provider routing + size discipline
(17, 19, 20). Red-team coverage was extended to the new surfaces (chat principal trust + a
non-authoritative classifier, verifier-owned fan-out, multi-task budgets, dev-UI
auth/read-only/redaction, a telemetry leak-canary).

---

## Size & quality

| Build | Size (Linux x86_64, stripped, nano profile) | Budget |
| --- | --- | --- |
| **nano** (default, no features) | **478.7 KiB** | 59.8% of 800 kB |
| nano (macOS, CI) | 412.0 KiB | 51.5% |
| **full** (`--features full`, every pack linked) | **576.7 KiB** (+98 KiB over nano) | **under the 600 kB stretch goal** |

- **~834 workspace tests** (up from ~663 in v0.4.0). Daemon: **128** default / **147** with
  `--features live` (live socket smokes `#[ignore]`d).
- `cargo xtask verify` green on **Linux and macOS** (build, test, clippy `-D warnings`, fmt,
  forbidden-deps, nano size gate, all-features composition); `cargo xtask full-size` green
  (576.7 KiB, 2 MiB tripwire); `cargo xtask reproduce` green (nano byte-identical).
- Heavy I/O (HTTP/TLS, DBs, tree-sitter) never links into nano or the `--features full` binary.

---

## Upgrading & compatibility

**Everything in v0.5.0 is additive and feature-gated; the nano binary is byte-identical to
v0.4.** Invariants 15 and 16 were amended (owner-authorized) — the security boundary is
unchanged, only stated more generally.

- **Operators:** `crustcore-daemon serve` uses `--chat-id` / `CRUSTCORE_TELEGRAM_ALLOW` for the
  allowlist; the bot token comes from `CRUSTCORE_TELEGRAM_TOKEN`. Tasks honor `/cancel <id>` and
  `/kill <id>`; draft PRs require approval via `--open-pr` + inline buttons.
- **Integrators:** the new non-nano packs are behind feature flags; `crustcore-full
  --features all` is the single "everything" build; live transports sit behind `--features
  live` (default builds stay mock-driven for CI).

## Still operator- and maintainer-owned

These genuinely cannot run in CI — each marked `TODO(*-live)`, CI-ignored, but proven
integration-ready by the composition tests: the live HTTPS sockets (Telegram, GitHub App,
model inference, OTLP, Qdrant/LanceDB, MCP-over-HTTP, keychain shell-out, repo enumeration);
Firecracker microVM boot and the full Windows native sandbox; live RAG indexing. And the
irreversible, maintainer-owned steps: the **signed release workflow + signing keys**
(CLAUDE.md §6.3). Self-improvement remains PR-based only; there is no live mutation of the
running kernel.
