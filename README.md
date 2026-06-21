<div align="center">

<img src="assets/crustcore-header-transparent.png" alt="CrustCore — a sub-800 kB Rust coding-agent verifier kernel" width="820">

# CrustCore

### The coding agent that can’t mark its own homework.

**A sub-800 kB Rust verifier kernel that owns authorization, verification, and audit — so a patch ships because the tests passed, not because a model said so.**

[![CI](https://github.com/RNT56/CrustCore/actions/workflows/ci.yml/badge.svg)](https://github.com/RNT56/CrustCore/actions/workflows/ci.yml)
&nbsp;![nano size](https://img.shields.io/badge/nano-412.0_KiB_%2F_800_KiB-2ea44f)
&nbsp;![tests](https://img.shields.io/badge/tests-352_passing-2ea44f)
&nbsp;![invariants](https://img.shields.io/badge/invariants-20_enforced-1f6feb)
&nbsp;![kernel](https://img.shields.io/badge/kernel-std--only_%C2%B7_no_async%2Fnet%2Fdb-8957e5)
&nbsp;![rust](https://img.shields.io/badge/rust-1.85+-orange)
&nbsp;![license](https://img.shields.io/badge/license-Apache--2.0-1f6feb)

<em>Models may propose. Subagents may explore. External workers may produce patches. Tools may execute.<br/>
Only CrustCore may <strong>authorize, verify, persist, expose, or integrate.</strong></em>

</div>

---

## The problem

Most coding-agent frameworks are large, trusted blobs. They hold your
credentials, run shell commands, push branches, open PRs — and the moment of
truth, *“is this change actually done?”*, comes down to a model emitting the word
**done**. You audit that by reading a transcript and hoping.

CrustCore refuses that bargain. It is built on one inversion:

> **A model’s claim is evidence, never authority.**
> Completion, integration, secrets, and approvals are decided by a small, typed,
> auditable kernel — and *proven*, not asserted.

You don’t have to trust CrustCore’s agent. You can **read the kernel, prove what
is allowed, and replay exactly what happened.**

---

## What that buys you

<table>
<tr>
<td width="50%" valign="top">

**🔒 Verifier-owned completion**

A patch is `done` only after CrustCore re-runs *your* verify command in a clean
sandbox and mints a `VerifiedPatch`. That type is **sealed** — the only thing
that can construct one is the verifier, and `complete_task` consumes it by value.
A model cannot fabricate completion; the type system won’t let it.

</td>
<td width="50%" valign="top">

**🧩 Dangerous states are unrepresentable**

Not “discouraged” — *uncompilable*. A secret can’t be `Debug`/`Serialize`/`Clone`d
or turned into model-visible text. A path that escapes the worktree has no type.
An irreversible action with no `Approved<_>` token doesn’t type-check. The
compiler is the first line of the security policy.

</td>
</tr>
<tr>
<td width="50%" valign="top">

**📜 Replayable, tamper-evident audit**

Every run is an **append-only, hash-chained event log** plus per-tool
**receipts** (a keyed MAC chain a model can’t forge). `crustcore inspect` walks
the chain and tells you the first byte that was altered. Your audit story is a
proof, not a vibe.

</td>
<td width="50%" valign="top">

**📦 Tiny by architecture, not by flag**

The trusted binary is **412.0 KiB stripped** and *refuses* to link Tokio, TLS, a
database, an MCP SDK, or any provider SDK. A CI size gate fails the build if it
creeps over 800 kB. Small enough to read end to end in an afternoon.

</td>
</tr>
<tr>
<td width="50%" valign="top">

**🧱 Sandboxed or not at all**

Shell, tests, and external workers run under an explicit sandbox profile —
bounded output, timeouts, process-tree kill, a from-scratch environment with no
inherited secrets, deny-all egress. If no sandbox backend is present, execution
is **refused**. There is no “just run it unsandboxed” path.

</td>
<td width="50%" valign="top">

**🪶 Pay only for what you use**

`nano → net → daemon → mcp → index → full`. Network, providers, Telegram, GitHub,
MCP, and code intelligence are separate capability packs. Unused capabilities
cost **zero model context** and, by feature-gating, **zero linked code**.

</td>
</tr>
</table>

---

## Architecture in one screen

A **nanokernel plus capability packs**. The kernel is a synchronous,
deterministic, allocation-light reducer — `event → state → bounded actions` —
with **no async runtime, no network, no database, and no wall clock**. The dirty
outside world only ever reaches it as translated events.

```text
                      ┌─────────────────────────────────────────────┐
   raw HTTP · TLS     │              crustcore-kernel               │
   Telegram · GitHub  │   sync · deterministic · std-only · tiny    │
   MCP · shell · SQL  │                                             │
        │             │   task/job state machine · typed budgets    │
        │  adapters    │   capability + approval tokens · policy     │
        ▼  translate   │   event/receipt framing · backend contract  │
   ┌──────────┐  events └──────────────────┬──────────────────────────┘
   │ sidecars │ ───────────────▶            │  bounded Action list
   └──────────┘                             ▼
   net · daemon · mcp · index      git worktree · sandbox · verifier
        (capability packs)         disposable · confined · evidence-only
```

Adapters do all the translation, so the trust boundary stays small and legible:

```text
Telegram update  →  InboundEnvelope    →  Event::UserTurn
GitHub webhook   →  GitHubEnvelope     →  Event::GitHubObserved
Model response   →  AgentObservation   →  Event::ModelOutput
Tool result      →  ToolReceipt + Artifact → Event::ToolCompleted
```

📐 Full design: **[docs/architecture.md](./docs/architecture.md)** · size discipline:
**[docs/nano-size-budget.md](./docs/nano-size-budget.md)**

---

## The promise, stated plainly

CrustCore is finished when a maintainer can say all six of these and mean them.
Today, they hold:

```text
✔ I can read the kernel.
✔ I can prove what is allowed.
✔ I can replay what happened.
✔ I can verify a patch shipped because tests passed.
✔ I can show secrets did not enter prompts.
✔ I can disable every optional surface and keep the harness tiny.
```

---

## Status — v0.1 trusted core + v0.2/v0.3 live surfaces merged

The entire roadmap (**Phases 0–16**) is implemented and merged, the v0.1
[definition of done](./ROADMAP.md) (all 12 criteria) is met, and the **v0.2
"light it up" (Track A) and v0.3 "expand" (Track B, B1–B6)** phases are merged on
top — wiring real model providers, Telegram, GitHub REST + webhooks, MCP
client/server, subagent execution, the native/vault secret store, semantic memory,
tier-aware sandboxing, the self-improvement loop, and reproducible builds onto the
already-verified cores.

| | |
| --- | --- |
| **Nano binary** | **412.0 KiB** stripped — 51.5 % of the 800 kB budget (CI-gated) |
| **Tests** | **~350** green across the workspace — property tests, no-panic fuzzes, tamper tests, red-team fixtures, goldens |
| **Trusted core** | kernel · hash-chained event log + receipts · symlink-safe path confinement · runner + sandbox · worktree verify loop · type-sealed `VerifiedPatch` |
| **Capability packs** | model transport · secret broker + vault · Telegram · GitHub REST + webhooks · subagent supervisor + executor · advisor · MCP gateway + server · repo / semantic memory · self-improvement — all as **std-only, fully-tested decision cores** with their live adapters wired behind a `live` feature |
| **Red-team** | prompt-injection, path-escape, fake-tool-result, secret-leak, MCP-hidden-instruction, memory-as-authority, silent-weakening, hostile-MCP-client, forged/replayed webhook, and hostile-embedded-doc fixtures all pass |

> **Honest scope.** The *trust, policy, and decision logic* of every layer is
> built and tested, and the v0.2/v0.3 live adapters (HTTP model providers, the
> Telegram Bot API, the GitHub REST flow + webhook verification, the encrypted
> secret vault, MCP server mode, …) are now implemented behind a `live` cargo
> feature. What remains are the few seams that genuinely cannot run in CI without
> real network, secrets, a sandbox backend, a microVM, or an embedding provider —
> each marked with a clear `TODO(*-live)` and dropping into an already-verified,
> transport-agnostic core.

---

## Product tiers

| Tier | Size target | Purpose |
| --- | --- | --- |
| **`crustcore` / `crustcore-nano`** | **< 800 kB** *(stretch < 600 kB)* | the trusted local verifier harness — the flagship |
| `crustcore-net` | 3–8 MB | network + provider sidecar (Tokio/TLS/providers) — a *spawned* helper, never linked into nano |
| `crustcore-daemon` | 4–10 MB | long-running runtime: Telegram/GitHub loops, supervision |
| `crustcore-mcp` | 3–10 MB | MCP gateway/client/server + code-mode |
| `crustcore-index` | 2–8 MB | repo memory / code intelligence |
| `crustcore-full` | 8–25 MB+ | convenience all-in-one (never the size-claim binary) |

---

## Quickstart

```bash
# 1. The full "is it done?" gate — fmt + clippy -D warnings + tests
#    + forbidden-dependency check + the nano size gate.
cargo xtask verify

# 2. Build the flagship and print size vs. budget.
cargo xtask size-check          # crustcore-nano: 412.0 KiB / 800 KiB (51.5%)

# 3. Is this host ready to run verified tasks?
cargo run -p crustcore --no-default-features --features nano -- doctor

# 4. Run a task: create a disposable worktree, re-run <cmd> in a sandbox,
#    and complete ONLY if it passes.
crustcore run -dir . -goal "fix the failing test" -verify "cargo test"

# 5. Audit it: verify the hash chain and replay the run.
crustcore inspect ./events.log      # → INTACT, with a task summary
crustcore export  ./events.log      # → JSONL

# 6. Cut a checksummed release artifact (size-gated).
cargo xtask release                 # → SHA256SUMS + release-manifest.txt
```

The workspace is **std-only and builds offline**; heavy dependencies live only in
the sidecar packs. Requires a stable Rust toolchain (≥ 1.85) with `rustfmt` and
`clippy`, pinned in [`rust-toolchain.toml`](./rust-toolchain.toml). Release &
operations: **[docs/releasing.md](./docs/releasing.md)**.

---

## The 20 invariants

These are **release blockers**, not aspirations — each is enforced in types,
tests, or both, and catalogued in **[INVARIANTS.md](./INVARIANTS.md)**.

<details>
<summary><strong>Show all 20</strong></summary>

```text
 1. The LLM never receives raw credentials.
 2. The LLM never receives unredacted secret-bearing logs.
 3. Secret material is not Debug, Serialize, Clone, or model-visible.
 4. The model cannot approve its own side effects.
 5. Subagents cannot directly message the user.
 6. External workers are patch producers, not truth authorities.
 7. Repo files, comments, web pages, MCP output, and shell output are untrusted data.
 8. Every side effect passes through policy.
 9. Every execution-capable operation runs in an explicit sandbox profile.
10. Every model-visible tool result has a receipt.
11. Every task has budget limits.
12. Every long-running job has lease, heartbeat, cancellation, and recovery.
13. Every shippable patch is a VerifiedPatch.
14. Irreversible actions require an approval token.
15. Runtime user communication goes through Telegram only by default.
16. The CLI is setup/admin/emergency, not a hidden second chat channel.
17. Model/provider names are config and capability-probed, not permanent assumptions.
18. Self-improvement happens through PRs/evals, not live mutation of the running kernel.
19. The nano build must remain below the configured size budget.
20. Unused capabilities cost zero model context and preferably zero linked code.
```

</details>

---

## Where to start

| If you are… | Read |
| --- | --- |
| 🤖 An agent/subagent working on the project | **[CLAUDE.md](./CLAUDE.md)** — the single source of truth |
| 🗺️ Understanding the full plan | [ROADMAP.md](./ROADMAP.md) (v0.1) · [docs/roadmap-v0.2.md](./docs/roadmap-v0.2.md) (v0.2+: light up & expand) |
| ⛓️ Wanting the rules that can never break | [INVARIANTS.md](./INVARIANTS.md) |
| 🛡️ Reviewing security posture | [SECURITY.md](./SECURITY.md) · [THREAT_MODEL.md](./THREAT_MODEL.md) · [docs/security-model.md](./docs/security-model.md) |
| 🤝 Contributing | [CONTRIBUTING.md](./CONTRIBUTING.md) |
| 🔬 Going deep on a subsystem | [`docs/`](./docs) — [architecture](./docs/architecture.md) · [sandbox](./docs/sandbox.md) · [secrets](./docs/secrets.md) · [policy](./docs/policy.md) · [event log](./docs/event-log.md) · [receipts](./docs/receipts.md) · [releasing](./docs/releasing.md) |

---

## License

Licensed under the [Apache License, Version 2.0](./LICENSE) — see [`NOTICE`](./NOTICE).
Unless you state otherwise, any contribution you intentionally submit for
inclusion shall be licensed as above, without additional terms
(see [CONTRIBUTING.md](./CONTRIBUTING.md)).

---

<div align="center">
<em>Keep the core small, typed, and provable. Push everything heavy to the edges.</em>
</div>
