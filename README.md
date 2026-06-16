<h1 align="center">CrustCore</h1>

<p align="center">
  <b>A sub-800kB Rust coding-agent <i>verifier kernel</i> with optional capability packs.</b>
</p>

<p align="center">
  <i>Models may propose. Only CrustCore may authorize, verify, persist, expose, or integrate.</i>
</p>

---

## What is CrustCore?

CrustCore is a Rust-native **coding-agent verifier kernel** and optional agent
runtime. Most agent frameworks are big trusted blobs that ask you to believe a
model when it says "done." CrustCore inverts that: it ships a tiny, typed,
auditable **kernel** that owns authorization, verification, and persistence —
and pushes everything heavy (network, providers, Telegram, GitHub, MCP, code
intelligence) out to optional sidecars and capability packs.

> **One-line definition:** CrustCore is a sub-800kB Rust coding-agent verifier
> kernel with typed capabilities, typed secrets, typed approvals, typed confined
> paths, hash-chained event receipts, sandboxed execution, verifier-owned
> completion, and optional larger capability packs for models, GitHub, Telegram,
> MCP, memory, and code intelligence.

The core **is** the trusted verifier kernel. The core **is not** a chat app, a
provider SDK, a database, an MCP platform, a dashboard, a code indexer, or a
general assistant.

## Why it's different

- **Verifier-owned completion.** A patch is done only after CrustCore reruns the
  verifier in a clean sandbox and produces a `VerifiedPatch` — never because a
  model said so.
- **Typed safety.** Dangerous states are unrepresentable. Secrets can't be
  `Debug`/`Serialize`/`Clone`d or turned into model-visible text; paths are
  confined to the worktree by type; irreversible actions need an `Approved<_>`
  token.
- **Tiny by architecture, not by flag.** The nano binary targets **< 800kB**
  stripped and refuses to link Tokio, TLS, DB, MCP SDK, or provider SDKs. A CI
  size gate enforces it.
- **Auditable.** A hash-chained event log plus per-tool receipts mean
  `crustcore inspect` can replay and verify exactly what happened.
- **Layered.** nano → net → daemon → mcp → index → full. Unused capabilities
  cost zero model context and preferably zero linked code.

## Product tiers

| Tier | Size target | Purpose |
| --- | --- | --- |
| `crustcore` / `crustcore-nano` | **< 800kB** (stretch < 600kB) | trusted local verifier harness |
| `crustcore-net` | 3–8MB | network + provider sidecar |
| `crustcore-daemon` | 4–10MB | long-running runtime (Telegram/GitHub/supervision) |
| `crustcore-mcp` | 3–10MB | MCP gateway/client/server + code-mode |
| `crustcore-index` | 2–8MB | repo memory / code intelligence |
| `crustcore-full` | 8–25MB+ | convenience all-in-one |

## Status

**Pre-Phase-0 — documentation first.** This repository currently contains the
complete project contract: vision, invariants, architecture, security model, and
a phased build plan. The Rust workspace is created in Phase 0. The documentation
defines the contract that the code must satisfy.

See the [roadmap](./ROADMAP.md) for the full plan and the v0.1 definition of done.

## Where to start

| If you are… | Read |
| --- | --- |
| An agent/subagent working on the project | **[CLAUDE.md](./CLAUDE.md)** — the single source of truth (start here) |
| Understanding the full plan | [ROADMAP.md](./ROADMAP.md) |
| Wanting the rules that can never break | [INVARIANTS.md](./INVARIANTS.md) |
| Contributing | [CONTRIBUTING.md](./CONTRIBUTING.md) |
| Reviewing security posture | [SECURITY.md](./SECURITY.md) · [THREAT_MODEL.md](./THREAT_MODEL.md) · [docs/security-model.md](./docs/security-model.md) |
| Going deep on a subsystem | the [`docs/`](./docs) directory ([architecture](./docs/architecture.md), [sandbox](./docs/sandbox.md), [secrets](./docs/secrets.md), [policy](./docs/policy.md), [event log](./docs/event-log.md), [receipts](./docs/receipts.md), …) |

## The non-negotiable north star

```text
Models may propose.
Subagents may explore.
External workers may produce patches.
Tools may execute.
Only CrustCore may authorize, verify, persist, expose, or integrate.
Credentials, approvals, and policy decisions are never delegated to an LLM.
A patch is not done because a model says so; it is done only after verifier evidence.
```

## License

License to be selected before the first release (see [CONTRIBUTING.md](./CONTRIBUTING.md)).

---

<p align="center"><i>Keep the core small, typed, and provable. Push everything heavy to the edges.</i></p>
