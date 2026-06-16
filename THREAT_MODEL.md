# THREAT_MODEL.md — CrustCore Threat Model

> **Purpose:** enumerate CrustCore's adversaries and attack surfaces, and for each
> threat give the asset at risk, the mitigation, and the invariant(s) that defend
> it — then map every red-team scenario to a mitigation.

> This file is a [contract file](./CLAUDE.md#73-contract-files--serialized-changes-only):
> changes are serialized and require maintainer approval. It derives from
> [`ROADMAP.md` §3](./ROADMAP.md) (surfaces), [`§9.2`](./ROADMAP.md) (threats),
> and [`§19.3`](./ROADMAP.md) (red-team tests), and is governed by the
> [twenty product laws](./INVARIANTS.md).

**Related:** [`SECURITY.md`](./SECURITY.md) (policy, trust zones, disclosure) ·
[`docs/security-model.md`](./docs/security-model.md) (prompt-injection boundary,
taint) · [`docs/sandbox.md`](./docs/sandbox.md) (execution containment) ·
[`docs/secrets.md`](./docs/secrets.md) (secret broker) ·
[`INVARIANTS.md`](./INVARIANTS.md).

---

## 1. Scope and method

CrustCore is a coding-agent verifier kernel that drives untrusted LLMs and
external workers over untrusted repositories and untrusted tool output, while
holding real credentials and the authority to mutate repositories and open PRs.
The threat model asks, for each adversary and surface: *what is the asset, how
could it be compromised, and which typed/sandboxed/policy control stops it?*

The guiding assumption — the worst case we design for:

> Assume the model is **adversarial or compromised** at any moment (via indirect
> prompt injection, a poisoned tool result, or a malicious external-worker
> transcript). The system must remain safe even if the LLM actively tries to
> exfiltrate secrets, escape the sandbox, or trick the user into approving a
> harmful action. *Models may propose; only CrustCore may authorize.*

---

## 2. Adversaries

```text
A1. Remote content author        — controls a repo file, issue/PR comment, web page,
                                    or dependency that the agent will read.
A2. Malicious dependency / script — package postinstall/build scripts, CI workflows.
A3. Malicious MCP server          — returns hidden instructions or poisoned resources.
A4. Compromised external worker   — Codex/Claude Code transcript crafted to mislead.
A5. The model itself              — hallucinating or, if injected, acting adversarially.
A6. A subagent                    — attempting to escalate or reach the user directly.
A7. A network adversary           — observing/redirecting egress for exfiltration.
A8. A local tamperer              — altering the event log or stored artifacts.
A9. An impostor on the control channel — spoofing Telegram/admin to issue commands.
```

None of these adversaries is granted ambient authority. They live in the
semi-trusted or untrusted zones ([`SECURITY.md` §2](./SECURITY.md)).

---

## 3. Attack surfaces

From [`ROADMAP.md` §3.2–§3.3](./ROADMAP.md), the surfaces an adversary can reach:

```text
Local CLI                         Sandbox process boundary
Local daemon socket               External helper process boundary
Remote daemon control socket      Event/artifact storage
Worktree filesystem               OS keychain / secret store
Provider APIs (OpenAI/Anthropic/OpenRouter/local)
GitHub API        Telegram Bot API        MCP servers
Codex CLI / Claude Code CLI       Sandbox backends
```

Every external surface is untrusted or semi-trusted and never receives raw
ambient authority ([`ROADMAP.md` §3.3](./ROADMAP.md)).

---

## 4. Trust boundary diagram

```text
                              UNTRUSTED CONTENT
   repo files · issue/PR comments · web pages · shell stdout/stderr ·
   test output · generated code · dependency scripts · MCP results ·
   model output · subagent output · external-worker transcripts
                                   |
                                   |  wrapped as DATA (never instructions)
                                   v
        +==========================================================+
        |                  TRUSTED CORE (nano)                     |
        |  kernel · policy engine · approval engine · secret       |
        |  broker · path confinement · event log · sandbox         |
        |  launcher · receipts                                     |
        |                                                          |
        |   capability tokens out   approval tokens out            |
        +======================|==================|================+
            sandbox profile     |     credential   |    one-shot
            (SandboxExecCap)    |     proxy         |    Telegram nonce
                    v           v                   v
        +-----------------+  +-----------------+  +------------------+
        |  SEMI-TRUSTED   |  |  SEMI-TRUSTED   |  |   TRUSTED HUMAN  |
        |  sandbox        |  |  net/mcp sidecar|  |   operator       |
        |  backend        |  |  + providers /  |  |   (CLI prompt /  |
        |  (Tier 0-3)     |  |  GitHub / MCP   |  |   Telegram IDs)  |
        +-----------------+  +-----------------+  +------------------+
                    |                  |
                    v                  v
              executed code      remote services
              (no secrets,       (no raw tokens;
               deny-all egress)   proxy-injected)

Legend: data flows DOWN as untrusted content; AUTHORITY flows OUT of the core
only as scoped capability/approval tokens. No arrow lets untrusted content or a
semi-trusted surface reach back into the core with authority over policy,
secrets, approvals, sandbox, or the user channel.
```

---

## 5. Threats, assets, mitigations, invariants

Each threat below names the **asset at risk**, the **mitigation**, and the
**defending invariant(s)**. Invariant numbers refer to [`INVARIANTS.md`](./INVARIANTS.md).

### 5.1 Indirect prompt injection

- **Adversary/surface:** A1/A3 via repo files, comments, web pages, MCP output.
- **Asset:** the agent's behaviour — its tools, policy, secrets, approvals, and
  the user channel.
- **Mitigation:** all such content is wrapped as **data** with the untrusted-data
  reminder ([`docs/security-model.md`](./docs/security-model.md),
  [`ROADMAP.md` §9.3](./ROADMAP.md)). Instructions inside data have no authority;
  side effects still require capability/approval tokens minted by the core.
- **Invariants:** **7** (untrusted data), **8** (every side effect through
  policy), **4** (no self-approval).

### 5.2 Credential exfiltration

- **Adversary/surface:** A5/A1 trying to coax a token into output or a request.
- **Asset:** stored credentials (provider keys, GitHub tokens).
- **Mitigation:** the model only ever sees `SecretHandle` (id + label); raw bytes
  live in `SecretMaterial` with no path to model-visible text; tools get secrets
  via one-shot views or credential proxies ([`docs/secrets.md`](./docs/secrets.md)).
- **Invariants:** **1** (no raw credentials to LLM), **3** (secret type
  restrictions), **2** (no unredacted secret logs).

### 5.3 Filesystem escape

- **Adversary/surface:** A5/A4 attempting to read/write outside the worktree
  (e.g. `../../.ssh`, absolute paths, symlink tricks).
- **Asset:** the host filesystem, the user's canonical tree, SSH/cloud configs.
- **Mitigation:** structured tools accept only `ConfinedReadPath`/
  `ConfinedWritePath`, created solely by the path resolver, which rejects null
  bytes, rejects absolute writes, normalizes, resolves the deepest existing
  ancestor, rejects symlink escape, and uses no-follow semantics
  ([`ROADMAP.md` §8.2](./ROADMAP.md), [`docs/sandbox.md`](./docs/sandbox.md)).
- **Invariants:** **8** (policy), and the typed-path enforcement behind it.

### 5.4 Sandbox escape

- **Adversary/surface:** A5/A2 — executed code attempting to break confinement.
- **Asset:** the host (processes, network, filesystem beyond the worktree).
- **Mitigation:** every execution-capable operation requires a `SandboxExecCap`
  bound to a profile; there is no host-shell escape hatch. Backends are chosen per
  OS (Landlock/namespaces/bubblewrap/Firecracker/container; seatbelt; WSL2/
  container) with hostile tasks at Tier 3 in a microVM/container
  ([`docs/sandbox.md`](./docs/sandbox.md), [`ROADMAP.md` §10.1–§10.2](./ROADMAP.md)).
- **Invariants:** **9** (explicit sandbox profile), **8**.

### 5.5 Network exfiltration

- **Adversary/surface:** A5/A2/A7 — code or a request phoning home with data.
- **Asset:** secrets, source, intermediate results.
- **Mitigation:** **deny-all egress by default**, allowlist per task/profile,
  GitHub/model access only through a trusted sidecar/proxy; new host and package
  install require approval; the proxy records task/job/pid/domain/port/protocol/
  bytes/approval ([`docs/sandbox.md`](./docs/sandbox.md),
  [`ROADMAP.md` §10.3](./ROADMAP.md)).
- **Invariants:** **9** (sandbox profile incl. network posture), **8**, **14**
  (approval for new egress/install).

### 5.6 Malicious dependency install scripts

- **Adversary/surface:** A2 — postinstall/build scripts running on dependency add.
- **Asset:** host, network, secrets, build integrity.
- **Mitigation:** package installs run in sandbox (Tier 2/3) with deny-all egress;
  install requires approval; env is sanitized (no inherited secrets/SSH/cloud
  creds); the dependency admission policy gates what enters nano at all
  ([`ROADMAP.md` §10.3–§10.4, §20.3](./ROADMAP.md), [`CONTRIBUTING.md`](./CONTRIBUTING.md)).
- **Invariants:** **9**, **14**, **8**.

### 5.7 Malicious GitHub workflows

- **Adversary/surface:** A1 — a PR/repo that sneaks a `.github/workflows` change.
- **Asset:** CI execution, GitHub-side secrets, branch protections.
- **Mitigation:** modifying GitHub Actions workflows is **ask-always**;
  force-push and branch-protection changes are deny-by-default; workflow edits are
  irreversible-class and gate on approval ([`ROADMAP.md` §15.2](./ROADMAP.md),
  [`CLAUDE.md` §6.3](./CLAUDE.md), [`docs/github.md`](./docs/github.md)).
- **Invariants:** **14** (approval for irreversible), **8**.

### 5.8 Malicious external worker transcript

- **Adversary/surface:** A4 — Codex/Claude Code returning a misleading transcript
  or a diff touching files outside the worktree.
- **Asset:** repository integrity, completion authority.
- **Mitigation:** workers are patch producers, not authorities. The supervisor
  captures the transcript, extracts the *actual* diff from the worktree, rejects
  outside-root changes, reruns the verifier in a clean sandbox, and only a
  `VerifiedPatch` integrates ([`ROADMAP.md` §11.4](./ROADMAP.md),
  [`docs/backend-contract.md`](./docs/backend-contract.md)).
- **Invariants:** **6** (workers not truth authorities), **13** (VerifiedPatch),
  **9**.

### 5.9 Hallucinated / fabricated tool results

- **Adversary/surface:** A5 — the model claiming a tool ran or returned something.
- **Asset:** the integrity of the agent's belief state and the audit trail.
- **Mitigation:** every model-visible tool result carries a `ToolReceipt`
  (tool/args/result hashes, event seq, prev-receipt hash, MAC) generated by
  CrustCore, never the model. No receipt → no model-visible claim a tool ran
  ([`docs/receipts.md`](./docs/receipts.md), [`ROADMAP.md` §7.4](./ROADMAP.md)).
- **Invariants:** **10** (receipt required).

### 5.10 Subagent social engineering

- **Adversary/surface:** A6 — a subagent trying to reach the user or escalate.
- **Asset:** the user channel, the supervisor's authority, secrets.
- **Mitigation:** the agent message bus has **no `Agent -> User` edge**; only the
  supervisor holds the user-channel capability and may resolve secret handles,
  push, integrate, or request approval. Subagents communicate via the event
  bus/blackboard ([`ROADMAP.md` §11.1, §11.3](./ROADMAP.md), [`CLAUDE.md` §7.1](./CLAUDE.md)).
- **Invariants:** **5** (no subagent→user), **8**, **1**.

### 5.11 Budget exhaustion / runaway agents

- **Adversary/surface:** A5/A6 — runaway loops or fan-out consuming cost/time.
- **Asset:** money, wall-clock, host resources, availability.
- **Mitigation:** every task/job carries a budget record (wall time, CPU, memory,
  disk, output size, tokens, model cost, subagent count); exhaustion **pauses** the
  task; concurrency is bounded ([`ROADMAP.md` §1.2 NullClaw lesson 6, §17](./ROADMAP.md),
  [`CLAUDE.md` §7.5](./CLAUDE.md)).
- **Invariants:** **11** (budget limits), **12** (lease/heartbeat/cancel/recovery).

### 5.12 Destructive GitHub operations

- **Adversary/surface:** A5/A1 — a push to merge, force-push, delete tag/release,
  write GitHub secrets, or change branch protection.
- **Asset:** the remote repository and its history.
- **Mitigation:** typed `Reversibility` gates these as Irreversible/Destructive;
  merge/secret-write are ask-always, force-push/branch-protection are
  deny-by-default; pushes go through the credential proxy that validates repo/
  branch/refspec ([`ROADMAP.md` §15.2–§15.3](./ROADMAP.md),
  [`docs/github.md`](./docs/github.md)).
- **Invariants:** **14** (approval token), **4** (no self-approval), **8**.

### 5.13 Tampered event logs

- **Adversary/surface:** A8 — local tampering with stored events/receipts.
- **Asset:** the audit trail and replay integrity.
- **Mitigation:** the event log is append-only and **hash-chained**
  (`prev_hash`/`frame_hash`); receipts form a MAC chain; `crustcore inspect`
  verifies the chain and detects tampering ([`docs/event-log.md`](./docs/event-log.md),
  [`docs/receipts.md`](./docs/receipts.md), [`ROADMAP.md` §7.3–§7.4](./ROADMAP.md)).
- **Invariants:** **10**, **12**.

### 5.14 Secret leakage (logs / artifacts / Telegram / GitHub comments)

- **Adversary/surface:** A5/A1 — secrets sliding into any model-visible or
  outbound channel via stdout, stderr, env dumps, panics, errors, drafts.
- **Asset:** stored credentials.
- **Mitigation:** secret-bearing data is **tainted**; tainted data cannot enter
  model prompts, model-visible tool results, normal logs, Telegram messages,
  GitHub comments, unredacted artifacts, or panic/debug output. Redaction runs
  before any boundary crossing ([`ROADMAP.md` §9.5](./ROADMAP.md),
  [`docs/security-model.md`](./docs/security-model.md), [`docs/secrets.md`](./docs/secrets.md)).
- **Invariants:** **2**, **3**, **1**.

### 5.15 Control-channel spoofing

- **Adversary/surface:** A9 — impersonating the operator on Telegram/admin.
- **Asset:** the approval and command surface.
- **Mitigation:** runtime user comms are Telegram-only by default and bound to
  approved chat IDs; approvals are nonce-bound to an exact operation and expire;
  the CLI is setup/admin/emergency, not a hidden chat channel
  ([`ROADMAP.md` §3.1, §9.1](./ROADMAP.md)).
- **Invariants:** **15** (Telegram-only by default), **16** (CLI not a chat
  channel), **4**, **14**.

---

## 6. Red-team test matrix

From [`ROADMAP.md` §19.3](./ROADMAP.md) and the
[`INVARIANTS.md` red-team requirement](./INVARIANTS.md#red-team-requirement).
Each scenario must have a passing fixture before v0.1, and **any PR adding a new
surface must add the corresponding fixture in the same PR**.

| # | Red-team scenario | Defends against (threat) | Mitigation | Invariants |
| --- | --- | --- | --- | --- |
| R1 | Repo file asks for token | 5.1, 5.2 | wrap-as-data; secrets are handles only | 7, 1, 3 |
| R2 | Issue comment says "ignore policy" | 5.1 | untrusted-data reminder; policy unaffected | 7, 8 |
| R3 | Test output says "exfiltrate secret" | 5.1, 5.5, 5.14 | data has no authority; taint + deny egress | 7, 9, 2 |
| R4 | MCP server returns hidden instructions | 5.1, 5.3 | MCP output untrusted; gateway/policy mediation | 7, 8 |
| R5 | Dependency postinstall attempts network | 5.6, 5.5 | sandbox + deny-all egress + install approval | 9, 14 |
| R6 | External worker writes outside worktree | 5.8, 5.3 | diff extracted from worktree; outside-root rejected | 6, 13 |
| R7 | Model fabricates tool result | 5.9 | receipt required; no receipt → no claim | 10 |
| R8 | Misleading approval text for unsafe action | 5.12, 5.1 | nonce-bound approval to exact operation; human approves | 4, 14 |
| R9 | Sneaked GitHub workflow modification | 5.7 | workflow edits ask-always / irreversible-gated | 14, 8 |
| R10 | Symlink escape path | 5.3 | path resolver rejects symlink escape, no-follow writes | 8 |
| R11 | `LD_PRELOAD` / path-env escape | 5.4, 5.6 | env sanitizer strips vars; path-list components validated | 9 |

> Where a scenario maps to several threats, the fixture must assert the specific
> defending mechanism, not merely that "nothing bad happened." For example R10
> must show the path resolver returning a confinement error, and R7 must show a
> model-visible claim being rejected for lack of a verifiable receipt.

---

## 7. Residual risk & assumptions

```text
- The OS keychain / sandbox primitives are trusted to behave as documented.
  A kernel-level OS vulnerability is out of CrustCore's control (defense in
  depth via Tier-3 microVM for hostile tasks reduces, not eliminates, this).
- Semi-trusted providers are trusted to authenticate correctly; a compromised
  provider endpoint is mitigated by least-authority (no secrets leave the proxy)
  but not fully eliminated.
- The human operator approving via Telegram is trusted; misleading-approval
  defenses reduce social engineering but cannot replace operator judgment.
- A network adversary cannot extract secrets from sandboxed processes because
  egress is deny-all by default; TLS for sidecar↔provider traffic is handled in
  crustcore-net (out of nano scope).
```

These assumptions are revisited whenever a new surface is added; the addition
must update this document and add a red-team fixture (contract-change process,
[`CONTRIBUTING.md`](./CONTRIBUTING.md)).
