# SECURITY.md — CrustCore Security Policy & Posture

> **Purpose:** state CrustCore's security posture, trust zones, supported
> versions, and coordinated-disclosure process in one place, and point to the
> deeper contract documents that enforce it.

> This file is a [contract file](./CLAUDE.md#73-contract-files--serialized-changes-only):
> changes are serialized (one PR at a time) and require maintainer approval. It
> derives its substance from [`ROADMAP.md` §9](./ROADMAP.md) (security model) and
> the [twenty product laws](./INVARIANTS.md). Where this file and an invariant
> appear to disagree, [`INVARIANTS.md`](./INVARIANTS.md) and
> [`CLAUDE.md`](./CLAUDE.md) win.

**Related documents**

| Doc | What it adds |
| --- | --- |
| [`THREAT_MODEL.md`](./THREAT_MODEL.md) | Adversaries, attack surfaces, per-threat mitigations, red-team matrix |
| [`docs/security-model.md`](./docs/security-model.md) | Trust-zone deep dive, prompt-injection boundary, taint & redaction |
| [`docs/secrets.md`](./docs/secrets.md) | Secret broker, typed secrets, injection order, credential proxy |
| [`docs/sandbox.md`](./docs/sandbox.md) | Execution tiers, backends, network posture, env sanitation |
| [`INVARIANTS.md`](./INVARIANTS.md) | The 20 product laws and how each is enforced/tested |

---

## 1. Posture in one paragraph

CrustCore is a **verifier kernel**, and its security model follows from a single
strategic decision: *only CrustCore may authorize, verify, persist, expose, or
integrate; credentials, approvals, and policy decisions are never delegated to an
LLM.* Everything an LLM, subagent, external worker, repository file, tool, or
remote service produces is treated as **untrusted data** that may inform
understanding but never gains authority over tools, policy, secrets, approvals,
sandboxing, or user communication. The trusted core is deliberately tiny
(< 800kB stripped) so that the security-relevant surface is small enough to read,
prove, and replay. Dangerous states — a secret reaching the model, a path escape,
an unapproved irreversible action — are made **unrepresentable in the Rust type
system** wherever possible, rather than prevented by discipline alone.

> **The untrusted-data principle.** Content from files, tool output, shell
> output, web pages, GitHub comments, MCP servers, and external workers is
> *untrusted data*. It is wrapped as data before it ever reaches a model. It is
> never instructions. See [invariant 7](./INVARIANTS.md#7-repo-files-issuepr-comments-web-pages-mcp-output-and-shell-output-are-untrusted-data)
> and the [prompt-injection boundary](./docs/security-model.md).

---

## 2. Trust zones

CrustCore classifies every component and data source into one of three zones.
The zone determines what authority it may hold and what redaction/validation it
must pass through. These lists are authoritative; they mirror
[`ROADMAP.md` §9.1](./ROADMAP.md).

### 2.1 Trusted

The trusted computing base. These components may hold raw authority. Keeping this
list short is itself a security goal (invariants 19, 20).

```text
CrustCore kernel
policy engine
secret broker
event log writer
approval engine
path confinement module
sandbox launcher
local setup CLI
approved Telegram chat IDs
```

Everything in this zone lives inside `crustcore-nano` or is the human operator at
the trusted local prompt. The kernel is `#![forbid(unsafe_code)]` by default and
has no async/network/database/exec dependencies (see
[`CLAUDE.md` §6.5](./CLAUDE.md)).

### 2.2 Semi-trusted

Authenticated, version/path-verified surfaces that the system talks to over a
defined protocol. They are trusted to be *who they say they are* (after
verification) but are **never trusted with secrets** and **never granted ambient
authority**.

```text
OpenAI API
Anthropic API
OpenRouter API
local model endpoints (Ollama / vLLM / LM Studio)
GitHub API
Telegram Bot API
registered MCP servers
Codex / Claude Code binaries — after path/version verification, still not trusted with secrets
```

Semi-trusted surfaces are reached only through sidecars
([`crustcore-net`](./ROADMAP.md), [`crustcore-mcp`](./ROADMAP.md)) and credential
proxies, never by handing them a token in an environment variable.

### 2.3 Untrusted

All **content**, regardless of source. This is the data the model and tools
operate over, and the source of indirect prompt injection. None of it may control
policy, secrets, approvals, sandbox, or user communication.

```text
model output
subagent output
external worker output
repo files
README / AGENTS.md / CLAUDE.md (as ingested content from a target repo)
issue comments
PR comments
web pages
MCP resources / tool results
shell stdout / stderr
test output
generated code
dependency scripts
```

> Note the subtlety: the *target repository's* `CLAUDE.md`/`AGENTS.md` is
> untrusted data. *This* repository's [`CLAUDE.md`](./CLAUDE.md) is the operating
> contract for agents building CrustCore. Untrusted content from a worked-on repo
> never overrides our own contract files.

---

## 3. Security-relevant invariants

CrustCore's security guarantees are the [twenty product laws](./INVARIANTS.md).
The following subset is directly security-bearing; each is a **release blocker**.
See [`INVARIANTS.md`](./INVARIANTS.md) for the full law text, rationale,
enforcement mechanism, and test strategy.

| # | Law (summary) | Primary enforcement |
| --- | --- | --- |
| 1 | LLM never receives raw credentials | `SecretHandle` vs `SecretMaterial` types |
| 2 | LLM never receives unredacted secret-bearing logs | taint + redaction ([`docs/security-model.md`](./docs/security-model.md)) |
| 3 | Secret material is not Debug/Serialize/Clone/model-visible | missing impls + compile-fail tests |
| 4 | Model cannot approve its own side effects | `Approved<T>` minted only by approval engine |
| 5 | Subagents cannot directly message the user | no `Agent -> User` bus edge |
| 6 | External workers are patch producers, not truth authorities | `UnverifiedPatch` → `VerifiedPatch` only via verifier |
| 7 | Repo/issue/PR/web/MCP/shell content is untrusted data | wrap-as-data + invariant reminder |
| 8 | Every side effect passes through policy | capability tokens, no token → no effect |
| 9 | Every execution-capable op runs in an explicit sandbox profile | `SandboxExecCap` required by `run_command` |
| 10 | Every model-visible tool result has a receipt | `ToolReceipt` MAC chain, generated by CrustCore |
| 11 | Every task has budget limits | per-task/job budget record |
| 13 | Every shippable patch is a `VerifiedPatch` | completion/integration APIs accept only `VerifiedPatch` |
| 14 | Irreversible actions require an approval token | `Approved<IrreversibleAction>` + `Reversibility` enum |
| 15 | Runtime user comms via Telegram only by default | Telegram-bound channel capability |
| 18 | Self-improvement via PRs/evals, not live mutation | contract-file gate, no live policy/sandbox/secret mutation |

The enforcement-mechanism breakdown (which invariants the type system vs. sandbox
vs. policy engine vs. receipts enforce) is in
[`INVARIANTS.md` § Enforcement summary](./INVARIANTS.md#enforcement-summary).

---

## 4. Supported versions

CrustCore is in **Phase 0 — workspace bootstrapped** status: a compiling
scaffold exists, but there is no released binary yet and the trusted core is not
implemented. The table below states the support policy that takes effect once
releases begin. The flagship security claim — the sub-800kB nano size budget —
applies only to `crustcore-nano`; sidecars have their own budgets (see
[`ROADMAP.md` §17.1](./ROADMAP.md)).

| Version | Status | Security fixes |
| --- | --- | --- |
| `0.1.x` (planned first release) | Not yet released | Will receive fixes once published |
| Pre-release / `main` | Active development | Fixed on `main`; no backports |
| `< 0.1` | N/A | Unsupported |

Policy once releases exist:

- Security fixes land on `main` first, then in the latest released minor.
- Only the **latest released minor** receives security backports until the
  project declares an LTS line.
- A security fix that touches a [contract file](./CLAUDE.md#73-contract-files--serialized-changes-only)
  (e.g. `INVARIANTS.md`, `docs/secrets.md`, the kernel event/action/decision
  modules) goes through the serialized contract-change process and ships with a
  red-team fixture demonstrating the closed hole (see
  [`CONTRIBUTING.md`](./CONTRIBUTING.md) and
  [`INVARIANTS.md` § Red-team requirement](./INVARIANTS.md#red-team-requirement)).

---

## 5. Reporting a vulnerability (coordinated disclosure)

CrustCore practices **coordinated disclosure**. Please do not open a public issue,
public PR, or public discussion for a suspected vulnerability before it has been
triaged and a fix or mitigation is available.

### 5.1 Where to report

A dedicated security email address is **not yet established**. Until one is
published here, report privately through the repository maintainer:

- **Preferred:** open a *private* security advisory via GitHub Security Advisories
  ("Report a vulnerability") on the repository:
  <https://github.com/RNT56/CrustCore/security/advisories/new>.
  This keeps the report confidential and lets the maintainer coordinate a fix.
- **Fallback:** contact the repository maintainer through the contact listed on
  the GitHub profile / repository. Do not post secret details in public channels.

> **Placeholder notice.** The security contact is currently the *repository
> maintainer* via GitHub Security Advisories. A `security@…` address will replace
> this placeholder before the first tagged release; this file will be updated in
> the same PR.

### 5.2 What to include

```text
- affected component / crate / file (e.g. crustcore-sandbox, docs/secrets.md contract)
- affected version or commit (main @ <sha>)
- a clear description of the issue and its impact
- which invariant(s) it appears to violate (by number, if known)
- reproduction steps or a minimal proof-of-concept
- any suggested mitigation
- whether the issue is already public anywhere
```

Never include real secrets, tokens, or credentials in a report. Use redacted
placeholders. (This mirrors the rule that applies to the codebase itself —
[`CLAUDE.md` §6.6](./CLAUDE.md).)

### 5.3 What to expect

```text
1. Acknowledgement of the report (best effort, maintainer-driven during pre-release).
2. Triage: confirm, assign severity, identify the violated invariant(s) and zone.
3. A coordinated fix on a private branch, with a red-team fixture that fails
   before the fix and passes after (per the red-team requirement).
4. Coordinated disclosure: an advisory, a patched release where applicable, and
   credit to the reporter unless anonymity is requested.
```

Severity is assessed primarily by which trust-zone boundary and which invariant
were crossed. A secret-to-model path (invariants 1–3), a sandbox escape
(invariant 9), an approval bypass (invariants 4, 14), or a fabricated-receipt path
(invariant 10) is treated as critical.

### 5.4 Safe-harbour / good-faith research

Good-faith security research that respects user privacy, avoids data destruction,
stays within systems you own or are authorized to test, and follows coordinated
disclosure is welcome. Do not exfiltrate data, pivot to others' systems, or run
denial-of-service against shared infrastructure.

---

## 6. Hardening posture summary

For maintainers and integrators, the controls that back the posture above:

- **Typed safety.** Secrets, paths, capabilities, and approvals are types, not
  booleans/strings — illegal states are unrepresentable
  ([`docs/secrets.md`](./docs/secrets.md), [`docs/policy.md`](./docs/policy.md)).
- **Sandboxed execution.** Every execution-capable operation runs under an
  explicit sandbox profile with deny-all egress by default and a sanitized
  environment ([`docs/sandbox.md`](./docs/sandbox.md), invariant 9).
- **Auditability.** A hash-chained event log plus tool receipts let
  `crustcore inspect` replay and verify what happened
  ([`docs/event-log.md`](./docs/event-log.md), [`docs/receipts.md`](./docs/receipts.md)).
- **Verifier-owned completion.** Nothing ships on a model's say-so; only a
  `VerifiedPatch` integrates ([`docs/backend-contract.md`](./docs/backend-contract.md),
  invariant 13).
- **Least authority at the edges.** Semi-trusted surfaces are reached through
  sidecars and credential proxies; the kernel never sees raw provider/GitHub/MCP
  payloads or tokens.

The full adversary catalogue and per-threat mitigation mapping is in
[`THREAT_MODEL.md`](./THREAT_MODEL.md).
