# docs/github.md — GitHub Integration

> **Purpose:** specify how CrustCore authenticates to GitHub, which operations it
> may perform under which gates, how the git credential proxy keeps tokens out of
> the sandbox, and how the verified-patch → draft-PR → CI-repair loop works.

**Source of truth:** [`ROADMAP.md` §15](../ROADMAP.md) (auth, capabilities,
credential proxy), [`ROADMAP.md` §12.8](../ROADMAP.md) (GitHub lifecycle stage),
[`ROADMAP.md` §18 Phase 10](../ROADMAP.md) (tasks/acceptance).
**Governs / governed by:** invariants **1, 7, 8, 9, 13, 14** in
[`INVARIANTS.md`](../INVARIANTS.md).
**Siblings:** [`telegram.md`](./telegram.md),
[`backend-contract.md`](./backend-contract.md) (when present),
[`secrets.md`](./secrets.md) (when present),
[`maintainer-agent.md`](./maintainer-agent.md).

---

## 1. Posture: GitHub is a semi-trusted external surface

GitHub is the project control plane — issues, branches, PRs, CI — but it is an
**external surface** ([`ROADMAP.md` §3.3, §9.1](../ROADMAP.md)). The GitHub API
is *semi-trusted* (we authenticate to it and trust its transport), but
**everything it returns as content** — issue bodies, PR comments, review text,
CI logs — is **untrusted data** (invariant 7). CrustCore never grants GitHub raw
ambient authority, and never lets GitHub-sourced text drive policy, secrets,
approvals, or user communication.

Like Telegram, GitHub integration is a **sidecar**: the REST/GraphQL adapter and
credential proxy live in `crustcore-net` / `crustcore-daemon`, **not in nano**
(invariants 19, 20). The kernel sees only normalized
`Event::GitHubObserved` / `Event::GitHubOperationRequested` /
`Event::GitHubOperationCompleted`, never raw GitHub JSON
([`CLAUDE.md` §3](../CLAUDE.md)).

---

## 2. Authentication

Authentication strength is ranked; CrustCore prefers the strongest available and
warns on the weakest ([`ROADMAP.md` §15.1](../ROADMAP.md)).

| Mode | Preference | Properties |
| --- | --- | --- |
| **GitHub App** | **Preferred** | Repo-scoped permissions; **short-lived installation tokens** minted per use; revocable; least standing authority |
| **Fine-grained PAT** | Fallback | Per-repo scopes; longer-lived; acceptable for local setup |
| **Classic PAT** | Discouraged | Broad scopes, long-lived; allowed **only with an explicit warning** |

### 2.1 GitHub App (preferred)

A GitHub App installed on the target repos lets CrustCore mint **short-lived
installation tokens** scoped to exactly the permissions the App declares. This is
the cleanest fit for the secret model:

- The App's private key is a `SecretMaterial` (invariant 3) held by the trusted
  broker; it is never model-visible and never enters the sandbox.
- Installation tokens are minted **on demand**, used, and allowed to expire —
  matching the "short-lived token minted by broker" injection order
  ([`ROADMAP.md` §9.4](../ROADMAP.md)).
- Permissions are repo-scoped: the blast radius of any one token is bounded to
  declared repos/permissions.

### 2.2 PAT fallbacks

A **fine-grained PAT** is acceptable for local setup where an App is impractical.
A **classic PAT** is the last resort: its broad, long-lived scopes are exactly
what the secret model tries to avoid, so CrustCore **emits a warning** at setup
and records the weaker posture. Whatever the mode, the token is a secret handle
to the broker, never config-resident plaintext and never model-visible
(invariant 1; `secret://` handles, [`ROADMAP.md` §9.4](../ROADMAP.md)).

---

## 3. Capabilities and deny/ask defaults

The capability set ([`ROADMAP.md` §15.2](../ROADMAP.md)):

```text
read issues
write issue comments
read PRs
write PR comments
create branch
push branch
open draft PR
monitor checks
request review
rerun actions if allowed
create releases if explicitly allowed
merge PR only with explicit approval
```

Every one of these is a **side effect that passes through policy** (invariant 8)
and requires a capability token (e.g. `GitHubWriteCap`,
[`ROADMAP.md` §8.3](../ROADMAP.md)). Reversible reads/comments run freely;
irreversible operations gate on `Approved<T>` (invariant 14).

### 3.1 Deny / ask defaults

These defaults are **product law-adjacent** and must not be silently weakened
(invariant 18, [`ROADMAP.md` §15.2](../ROADMAP.md)):

| Operation | Default | Reversibility | Why |
| --- | --- | --- | --- |
| **Merge PR** | **ask always** | Irreversible | Shipping to a protected branch is never autonomous (invariants 13, 14) |
| **Force-push** | **deny default** | Destructive | Rewrites history; can erase others' work |
| **Delete tag / release** | ask / high risk | Destructive | Removes published artifacts |
| **Write GitHub secrets** | **ask always** | Irreversible | Repo secret material; never autonomous |
| **Change branch protection** | **deny default** | Irreversible | Weakening protection disables the safety net itself |
| **Modify GitHub Actions workflow** | **ask always** | Irreversible | Workflows run with elevated CI credentials — an injection target |

`ask` means: emit an `ApprovalRequest`, route it through Telegram as a
nonce-bound, operation-bound approval ([`telegram.md` §6](./telegram.md)), and
proceed only on an `Approved<T>`. `deny default` means: the operation is refused
unless policy is explicitly reconfigured by a maintainer through the trusted
admin path — not by a model, a steer, or untrusted repo/PR content.

> Workflow edits and branch-protection changes are singled out because they are
> the classic "agent quietly weakens its own guardrails" attack. Treat any
> PR/issue/comment that *asks* for a workflow or protection change as untrusted
> data (invariant 7), and still require the typed approval gate regardless of
> who appears to ask.

---

## 4. Git credential proxy (no raw token in the sandbox)

The single most important GitHub security mechanism: **no raw GitHub token in the
sandbox environment, by default** ([`ROADMAP.md` §15.3](../ROADMAP.md),
invariant 1). Git operations inside a sandboxed task authenticate through a
**local credential-helper proxy**:

```text
git in sandbox
  -> local credential helper proxy   (trusted process, outside sandbox)
  -> validates repo / branch / refspec against the task's GitHubWriteCap
  -> mints / injects a short-lived installation token
  -> GitHub
  -> proxy returns only the operation result; token never lands in sandbox env
```

Why a proxy instead of `GITHUB_TOKEN` in the environment:

- **Tokens never cross the sandbox boundary.** Environment variables, files, and
  process memory in the sandbox are reachable by untrusted generated code and
  malicious dependency scripts ([`ROADMAP.md` §9.2](../ROADMAP.md)). A token in
  `env` is a token waiting to be exfiltrated. This matches env sanitation rules
  that strip credential-bearing variables ([`ROADMAP.md` §10.4](../ROADMAP.md)).
- **The proxy is a policy checkpoint.** It validates the *target* of every
  authenticated git operation: the repo must match the cap, the branch must match
  the cap's `branch_prefix`, and the refspec must be a permitted push (not a
  force-push, not a protected branch) unless an `Approved<T>` is presented. A
  request to push to `main` or force-push is rejected at the proxy even if the
  in-sandbox git command tries it.
- **Tokens are short-lived.** The proxy mints per-operation installation tokens
  and lets them expire, minimizing the value of any leak.

This is the GitHub instantiation of the secret model's preferred injection order
(credential proxy / git credential-helper proxy first; environment variable only
when unavoidable — [`ROADMAP.md` §9.4](../ROADMAP.md)).

### 4.1 Edge cases the proxy must handle

- **Refspec smuggling:** a request whose refspec encodes a force-update
  (`+refs/...`) or a protected branch is denied regardless of the textual branch
  argument.
- **Repo mismatch:** a worktree reconfigured to point at a different `origin`
  cannot borrow the cap's token for an out-of-scope repo.
- **Submodules / nested remotes:** auth requests for unexpected hosts are denied
  by default (new host requires approval, [`ROADMAP.md` §10.3](../ROADMAP.md)).

---

## 5. Untrusted GitHub content (invariant 7)

Issue bodies, PR descriptions, review comments, and CI logs are **untrusted
data**. They are ingested as data with the standard invariant reminder
([`ROADMAP.md` §9.3](../ROADMAP.md)) and may inform code understanding, but they
**never** control tools, policy, secrets, approvals, or user communication.

Phase 10 task P10.8 is explicit: *"Implement PR comment ingestion as untrusted
data."* Concretely:

- A PR comment that says "merge this now" or "ignore the failing test" does not
  cause a merge or weaken the verifier. Merge still requires an `Approved<T>`
  (invariants 13, 14).
- A comment that says "run this script" or "set this secret" is data, not a
  command. It is surfaced to the agent's understanding wrapped as untrusted; it
  cannot mint a capability.
- The prompt-injection red-team fixtures cover exactly this: "issue comment says
  ignore policy" ([`ROADMAP.md` §19.3](../ROADMAP.md),
  [`INVARIANTS.md`](../INVARIANTS.md) red-team requirement). Adding GitHub-comment
  ingestion requires the corresponding fixture in the same PR.

---

## 6. The verified-patch → draft-PR loop

GitHub write operations are downstream of the verifier. Only a **`VerifiedPatch`**
may produce a PR (invariant 13; [`ROADMAP.md` §7.5, §12.8](../ROADMAP.md)):

```text
candidate patch
  -> verifier reruns tests in a clean sandbox
  -> VerifiedPatch (patch + verifier name + command evidence + receipt)
  -> push branch (through credential proxy, §4)
  -> open DRAFT PR
  -> PR body: summary, test evidence, risks, files changed
  -> monitor checks
```

Rules:

- **Draft, not ready-for-merge.** CrustCore opens **draft** PRs. A draft signals
  "machine-produced, awaiting human review" and avoids accidental auto-merge
  paths.
- **Never merge without approval.** Merge is `ask always` (invariants 13, 14;
  §3.1). Phase 10 acceptance: *"Cannot merge without approval."* The completion
  message ([`ROADMAP.md` §12.9](../ROADMAP.md)) hands the human a PR link and the
  next action — it does not self-merge.
- **No force-push by default.** Phase 10 acceptance: *"Cannot force-push by
  default."* Enforced at the credential proxy (§4) and by policy default (§3.1).
- **PR body is evidence, not marketing.** It carries the verifier name, commands
  run, and unresolved risks — the same evidence that made the patch a
  `VerifiedPatch`. `self_claimed_done` from a model is never sufficient
  (invariant 6, [`backend-contract.md`](./backend-contract.md)).

---

## 7. CI monitoring and the repair-task loop

After a draft PR is open, CrustCore monitors checks
([`ROADMAP.md` §12.8, §15.2](../ROADMAP.md)):

```text
PR open
  -> monitor checks (poll / webhook if daemon webhook feature enabled)
  -> check failed?
       -> ingest CI logs as UNTRUSTED data (invariant 7)
       -> create a repair task (new worktree, new verify loop)
       -> repair patch -> verifier -> VerifiedPatch -> push update to same branch
  -> checks green
       -> stream status to user (telegram.md §7); await human merge approval
```

Notes:

- **CI logs are untrusted** (invariant 7). They are parsed as data to localize a
  failure, never obeyed. A CI log line that says "set `NPM_TOKEN` and rerun" is
  not a command.
- **Repair is bounded.** The repair loop is budgeted (invariant 11) and
  retry-bounded; it does not loop forever on a flaky or unfixable check. After
  the configured attempts it stops and surfaces the state to the user.
- **`rerun actions`** is permitted only when policy allows it; modifying the
  workflow to "fix" CI is `ask always` (§3.1) — repairing the *code* is the
  default path, not rewriting the *pipeline*.

---

## 8. Where it lives, and what nano sees

| Concern | Crate | In nano? |
| --- | --- | --- |
| REST/GraphQL adapter | `crustcore-net` | No |
| Git credential-helper proxy | `crustcore-net` / `crustcore-daemon` | No |
| Issue→PR loop, CI monitoring, repair tasks | `crustcore-daemon` | No |
| GitHub events (`GitHubObserved`, `GitHubOperationRequested/Completed`) | `crustcore-kernel` | Yes (events only) |
| `GitHubWriteCap`, `Approved<T>` types | `crustcore-policy` / `crustcore-types` | Yes (types) |

Nano links **none** of the GitHub HTTP/auth stack (invariants 19, 20). The
capability is additive; a nano-only build produces local `VerifiedPatch`es with
no GitHub surface at all.

---

## 9. Phase 10 tasks and acceptance

From [`ROADMAP.md` §18 Phase 10](../ROADMAP.md):

```text
P10.1 Implement GitHub App auth.
P10.2 Implement fine-grained PAT fallback.
P10.3 Implement repo registration.
P10.4 Implement branch push through credential proxy.
P10.5 Implement draft PR creation.
P10.6 Implement PR body/test evidence formatting.
P10.7 Implement check monitoring.
P10.8 Implement PR comment ingestion as untrusted data.
```

**Acceptance criteria:**

```text
Can open draft PR from VerifiedPatch.    -> §6
Cannot merge without approval.           -> §3.1, §6
Cannot force-push by default.            -> §3.1, §4
CI failure can create a repair task.     -> §7
```

### 9.1 Testing notes

- **Auth:** App installation-token minting works and tokens expire; fine-grained
  PAT fallback works; classic PAT emits the warning. No token is ever
  model-visible or serialized (cross-check invariants 1, 3).
- **Credential proxy:** in-sandbox git authenticates with no token in `env`;
  force-push and protected-branch pushes are rejected at the proxy; refspec
  smuggling and repo mismatch are rejected; unexpected hosts are denied.
- **Gates:** merge, force-push, branch-protection change, secret write, and
  workflow edit each require the correct gate (ask/deny) and the right
  `Approved<T>` type (policy tests per irreversible class, invariant 14).
- **Untrusted content (P10.8):** the "issue/PR comment says ignore policy / merge
  now / set secret" red-team fixtures pass — none cause a privileged action.
- **Verified-only PR:** an `UnverifiedPatch` cannot open a PR; only a
  `VerifiedPatch` can (cross-check invariant 13).
- **Repair loop:** a failing check spawns a budgeted, retry-bounded repair task
  that pushes a fix to the same branch; CI logs are treated as untrusted.
