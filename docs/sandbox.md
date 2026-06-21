# docs/sandbox.md — Sandboxing Deep Dive

> **Purpose:** specify CrustCore's execution sandboxing — the execution tiers,
> per-OS backend order, network posture, environment sanitation, the
> `CommandSpec`/`CommandResult` contract with bounded output and process-tree
> kill, the `SandboxExecCap` requirement, and the red-team tests that prove
> containment.

> This is a [contract file](../CLAUDE.md#73-contract-files--serialized-changes-only):
> changes are serialized and require maintainer approval. Source of truth:
> [`ROADMAP.md` §10](../ROADMAP.md) (sandbox model), [`§1.2 NullClaw lesson 5`](../ROADMAP.md)
> (path-env lesson), [`§18 Phase 4`](../ROADMAP.md) (tasks/acceptance).
> Governs invariant **9** (and supports 2, 7, 8, 14).

> Siblings: [`docs/security-model.md`](./security-model.md) (taint/redaction) ·
> [`docs/secrets.md`](./secrets.md) (no inherited secrets) ·
> [`docs/policy.md`](./policy.md) (capability/approval tokens) ·
> [`THREAT_MODEL.md`](../THREAT_MODEL.md) · [`INVARIANTS.md`](../INVARIANTS.md).

---

## 1. The rule

> **Every execution-capable operation runs in an explicit sandbox profile.** There
> is no host-shell escape hatch. `run_command` requires a `SandboxExecCap` bound to
> a profile; no capability, no execution (invariant 9).

```rust
fn run_command(cap: &SandboxExecCap, spec: CommandSpec) -> Result<CommandResult>;
```

The `SandboxExecCap` is a capability token issued by the policy engine
([`docs/policy.md`](./policy.md)); it names the `SandboxProfileRef` and a scope.
Because the only execution entry point takes this token, there is no way to "just
run a shell" — execution is always profiled and always governed (invariant 8).

```rust
pub struct SandboxExecCap { profile: SandboxProfileRef, scope: ScopeId }
```

---

## 2. Execution tiers

From [`ROADMAP.md` §10.1`](../ROADMAP.md). The tier sets the containment strength;
risk classification chooses the tier.

| Tier | Name | Examples | Containment |
| --- | --- | --- | --- |
| **0** | No execution | planning, review, summarization, policy evaluation | none needed — nothing runs |
| **1** | Structured host-side | `read_file`, `search`, `apply_patch`, `write_file`, `git status`, `git diff` | typed confined paths; **no arbitrary execution** |
| **2** | Sandboxed execution | tests, builds, shell, package managers, Codex CLI, Claude Code CLI, MCP code-mode glue | OS sandbox profile + deny-all egress + sanitized env |
| **3** | Hostile execution | untrusted generated code, unknown repos, risky install scripts | microVM / container / hard sandbox, network denied |

Notes:

- **Tier 1 is not "trusted execution"** — it executes *nothing arbitrary*. It is
  structured host-side operations that require typed confined paths
  (`ConfinedReadPath`/`ConfinedWritePath`, [`ROADMAP.md` §8.2`](../ROADMAP.md)).
  Git wrappers use fixed subcommands and must not execute hooks or read
  model-written config (Phase 3 acceptance).
- **Tier 2 is the default for any arbitrary command.** Tests/builds/package
  managers are arbitrary code and run here.
- **Tier 3 is for hostile or unknown code** — escalate to a microVM/container with
  network denied. Unknown repos and risky install scripts belong here.

---

## 3. Backend order per OS

The launcher selects the strongest available backend for the OS
([`ROADMAP.md` §10.2`](../ROADMAP.md)). v0.1 ships the Linux backend v1
(Phase 4); macOS/Windows and Firecracker come later
([`ROADMAP.md` §2.3, §21`](../ROADMAP.md)).

**Linux:**

```text
1. Landlock / namespaces where available   (in-process LSM + user namespaces)
2. bubblewrap                              (unprivileged container helper)
3. Firecracker                             (microVM for hostile / Tier 3 tasks)
4. container CLI fallback                  (docker/podman style)
```

**macOS:**

```text
1. seatbelt sandbox profile (sandbox-exec style profile)
2. network proxy            (egress mediation)
3. container fallback
```

**Windows:**

```text
1. WSL2 / container initially
2. AppContainer / job objects later
```

The launcher records which backend was selected (for the event log /
`crustcore inspect`). If no acceptable backend is available for the required tier,
execution is **refused** — there is no "run unsandboxed" degrade path.

### 3.1 macOS backend v1: `sandbox-exec` (Seatbelt)

The macOS Tier-2 backend (`SeatbeltBackend`, compiled only under
`#[cfg(target_os = "macos")]`, std-only) wraps the command in
`/usr/bin/sandbox-exec` under a generated SBPL profile, matching the bubblewrap
backend's security posture: **deny-all network egress** and **writes confined to
the worktree**. It is detected at runtime (probing `/usr/bin/sandbox-exec`, which
ships on every macOS); a host without it **refuses** rather than degrading to
unsandboxed execution. Like bubblewrap, allowlisted egress is not granted here in
v1 — an `Allowlist` profile is refused until the trusted egress proxy exists.

The generated profile uses an "allow-all, then deny the two load-bearing classes,
then re-allow the writable surface" recipe (later SBPL rules override earlier
ones), so a toolchain keeps its read access while the two guarantees are enforced:

```scheme
(version 1)
(allow default)
(deny network*)            ; deny-all egress — mirrors bubblewrap --unshare-all
(deny file-write*)         ; then re-allow only the writable surface below
(allow file-write*
    (subpath "<CANONICAL_WORKTREE>")
    (subpath "<CANONICAL_TMPDIR>")
    (subpath "/private/tmp")
    (subpath "/private/var/tmp")
    (literal "/dev/null") (literal "/dev/zero")
    (literal "/dev/stdout") (literal "/dev/stderr") (literal "/dev/tty")
    (literal "/dev/dtracehelper") (literal "/dev/urandom"))
```

- `(deny network*)` is the deny-all-egress guarantee; `(deny file-write*)`
  followed by re-allowing only the worktree + temp dirs is the write-confinement
  guarantee. Both are verified by live confinement tests on macOS.
- **Paths are canonicalized.** macOS symlinks `/tmp`→`/private/tmp`,
  `/var`→`/private/var`, and worktrees under `/var/folders/...`; SBPL `subpath`
  matches the kernel's **resolved** path. The backend therefore
  `canonicalize`s the worktree and the (sanitized) `TMPDIR` before embedding them
  (falling back to `/private/tmp` when `TMPDIR` is unset). If a path cannot be
  canonicalized the backend **fails closed** (`SandboxError::Setup`) rather than
  embedding an unresolved path that would either fail open or block legitimate
  worktree writes. Embedded paths are escaped (`"` and `\`) to prevent breaking
  out of the SBPL string literal.
- The child runs with `cwd` set to the worktree and the env sanitized at the
  launch boundary (§5), exactly as the bubblewrap backend does.

Firecracker (Tier 3) and the network-proxy / container fallbacks remain future
work; a Tier-3 (hostile) task on macOS is still refused without a microVM.

---

## 4. Network posture

Default network policy ([`ROADMAP.md` §10.3`](../ROADMAP.md)):

```text
deny all egress                                  (default)
allowlist per task / profile                     (explicit opt-in only)
GitHub and model access through trusted sidecar/proxy
package install requires approval
new host requires approval
```

This implements NullClaw's allowlist discipline ([`ROADMAP.md` §1.2`](../ROADMAP.md)):
an empty allowlist means **deny all**; `*` is an explicit opt-in, never a default.
Secrets never enter the sandbox to reach the network — GitHub/model traffic goes
through the credential proxy / sidecar ([`docs/secrets.md`](./secrets.md),
[`docs/github.md`](./github.md)), so a sandboxed process cannot exfiltrate a token
even if it reaches an allowed host.

**Network proxy records** (per connection), for audit and the event log:

```text
task id
job id
process id
domain
port
protocol
bytes in / out
approval id (if applicable)
```

Adding a host or installing a package is an approval-gated action (invariant 14):
the proxy ties the connection to the `approval_id` that authorized it.

---

## 5. Environment sanitation

Sandbox env rules ([`ROADMAP.md` §10.4`](../ROADMAP.md)):

```text
minimal env by default
no inherited secrets
no inherited SSH agent unless explicit
no inherited cloud credentials
no arbitrary PATH
validate path-list env vars component-by-component
strip dangerous variables by default
```

### 5.1 Stripped-by-default variables

Stripped before a sandboxed process starts (non-exhaustive; the implementation
strips this class):

```text
LD_PRELOAD        DYLD_*            GIT_CONFIG_*
SSH_AUTH_SOCK     AWS_*             GCP_*
AZURE_*           NPM_TOKEN         (and similar credential/loader vars)
```

`LD_PRELOAD`/`DYLD_*` are loader-injection vectors (a path to attacker code);
`GIT_CONFIG_*` can redirect git to attacker config/hooks; `SSH_AUTH_SOCK` would
forward the agent's SSH identity into untrusted execution; the cloud-credential
vars (`AWS_*`/`GCP_*`/`AZURE_*`/`NPM_TOKEN`) are exactly the secrets we refuse to
inherit (invariant 2, [`docs/secrets.md`](./secrets.md)).

### 5.2 Path-list env var validation (the NullClaw lesson)

[`ROADMAP.md` §1.2 (NullClaw lesson 5)](../ROADMAP.md) records the lesson:
**path-list env vars must be validated component-by-component before crossing
into a sandbox.**
This applies to:

```text
PATH   LD_LIBRARY_PATH   DYLD_*   PYTHONPATH   NODE_PATH   GIT_* paths   (etc.)
```

The validator splits the variable on the OS path separator and checks **each
component**:

```text
- reject empty components (an empty PATH entry means "current directory")
- reject relative components (must be absolute, normalized)
- reject components that escape allowed roots / point at untrusted writable dirs
- reject symlink-escaping components
- reject components containing null bytes
- a single bad component fails the whole variable (no silent drop-and-continue)
```

Validating the *whole string* is insufficient — a single injected component (e.g.
a writable worktree dir prepended to `PATH`, or a malicious dir in
`LD_LIBRARY_PATH`) is a code-execution vector. Component-wise validation is what
blocks the `LD_PRELOAD`/path-env escape red-team scenario (R11 in
[`THREAT_MODEL.md` §6`](../THREAT_MODEL.md)).

---

## 6. `CommandSpec` / `CommandResult`

The execution contract (Phase 4, [`ROADMAP.md` §18`](../ROADMAP.md)). A
`CommandSpec` is a fully-specified, non-shell-interpreted command; a
`CommandResult` is bounded and captured.

```rust
fn run_command(cap: &SandboxExecCap, spec: CommandSpec) -> Result<CommandResult>;
```

`CommandSpec` carries (conceptually):

```text
program + argv          (explicit; not a shell string to interpret)
working directory       (a confined path inside the worktree)
sanitized environment   (built from scratch; see §5)
sandbox profile ref     (matches the SandboxExecCap; sets tier/network/fs)
resource limits         (wall time, CPU, memory, disk, output size)
network policy           (deny-all by default; allowlist if profile permits)
```

`CommandResult` carries:

```text
exit status / signal
bounded stdout          (truncated at the output-size limit, marked truncated)
bounded stderr          (same)
duration
whether it was killed / timed out
resource usage summary
```

### 6.1 Bounded output

Stdout/stderr capture is **bounded** ([`CLAUDE.md` §6.5`](../CLAUDE.md): "bounded
everything"): once the configured byte limit is reached, capture stops and the
result is marked truncated. This prevents a hostile command from flooding model
context or exhausting memory (supports invariant 11, budgets). Output is redacted
before it becomes a model-visible tool result ([`docs/security-model.md`](./security-model.md)).

### 6.2 Timeout, cancel, and process-tree kill

```text
- Each command has a wall-time timeout; on expiry it is killed.
- A command is cancellable (tied to the job's cancellation token / process handle,
  invariant 12).
- Kill terminates the WHOLE process tree, not just the direct child:
    Linux: run the child in its own process group / pid namespace and signal the
           group (SIGTERM then SIGKILL) so orphaned grandchildren cannot survive.
  A lingering grandchild could keep network connections or hold the worktree;
  killing the tree closes that gap.
```

---

## 7. Red-team tests

Sandbox-specific red-team fixtures (Phase 4 acceptance + [`ROADMAP.md` §19.3`](../ROADMAP.md);
mapped in [`THREAT_MODEL.md` §6`](../THREAT_MODEL.md)). Each must pass before v0.1:

| Scenario | Asserts |
| --- | --- |
| Dependency postinstall attempts network (R5) | deny-all egress blocks it; install needed approval |
| External worker / code writes outside worktree (R6) | confined paths reject; outside-root writes fail |
| Symlink escape path (R10) | path resolver rejects symlink escape; no-follow writes |
| `LD_PRELOAD` / path-env escape (R11) | env sanitizer strips loader vars; path-list components validated |
| Secret/env inheritance | secrets and SSH/cloud creds are not inherited (§5) |
| Output flood | bounded capture truncates; no unbounded read into context |
| Runaway command | timeout fires; whole process tree is killed |

Phase 4 acceptance ([`ROADMAP.md` §18`](../ROADMAP.md)):

```text
- Commands run with bounded output and timeout.
- Secrets/env are not inherited by default.
- Network is denied by default in supported sandbox.
- Path-list env escapes are blocked.
```

---

## 8. Phase 4 tasks

```text
P4.1 Implement CommandSpec and CommandResult.
P4.2 Implement bounded stdout/stderr capture.
P4.3 Implement timeout/cancel/kill process tree.
P4.4 Implement environment sanitizer.
P4.5 Implement path-env-var validator.
P4.6 Implement Linux sandbox backend v1.
P4.7 Add sandbox red-team tests.
```

> **Scope note.** v0.1 ships **Linux sandbox backend v1**; Firecracker (Tier 3
> microVM) and the Windows native sandbox are explicitly out of scope for v0.1
> ([`ROADMAP.md` §21`](../ROADMAP.md)). Until those land, hostile (Tier 3) tasks on
> unsupported platforms must be refused rather than downgraded to a weaker tier —
> consistent with the "no run-unsandboxed degrade path" rule in §3.

---

## 9. How this maps to invariants

```text
Explicit sandbox profile for all execution ......... invariant 9 (primary)
No inherited secrets / redacted output ............. invariants 2, (1)
Untrusted execution output is data ................. invariant 7
Execution gated by capability token ................ invariant 8
Network/install/new-host require approval .......... invariant 14
Bounded output / timeouts (budgets) ................ invariant 11
Cancellation / kill tied to job lifecycle .......... invariant 12
```
