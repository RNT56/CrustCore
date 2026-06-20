# docs/secrets.md — Secret Broker & Typed Secrets Deep Dive

> **Purpose:** specify the secret broker, the typed secret model
> (`SecretHandle` / `SecretMaterial` and their *forbidden* trait impls), the
> secret flow and preferred injection order, the `ApprovedSecretView` one-shot
> pattern, and the testing that proves a secret can never reach a model.

> This is a [contract file](../CLAUDE.md#73-contract-files--serialized-changes-only):
> changes are serialized and require maintainer approval. Source of truth:
> [`ROADMAP.md` §8.1`](../ROADMAP.md) (secret types), [`§9.4`](../ROADMAP.md)
> (secret flow / injection order), [`§9.5`](../ROADMAP.md) (redaction/taint),
> [`§18 Phase 8`](../ROADMAP.md) (tasks/acceptance). Governs invariants **1–3**.

> Siblings: [`docs/security-model.md`](./security-model.md) (taint/redaction
> boundary) · [`docs/github.md`](./github.md) (credential proxy in practice) ·
> [`docs/sandbox.md`](./sandbox.md) (env sanitation) ·
> [`SECURITY.md`](../SECURITY.md) · [`INVARIANTS.md`](../INVARIANTS.md).

---

## 1. The guarantee

> A raw credential **never** exists in model-visible space, in a log, in an
> artifact, in a Telegram message, or in a GitHub comment. The model sees only a
> `SecretHandle` (an id and a label) and an availability state. Raw bytes live in
> `SecretMaterial`, which the type system refuses to print, serialize, clone, or
> convert to model-visible text.

This is invariants **1** (no raw credentials to the LLM), **2** (no unredacted
secret-bearing logs), and **3** (secret material is not Debug/Serialize/Clone/
model-visible), made structural rather than disciplinary.

---

## 2. Typed secrets

### 2.1 The two types

From [`ROADMAP.md` §8.1`](../ROADMAP.md):

```rust
/// Model-visible reference to a secret. Carries NO bytes.
pub struct SecretHandle {
    pub id: SecretId,        // compact u32 id (ROADMAP §7.1)
    pub label: BoundedText,  // e.g. "github-app-token"; safe to show
}

/// The actual secret bytes. Never model-visible.
pub struct SecretMaterial {
    bytes: Zeroizing<Vec<u8>>, // zeroized on drop
}
```

`SecretHandle` is the *only* secret-related thing that may appear in model
prompts, tool args, logs, or config. It is a name, not a value. `SecretMaterial`
is the value and lives only inside the trusted secret broker and inside one-shot
views handed to approved tools.

### 2.2 Forbidden impls (the heart of the guarantee)

`SecretMaterial` **deliberately does not implement** the traits that cause
accidental leaks ([`ROADMAP.md` §8.1`](../ROADMAP.md), invariant 3):

```text
SecretMaterial is NOT Debug.       // `{:?}` on it does not compile
SecretMaterial is NOT Serialize.   // it cannot be written to JSON/log/event
SecretMaterial is NOT Clone.       // it cannot be silently duplicated
SecretMaterial CANNOT become ModelVisibleText.  // no such conversion exists
SecretMaterial can ONLY be exposed through ApprovedSecretView. // §5
```

Rationale per impl:

- **No `Debug`:** `{:?}` and derive-`Debug` on a containing struct are the single
  most common accidental leak. Removing the impl turns a leak into a compile error.
- **No `Serialize`:** the event log, JSONL export, artifacts, and config all
  serialize. If `SecretMaterial` cannot serialize, none of those paths can carry it
  (invariant 2). Containing types must therefore hold a `SecretHandle`, not bytes.
- **No `Clone`:** prevents fan-out of the raw bytes into multiple owners that each
  might leak; the broker keeps a single authoritative copy.
- **No `ModelVisibleText` conversion:** the model boundary is sealed by absence —
  there is no function with signature `fn(SecretMaterial) -> ModelVisibleText`, so
  invariant 1 holds by construction.

> **Edge case — `Display`:** `SecretMaterial` must also not implement `Display`
> (and any `to_string()` path), for the same reason as `Debug`. Treat `Display`
> as forbidden alongside the list above.

---

## 3. The secret broker

The broker is a **trusted** component ([`SECURITY.md` §2.1`](../SECURITY.md)). It
owns secret storage and is the only thing that materializes `SecretMaterial`.

### 3.1 Storage backends

Outside nano (Phase 8), the broker stores secrets in, in order of preference:

```text
1. Native OS keychain (macOS Keychain, Windows Credential Manager, libsecret/
   Secret Service on Linux) — preferred; the OS guards the bytes.
2. Encrypted-file vault fallback — when no native keychain is available; bytes are
   encrypted at rest with a key derived from an OS-protected secret / passphrase.
```

**Nano stores only `secret://` handles** — never secret bytes. The nano binary
has no keychain or vault code; it references secrets by handle and delegates
materialization to the broker (which lives outside nano). This keeps nano small
(invariants 19, 20) and keeps the secret-bearing code out of the tiny trusted
kernel surface.

### 3.2 What config and the model see

```text
Config:        secret://github-app-token   (a handle URI; no bytes)
Model context: SecretHandle { id, label } + availability state ("present"/"absent")
Broker only:   SecretMaterial { bytes: Zeroizing<...> }
```

---

## 4. Secret flow

End-to-end flow ([`ROADMAP.md` §9.4`](../ROADMAP.md)):

```text
1. User enters the secret through a trusted local prompt or an approved OS
   mechanism (never pasted into a model conversation).
2. CrustCore stores it in the OS keychain or the encrypted vault.
3. Config stores only secret:// handles.
4. The model sees only handles and availability states.
5. An approved tool receives a one-shot secret view or a credential proxy.
6. The tool's result is redacted before it becomes model-visible.
```

At no step do raw bytes pass through model-visible space, the event log, or an
artifact. Step 1 is deliberately a *trusted local* path so the secret never
transits the untrusted model channel.

---

## 5. The `ApprovedSecretView` one-shot pattern

A tool that genuinely needs a secret (e.g. to authenticate a request) does not get
`SecretMaterial`. It gets a **one-shot, scoped, expiring view**, minted by the
broker only after policy/approval:

```rust
/// Single-use exposure of a secret to one approved operation.
pub struct ApprovedSecretView<'b> {
    handle: SecretHandle,
    // borrowed access to the broker-held bytes; cannot outlive the broker,
    // cannot be cloned, cannot be stored, consumed on use.
    broker: &'b SecretBroker,
    approval_id: ApprovalId,
    expires_at: Timestamp,
}
```

Properties:

```text
- One-shot: consumed by the single operation it authorizes; not reusable.
- Scoped: bound to a specific operation/capability and an approval_id.
- Expiring: has an expiry; a stale view is rejected.
- Non-escaping: the borrow ('b) prevents storing the bytes past the call;
  no Clone/Serialize/Debug, same as SecretMaterial.
- Redacting: anything the operation emits passes through redaction (§7).
```

This is the only sanctioned way bytes leave the broker, and even then they go to a
*trusted-process operation*, not to the model. Compare with the credential-proxy
pattern (§6), which avoids handing bytes to the consumer at all.

---

## 6. Credential proxy pattern

The preferred mechanism for GitHub and model access is to **not give the secret to
the consumer at all** — a trusted proxy injects it at the last moment. For git in
the sandbox ([`ROADMAP.md` §15.3`](../ROADMAP.md), depth in
[`docs/github.md`](./github.md)):

```text
git in sandbox
  -> local credential helper proxy
  -> validates repo / branch / refspec
  -> injects a short-lived installation token
  -> GitHub
```

No raw GitHub token sits in the sandbox env by default. The same shape applies to
model providers: the `crustcore-net` sidecar injects the provider key into the
outbound request header; the key never enters nano, the sandbox, or model context.

---

## 7. Redaction & taint

Secret-bearing data is **tainted**; tainted data cannot enter model prompts,
model-visible tool results, normal logs, Telegram, GitHub comments, unredacted
artifacts, or panic/debug output ([`ROADMAP.md` §9.5`](../ROADMAP.md)). The taint
model and the boundary list are specified in
[`docs/security-model.md` §4`](./security-model.md). Key points for the broker:

- Outbound text crossing a model/Telegram/GitHub boundary passes through a
  redacting wrapper; there is no constructor turning `SecretMaterial` into
  model-visible text (so leakage is unrepresentable, not merely filtered).
- Tool stdout/stderr and errors are redacted before becoming a model-visible
  result (with a receipt; [`docs/receipts.md`](./receipts.md)).
- The event log and JSONL export carry handles and redaction state, never bytes
  ([`docs/event-log.md`](./event-log.md)).

---

## 8. Preferred injection order (with rationale)

When a secret unavoidably must reach a process, use the **highest-numbered-safe**
mechanism available, in this order ([`ROADMAP.md` §9.4`](../ROADMAP.md)):

| # | Mechanism | Why it ranks here |
| --- | --- | --- |
| 1 | **Local credential proxy** | The secret never leaves the trusted process; the consumer gets an authenticated channel, not bytes. Best containment. |
| 2 | **Git credential-helper proxy** | Same idea specialized for git; validates repo/branch/refspec and injects a short-lived token (no token in env). |
| 3 | **Per-request header injection by a trusted process** | The sidecar adds the secret to a single outbound request; the secret stays in the trusted process, scoped to one request. |
| 4 | **Short-lived token minted by the broker** | If a token must be handed over, a short TTL bounds the blast radius of a leak. |
| 5 | **File descriptor / protected temp file with tight lifetime** | When a child needs a file/fd, restrict permissions and lifetime; avoids the env entirely. |
| 6 | **Environment variable — only when unavoidable** | Env is the leakiest path (inherited by children, shows in `/proc`, easy to dump). Last resort, and env is sanitized/stripped by default (see [`docs/sandbox.md` §env sanitation`](./sandbox.md)). |

The ordering encodes a single principle: **prefer to never hand over the bytes;
if you must, minimize who holds them and for how long.**

---

## 9. Phase 8 tasks & acceptance

From [`ROADMAP.md` §18 Phase 8`](../ROADMAP.md):

```text
P8.1 Define SecretHandle/SecretMaterial types.
P8.2 Implement native keychain backends.
P8.3 Implement encrypted-file vault fallback.
P8.4 Implement secret request flow.
P8.5 Implement redactor/taint tests.
P8.6 Implement credential proxy pattern for GitHub/model helpers.
```

Acceptance:

```text
- SecretMaterial cannot be serialized / debugged / cloned.
- The LLM sees only handles.
- Tests fail on attempted secret leakage.
```

**Status (P8-store — encrypted-file vault implemented).** The trust types
(`SecretMaterial`/`SecretHandle`), the broker, the redactor/taint boundary, and the
credential proxy are nano-linked and std-only. The **encrypted-file vault**
`SecretStore` backend ([`crustcore_secrets::store`]) is implemented behind the
**`vault-file`** cargo feature (P8.3): `seal_vault(path, passphrase, entries)`
encrypts secrets to a single file — `magic | version | salt | nonce |
AES-256-GCM(plaintext)`, with a **scrypt** (N=2¹⁵) passphrase-derived key — and
`open_vault(path, passphrase)` decrypts them back into an [`InMemoryStore`] the broker
reads. It **fails closed**: a wrong passphrase or any tampered byte fails AEAD
decryption (`VaultError::Decrypt`) with no partial/plaintext leak; the on-disk bytes
never contain a secret value; the decrypted blob and derived key are zeroed after use;
the decoded length-prefixed contents are bounded and parsed panic-free. **Nano
isolation (invariants 19/20):** the module and its crypto deps (`aes-gcm`, `scrypt`,
`getrandom`) are gated behind `vault-file`, never enabled in the nano build, and the
`xtask forbidden-deps` gate asserts no crypto crate enters the nano graph; the
`xtask` verify gate clippy- and test-checks the feature explicitly. **What remains**
(`TODO(P8-store)`): the **native OS keychain** backends (macOS Keychain / Linux Secret
Service / Windows Credential Manager) — also feature-gated, never in nano — which
load secrets from the OS store into the same in-memory `SecretStore` shape.

---

## 10. Testing requirements

The guarantee is only real if the *absence* of dangerous impls is tested.

- **Compile-fail tests (trybuild-style):** assert that programs which try to
  `Debug`, `Display`, `Serialize`, or `Clone` a `SecretMaterial`, or convert it to
  model-visible text, **fail to compile** (invariant 3). These are the gold
  standard — they prove the leak path does not exist in the type system, not just
  that a runtime check caught it.
- **Redaction / taint runtime tests:** the secret-leak matrix S1–S10 in
  [`docs/security-model.md` §5`](./security-model.md) — a sentinel secret routed
  toward each forbidden boundary (stdout, stderr, env dump, panic, tool error,
  GitHub error, Telegram draft, external-worker transcript, MCP result) must come
  out absent / redacted.
- **One-shot/expiry tests:** an `ApprovedSecretView` cannot be reused after
  consumption, cannot outlive its borrow, and is rejected after expiry.
- **Handle-only event-log test:** assert serialized events/artifacts contain
  handles and redaction state, never bytes.
- **New-surface rule:** any new outbound surface that could carry a secret adds its
  own leak-matrix row and fixture in the same PR
  ([`INVARIANTS.md` § Red-team requirement`](../INVARIANTS.md#red-team-requirement)).
