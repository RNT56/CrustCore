# docs/chat.md — The Conversational Front Door (`crustcore chat`)

> **Purpose:** specify CrustCore's conversational front door — the NilCore-parity
> `nilcore chat` analog — and the precise way it adds chat ergonomics **without**
> widening the trust boundary.

**Crate:** [`crustcore-chat`](../crates/crustcore-chat) (non-nano, feature-gated).
**Governs / governed by:** invariants **4, 5, 7, 8, 11, 13, 14, 15, 16** in
[`INVARIANTS.md`](../INVARIANTS.md) (15/16 amended v0.4.x).
**Siblings:** [`telegram.md`](./telegram.md) §8, [`persona.md`](./persona.md),
[`model-routing.md`](./model-routing.md), [`advisor-executor.md`](./advisor-executor.md).

---

## 1. What it is

`crustcore chat` is a single conversational entry point: you type a message, it is
**classified** into the kind of work it implies, and it is either **answered**
(converse) or **handed to a kernel task flow** (quick-fix / feature / project /
continue). It runs in the terminal today; a Telegram converse mode is the next
increment. It is a **non-nano capability pack** — the nano binary carries only a stub.

It is built the CrustCore way: a **std-only deterministic decision core** (no network),
with the live model transport being the spawned `crustcore-net` helper (the same
git/codex/claude/net spawn pattern). So the front door embeds no HTTP/TLS.

## 2. The pipeline

```text
raw message
  -> accept(Principal)            only an AUTHORIZED principal becomes a user turn (else dropped)
  -> Inbound::parse               plain | !steer | /cancel | /command
  -> TurnQueue::admit             queue (FIFO, bounded) / steer (cancel model, never a tool) / cancel
  -> Classifier::classify         ChatRoute (model honored-if-parseable, else heuristic; non-authoritative)
  ├─ execution route ─> Turn::StartTask{route, prompt}    (kernel runs it behind policy/sandbox/verifier)
  └─ converse route  ─> model consult -> ConverseRenderer (redact -> bound -> ModelVisibleText) -> Turn::Answer
```

Each stage is a small, deterministic, CI-tested unit (see `crustcore-chat`'s modules:
`route`, `persona`, `converse`, `steer`, `session`, `terminal`).

## 3. The five trust rules (why a chat surface is still safe)

1. **Principal trust at the boundary.** Only an authorized principal (an allowlisted
   Telegram chat id, or the local operator at the terminal) produces a user turn
   (`accept`). Model / tool / file / peer content can never be an authorized principal,
   so it can never masquerade as a steer or command (the NilCore `guard.Wrap` trust line).
2. **The classifier is non-authoritative.** `ChatRoute` is a plain enum — it selects
   *which* kernel flow starts and nothing more. It grants no capability, mints no
   approval, and completes no task. A maliciously-crafted "project" message still hits
   every downstream policy/sandbox/verifier gate.
3. **Converse answers are redacted, never raw.** A model answer reaches the user only
   through `ConverseRenderer`: **redact → bound → re-seal** as `ModelVisibleText` (the
   sole `Redactor`-minted type). The model holds no `send_message` tool; trusted code
   renders its answer. See [`telegram.md` §8.1](./telegram.md).
4. **Persona shapes tone, never authority.** `Persona`/`OperatorSteering` produce only a
   system-prompt `String`, and a fixed `SAFETY_PREAMBLE` always leads and overrides them.
   See [`persona.md`](./persona.md).
5. **Completion stays verifier-owned.** A converse turn never completes a task; an
   execution route hands off to the kernel, where only a `VerifiedPatch` completes work
   and only a human `Approved<T>` authorizes an irreversible action (invariants 13, 14).

## 4. Queue / steer / cancel

- **Plain message** while busy → queued (FIFO, bounded `MAX_QUEUE_DEPTH`) for the next
  safe boundary.
- **`!text` / `/steer`** → cancels the in-flight **model** inference (preserving the
  reasoning so far) and jumps to the front. A steer arriving while a **sandbox tool**
  runs is **buffered** to the next boundary — it never kills a running container/git op
  (NilCore's exact hard rule).
- **`/cancel`** → aborts the active run, drops pending turns, stays in the conversation.

## 5. Channels

| Channel | Status | Notes |
| --- | --- | --- |
| Terminal (`crustcore chat`) | **implemented** | local operator = authorized principal; feature `chat` |
| Telegram (`crustcore-daemon serve`) | **implemented** (loop behind `live`) | the running bot: long-poll → dispatch → reply, with a 🛑 Steer button on answers, approve/deny buttons, and chat-launched verified tasks |

## 5.1 Running the Telegram bot

The runtime loop lives in `crustcore_daemon::runtime` (`dispatch_event` is the pure,
CI-tested core; `run_serve_loop` wires the live transports behind the `live` feature).
Setup — binding is **CLI-side, never a DM-to-pair flow** (an attacker race; §4 of
[`telegram.md`](./telegram.md)):

```bash
# 1. Create a bot with @BotFather, copy the token.
export CRUSTCORE_TELEGRAM_TOKEN=<token>

# 2. Discover your chat id (message the bot; it prints it).
crustcore-daemon serve --pair        # built with --features live

# 3. Bind it + (optionally) enable task execution against a repo.
crustcore-daemon serve --chat-id <id> --dir . --verify 'cargo test'
```

Then in the chat: plain text is answered (with a 🛑 Steer button to interrupt); a task
request ("fix the failing test") runs the **same** worktree → sandbox → verifier flow as
`crustcore run` on a background thread, streaming progress; `!text` steers; `/cancel`
aborts; `/approve <id>`/`/deny <id>` (or the inline buttons) resolve approvals. An empty
allowlist is deny-all (the bot ignores everyone); the bot token rides only in the URL
path and is never logged.

## 6. Reasoning streaming

By default the converse answer is rendered after redaction (a secret cannot straddle a
streamed chunk boundary). A per-session `reveal_reasoning` toggle (owner-authorized,
off by default) streams the model's reasoning text — still through the redactor. Raw,
un-redacted chain-of-thought is never streamed.

## 7. Where it lives, and what nano sees

| Concern | Crate | In nano? |
| --- | --- | --- |
| Classifier, persona, converse boundary, queue/steer, session, terminal REPL | `crustcore-chat` | No |
| `crustcore chat` subcommand | `crustcore` (`chat` feature) | No (nano ships a stub) |
| Kernel events / task flows the chat starts | `crustcore-kernel` | Yes (events only) |

Nano links **none** of the chat stack. `cargo xtask forbidden-deps` confirms the chat
pack links only the std-only protocol — no HTTP/TLS — and the nano size gate is
unaffected.
