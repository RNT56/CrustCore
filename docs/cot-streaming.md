# docs/cot-streaming.md — Token-by-token CoT streaming feasibility (roadmap-v0.6 E.4)

> **Question.** Can CrustCore stream a model's chain-of-thought (CoT) reasoning to
> the operator **token by token** without ever leaking an unredacted secret
> (invariants 2, 3)?
>
> **Answer: feasible, with a bounded buffer-to-boundary redactor and one documented
> constraint.** A working prototype ships as
> [`crustcore_secrets::token_stream::TokenRedactor`]; this note records the design,
> the red-team analysis, the latency bound, and the constraint.

---

## The hazard

Naively forwarding each model token to the user is unsafe: a registered secret can
arrive **split across tokens** (`ghp_` then `SECRET` then `TOKEN`). The batch
[`Redactor`] only catches a secret once it sees the whole value, so per-token
emission would leak the prefix of any streamed secret before the match completes.

## The design — buffer to a redaction boundary, retain the dangling tail

`TokenRedactor` wraps the existing `Redactor` and emits only **fully redacted**
chunks:

1. **Boundary = newline.** A registered secret value never contains a newline, so a
   secret can never straddle one. Whenever the buffer contains a newline, the
   redactor flushes everything up to and including the last newline, redacts that
   chunk, and emits it. Any secret in the chunk is wholly inside it → caught.

2. **Bounded latency via dangling-prefix retention.** A long boundary-free run must
   still emit before the buffer grows without bound. On reaching `max_buffer` with no
   newline, the redactor computes the **longest suffix of the buffer that is a proper
   prefix of some secret** (`Redactor::longest_dangling_prefix`) and retains exactly
   that suffix; it redacts and emits everything before it. This is the key safety
   property: the only thing held back is the *start of a secret that has not finished
   yet*. Everything emitted has no partial-secret tail, so redacting it in isolation
   is complete. The retained dangling prefix is at most `max_needle_len - 1` bytes, so
   the buffer stays bounded.

```text
buffer = "…reasoning… ghp_SEC"   (max_buffer hit, no newline)
          └── emit redact(…)──┘ └ retained: "ghp_SEC" is a prefix of a secret
next token "RETTOKEN\n"  → buffer "ghp_SECRETTOKEN\n" → newline flush → redacted ✓
```

## Red-team analysis (all pass — see the module tests)

| Scenario | Outcome |
| --- | --- |
| Secret split across tokens (same line) | buffered to the newline, redacted as one chunk — **no leak** |
| Secret straddling a forced (no-boundary) emit | retained as the dangling prefix, completed + redacted next chunk — **no leak** |
| Full secret present at a forced emit | dangling length 0 → whole buffer redacted + emitted — **no leak** |
| Non-secret text | passes through unchanged (no false positives — only registered needles match) |
| Trailing partial line at end-of-stream | `flush()` redacts the tail — **no leak** |
| Worst-case boundary-free run | buffer bounded by `max_buffer` + one token; emits incrementally |

**False positives.** The redactor matches only *registered* secret values, so benign
text that merely resembles a secret is never redacted — the tradeoff is that a secret
must be registered with the broker to be scrubbed (the same contract as the batch
redactor; nothing new mid-stream).

**Latency bound.** Output is delayed only until the next newline, or at most until
`max_buffer` bytes accumulate. With `max_buffer` sized above realistic reasoning line
lengths (e.g. 4 KiB), added latency is one line of reasoning — well under the 500 ms
target on any normal stream. A pathological no-newline run emits every `max_buffer`
bytes, so latency is bounded, not unbounded.

## The one constraint

Safety rests on **the boundary character (`\n`) never appearing inside a registered
secret**, and on **every secret being registered with the broker** before the stream
starts. Both already hold for CrustCore's secret types (API keys, tokens, PEM bodies
are single-line opaque values; multi-line PEMs are redacted as their whole armored
block, which contains no bare reasoning newline mid-value). A hypothetical secret that
embedded a newline *and* was streamed across that newline would need a sentence/format
boundary instead — out of scope until such a secret type exists.

## Wiring (the live seam — not built here)

The prototype is the pure, CI-tested core. Going live needs three things, none of
which change the trust boundary:

1. the provider/`crustcore-net` helper must expose an **incremental token stream**
   (most do — SSE `delta` events);
2. the chat/Telegram dispatch loop feeds each token through a `TokenRedactor` and
   forwards the emitted chunks;
3. it is gated behind the existing **`reveal_reasoning` opt-in** (`docs/chat.md`) —
   off by default; the operator turns it on knowing reasoning is shown (redacted).

## Conclusion

**Token-level CoT streaming is compatible with the redaction boundary** using
boundary-buffered redaction with dangling-prefix retention. The prototype
(`TokenRedactor`) demonstrates leak-free streaming on the red-team scenarios with a
bounded, sub-500 ms latency profile. Recommend shipping it behind `reveal_reasoning`
once the net helper exposes a token stream; no invariant relaxation is required.
