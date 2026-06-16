# tests/

Repo-level homes for the verification corpus. The **runnable** harness that
loads these lives in [`crates/crustcore-eval`](../crates/crustcore-eval) (its
`tests/redteam.rs` and `tests/golden.rs`); these directories hold the fixtures,
golden data, and scenario inputs those tests consume.

| Directory | Purpose | Source |
| --- | --- | --- |
| [`redteam/`](./redteam) | Adversarial scenarios (prompt injection, path/sandbox escape, fake tool results, secret leakage) | `ROADMAP.md` §19.3, [`THREAT_MODEL.md`](../THREAT_MODEL.md) |
| [`golden/`](./golden) | Golden coding tasks run end-to-end through the verifier loop | `ROADMAP.md` §19.4 |
| [`fixtures/`](./fixtures) | Shared inputs (sample repos, malicious paths, mock transcripts) | both |

Rule (`INVARIANTS.md`): a change that adds a new attack surface must add the
matching red-team fixture in the same PR. Scenarios are `#[ignore]`d in the
harness until their phase implements them, so the suite never reports false
green.
