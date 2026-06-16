<!--
CrustCore PR template. Read CLAUDE.md §6 (workflow) and §7 (parallel/contract files) before opening.
One task = one branch = one PR.
-->

## Summary

<!-- What does this PR do and why? Link the roadmap phase/task id, e.g. P1.3. -->

- Phase / task:
- Closes:

## Owned file globs

<!-- The files/globs this task owns. Must not overlap with another in-flight PR. -->

```
```

## Verification

<!-- Paste the result of `cargo xtask verify` (build, nano build, test, clippy, fmt, size gate, red-team). -->

- [ ] `cargo xtask verify` is green
- [ ] Tests added (or a written reason why not): 
- [ ] Red-team fixture added for any new surface (or n/a)

## Nano size impact

<!-- Required for any change that could affect crustcore-nano. Attach cargo-bloat output. -->

- Nano size delta: <!-- e.g. +3.1kB / -0.4kB / n/a -->
- [ ] Still under the 800kB budget (or budget explicitly updated with justification)
- `cargo bloat` output (if dependency/size-affecting):

```
```

## Dependencies

- [ ] No new dependencies, **or** they satisfy the [admission policy](../CONTRIBUTING.md) (5 rules) and cargo-bloot output is attached
- [ ] No new dependency leaks into `crustcore-nano` / `crustcore-kernel`

## Invariants

<!-- List invariants (see INVARIANTS.md) this PR touches or verifies. Note any contract files changed. -->

- Invariants touched/verified:
- [ ] No [contract file](../CLAUDE.md#73-contract-files--serialized-changes-only) changed, **or** this is a serialized, maintainer-reviewed contract change
- [ ] No invariant weakened

## Changelog

- [ ] `CHANGELOG.md` updated under `[Unreleased]` with an Agent Log entry

## Risks / follow-ups

<!-- Known risks, unresolved items, next human action. -->
