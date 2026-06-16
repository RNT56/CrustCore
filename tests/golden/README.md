# tests/golden/

Golden coding tasks (`ROADMAP.md` §19.4) exercised end-to-end through the
verifier-owned completion loop. Each proves that nothing completes without a
`VerifiedPatch` (invariant 13).

- fix a failing unit test
- add a small feature with tests
- repair a CI failure
- update a dependency safely
- documentation-only change
- auth-sensitive change
- DB migration
- greenfield small service
- multi-agent project build
- GitHub issue-to-PR flow

Golden inputs/expected outputs go here; the assertions live in
`crates/crustcore-eval/tests/golden.rs`.
