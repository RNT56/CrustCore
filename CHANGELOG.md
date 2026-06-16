# Changelog

All notable changes to CrustCore are recorded here. This file is the
**agent/PR progress log** as well as the release changelog: every agent and
subagent records its work here so the project stays auditable across many
sessions. See [`CLAUDE.md` §8](./CLAUDE.md) for the rules.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html),
extended with a CrustCore **Agent Log** subsection that captures the
agent/PR/role/size/invariant audit trail.

## How to add an entry (read before editing)

- Put in-progress work under **[Unreleased]**, in the correct group
  (`Added` / `Changed` / `Deprecated` / `Removed` / `Fixed` / `Security`).
- Add a matching line to **Agent Log** with: phase/task id (e.g. `P1.3`),
  PR/branch, owning agent/role, nano size impact (Δ kB or `n/a`), and
  invariants touched/verified.
- Update this file in the **same PR** as the change.
- In parallel work, subagents **report** their lines to the supervisor, which
  writes the consolidated entries (avoids merge conflicts). See
  [`CLAUDE.md` §7.2](./CLAUDE.md).
- On release, move `[Unreleased]` items into a dated `[x.y.z] - YYYY-MM-DD`
  section and start a fresh `[Unreleased]`.

---

## [Unreleased]

### Added

- Project documentation foundation: single-source-of-truth `CLAUDE.md`;
  authoritative `ROADMAP.md`; product laws in `INVARIANTS.md`; `THREAT_MODEL.md`,
  `SECURITY.md`, `CONTRIBUTING.md`, and `README.md`.
- Subsystem deep-dive docs under `docs/`: `architecture.md`,
  `nano-size-budget.md`, `security-model.md`, `secrets.md`, `sandbox.md`,
  `policy.md`, `event-log.md`, `receipts.md`, `backend-contract.md`,
  `telegram.md`, `github.md`, `mcp.md`, `model-routing.md`,
  `advisor-executor.md`, `self-improvement.md`, `maintainer-agent.md`.
- This `CHANGELOG.md` with the agent-log convention.
- GitHub issue templates and a documentation map.
- `AGENTS.md` — a thin router to `CLAUDE.md` so agents that look for `AGENTS.md`
  first (e.g. Codex) get the same single source of truth. Added to the contract
  file list.

### Changed

- Reconciled documentation inconsistencies end to end: added `/cancel` as a
  first-class graceful-cancellation command (distinct from `/kill`); clarified
  that `crustcore-nano` is the `crustcore` package built with `--features nano`
  (no separate crate) and added `crustcore` to the workspace/crate maps; added
  `crustcore-mcp`/`crustcore-index` to the §17.1 size-budget table; made the
  nano MCP-lite "no rmcp" constraint explicit; made "no secrets to external
  workers" an explicit `"secrets": "none"` field in the worker input contract;
  unified the contract-file list across `CLAUDE.md` §7.3 and `ROADMAP.md` §20.2
  (now including `CLAUDE.md` and `AGENTS.md`); fixed approximate roadmap
  list-item anchors in `THREAT_MODEL.md` and `docs/sandbox.md`.

### Agent Log

| Date | Phase/Task | Change | PR / Branch | Agent / Role | Nano Δ | Invariants |
| --- | --- | --- | --- | --- | --- | --- |
| 2026-06-16 | Pre-P0 | Author CLAUDE.md single source of truth + full documentation set from approved roadmap | `claude/crustcore-project-docs-q0kr2p` | Maintainer agent (DocumentationWriter) | n/a (docs only) | Documents all 20; none weakened |
| 2026-06-16 | Pre-P0 | Add AGENTS.md router; reconcile flagged doc inconsistencies end to end | `claude/crustcore-docs-reconcile-q0kr2p` (PR) | Maintainer agent (DocumentationWriter) | n/a (docs only) | Clarifies 1–3, 13, 15, 19, 20; none weakened |

---

## Release history

_No releases yet. CrustCore v0.1 targets the definition of done in
[`ROADMAP.md` §22](./ROADMAP.md) and [`CLAUDE.md` §2.2](./CLAUDE.md)._

<!--
Template for a future release section:

## [0.1.0] - YYYY-MM-DD

### Added
### Changed
### Fixed
### Security

### Agent Log
| Date | Phase/Task | Change | PR / Branch | Agent / Role | Nano Δ | Invariants |
| --- | --- | --- | --- | --- | --- | --- |
-->
