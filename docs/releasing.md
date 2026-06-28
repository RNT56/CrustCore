# docs/releasing.md — Release & Operations

> **Purpose:** specify how a CrustCore release is built, checksummed, signed,
> installed, run as a service, backed up, and rolled back — the Phase-16
> "release hardening" contract (`ROADMAP.md` §18 Phase 16).

**Source of truth:** [`ROADMAP.md` §18 Phase 16](../ROADMAP.md) (tasks/acceptance),
[`ROADMAP.md` §22](../ROADMAP.md) (v0.1 definition of done),
[`docs/nano-size-budget.md`](./nano-size-budget.md) (the size gate).
**Governed by:** invariants **13/14** (only verified, approved artifacts ship),
**16** (the CLI is setup/admin/emergency), **18** (improvement via PRs),
**19** (nano stays under budget).

Phase-16 acceptance:

```text
Install/doctor works on target platforms.
Releases are signed and reproducible enough for audit.
Nano remains under size budget.
```

---

## 1. What ships

The flagship artifact is **`crustcore-nano`** — the `crustcore` package built with
`--no-default-features --features nano` under the `nano` profile. The capability
packs (`net`, `daemon`, `mcp`, `index`, `full`) are separate, larger builds and are
**never** the size-claim binary (`CLAUDE.md` §3).

A release is the nano binary **plus its checksum and a manifest**, produced by the
offline release runner:

```sh
cargo xtask release
```

This (P16.1/P16.2):

1. builds the nano binary under the `nano` profile,
2. enforces the **size budget** (fails if over 800 KiB — invariant 19),
3. writes `target/nano/SHA256SUMS` (`<sha256>  crustcore`, `sha256sum -c`-compatible),
4. writes `target/nano/release-manifest.txt` (version, artifact, profile, size,
   budget %, SHA-256).

The checksum is computed with CrustCore's own vendored SHA-256 (no external crypto
dependency) and is byte-compatible with system `sha256sum`/`shasum -a 256 -c`.

---

## 2. Signing (P16.1)

Signing is a **keyed, irreversible** step performed out-of-band — never wired into
the offline `xtask` runner and never given a key by an agent (invariants 1–3, 14).
A maintainer signs the **`SHA256SUMS`** file (so one signature covers every listed
artifact):

```sh
# minisign (recommended: small, no PKI)
minisign -Sm target/nano/SHA256SUMS

# or cosign (keyless/OIDC or a KMS key)
cosign sign-blob --yes target/nano/SHA256SUMS > SHA256SUMS.sig
```

Verification by a downstream user:

```sh
minisign -Vm SHA256SUMS -P <pubkey>      # signature over the checksum list
sha256sum -c SHA256SUMS                   # bytes match the signed digest
```

**"Reproducible enough for audit"** means: the manifest records exactly what was
built (package, profile, feature set) and its SHA-256, and the build is
dependency-pinned by `Cargo.lock`, so an auditor can rebuild and compare the digest.
The deterministic-build pieces (`--remap-path-prefix` + `SOURCE_DATE_EPOCH` + a pinned
toolchain) are now implemented and **same-machine verified** — see §9; the checksum +
manifest + lockfile remain the audit floor.

> The **GitHub Actions release workflow** ([`.github/workflows/release.yml`](../.github/workflows/release.yml))
> is an *irreversible, CI-credentialed* change (`CLAUDE.md` §6.3), so it is added by a
> maintainer through a serialized, approved PR — not self-merged by the build agent. On a
> `vX.Y.Z` tag it builds the three user-facing artifacts on **Linux x86_64 + macOS arm64** —
> `crustcore` (the trusted verifier; on Linux via `cargo xtask release`, so the reproducible
> build + `release-manifest.txt` are produced), `crustcore-net` (the model helper), and
> `crustcore-full` (the single-binary all-in-one) — emits a combined `SHA256SUMS`, and
> assembles a **draft** GitHub release. It **never signs or publishes**: the maintainer
> reviews the draft, signs `SHA256SUMS` out-of-band (the flow below), and publishes manually.
> No signing key or publish credential ever touches CI. A `workflow_dispatch` run is a
> build-only dry-run (artifacts, no release).

---

## 3. Readiness: `crustcore doctor` (P16.3)

Before running tasks, check the host is ready:

```sh
crustcore doctor
```

It reports (and exits non-zero if anything **FAIL**s):

- **git** — required to create/manage disposable worktrees.
- **sandbox** — a bubblewrap backend must be present; without one, execution-capable
  tasks are **refused** (invariant 9: there is no unsandboxed degrade path).
- **state-dir** — a writable scratch directory (`$CRUSTCORE_STATE`, else the system
  temp dir) for worktrees and logs.

`doctor` is an admin/setup command (invariant 16), not a runtime channel.

---

## 4. Install (P16.3)

[`scripts/install.sh`](../scripts/install.sh) is a POSIX installer that verifies the
checksum (and, if a `.sig` and pubkey are provided, the signature) before copying the
binary into a prefix:

```sh
# verify + install to ~/.local/bin (default PREFIX)
scripts/install.sh target/nano/crustcore

# custom prefix
PREFIX=/usr/local scripts/install.sh target/nano/crustcore
```

The script refuses to install a binary whose SHA-256 does not match `SHA256SUMS`
next to it. After install, run `crustcore doctor`.

---

## 5. Run as a service (P16.4)

CrustCore's *runtime* is the daemon (`crustcore-daemon`, a capability pack), not the
nano binary. Reference service units:

**systemd** (Linux) — `~/.config/systemd/user/crustcore.service`:

```ini
[Unit]
Description=CrustCore daemon
After=network.target

[Service]
Type=simple
ExecStart=%h/.local/bin/crustcore-daemon
Environment=CRUSTCORE_STATE=%h/.local/state/crustcore
Restart=on-failure
# Credentials come from the broker/credential proxy, never the unit file
# (invariants 1–3). Do NOT put tokens in Environment= here.

[Install]
WantedBy=default.target
```

```sh
systemctl --user daemon-reload && systemctl --user enable --now crustcore
```

**launchd** (macOS) — `~/Library/LaunchAgents/dev.crustcore.daemon.plist`: a
`ProgramArguments` pointing at `crustcore-daemon`, `RunAtLoad` true, `KeepAlive` true,
and `CRUSTCORE_STATE` in `EnvironmentVariables`. Same rule: **no secrets in the
plist** — the broker injects credentials at use.

---

## 6. Backup & restore (P16.5)

CrustCore's durable state is the **append-only event log** and the state directory
(`$CRUSTCORE_STATE`). Because the event log is **hash-chained** (`docs/event-log.md`),
a backup is trivially integrity-checkable:

```sh
# Back up (the log is append-only; a copy is a consistent snapshot)
tar czf crustcore-state-$(date +%Y%m%d).tgz -C "$CRUSTCORE_STATE" .

# Restore, then verify the chain is intact before trusting it
tar xzf crustcore-state-YYYYMMDD.tgz -C "$CRUSTCORE_STATE"
crustcore inspect "$CRUSTCORE_STATE/events.log"   # must report INTACT
```

Never restore a log that fails `inspect` — a broken chain means tamper or corruption
(`docs/event-log.md`). The event-log **frame format is versioned** (`FRAME_VERSION`);
a newer-versioned log is *rejected*, never silently misread, so a downgrade cannot
misinterpret a forward-migrated log (P16.6).

---

## 7. Rollback

Releases are plain, checksummed binaries, so rollback is "install the previous
artifact":

```sh
sha256sum -c SHA256SUMS         # verify the older artifact first
scripts/install.sh ./crustcore-vPREV
```

State is forward/backward safe at the format-version boundary (§6): an older binary
refuses a log written by a newer format rather than corrupting it. Migrations that
bump `FRAME_VERSION` ship with explicit reader/writer handling and a regression test
(see `frame_format_version_is_stable_and_stamped`).

---

## 8. Pre-release checklist

```text
[ ] cargo xtask verify            # fmt, clippy, test, forbidden-deps, size gate — green
[ ] cargo xtask release           # nano under budget; SHA256SUMS + manifest written
[ ] red-team + golden suites pass (incl. ignored-where-deferred, honest)
[ ] CHANGELOG [Unreleased] moved to a dated, versioned section
[ ] SHA256SUMS signed out-of-band (maintainer) and .sig published
[ ] docs reflect the shipped surface
```

## 9. Reproducible builds (v0.3 B6.2)

The nano binary builds **deterministically**: on a fixed platform + toolchain, a
rebuild reproduces the same bytes, so the released digest can be re-derived rather
than taken on trust.

`cargo xtask` builds nano under a **deterministic env** (`reproducible_env`):

- `--remap-path-prefix` strips every machine-specific absolute prefix — the
  workspace path, the cargo home (registry/source cache), and the rustup toolchain
  sysroot — so the binary embeds none of the builder's `$HOME`/install paths;
- `SOURCE_DATE_EPOCH=0` pins any embedded build timestamp;
- `CARGO_INCREMENTAL=0` disables the non-deterministic incremental cache;
- on **macOS**, `-C link-arg=-Wl,-no_uuid` (macOS-only, via `cfg!(target_os)`) omits the
  linker-stamped Mach-O `LC_UUID` — derived from input object paths, so it otherwise
  differs between build dirs — making the Mach-O reproducible the same way the path
  remaps make the Linux ELF reproducible. The Linux ELF has no equivalent field under
  these flags, so the flag is macOS-only.

Combined with the `nano` profile (`codegen-units = 1`, `lto = "fat"`,
`strip = "symbols"`, `panic = "abort"`) and the pinned toolchain
(`rust-toolchain.toml`), the build is deterministic, and `size-check`, `release`,
and `reproduce` all measure the **same** binary.

**Verify it:**

```sh
cargo xtask reproduce   # builds nano twice into independent target dirs; the
                        # two SHA-256 digests must match, else it fails
```

**What `reproduce` proves, and what it doesn't.** It runs two builds on the *same
machine* (different target dirs), so it verifies **same-machine determinism** — the
build does not depend on the incremental cache or the target directory. Full
**cross-machine** bit-identity additionally requires that the *exact same* compiler
build is used (note `rust-toolchain.toml` pins the `stable` **channel**, not a fixed
version — a `1.x.y` pin is the remaining step) and the same target triple (the nano
size claim is for `x86_64-unknown-linux-gnu`). With those held equal, the path
remapping above removes the known machine-specific variance; cross-machine parity is
not yet machine-independently verified. So: a maintainer or auditor on the same
platform/toolchain can rebuild a tagged release and match the signed `SHA256SUMS` —
moving from "trust the signer" toward "verify the bytes."

(The signed GitHub Actions release workflow and the `cargo-bloat`/fuzz CI jobs
(B6.1/B6.3) edit `.github/workflows/**` — an irreversible, CI-credentialed,
**maintainer-owned** step (`CLAUDE.md` §6.3) — and are wired by the maintainer, not
the agent.)
