#!/usr/bin/env bash
# validate_live_socket_runbook.sh — keep docs/live-socket-validation.md honest.
#
# Every live seam in the tree must be catalogued in the runbook, so validating
# CrustCore against real infrastructure stays systematic instead of relying on
# tribal knowledge. This lint fails if either:
#
#   1. a named `#[ignore = "…"]` test exists whose fn name is NOT in the runbook, or
#   2. a `TODO(*-live)` tag exists that is NOT mentioned in the runbook.
#
# It runs standalone (`bash scripts/validate_live_socket_runbook.sh`) and as part
# of `cargo xtask verify` (the `runbook-check` step). No external deps beyond a
# POSIX userland (grep, awk, sort) — matches the CI environment (Linux/macOS).
set -euo pipefail

# Resolve the workspace root (this script lives in scripts/).
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

RUNBOOK="docs/live-socket-validation.md"
if [ ! -f "$RUNBOOK" ]; then
  echo "FAIL: $RUNBOOK is missing — the live-socket runbook must exist." >&2
  exit 1
fi

missing=0

# --- 1. Named ignored live tests ------------------------------------------------
# For each file containing an `#[ignore = "…"]` attribute, emit the fn name on the
# next `fn …` line. Using awk (not grep -A) so adjacent tests/bodies can't bleed
# into the match.
ignored_fns="$(
  grep -rl '#\[ignore = "' --include='*.rs' crates | while IFS= read -r f; do
    awk '
      /#\[ignore = "/ { want = 1; next }
      want && match($0, /fn [A-Za-z0-9_]+/) {
        print substr($0, RSTART + 3, RLENGTH - 3)
        want = 0
      }
    ' "$f"
  done | sort -u
)"

while IFS= read -r fn; do
  [ -z "$fn" ] && continue
  if ! grep -q -- "$fn" "$RUNBOOK"; then
    echo "MISSING from $RUNBOOK: ignored live test  '$fn'" >&2
    missing=1
  fi
done <<EOF
$ignored_fns
EOF

# --- 2. Distinct TODO(*-live) tags ---------------------------------------------
live_tags="$(
  grep -rhoE 'TODO\([A-Za-z0-9_-]*-live\)' --include='*.rs' crates \
    | sed -E 's/^TODO\((.*)\)$/\1/' | sort -u
)"

while IFS= read -r tag; do
  [ -z "$tag" ] && continue
  if ! grep -q -- "$tag" "$RUNBOOK"; then
    echo "MISSING from $RUNBOOK: live seam tag  '$tag'" >&2
    missing=1
  fi
done <<EOF
$live_tags
EOF

if [ "$missing" -ne 0 ]; then
  echo "" >&2
  echo "live-socket runbook is stale: add the entries above to $RUNBOOK" >&2
  echo "(see the 'How to add a seam' note at the bottom of the runbook)." >&2
  exit 1
fi

n_fns="$(printf '%s\n' "$ignored_fns" | grep -c . || true)"
n_tags="$(printf '%s\n' "$live_tags" | grep -c . || true)"
echo "live-socket runbook OK: ${n_fns} ignored tests + ${n_tags} TODO(*-live) tags all catalogued."
