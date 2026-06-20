#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# CrustCore installer (Phase 16, P16.3). Verifies the SHA-256 checksum of a built
# nano binary against the SHA256SUMS file beside it, then installs it into PREFIX.
#
# Usage:
#   scripts/install.sh <path-to-crustcore-binary>
#   PREFIX=/usr/local scripts/install.sh target/nano/crustcore
#
# It refuses to install a binary whose checksum does not match SHA256SUMS. Signature
# verification (minisign/cosign over SHA256SUMS) is a separate, out-of-band step —
# see docs/releasing.md §2.
set -eu

BIN="${1:-}"
PREFIX="${PREFIX:-$HOME/.local}"
BINDIR="$PREFIX/bin"

if [ -z "$BIN" ] || [ ! -f "$BIN" ]; then
    echo "usage: scripts/install.sh <path-to-crustcore-binary>" >&2
    echo "  (PREFIX defaults to \$HOME/.local; binary installs to \$PREFIX/bin)" >&2
    exit 2
fi

BIN_DIR=$(CDPATH= cd -- "$(dirname -- "$BIN")" && pwd)
BIN_NAME=$(basename -- "$BIN")
SUMS="$BIN_DIR/SHA256SUMS"

# Pick whichever checksum tool exists (Linux: sha256sum; macOS: shasum -a 256).
if command -v sha256sum >/dev/null 2>&1; then
    sha256_of() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
    sha256_of() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
    echo "error: no sha256sum/shasum found to verify the checksum" >&2
    exit 1
fi

if [ ! -f "$SUMS" ]; then
    echo "error: $SUMS not found — run 'cargo xtask release' to produce it" >&2
    exit 1
fi

# Expected digest for this binary's basename, from SHA256SUMS.
EXPECTED=$(awk -v n="$BIN_NAME" '$2==n || $2=="*"n {print $1}' "$SUMS" | head -n1)
if [ -z "$EXPECTED" ]; then
    echo "error: no entry for '$BIN_NAME' in $SUMS" >&2
    exit 1
fi
ACTUAL=$(sha256_of "$BIN")
if [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "error: checksum mismatch for $BIN_NAME" >&2
    echo "  expected $EXPECTED" >&2
    echo "  actual   $ACTUAL" >&2
    exit 1
fi
echo "checksum ok: $BIN_NAME ($ACTUAL)"

mkdir -p "$BINDIR"
install -m 0755 "$BIN" "$BINDIR/$BIN_NAME"
echo "installed: $BINDIR/$BIN_NAME"
echo "next: run '$BIN_NAME doctor' to check host readiness."
