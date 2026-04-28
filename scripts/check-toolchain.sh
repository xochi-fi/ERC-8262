#!/usr/bin/env bash
# Verify the local nargo and bb versions match what this repo was tested with.
# Source of truth: .tool-versions in the repo root.
#
# Usage: ./scripts/check-toolchain.sh
# Exit 0 = matches, exit 1 = mismatch (does not auto-fix).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TOOL_VERSIONS="$REPO_ROOT/.tool-versions"

if [[ ! -f "$TOOL_VERSIONS" ]]; then
    echo "error: .tool-versions not found at $TOOL_VERSIONS" >&2
    exit 1
fi

NARGO="${NARGO:-$(command -v nargo 2>/dev/null || echo "$HOME/.nargo/bin/nargo")}"
BB="${BB:-$(command -v bb 2>/dev/null || echo "$HOME/.bb/bb")}"

expected_nargo=$(grep -E '^nargo ' "$TOOL_VERSIONS" | awk '{print $2}')
expected_bb=$(grep -E '^bb ' "$TOOL_VERSIONS" | awk '{print $2}')

failed=0

# nargo
if [[ ! -x "$NARGO" ]]; then
    echo "error: nargo not found (expected $expected_nargo)" >&2
    failed=1
else
    actual_nargo=$("$NARGO" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+(-[a-z0-9.]+)?' | head -1)
    if [[ "$actual_nargo" != "$expected_nargo" ]]; then
        echo "warn: nargo version mismatch: have $actual_nargo, expected $expected_nargo" >&2
        echo "      install with: noirup -v $expected_nargo" >&2
        failed=1
    else
        echo "ok: nargo $actual_nargo"
    fi
fi

# bb
if [[ ! -x "$BB" ]]; then
    echo "error: bb not found (expected $expected_bb)" >&2
    failed=1
else
    actual_bb=$("$BB" --version 2>/dev/null | head -1)
    if [[ "$actual_bb" != "$expected_bb" ]]; then
        echo "warn: bb version mismatch: have $actual_bb, expected $expected_bb" >&2
        echo "      install with: bbup -v $expected_bb" >&2
        failed=1
    else
        echo "ok: bb $actual_bb"
    fi
fi

# foundry (informational only -- we don't pin a specific commit since stable
# is the most-tested config; just ensure it's installed)
if ! command -v forge &>/dev/null; then
    echo "warn: forge not found in PATH" >&2
    failed=1
else
    forge_version=$(forge --version 2>/dev/null | head -1)
    echo "info: $forge_version"
fi

if [[ $failed -ne 0 ]]; then
    echo ""
    echo "Toolchain check failed. Regenerating fixtures with mismatched versions"
    echo "produces different VK_HASH values and breaks the integration test suite."
    exit 1
fi

echo "All pinned tool versions match."
