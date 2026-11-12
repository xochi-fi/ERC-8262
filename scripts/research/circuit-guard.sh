#!/usr/bin/env bash
# Guard for the circuit-binding research: every circuit test passes except the
# research attack tests (which fail while an attack is still open), the
# workspace compiles, circuit <-> Solidity public-input arity agrees, and, when
# src/ or test/ differ from the research base, the fast forge suite passes.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NARGO="${NARGO:-$(command -v nargo 2>/dev/null || echo "$HOME/.nargo/bin/nargo")}"
BASE="${RESEARCH_BASE:-research/anti-structuring}"

cd "$REPO_ROOT/circuits"
out=$("$NARGO" test --workspace 2>&1 | perl -pe 's/\e\[[0-9;]*m//g' || true)
if ! printf '%s\n' "$out" | grep -qE 'tests passed'; then
  printf '%s\n' "$out" >&2
  printf 'guard: nargo test did not run\n' >&2
  exit 1
fi
bad=$(printf '%s\n' "$out" | grep -E 'Testing .* \.\.\. FAIL' | grep -vE 'research::test_attack_' || true)
if [[ -n "$bad" ]]; then
  printf 'guard: failing circuit tests:\n%s\n' "$bad" >&2
  exit 1
fi
"$NARGO" compile --workspace >/dev/null

cd "$REPO_ROOT"
python3 scripts/parity-check.py .

if ! git diff --quiet "$BASE" -- src test; then
  forge test --no-match-contract 'StructuringAttacks|Invariant' >/dev/null
fi
