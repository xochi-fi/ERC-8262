#!/usr/bin/env bash
# Circuit-binding research metric (XIP-1 remediation).
# Prints `METRIC circuit_attacks_blocked=N`: passing research::test_attack_* in
# circuits/pattern. Any failing research::test_honest_* zeroes it.
# Size lines: `METRIC <pkg>_gates=N` (sum of per-opcode UltraHonk gates, the
# resolution metric) and `METRIC <pkg>_circuit_size=N` (`bb gates` circuit size,
# floored by lookup tables; what proving pays) for pattern and compliance, since
# binding designs move work into the compliance circuit.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NARGO="${NARGO:-$(command -v nargo 2>/dev/null || echo "$HOME/.nargo/bin/nargo")}"
# The pinned bb (see .tool-versions); newer bb cannot read nargo 1.0.0-beta.20 ACIR.
BB="${BB:-$HOME/.bb/bb}"

cd "$REPO_ROOT/circuits"

out=$("$NARGO" test --package pattern 2>&1 | perl -pe 's/\e\[[0-9;]*m//g' \
  | grep -E 'Testing research::test_(attack|honest)_' | sort -u || true)
honest_fail=$(printf '%s\n' "$out" | grep -cE 'test_honest_.* \.\.\. FAIL' || true)
honest_pass=$(printf '%s\n' "$out" | grep -cE 'test_honest_.* \.\.\. ok' || true)
blocked=$(printf '%s\n' "$out" | grep -cE 'test_attack_.* \.\.\. ok' || true)
total=$(printf '%s\n' "$out" | grep -cE 'test_attack_' || true)

printf '%s\n' "$out"
if [[ "$honest_fail" -gt 0 || "$honest_pass" -eq 0 ]]; then
  printf 'honest proofs failing: %s\n' "$honest_fail" >&2
  blocked=0
fi

sizes() {
  local pkg="$1"
  "$NARGO" compile --package "$pkg" >/dev/null 2>&1
  "$BB" gates -b "target/$pkg.json" --include_gates_per_opcode 2>/dev/null | python3 -c '
import json, sys
f = json.load(sys.stdin)["functions"][0]
print(sum(f["gates_per_opcode"]), f["circuit_size"])'
}

printf 'METRIC circuit_attacks_total=%s\n' "$total"
printf 'METRIC circuit_attacks_blocked=%s\n' "$blocked"
for pkg in pattern compliance; do
  read -r g s < <(sizes "$pkg")
  printf 'METRIC %s_gates=%s\nMETRIC %s_circuit_size=%s\n' "$pkg" "$g" "$pkg" "$s"
done
