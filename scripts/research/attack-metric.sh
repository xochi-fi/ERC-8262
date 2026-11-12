#!/usr/bin/env bash
# Anti-structuring research metric (XIP-1 remediation).
# Prints `METRIC attacks_blocked=N`: passing test_attack_* in StructuringAttacks.
# Any failing test_honest_* zeroes the metric: a design that breaks legitimate
# splits does not count, however many attacks it blocks.
set -euo pipefail

# forge repeats failures in its summary; keep one line per test.
out=$(forge test --match-contract StructuringAttacks 2>&1 | grep -E '\[(PASS|FAIL[^]]*)\] test_(attack|honest)_' | sort -u || true)
honest_fail=$(printf '%s\n' "$out" | grep -cE '\[FAIL[^]]*\] test_honest_' || true)
honest_pass=$(printf '%s\n' "$out" | grep -cE '\[PASS\] test_honest_' || true)
blocked=$(printf '%s\n' "$out" | grep -cE '\[PASS\] test_attack_' || true)
total=$(printf '%s\n' "$out" | grep -cE '\[(PASS|FAIL[^]]*)\] test_attack_' || true)

printf '%s\n' "$out"
if [[ "$honest_fail" -gt 0 || "$honest_pass" -eq 0 ]]; then
  printf 'honest flows failing: %s\n' "$honest_fail" >&2
  blocked=0
fi
printf 'METRIC attacks_total=%s\n' "$total"
printf 'METRIC attacks_blocked=%s\n' "$blocked"
