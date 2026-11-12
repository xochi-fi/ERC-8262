#!/usr/bin/env bash
# Proving-cost bench for the circuit-binding research: witness generation
# (`nargo execute` on each package's Prover.toml) and `bb prove` wall time.
# Usage: scripts/research/circuit-bench.sh [package ...]   (default: pattern compliance)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
NARGO="${NARGO:-$(command -v nargo 2>/dev/null || echo "$HOME/.nargo/bin/nargo")}"
BB="${BB:-$HOME/.bb/bb}"
OUT_DIR="$(mktemp -d)"
trap 'rm -r "$OUT_DIR"' EXIT

now_ms() { python3 -c 'import time; print(int(time.time() * 1000))'; }

bench() {
  local pkg="$1" t0 t1 t2 size
  cd "$REPO_ROOT/circuits/$pkg"
  "$NARGO" compile >/dev/null 2>&1
  t0=$(now_ms)
  "$NARGO" execute >/dev/null 2>&1
  t1=$(now_ms)
  "$BB" write_vk -b "../target/$pkg.json" -t evm -o "$OUT_DIR/$pkg-vk" >/dev/null 2>&1
  t1b=$(now_ms)
  "$BB" prove -b "../target/$pkg.json" -w "../target/$pkg.gz" -k "$OUT_DIR/$pkg-vk/vk" \
    -t evm -o "$OUT_DIR/$pkg" >/dev/null 2>&1
  t2=$(now_ms)
  "$BB" verify -k "$OUT_DIR/$pkg-vk/vk" -p "$OUT_DIR/$pkg/proof" \
    -i "$OUT_DIR/$pkg/public_inputs" -t evm >/dev/null 2>&1
  size=$("$BB" gates -b "../target/$pkg.json" 2>/dev/null | grep -oE '"circuit_size": *[0-9]+' | grep -oE '[0-9]+$')
  printf 'METRIC %s_gates=%s\n' "$pkg" "$size"
  printf 'METRIC %s_execute_ms=%s\n' "$pkg" "$((t1 - t0))"
  printf 'METRIC %s_prove_ms=%s\n' "$pkg" "$((t2 - t1b))"
  printf 'METRIC %s_public_inputs_bytes=%s\n' "$pkg" "$(wc -c <"$OUT_DIR/$pkg/public_inputs" | tr -d ' ')"
}

pkgs=("$@")
[[ ${#pkgs[@]} -eq 0 ]] && pkgs=(pattern compliance)
for p in "${pkgs[@]}"; do bench "$p"; done
