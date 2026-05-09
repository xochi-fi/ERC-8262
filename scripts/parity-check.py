#!/usr/bin/env python3
"""Circuit<->Solidity public-input parity check.

Vendored from the `zk-x-ray` skill (DROOdotFOO/agent-skills,
skills/zk-x-ray/scripts/parity-check.py). Kept in this repo so CI does
not depend on an external skill checkout. Update both copies in lockstep.

Compares four sources of truth that must agree for a ZK + EVM hybrid to verify
proofs correctly:

1. Logical pub count from each `circuits/<name>/src/main.nr` (the count of
   `name: pub Type` parameters in `fn main(...)`).
2. Physical pub count from each `circuits/**/target/<name>.json` (the number of
   `abi.parameters` entries with `visibility == "public"`).
3. Solidity expected count from `expectedPublicInputCount(uint8)` returns in
   any `*.sol` file under the project's source tree.
4. `NUMBER_OF_PUBLIC_INPUTS` from each generated verifier in `src/generated/`.

Acceptance rules:
- logical <= physical (Noir flattens arrays into individual field elements;
  e.g. `pub [Field; 8]` is 1 logical, 8 physical).
- Solidity expected count == logical count (the on-chain library expects the
  prover-facing arity, not the post-flattening count).
- NUMBER_OF_PUBLIC_INPUTS == physical + 16 (UltraHonk's hash-input overhead).

Exits 0 on full parity, 1 on drift, 2 on usage error / missing tooling.

Usage: parity-check.py [project-root]
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


def find_main_nr_files(circuits_dir: Path) -> list[Path]:
    return sorted(p for p in circuits_dir.rglob("src/main.nr") if "target" not in p.parts)


def count_pub_params(main_nr: Path) -> int:
    """Count every `name: pub Type` parameter, even when several share a line."""
    pattern = re.compile(r":\s*pub\s")
    return sum(len(pattern.findall(line)) for line in main_nr.read_text().splitlines())


def find_target_jsons(circuits_dir: Path) -> dict[str, Path]:
    """Map circuit name -> compiled target JSON path. Skips ACIR / proof artefacts."""
    out: dict[str, Path] = {}
    for json_path in sorted(circuits_dir.rglob("target/*.json")):
        circuit_name = json_path.stem
        if circuit_name.endswith(".acir") or circuit_name.endswith(".vk"):
            continue
        out[circuit_name] = json_path
    return out


def physical_pub_count(target_json: Path) -> int | None:
    try:
        data = json.loads(target_json.read_text())
    except json.JSONDecodeError:
        return None
    params = data.get("abi", {}).get("parameters", [])
    return sum(1 for p in params if p.get("visibility") == "public")


def detect_src_dir(root: Path) -> Path:
    foundry = root / "foundry.toml"
    if foundry.exists():
        for line in foundry.read_text().splitlines():
            m = re.match(r'\s*src\s*=\s*"([^"]+)"', line)
            if m:
                return root / m.group(1)
    if (root / "src").is_dir():
        return root / "src"
    if (root / "contracts").is_dir():
        return root / "contracts"
    return root / "src"


def find_solidity_expected(src_dir: Path) -> dict[str, int]:
    """Map lowercased proofType constant -> expected count from `if (proofType == X) return N;`."""
    out: dict[str, int] = {}
    pattern = re.compile(
        r"if\s*\(\s*proofType\s*==\s*([A-Z_][A-Z0-9_]*)\s*\)\s*return\s+(\d+)\s*;"
    )
    for sol in src_dir.rglob("*.sol"):
        if "generated" in sol.parts:
            continue
        for match in pattern.finditer(sol.read_text()):
            const, count = match.group(1), int(match.group(2))
            out[const.lower()] = count
    return out


def find_verifier_constants(src_dir: Path) -> dict[str, int]:
    """Map circuit name (derived from filename) -> NUMBER_OF_PUBLIC_INPUTS constant."""
    out: dict[str, int] = {}
    pattern = re.compile(r"NUMBER_OF_PUBLIC_INPUTS\s*=\s*(\d+)")
    generated_dir = src_dir / "generated"
    if not generated_dir.is_dir():
        return out
    for sol in sorted(generated_dir.glob("*_verifier.sol")):
        circuit = sol.stem.removesuffix("_verifier")
        text = sol.read_text()
        match = pattern.search(text)
        if match:
            out[circuit] = int(match.group(1))
    return out


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    circuits_dir = root / "circuits"
    if not circuits_dir.is_dir():
        print("[parity-check] no circuits/ directory; skipping", file=sys.stderr)
        return 0

    src_dir = detect_src_dir(root)

    logical = {p.parent.parent.name: count_pub_params(p) for p in find_main_nr_files(circuits_dir)}
    physical_paths = find_target_jsons(circuits_dir)
    physical = {name: physical_pub_count(p) for name, p in physical_paths.items()}
    sol_expected = find_solidity_expected(src_dir)
    verifier = find_verifier_constants(src_dir)

    circuit_names = sorted(set(logical) | set(physical) | set(verifier))
    if not circuit_names:
        print("[parity-check] no circuits detected", file=sys.stderr)
        return 0

    rows: list[tuple[str, str, str, str, str, str]] = []
    drift = False

    for name in circuit_names:
        L = logical.get(name)
        P = physical.get(name)
        S = sol_expected.get(name)
        V = verifier.get(name)

        # Drift = an actual mismatch between two non-? values. Missing data
        # (uncompiled targets, no generated verifier yet) is reported as
        # informational and does not flip the exit code -- the script is meant
        # to be safe to run mid-development.
        drift_reasons: list[str] = []
        info_reasons: list[str] = []
        if L is None:
            info_reasons.append("missing main.nr")
        if P is None:
            info_reasons.append("missing target/json")
        if V is None:
            info_reasons.append("missing generated verifier")
        if L is not None and P is not None and L > P:
            drift_reasons.append("logical>physical")
        if L is not None and S is not None and L != S:
            drift_reasons.append("sol-expected!=logical")
        if V is not None and P is not None and V != P + 16:
            drift_reasons.append("verifier!=physical+16")
        if drift_reasons:
            status = "DRIFT(" + ",".join(drift_reasons) + ")"
            drift = True
        elif info_reasons:
            status = "INFO(" + ",".join(info_reasons) + ")"
        else:
            status = "OK"

        rows.append(
            (
                name,
                "?" if L is None else str(L),
                "?" if P is None else str(P),
                "?" if S is None else str(S),
                "?" if V is None else str(V),
                status,
            )
        )

    headers = ("Circuit", "Logical", "Physical", "Sol expected", "Verifier", "Status")
    widths = [max(len(r[i]) for r in (rows + [headers])) for i in range(len(headers))]
    fmt = "  ".join("{:<" + str(w) + "}" for w in widths)
    print(fmt.format(*headers))
    print("  ".join("-" * w for w in widths))
    for row in rows:
        print(fmt.format(*row))

    if drift:
        print("\n[parity-check] DRIFT detected -- review the rows flagged above")
        return 1
    print("\n[parity-check] all rows in parity")
    return 0


if __name__ == "__main__":
    sys.exit(main())
