#!/usr/bin/env python3
"""ERC draft <-> Oracle public-input validation drift check.

The `Public Input Validation` section of `ERC-8262.md` carries one table per
proof type enumerating every public input at its declared index. Those tables
are hand-maintained and have drifted from the Oracle before: COMPLIANCE_MULTI_SIGNED
had no table at all, and RISK_SCORE / RISK_SCORE_SIGNED claimed `provider_set_hash`
was validated when the Oracle never reads it.

This script compares three sources of truth that must agree:

1. The per-type tables in the `Public Input Validation` section of `ERC-8262.md`
   (index + input name, in order).
2. The `//   [n]: name` layout comments above each `_validate*Inputs` function in
   `src/ERC8262Oracle.sol`.
3. `ProofTypes.expectedPublicInputCount(uint8)` in `src/libraries/ProofTypes.sol`.

It checks names, ordering, indices, and counts. It deliberately does NOT try to
verify the prose in the `Oracle validation` column -- that stays human-maintained.
What it guarantees is that no public input can be silently omitted from, added to,
or reordered in the draft without CI noticing.

Exits 0 on parity, 1 on drift, 2 on usage/parsing error.

Usage:
  public-input-drift.py [project-root]
  public-input-drift.py --eip PATH --oracle PATH --proof-types PATH
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# ERC draft extraction
# ---------------------------------------------------------------------------

# The `Public Input Validation` section only. Scoping matters: `Per-Type Circuit
# Specifications` uses identical `#### NAME (0xNN)` headers for the circuit-side
# constraints, and those tables have a different shape.
PIV_SECTION = re.compile(
    r"^### Public Input Validation\s*$(?P<body>.*?)(?=^### )", re.M | re.S
)
TYPE_HEADER = re.compile(r"^#### (?P<name>[A-Z_0-9]+) \((?P<id>0x[0-9a-fA-F]{2})\)\s*$", re.M)
# Table rows of the form: | 0 | `jurisdiction_id` | ... |
TABLE_ROW = re.compile(r"^\|\s*(?P<index>\d+)\s*\|\s*`(?P<field>[A-Za-z0-9_]+)`\s*\|", re.M)


def parse_eip_tables(text: str) -> dict[str, list[tuple[int, str]]]:
    section = PIV_SECTION.search(text)
    if section is None:
        raise ValueError("could not locate the 'Public Input Validation' section")
    body = section.group("body")

    headers = list(TYPE_HEADER.finditer(body))
    tables: dict[str, list[tuple[int, str]]] = {}
    for i, header in enumerate(headers):
        start = header.end()
        end = headers[i + 1].start() if i + 1 < len(headers) else len(body)
        rows = [
            (int(m.group("index")), m.group("field"))
            for m in TABLE_ROW.finditer(body[start:end])
        ]
        tables[header.group("name")] = rows
    return tables


# ---------------------------------------------------------------------------
# Oracle extraction
# ---------------------------------------------------------------------------

LAYOUT_HEADER = re.compile(r"//\s*(?P<name>[A-Z_0-9]+) public inputs layout")
# //   [0]: jurisdiction_id            (trailing annotations are ignored)
LAYOUT_ENTRY = re.compile(r"//\s*\[(?P<index>\d+)\]:\s*(?P<field>[a-z0-9_]+)")
# //   [6..11): signer_pubkey_hash_0..4   -- a contiguous run of numbered slots
LAYOUT_RANGE = re.compile(
    r"//\s*\[(?P<start>\d+)\.\.(?P<stop>\d+)\):\s*(?P<base>[a-z0-9_]+?)_(?P<first>\d+)\.\.(?P<last>\d+)"
)


def parse_oracle_layouts(text: str) -> dict[str, list[tuple[int, str]]]:
    layouts: dict[str, list[tuple[int, str]]] = {}
    current: str | None = None
    entries: list[tuple[int, str]] = []

    for line in text.splitlines():
        header = LAYOUT_HEADER.search(line)
        if header is not None:
            if current is not None:
                layouts[current] = entries
            current, entries = header.group("name"), []
            continue
        if current is None:
            continue

        rng = LAYOUT_RANGE.search(line)
        if rng is not None:
            start, stop = int(rng.group("start")), int(rng.group("stop"))
            first, last = int(rng.group("first")), int(rng.group("last"))
            base = rng.group("base")
            if stop - start != last - first + 1:
                raise ValueError(
                    f"{current}: range [{start}..{stop}) does not match "
                    f"suffixes {first}..{last}"
                )
            entries.extend(
                (start + offset, f"{base}_{first + offset}")
                for offset in range(stop - start)
            )
            continue

        entry = LAYOUT_ENTRY.search(line)
        if entry is not None:
            entries.append((int(entry.group("index")), entry.group("field")))
            continue

        # First line after the block that is not a layout entry ends it.
        if entries:
            layouts[current] = entries
            current, entries = None, []

    if current is not None:
        layouts[current] = entries
    return layouts


# ---------------------------------------------------------------------------
# ProofTypes extraction
# ---------------------------------------------------------------------------

EXPECTED_COUNT = re.compile(r"if \(proofType == (?P<name>[A-Z_]+)\) return (?P<count>\d+);")


def parse_expected_counts(text: str) -> dict[str, int]:
    return {m.group("name"): int(m.group("count")) for m in EXPECTED_COUNT.finditer(text)}


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------


def compare(
    eip: dict[str, list[tuple[int, str]]],
    oracle: dict[str, list[tuple[int, str]]],
    counts: dict[str, int],
) -> list[str]:
    drift: list[str] = []

    for name in sorted(set(eip) | set(oracle) | set(counts)):
        eip_rows = eip.get(name)
        oracle_rows = oracle.get(name)

        if oracle_rows is None:
            drift.append(f"[{name}] no layout comment found in ERC8262Oracle.sol")
            continue
        if eip_rows is None:
            drift.append(
                f"[{name}] no table in the 'Public Input Validation' section of the ERC draft "
                f"(Oracle declares {len(oracle_rows)} public inputs)"
            )
            continue

        expected = counts.get(name)
        if expected is not None and len(oracle_rows) != expected:
            drift.append(
                f"[{name}] Oracle layout lists {len(oracle_rows)} inputs but "
                f"ProofTypes.expectedPublicInputCount returns {expected}"
            )
        if expected is not None and len(eip_rows) != expected:
            drift.append(
                f"[{name}] ERC table lists {len(eip_rows)} inputs but "
                f"ProofTypes.expectedPublicInputCount returns {expected}"
            )

        for rows, label in ((eip_rows, "ERC table"), (oracle_rows, "Oracle layout")):
            actual = [index for index, _ in rows]
            if actual != list(range(len(rows))):
                drift.append(f"[{name}] {label} indices are not 0..{len(rows) - 1}: {actual}")

        eip_fields = [field for _, field in eip_rows]
        oracle_fields = [field for _, field in oracle_rows]
        if eip_fields != oracle_fields:
            for index in range(max(len(eip_fields), len(oracle_fields))):
                in_eip = eip_fields[index] if index < len(eip_fields) else "<missing>"
                in_oracle = oracle_fields[index] if index < len(oracle_fields) else "<missing>"
                if in_eip != in_oracle:
                    drift.append(
                        f"[{name}] index {index}: ERC table says '{in_eip}', "
                        f"Oracle layout says '{in_oracle}'"
                    )

    return drift


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def resolve_paths(argv: list[str]) -> tuple[Path, Path, Path]:
    if "--eip" in argv:
        def flag(name: str) -> Path:
            return Path(argv[argv.index(name) + 1]).resolve()

        return flag("--eip"), flag("--oracle"), flag("--proof-types")

    root = Path(argv[1] if len(argv) > 1 else ".").resolve()
    return (
        root / "ERC-8262.md",
        root / "src" / "ERC8262Oracle.sol",
        root / "src" / "libraries" / "ProofTypes.sol",
    )


def main(argv: list[str]) -> int:
    try:
        eip_path, oracle_path, proof_types_path = resolve_paths(argv)
    except (IndexError, ValueError):
        print(__doc__, file=sys.stderr)
        return 2

    for path in (eip_path, oracle_path, proof_types_path):
        if not path.is_file():
            print(f"error: file not found at {path}", file=sys.stderr)
            return 2

    try:
        eip = parse_eip_tables(eip_path.read_text())
        oracle = parse_oracle_layouts(oracle_path.read_text())
        counts = parse_expected_counts(proof_types_path.read_text())
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not oracle:
        print("error: no public-input layout comments found in the Oracle", file=sys.stderr)
        return 2

    drift = compare(eip, oracle, counts)
    if drift:
        print("Public-input validation drift detected:\n")
        for line in drift:
            print(f"  {line}")
        print(
            "\nThe per-type tables in the 'Public Input Validation' section of "
            "ERC-8262.md must enumerate exactly the public inputs declared in the "
            "layout comments of ERC8262Oracle.sol, in the same order. Update the "
            "draft or the Oracle so they agree."
        )
        return 1

    total = sum(len(rows) for rows in oracle.values())
    print(
        f"Public-input tables match the Oracle: {len(oracle)} proof types, "
        f"{total} public inputs."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
