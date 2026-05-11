#!/usr/bin/env python3
"""EIP draft <-> src/interfaces drift check.

The EIP draft (`eip-draft_xochi-zkp.md`) embeds Solidity interface listings for
`IXochiZKPVerifier` and `IXochiZKPOracle`. Those listings are hand-maintained
and have drifted from the source twice already. This script extracts the
function signatures from both sides and fails CI when they diverge.

Comparison is signature-level only (function name + parameter types + return
types). NatSpec, parameter names, and whitespace are normalized away so cosmetic
edits don't trigger drift. Struct field names and event arguments are checked
because they are part of the ABI.

Exits 0 on parity, 1 on drift, 2 on usage/parsing error.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path


# ---------------------------------------------------------------------------
# Interface extraction
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Signature:
    kind: str  # "function" | "event" | "struct"
    name: str
    body: str  # normalized signature body (types only)

    def render(self) -> str:
        return f"{self.kind} {self.name}{self.body}"


SOLIDITY_BLOCK = re.compile(r"```solidity\n(.*?)\n```", re.DOTALL)
INTERFACE_OPEN = re.compile(r"interface\s+(\w+)\s*\{")
FUNCTION_DECL = re.compile(
    r"function\s+(\w+)\s*\(([^)]*)\)\s*(.*?)(?:returns\s*\(([^)]*)\))?\s*;",
    re.DOTALL,
)
EVENT_DECL = re.compile(r"event\s+(\w+)\s*\(([^)]*)\)\s*;", re.DOTALL)
STRUCT_DECL = re.compile(r"struct\s+(\w+)\s*\{([^}]*)\}", re.DOTALL)
SINGLE_LINE_COMMENT = re.compile(r"//[^\n]*")
MULTI_LINE_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)


def strip_comments(text: str) -> str:
    text = MULTI_LINE_COMMENT.sub("", text)
    text = SINGLE_LINE_COMMENT.sub("", text)
    return text


def normalize_param_list(params: str) -> str:
    """Drop parameter names and storage location keywords; keep types only."""
    if not params.strip():
        return ""
    parts = [p.strip() for p in params.split(",")]
    normalized = []
    for part in parts:
        tokens = [t for t in re.split(r"\s+", part) if t]
        # Drop storage-location qualifiers and indexed (for events).
        tokens = [t for t in tokens if t not in {"calldata", "memory", "storage", "indexed"}]
        # If two tokens remain, last one is the param name -- drop it.
        # If only one remains, it IS the type.
        if len(tokens) >= 2:
            tokens = tokens[:-1]
        normalized.append(" ".join(tokens))
    return ", ".join(normalized)


def normalize_struct_body(body: str) -> str:
    """Struct fields: keep `type name` pairs, sorted-by-position so order matters."""
    cleaned = strip_comments(body)
    fields = [line.strip().rstrip(";").strip() for line in cleaned.split(";") if line.strip()]
    out = []
    for field in fields:
        tokens = re.split(r"\s+", field)
        if len(tokens) < 2:
            continue
        out.append(f"{tokens[0]} {tokens[-1]}")
    return "{" + "; ".join(out) + "}"


def extract_interface_body(source: str, interface_name: str) -> str | None:
    """Return the body (between { and matching }) of an interface declaration."""
    match = INTERFACE_OPEN.search(source)
    while match:
        if match.group(1) == interface_name:
            start = match.end()
            depth = 1
            i = start
            while i < len(source) and depth > 0:
                c = source[i]
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                i += 1
            return source[start : i - 1]
        match = INTERFACE_OPEN.search(source, match.end())
    return None


def parse_signatures(body: str) -> list[Signature]:
    body = strip_comments(body)
    sigs: list[Signature] = []

    for m in STRUCT_DECL.finditer(body):
        sigs.append(Signature("struct", m.group(1), normalize_struct_body(m.group(2))))

    for m in EVENT_DECL.finditer(body):
        sigs.append(Signature("event", m.group(1), f"({normalize_param_list(m.group(2))})"))

    for m in FUNCTION_DECL.finditer(body):
        name = m.group(1)
        params = normalize_param_list(m.group(2))
        modifiers = re.sub(r"\s+", " ", m.group(3).strip())
        # Drop visibility keywords -- they are not part of the ABI.
        modifiers = " ".join(
            t for t in modifiers.split() if t not in {"external", "public", "view", "pure", "payable"}
        )
        returns = m.group(4) or ""
        returns_norm = normalize_param_list(returns)
        body_str = f"({params})"
        if modifiers:
            body_str += f" {modifiers}"
        if returns_norm:
            body_str += f" returns ({returns_norm})"
        sigs.append(Signature("function", name, body_str))

    return sorted(sigs, key=lambda s: (s.kind, s.name, s.body))


# ---------------------------------------------------------------------------
# EIP block extraction
# ---------------------------------------------------------------------------


def extract_eip_solidity_blocks(eip_text: str) -> dict[str, str]:
    """Find each fenced ```solidity block that declares one of our interfaces."""
    blocks: dict[str, str] = {}
    for m in SOLIDITY_BLOCK.finditer(eip_text):
        code = m.group(1)
        for iface_match in INTERFACE_OPEN.finditer(code):
            blocks[iface_match.group(1)] = code
    return blocks


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def compare(name: str, eip_sigs: list[Signature], src_sigs: list[Signature]) -> list[str]:
    eip_set = {s.render() for s in eip_sigs}
    src_set = {s.render() for s in src_sigs}
    drift: list[str] = []
    only_in_src = sorted(src_set - eip_set)
    only_in_eip = sorted(eip_set - src_set)
    for item in only_in_src:
        drift.append(f"[{name}] missing from EIP: {item}")
    for item in only_in_eip:
        drift.append(f"[{name}] missing from src: {item}")
    return drift


def main(argv: list[str]) -> int:
    root = Path(argv[1] if len(argv) > 1 else ".").resolve()
    eip_path = root / "eip-draft_xochi-zkp.md"
    if not eip_path.is_file():
        print(f"error: EIP draft not found at {eip_path}", file=sys.stderr)
        return 2

    interfaces = {
        "IXochiZKPVerifier": root / "src" / "interfaces" / "IXochiZKPVerifier.sol",
        "IXochiZKPOracle": root / "src" / "interfaces" / "IXochiZKPOracle.sol",
    }
    for name, path in interfaces.items():
        if not path.is_file():
            print(f"error: source not found at {path}", file=sys.stderr)
            return 2

    eip_blocks = extract_eip_solidity_blocks(eip_path.read_text())
    drift: list[str] = []
    for name, path in interfaces.items():
        if name not in eip_blocks:
            drift.append(f"[{name}] no ```solidity block declaring this interface found in EIP draft")
            continue
        eip_body = extract_interface_body(eip_blocks[name], name)
        src_body = extract_interface_body(path.read_text(), name)
        if eip_body is None or src_body is None:
            drift.append(f"[{name}] failed to extract interface body")
            continue
        eip_sigs = parse_signatures(eip_body)
        src_sigs = parse_signatures(src_body)
        drift.extend(compare(name, eip_sigs, src_sigs))

    if drift:
        print("EIP interface drift detected:\n")
        for line in drift:
            print(f"  {line}")
        print(
            "\nThe Solidity interface listings in eip-draft_xochi-zkp.md must match "
            "src/interfaces/*.sol. Update the EIP draft or the source so they agree."
        )
        return 1

    print("EIP interface listings match src/interfaces/*.sol.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
