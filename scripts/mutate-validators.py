#!/usr/bin/env python3
"""Mutation gate for the Oracle's input validators.

Every check in ERC8262Oracle's `_validate*` / `_assert*` / `_require*`
functions must be pinned by a test: removing it has to make some test fail. Real-proof tests
only show that valid proofs pass, so a dropped rejection check (for example
the audit F-6 chain/Oracle binding) can otherwise go unnoticed.

Mutants, one at a time:
- every `revert ...;` statement in those functions, replaced by `{}`
  (`if (c) revert E();` becomes `if (c) {}`);
- every statement that is a bare call to an `_assert*` / `_validate*` /
  `_require*` helper,
  replaced by `{}` (a per-call-site deletion, so each proof type's validator
  is checked on its own even when the helper is shared);
- every helper call whose result is used (`x = _assertFoo(h)`), when the
  helper has more than one call site: the call is swapped for the value it
  returns without its checks, taken from `UNCHECKED_EQUIVALENT`. A helper with
  a single call site needs no such mutant, since the mutants inside it are
  already specific to that caller. A shared helper used as a value with no
  `UNCHECKED_EQUIVALENT` entry is an error, so new call sites cannot go
  unmutated silently.

Each mutant runs the Solidity suite except `InvariantTest` (minutes per run,
and it drives the Oracle through mock verifiers that the unit suites already
cover) with a fixed fuzz seed. A mutant is killed only when forge reports a
failing test; a nonzero exit without one (OOM kill, signal, tool crash) is not
evidence that a test pins the check. The source file is restored after every
mutant and on interrupt. `--shard=K/N` runs every N-th mutant starting at the
K-th (1-based), for parallel CI jobs.

Exits 0 when every mutant is killed, 1 when any survives, 2 on usage error,
missing tooling, a mutant that does not compile (an operator bug), or a forge
run that exits nonzero without a failing test.

Usage: mutate-validators.py [project-root] [--list] [--shard=K/N]
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

TARGET = Path("src/ERC8262Oracle.sol")
FUNCTION_RE = re.compile(r"\bfunction\s+(_(?:validate|assert|require)\w*)\s*\(")
HELPER_CALL_RE = re.compile(r"(_(?:validate|assert|require)\w*)\s*\(")
# Value-returning shared helpers: the expression a call site falls back to
# when the helper's checks are removed. `{args}` is the call's argument list.
UNCHECKED_EQUIVALENT = {
    "_assertSignerAuthorized": "_signerProvider[{args}]",
}
SOLC_ERROR_RE = re.compile(r"^Error \(\d+\)", re.MULTILINE)
FORGE_ARGS = ["test", "--no-match-contract", "InvariantTest", "--fuzz-seed", "0x8262", "--fail-fast"]
FORGE = os.environ.get("FORGE", "forge")


@dataclass(frozen=True)
class Mutant:
    function: str
    line: int
    start: int
    end: int
    snippet: str
    replacement: str = "{}"

    @property
    def change(self) -> str:
        return self.snippet if self.replacement == "{}" else f"{self.snippet} -> {self.replacement}"


def code_mask(src: str) -> list[bool]:
    """True for each character that is code (not inside a comment or string)."""
    mask = [True] * len(src)
    i, n = 0, len(src)
    while i < n:
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j == -1 else j
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j == -1 else j + 2
        elif src[i] in "\"'":
            quote, j = src[i], i + 1
            while j < n and src[j] != quote:
                j += 2 if src[j] == "\\" else 1
            j = min(j + 1, n)
        else:
            i += 1
            continue
        for k in range(i, j):
            mask[k] = False
        i = j
    return mask


def match_close(src: str, mask: list[bool], open_idx: int, open_ch: str = "{", close_ch: str = "}") -> int:
    depth = 0
    for i in range(open_idx, len(src)):
        if not mask[i]:
            continue
        if src[i] == open_ch:
            depth += 1
        elif src[i] == close_ch:
            depth -= 1
            if depth == 0:
                return i
    raise ValueError(f"unbalanced {open_ch}{close_ch} from offset {open_idx}")


def statement_end(src: str, mask: list[bool], start: int) -> int:
    """Index just past the `;` that ends the statement starting at `start`."""
    depth = 0
    for i in range(start, len(src)):
        if not mask[i]:
            continue
        c = src[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == ";" and depth == 0:
            return i + 1
    raise ValueError(f"unterminated statement at offset {start}")


def is_word_start(src: str, i: int) -> bool:
    prev = src[i - 1]
    return not (prev.isalnum() or prev == "_")


def helper_call_counts(src: str, mask: list[bool]) -> dict[str, int]:
    """Number of call sites (not definitions) of each helper in the whole file."""
    counts: dict[str, int] = {}
    for call in HELPER_CALL_RE.finditer(src):
        i = call.start()
        if mask[i] and is_word_start(src, i) and not src[:i].rstrip().endswith("function"):
            counts[call.group(1)] = counts.get(call.group(1), 0) + 1
    return counts


def find_mutants(src: str) -> list[Mutant]:
    mask = code_mask(src)
    call_counts = helper_call_counts(src, mask)
    mutants: list[Mutant] = []
    for fn in FUNCTION_RE.finditer(src):
        if not mask[fn.start()]:
            continue
        body_open = next(i for i in range(fn.end(), len(src)) if mask[i] and src[i] in "{;")
        if src[body_open] == ";":  # declaration without a body
            continue
        body_close = match_close(src, mask, body_open)
        i = body_open + 1
        while i < body_close:
            if not mask[i]:
                i += 1
                continue
            at_word = is_word_start(src, i)
            is_revert = at_word and src.startswith("revert", i) and not (src[i + 6].isalnum() or src[i + 6] == "_")
            line_start = src.rfind("\n", 0, i) + 1
            call = HELPER_CALL_RE.match(src, i) if at_word else None
            line = src.count("\n", 0, i) + 1
            if is_revert or (call and src[line_start:i].strip() == ""):
                end = statement_end(src, mask, i)
                mutants.append(
                    Mutant(
                        function=fn.group(1),
                        line=line,
                        start=i,
                        end=end,
                        snippet=" ".join(src[i:end].split()),
                    )
                )
                i = end
                continue
            if call:
                name = call.group(1)
                if call_counts[name] > 1:
                    template = UNCHECKED_EQUIVALENT.get(name)
                    if template is None:
                        raise ValueError(
                            f"{TARGET}:{line}: `{name}(...)` is used as a value and has {call_counts[name]} "
                            "call sites; add an UNCHECKED_EQUIVALENT entry so this call site gets its own mutant"
                        )
                    close = match_close(src, mask, call.end() - 1, "(", ")")
                    mutants.append(
                        Mutant(
                            function=fn.group(1),
                            line=line,
                            start=i,
                            end=close + 1,
                            snippet=" ".join(src[i : close + 1].split()),
                            replacement=template.format(args=src[call.end() : close].strip()),
                        )
                    )
                i = call.end()
                continue
            i += 1
    return mutants


def run_forge(root: Path) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "FOUNDRY_PROFILE": "default"}
    return subprocess.run([FORGE, *FORGE_ARGS], cwd=root, env=env, capture_output=True, text=True)


def first_failure(output: str) -> str | None:
    for line in output.splitlines():
        if line.startswith("[FAIL"):
            return line.strip()
    return None


def parse_shard(flag: str | None) -> tuple[int, int] | None:
    if flag is None:
        return (1, 1)
    match = re.fullmatch(r"--shard=(\d+)/(\d+)", flag)
    if match is None:
        return None
    k, n = int(match.group(1)), int(match.group(2))
    return (k, n) if 1 <= k <= n else None


def main(argv: list[str]) -> int:
    sys.stdout.reconfigure(line_buffering=True)
    args = [a for a in argv[1:] if not a.startswith("--")]
    flags = [a for a in argv[1:] if a.startswith("--")]
    shard_flags = [f for f in flags if f.startswith("--shard=")]
    shard = parse_shard(shard_flags[0] if shard_flags else None)
    if len(args) > 1 or len(shard_flags) > 1 or shard is None or set(flags) - {"--list", *shard_flags}:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        return 2
    root = Path(args[0] if args else ".").resolve()
    target = root / TARGET
    if not target.is_file():
        print(f"error: {target} not found", file=sys.stderr)
        return 2

    original = target.read_text()
    try:
        mutants = find_mutants(original)
    except ValueError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2
    if not mutants:
        print(f"error: no mutants found in {TARGET}", file=sys.stderr)
        return 2
    shard_k, shard_n = shard
    mutants = mutants[shard_k - 1 :: shard_n]

    if "--list" in flags:
        for m in mutants:
            print(f"{TARGET}:{m.line} {m.function}: {m.change}")
        print(f"{len(mutants)} mutants")
        return 0

    if shutil.which(FORGE) is None:
        print(f"error: {FORGE} not found (set FORGE or put forge on PATH)", file=sys.stderr)
        return 2

    baseline = run_forge(root)
    if baseline.returncode != 0:
        print("error: the unmutated suite fails; fix it before running the gate", file=sys.stderr)
        print(baseline.stdout[-4000:], baseline.stderr[-4000:], sep="\n", file=sys.stderr)
        return 2

    survivors: list[Mutant] = []
    broken: list[tuple[Mutant, str, str]] = []
    try:
        for n, m in enumerate(mutants, 1):
            target.write_text(original[: m.start] + m.replacement + original[m.end :])
            result = run_forge(root)
            output = result.stdout + result.stderr
            label = f"[{n}/{len(mutants)}] {TARGET}:{m.line} {m.function}: {m.change}"
            failure = first_failure(output)
            if "Compiler run failed" in output or SOLC_ERROR_RE.search(output):
                broken.append((m, "did not compile", output[-2000:]))
                print(f"BROKEN   {label}")
            elif result.returncode == 0:
                survivors.append(m)
                print(f"SURVIVED {label}")
            elif failure is None:
                reason = f"forge exited {result.returncode} without a failing test"
                broken.append((m, reason, output[-2000:]))
                print(f"ERRORED  {label}")
            else:
                print(f"killed   {label}\n           by {failure}")
    finally:
        target.write_text(original)

    print(f"\n{len(mutants)} mutants: {len(mutants) - len(survivors) - len(broken)} killed, "
          f"{len(survivors)} survived, {len(broken)} did not run")
    for m, reason, tail in broken:
        print(f"\n--- {reason}: {TARGET}:{m.line} {m.change}\n{tail}", file=sys.stderr)
    if broken:
        return 2
    if survivors:
        print("\nSurviving mutants: no test fails when these checks are removed. Add a test per survivor.")
        for m in survivors:
            print(f"  {TARGET}:{m.line} {m.function}: {m.change}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
