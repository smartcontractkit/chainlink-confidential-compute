#!/usr/bin/env python3
"""Check that every github.com/smartcontractkit/* direct require resolves
to a single version across all Go modules in the repo.

Skipped:
  - Indirect requires (// indirect).
  - Deps that have a local replace directive in the same module (replace wins).
  - Toy example modules named "hello".

Exits 1 and prints a skew table if any smartcontractkit direct dep is pinned
to more than one version across modules; 0 otherwise.
"""
from __future__ import annotations

import os
import re
import sys
from collections import defaultdict
from pathlib import Path

SCOPE_PREFIX = "github.com/smartcontractkit/"
EXCLUDED_MODULE_NAMES = {"hello"}  # toy examples


def parse_go_mod(path: Path):
    """Return (module_name, direct_requires, replaced_paths).

    direct_requires: dict[dep_path] -> version for direct, non-indirect requires.
    replaced_paths: set of dep paths that are replaced in this module.
    """
    text = path.read_text()
    module_name = ""
    m = re.search(r"^module\s+(\S+)", text, re.MULTILINE)
    if m:
        module_name = m.group(1)

    replaced: set[str] = set()
    for block, single in _iter_block(text, "replace"):
        for line in block + single:
            # replace foo [v1] => bar [v2 | ../local]
            rhs = line.split("=>", 1)
            if len(rhs) != 2:
                continue
            lhs = rhs[0].split()
            if lhs:
                replaced.add(lhs[0])

    requires: dict[str, str] = {}
    for block, single in _iter_block(text, "require"):
        for line in block + single:
            if "// indirect" in line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            requires[parts[0]] = parts[1]

    return module_name, requires, replaced


def _iter_block(text: str, keyword: str):
    """Yield ([block_lines], [single_lines]) for `keyword ( ... )` blocks
    and single `keyword foo bar` lines."""
    block_lines: list[str] = []
    single_lines: list[str] = []
    i = 0
    lines = text.splitlines()
    in_block = False
    for line in lines:
        s = line.strip()
        if not s or s.startswith("//"):
            continue
        if in_block:
            if s == ")":
                in_block = False
            else:
                block_lines.append(s)
            continue
        if s.startswith(f"{keyword} ("):
            in_block = True
            continue
        if s.startswith(f"{keyword} "):
            single_lines.append(s[len(keyword):].strip())
    yield block_lines, single_lines


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    # dep -> version -> set(module dirs)
    records: dict[str, dict[str, set[str]]] = defaultdict(
        lambda: defaultdict(set)
    )

    for go_mod in sorted(root.rglob("go.mod")):
        if "vendor" in go_mod.parts:
            continue
        module_name, requires, replaced = parse_go_mod(go_mod)
        if module_name in EXCLUDED_MODULE_NAMES:
            continue
        mod_dir = str(go_mod.parent.relative_to(root)) or "."
        for dep, version in requires.items():
            if not dep.startswith(SCOPE_PREFIX):
                continue
            if dep in replaced:
                continue
            records[dep][version].add(mod_dir)

    skews = {dep: versions for dep, versions in records.items() if len(versions) > 1}
    if not skews:
        print("OK: all smartcontractkit direct deps are consistent across modules.")
        return 0

    print("FAIL: smartcontractkit direct deps are pinned to multiple versions:")
    for dep in sorted(skews):
        print(f"\n  {dep}")
        for version, mods in sorted(skews[dep].items()):
            print(f"    {version}  <- {sorted(mods)}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
