#!/usr/bin/env python3
"""Enforce D-032: no ERC-8441 (scheme-3) work on `main`.

D-032 keeps that proposal out of this repository. The rule was enforced by
inspection only; this script makes it checkable. It scans every file that would
land on `main` (tracked, plus untracked but not gitignored, so a stray module
fails before the commit as well as after) for identifiers that only exist in
that work tree:

    Scheme3Wire, ANOAssumption, ClosedUnlinkability, HybridKEM, fo-rom,
    scheme3-… / scheme-3-… identifiers, and any *path* named 8441 / scheme-3

Deliberately NOT matched in file content: the bare string "8441". Prose that
records the separation (D-032 itself, README, AGENTS.md) must stay legal, and
four hex digits occur inside vector constants by chance.
Textual mentions are a review question; what this guards is *code and paths*.

`ALLOWED_PATHS` lists the files where a textual mention is the point; a hit
anywhere else fails.

Usage: python3 scripts/check_scope.py [--verbose]
Exit 1 on any hit.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Code identifiers that only exist in the scheme-3 work tree.
PATTERNS = [
    re.compile(r"Scheme3Wire"),
    re.compile(r"ANOAssumption"),
    re.compile(r"ClosedUnlinkability"),
    re.compile(r"HybridKEM"),
    re.compile(r"fo-rom"),
    re.compile(r"\bscheme3[-_A-Za-z]"),
    re.compile(r"\bscheme-3[-_A-Za-z]"),
]

# Path-shaped hits: a file *named* after the proposal, anywhere on main.
PATH_PATTERNS = [re.compile(r"(?i)8441"), re.compile(r"(?i)scheme-?3")]

# Paths where a textual mention is the point (the rule itself and the docs that
# record why it exists). Keep this list short and stable.
ALLOWED_PATHS = (
    "docs/DECISIONS.md",          # D-032 / D-033 (the rule itself)
    "wiki/src/pages/spec/decisions.md",  # generated mirror of the above
    "AGENTS.md",
    "README.md",
    "scripts/check_scope.py",
    ".gitignore",
)

SKIP_SUFFIXES = ("-lock.json", "pnpm-lock.yaml", "package-lock.json")


def tracked_files() -> list[str]:
    """Every file that would land on `main`: tracked, plus untracked but not
    gitignored (so a new file is caught before it is committed, not after)."""
    env = {"GIT_CONFIG_GLOBAL": "/dev/null", "PATH": "/usr/bin:/bin"}
    def git(*args: str) -> list[str]:
        out = subprocess.run(["git", "-C", str(ROOT), *args],
                             capture_output=True, text=True, check=True, env=env)
        return [line for line in out.stdout.splitlines() if line]
    return git("ls-files") + git("ls-files", "--others", "--exclude-standard")


def main() -> int:
    verbose = "--verbose" in sys.argv
    hits: list[tuple[str, int, str]] = []
    for rel in tracked_files():
        if rel.endswith(SKIP_SUFFIXES) or any(rel.startswith(p) for p in ALLOWED_PATHS):
            continue
        path = ROOT / rel
        try:
            text = path.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        if any(p.search(rel) for p in PATH_PATTERNS):
            hits.append((rel, 0, "path names the ERC-8441 / scheme-3 work"))
            continue
        if "\x00" in text:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for pattern in PATTERNS:
                if pattern.search(line):
                    hits.append((rel, lineno, line.strip()[:120]))
                    break

    if hits:
        print(f"D-032 violation: {len(hits)} line(s) reference scheme-3 / ERC-8441 work")
        for rel, lineno, line in hits:
            print(f"  {rel}:{lineno}: {line}")
        print("\nThat work lives on its branch only (D-032). Remove it from `main`.")
        return 1
    if verbose:
        print(f"ok: scanned {len(tracked_files())} tracked files, no scheme-3/ERC-8441 code")
    else:
        print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
