#!/usr/bin/env python3
"""Check `File.lean:N` / `File.lean:N-M` citations in lean/docs and lean/README.md.

Every citation is resolved to a real file (PqStealth, scratch, or the pinned
VCVio checkout under .lake/packages) and the cited line range must exist. When
a declaration name accompanies the citation — either inside the same backticks
(`Security.lean:70 kpke_delta_correct`) or in the backticks immediately before
it (`IsSigningKey` (`Invariants.lean:84-87`)) — the name must occur within the
cited range. `--fix` moves a drifted range to the line that now declares the
name, keeping the span length.

Pattern borrowed from etheorem's scripts/check_citations.py (the idea, not the
code); see docs/etheorem-lessons.md.

Usage: python3 lean/scripts/check_citations.py [--fix] [paths...]
Exit 1 on any unresolved or stale citation.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

LEAN = Path(__file__).resolve().parent.parent
ROOTS = [LEAN / "PqStealth", LEAN, LEAN / "scratch", LEAN / ".lake" / "packages" / "VCVio"]
DEFAULT_DOCS = sorted((LEAN / "docs").glob("*.md")) + [LEAN / "README.md"]

# `name` (`path.lean:N-M`)   or   `path.lean:N-M name`
CITE = re.compile(
    r"(?:`(?P<pre>[A-Za-z_][\w.']*)`\s*\()?"
    r"`(?P<path>[\w./-]+\.lean):(?P<start>\d+)(?:-(?P<end>\d+))?(?:\s+(?P<post>[A-Za-z_][\w.']*))?`"
)
DECL = r"^(?:@\[[^\]]*\]\s*)?(?:private\s+|protected\s+|noncomputable\s+|nonrec\s+|unsafe\s+)*" \
       r"(?:theorem|lemma|def|abbrev|structure|class|instance|inductive|opaque|axiom|example)\s+{name}\b"


def resolve(rel: str) -> Path | None:
    for root in ROOTS:
        for cand in root.rglob(Path(rel).name):
            if str(cand).endswith(rel):
                return cand
    return None


def find_decl(lines: list[str], name: str) -> int | None:
    short = name.split(".")[-1]
    pat = re.compile(DECL.format(name=re.escape(short)))
    for i, line in enumerate(lines, 1):
        if pat.match(line):
            return i
    return None


def check_doc(doc: Path, fix: bool) -> list[str]:
    problems: list[str] = []
    text = doc.read_text()
    out = text
    for m in CITE.finditer(text):
        rel, start = m["path"], int(m["start"])
        end = int(m["end"]) if m["end"] else start
        name = m["post"] or m["pre"]
        shown = doc.relative_to(LEAN) if doc.resolve().is_relative_to(LEAN) else doc
        where = f"{shown}:{text.count(chr(10), 0, m.start()) + 1}"
        f = resolve(rel)
        if f is None:
            problems.append(f"{where}: cannot resolve `{rel}`")
            continue
        lines = f.read_text().splitlines()
        if end > len(lines) or start < 1 or end < start:
            problems.append(f"{where}: `{rel}:{start}-{end}` out of range (file has {len(lines)} lines)")
            continue
        if not name:
            continue
        short = name.split(".")[-1]
        if any(short in l for l in lines[start - 1:end]):
            continue
        new = find_decl(lines, name)
        if new is None:
            problems.append(f"{where}: `{short}` not declared anywhere in {rel} (cited {start}-{end})")
            continue
        span = end - start
        fixed = f"{rel}:{new}" + (f"-{new + span}" if m["end"] else "")
        msg = f"{where}: `{short}` not in {rel}:{start}-{end}; now at {new}"
        if fix:
            out = out.replace(f"`{rel}:{start}" + (f"-{end}" if m["end"] else ""), f"`{fixed}", 1)
            msg += " (fixed)"
        else:
            problems.append(msg)
    if fix and out != text:
        doc.write_text(out)
    return problems


def main(argv: list[str]) -> int:
    fix = "--fix" in argv
    paths = [Path(a) for a in argv if a != "--fix"] or DEFAULT_DOCS
    problems = [p for doc in paths for p in check_doc(doc, fix)]
    for p in problems:
        print(p)
    n = sum(len(CITE.findall(d.read_text())) for d in paths)
    print(f"{n} citations checked, {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
