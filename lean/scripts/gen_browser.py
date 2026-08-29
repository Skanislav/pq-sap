#!/usr/bin/env python3
"""Generate per-module theorem/proof browser pages for the wiki.

Reads lean/PqStealth/<Module>.lean (excluding Axioms.lean), extracts
public declarations with docstrings, splits statements and tactic proofs,
and emits:

  lean/docs-proofs/<module>.md      -- one page per module
  lean/docs-proofs/index.md         -- landing page listing every module
  wiki/src/generated/theoremIndex.json -- index used by the linker plugin

No Lean toolchain is required; this is a stdlib-only Python script.
"""

from __future__ import annotations

import json
import re
import textwrap
from pathlib import Path

LEAN = Path(__file__).resolve().parent.parent
PQSTEALTH = LEAN / "PqStealth"
OUT_DIR = LEAN / "docs-proofs"
INDEX_PATH = LEAN.parent / "wiki" / "src" / "generated" / "theoremIndex.json"

GITHUB = "https://github.com/Skanislav/pq-sap"
BRANCH = "main"

# Matches a Lean identifier, including unicode primes and subscript digits
# used in a few declaration names (e.g. card_fiber_eval', evalDist_pull₆).
IDENT_RE = r"[A-Za-z_][\w.'\u1D09\u2083\u2084\u2085\u2086]*"
DECL_KEYWORDS = (
    "theorem|lemma|def|abbrev|structure|class|instance|inductive|opaque|axiom|example"
)
DECL_PAT = re.compile(
    rf"^(?:@[\[\]\w\s,\.\(\)]+\s+)?"
    rf"(?:private\s+|protected\s+|noncomputable\s+|nonrec\s+|unsafe\s+)*"
    rf"({DECL_KEYWORDS})\s+({IDENT_RE})\b",
    re.M,
)
BOUNDARY_PAT = re.compile(
    rf"^(?:{DECL_KEYWORDS})\b|"
    r"^(?:/--|/-!|namespace|section|variable|open|end|set_option|attribute|"
    r"#guard_msgs|#check|#eval|#print|#reduce)(?:\s|$)"
)

# Axiom badge parsing from Axioms.lean.
AXIOM_INFO_PAT = re.compile(
    r"/--\s+info:\s+'PqStealth\.([\w.'\u1D09\u2083\u2084\u2085\u2086]+)'"
    r"\s+(?:depends on axioms:\s*\[([^\]]*)\]|does not depend on any axioms)\s+-/"
)


def clean_comment(raw: str) -> str:
    """Strip `/--`/`/-!` and `-/` and dedent a doc-comment block."""
    body = raw.removeprefix("/--").removeprefix("/-!")
    if body.rstrip().endswith("-/"):
        body = body.rsplit("-/", 1)[0]
    return textwrap.dedent(body).strip()


def extract_intro_and_sections(
    lines: list[str],
) -> tuple[str | None, list[tuple[int, str]]]:
    """Find the module-level `/-!` intro and any `/-! ## Section -/` headings."""
    intro: str | None = None
    sections: list[tuple[int, str]] = []

    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.startswith("/-!"):
            i += 1
            continue
        block = [line]
        j = i
        while "-/" not in line and j + 1 < len(lines):
            j += 1
            line = lines[j]
            block.append(line)
        body = clean_comment("\n".join(block))
        # Strip leading `# Title` from the intro; the page already has its own H1.
        if intro is None:
            body = re.sub(r"^#\s+.+?\n+", "", body, count=1)
            intro = body
        else:
            m = re.match(r"##?\s+(.+?)\s*$", body, re.M)
            if m:
                sections.append((i + 1, m.group(1).strip()))
        i = j + 1
    return intro, sections


def find_declarations(lines: list[str]) -> list[dict]:
    """Return list of declaration dicts with name/doc/src range/attrs."""
    decls: list[dict] = []
    pending_doc: str | None = None
    pending_attrs: list[str] = []

    def declaration_end(start_1idx: int) -> int:
        # First line with non-empty, column-0 content that is a boundary.
        for j in range(start_1idx + 1, len(lines) + 1):
            if j - 1 >= len(lines):
                return len(lines) + 1
            line = lines[j - 1]
            if line.strip() == "" or line.startswith(" "):
                continue
            if BOUNDARY_PAT.match(line):
                return j
        return len(lines) + 1

    i = 0
    while i < len(lines):
        line = lines[i]

        if line.startswith("/--"):
            block = [line]
            j = i
            while "-/" not in line and j + 1 < len(lines):
                j += 1
                line = lines[j]
                block.append(line)
            pending_doc = clean_comment("\n".join(block))
            i = j + 1
            continue

        attr_match = re.match(r"^@\[.*\]\s*$", line)
        if attr_match:
            pending_attrs.append(line)
            i += 1
            continue

        m = DECL_PAT.match(line)
        if m:
            start = i + 1  # 1-indexed line number
            end = declaration_end(start)
            src = "\n".join(lines[start - 1 : end - 1])
            decls.append(
                {
                    "name": m.group(2),
                    "kind": m.group(1),
                    "doc": pending_doc,
                    "attrs": list(pending_attrs),
                    "start": start,
                    "end": end - 1,
                    "src": src,
                }
            )
            pending_doc = None
            pending_attrs = []
            i = end
            continue

        i += 1

    return decls


def split_statement_proof(src: str) -> tuple[str, str | None]:
    """Split a declaration into statement and tactic proof body.

    Returns (statement, proof_body_or_None).  If no `:= by` is found, the
    whole source is the statement and proof is None.  The statement keeps the
    `:= by` line; the proof body starts with the line after it.
    """
    lines = src.splitlines()
    for idx, line in enumerate(lines):
        if re.search(r"\s*:=\s*by\b", line):
            statement = "\n".join(lines[: idx + 1])
            proof = "\n".join(lines[idx + 1 :])
            return statement, proof if proof.strip() else None
    return src, None


def load_axiom_map() -> dict[str, tuple[list[str], bool]]:
    """Map short declaration name -> (axiom list, sorry-free flag)."""
    axioms: dict[str, tuple[list[str], bool]] = {}
    text = (PQSTEALTH / "Axioms.lean").read_text()
    for m in AXIOM_INFO_PAT.finditer(text):
        full_name = m.group(1)
        short = full_name.split(".")[-1]
        if "depends on axioms" in m.group(0):
            raw = m.group(2)
            ax_list = [a.strip() for a in raw.split(",") if a.strip()]
        else:
            ax_list = []
        sorry_free = "sorryAx" not in ax_list
        axioms[short] = (ax_list, sorry_free)
    return axioms


def github_permalink(module: str, start: int, end: int) -> str:
    return f"{GITHUB}/blob/{BRANCH}/lean/PqStealth/{module}.lean#L{start}-L{end}"


def slugify(name: str) -> str:
    """Best-effort Python mirror of github-slugger for identifier-only text.

    The browser headings are `## `name``; rehype-slug/toString strips the
    backticks and passes the identifier to github-slugger.  Identifiers are
    mostly ASCII alphanumerics and underscores, with a few containing unicode
    subscript digits or trailing primes.  github-slugger strips punctuation and
    subscript digits, so we do the same.
    """
    lowered = name.lower()
    # github-slugger strips subscript digits and apostrophes/primes.
    no_sub = re.sub(r"[\u2080-\u209F'']", "", lowered)
    slug = re.sub(r"[^\w\s-]", "", no_sub, flags=re.UNICODE).strip().replace(" ", "-")
    return slug


def render_module_page(
    module: str,
    intro: str | None,
    sections: list[tuple[int, str]],
    decls: list[dict],
    axiom_map: dict[str, tuple[list[str], bool]],
) -> str:
    out_lines: list[str] = [f"# {module}", ""]

    if intro:
        out_lines.append(intro)
        out_lines.append("")

    # Build a section iterator. Each section heading is active for declarations
    # whose start line is at or after the heading line, until the next heading.
    section_iter = iter(sections)
    current_section = next(section_iter, None)
    next_section = next(section_iter, None)

    for decl in decls:
        while next_section and next_section[0] <= decl["start"]:
            if current_section:
                out_lines.append(f"### {current_section[1]}")
                out_lines.append("")
            current_section = next_section
            next_section = next(section_iter, None)

        name = decl["name"]
        out_lines.append(f"## `{name}`")
        out_lines.append("")

        if decl["doc"]:
            out_lines.append(decl["doc"])
            out_lines.append("")

        badge = axiom_map.get(name.split(".")[-1])
        if badge:
            ax_list, sorry_free = badge
            ax_text = ", ".join(ax_list) if ax_list else "none"
            sorry_text = "sorry-free ✓" if sorry_free else "uses `sorry` ✗"
            out_lines.append(f"`axioms: {ax_text}` · {sorry_text}")
            out_lines.append("")

        statement, proof = split_statement_proof(decl["src"])
        out_lines.append("```lean")
        out_lines.append(statement)
        out_lines.append("```")
        out_lines.append("")

        if proof:
            out_lines.append(":::details[proof]")
            out_lines.append("")
            out_lines.append("```lean")
            out_lines.append(proof)
            out_lines.append("```")
            out_lines.append("")
            out_lines.append(":::")
            out_lines.append("")

        link = github_permalink(module, decl["start"], decl["end"])
        out_lines.append(f"[`{module}.lean:{decl['start']}-{decl['end']} ↗`]({link})")
        out_lines.append("")

    return "\n".join(out_lines).rstrip() + "\n"


def module_summary(module: str, intro, decls: list[dict], axiom_map: dict) -> dict:
    """One row of the landing page: declaration count, sorry status, first sentence."""
    text = intro if isinstance(intro, str) else "\n".join(intro)
    first_para = text.strip().split("\n\n")[0].replace("\n", " ").strip()
    m = re.match(r"(.+?[.!?])(\s|$)", first_para)
    blurb = m.group(1) if m else first_para
    if len(blurb) > 160:
        blurb = blurb[:160].rsplit(" ", 1)[0].rstrip(" ,;:-\u2013\u2014") + " \u2026"
    checked = sorry = 0
    for decl in decls:
        badge = axiom_map.get(decl["name"].split(".")[-1])
        if badge is None:
            continue
        checked += 1
        if not badge[1]:
            sorry += 1
    if checked == 0:
        status = "—"
    elif sorry == 0:
        status = "sorry-free ✓"
    else:
        status = f"uses `sorry` ✗ ({sorry})"
    return {"module": module, "count": len(decls), "status": status, "blurb": blurb}


def render_index_page(summaries: list[dict]) -> str:
    total = sum(s["count"] for s in summaries)
    out = [
        "# Lean proof browser",
        "",
        f"{len(summaries)} modules, {total} public declarations from "
        "`lean/PqStealth/*.lean`, one page per module. Every page shows each "
        "declaration's docstring, statement, "
        "axiom badge, a collapsible tactic proof and a GitHub permalink. Inline "
        "theorem names anywhere on this site link here.",
        "",
        "| Module | Declarations | Axioms | Summary |",
        "|---|---:|---|---|",
    ]
    for s in summaries:
        blurb = s["blurb"].replace("|", "\\|")
        link = f"[{s['module']}]({s['module'].lower()}.md)"
        out.append(f"| {link} | {s['count']} | {s['status']} | {blurb} |")
    return "\n".join(out) + "\n"


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    INDEX_PATH.parent.mkdir(parents=True, exist_ok=True)

    axiom_map = load_axiom_map()

    index: dict[str, dict] = {}
    summaries: list[dict] = []

    for path in sorted(PQSTEALTH.glob("*.lean")):
        if path.name in ("Axioms.lean", "PqStealth.lean"):
            continue
        module = path.stem
        lines = path.read_text().splitlines()

        intro, sections = extract_intro_and_sections(lines)
        decls = find_declarations(lines)

        page = render_module_page(module, intro, sections, decls, axiom_map)
        (OUT_DIR / f"{module.lower()}.md").write_text(page)
        summaries.append(module_summary(module, intro, decls, axiom_map))

        for decl in decls:
            name = decl["name"]
            short = name.split(".")[-1]
            entry = {
                "route": f"/lean/proofs/{module.lower()}",
                "slug": slugify(name),
                "module": module,
            }
            index[short] = entry
            # Also index dotted names, e.g. `ProbComp.boolDistAdvantage_congr`.
            if "." in name and name not in index:
                index[name] = entry

    (OUT_DIR / "index.md").write_text(render_index_page(summaries))
    INDEX_PATH.write_text(json.dumps(index, indent=2, sort_keys=True) + "\n")

    print(f"gen-browser: wrote {len(list(OUT_DIR.glob('*.md')))} pages to {OUT_DIR}")
    print(f"gen-browser: wrote {len(index)} entries to {INDEX_PATH}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
