#!/usr/bin/env python3
"""Cross-check byte-size constants between the Lean proofs and the reference
implementation's test vectors.

This is the only place where a number proved in Lean is compared against a
number the Python/JS implementations actually emit. Each row below names a
Lean theorem whose statement ends in `= NNNN`, and a value read from
python/vectors/*/vectors.json (a declared `sizes.*` entry or the measured hex
length of a field in the first case/recipient). Known layout differences are
listed in EXPECTED_MISMATCH so they are reported, not failed.

Idea from etheorem's check_constant_tiers.py; see docs/etheorem-lessons.md.

Usage: python3 lean/scripts/check_sizes.py        (exit 1 on any mismatch)
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LEAN = ROOT / "lean" / "PqStealth"
PQ = ROOT / "python" / "vectors" / "v0" / "vectors.json"
CLASSICAL = ROOT / "python" / "vectors" / "classical" / "v0" / "vectors.json"


def lean_rfl_constant(file: str, theorem: str) -> int:
    """Value `NNNN` in `theorem <name> : ... = NNNN := rfl` (statement may span lines)."""
    src = (LEAN / file).read_text()
    m = re.search(rf"theorem {re.escape(theorem)}\b[^:]*:(.*?)=\s*(\d+)\s*:=", src, re.S)
    if not m:
        sys.exit(f"{file}: theorem {theorem} with a numeric RHS not found")
    return int(m[2])


def lean_bytes_width(file: str, theorem: str, binder: str) -> int:
    """Width `n` in `(<binder> : ... → Bytes n)` inside the theorem's signature."""
    src = (LEAN / file).read_text()
    body = src[src.index(f"theorem {theorem}"):]
    m = re.search(rf"\({re.escape(binder)} : [^)]*?Bytes (\d+)\)", body)
    if not m:
        sys.exit(f"{file}: `{binder} : … → Bytes n` not found in {theorem}")
    return int(m[1])


def hexlen(s: str) -> int:
    return len(s.removeprefix("0x")) // 2


def main() -> int:
    pq = json.loads(PQ.read_text())
    cl = json.loads(CLASSICAL.read_text())
    pq_case, cl_case = pq["cases"][0], cl["cases"][0]
    pq_rcpt = next(iter(pq["recipients"].values()))

    rows = [
        # (label, lean value, vector value, source description)
        ("meta address (ML-DSA-65 + ML-KEM-768)",
         lean_rfl_constant("Invariants.lean", "metaAddress_size_mldsa65_mlkem768"),
         pq["sizes"]["meta_address"], "v0 sizes.meta_address"),
        ("meta address, measured recipient hex",
         lean_rfl_constant("Invariants.lean", "metaAddress_size_mldsa65_mlkem768"),
         hexlen(pq_rcpt["meta_address"]), "v0 recipients[0].meta_address"),
        ("ML-KEM-768 encapsulation key (packEk codomain)",
         lean_bytes_width("Invariants.lean", "meta_address_roundtrips_5633", "packEk"),
         pq["sizes"]["meta_address"] - 1 - 32 - 4416,
         "v0 sizes.meta_address − version(1) − rho(32) − packed t(6·736)"),
        # MLKEM.lean states the ciphertext size only symbolically
        # (`Params.ciphertextBytes mlkem768`, FIPS 203 = 1088); the literal
        # here is that documented value, not a number parsed from Lean.
        ("ML-KEM-768 ciphertext = ephemeral key (FIPS 203 literal)", 1088,
         hexlen(pq_case["announcement"]["ephemeral_pub_key"]), "v0 cases[0].announcement.ephemeral_pub_key"),
        ("ML-KEM-768 ciphertext, classical hybrid (FIPS 203 literal)", 1088,
         hexlen(cl_case["announcement"]["ephemeral_pub_key"]), "classical cases[0].announcement.ephemeral_pub_key"),
        ("ZK meta address (Lean D-012 layout) vs classical hybrid",
         lean_rfl_constant("Invariants.lean", "metaAddressZk_size_mlkem768"),
         cl["sizes"]["meta_address"], "classical sizes.meta_address"),
    ]
    # Lean's ZK layout is version(1) ‖ commitment(32) ‖ ek(1184) = 1217; the
    # classical hybrid vectors carry a 33-byte compressed secp256k1 point instead
    # of a 32-byte commitment, hence 1218. Different layouts, not drift.
    EXPECTED_MISMATCH = {"ZK meta address (Lean D-012 layout) vs classical hybrid": (1217, 1218)}

    bad = 0
    for label, lean_v, vec_v, src in rows:
        if lean_v == vec_v:
            status = "ok"
        elif EXPECTED_MISMATCH.get(label) == (lean_v, vec_v):
            status = "expected difference"
        else:
            status, bad = "MISMATCH", bad + 1
        print(f"{status:19} {label}: lean={lean_v} vectors={vec_v}  [{src}]")
    print(f"{len(rows)} rows, {bad} mismatches")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
