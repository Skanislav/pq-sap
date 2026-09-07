#!/usr/bin/env python3
"""Keep the key-exchange parameter table identical across its four copies:

  * src/StealthKeyExchange.sol      (`uint256 public constant X = N;`)
  * lean/StealthKeyExchange/Params.lean  (`| .set => N` under each size function)
  * js-client/src/key-exchange.ts   (`KEM_SIZES` table)
  * python/vectors/v0/vectors.json  (declared and measured sizes of the default set)

The Lean theorems are about the Lean numbers; the Foundry tests run against the
Solidity numbers; this script is what makes the two the same table. Stdlib
only, exits 1 on any drift. Same idea as lean/scripts/check_sizes.py.

Usage: python3 check_constants.py   (from anywhere)
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CONTRACTS = HERE.parents[1]
ROOT = HERE.parents[3]
SOL = CONTRACTS / "src" / "StealthKeyExchange.sol"
LEAN = CONTRACTS / "lean" / "StealthKeyExchange" / "Params.lean"
TS = ROOT / "js-client" / "src" / "key-exchange.ts"
VECTORS = ROOT / "python" / "vectors" / "v0" / "vectors.json"

SETS = ["mlkem512", "mlkem768", "mlkem1024", "xwing"]
SOL_NAMES = {"mlkem512": "MLKEM512", "mlkem768": "MLKEM768", "mlkem1024": "MLKEM1024", "xwing": "XWING"}


def sol_constants() -> dict[str, int]:
    src = SOL.read_text()
    out = {m[1]: int(m[2], 0) for m in re.finditer(r"constant\s+(\w+)\s*=\s*(0x[0-9a-fA-F]+|\d+);", src)}
    # enum order is the ABI value; Lean's constructor order must match
    enum = re.search(r"enum Kem \{([^}]*)\}", src)
    out["__enum__"] = [x.strip() for x in enum[1].split(",") if x.strip()]  # type: ignore[assignment]
    return out


def lean_table(fn: str) -> dict[str, int]:
    """`| .set => N` rows of `def Kem.<fn> : Kem → Nat`."""
    src = LEAN.read_text()
    body = src[src.index(f"def Kem.{fn} "):]
    body = body[: body.index("\n\n")]
    rows = {m[1]: int(m[2]) for m in re.finditer(r"\|\s*\.(\w+)\s*=>\s*(\d+)", body)}
    missing = [s for s in SETS if s not in rows]
    if missing:
        sys.exit(f"Params.lean: Kem.{fn} has no row for {missing}")
    return rows


def lean_scalar(name: str) -> int:
    m = re.search(rf"def {re.escape(name)} : (?:Nat|UInt8) := (0x[0-9a-fA-F]+|\d+)", LEAN.read_text())
    if not m:
        sys.exit(f"Params.lean: def {name} not found")
    return int(m[1], 0)


def lean_enum() -> list[str]:
    src = LEAN.read_text()
    body = src[src.index("inductive Kem where"):]
    body = body[: body.index("deriving")]
    return re.findall(r"^\s*\|\s*(\w+)", body, re.M)


def ts_table() -> dict[str, dict[str, int]]:
    src = TS.read_text()
    body = src[src.index("KEM_SIZES"):]
    body = body[: body.index("} as const")]
    out = {}
    for m in re.finditer(r"(\w+):\s*\{\s*ek:\s*(\d+),\s*ct:\s*(\d+)\s*\}", body):
        out[m[1]] = {"ek": int(m[2]), "ct": int(m[3])}
    return out


def main() -> int:
    sol = sol_constants()
    ct, ek, packed = lean_table("ciphertextBytes"), lean_table("encapsulationKeyBytes"), lean_table("packedTBytes")
    ts = ts_table()
    v = json.loads(VECTORS.read_text())
    rows: list[tuple[str, object, object]] = []

    for s in SETS:
        n = SOL_NAMES[s]
        rows.append((f"{s} ciphertext: sol vs lean", sol[f"{n}_CT_BYTES"], ct[s]))
        rows.append((f"{s} ek: sol vs lean", sol[f"{n}_EK_BYTES"], ek[s]))
        rows.append((f"{s} ciphertext: ts vs lean", ts[n]["ct"], ct[s]))
        rows.append((f"{s} ek: ts vs lean", ts[n]["ek"], ek[s]))
    rows.append(("packed t, ML-DSA-44: sol vs lean", sol["PACKED_T_BYTES_MLDSA44"], packed["mlkem512"]))
    rows.append(("packed t, ML-DSA-65: sol vs lean", sol["PACKED_T_BYTES_MLDSA65"], packed["mlkem768"]))
    rows.append(("packed t, ML-DSA-65 (xwing): sol vs lean", sol["PACKED_T_BYTES_MLDSA65"], packed["xwing"]))
    rows.append(("packed t, ML-DSA-87: sol vs lean", sol["PACKED_T_BYTES_MLDSA87"], packed["mlkem1024"]))
    rows.append(("scheme id: sol vs lean", sol["SCHEME_ID"], lean_scalar("schemeId")))
    rows.append(("view tag bytes: sol vs lean", sol["VIEW_TAG_BYTES"], lean_scalar("viewTagBytes")))
    rows.append(("meta version mlkem: sol vs lean", sol["META_VERSION_MLKEM"], lean_scalar("metaVersionMlkem")))
    rows.append(("meta version xwing: sol vs lean", sol["META_VERSION_XWING"], lean_scalar("metaVersionXwing")))
    rows.append(("enum order: sol vs lean", [x.lower() for x in sol["__enum__"]], lean_enum()))
    rows.append(("enum order: ts vs sol", list(ts.keys()), sol["__enum__"]))

    # the vectors: declared sizes and measured hex lengths of the default set
    case = v["cases"][0]["announcement"]
    rcpt = next(iter(v["recipients"].values()))
    meta_len = len(rcpt["meta_address"].removeprefix("0x")) // 2
    rows.append(("scheme id: vectors vs lean", v["scheme_id"], lean_scalar("schemeId")))
    rows.append(("view tag bytes: vectors vs lean", v["view_tag_bytes"], lean_scalar("viewTagBytes")))
    rows.append(("ML-KEM-768 ciphertext: vectors vs lean", v["sizes"]["ephemeral_pub_key"], ct["mlkem768"]))
    rows.append(("ML-KEM-768 ciphertext, measured: vectors vs lean",
                 len(case["ephemeral_pub_key"].removeprefix("0x")) // 2, ct["mlkem768"]))
    rows.append(("meta-address: vectors vs lean 1+32+t+ek", v["sizes"]["meta_address"],
                 1 + 32 + packed["mlkem768"] + ek["mlkem768"]))
    rows.append(("meta-address, measured: vectors vs lean", meta_len, 1 + 32 + packed["mlkem768"] + ek["mlkem768"]))
    rows.append(("meta-address version, measured: vectors vs lean",
                 int(rcpt["meta_address"][2:4], 16), lean_scalar("metaVersionMlkem")))

    bad = 0
    for label, a, b in rows:
        ok = a == b
        bad += not ok
        print(f"{'ok  ' if ok else 'DRIFT'} {label}: {a} vs {b}")
    print(f"{len(rows) - bad}/{len(rows)} in step")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
