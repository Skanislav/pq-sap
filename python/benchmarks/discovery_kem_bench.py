#!/usr/bin/env python3
"""Discovery-KEM comparison — alternatives to Module-LWE for detection.

Framing: spending is a ZK ownership proof, so discovery is "just a KEM" with
no key-homomorphism constraint. The KEM is then chosen on three axes this
benchmark measures across the PQ families liboqs ships:

  1. SCAN COST — a scanner runs decaps on *every* announcement, so decaps
     latency is the scanning bottleneck (not keygen, which is one-time).
  2. FOOTPRINT — under ZK-spend the meta-address sheds the full-precision
     ML-DSA `t` (4,416 B) and carries only version + a 32-B commitment + the
     KEM public key. The announcement carries the KEM ciphertext.
  3. ON-CHAIN — the announcement's EIP-7623 calldata-floor gas (same model as
     onchain_cost.py, which reproduces the measured 67,580-gas ML-KEM number).

Security levels are NOT uniform across rows (each family's smallest set sits
at a different level); the level column says where each sits. ML-KEM-768 (our
default, level 3) is included as the reference. CSIDH (isogeny NIKE, ~64-B
keys) is listed from literature — it is not in liboqs, so it is not timed.

Usage: discovery_kem_bench.py [--reps 60] [--json out]
"""

import argparse
import json
import os
import statistics
import time

import oqs
from onchain_cost import (
    G_TX,
    TOTAL_COST_FLOOR_PER_TOKEN,
    abi_encode_announce,
    byte_stats,
    calldata_tokens,
)

# (liboqs name, family, assumption, NIST level label).
# Grouped by matched security level so rows compare like against like;
# our default (ML-KEM-768, L3) is the reference row.
KEMS = [
    # --- level 1 ---
    ("ML-KEM-512", "lattice", "Module-LWE", "L1"),
    ("NTRU-HPS-2048-509", "lattice", "NTRU", "L1"),
    ("FrodoKEM-640-AES", "lattice", "LWE (unstructured)", "L1"),
    ("HQC-1", "code", "quasi-cyclic codes", "L1"),
    ("BIKE-L1", "code", "quasi-cyclic codes", "L1"),
    ("Classic-McEliece-348864", "code", "Goppa codes", "L1"),
    # --- level 3 (our default level) ---
    ("ML-KEM-768", "lattice", "Module-LWE", "L3*"),   # our default (reference)
    ("sntrup761", "lattice", "NTRU", "~L2"),
    ("NTRU-HPS-2048-677", "lattice", "NTRU", "L3"),
    ("NTRU-HRSS-701", "lattice", "NTRU", "L3"),
    ("FrodoKEM-976-AES", "lattice", "LWE (unstructured)", "L3"),
    ("HQC-3", "code", "quasi-cyclic codes", "L3"),
    ("BIKE-L3", "code", "quasi-cyclic codes", "L3"),
    ("Classic-McEliece-460896", "code", "Goppa codes", "L3"),
]
# Literature rows: not in liboqs, so sizes/assumptions only (no local timing).
# decaps_ms None = not timed here; CSIDH carries a literature figure since its
# scan cost is the whole argument against it.
LITERATURE = [
    {"name": "CSIDH-512", "family": "isogeny", "assumption": "isogeny (NIKE)",
     "level": "~L1(disputed)", "pk": 64, "ct": 64, "decaps_ms": 80.0,
     "note": "true PQ NIKE; ~40-300 ms/op constant-time; params contested"},
    {"name": "Saber (lit.)", "family": "lattice", "assumption": "Module-LWR",
     "level": "L3", "pk": 992, "ct": 1088, "decaps_ms": None,
     "note": "NIST round-3 finalist, not selected; dropped from liboqs"},
    {"name": "NewHope-1024 (lit.)", "family": "lattice", "assumption": "Ring-LWE",
     "level": "L5", "pk": 1824, "ct": 2208, "decaps_ms": None,
     "note": "round-2 exit; rank-1 module (less conservative than MLWE)"},
]

SCHEME_ID = 2


def median_ms(fn, reps):
    xs = []
    for _ in range(reps):
        t = time.perf_counter()
        fn()
        xs.append((time.perf_counter() - t) * 1e3)
    return statistics.median(xs)


def decaps_median_ms(mech, reps):
    """Isolated decaps latency: one scanner object we own, reused in a loop —
    exactly the scanning inner loop, no per-call object/keygen overhead."""
    scanner = oqs.KeyEncapsulation(mech)
    ek = scanner.generate_keypair()
    ct, _ = oqs.KeyEncapsulation(mech).encap_secret(ek)
    return median_ms(lambda: scanner.decap_secret(ct), reps)


def announce_floor_gas(ct_len: int) -> int:
    """EIP-7623 calldata-floor gas for announce(schemeId, addr, ct, viewtag).
    Ciphertext is pseudorandom → ~all-nonzero; use random bytes for honest
    token counting."""
    ct = os.urandom(ct_len)
    addr = bytes(range(1, 21))          # 20 nonzero bytes
    metadata = b"\x2a"                   # 1-byte view tag
    calldata = abi_encode_announce(SCHEME_ID, addr, ct, metadata)
    z, nz = byte_stats(calldata)
    return G_TX + TOTAL_COST_FLOOR_PER_TOKEN * calldata_tokens(z, nz)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=60)
    ap.add_argument("--json", default=None)
    args = ap.parse_args()

    rows = []
    for name, family, assumption, level in KEMS:
        with oqs.KeyEncapsulation(name) as k:
            d = k.details
            pk, ct = d["length_public_key"], d["length_ciphertext"]
        # McEliece decaps is ~ms; cap its reps so the run stays quick.
        reps = args.reps if pk < 100_000 else max(15, args.reps // 4)
        keygen = median_ms(lambda: oqs.KeyEncapsulation(name).generate_keypair(),
                           min(reps, 15) if pk < 100_000 else 5)
        decaps = decaps_median_ms(name, reps)
        meta_addr = 1 + 32 + pk          # ZK-spend: version + commitment + KEM pk
        announce_gas = announce_floor_gas(ct)
        rows.append({
            "name": name, "family": family, "assumption": assumption,
            "level": level, "pk_B": pk, "ct_B": ct,
            "keygen_ms": round(keygen, 3), "decaps_ms": round(decaps, 4),
            "scan80k_s": round(decaps * 80_000 / 1e3, 2),
            "meta_addr_B": meta_addr, "announce_gas": announce_gas,
        })

    lit_rows = []
    for c in LITERATURE:
        lit_rows.append({
            "name": c["name"], "family": c["family"],
            "assumption": c["assumption"], "level": c["level"],
            "pk_B": c["pk"], "ct_B": c["ct"],
            "decaps_ms": c["decaps_ms"],
            "scan80k_s": (round(c["decaps_ms"] * 80_000 / 1e3, 1)
                          if c["decaps_ms"] else None),
            "meta_addr_B": 1 + 32 + c["pk"],
            "announce_gas": announce_floor_gas(c["ct"]),
            "note": c["note"],
        })

    # ---- report ----
    def fmt(v, w, prec=None):
        if v is None:
            return f"{'-':>{w}}"
        return f"{v:>{w},}" if prec is None else f"{v:>{w}.{prec}f}"

    print("DISCOVERY-KEM COMPARISON  (ZK-spend: meta-addr = 33 + KEM pk; "
          "scan80k = decaps-bound projection for an 80,000-announcement registry)")
    header = (f"{'KEM':<26}{'assumption':<20}{'lvl':>6}{'pk B':>8}{'ct B':>8}"
              f"{'decaps ms':>10}{'scan80k s':>10}{'meta B':>9}{'announce gas':>13}")
    for lvl_group, title in (("L1", "-- level 1 --"),
                             ("L3", "-- level 3 (default level) --")):
        print(f"\n{title}")
        print(header)
        print("-" * 110)
        for r in rows:
            if not r["level"].lstrip("~*").startswith(lvl_group) and \
               not (lvl_group == "L3" and r["level"] in ("~L2", "L3*")):
                continue
            print(f"{r['name']:<26}{r['assumption']:<20}{r['level']:>6}"
                  f"{r['pk_B']:>8}{r['ct_B']:>8}{fmt(r['decaps_ms'],10,4)}"
                  f"{fmt(r['scan80k_s'],10,2)}{r['meta_addr_B']:>9}"
                  f"{r['announce_gas']:>13,}")
    print("\n-- literature (not in liboqs; sizes from the papers) --")
    print(header)
    print("-" * 110)
    for r in lit_rows:
        print(f"{r['name']:<26}{r['assumption']:<20}{r['level']:>6}"
              f"{r['pk_B']:>8}{r['ct_B']:>8}{fmt(r['decaps_ms'],10,1)}"
              f"{fmt(r['scan80k_s'],10,1)}{r['meta_addr_B']:>9}"
              f"{r['announce_gas']:>13,}")

    # ---- takeaways ----
    fast_decaps = min(rows, key=lambda r: r["decaps_ms"])
    slow_decaps = max(rows, key=lambda r: r["decaps_ms"])
    mlkem768 = next(r for r in rows if r["name"] == "ML-KEM-768")
    l3 = [r for r in rows if r["level"] in ("L3", "L3*", "~L2")]
    ntru_best = min((r for r in l3 if r["assumption"] == "NTRU"),
                    key=lambda r: r["decaps_ms"], default=None)
    csidh = lit_rows[0]
    print(f"\nSCAN (decaps-bound, the axis that decides it): "
          f"{mlkem768['name']} scans 80k in {mlkem768['scan80k_s']:.1f} s; "
          f"best NTRU at level ({ntru_best['name']}) {ntru_best['scan80k_s']:.1f} s; "
          f"slowest benchmarked ({slow_decaps['name']}) "
          f"{slow_decaps['scan80k_s']:.0f} s; "
          f"CSIDH (lit.) ~{csidh['scan80k_s']/60:.0f} min. "
          f"Spread {slow_decaps['decaps_ms']/fast_decaps['decaps_ms']:.0f}x "
          f"across benchmarked rows.")
    print(f"FOOTPRINT: CSIDH (lit.) meta-addr {csidh['meta_addr_B']} B is the "
          f"only sub-ML-KEM option; Classic-McEliece inverts (huge pk, "
          f"{min(r['ct_B'] for r in rows)}-B ct -> cheapest announcement "
          f"{min(r['announce_gas'] for r in rows):,} gas).")
    print(f"ZK-spend already shrinks the ML-KEM-768 meta-addr from 5,633 B to "
          f"{mlkem768['meta_addr_B']} B (dropped the 4,416-B ML-DSA t).")

    if args.json:
        json.dump({"benchmarked": rows, "literature": lit_rows},
                  open(args.json, "w"), indent=2)
        print(f"\nwrote {args.json}")


if __name__ == "__main__":
    main()
