#!/usr/bin/env python3
"""Hash-only key exchange vs ML-KEM — the cost of "no structured assumption".

Question (2026-08-25): can a SHA-256 / BLAKE3 commitment scheme replace the
discovery KEM (ML-KEM) so the scheme needs no lattice assumption at all?

Theory answer: key exchange from a hash alone has a provable ceiling.
  * Impagliazzo-Rudich (STOC'89): no black-box key exchange from one-way
    functions beyond a polynomial gap; Barak-Mahmoody (CRYPTO'09): every
    random-oracle key exchange where honest parties make n queries is broken
    with O(n^2) queries — Merkle puzzles (1974) are tight.
  * Brassard-Hoyer-Kalach-Kaplan-Laplante-Salvail (CRYPTO'11): against a
    QUANTUM eavesdropper, Merkle's scheme with classical honest parties gives
    NO gap (Eve ~ n via Grover); their best classical-parties scheme gives
    n^{7/6} (a family approaching n^{3/2}), their quantum-parties scheme
    n^{5/3} (a family approaching n^2).

This script turns those exponents into engineering numbers on this machine:
measured hash rates -> honest-party work, recipient "public key" size (the
puzzle set), on-chain cost, vs the measured ML-KEM rows in
discovery_kem_20260801.json. Also times the per-announcement hashing a
scanner does (view tag / KDF) to show the hash *choice* is a non-issue.

Usage: hash_kex_bench.py [--reps 5] [--json out]
"""

import argparse
import hashlib
import json
import math
import os
import time

import blake3

HERE = os.path.dirname(os.path.abspath(__file__))

# EIP-7623 floor: 10 gas/token, nonzero byte = 4 tokens -> 40 gas/B (worst
# case, matches onchain_cost.py's floor model for random bytes).
GAS_PER_NONZERO_BYTE = 40
PUZZLE_BYTES = 40  # 32-B ciphertext of (index, key) + 8-B hint; generous lower bound

# Reference attacker throughputs (H/s), log2. Local CPU is measured below.
ATTACKER_RATES = {
    "one GPU (~16 GH/s SHA-256)": 34.0,
    "Bitcoin network (~1e21 H/s, 2026)": 70.0,
}


def rate(fn, data, reps, secs=0.6):
    """Best-of-reps calls/second for fn(data) on a small message."""
    best = 0.0
    for _ in range(reps):
        n = 0
        t0 = time.perf_counter()
        while True:
            for _ in range(2000):
                fn(data)
            n += 2000
            dt = time.perf_counter() - t0
            if dt >= secs:
                break
        best = max(best, n / dt)
    return best


def bulk(fn, mb, reps):
    data = os.urandom(mb << 20)
    best = 0.0
    for _ in range(reps):
        t0 = time.perf_counter()
        fn(data)
        best = max(best, mb / (time.perf_counter() - t0))
    return best  # MB/s


HASHES = {
    "SHA-256": lambda d: hashlib.sha256(d).digest(),
    "SHA3-256": lambda d: hashlib.sha3_256(d).digest(),
    "BLAKE3": lambda d: blake3.blake3(d).digest(),
    "keccak256": None,  # filled if pycryptodome present
}
try:
    from Crypto.Hash import keccak

    HASHES["keccak256"] = lambda d: keccak.new(digest_bits=256, data=d).digest()
except ImportError:
    del HASHES["keccak256"]


def fmt_time(s):
    if s < 1e-3:
        return f"{s*1e6:.1f} µs"
    if s < 1:
        return f"{s*1e3:.1f} ms"
    if s < 3600:
        return f"{s:.1f} s"
    if s < 86400 * 365:
        return f"{s/3600:.1f} h"
    return f"{s/(86400*365.25):.3g} yr"


def fmt_bytes(b):
    for unit in ("B", "kB", "MB", "GB", "TB", "PB", "EB"):
        if b < 1000:
            return f"{b:.3g} {unit}"
        b /= 1000
    return f"{b:.3g} ZB"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--json", default=None)
    args = ap.parse_args()

    out = {"hash_rates": {}, "scan_hashing": {}, "merkle_puzzles": [], "mlkem": {}}

    # --- 1. hash rates on this machine (Python-call-bound for small msgs) ---
    print("== hash primitives (this machine, single thread, Python binding) ==")
    print(f"{'hash':10} {'64-B msg calls/s':>18} {'log2':>6} {'bulk MB/s':>10}")
    for name, fn in HASHES.items():
        r = rate(fn, os.urandom(64), args.reps)
        b = bulk(fn, 64, args.reps)
        out["hash_rates"][name] = {
            "small_calls_per_s": r,
            "log2": math.log2(r),
            "bulk_MB_s": b,
        }
        print(f"{name:10} {r:18,.0f} {math.log2(r):6.1f} {b:10,.0f}")

    # --- 2. per-announcement scanner hashing (view tag / KDF) ---
    print("\n== per-announcement hashing a scanner does (vs decaps) ==")
    sizes = {"view tag over 32-B ss": 32, "KDF over 1088-B ct": 1088}
    for label, sz in sizes.items():
        row = {}
        for name, fn in HASHES.items():
            r = rate(fn, os.urandom(sz), args.reps)
            row[name] = 1e6 / r
        out["scan_hashing"][label] = row
        print(f"  {label:24} " + "  ".join(f"{k} {v:.2f}µs" for k, v in row.items()))

    # --- 3. ML-KEM reference rows ---
    try:
        d = json.load(open(os.path.join(HERE, "discovery_kem_20260801.json")))
        for r in d["benchmarked"]:
            if r["name"] in ("ML-KEM-512", "ML-KEM-768"):
                out["mlkem"][r["name"]] = r
    except (OSError, KeyError):
        pass
    if out["mlkem"]:
        print("\n== ML-KEM reference (discovery_kem_20260801.json) ==")
        for k, r in out["mlkem"].items():
            print(
                f"  {k}: pk {r['pk_B']} B, ct {r['ct_B']} B, "
                f"decaps {r['decaps_ms'] * 1e3:.1f} µs, "
                f"announce {r['announce_gas']:,} gas, "
                f"scan80k {r['scan80k_s']} s"
            )

    # --- 4. Merkle-puzzle economics ---
    # Honest work n (hash calls per party) needed so that Eve's work is 2^W
    # under gap exponent e (Eve = n^e). Puzzle-set size = n puzzles.
    local = out["hash_rates"]["SHA-256"]["small_calls_per_s"]
    local_log2 = math.log2(local)
    # ~24M SHA-256/s: one core with SHA extensions (native, not Python)
    hw_core_log2 = 24.5
    gap_models = [
        ("classical Eve, Merkle 1974 (Barak-Mahmoody: optimal)", 2.0),
        (
            "quantum Eve, classical parties, Merkle 1974 "
            "(BHKKLS'11: broken, no gap)",
            1.0,
        ),
        ("quantum Eve, classical parties, BHKKLS'11 concrete scheme", 7 / 6),
        (
            "quantum Eve, classical parties, BHKKLS'11 family limit "
            "(never reached)",
            1.5,
        ),
        ("quantum Eve, QUANTUM honest parties, BHKKLS'11 concrete scheme", 5 / 3),
    ]
    targets = [80, 96, 128]
    print("\n== Merkle-puzzle key exchange: honest cost to reach attacker work 2^W ==")
    print("  (n = hash calls per honest party = puzzles the recipient must publish)")
    for label, e in gap_models:
        print(f"\n  {label}  [Eve = n^{e:.3g}]")
        for W in targets:
            n_log2 = W / e
            n = 2 ** n_log2
            row = {
                "model": label, "exponent": e, "attacker_work_log2": W,
                "honest_work_log2": n_log2,
                "sender_time_native_core_s": n / 2 ** hw_core_log2,
                "sender_time_gpu_s": n / 2 ** 34,
                "puzzle_set_bytes": n * PUZZLE_BYTES,
                "puzzle_set_calldata_gas": n * PUZZLE_BYTES * GAS_PER_NONZERO_BYTE,
            }
            out["merkle_puzzles"].append(row)
            print(
                f"    W=2^{W:3}: n=2^{n_log2:5.1f} "
                f"sender {fmt_time(row['sender_time_native_core_s']):>9} (1 core) "
                f"/ {fmt_time(row['sender_time_gpu_s']):>9} (GPU); "
                f"recipient pubkey = {fmt_bytes(row['puzzle_set_bytes']):>8}; "
                f"calldata {row['puzzle_set_calldata_gas']:.2e} gas"
            )

    # Attacker time for the classical-Eve, W=2^128 case at reference rates
    print("\n== who can afford what (SHA-256 H/s, log2) ==")
    print(
        f"  this machine, Python-bound: 2^{local_log2:.1f}; "
        f"native core assumed 2^{hw_core_log2}"
    )
    for k, v in ATTACKER_RATES.items():
        print(f"  {k}: 2^{v}")
    out["attacker_rates_log2"] = {
        **ATTACKER_RATES,
        "local_python": local_log2,
        "native_core_assumed": hw_core_log2,
    }

    if args.json:
        json.dump(out, open(args.json, "w"), indent=1)
        print(f"\nwrote {args.json}")


if __name__ == "__main__":
    main()
