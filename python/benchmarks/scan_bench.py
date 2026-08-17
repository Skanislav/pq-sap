#!/usr/bin/env python3
"""Scan benchmark: our PQ scheme vs the DKSAP elliptic-curve baseline.

Methodology mirrors the ePrint 2025/112 harness (pq-sap
`pq_sap_benchmark.rs`): a registry of N announcements encapsulated to
*random* recipients (so view tags false-positive at ~1/256), scanned by
one recipient: decapsulate, check the 1-byte view tag, and run the full
stealth-key derivation only on tag matches.

Backends:
  * ours/liboqs  — ML-KEM-768 decaps via liboqs (audited C); full blinded
                   derivation (pure Python) on tag match only
  * ours/pure    — everything pure Python (kyber-py), small N only
  * dksap        — secp256k1 baseline via coincurve (libsecp256k1):
                   ss = v*R, tag check, then P = K + H(ss)*G on match

Usage: scan_bench.py [--sizes 5000,20000,80000] [--reps 3] [--json out]
"""

import argparse
import hashlib
import json
import time


def VIEW_TAG(ss):
    return hashlib.sha256(ss).digest()[0]


# --------------------------------------------------------------------------
# Ours: ML-KEM-768 + blinded ML-DSA-65 derivation
# --------------------------------------------------------------------------
def bench_ours_liboqs(n: int) -> tuple[float, int]:
    import oqs

    from pq_stealth import DEFAULT, derive_stealth_pk, gen_meta_address

    meta_pub, meta_priv = gen_meta_address(DEFAULT)
    with oqs.KeyEncapsulation("ML-KEM-768") as noise_kem:
        registry = []
        for _ in range(n):
            other_ek = noise_kem.generate_keypair()
            ct, ss = oqs.KeyEncapsulation("ML-KEM-768").encap_secret(other_ek)
            registry.append((ct, VIEW_TAG(ss)))

    scanner = oqs.KeyEncapsulation("ML-KEM-768", secret_key=meta_priv.kem_dk)
    matches = 0
    t0 = time.perf_counter()
    for ct, tag in registry:
        ss = scanner.decap_secret(ct)
        if VIEW_TAG(ss) == tag:
            derive_stealth_pk(meta_pub.rho, meta_pub.t, ss, DEFAULT)
            matches += 1
    return time.perf_counter() - t0, matches


def bench_ours_pure(n: int) -> tuple[float, int]:
    from pq_stealth import DEFAULT, derive_stealth_pk, gen_meta_address

    meta_pub, meta_priv = gen_meta_address(DEFAULT)
    kem = DEFAULT.kem
    registry = []
    for _ in range(n):
        other_ek, _ = kem.keygen()
        ss, ct = kem.encaps(other_ek)
        registry.append((ct, VIEW_TAG(ss)))

    matches = 0
    t0 = time.perf_counter()
    for ct, tag in registry:
        ss = kem.decaps(meta_priv.kem_dk, ct)
        if VIEW_TAG(ss) == tag:
            derive_stealth_pk(meta_pub.rho, meta_pub.t, ss, DEFAULT)
            matches += 1
    return time.perf_counter() - t0, matches


# --------------------------------------------------------------------------
# DKSAP baseline (ERC-5564 SECP256K1 flavor) via libsecp256k1
# --------------------------------------------------------------------------
def bench_dksap(n: int) -> tuple[float, int]:
    from coincurve import PrivateKey, PublicKey

    v = PrivateKey()                      # viewing key
    K = PrivateKey().public_key           # spending pubkey
    registry = []
    for _ in range(n):
        r = PrivateKey()                  # ephemeral key
        other_v = PrivateKey()            # ...addressed to a random recipient
        ss = other_v.public_key.multiply(r.secret).format()
        registry.append((r.public_key.format(), VIEW_TAG(ss)))

    matches = 0
    t0 = time.perf_counter()
    for R_bytes, tag in registry:
        ss = PublicKey(R_bytes).multiply(v.secret).format()
        if VIEW_TAG(ss) == tag:
            h = hashlib.sha256(ss).digest()
            PublicKey.combine_keys([K, PrivateKey(h).public_key])
            matches += 1
    return time.perf_counter() - t0, matches


BACKENDS = {
    "ours/liboqs": bench_ours_liboqs,
    "ours/pure": bench_ours_pure,
    "dksap": bench_dksap,
}
PURE_MAX_N = 5000  # pure-Python decaps is ~ms each; cap the slow backend


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", default="5000,20000,80000")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--json", default=None)
    args = ap.parse_args()
    sizes = [int(s) for s in args.sizes.split(",")]

    results = []
    for name, fn in BACKENDS.items():
        for n in sizes:
            if name == "ours/pure" and n > PURE_MAX_N:
                continue
            times, matches = [], 0
            for _ in range(args.reps):
                dt, matches = fn(n)
                times.append(dt)
            best = min(times)
            per = best / n * 1e6
            results.append({"backend": name, "n": n, "best_s": round(best, 4),
                            "per_announcement_us": round(per, 2),
                            "tag_matches": matches, "reps": args.reps})
            print(f"{name:12s} N={n:6d}  {best*1000:9.1f} ms  "
                  f"({per:7.2f} us/announcement, {matches} tag matches)")

    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=2)
        print(f"wrote {args.json}")


if __name__ == "__main__":
    main()
