#!/usr/bin/env python3
"""Per-operation micro-benchmarks for the PQ stealth scheme.

Secondary to the scanning throughput (scan_bench.py) and the on-chain data
cost (onchain_cost.py) — those are the numbers that matter. This table just
puts a wall-clock figure on each one-shot operation a wallet does off-chain,
so the cost report can say "sender derivation is X, a full blinded sign is Y".

KEM ops use audited liboqs; the blinding/derivation/sign path is the pure-
Python reference (a wallet would bind native crypto — these are the spec's
timings, not a product's). Median of N reps, reported in ms.

Usage: op_bench.py [--reps 20] [--json out.json]
"""

import argparse
import json
import statistics
import time

from pq_stealth import (gen_meta_address, derive_stealth_pk, sign_blinded,
                        verify, send, check_announcement, DEFAULT)


def timed(fn, reps: int) -> tuple[float, float]:
    xs = []
    for _ in range(reps):
        t0 = time.perf_counter()
        fn()
        xs.append((time.perf_counter() - t0) * 1e3)
    return statistics.median(xs), min(xs)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reps", type=int, default=20)
    ap.add_argument("--json", default=None)
    args = ap.parse_args()
    reps = args.reps

    # one shared setup so each op benches in isolation
    meta_pub, meta_priv = gen_meta_address(DEFAULT)
    ann = send(meta_pub)
    payment = check_announcement(meta_pub, meta_priv.kem_dk, ann)
    assert payment is not None
    msg = b"benchmark message"
    sig = sign_blinded(meta_priv, payment.stealth_pk, payment.t0,
                       payment.shared_secret, msg)

    ops = {
        "gen_meta_address": lambda: gen_meta_address(DEFAULT),
        "send (sender: encaps + stealth-pk derive)": lambda: send(meta_pub),
        "scan hit (decaps + view-tag + derive)":
            lambda: check_announcement(meta_pub, meta_priv.kem_dk, ann),
        "derive_stealth_pk (sender-side, isolated)":
            lambda: derive_stealth_pk(meta_pub.rho, meta_pub.t,
                                      payment.shared_secret, DEFAULT),
        "sign_blinded (rejection loop)":
            lambda: sign_blinded(meta_priv, payment.stealth_pk, payment.t0,
                                 payment.shared_secret, msg),
        "verify (stock FIPS 204)":
            lambda: verify(DEFAULT, payment.stealth_pk, msg, sig),
    }

    results = []
    print(f"{'operation':<44} {'median ms':>10} {'best ms':>10}")
    print("-" * 66)
    for name, fn in ops.items():
        med, best = timed(fn, reps)
        results.append({"op": name, "median_ms": round(med, 3),
                        "best_ms": round(best, 3), "reps": reps})
        print(f"{name:<44} {med:>10.3f} {best:>10.3f}")

    rounds = rejection_rounds(meta_pub, meta_priv, reps=max(reps, 30))
    print("\nrejection rounds per signature (widened bound beta' = 2*beta):")
    print(f"  blinded (construction A): median {rounds['blinded_median']}, "
          f"mean {rounds['blinded_mean']}, max {rounds['blinded_max']}")
    print(f"  stock ML-DSA-65:          median {rounds['stock_median']}, "
          f"mean {rounds['stock_mean']}, max {rounds['stock_max']}")
    print(f"  => blinding costs ~{rounds['ratio_mean']}x the rejection rounds "
          f"(both secret vectors are 2*eta-normed)")

    out = {"ops": results, "rejection_rounds": rounds}
    if args.json:
        json.dump(out, open(args.json, "w"), indent=2)
        print(f"\nwrote {args.json}")


def rejection_rounds(meta_pub, meta_priv, reps: int) -> dict:
    """Count `sample_in_ball` calls (= rejection-loop iterations) for the
    blinded signer vs stock ML-DSA-65 on the same library. The widened bound
    beta' = tau*(2*eta) shrinks the acceptance region, so construction A
    rejects more often; this is a real cost of the scheme, measured here."""
    import statistics
    dsa = DEFAULT.dsa
    orig = dsa.R.sample_in_ball
    n = {"c": 0}

    def wrap(*a, **k):
        n["c"] += 1
        return orig(*a, **k)

    dsa.R.sample_in_ball = wrap
    try:
        blinded = []
        for _ in range(reps):
            ann = send(meta_pub)
            p = check_announcement(meta_pub, meta_priv.kem_dk, ann)
            n["c"] = 0
            sign_blinded(meta_priv, p.stealth_pk, p.t0, p.shared_secret, b"m")
            blinded.append(n["c"])
        pk, sk = dsa.keygen()
        stock = []
        for i in range(reps):
            n["c"] = 0
            dsa.sign(sk, b"m%d" % i)
            stock.append(n["c"])
    finally:
        dsa.R.sample_in_ball = orig

    return {
        "reps": reps,
        "blinded_median": statistics.median(blinded),
        "blinded_mean": round(statistics.mean(blinded), 1),
        "blinded_max": max(blinded),
        "stock_median": statistics.median(stock),
        "stock_mean": round(statistics.mean(stock), 1),
        "stock_max": max(stock),
        "ratio_mean": round(statistics.mean(blinded) / statistics.mean(stock), 1),
    }


if __name__ == "__main__":
    main()
