#!/usr/bin/env python3
"""Security-level sweep across the three parameter sets.

The scheme is parameter-agile (pq_stealth/params.py): ML-KEM-512+ML-DSA-44
(NIST level 1), ML-KEM-768+ML-DSA-65 (level 3, default), ML-KEM-1024+ML-DSA-87
(level 5). This benchmark measures what changes with the level so the
"parameter-agile" claim in the spec has numbers behind it:

  * object sizes (meta-address, ciphertext, stealth pk, signature)
  * KEM keygen/encaps/decaps (audited liboqs)
  * sender-side stealth-pk derivation (pure Python reference)
  * blinded-sign rejection rounds vs stock ML-DSA at that level

The rejection-round row is the non-obvious one: the widened bound is
beta' = tau * 2*eta, and eta is NOT monotone in the level (ML-DSA-44/87 use
eta=2, ML-DSA-65 uses eta=4), so the *default* level-3 set pays the largest
blinding penalty, not level 5.

Usage: param_sweep.py [--n 20000] [--reps 5] [--sign-reps 40] [--json out]
"""

import argparse
import hashlib
import json
import statistics
import time

from pq_stealth import (
    PARAM_SETS,
    check_announcement,
    derive_stealth_pk,
    gen_meta_address,
    send,
    sign_blinded,
)

# level ordering + matching liboqs mechanism names
LEVELS = [
    ("L1", "ML-KEM-512+ML-DSA-44", "ML-KEM-512", "ML-DSA-44"),
    ("L3", "ML-KEM-768+ML-DSA-65", "ML-KEM-768", "ML-DSA-65"),
    ("L5", "ML-KEM-1024+ML-DSA-87", "ML-KEM-1024", "ML-DSA-87"),
]


def VIEW_TAG(ss):
    return hashlib.sha256(ss).digest()[0]


def median_ms(fn, reps):
    xs = []
    for _ in range(reps):
        t = time.perf_counter()
        fn()
        xs.append((time.perf_counter() - t) * 1e3)
    return round(statistics.median(xs), 3)


def kem_ops(mech, reps):
    import oqs
    kg = median_ms(lambda: oqs.KeyEncapsulation(mech).generate_keypair(), reps)
    with oqs.KeyEncapsulation(mech) as k:
        ek = k.generate_keypair()
    enc = median_ms(lambda: oqs.KeyEncapsulation(mech).encap_secret(ek), reps)
    # a key we own, so decaps is valid
    dec_k = oqs.KeyEncapsulation(mech)
    my_ek = dec_k.generate_keypair()
    ct, _ = oqs.KeyEncapsulation(mech).encap_secret(my_ek)
    dec = median_ms(lambda: dec_k.decap_secret(ct), reps)
    return {"keygen_ms": kg, "encaps_ms": enc, "decaps_ms": dec}


def scan_throughput(params, meta_pub, meta_priv, mech, n):
    import oqs
    with oqs.KeyEncapsulation(mech) as noise:
        reg = []
        for _ in range(n):
            other = noise.generate_keypair()
            ct, ss = oqs.KeyEncapsulation(mech).encap_secret(other)
            reg.append((ct, VIEW_TAG(ss)))
    scanner = oqs.KeyEncapsulation(mech, secret_key=meta_priv.kem_dk)
    t = time.perf_counter()
    for ct, tag in reg:
        ss = scanner.decap_secret(ct)
        if VIEW_TAG(ss) == tag:
            derive_stealth_pk(meta_pub.rho, meta_pub.t, ss, params)
    dt = time.perf_counter() - t
    return round(dt / n * 1e6, 2)


def rejection_rounds(params, meta_pub, meta_priv, reps):
    dsa = params.dsa
    orig = dsa.R.sample_in_ball
    c = {"n": 0}

    def wrap(*a, **k):
        c["n"] += 1
        return orig(*a, **k)

    dsa.R.sample_in_ball = wrap
    try:
        bl = []
        for _ in range(reps):
            ann = send(meta_pub)
            p = check_announcement(meta_pub, meta_priv.kem_dk, ann)
            c["n"] = 0
            sign_blinded(meta_priv, p.stealth_pk, p.t0, p.shared_secret, b"m")
            bl.append(c["n"])
        _pk, sk = dsa.keygen()
        st = []
        for i in range(reps):
            c["n"] = 0
            dsa.sign(sk, b"m%d" % i)
            st.append(c["n"])
    finally:
        dsa.R.sample_in_ball = orig
    return {
        "eta": dsa.eta, "tau": dsa.tau, "beta_blinded": params.beta_blinded,
        "blinded_mean": round(statistics.mean(bl), 1),
        "stock_mean": round(statistics.mean(st), 1),
        "ratio": round(statistics.mean(bl) / statistics.mean(st), 1),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=20000)
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--sign-reps", type=int, default=40)
    ap.add_argument("--json", default=None)
    args = ap.parse_args()

    rows = []
    for tag, pname, kmech, smech in LEVELS:
        p = PARAM_SETS[pname]
        meta_pub, meta_priv = gen_meta_address(p)
        pay = check_announcement(meta_pub, meta_priv.kem_dk, send(meta_pub))
        sig = sign_blinded(meta_priv, pay.stealth_pk, pay.t0,
                           pay.shared_secret, b"x")
        sizes = {
            "meta_address_B": p.meta_address_bytes,
            "ciphertext_B": p.kem_ct_bytes,
            "stealth_pk_B": len(pay.stealth_pk),
            "sig_B": len(sig),
        }
        kem = kem_ops(kmech, args.reps)
        scan_us = scan_throughput(p, meta_pub, meta_priv, kmech, args.n)
        rej = rejection_rounds(p, meta_pub, meta_priv, args.sign_reps)
        rows.append({"level": tag, "params": pname, "liboqs_kem": kmech,
                     "sizes": sizes, "kem_ms": kem,
                     "scan_us_per_ann": scan_us, "rejection": rej})

    # ---- report ----
    print("SIZES (bytes)")
    print(f"{'lvl':<4}{'meta-addr':>11}{'ct':>7}{'sig':>7}")
    for r in rows:
        s = r["sizes"]
        print(f"{r['level']:<4}{s['meta_address_B']:>11}{s['ciphertext_B']:>7}"
              f"{s['sig_B']:>7}")

    print("\nKEM OPS (median ms, liboqs) + SCAN THROUGHPUT")
    print(f"{'lvl':<4}{'keygen':>9}{'encaps':>9}{'decaps':>9}"
          f"{'scan us/ann':>13}")
    for r in rows:
        k = r["kem_ms"]
        print(f"{r['level']:<4}{k['keygen_ms']:>9}{k['encaps_ms']:>9}"
              f"{k['decaps_ms']:>9}{r['scan_us_per_ann']:>13}")

    print("\nBLINDED-SIGN REJECTION (blinding penalty is NOT monotone in level)")
    print(f"{'lvl':<4}{'eta':>4}{'tau':>5}{'beta_blind':>11}"
          f"{'blinded':>9}{'stock':>7}{'x':>6}")
    for r in rows:
        j = r["rejection"]
        print(f"{r['level']:<4}{j['eta']:>4}{j['tau']:>5}{j['beta_blinded']:>11}"
              f"{j['blinded_mean']:>9}{j['stock_mean']:>7}{j['ratio']:>5}x")

    if args.json:
        json.dump(rows, open(args.json, "w"), indent=2)
        print(f"\nwrote {args.json}")


if __name__ == "__main__":
    main()
