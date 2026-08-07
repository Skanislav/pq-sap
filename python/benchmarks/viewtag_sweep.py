#!/usr/bin/env python3
"""View-tag length sweep: the false-positive vs scan-cost knob.

A view tag is the first `b` bytes of a hash of the shared secret, stored in
the announcement so a scanner can reject non-matching payments before the
expensive stealth-key derivation. False-positive rate is ~256^-b, so each
extra tag byte cuts wasted derivations ~256x, at the cost of `b` extra bytes
per announcement (negligible next to a 1088-byte ciphertext).

The point this measures: the *right* tag length depends on how expensive the
derivation is. With our pure-Python reference derivation (~ms), false
positives dominate scan time and a 2nd byte helps a lot. With native decaps
+ derivation (~us), the 1/256 rate is already cheap and 1 byte is enough —
which is why the spec keeps `VIEW_TAG_BYTES = 1` as the default while noting
longer tags are safe and cheap on-chain.

All N announcements are addressed to random recipients, so every tag match is
a false positive (~N/256^b of them); we count derivations triggered and the
wall time. Uses audited liboqs decaps + the pure-Python derivation.

Usage: viewtag_sweep.py [--n 40000] [--tags 1,2,3] [--json out]
"""

import argparse
import hashlib
import json
import time

from pq_stealth import gen_meta_address, derive_stealth_pk, DEFAULT


def tag_of(ss: bytes, b: int) -> bytes:
    return hashlib.sha256(ss).digest()[:b]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=40000)
    ap.add_argument("--tags", default="1,2,3")
    ap.add_argument("--json", default=None)
    args = ap.parse_args()
    tag_lens = [int(x) for x in args.tags.split(",")]

    import oqs
    mech = "ML-KEM-768"
    meta_pub, meta_priv = gen_meta_address(DEFAULT)

    # one registry of ciphertexts to random recipients; store the FULL-width
    # tag once, slice per sweep so every length scans the identical set.
    with oqs.KeyEncapsulation(mech) as noise:
        reg = []
        for _ in range(args.n):
            other = noise.generate_keypair()
            ct, ss = oqs.KeyEncapsulation(mech).encap_secret(other)
            reg.append((ct, tag_of(ss, 4)))  # 4-byte stored tag, sliced below

    rows = []
    for b in tag_lens:
        scanner = oqs.KeyEncapsulation(mech, secret_key=meta_priv.kem_dk)
        derivations = 0
        t = time.perf_counter()
        for ct, full_tag in reg:
            ss = scanner.decap_secret(ct)
            if tag_of(ss, b) == full_tag[:b]:
                derive_stealth_pk(meta_pub.rho, meta_pub.t, ss, DEFAULT)
                derivations += 1
        dt = time.perf_counter() - t
        rows.append({
            "tag_bytes": b,
            "expected_fp_rate": f"1/{256**b}",
            "derivations": derivations,
            "total_s": round(dt, 3),
            "us_per_ann": round(dt / args.n * 1e6, 2),
        })

    print(f"N={args.n} announcements to random recipients "
          f"(every match is a false positive)")
    print(f"{'tag B':>6}{'FP rate':>12}{'derivations':>13}"
          f"{'total s':>10}{'us/ann':>9}")
    for r in rows:
        print(f"{r['tag_bytes']:>6}{r['expected_fp_rate']:>12}"
              f"{r['derivations']:>13}{r['total_s']:>10}{r['us_per_ann']:>9}")

    base = rows[0]["us_per_ann"]
    floor = rows[-1]["us_per_ann"]
    print(f"\n1-byte tag spends {base} us/ann; a {tag_lens[-1]}-byte tag drops "
          f"to {floor} us/ann (~pure decaps floor).")
    print("Each derivation here is pure-Python (~ms); in native code the "
          "derivation is ~us, so 1 byte is already near-optimal — the sweep "
          "shows the knob matters most when derivation is the bottleneck.")

    if args.json:
        json.dump(rows, open(args.json, "w"), indent=2)
        print(f"wrote {args.json}")


if __name__ == "__main__":
    main()
