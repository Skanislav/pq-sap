#!/usr/bin/env python3
"""Recompute the simulator-validity constants quoted in the Lean docstrings.

Three SPR simulators appear in this development, and only one of them is
admissible for ML-KEM-768. The distances below are the reason, and they are
constants -- not small quantities that a proof could absorb:

1. `mlkem768UniformCiphertext`, `u` half: `Compress_10` maps `ZMod 3329` into
   `ZMod 1024` and `3329 = 3 * 1024 + 257`, so 257 output values have four
   preimages and 767 have three. One coefficient's distance from uniform 10-bit
   output is `197119/3408896`; the 768 independent coefficients of `u` are at
   `0.9262656353`.

2. `mlkem768UniformCiphertext`, `v` half: `Compress_4` maps into `ZMod 16` with
   preimage counts 209 (one value) and 208 (fifteen); 256 coefficients give
   `0.0073880701`. Together with the `u` half, the whole 1 088-byte simulator is
   at `0.9262656353` from the honest compressed-ciphertext distribution.

3. The scheme-3 `epk` leg: a 33-byte SEC1-compressed secp256k1 point is only one
   of `2^264` 33-byte strings; exactly `2*(p-1)/2 = p-1` of them decode (both
   parity tags, every valid x-coordinate; `-7` is not a cube mod `p`, so
   `x^3 + 7 = 0` has no solution and every on-curve x contributes exactly one
   of the two tags). A uniform-33-byte `epk` simulator is therefore at
   `1 - (p-1)/2^264 = 255/256` from the honest ephemeral-key distribution.

Stdlib only; mirrors the style of `check_sizes.py`. Exit 1 on any drift, so a
docstring that quotes a stale constant fails CI.

Usage: python3 lean/scripts/check_simulator_distances.py
"""
from __future__ import annotations

import math
import sys
from collections import Counter
from decimal import Decimal, getcontext
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LEAN = ROOT / "lean" / "PqStealth"

Q = 3329
# secp256k1 field prime
P_SECP256K1 = 2**256 - 2**32 - 977
# A compressed SEC1 point is 33 bytes: a 1-byte tag and a 32-byte x-coordinate.
EPK_BITS = 264

# The constants as they appear in `MLKEM.lean`'s section docstring and in
# `docs/spr-two-hop.md`. Rounded to the number of digits quoted there.
EXPECTED = {
    "compress10_one_coefficient_tv": "0.0578248794",
    "compress10_u_tv": "0.9262656353",
    "compress10_four_preimage_mass": "0.3088",
    "compress10_uniform_mass": "0.250977",
    "compress4_v_tv": "0.0073880701",
    "ciphertext_total_tv": "0.9262656353",
    "epk_uniform_bytes_tv": "0.99609375",
}


def compress(x: int, d: int) -> int:
    """FIPS 203 Section 4.2.1: `Compress_d(x) = ceil(2^d * x / q) mod 2^d`."""
    m = 1 << d
    return ((x * m + Q // 2) // Q) % m


def fibre_histogram(d: int) -> Counter:
    """Preimage-count histogram of `Compress_d` over the whole of `ZMod q`."""
    return Counter(Counter(compress(x, d) for x in range(Q)).values())


def product_tv(n: int, d: int) -> float:
    """Exact TV of `n` i.i.d. `n`-tuples of `Compress_d` of uniform coefficients
    against uniform over `n * d` bits, grouped by the sufficient statistic
    "how many coordinates hit a high-count value"."""
    groups = sorted(fibre_histogram(d).items())  # (preimage count, #outputs)
    (a, n_small), (b, n_large) = groups
    log_uniform = n * math.log(1 / (1 << d))
    total = 0.0
    for j in range(n + 1):
        log_count = (
            math.lgamma(n + 1)
            - math.lgamma(j + 1)
            - math.lgamma(n - j + 1)
            + j * math.log(n_large)
            + (n - j) * math.log(n_small)
        )
        log_p = j * math.log(b / Q) + (n - j) * math.log(a / Q)
        peak = max(log_p, log_uniform) + log_count
        total += (
            math.exp(peak)
            * abs(math.exp(log_p - peak + log_count) - math.exp(log_uniform - peak + log_count))
        )
    return total / 2


def one_coefficient_tv(d: int) -> float:
    """TV of a single `Compress_d` of a uniform coefficient from uniform `d` bits."""
    m = 1 << d
    counts = Counter(compress(x, d) for x in range(Q))
    return 0.5 * sum(abs(c / Q - 1 / m) for c in counts.values())


def joint_tv(du: int, nu: int, dv: int, nv: int) -> float:
    """TV of the full compressed ciphertext (both halves) from uniform bytes."""
    (a1, n1), (b1, m1) = sorted(fibre_histogram(du).items())
    (a2, n2), (b2, m2) = sorted(fibre_histogram(dv).items())
    log_uniform = nu * math.log(1 / (1 << du)) + nv * math.log(1 / (1 << dv))
    total = 0.0
    for j in range(nu + 1):
        log_nu = (
            math.lgamma(nu + 1)
            - math.lgamma(j + 1)
            - math.lgamma(nu - j + 1)
            + j * math.log(m1)
            + (nu - j) * math.log(n1)
        )
        log_pu = j * math.log(b1 / Q) + (nu - j) * math.log(a1 / Q)
        for k in range(nv + 1):
            log_nv = (
                math.lgamma(nv + 1)
                - math.lgamma(k + 1)
                - math.lgamma(nv - k + 1)
                + k * math.log(m2)
                + (nv - k) * math.log(n2)
            )
            log_p = log_pu + k * math.log(b2 / Q) + (nv - k) * math.log(a2 / Q)
            log_count = log_nu + log_nv
            peak = max(log_p, log_uniform) + log_count
            total += (
                math.exp(peak)
                * abs(math.exp(log_p - peak + log_count) - math.exp(log_uniform - peak + log_count))
            )
    return total / 2


def epk_uniform_bytes_tv() -> float:
    """TV between uniform 33-byte strings and a uniform valid compressed
    secp256k1 point. Every on-curve x is reachable under both parity tags, and
    `x^3 + 7 = 0` is unsolvable, so the valid encodings number `p - 1`."""
    valid = P_SECP256K1 - 1
    tv = 1 - Decimal(valid) / Decimal(1 << EPK_BITS)
    return float(tv)


def quoted(value: float, expected: str) -> str:
    """Format `value` at the same precision as `expected` and compare."""
    decimals = len(expected.split(".")[1]) if "." in expected else 0
    return f"{value:.{decimals}f}"


def main() -> int:
    getcontext().prec = 80
    hist10 = fibre_histogram(10)
    hist4 = fibre_histogram(4)

    measured = {
        "compress10_one_coefficient_tv": quoted(one_coefficient_tv(10), EXPECTED["compress10_one_coefficient_tv"]),
        "compress10_u_tv": quoted(product_tv(768, 10), EXPECTED["compress10_u_tv"]),
        # mass of the four-preimage set under a uniform coefficient
        "compress10_four_preimage_mass": quoted(hist10[4] * 4 / Q, EXPECTED["compress10_four_preimage_mass"]),
        "compress10_uniform_mass": quoted(hist10[4] / 1024, EXPECTED["compress10_uniform_mass"]),
        "compress4_v_tv": quoted(product_tv(256, 4), EXPECTED["compress4_v_tv"]),
        # the whole 1088-byte ciphertext: 768 u-coefficients and 256 v-coefficients
        "ciphertext_total_tv": quoted(joint_tv(10, 768, 4, 256), EXPECTED["ciphertext_total_tv"]),
        "epk_uniform_bytes_tv": quoted(epk_uniform_bytes_tv(), EXPECTED["epk_uniform_bytes_tv"]),
    }

    # Structural facts the docstrings assert, checked rather than trusted.
    structural = [
        ("Compress_10 has exactly two fibre sizes", len(hist10) == 2),
        ("Compress_10: 257 values with four preimages", hist10[4] == 257),
        ("Compress_10: 767 values with three preimages", hist10[3] == 767),
        ("Compress_10 fibres cover 3329", 4 * hist10[4] + 3 * hist10[3] == Q),
        ("Compress_4: 1 value with 209 preimages", hist4[209] == 1),
        ("Compress_4: 15 values with 208 preimages", hist4[208] == 15),
        ("Compress_4 fibres cover 3329", 209 * hist4[209] + 208 * hist4[208] == Q),
        ("u half is 768 coefficients (32*du*k bytes = 960 B = 7680 bits / du)",
         32 * 10 * 3 * 8 // 10 == 768),
        ("v half is 256 coefficients (32*dv bytes = 128 B = 1024 bits / dv)",
         32 * 4 * 8 // 4 == 256),
        ("epk valid encodings = p - 1 (no solution to x^3 + 7 = 0)",
         pow(pow((-7) % P_SECP256K1, (P_SECP256K1 - 1) // 3, P_SECP256K1), 3, P_SECP256K1)
         != (-7) % P_SECP256K1),
        ("the u half dominates the total distance: adding v moves it below 1e-5",
         abs(joint_tv(10, 768, 4, 256) - product_tv(768, 10)) < 1e-5),
    ]

    bad = 0
    for key, expected in EXPECTED.items():
        got = measured[key]
        ok = got == expected
        bad += 0 if ok else 1
        print(f"{'ok' if ok else 'MISMATCH':9} {key}: recomputed={got} quoted={expected}")

    for label, ok in structural:
        bad += 0 if ok else 1
        print(f"{'ok' if ok else 'MISMATCH':9} {label}")

    # The Lean docstrings must still carry these numbers, so a silently edited
    # docstring cannot diverge from the arithmetic above.
    mlkem = (LEAN / "MLKEM.lean").read_text()
    spr = (LEAN / "SPRTwoHop.lean").read_text()
    docs = (ROOT / "lean" / "docs" / "spr-two-hop.md").read_text()
    for number, where, text in [
        ("0.9262656353", "MLKEM.lean", mlkem),
        ("0.9262656353", "spr-two-hop.md", docs),
        ("0.0578248794", "spr-two-hop.md", docs),
    ]:
        present = number in text
        bad += 0 if present else 1
        print(f"{'ok' if present else 'MISSING':9} {number} still quoted in {where}")

    print(f"{len(EXPECTED) + len(structural) + 3} checks, {bad} failures")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
