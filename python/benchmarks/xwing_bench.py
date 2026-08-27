#!/usr/bin/env python3
"""X-Wing hybrid KEM (X25519 + ML-KEM-768) as a discovery-KEM candidate.

X-Wing (draft-connolly-cfrg-xwing-kem / eprint 2024/039) is the CFRG
standalone hybrid KEM: one ML-KEM-768 encapsulation plus one X25519 ECDH,
combined as  ss = SHA3-256(ss_M || ss_X || ct_X || pk_X || "\\.//^\\").
The ML-KEM ciphertext is deliberately NOT hashed (relies on ML-KEM's
ciphertext second-preimage resistance), which keeps the combiner one short
hash.  pk = ek_M || pk_X = 1216 B, ct = ct_M || ct_X = 1120 B, sk = 32-B
seed (SHAKE256-expanded to both component keys).

Why it matters here: D-012/D-016 concluded lattice (ML-KEM) is load-bearing
for discovery.  X-Wing is the classical-cryptanalysis hedge — but note the
scope (docs/research/xwing-hybrid-kem.md): it hedges shared-secret
pseudorandomness (view tags, derived stealth addresses; "MLWE OR
strong-DH"), while announcement<->meta-address CIPHERTEXT anonymity remains
ML-KEM's alone (parallel hybrids need both legs anonymous, and ct_M is
on-chain; Bao-Pan PKC 2026, eprint 2026/396).  Against a QUANTUM adversary
the X25519 leg is dead and security degrades to exactly ML-KEM alone.

This benchmark measures the three discovery axes (same models as
discovery_kem_bench.py):

  1. SCAN COST — hybrid decaps = ML-KEM-768 decaps + one X25519 + SHA3-256.
     The X25519/SHA3 legs are timed natively here; the ML-KEM leg reuses the
     liboqs figure from discovery_kem_20260801.json (same machine) so the
     composed number is apples-to-apples with the native rows of that table.
     NOTE the Python `cryptography` wrapper adds ~5x per-call overhead over
     raw OpenSSL (`openssl speed ecdhx25519`); both numbers are reported.
  2. FOOTPRINT — ZK-spend meta-address = version + 32-B commitment + pk.
  3. ON-CHAIN — EIP-7623 calldata-floor gas for the announcement.

Correctness: the implementation is validated against the official test
vectors from the draft repository (one embedded below, all-fields check:
pk, ct, encaps ss, decaps ss).

Deps: kyber-py, cryptography, eth-abi, eth-utils (the ML-KEM leg here is
kyber-py's pure-Python internals — fine for vectors, not for timing).

Usage: xwing_bench.py [--json out]
"""

import argparse
import hashlib
import json
import os
import statistics
import time

from kyber_py.ml_kem import ML_KEM_768
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from onchain_cost import (
    G_TX,
    TOTAL_COST_FLOOR_PER_TOKEN,
    abi_encode_announce,
    byte_stats,
    calldata_tokens,
)

SCHEME_ID = 2

# 6-byte domain-separation label from the spec ("\.//^\", the X-Wing).
XWING_LABEL = bytes([0x5C, 0x2E, 0x2F, 0x2F, 0x5E, 0x5C])

# liboqs ML-KEM-768 decaps on this machine (discovery_kem_20260801.json) —
# the native figure the rest of the discovery table is built from.
LIBOQS_MLKEM768_DECAPS_MS = 0.0172

# Native X25519 derive from `openssl speed -seconds 1 ecdhx25519` on this
# machine: 33,169 op/s -> 30.2 us.  Used for the native-composition row.
OPENSSL_X25519_US = 30.2


# --- X-Wing (draft-connolly-cfrg-xwing-kem) over kyber-py + cryptography ---

def _x25519(sk32: bytes, pk32: bytes | None = None) -> bytes:
    priv = X25519PrivateKey.from_private_bytes(sk32)
    if pk32 is None:
        return priv.public_key().public_bytes_raw()
    return priv.exchange(X25519PublicKey.from_public_bytes(pk32))


def _expand(sk: bytes):
    e = hashlib.shake_256(sk).digest(96)
    ek_m, dk_m = ML_KEM_768._keygen_internal(e[0:32], e[32:64])
    sk_x = e[64:96]
    return ek_m, dk_m, sk_x, _x25519(sk_x)


def _combine(ss_m: bytes, ss_x: bytes, ct_x: bytes, pk_x: bytes) -> bytes:
    return hashlib.sha3_256(ss_m + ss_x + ct_x + pk_x + XWING_LABEL).digest()


def keygen(seed: bytes):
    ek_m, _, _, pk_x = _expand(seed)
    return ek_m + pk_x, seed


def encaps_derand(pk: bytes, eseed: bytes):
    ek_m, pk_x = pk[:1184], pk[1184:]
    ss_m, ct_m = ML_KEM_768._encaps_internal(ek_m, eseed[0:32])
    ct_x = _x25519(eseed[32:64])
    ss_x = _x25519(eseed[32:64], pk_x)
    return _combine(ss_m, ss_x, ct_x, pk_x), ct_m + ct_x


def encaps(pk: bytes):
    return encaps_derand(pk, os.urandom(64))


def decaps(sk: bytes, ct: bytes):
    _, dk_m, sk_x, pk_x = _expand(sk)
    ct_m, ct_x = ct[:1088], ct[1088:]
    ss_m = ML_KEM_768.decaps(dk_m, ct_m)
    ss_x = _x25519(sk_x, ct_x)
    return _combine(ss_m, ss_x, ct_x, pk_x)


# --- official test vector (vector 0 of the draft repo's test-vectors.json) ---

VECTOR = {
    "seed": "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
    "eseed": "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2"
             "35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2",
    "ss": "d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384",
    # pk/ct are 1216/1120 B; compared via SHA-256 of the official vector's
    # full-length values to keep this file readable.
    "pk_sha256":
        "2e816deebcd76c5c80d0cd2d174478871658e8e2ff42bc9d4a6e486372e856bb",
    "ct_sha256":
        "17cd532d657e44c897ca6583e548a5424fc70bf54f99515a4d2bcf99e3469f33",
}


def verify_vector() -> None:
    seed = bytes.fromhex(VECTOR["seed"])
    eseed = bytes.fromhex(VECTOR["eseed"])
    pk, sk = keygen(seed)
    assert hashlib.sha256(pk).hexdigest() == VECTOR["pk_sha256"], "pk mismatch"
    ss, ct = encaps_derand(pk, eseed)
    assert hashlib.sha256(ct).hexdigest() == VECTOR["ct_sha256"], "ct mismatch"
    assert ss == bytes.fromhex(VECTOR["ss"]), "encaps ss mismatch"
    assert decaps(sk, ct) == ss, "decaps ss mismatch"


# --- measurement -----------------------------------------------------------

def median_us(fn, reps, batches=7):
    outs = []
    for _ in range(batches):
        t0 = time.perf_counter()
        for _ in range(reps):
            fn()
        outs.append((time.perf_counter() - t0) / reps * 1e6)
    return statistics.median(outs)


def announce_floor_gas(ct_len: int) -> int:
    ct = os.urandom(ct_len)
    calldata = abi_encode_announce(SCHEME_ID, bytes(range(1, 21)), ct, b"\x2a")
    z, nz = byte_stats(calldata)
    return G_TX + TOTAL_COST_FLOOR_PER_TOKEN * calldata_tokens(z, nz)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", type=str, default=None)
    args = ap.parse_args()

    verify_vector()
    print("official test vector: pk/ct/encaps-ss/decaps-ss all match\n")

    priv = X25519PrivateKey.generate()
    peer_raw = X25519PrivateKey.generate().public_key().public_bytes_raw()
    buf = os.urandom(32 * 3 + 32 + 6)

    x_wrap = median_us(
        lambda: priv.exchange(X25519PublicKey.from_public_bytes(peer_raw)),
        reps=2000)
    sha3 = median_us(lambda: hashlib.sha3_256(buf).digest(), reps=2000)

    mlkem_us = LIBOQS_MLKEM768_DECAPS_MS * 1e3
    hybrid_native = mlkem_us + OPENSSL_X25519_US + sha3
    hybrid_pywrap = mlkem_us + x_wrap + sha3

    rows = [
        {"name": "ML-KEM-768 (reference)", "pk_B": 1184, "ct_B": 1088,
         "decaps_us": round(mlkem_us, 1),
         "scan80k_s": round(mlkem_us * 80_000 / 1e6, 2),
         "meta_addr_B": 1 + 32 + 1184, "announce_gas": announce_floor_gas(1088)},
        {"name": "X-Wing (native comp.)", "pk_B": 1216, "ct_B": 1120,
         "decaps_us": round(hybrid_native, 1),
         "scan80k_s": round(hybrid_native * 80_000 / 1e6, 2),
         "meta_addr_B": 1 + 32 + 1216, "announce_gas": announce_floor_gas(1120)},
        {"name": "X-Wing (py-wrapped x25519)", "pk_B": 1216, "ct_B": 1120,
         "decaps_us": round(hybrid_pywrap, 1),
         "scan80k_s": round(hybrid_pywrap * 80_000 / 1e6, 2),
         "meta_addr_B": 1 + 32 + 1216, "announce_gas": announce_floor_gas(1120)},
    ]
    components = {
        "mlkem768_decaps_us_liboqs": mlkem_us,
        "x25519_us_openssl_native": OPENSSL_X25519_US,
        "x25519_us_python_cryptography": round(x_wrap, 2),
        "sha3_256_combiner_us": round(sha3, 3),
    }

    print(f"{'candidate':<28}{'pk B':>7}{'ct B':>7}{'decaps us':>11}"
          f"{'scan80k s':>11}{'meta B':>8}{'announce gas':>14}")
    for r in rows:
        print(f"{r['name']:<28}{r['pk_B']:>7}{r['ct_B']:>7}"
              f"{r['decaps_us']:>11}{r['scan80k_s']:>11}"
              f"{r['meta_addr_B']:>8}{r['announce_gas']:>14,}")

    print(f"\ncomponents: ML-KEM-768 decaps {mlkem_us:.1f} us (liboqs) | "
          f"x25519 {OPENSSL_X25519_US} us native / {x_wrap:.1f} us via "
          f"python-cryptography | SHA3-256 combine {sha3:.2f} us")
    print(f"hybrid tax (native): {rows[1]['decaps_us']/rows[0]['decaps_us']:.1f}x "
          f"scan, +{rows[1]['announce_gas']-rows[0]['announce_gas']:,} gas "
          f"(+{(rows[1]['announce_gas']/rows[0]['announce_gas']-1)*100:.1f}%), "
          f"+32 B meta-address. The x25519 leg costs ~1.8x the ML-KEM leg — "
          f"the classical half dominates hybrid scan cost.")

    if args.json:
        with open(args.json, "w") as f:
            json.dump({"rows": rows, "components": components,
                       "vector_checked": True}, f, indent=1)
        print(f"\nwrote {args.json}")


if __name__ == "__main__":
    main()
