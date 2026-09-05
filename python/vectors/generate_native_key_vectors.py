#!/usr/bin/env python3
"""Conformance vectors for EIP-8164 native-key stealth addresses.

Deterministic: an ML-KEM-512+ML-DSA-44 recipient from fixed seeds, one
announcement with fixed encapsulation randomness, and the crafted
authorization for the resulting stealth pk on a few chain ids. The TS client
(`js-client/test/native-key.test.ts`) must reproduce `r`, `msg_hash` and
`address` from `stealth_pk` alone.

Usage: generate_native_key_vectors.py [-o OUTDIR]
"""

import argparse
import json
import pathlib

from pq_stealth import PARAM_SETS, check_announcement, gen_meta_address, send
from pq_stealth.native_key import craft_authorization

SCHEMA_VERSION = "v0"
CHAIN_IDS = [1, 11155111, 81410]


def hx(b: bytes) -> str:
    return "0x" + b.hex()


def generate() -> dict:
    params = PARAM_SETS["ML-KEM-512+ML-DSA-44"]
    meta_pub, meta_priv = gen_meta_address(
        params, zeta=b"\x44" * 32, kem_d=b"\x45" * 32, kem_z=b"\x46" * 32)
    ann = send(meta_pub, encaps_m=b"\x47" * 32)
    payment = check_announcement(meta_pub, meta_priv.kem_dk, ann)
    assert payment is not None
    pk = payment.stealth_pk

    cases = []
    for cid in CHAIN_IDS:
        a = craft_authorization(pk, chain_id=cid)
        cases.append({
            "chain_id": cid,
            "nonce": a.nonce,
            "y_parity": a.y_parity,
            "r": hx(a.r.to_bytes(32, "big")),
            "s": hx(a.s.to_bytes(32, "big")),
            "msg_hash": hx(a.msg_hash),
            "address": hx(a.address),
            "code_prefix": hx(a.code[:3]),
        })
    return {
        "schema": SCHEMA_VERSION,
        "eip": "EIP-8164 (Draft 2026-02-17) crafted native-key authorization",
        "params": params.name,
        "encoding": {
            "r_seed": "keccak256('nkd-v1' || uint256_be(chain_id) || pk)",
            "r": "smallest valid secp256k1 x >= r_seed mod p, also < n",
            "s": 1, "y_parity": 0,
            "msg_hash": "keccak256(0x07 || rlp([chain_id, pk, nonce]))",
        },
        "recipient": {
            "seeds": {"zeta": hx(b"\x44" * 32), "kem_d": hx(b"\x45" * 32),
                      "kem_z": hx(b"\x46" * 32)},
            "meta_address": hx(meta_pub.encode()),
        },
        "announcement": {
            "encaps_m": hx(b"\x47" * 32),
            "stealth_address_create2_form": hx(ann.stealth_address),
            "ephemeral_pub_key": hx(ann.ephemeral_pub_key),
            "view_tag": hx(ann.view_tag),
        },
        "stealth_pk": hx(pk),
        "cases": cases,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--outdir",
                    default=str(pathlib.Path(__file__).parent / SCHEMA_VERSION))
    args = ap.parse_args()
    out = pathlib.Path(args.outdir) / "native_key.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(generate(), indent=2) + "\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
