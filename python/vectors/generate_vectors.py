#!/usr/bin/env python3
"""Generate versioned conformance vectors (positive and negative) as JSON.

Fully deterministic: recipient keys come from fixed seeds via the FIPS
internal keygen functions, encapsulation uses fixed randomness m, and
possession proofs use the deterministic signing variant (rnd = 0^32).
Running this script twice must produce byte-identical output.

Usage: generate_vectors.py [-o OUTDIR]
"""

import argparse
import json
import pathlib

from pq_stealth import (gen_meta_address, send, check_announcement,
                        prove_possession, Announcement, DEFAULT)

SCHEMA_VERSION = "v0"


def hx(b: bytes) -> str:
    return "0x" + b.hex()


def recipient_entry(zeta, kem_d, kem_z):
    meta_pub, meta_priv = gen_meta_address(
        DEFAULT, zeta=zeta, kem_d=kem_d, kem_z=kem_z)
    return meta_pub, meta_priv, {
        "seeds": {"zeta": hx(zeta), "kem_d": hx(kem_d), "kem_z": hx(kem_z)},
        "meta_address": hx(meta_pub.encode()),
        "kem_dk": hx(meta_priv.kem_dk),
    }


def ann_json(a: Announcement) -> dict:
    return {
        "stealth_address": hx(a.stealth_address),
        "ephemeral_pub_key": hx(a.ephemeral_pub_key),
        "view_tag": hx(a.view_tag),
    }


def generate() -> dict:
    pub_a, priv_a, rec_a = recipient_entry(b"\xa1" * 32, b"\xa2" * 32, b"\xa3" * 32)
    pub_b, priv_b, rec_b = recipient_entry(b"\xb1" * 32, b"\xb2" * 32, b"\xb3" * 32)

    ann1 = send(pub_a, encaps_m=b"\xc1" * 32)
    ann2 = send(pub_a, encaps_m=b"\xc2" * 32)

    payment = check_announcement(pub_a, priv_a.kem_dk, ann1)
    assert payment is not None
    challenge = b"pq-stealth conformance challenge"
    proof = prove_possession(priv_a, payment.stealth_pk, payment.t0,
                             payment.shared_secret, challenge,
                             deterministic=True)

    cases = [
        {
            "name": "positive/basic-match",
            "recipient": "A",
            "encaps_m": hx(b"\xc1" * 32),
            "announcement": ann_json(ann1),
            "stealth_pk": hx(payment.stealth_pk),
            "expect": "match",
        },
        {
            "name": "positive/second-payment-unlinkable",
            "recipient": "A",
            "encaps_m": hx(b"\xc2" * 32),
            "announcement": ann_json(ann2),
            "expect": "match",
            "note": "distinct stealth address for the same recipient",
        },
        {
            "name": "negative/wrong-view-tag",
            "recipient": "A",
            "announcement": {**ann_json(ann1),
                             "view_tag": hx(bytes([ann1.view_tag[0] ^ 0xFF]))},
            "expect": "no_match",
        },
        {
            "name": "negative/wrong-recipient",
            "recipient": "B",
            "announcement": ann_json(ann1),
            "expect": "no_match",
        },
        {
            "name": "negative/truncated-ciphertext",
            "recipient": "A",
            "announcement": {**ann_json(ann1),
                             "ephemeral_pub_key": hx(ann1.ephemeral_pub_key[:-1])},
            "expect": "no_match",
            "note": "malformed ciphertext must be rejected, not raise",
        },
        {
            "name": "negative/bitflipped-ciphertext",
            "recipient": "A",
            "announcement": {
                **ann_json(ann1),
                "ephemeral_pub_key": hx(
                    bytes([ann1.ephemeral_pub_key[0] ^ 0x01])
                    + ann1.ephemeral_pub_key[1:])},
            "expect": "no_match",
            "note": "ML-KEM implicit rejection yields an unrelated secret",
        },
        {
            "name": "possession/deterministic-proof",
            "recipient": "A",
            "announcement": ann_json(ann1),
            "challenge": hx(challenge),
            "proof": hx(proof),
            "expect": "valid_proof",
        },
    ]

    return {
        "schema": SCHEMA_VERSION,
        "scheme": "pq-stealth (ML-KEM encaps + additive ML-DSA key blinding, fresh error term)",
        "params": DEFAULT.name,
        "view_tag_bytes": DEFAULT.view_tag_bytes,
        "sizes": {
            "meta_address": DEFAULT.meta_address_bytes,
            "ephemeral_pub_key": DEFAULT.kem_ct_bytes,
            "stealth_pk": len(payment.stealth_pk),
            "signature": len(proof),
        },
        "recipients": {"A": rec_a, "B": rec_b},
        "cases": cases,
    }


def verify_vectors(doc: dict) -> None:
    """Self-check: replay every case through the library."""
    from pq_stealth import MetaPublic, verify_possession
    from pq_stealth.encoding import decode_meta_address

    def unhx(s):
        return bytes.fromhex(s[2:])

    pubs, dks = {}, {}
    for name, rec in doc["recipients"].items():
        rho, t, ek = decode_meta_address(unhx(rec["meta_address"]), DEFAULT)
        pubs[name] = MetaPublic(rho, t, ek, DEFAULT)
        dks[name] = unhx(rec["kem_dk"])

    for case in doc["cases"]:
        a = case["announcement"]
        ann = Announcement(unhx(a["stealth_address"]),
                           unhx(a["ephemeral_pub_key"]), unhx(a["view_tag"]))
        r = case["recipient"]
        payment = check_announcement(pubs[r], dks[r], ann)
        if case["expect"] == "match":
            assert payment is not None, case["name"]
        elif case["expect"] == "no_match":
            assert payment is None, case["name"]
        elif case["expect"] == "valid_proof":
            assert payment is not None, case["name"]
            assert verify_possession(DEFAULT, ann.stealth_address,
                                     payment.stealth_pk,
                                     unhx(case["challenge"]),
                                     unhx(case["proof"])), case["name"]
    print(f"self-check OK: {len(doc['cases'])} cases")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--outdir",
                    default=pathlib.Path(__file__).parent / "v0")
    args = ap.parse_args()

    doc = generate()
    verify_vectors(doc)
    out = pathlib.Path(args.outdir) / "vectors.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"wrote {out} ({out.stat().st_size} bytes)")
