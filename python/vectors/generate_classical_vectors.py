#!/usr/bin/env python3
"""Generate versioned conformance vectors for the classical-spend hybrid.

Fully deterministic: recipient keys come from fixed seeds (secp256k1 from a
32-byte seed, ML-KEM from the FIPS internal keygen), encapsulation uses
fixed randomness m, and the possession signature uses RFC 6979 (coincurve /
libsecp256k1 is deterministic). Running this script twice must produce
byte-identical output.

Usage: generate_classical_vectors.py [-o OUTDIR]
"""

import argparse
import hashlib
import json
import pathlib

from coincurve import PublicKey

from pq_stealth.classical import (
    gen_meta_address, send, check_announcement, derive_stealth_privkey,
    eth_address, Announcement, DEFAULT,
)

SCHEMA_VERSION = "v0"


def hx(b: bytes) -> str:
    return "0x" + b.hex()


def recipient_entry(spend_seed, kem_d, kem_z):
    meta_pub, meta_priv = gen_meta_address(
        DEFAULT, spend_seed=spend_seed, kem_d=kem_d, kem_z=kem_z)
    return meta_pub, meta_priv, {
        "seeds": {"spend_seed": hx(spend_seed),
                  "kem_d": hx(kem_d), "kem_z": hx(kem_z)},
        "meta_address": hx(meta_pub.encode()),
        "spend_priv": hx(meta_priv.spend_priv),
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

    # possession: derive the stealth EOA key and sign a challenge; recovering
    # the signature must yield the announced address (a plain ECDSA spend).
    spend = derive_stealth_privkey(priv_a.spend_priv, payment.shared_secret)
    challenge = hashlib.sha256(b"pq-stealth conformance challenge").digest()
    signature = spend.sign_recoverable(challenge, hasher=None)

    cases = [
        {
            "name": "positive/basic-match",
            "recipient": "A",
            "encaps_m": hx(b"\xc1" * 32),
            "announcement": ann_json(ann1),
            "stealth_pub": hx(payment.stealth_pub),
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
            "name": "possession/ecdsa-spend",
            "recipient": "A",
            "announcement": ann_json(ann1),
            "challenge": hx(challenge),
            "spend_key": hx(spend.secret),
            "signature": hx(signature),
            "expect": "valid_proof",
            "note": "recoverable ECDSA (RFC 6979) over the 32-byte challenge",
        },
    ]

    return {
        "schema": SCHEMA_VERSION,
        "scheme": "classical-spend hybrid (ML-KEM encaps + additive secp256k1 key blinding)",
        "params": DEFAULT.name,
        "view_tag_bytes": DEFAULT.view_tag_bytes,
        "sizes": {
            "meta_address": DEFAULT.meta_address_bytes,
            "ephemeral_pub_key": DEFAULT.kem_ct_bytes,
            "stealth_pub": len(payment.stealth_pub),
            "signature": len(signature),
        },
        "recipients": {"A": rec_a, "B": rec_b},
        "cases": cases,
    }


def verify_vectors(doc: dict) -> None:
    """Self-check: replay every case through the library."""
    from pq_stealth.classical import MetaPublic, decode_meta_address

    def unhx(s):
        return bytes.fromhex(s[2:])

    pubs, dks = {}, {}
    for name, rec in doc["recipients"].items():
        spend_pub, ek = decode_meta_address(unhx(rec["meta_address"]), DEFAULT)
        pubs[name] = MetaPublic(spend_pub, ek, DEFAULT)
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
            challenge = unhx(case["challenge"])
            recovered = PublicKey.from_signature_and_message(
                unhx(case["signature"]), challenge, hasher=None)
            assert eth_address(recovered) == ann.stealth_address, case["name"]
    print(f"self-check OK: {len(doc['cases'])} cases")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--outdir",
                    default=pathlib.Path(__file__).parent / "classical" / "v0")
    args = ap.parse_args()

    doc = generate()
    verify_vectors(doc)
    out = pathlib.Path(args.outdir) / "vectors.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"wrote {out} ({out.stat().st_size} bytes)")
