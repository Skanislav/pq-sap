#!/usr/bin/env python3
"""Emit the on-chain fixture for the classical-spend hybrid's ERC-7913 route.

The counterpart to zknox_7913_demo.py for the ML-DSA scheme, and deliberately
much smaller. Where the ML-DSA scheme's signer is `verifier || pkPointer`
(over 20 bytes, dispatched to an on-chain verifier), the classical hybrid's
signer is the 20-byte stealth address with an empty key: the base case OZ's
SignatureChecker resolves through `ecrecover`. No verifier contract, no
PKContract, no expanded public key to store.

Fully deterministic (fixed seeds, fixed encapsulation randomness, RFC 6979
signing), so running it twice yields byte-identical output. The signature is
emitted in Ethereum's `r || s || v` form with `v` in {27, 28}, which is what
`ECDSA.tryRecover` (and therefore `Stealth7913Account.isValidSignature`)
expects; coincurve's native recovery id is remapped by adding 27.

Consumed by js-client/test/e2e-7913-classical.test.ts.

Usage: classical_7913_demo.py [-o OUTFILE]
"""

import argparse
import hashlib
import json
import pathlib

from coincurve import PublicKey

from pq_stealth.classical import (
    gen_meta_address, send, check_announcement, derive_stealth_privkey,
    eth_address, DEFAULT,
)

# Fixed inputs. Distinct from the conformance-vector seeds so the two
# artifacts cannot be confused, but equally deterministic.
SPEND_SEED = b"\x71" * 32
KEM_D = b"\x72" * 32
KEM_Z = b"\x73" * 32
ENCAPS_M = b"\x74" * 32

# Stands in for the message hash the account would actually be asked to
# validate (an ERC-191 / ERC-4337 userOp hash). ecrecover consumes the
# 32-byte hash directly, so no further hashing happens on-chain.
CHALLENGE = hashlib.sha256(b"pq-stealth/classical/erc7913 spend demo").digest()


def hx(b: bytes) -> str:
    return "0x" + b.hex()


def build() -> dict:
    meta_pub, meta_priv = gen_meta_address(
        DEFAULT, spend_seed=SPEND_SEED, kem_d=KEM_D, kem_z=KEM_Z)

    ann = send(meta_pub, encaps_m=ENCAPS_M)
    payment = check_announcement(meta_pub, meta_priv.kem_dk, ann)
    assert payment is not None, "recipient must detect its own payment"

    spend = derive_stealth_privkey(meta_priv.spend_priv, payment.shared_secret)
    stealth_address = eth_address(spend.public_key)
    assert stealth_address == ann.stealth_address, "address must match announcement"

    # The ERC-7913 signer for this scheme: the 20-byte stealth address, empty
    # key. `signer.length == 20`, so SignatureChecker takes the ecrecover path.
    signer = stealth_address

    # coincurve recovery id is 0..3; Ethereum's ecrecover wants v in {27, 28}.
    sig_c = spend.sign_recoverable(CHALLENGE, hasher=None)
    recovered = PublicKey.from_signature_and_message(sig_c, CHALLENGE, hasher=None)
    assert eth_address(recovered) == stealth_address, "self-check: sig must recover"
    sig_eth = sig_c[:64] + bytes([sig_c[64] + 27])

    return {
        "profile": "secp256k1 + ML-KEM-768 (classical spend, ERC-7913 20-byte base case)",
        "kem": "ML-KEM-768",
        "kem_ct": hx(ann.ephemeral_pub_key),
        "view_tag": hx(ann.view_tag),
        "meta_address": hx(meta_pub.encode()),
        "signer": hx(signer),
        "stealth_address": hx(stealth_address),
        "challenge": hx(CHALLENGE),
        "sig": hx(sig_eth),
        "sizes": {
            "signer": len(signer),
            "kem_ct": len(ann.ephemeral_pub_key),
            "sig": len(sig_eth),
        },
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--outfile",
                    default=pathlib.Path(__file__).parent / "classical_7913_demo.json")
    args = ap.parse_args()

    doc = build()
    out = pathlib.Path(args.outfile)
    out.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"wrote {out} ({out.stat().st_size} bytes): "
          f"signer {doc['sizes']['signer']} B, sig {doc['sizes']['sig']} B")
