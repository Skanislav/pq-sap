#!/usr/bin/env python3
"""Conformance vectors for the ML-DSA-44 committed-key profile
(``ml-dsa-44-commit/v0``) of the commitment meta-address (format 0x02).

Deterministic: seeded ML-DSA-44 keys (FIPS 204 ``_keygen_internal(zeta)``),
seeded ML-KEM-768 viewing keys, fixed encapsulation randomness, deterministic
ML-DSA signing (rnd = 0^32), and the same synthetic deployment binding the
commitment vectors use, so the CREATE2 address reproduces without a compiler.
The TS client (`js-client/test/mldsa44-commit-vectors.test.ts`) must reproduce
every field and re-verify every authorization payload with an independent
ML-DSA-44 implementation (@noble/post-quantum).

The negative authorization cases are the security boundary of the profile:
sender-known values (shared secret, opener) must not authorize a spend, and a
payload must not transfer to another commitment, digest, or domain profile.

Usage: generate_mldsa44_commit_vectors.py [-o OUTDIR]
"""

import argparse
import hashlib
import json
import pathlib

from pq_stealth.commit import (
    SPHINCS_C13_DOMAINS,
    Deployment,
    derive_commitment,
    derive_opener,
)
from pq_stealth.profiles import (
    ML_DSA_44_COMMIT_V0,
    build_authorization,
    check_with_profile,
    gen_ml_dsa_recipient,
    select_profile,
    send_with_profile,
    spend_key_from_ml_dsa_pk,
    verify_authorization,
)

SCHEMA_VERSION = "v0"
HERE = pathlib.Path(__file__).resolve().parent
PROFILE = ML_DSA_44_COMMIT_V0
CHAIN_ID = 31337  # synthetic binding: anvil's chain id, nothing deployed
DEP = Deployment(
    factory=bytes.fromhex("303cb317624c74bb20acbb9e13c8d745c6379826"),
    creation_code=bytes.fromhex("60806040526001600055"),
    verifier=bytes.fromhex("f01ecc1df1868c3b15f0edc4768812b9c435bbfb"),
    frame_ctx=bytes.fromhex("1adb9959eb142be128e6dfecc8d571f07cd66dee"),
)
DIGESTS = {
    "m-1": hashlib.sha256(b"pq-stealth/ml-dsa-44/vectors/digest/m-1").digest(),
    "m-2": hashlib.sha256(b"pq-stealth/ml-dsa-44/vectors/digest/m-2").digest(),
}


def hx(b: bytes) -> str:
    return "0x" + b.hex()


def flip(b: bytes, i: int) -> bytes:
    out = bytearray(b)
    out[i] ^= 0x01
    return bytes(out)


def generate() -> dict:
    binding = select_profile(PROFILE.name, CHAIN_ID, DEP)
    dsa = PROFILE.authorization.dsa
    meta_m, dk_m, pk_m, sk_m = gen_ml_dsa_recipient(
        PROFILE, zeta=b"\x91" * 32, kem_d=b"\x83" * 32, kem_z=b"\x84" * 32
    )
    meta_n, dk_n, pk_n, _sk_n = gen_ml_dsa_recipient(
        PROFILE, zeta=b"\x92" * 32, kem_d=b"\x85" * 32, kem_z=b"\x86" * 32
    )
    assert meta_m.spend_key == spend_key_from_ml_dsa_pk(pk_m, PROFILE)

    payments = {}
    cases = []
    for name, m in [("m-1", b"\x47" * 32), ("m-2", b"\x48" * 32)]:
        ann, commitment = send_with_profile(meta_m, binding, encaps_m=m)
        hit = check_with_profile(meta_m, dk_m, ann, binding)
        assert hit is not None and hit.commitment == commitment
        assert check_with_profile(meta_n, dk_n, ann, binding) is None
        payments[name] = (ann, hit, commitment)
        cases.append(
            {
                "name": name,
                "recipient": "m",
                "encaps_m": hx(m),
                "expect": "match",
                "announcement": {
                    "stealth_address": hx(ann.stealth_address),
                    "ephemeral_pub_key": hx(ann.ephemeral_pub_key),
                    "view_tag": hx(ann.view_tag),
                },
                "shared_secret": hx(hit.shared_secret),
                "opener": hx(hit.opener),
                "commitment": hx(commitment),
            }
        )
    cases.append(
        {
            "name": "m-1-seen-by-n",
            "recipient": "n",
            "expect": "no_match",
            "announcement": cases[0]["announcement"],
        }
    )

    # -- authorizations -------------------------------------------------------
    auths = []
    payload_of = {}
    for name in ("m-1", "m-2"):
        _ann, hit, commitment = payments[name]
        payload = build_authorization(
            sk_m, pk_m, hit.opener, DIGESTS[name], PROFILE, deterministic=True
        )
        assert verify_authorization(commitment, DIGESTS[name], payload, PROFILE)
        payload_of[name] = payload
        auths.append(
            {
                "name": name,
                "payment": name,
                "commitment": hx(commitment),
                "digest": hx(DIGESTS[name]),
                "payload": hx(payload),
                "expect": True,
                "note": "pk(1312) || opener(32) || sig(2420); deterministic "
                "ML-DSA-44 signature, empty ctx, over the 32-byte digest",
            }
        )

    _ann1, hit1, c1 = payments["m-1"]
    _ann2, hit2, c2 = payments["m-2"]
    p1 = payload_of["m-1"]
    pk_len, op_len = PROFILE.authorization.pk_bytes, 32

    def neg(name: str, commitment: bytes, digest: bytes, payload: bytes, why: str):
        assert not verify_authorization(commitment, digest, payload, PROFILE), name
        auths.append(
            {
                "name": name,
                "commitment": hx(commitment),
                "digest": hx(digest),
                "payload": hx(payload),
                "expect": False,
                "note": why,
            }
        )

    neg("wrong-digest", c1, DIGESTS["m-2"], p1, "signature over another digest")
    neg("wrong-commitment", c2, DIGESTS["m-1"], p1,
        "payload replayed against a different account commitment")
    neg("wrong-opener", c1, DIGESTS["m-1"],
        pk_m + hit2.opener + p1[pk_len + op_len:],
        "opener of another payment: commitment recomputes differently")
    neg("tampered-signature", c1, DIGESTS["m-1"], flip(p1, pk_len + op_len + 100),
        "one bit flipped in the signature")
    neg("tampered-pk", c1, DIGESTS["m-1"], flip(p1, 40),
        "one bit flipped in pk: spend_key and commitment change")
    neg("truncated", c1, DIGESTS["m-1"], p1[:-1], "payload one byte short")
    neg("extended", c1, DIGESTS["m-1"], p1 + b"\x00", "payload one byte long")
    neg("empty", c1, DIGESTS["m-1"], b"", "empty payload")

    # sender-known values are not credentials: a signer keyed from the shared
    # secret or the opener can sign, but its pk does not open the commitment
    for label, seed in [
        ("sender-key-from-shared-secret",
         hashlib.sha256(b"attacker/kdf" + hit1.shared_secret).digest()),
        ("sender-key-from-opener",
         hashlib.sha256(b"attacker/kdf" + hit1.opener).digest()),
    ]:
        apk, ask = dsa._keygen_internal(seed)
        att = build_authorization(ask, apk, hit1.opener, DIGESTS["m-1"], PROFILE,
                                  deterministic=True)
        assert dsa.verify(apk, DIGESTS["m-1"], att[pk_len + op_len:])
        neg(label, c1, DIGESTS["m-1"], att,
            "valid ML-DSA-44 signature under a key derived from sender-known "
            "material; keccak(KEY || pk) != published spend_key")
    # the recipient's real pk with a signature from another key
    apk, ask = dsa._keygen_internal(b"\x93" * 32)
    neg("signature-from-other-key", c1, DIGESTS["m-1"],
        pk_m + hit1.opener + dsa.sign(ask, DIGESTS["m-1"], deterministic=True),
        "correct pk and opener, signature under a different key")
    # domain profile confusion: the same spend_key/opener committed under the
    # C13 domains is a different account; the payload does not open it
    c13_commit = derive_commitment(
        meta_m.spend_key, derive_opener(hit1.shared_secret, SPHINCS_C13_DOMAINS),
        SPHINCS_C13_DOMAINS)
    neg("wrong-domain-profile", c13_commit, DIGESTS["m-1"], p1,
        "commitment formed under sphincs-c13-commit/v0 domains for the same "
        "spend_key and shared secret")

    # -- linkage (a property, not a bug: documented spend-time linkability) ---
    revealed = {n: payload_of[n][:pk_len] for n in ("m-1", "m-2")}
    assert revealed["m-1"] == revealed["m-2"] == pk_m
    assert spend_key_from_ml_dsa_pk(revealed["m-1"], PROFILE) == meta_m.spend_key

    return {
        "schema": SCHEMA_VERSION,
        "profile": {
            "name": PROFILE.name,
            "meta_address_version": PROFILE.meta_address_version,
            "kem": PROFILE.kem.name,
            "authorization": PROFILE.authorization.scheme,
            "message_convention": PROFILE.authorization.message_convention,
            "pk_bytes": PROFILE.authorization.pk_bytes,
            "sig_bytes": PROFILE.authorization.sig_bytes,
            "payload_bytes": PROFILE.authorization.payload_bytes,
            "domains": {
                "key": PROFILE.authorization.key_domain.decode(),
                "open": PROFILE.domains.open_domain.decode(),
                "commit": PROFILE.domains.commit_domain.decode(),
            },
            "spend_key": "keccak256(key || pk)",
            "opener": "SHA-256(open || ss)",
            "commitment": "keccak256(commit || spend_key || opener)",
            "view_tag": "SHA-256(ss)[0:1]",
            "spend_route_status": PROFILE.spend_route_status,
        },
        "binding": {
            "chain_id": CHAIN_ID,
            "factory": hx(DEP.factory),
            "creation_code": hx(DEP.creation_code),
            "verifier": hx(DEP.verifier),
            "frame_ctx": hx(DEP.frame_ctx),
            "salt": hx(DEP.salt),
            "layout": PROFILE.binding_layout,
            "note": "synthetic creation code: address derivation only, nothing "
            "deployable or deployed",
        },
        "recipients": {
            "m": {
                "zeta": hx(b"\x91" * 32),
                "ml_dsa_pk": hx(pk_m),
                "spend_key": hx(meta_m.spend_key),
                "seeds": {"kem_d": hx(b"\x83" * 32), "kem_z": hx(b"\x84" * 32)},
                "meta_address": hx(meta_m.encode()),
                "kem_dk": hx(dk_m),
            },
            "n": {
                "zeta": hx(b"\x92" * 32),
                "ml_dsa_pk": hx(pk_n),
                "spend_key": hx(meta_n.spend_key),
                "seeds": {"kem_d": hx(b"\x85" * 32), "kem_z": hx(b"\x86" * 32)},
                "meta_address": hx(meta_n.encode()),
                "kem_dk": hx(dk_n),
            },
        },
        "cases": cases,
        "authorizations": auths,
        "linkage": {
            "note": "both authorizations reveal the same pk; keccak256(key || pk) "
            "equals recipient m's published spend_key, so two direct spends are "
            "linkable to each other and to the meta-address",
            "revealed_pk_equal": True,
            "revealed_spend_key": hx(
                spend_key_from_ml_dsa_pk(revealed["m-1"], PROFILE)
            ),
        },
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--outdir", default=str(HERE / SCHEMA_VERSION))
    args = ap.parse_args()
    out = pathlib.Path(args.outdir) / "mldsa44_commit_vectors.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(generate(), indent=2) + "\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
