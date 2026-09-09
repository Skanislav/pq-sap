#!/usr/bin/env python3
"""Conformance vectors for the commitment meta-address (format 0x02).

Deterministic: the D-018 fixture's C13 key as the spend-key commitment, seeded
ML-KEM-768 viewing keys, fixed encapsulation randomness, and a synthetic
deployment binding (factory / creation code / verifier / frameCtx) so the
CREATE2 address is reproducible without a compiler. The TS client
(`js-client/test/commit-vectors.test.ts`) must reproduce every field.

Usage: generate_commit_vectors.py [-o OUTDIR]
"""

import argparse
import hashlib
import json
import pathlib

from pq_stealth.commit import (
    PREIMAGE_DOMAINS,
    PREIMAGE_KEY_DOMAIN,
    SPHINCS_C13_DOMAINS,
    Deployment,
    check_commit_announcement,
    gen_commit_meta_address,
    send_commit,
    spend_key_from_secret,
)

SCHEMA_VERSION = "v0"
HERE = pathlib.Path(__file__).resolve().parent
FIXTURE = HERE.parents[0] / "scripts" / "sphincs_c13_7913_demo.json"

DEP = Deployment(
    factory=bytes.fromhex("303cb317624c74bb20acbb9e13c8d745c6379826"),
    creation_code=bytes.fromhex("60806040526001600055"),
    verifier=bytes.fromhex("f01ecc1df1868c3b15f0edc4768812b9c435bbfb"),
    frame_ctx=bytes.fromhex("1adb9959eb142be128e6dfecc8d571f07cd66dee"),
)


def hx(b: bytes) -> str:
    return "0x" + b.hex()


def generate() -> dict:
    fx = json.loads(FIXTURE.read_text())
    spend_key = bytes.fromhex(fx["key"].removeprefix("0x"))
    meta_a, dk_a = gen_commit_meta_address(
        spend_key, kem_d=b"\x83" * 32, kem_z=b"\x84" * 32
    )
    meta_b, dk_b = gen_commit_meta_address(
        b"\xbb" * 32, kem_d=b"\x85" * 32, kem_z=b"\x86" * 32
    )
    # recipient c: preimage-ownership scheme (D-025) — spend_key = keccak(KEY || sk),
    # sk = SHA-256("pq-stealth/preimage/keygen/v0" || spend_seed) as the demo derives it
    sk_c = hashlib.sha256(b"pq-stealth/preimage/keygen/v0" + b"\x81" * 32).digest()
    meta_c, dk_c = gen_commit_meta_address(
        spend_key_from_secret(sk_c), kem_d=b"\x83" * 32, kem_z=b"\x84" * 32
    )
    domains_of = {
        "a": SPHINCS_C13_DOMAINS,
        "b": SPHINCS_C13_DOMAINS,
        "c": PREIMAGE_DOMAINS,
    }

    cases = []
    for name, meta, dk, m, expect in [
        ("a-1", meta_a, dk_a, b"\x47" * 32, "match"),
        ("a-2", meta_a, dk_a, b"\x48" * 32, "match"),
        ("b-1", meta_b, dk_b, b"\x49" * 32, "match"),
        ("c-1", meta_c, dk_c, b"\x4a" * 32, "match"),
    ]:
        dom = domains_of[name[0]]
        ann, commitment = send_commit(meta, DEP, encaps_m=m, domains=dom)
        hit = check_commit_announcement(meta, dk, ann, DEP, domains=dom)
        assert hit is not None and hit.commitment == commitment
        cases.append(
            {
                "name": name,
                "recipient": name[0],
                "encaps_m": hx(m),
                "expect": expect,
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
    # recipient b must not see a's payment
    ann_a, _ = send_commit(meta_a, DEP, encaps_m=b"\x47" * 32)
    assert check_commit_announcement(meta_b, dk_b, ann_a, DEP) is None
    cases.append(
        {
            "name": "a-1-seen-by-b",
            "recipient": "b",
            "expect": "no_match",
            "announcement": cases[0]["announcement"],
        }
    )

    return {
        "schema": SCHEMA_VERSION,
        "format": "version(1)=0x02 || spend_key(32) || ML-KEM-768 ek(1184) = 1217 B",
        "domains": {
            "sphincs-c13": {
                "open": SPHINCS_C13_DOMAINS.open_domain.decode(),
                "commit": SPHINCS_C13_DOMAINS.commit_domain.decode(),
            },
            "preimage": {
                "open": PREIMAGE_DOMAINS.open_domain.decode(),
                "commit": PREIMAGE_DOMAINS.commit_domain.decode(),
                "key": PREIMAGE_KEY_DOMAIN.decode(),
                "spend_key": "keccak256(key || sk)",
            },
            "opener": "SHA-256(open || ss)",
            "commitment": "keccak256(commit || spend_key || opener)",
            "view_tag": "SHA-256(ss)[0:1]",
        },
        "deployment": {
            "factory": hx(DEP.factory),
            "creation_code": hx(DEP.creation_code),
            "verifier": hx(DEP.verifier),
            "frame_ctx": hx(DEP.frame_ctx),
            "salt": hx(DEP.salt),
            "address": "CREATE2(factory, salt, keccak256(creation_code || commitment"
            " || pad32(verifier) || pad32(frame_ctx)))",
        },
        "recipients": {
            "a": {
                "spend_key": hx(meta_a.spend_key),
                "spend_key_source": "D-018 fixture C13 key",
                "seeds": {"kem_d": hx(b"\x83" * 32), "kem_z": hx(b"\x84" * 32)},
                "meta_address": hx(meta_a.encode()),
                "kem_dk": hx(dk_a),
            },
            "b": {
                "spend_key": hx(meta_b.spend_key),
                "seeds": {"kem_d": hx(b"\x85" * 32), "kem_z": hx(b"\x86" * 32)},
                "meta_address": hx(meta_b.encode()),
                "kem_dk": hx(dk_b),
            },
            "c": {
                "scheme": "preimage",
                "spend_seed": hx(b"\x81" * 32),
                "sk": hx(sk_c),
                "spend_key": hx(meta_c.spend_key),
                "seeds": {"kem_d": hx(b"\x83" * 32), "kem_z": hx(b"\x84" * 32)},
                "meta_address": hx(meta_c.encode()),
                "kem_dk": hx(dk_c),
            },
        },
        "cases": cases,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--outdir", default=str(HERE / SCHEMA_VERSION))
    args = ap.parse_args()
    out = pathlib.Path(args.outdir) / "commit_vectors.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(generate(), indent=2) + "\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
