#!/usr/bin/env python3
"""Fixture for the ML-DSA-44 committed-key spend route
(`ml-dsa-44-commit/v0`, `js-client/contracts/src/MlDsa44CommitSigner7913.sol`).

Deterministic (seeded ML-DSA-44 key via FIPS 204 `_keygen_internal`, seeded
ML-KEM-768 viewing key, fixed encapsulation randomness, deterministic
signing), so a regenerated file must be byte-identical. Emits:

  * ml_dsa_pk         — the canonical 1,312-byte ML-DSA-44 public key
  * spend_key         — keccak256("pq-stealth/ml-dsa-44/key/v0" || pk)
  * public_key_data   — abi(bytes,bytes,bytes) = (aHat NTT, tr, t1 plain), the
                        expanded key exactly as the ZKNOX PKContract stores it
                        (df999ed format); registered by the trusted registrar
  * a_hat             — the same aHat as uint256[4][4][32] for `vm.parseJson`
  * shared secret / opener / commitment for one payment under the profile
  * digest + payload  — `pk || opener || sig`, the ERC-7913 signature bytes
  * negatives         — a payload signed for another digest, one with a
                        sender-derived key

The expanded key is what makes this route need a trusted key setup: expanding
`rho` into `aHat` on chain costs ~40 M gas with the vendored SHAKE, so the
registry trusts its registrar to supply `aHat = ExpandA(rho)`; `tr` and `t1`
are recomputed on chain from the pk bytes. See docs/ml-dsa-commit-profile.md.

Usage: mldsa44_commit_7913_demo.py -o mldsa44_commit_7913_demo.json
(needs `eth_abi`, as the other ZKNOX fixture generators do)
"""

import argparse
import hashlib
import json
import pathlib

from eth_abi import encode

from pq_stealth.commit import Deployment
from pq_stealth.profiles import (
    ML_DSA_44_COMMIT_V0,
    build_authorization,
    check_with_profile,
    gen_ml_dsa_recipient,
    select_profile,
    send_with_profile,
    verify_authorization,
)

PROFILE = ML_DSA_44_COMMIT_V0
DSA = PROFILE.authorization.dsa
# Only the domains/derivation matter for the on-chain test; the CREATE2
# binding is re-derived by the contracts themselves (real creation code).
DEP = Deployment(
    factory=bytes.fromhex("303cb317624c74bb20acbb9e13c8d745c6379826"),
    creation_code=bytes.fromhex("60806040526001600055"),
    verifier=bytes.fromhex("f01ecc1df1868c3b15f0edc4768812b9c435bbfb"),
    frame_ctx=bytes.fromhex("1adb9959eb142be128e6dfecc8d571f07cd66dee"),
)


def hx(b: bytes) -> str:
    return "0x" + b.hex()


def compact_256(coeffs: list[int]) -> list[int]:
    """ZKNOX packing: 8 coefficients of 32 bits per uint256 word (little end)."""
    assert len(coeffs) == 256 and all(0 <= c < (1 << 32) for c in coeffs)
    return [
        sum(coeffs[8 * w + j] << (32 * j) for j in range(8)) for w in range(32)
    ]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--out", required=True)
    args = ap.parse_args()

    binding = select_profile(PROFILE.name, 31337, DEP)
    meta, dk, pk, sk = gen_ml_dsa_recipient(
        PROFILE, zeta=b"\xa1" * 32, kem_d=b"\xa2" * 32, kem_z=b"\xa3" * 32
    )
    ann, commitment = send_with_profile(meta, binding, encaps_m=b"\xa4" * 32)
    hit = check_with_profile(meta, dk, ann, binding)
    assert hit is not None and hit.commitment == commitment

    # expanded key in the ZKNOX df999ed PKContract format
    rho, t1 = DSA._unpack_pk(pk)
    a_hat = DSA._expand_matrix_from_seed(rho)  # NTT domain (FIPS 204 ExpandA)
    tr = DSA._h(pk, 64)
    a_hat_compact = [
        [compact_256(a_hat[i, j].coeffs) for j in range(DSA.l)] for i in range(DSA.k)
    ]
    t1_compact = [compact_256(t1[i, 0].coeffs) for i in range(DSA.k)]
    public_key_data = encode(
        ["bytes", "bytes", "bytes"],
        [
            encode(["uint256[][][]"], [a_hat_compact]),
            tr,
            encode(["uint256[][]"], [t1_compact]),
        ],
    )

    digest = hashlib.sha256(b"pq-stealth/ml-dsa-44/7913-demo/digest").digest()
    payload = build_authorization(sk, pk, hit.opener, digest, PROFILE, True)
    assert verify_authorization(commitment, digest, payload, PROFILE)
    other_digest = hashlib.sha256(b"pq-stealth/ml-dsa-44/7913-demo/other").digest()
    payload_other = build_authorization(
        sk, pk, hit.opener, other_digest, PROFILE, True
    )
    apk, ask = DSA._keygen_internal(hashlib.sha256(b"kdf" + hit.shared_secret).digest())
    sender_payload = build_authorization(ask, apk, hit.opener, digest, PROFILE, True)
    assert not verify_authorization(commitment, digest, sender_payload, PROFILE)

    out = {
        "profile": PROFILE.name,
        "verifier": "ZKNOX ETHDILITHIUM df999ed ZKNOX_dilithium (NIST/SHAKE, "
        "k = l = 4): accepts FIPS 204 ML-DSA-44 signatures, M' = 0x00||0x00||m",
        "ml_dsa_pk": hx(pk),
        "spend_key": hx(meta.spend_key),
        "meta_address": hx(meta.encode()),
        "tr": hx(tr),
        "a_hat": a_hat_compact,
        "t1": t1_compact,
        "public_key_data": hx(public_key_data),
        "kem_ct": hx(ann.ephemeral_pub_key),
        "view_tag": hx(ann.view_tag),
        "shared_secret_DEMO_ONLY": hx(hit.shared_secret),
        "opener": hx(hit.opener),
        "commitment": hx(commitment),
        "digest": hx(digest),
        "payload": hx(payload),
        "other_digest": hx(other_digest),
        "payload_other_digest": hx(payload_other),
        "sender_derived_pk": hx(apk),
        "sender_derived_payload": hx(sender_payload),
    }
    pathlib.Path(args.out).write_text(json.dumps(out, indent=2) + "\n")
    print(
        f"pk {len(pk)} B, public_key_data {len(public_key_data)} B, "
        f"payload {len(payload)} B -> {args.out}"
    )


if __name__ == "__main__":
    main()
