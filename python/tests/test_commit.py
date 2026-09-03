"""Commitment meta-address (format 0x02): encoding, derivation, scan."""

import json
import pathlib

import pytest

from pq_stealth.commit import (
    DEFAULT_KEM,
    KEM_SETS,
    SPHINCS_C13_DOMAINS,
    CommitAnnouncement,
    Deployment,
    account_address,
    check_commit_announcement,
    decode_commit_meta_address,
    derive_commitment,
    derive_opener,
    encode_commit_meta_address,
    gen_commit_meta_address,
    scan_commit,
    send_commit,
)
from pq_stealth.encoding import keccak256

FIXTURE = (
    pathlib.Path(__file__).resolve().parents[1]
    / "scripts"
    / "sphincs_c13_7913_demo.json"
)
DEP = Deployment(
    factory=bytes.fromhex("303cb317624c74bb20acbb9e13c8d745c6379826"),
    creation_code=bytes.fromhex("60806040526001600055"),  # synthetic, vectors only
    verifier=bytes.fromhex("f01ecc1df1868c3b15f0edc4768812b9c435bbfb"),
    frame_ctx=bytes.fromhex("1adb9959eb142be128e6dfecc8d571f07cd66dee"),
)


@pytest.fixture(scope="module")
def recipient():
    fx = json.loads(FIXTURE.read_text())
    spend_key = bytes.fromhex(fx["key"].removeprefix("0x"))
    meta, dk = gen_commit_meta_address(
        spend_key, kem_d=b"\x83" * 32, kem_z=b"\x84" * 32
    )
    return fx, meta, dk


def test_meta_address_is_1217_bytes(recipient):
    _, meta, _ = recipient
    enc = meta.encode()
    assert len(enc) == 1217 == DEFAULT_KEM.meta_address_bytes
    assert enc[0] == 0x02
    back = decode_commit_meta_address(enc)
    assert back.spend_key == meta.spend_key and back.kem_ek == meta.kem_ek
    for k in KEM_SETS.values():
        assert k.meta_address_bytes == 33 + k.ek_bytes


def test_encode_rejects_bad_sizes(recipient):
    _, meta, _ = recipient
    with pytest.raises(ValueError):
        encode_commit_meta_address(b"\x00" * 31, meta.kem_ek)
    with pytest.raises(ValueError):
        encode_commit_meta_address(meta.spend_key, meta.kem_ek[:-1])
    with pytest.raises(ValueError):
        decode_commit_meta_address(b"\x01" + meta.encode()[1:])


def test_derivation_matches_the_d018_fixture(recipient):
    """Same opener/commitment as the deployed C13 commit signer and ZK circuit."""
    fx, meta, _ = recipient
    ss = bytes.fromhex(fx["shared_secret_DEMO_ONLY"].removeprefix("0x"))
    opener = derive_opener(ss)
    assert opener == bytes.fromhex(fx["opener"].removeprefix("0x"))
    assert derive_commitment(meta.spend_key, opener) == bytes.fromhex(
        fx["commitment"].removeprefix("0x")
    )
    assert derive_commitment(meta.spend_key, opener) == keccak256(
        SPHINCS_C13_DOMAINS.commit_domain + meta.spend_key + opener
    )


def test_create2_binding_is_deterministic():
    c = b"\x11" * 32
    a = account_address(c, DEP)
    assert len(a) == 20 and a == account_address(c, DEP)
    assert a != account_address(b"\x12" * 32, DEP)
    init = (
        DEP.creation_code
        + c
        + DEP.verifier.rjust(32, b"\x00")
        + DEP.frame_ctx.rjust(32, b"\x00")
    )
    assert a == keccak256(b"\xff" + DEP.factory + b"\x00" * 32 + keccak256(init))[12:]


def test_send_scan_roundtrip(recipient):
    _, meta, dk = recipient
    ann, commitment = send_commit(meta, DEP, encaps_m=b"\x47" * 32)
    assert len(ann.stealth_address) == 20 and len(ann.ephemeral_pub_key) == 1088
    hit = check_commit_announcement(meta, dk, ann, DEP)
    assert hit is not None
    assert hit.commitment == commitment
    assert account_address(hit.commitment, DEP) == ann.stealth_address
    # a second payment gets a different address from the same key
    ann2, c2 = send_commit(meta, DEP, encaps_m=b"\x48" * 32)
    assert c2 != commitment and ann2.stealth_address != ann.stealth_address
    assert len(scan_commit(meta, dk, [ann, ann2], DEP)) == 2


def test_negatives(recipient):
    _, meta, dk = recipient
    ann, _ = send_commit(meta, DEP, encaps_m=b"\x47" * 32)
    # wrong viewing key
    _, other_dk = gen_commit_meta_address(
        meta.spend_key, kem_d=b"\x01" * 32, kem_z=b"\x02" * 32
    )
    assert check_commit_announcement(meta, other_dk, ann, DEP) is None
    # wrong view tag
    bad = CommitAnnouncement(
        ann.stealth_address, ann.ephemeral_pub_key, bytes([ann.view_tag[0] ^ 1])
    )
    assert check_commit_announcement(meta, dk, bad, DEP) is None
    # wrong address
    bad = CommitAnnouncement(b"\x00" * 20, ann.ephemeral_pub_key, ann.view_tag)
    assert check_commit_announcement(meta, dk, bad, DEP) is None
    # malformed ciphertext never raises
    bad = CommitAnnouncement(ann.stealth_address, b"\x00" * 10, ann.view_tag)
    assert check_commit_announcement(meta, dk, bad, DEP) is None
    # different deployment, different address
    other = Deployment(b"\x01" * 20, DEP.creation_code, DEP.verifier, DEP.frame_ctx)
    assert check_commit_announcement(meta, dk, ann, other) is None
