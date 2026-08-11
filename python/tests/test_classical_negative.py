"""Negative tests for the classical-spend hybrid.

Mirrors test_negative.py for the ML-DSA scheme (view-tag, wrong recipient,
malformed and bit-flipped ciphertext, tampered address), plus the
encoding-level checks specific to this scheme's meta-address.
"""

from dataclasses import replace

import pytest

pytest.importorskip("coincurve")  # the classical scheme needs the bench extra

from pq_stealth.classical import (  # noqa: E402
    gen_meta_address, send, check_announcement, decode_meta_address, DEFAULT,
)


def _recipient():
    return gen_meta_address(DEFAULT, spend_seed=b"\x01" * 32,
                            kem_d=b"\x02" * 32, kem_z=b"\x03" * 32)


def _announcement(meta_pub):
    return send(meta_pub, encaps_m=b"\x04" * 32)


def test_wrong_view_tag_rejected():
    meta_pub, meta_priv = _recipient()
    ann = _announcement(meta_pub)
    bad = replace(ann, view_tag=bytes([ann.view_tag[0] ^ 0xFF]))
    assert check_announcement(meta_pub, meta_priv.kem_dk, bad) is None


def test_wrong_recipient_no_match():
    meta_pub, _ = _recipient()
    ann = _announcement(meta_pub)
    other_pub, other_priv = gen_meta_address(
        DEFAULT, spend_seed=b"\x31" * 32, kem_d=b"\x32" * 32, kem_z=b"\x33" * 32)
    assert check_announcement(other_pub, other_priv.kem_dk, ann) is None


def test_truncated_ciphertext_rejected_not_raised():
    meta_pub, meta_priv = _recipient()
    ann = _announcement(meta_pub)
    bad = replace(ann, ephemeral_pub_key=ann.ephemeral_pub_key[:-1])
    assert check_announcement(meta_pub, meta_priv.kem_dk, bad) is None


def test_bitflipped_ciphertext_no_match():
    # ML-KEM implicit rejection: decaps succeeds but yields an unrelated
    # shared secret, so the view tag (or address) must mismatch
    meta_pub, meta_priv = _recipient()
    ann = _announcement(meta_pub)
    ct = bytearray(ann.ephemeral_pub_key)
    ct[0] ^= 0x01
    bad = replace(ann, ephemeral_pub_key=bytes(ct))
    assert check_announcement(meta_pub, meta_priv.kem_dk, bad) is None


def test_tampered_stealth_address_no_match():
    meta_pub, meta_priv = _recipient()
    ann = _announcement(meta_pub)
    addr = bytearray(ann.stealth_address)
    addr[-1] ^= 0x01
    bad = replace(ann, stealth_address=bytes(addr))
    assert check_announcement(meta_pub, meta_priv.kem_dk, bad) is None


def test_empty_ciphertext_rejected_not_raised():
    meta_pub, meta_priv = _recipient()
    ann = _announcement(meta_pub)
    bad = replace(ann, ephemeral_pub_key=b"")
    assert check_announcement(meta_pub, meta_priv.kem_dk, bad) is None


def test_meta_address_wrong_version_rejected():
    meta_pub, _ = _recipient()
    blob = bytearray(meta_pub.encode())
    blob[0] ^= 0xFF  # corrupt the version byte
    with pytest.raises(ValueError):
        decode_meta_address(bytes(blob), DEFAULT)


def test_meta_address_wrong_length_rejected():
    meta_pub, _ = _recipient()
    with pytest.raises(ValueError):
        decode_meta_address(meta_pub.encode()[:-1], DEFAULT)


def test_announcement_shorter_ciphertext_than_scheme():
    # a ciphertext of a smaller ML-KEM parameter set must not match
    meta_pub, meta_priv = _recipient()
    ann = _announcement(meta_pub)
    bad = replace(ann, ephemeral_pub_key=ann.ephemeral_pub_key[:768])
    assert check_announcement(meta_pub, meta_priv.kem_dk, bad) is None
