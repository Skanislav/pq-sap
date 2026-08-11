"""End-to-end tests for the classical-spend hybrid.

Mirrors test_roundtrip.py for the ML-DSA scheme, plus the piece that scheme
cannot exercise: the recipient derives the stealth EOA private key and
proves control with a plain ECDSA signature (recover -> same address).
"""

import hashlib

import pytest

pytest.importorskip("coincurve")  # the classical scheme needs the bench extra

from coincurve import PublicKey  # noqa: E402

from pq_stealth.classical import (  # noqa: E402
    gen_meta_address, send, scan, check_announcement,
    derive_stealth_privkey, eth_address, encode_meta_address,
    decode_meta_address, DEFAULT,
)


def _recipient():
    return gen_meta_address(DEFAULT, spend_seed=b"\x01" * 32, kem_d=b"\x02" * 32, kem_z=b"\x03" * 32)


def test_recipient_detects_own_payment():
    meta_pub, meta_priv = _recipient()
    ann = send(meta_pub, encaps_m=b"\x04" * 32)
    payment = check_announcement(meta_pub, meta_priv.kem_dk, ann)
    assert payment is not None
    assert len(payment.stealth_address) == 20
    assert payment.stealth_address == ann.stealth_address


def test_scan_filters_mixed_announcements():
    meta_pub, meta_priv = _recipient()
    ann = send(meta_pub, encaps_m=b"\x04" * 32)
    other_pub, _ = gen_meta_address(DEFAULT, spend_seed=b"\x11" * 32, kem_d=b"\x12" * 32, kem_z=b"\x13" * 32)
    noise = [send(other_pub, encaps_m=bytes([i]) * 32) for i in range(3)]
    hits = scan(meta_pub, meta_priv.kem_dk, noise + [ann] + noise)
    assert len(hits) == 1
    assert hits[0].announcement == ann


def test_distinct_payments_get_distinct_addresses():
    meta_pub, _ = _recipient()
    a1 = send(meta_pub, encaps_m=b"\x21" * 32)
    a2 = send(meta_pub, encaps_m=b"\x22" * 32)
    assert a1.stealth_address != a2.stealth_address
    assert a1.ephemeral_pub_key != a2.ephemeral_pub_key


def test_deterministic_send_is_reproducible():
    meta_pub, _ = _recipient()
    a1 = send(meta_pub, encaps_m=b"\x04" * 32)
    a2 = send(meta_pub, encaps_m=b"\x04" * 32)
    assert a1 == a2


def test_derived_key_controls_the_stealth_address():
    """The property the ML-DSA scheme defers to EIP-8141: a plain ECDSA
    signature from the derived key recovers to the stealth address."""
    meta_pub, meta_priv = _recipient()
    ann = send(meta_pub, encaps_m=b"\x04" * 32)
    payment = check_announcement(meta_pub, meta_priv.kem_dk, ann)
    assert payment is not None

    priv = derive_stealth_privkey(meta_priv.spend_priv, payment.shared_secret)
    # the private key's own pubkey yields the announced address
    assert eth_address(priv.public_key) == ann.stealth_address

    # and a real ECDSA signature recovers to that same address
    msg = hashlib.sha256(b"spend").digest()
    sig = priv.sign_recoverable(msg, hasher=None)
    recovered = PublicKey.from_signature_and_message(sig, msg, hasher=None)
    assert eth_address(recovered) == ann.stealth_address


def test_meta_address_roundtrips():
    meta_pub, _ = _recipient()
    blob = encode_meta_address(meta_pub.spend_pub, meta_pub.kem_ek, DEFAULT)
    assert len(blob) == DEFAULT.meta_address_bytes
    spend_pub, kem_ek = decode_meta_address(blob, DEFAULT)
    assert spend_pub == meta_pub.spend_pub
    assert kem_ek == meta_pub.kem_ek
