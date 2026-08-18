import pytest

from pq_stealth import (
    DEFAULT,
    check_announcement,
    prove_possession,
    sign_blinded,
    verify,
    verify_possession,
)


@pytest.fixture(scope="module")
def payment(recipient, announcement):
    meta_pub, meta_priv = recipient
    p = check_announcement(meta_pub, meta_priv.kem_dk, announcement)
    assert p is not None
    return p


def test_blinded_signature_verifies_with_stock_verifier(recipient, payment):
    _, meta_priv = recipient
    msg = b"hello post-quantum stealth world"
    sig = sign_blinded(meta_priv, payment.stealth_pk, payment.t0,
                       payment.shared_secret, msg)
    assert verify(DEFAULT, payment.stealth_pk, msg, sig)
    # wrong message and tampered signature must fail
    assert not verify(DEFAULT, payment.stealth_pk, msg + b"!", sig)
    bad = bytearray(sig)
    bad[0] ^= 0x01
    assert not verify(DEFAULT, payment.stealth_pk, msg, bytes(bad))


def test_deterministic_signing_reproducible(recipient, payment):
    _, meta_priv = recipient
    msg = b"deterministic"
    s1 = sign_blinded(meta_priv, payment.stealth_pk, payment.t0,
                      payment.shared_secret, msg, deterministic=True)
    s2 = sign_blinded(meta_priv, payment.stealth_pk, payment.t0,
                      payment.shared_secret, msg, deterministic=True)
    assert s1 == s2


def test_proof_of_possession_roundtrip(recipient, payment):
    _, meta_priv = recipient
    challenge = b"prove you own this address"
    proof = prove_possession(meta_priv, payment.stealth_pk, payment.t0,
                             payment.shared_secret, challenge)
    addr = payment.announcement.stealth_address
    assert verify_possession(DEFAULT, addr, payment.stealth_pk,
                             challenge, proof)
    # wrong address and wrong challenge must fail
    other = bytes(20)
    assert not verify_possession(DEFAULT, other, payment.stealth_pk,
                                 challenge, proof)
    assert not verify_possession(DEFAULT, addr, payment.stealth_pk,
                                 b"different challenge", proof)


def test_blinded_signature_verifies_under_liboqs(recipient, payment):
    """Cross-check against the audited liboqs ML-DSA-65 verifier."""
    oqs = pytest.importorskip("oqs")
    _, meta_priv = recipient
    msg = b"cross-implementation check"
    sig = sign_blinded(meta_priv, payment.stealth_pk, payment.t0,
                       payment.shared_secret, msg)
    with oqs.Signature("ML-DSA-65") as verifier:
        assert verifier.verify(msg, sig, payment.stealth_pk)
