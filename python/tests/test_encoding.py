from pq_stealth import (decode_meta_address, pack_blinded_sk,
                        unpack_blinded_sk, derive_blinding, DEFAULT,
                        check_announcement)
from pq_stealth.encoding import pack_t, unpack_t


def _vecs_equal(a, b):
    return all(ra[0].coeffs == rb[0].coeffs
               for ra, rb in zip(a._data, b._data))


def test_measured_sizes_match_spec(recipient, announcement):
    meta_pub, _ = recipient
    assert DEFAULT.t_bytes == 4416
    assert DEFAULT.meta_address_bytes == 5633
    assert len(meta_pub.encode()) == 5633
    assert len(announcement.ephemeral_pub_key) == 1088
    assert len(announcement.view_tag) == 1
    assert len(announcement.stealth_address) == 20


def test_stealth_pk_and_sig_sizes(recipient, announcement):
    meta_pub, meta_priv = recipient
    payment = check_announcement(meta_pub, meta_priv.kem_dk, announcement)
    assert len(payment.stealth_pk) == 1952       # standard ML-DSA-65 pk
    from pq_stealth import sign_blinded
    sig = sign_blinded(meta_priv, payment.stealth_pk, payment.t0,
                       payment.shared_secret, b"size check")
    assert len(sig) == 3309                       # standard ML-DSA-65 sig


def test_t_pack_roundtrip(recipient):
    meta_pub, _ = recipient
    packed = pack_t(meta_pub.t, DEFAULT)
    assert len(packed) == DEFAULT.t_bytes
    assert _vecs_equal(unpack_t(packed, DEFAULT), meta_pub.t)


def test_meta_address_roundtrip(recipient, announcement):
    meta_pub, meta_priv = recipient
    rho, t, kem_ek = decode_meta_address(meta_pub.encode(), DEFAULT)
    assert rho == meta_pub.rho
    assert kem_ek == meta_pub.kem_ek
    assert _vecs_equal(t, meta_pub.t)
    # a decoded meta-address is fully usable: re-derive the same payment
    from pq_stealth import MetaPublic
    rebuilt = MetaPublic(rho, t, kem_ek, DEFAULT)
    assert check_announcement(rebuilt, meta_priv.kem_dk,
                              announcement) is not None


def test_blinded_sk_pack_roundtrip(recipient, announcement):
    meta_pub, meta_priv = recipient
    payment = check_announcement(meta_pub, meta_priv.kem_dk, announcement)
    s_p, e_p = derive_blinding(payment.shared_secret, DEFAULT)
    s1_b, s2_b = meta_priv.s1 + s_p, meta_priv.s2 + e_p
    blob = pack_blinded_sk(meta_pub.rho, s1_b, s2_b, payment.t0, DEFAULT)
    rho2, s1_2, s2_2, t0_2 = unpack_blinded_sk(blob, DEFAULT)
    assert rho2 == meta_pub.rho
    from pq_stealth.encoding import _centered
    for orig, rt in ((s1_b, s1_2), (s2_b, s2_2), (payment.t0, t0_2)):
        for ro, rr in zip(orig._data, rt._data):
            assert [_centered(c) for c in ro[0].coeffs] == \
                   [_centered(c) for c in rr[0].coeffs]
