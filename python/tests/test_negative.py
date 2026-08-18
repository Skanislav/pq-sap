from dataclasses import replace

from pq_stealth import DEFAULT, check_announcement, gen_meta_address


def test_wrong_view_tag_rejected(recipient, announcement):
    meta_pub, meta_priv = recipient
    bad = replace(announcement,
                  view_tag=bytes([announcement.view_tag[0] ^ 0xFF]))
    assert check_announcement(meta_pub, meta_priv.kem_dk, bad) is None


def test_wrong_recipient_no_match(announcement):
    other_pub, other_priv = gen_meta_address(
        DEFAULT, zeta=b"\x31" * 32, kem_d=b"\x32" * 32, kem_z=b"\x33" * 32)
    assert check_announcement(other_pub, other_priv.kem_dk,
                              announcement) is None


def test_truncated_ciphertext_rejected_not_raised(recipient, announcement):
    meta_pub, meta_priv = recipient
    bad = replace(announcement,
                  ephemeral_pub_key=announcement.ephemeral_pub_key[:-1])
    assert check_announcement(meta_pub, meta_priv.kem_dk, bad) is None


def test_bitflipped_ciphertext_no_match(recipient, announcement):
    # ML-KEM implicit rejection: decaps succeeds but yields an unrelated
    # shared secret, so the view tag (or address) must mismatch
    meta_pub, meta_priv = recipient
    ct = bytearray(announcement.ephemeral_pub_key)
    ct[0] ^= 0x01
    bad = replace(announcement, ephemeral_pub_key=bytes(ct))
    assert check_announcement(meta_pub, meta_priv.kem_dk, bad) is None


def test_tampered_stealth_address_no_match(recipient, announcement):
    meta_pub, meta_priv = recipient
    addr = bytearray(announcement.stealth_address)
    addr[-1] ^= 0x01
    bad = replace(announcement, stealth_address=bytes(addr))
    assert check_announcement(meta_pub, meta_priv.kem_dk, bad) is None
