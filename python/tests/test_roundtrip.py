from pq_stealth import DEFAULT, check_announcement, gen_meta_address, scan, send


def test_recipient_detects_own_payment(recipient, announcement):
    meta_pub, meta_priv = recipient
    payment = check_announcement(meta_pub, meta_priv.kem_dk, announcement)
    assert payment is not None
    assert payment.stealth_pk is not None
    assert len(payment.announcement.stealth_address) == 20


def test_scan_filters_mixed_announcements(recipient, announcement):
    meta_pub, meta_priv = recipient
    other_pub, _ = gen_meta_address(DEFAULT, zeta=b"\x11" * 32,
                                    kem_d=b"\x12" * 32, kem_z=b"\x13" * 32)
    noise = [send(other_pub, encaps_m=bytes([i]) * 32) for i in range(3)]
    hits = scan(meta_pub, meta_priv.kem_dk, [*noise, announcement, *noise])
    assert len(hits) == 1
    assert hits[0].announcement == announcement


def test_distinct_payments_get_distinct_addresses(recipient):
    meta_pub, _ = recipient
    a1 = send(meta_pub, encaps_m=b"\x21" * 32)
    a2 = send(meta_pub, encaps_m=b"\x22" * 32)
    assert a1.stealth_address != a2.stealth_address
    assert a1.ephemeral_pub_key != a2.ephemeral_pub_key


def test_deterministic_send_is_reproducible(recipient, announcement):
    meta_pub, _ = recipient
    again = send(meta_pub, encaps_m=b"\x04" * 32)
    assert again == announcement
