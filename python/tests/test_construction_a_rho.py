"""Construction A (format 0x01) key-disclosure check: the blinded stealth
public key carries the recipient's matrix seed `rho` verbatim.

`derive_stealth_pk` returns `pack_pk(rho, t1')` where `rho` is the same
32-byte seed the recipient publishes in its meta-address
(`0x01 || rho || pack23(t) || kem_ek`). The blinding hides `t`, not `rho`.
Announcements only expose `keccak256(stealth_pk)[12:]`, so receive-time
privacy is unaffected; but any spend route that reveals the full stealth
public key (an ML-DSA signature verified against `stealth_pk`, a deployed
`PKContract` holding `ExpandA(rho)`, a pointer-signature key table) exposes
`rho`, and `rho` alone identifies the recipient among all registered
meta-addresses. This test pins that fact so documentation cannot drift.
"""

from pq_stealth import DEFAULT, check_announcement, gen_meta_address, send
from pq_stealth.encoding import decode_meta_address, stealth_address


def test_revealed_stealth_pk_exposes_recipient_rho(recipient, announcement):
    meta_pub, meta_priv = recipient
    payment = check_announcement(meta_pub, meta_priv.kem_dk, announcement)
    assert payment is not None
    stealth_pk = payment.stealth_pk
    # the first 32 bytes of the FIPS 204 public key are rho
    rho_in_pk = DEFAULT.dsa._unpack_pk(stealth_pk)[0]
    assert stealth_pk[:32] == rho_in_pk
    # ... and they equal the rho published in the 0x01 meta-address
    published_rho = decode_meta_address(meta_pub.encode(), DEFAULT)[0]
    assert rho_in_pk == meta_pub.rho == published_rho == meta_pub.encode()[1:33]
    # the announcement itself does not: only the hashed address is public
    assert announcement.stealth_address == stealth_address(stealth_pk)
    assert len(announcement.stealth_address) == 20


def test_every_stealth_pk_of_one_recipient_shares_rho(recipient):
    meta_pub, meta_priv = recipient
    pks = []
    for m in (b"\x31" * 32, b"\x32" * 32):
        ann = send(meta_pub, encaps_m=m)
        pk = check_announcement(meta_pub, meta_priv.kem_dk, ann).stealth_pk
        pks.append(pk)
    assert pks[0] != pks[1]  # distinct addresses / t1'
    # same rho in both: linkable to each other and to the meta-address once revealed
    assert pks[0][:32] == pks[1][:32] == meta_pub.rho
    # a different recipient has a different rho, so revealed keys partition by recipient
    other_pub, _ = gen_meta_address(DEFAULT, zeta=b"\x41" * 32,
                                    kem_d=b"\x42" * 32, kem_z=b"\x43" * 32)
    assert other_pub.rho != meta_pub.rho
