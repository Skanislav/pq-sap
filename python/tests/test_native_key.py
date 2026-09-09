"""EIP-8164 crafted-signature stealth addresses (native_key.py)."""

import pytest

from pq_stealth import PARAM_SETS, check_announcement, gen_meta_address, send
from pq_stealth.encoding import keccak256
from pq_stealth.native_key import (
    GX,
    GY,
    ML_DSA_44_DESIGNATION,
    ML_DSA_44_PK_BYTES,
    NKD_SEED_DOMAIN,
    N,
    P,
    _mul,
    authorization_msg_hash,
    craft_authorization,
    crafted_r,
    ecrecover,
    is_valid_x,
    native_key_stealth_address,
    rlp_list,
)

L1 = PARAM_SETS["ML-KEM-512+ML-DSA-44"]


@pytest.fixture(scope="module")
def stealth_pk_44():
    meta_pub, meta_priv = gen_meta_address(
        L1, zeta=b"\x44" * 32, kem_d=b"\x45" * 32, kem_z=b"\x46" * 32)
    ann = send(meta_pub, encaps_m=b"\x47" * 32)
    payment = check_announcement(meta_pub, meta_priv.kem_dk, ann)
    assert payment is not None
    return payment.stealth_pk


# --- secp256k1 / ecrecover sanity ------------------------------------------
def test_ecrecover_matches_known_key():
    # Known private key 1: address of G is 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf
    # Sign by hand: k = 2, e = keccak("x")
    e_bytes = keccak256(b"x")
    e = int.from_bytes(e_bytes, "big") % N
    k = 2
    R = _mul(k, (GX, GY))
    r = R[0] % N
    s = pow(k, N - 2, N) * (e + r * 1) % N
    y_parity = R[1] & 1
    if s > N // 2:
        s = N - s
        y_parity ^= 1
    assert ecrecover(e_bytes, y_parity, r, s).hex() == \
        "7e5f4552091a69125d5dfcb7b8c2659029395bdf"


def test_is_valid_x_rejects_non_residue():
    assert is_valid_x(GX)
    # x = 5: 5^3 + 7 = 132 is a non-residue mod p
    assert not is_valid_x(5)


# --- EIP-8164 crafted authorization ----------------------------------------
def test_crafted_r_is_smallest_valid_x_at_or_above_seed(stealth_pk_44):
    r_seed, r = crafted_r(1, stealth_pk_44)
    assert r_seed == keccak256(
        NKD_SEED_DOMAIN + (1).to_bytes(32, "big") + stealth_pk_44)
    start = int.from_bytes(r_seed, "big") % P
    assert r >= start and r < N and is_valid_x(r)
    for x in range(start, r):
        assert not (x < N and is_valid_x(x))


def test_msg_hash_is_magic_plus_rlp(stealth_pk_44):
    h = authorization_msg_hash(1, stealth_pk_44, 0)
    # 1,312-byte string -> long-string header 0xb7+2, then 0x0520 big-endian
    body = rlp_list([b"\x01", b"\xb9\x05\x20" + stealth_pk_44, b"\x80"])
    assert h == keccak256(b"\x07" + body)
    assert len(stealth_pk_44) == ML_DSA_44_PK_BYTES == 0x0520


def test_address_is_recovered_and_deterministic(stealth_pk_44):
    a = craft_authorization(stealth_pk_44, chain_id=1)
    b = craft_authorization(stealth_pk_44, chain_id=1)
    assert a == b
    assert a.s == 1 and a.y_parity == 0 and a.nonce == 0
    assert a.address == ecrecover(a.msg_hash, a.y_parity, a.r, a.s)
    assert len(a.address) == 20
    assert a.code[:3] == ML_DSA_44_DESIGNATION and len(a.code) == 1315
    assert native_key_stealth_address(stealth_pk_44, 1) == a.address


def test_address_depends_on_chain_and_key(stealth_pk_44):
    a1 = native_key_stealth_address(stealth_pk_44, 1)
    a2 = native_key_stealth_address(stealth_pk_44, 81410)
    assert a1 != a2
    other = bytes([stealth_pk_44[0] ^ 1]) + stealth_pk_44[1:]
    assert native_key_stealth_address(other, 1) != a1


def test_rejects_non_44_key():
    with pytest.raises(ValueError):
        craft_authorization(b"\x00" * 1952, chain_id=1)
