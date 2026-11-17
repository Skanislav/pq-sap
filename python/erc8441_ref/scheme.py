"""ERC-8441 schemeId 3 — reference implementation for conformance replay.

Implements the ERC text as published (ethereum/ERCs master, assets/erc-8441,
merged 2026-10-29). Every function is a direct rendering of the normative
section named in its docstring; nothing here is invented. This module is the
*second, independent* implementation surface for conformance purposes: the
first is namnc's Rust (`pq-stealth-scheme3-public`).

Libraries (validated at import): kyber_py >= 1.2 for ML-KEM-768 (FIPS 203
interface incl. the deterministic `_keygen_internal`/`_encaps_internal`
entry points and encapsulation-key validation), pure-Python secp256k1 below
(cross-checked against coincurve by the runner's self-test).

Note on ML-KEM entry points: the ERC's Test Cases pin `ct` through
`ML-KEM.Encaps_internal(ek, m)` (FIPS 203 Algorithm 17) and expand keys from
the seed `(d, z)` via `ML-KEM.KeyGen_internal` (Algorithm 16).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from kyber_py.ml_kem import ML_KEM_768 as _KEM

# ---------------------------------------------------------------- constants

DS_HYBRID = b"pq-stealth/hybrid-payment/v1"  # 28 bytes, Section 1.1
DS_OFFSET = b"pq-stealth/offset/v1"          # Section 1
DS_VIEW_TAG = b"pq-stealth/view-tag/v1"      # Section 1

SECP_P = 2**256 - 2**32 - 977
SECP_N = (
    0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
)
SECP_GX = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
)
SECP_GY = (
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
)
SECP_B = 7

EK_LEN = 1184   # ML-KEM-768 encapsulation key (FIPS 203)
DK_LEN = 2400   # expanded decapsulation key
CT_LEN = 1088   # ML-KEM-768 ciphertext
META_LEN = 1250  # Section 2.2: spending_pk(33) || viewing_pk_ec(33) || ek(1184)
EPK_CT_LEN = 1121  # Section 3: ephemeralPubKey = epk(33) || ct(1088)


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def sha3_256(b: bytes) -> bytes:
    return hashlib.sha3_256(b).digest()


def keccak256(b: bytes) -> bytes:
    from Crypto.Hash import keccak as _k

    h = _k.new(digest_bits=256)
    h.update(b)
    return h.digest()


# ------------------------------------------------------------ secp256k1 (pure)

def _inv(a: int, m: int) -> int:
    return pow(a, -1, m)


def scalar_valid(k: int) -> bool:
    """Section 1: a valid scalar is an integer k with 0 < k < n."""
    return 0 < k < SECP_N


def point_on_curve(x: int, y: int) -> bool:
    return (y * y - x * x * x - SECP_B) % SECP_P == 0


def decompress_point(data: bytes) -> tuple[int, int]:
    """SEC1 compressed point (33 B, tag 0x02/0x03) -> (x, y).

    Section 2.2: a decoder MUST check tag 0x02 or 0x03 and decode to a point
    on secp256k1; MUST NOT accept other SEC1 forms. Raises ValueError.
    """
    if len(data) != 33 or data[0] not in (2, 3):
        raise ValueError("not a valid compressed point")
    x = int.from_bytes(data[1:], "big")
    if x >= SECP_P:
        raise ValueError("x out of range")
    y_sq = (x * x * x + SECP_B) % SECP_P
    y = pow(y_sq, (SECP_P + 1) // 4, SECP_P)
    if (y * y) % SECP_P != y_sq:
        raise ValueError("not on curve")
    if (y % 2) != (data[0] % 2):
        y = SECP_P - y
    return x, y


def compress_point(x: int, y: int) -> bytes:
    tag = 2 + (y & 1)
    return bytes([tag]) + x.to_bytes(32, "big")


def _point_add(p: tuple[int, int] | None, q: tuple[int, int] | None):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and (y1 + y2) % SECP_P == 0:
        return None
    if p == q:
        lam = (3 * x1 * x1) * _inv(2 * y1, SECP_P) % SECP_P
    else:
        lam = (y2 - y1) * _inv(x2 - x1, SECP_P) % SECP_P
    x3 = (lam * lam - x1 - x2) % SECP_P
    y3 = (lam * (x1 - x3) - y1) % SECP_P
    return x3, y3


def scalar_mult(k: int, point: tuple[int, int] | None = None):
    """k * point (default G). Returns None for infinity."""
    if point is None:
        point = (SECP_GX, SECP_GY)
    if not scalar_valid(k):
        raise ValueError("scalar out of range")
    acc = None
    addend = point
    while k:
        if k & 1:
            acc = _point_add(acc, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return acc


def point_from_compressed(data: bytes):
    return decompress_point(data)


def ecdh_x(esk_scalar: int, pk_compressed: bytes) -> bytes:
    """Section 2.4: ss_ec = ECDH(esk, viewing_pk_ec).x, the 32-byte
    big-endian x-coordinate alone (V3-04)."""
    x, _ = scalar_mult(esk_scalar % SECP_N, decompress_point(pk_compressed))
    return x.to_bytes(32, "big")


def address_from_uncompressed(uncompressed65: bytes) -> bytes:
    """Section 1: address(stealth_pk) = keccak256(uncompressed(stealth_pk)[1..65])[12..32]."""
    if len(uncompressed65) != 65 or uncompressed65[0] != 0x04:
        raise ValueError("expected the 65-byte uncompressed SEC1 form")
    return keccak256(uncompressed65[1:])[12:]


def eip55(addr20: bytes) -> str:
    """EIP-55 mixed-case checksum (V3-13)."""
    hexs = addr20.hex()
    digest = keccak256(hexs.encode()).hex()
    return "0x" + "".join(
        c.upper() if int(digest[i], 16) >= 8 else c for i, c in enumerate(hexs)
    )


# ------------------------------------------------------------- Section 1

def offset_base(ss: bytes) -> bytes:
    """base = SHA256("pq-stealth/offset/v1" || ss)."""
    return sha256(DS_OFFSET + ss)


def H_ss_checked(ss: bytes) -> int | None:
    """H(ss): the range-checked scalar.

    Section 1: if 0 < u256be(base) < n: H(ss) = u256be(base); else fail.
    A sender MUST NOT reduce base mod n or derive another candidate.
    Returns None on failure (test vectors reach failure by supplying base
    directly, V1-03/V1-04)."""
    base = u256be_be_bytes_to_int(offset_base(ss))
    if scalar_valid(base):
        return base
    return None


def offset_from_base(base_bytes: bytes) -> int | None:
    """The range check applied to a supplied base (V1-02..V1-05)."""
    base = u256be_be_bytes_to_int(base_bytes)
    return base if scalar_valid(base) else None


def u256be_be_bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def view_tag(ss: bytes) -> bytes:
    """Section 1: view_tag(ss) = SHA256("pq-stealth/view-tag/v1" || ss)[0..1]."""
    return sha256(DS_VIEW_TAG + ss)[:1]


# --------------------------------------------------------- Section 1.1

def hybrid_combine(
    ds: bytes,
    ss_ec: bytes,
    ss_pq: bytes,
    epk: bytes,
    ct: bytes,
    viewing_pk_ec: bytes,
    ek: bytes,
) -> bytes:
    """hybrid_combine = SHA3-256(DS || ss_ec || ss_pq || epk || ct ||
    viewing_pk_ec || ek)  -- 32 B (Section 1.1). Input order MUST be exactly
    as shown, DS first, output the full 32-byte digest."""
    return sha3_256(ds + ss_ec + ss_pq + epk + ct + viewing_pk_ec + ek)


# --------------------------------------------------------- Section 2.1

class KeygenError(ValueError):
    """Error at key generation (Section 2.7)."""


@dataclass
class KeygenOutputs:
    meta_address: bytes   # 1250 B: spending_pk || viewing_pk_ec || ek
    master_key: bytes     # spending_sk, 32 B
    tracking_key: bytes   # viewing_ec || d || z, 96 B
    spending_pk: bytes
    viewing_pk_ec: bytes
    ek: bytes
    dk: bytes  # expanded (vectors address it via ek_source/dk layout notes)


def keygen(seed: bytes) -> KeygenOutputs:
    """Section 2.1: key generation takes a 128-byte seed
    seed = spending_seed(32) || viewing_ec_seed(32) || kem_seed(64),
    kem_seed = d(32) || z(32). MUST reject any other length (no pad/truncate).
    spending_seed and viewing_ec_seed MUST be valid scalars; MUST fail if
    spending_seed equals viewing_ec_seed, d, or z. Deterministic."""
    if len(seed) != 128:
        raise KeygenError("seed must be 128 bytes (no pad, no truncate)")
    spending_seed, viewing_ec_seed, kem_seed = seed[:32], seed[32:64], seed[64:]
    d, z = kem_seed[:32], kem_seed[32:]
    for other in (viewing_ec_seed, d, z):
        if spending_seed == other:
            raise KeygenError("spending_seed equals a key component")
    spending_sk = u256be_be_bytes_to_int(spending_seed)
    viewing_ec = u256be_be_bytes_to_int(viewing_ec_seed)
    if not scalar_valid(spending_sk):
        raise KeygenError("spending_seed not a valid scalar")
    if not scalar_valid(viewing_ec):
        raise KeygenError("viewing_ec_seed not a valid scalar")
    ek, dk = _KEM._keygen_internal(d, z)
    spending_pk = scalar_mult(spending_sk)
    viewing_pk = scalar_mult(viewing_ec)
    assert spending_pk is not None and viewing_pk is not None
    meta = (
        compress_point(*spending_pk) + compress_point(*viewing_pk) + ek
    )
    return KeygenOutputs(
        meta_address=meta,
        master_key=spending_seed,
        tracking_key=viewing_ec_seed + d + z,
        spending_pk=compress_point(*spending_pk),
        viewing_pk_ec=compress_point(*viewing_pk),
        ek=ek,
        dk=dk,
    )


# --------------------------------------------------------- Section 2.2

def decode_meta(meta: bytes) -> tuple[bytes, bytes, bytes]:
    """Section 2.2: a decoder MUST reject any length other than 1250; both
    33-byte fields MUST carry tag 0x02/0x03 and decode to points on
    secp256k1; ek MUST pass FIPS 203's encapsulation input check (done at
    encapsulation in this implementation, per Section 2.7's timing)."""
    if len(meta) != META_LEN:
        raise KeygenError("meta-address must be 1250 bytes")
    spending_pk, viewing_pk_ec = meta[:33], meta[33:66]
    ek = meta[66:]
    decompress_point(spending_pk)
    decompress_point(viewing_pk_ec)
    return spending_pk, viewing_pk_ec, ek


# --------------------------------------------------------- Section 2.4

@dataclass
class Ephemeral:
    esk: int
    epk: bytes
    m: bytes  # the Encaps_internal randomness (test-vector pinning)


def sender_derive(
    ephemeral: Ephemeral,
    meta: bytes,
    *,
    m: bytes | None = None,
) -> dict | None:
    """Section 2.4. `m` fixes Encaps_internal's randomness for the vectors;
    with m=None the caller's ephemeral.m is used. Returns the announcement
    fields or None when H(ss)'s range check fails (sender discards and
    redraws — unrepresentable in a deterministic vector replay)."""
    if meta and len(meta) != META_LEN:
        raise KeygenError("meta-address must be 1250 bytes")
    spending_pk, viewing_pk_ec, ek = decode_meta(meta)
    ss_ec = ecdh_x(ephemeral.esk, viewing_pk_ec)
    m = m if m is not None else ephemeral.m
    ss_pq, ct = _KEM._encaps_internal(ek, m)  # raises on ek-check failure
    ss = hybrid_combine(
        DS_HYBRID, ss_ec, ss_pq, ephemeral.epk, ct, viewing_pk_ec, ek
    )
    h = H_ss_checked(ss)
    if h is None:
        return None
    stealth_pk_point = _point_add(
        decompress_point(spending_pk), scalar_mult(h)
    )
    stealth_pk = compress_point(*stealth_pk_point)
    full = bytes([4]) + stealth_pk_point[0].to_bytes(32, "big") + \
        stealth_pk_point[1].to_bytes(32, "big")
    addr = address_from_uncompressed(full)
    return {
        "ss": ss,
        "ss_ec": ss_ec,
        "ss_pq": ss_pq,
        "ct": ct,
        "epk": ephemeral.epk,
        "view_tag": view_tag(ss),
        "stealth_pk": stealth_pk,
        "stealth_pk_uncompressed": full,
        "address": addr,
        "H_ss": h,
    }


# --------------------------------------------------------- Section 2.5

@dataclass
class ScanOutcome:
    outcome: str           # "match" | "skip"
    stage: str | None = None  # "entry"|"tag"|"offset"|"address"|"match"
    ss: bytes | None = None
    ss_ec: bytes | None = None
    ss_pq: bytes | None = None
    view_tag: bytes | None = None
    stealth_pk: bytes | None = None
    address: bytes | None = None


def scan(
    tracking_key: bytes,
    meta: bytes,
    announcement: dict,
    *,
    dk: bytes | None = None,
    stealthAddress: bytes | None = None,
) -> ScanOutcome:
    """Section 2.5. `announcement` has stealthAddress (bytes), ephemeralPubKey
    (bytes), metadata (bytes). Sections 2.7/3: ephemeralPubKey not exactly
    1121 B, or empty metadata, is a skip at the entry point; a bad epk point
    is a skip; view-tag mismatch is a skip; announced address mismatch is a
    skip. Decapsulation never fails (implicit rejection). `dk` overrides the
    KEM key with an expanded 2400-byte ACVP key (V3-14/17); `stealthAddress`
    overrides the announcement's address (V3-17 honest/lie)."""
    sa = stealthAddress if stealthAddress is not None \
        else announcement["stealthAddress"]
    epkct = announcement["ephemeralPubKey"]
    metadata = announcement["metadata"]
    if len(epkct) != EPK_CT_LEN or len(metadata) < 1:
        return ScanOutcome(outcome="skip", stage="entry")
    epk, ct = epkct[:33], epkct[33:]
    try:
        decompress_point(epk)
    except ValueError:
        return ScanOutcome(outcome="skip", stage="entry")
    spending_pk, viewing_pk_ec, ek = decode_meta(meta)
    if len(tracking_key) != 96:
        raise KeygenError("tracking key must be viewing_ec || d || z (96 B)")
    viewing_ec_seed, d, z = tracking_key[:32], tracking_key[32:64], tracking_key[64:]
    viewing_ec = u256be_be_bytes_to_int(viewing_ec_seed)
    if not scalar_valid(viewing_ec):
        raise KeygenError("viewing_ec not a valid scalar")
    if dk is None:
        dk = _KEM._keygen_internal(d, z)[1]
    else:
        # FIPS 203 expanded-dk layout: ek at 1152:2336, K = SHA3-256(ek) at
        # 2336:2368 (dk_probe-verified against the vendored ACVP rows)
        if dk[1152:2336] != ek or sha3_256(dk[1152:2336]) != dk[2336:2368]:
            raise KeygenError("expanded dk does not match the registered ek")
    ss_ec = ecdh_x(viewing_ec, epk)
    ss_pq = _KEM._decaps_internal(dk, ct)  # never raises for well-formed ct
    ss = hybrid_combine(DS_HYBRID, ss_ec, ss_pq, epk, ct, viewing_pk_ec, ek)
    derived_tag = view_tag(ss)
    if derived_tag != metadata[:1]:
        return ScanOutcome(outcome="skip", stage="tag", ss=ss, ss_ec=ss_ec,
                           ss_pq=ss_pq, view_tag=derived_tag)
    h = H_ss_checked(ss)
    if h is None:
        return ScanOutcome(outcome="skip", stage="offset")
    stealth_pk_point = _point_add(
        decompress_point(spending_pk), scalar_mult(h)
    )
    full = bytes([4]) + stealth_pk_point[0].to_bytes(32, "big") + \
        stealth_pk_point[1].to_bytes(32, "big")
    addr = address_from_uncompressed(full)
    stealth_pk = compress_point(*stealth_pk_point)
    if addr != sa:
        return ScanOutcome(outcome="skip", stage="address", ss=ss,
                           stealth_pk=stealth_pk, address=addr,
                           view_tag=derived_tag)
    return ScanOutcome(outcome="match", stage="match", ss=ss, ss_ec=ss_ec,
                       ss_pq=ss_pq, view_tag=derived_tag, stealth_pk=stealth_pk,
                       address=addr)


# --------------------------------------------------------- Section 2.6

def recipient_key(spending_sk: int, ss: bytes) -> tuple[int, bytes] | None:
    """stealth_sk = (spending_sk + H(ss)) mod n (Section 2.6)."""
    h = H_ss_checked(ss)
    if h is None:
        return None
    stealth_sk = (spending_sk + h) % SECP_N
    if not scalar_valid(stealth_sk):
        raise KeygenError("derived stealth_sk out of range")
    p = scalar_mult(stealth_sk)
    assert p is not None
    return stealth_sk, compress_point(*p)


# --------------------------------------------------- Section 2.8

class _MalformedAnnouncement(Exception):
    """ephemeralPubKey failed the wire checks (Section 3)."""


class _InvalidOffset(Exception):
    """H(ss)'s range check failed (Section 1)."""


def _g_mul(k: int) -> tuple[int, int]:
    """k*G for a validated scalar; never the point at infinity."""
    p = scalar_mult(k)
    assert p is not None
    return p


def _derive_ss_epk(ephemeral_pubkey: bytes, viewing_key: bytes):
    """Shared Section 2.8 plumbing: from a 1121-byte `ephemeralPubKey` and the
    96-byte `viewingKey` (tracking key), recompute viewing_pk_ec and ek
    (Section 2.8) and derive ss (Section 2.5's derivation).
    Raises KeygenError for a malformed viewingKey (caller's own key ->
    error, Section 2.7), _MalformedAnnouncement for a malformed
    ephemeralPubKey (-> `false`/fail at the method level)."""
    if len(viewing_key) != 96:
        raise KeygenError("viewingKey must be the 96-byte tracking key")
    viewing_ec_seed, d, z = viewing_key[:32], viewing_key[32:64], viewing_key[64:]
    viewing_ec = u256be_be_bytes_to_int(viewing_ec_seed)
    if not scalar_valid(viewing_ec):
        raise KeygenError("viewingKey's viewing_ec is not a valid scalar")
    ek, dk = _KEM._keygen_internal(d, z)
    viewing_pk_ec = compress_point(*_g_mul(viewing_ec))
    if len(ephemeral_pubkey) != EPK_CT_LEN:
        raise _MalformedAnnouncement("ephemeralPubKey must be 1121 bytes")
    epk, ct = ephemeral_pubkey[:33], ephemeral_pubkey[33:]
    try:
        epk_point = decompress_point(epk)
    except ValueError as exc:
        raise _MalformedAnnouncement("bad epk point") from exc
    ss_ec = ecdh_x(viewing_ec, epk)
    ss_pq = _KEM._decaps_internal(dk, ct)  # implicit rejection, Section 4
    ss = hybrid_combine(DS_HYBRID, ss_ec, ss_pq, epk, ct,
                        viewing_pk_ec, ek)
    return ss, epk_point


def generate_stealth_address(meta: bytes, esk: int, m: bytes) -> dict | None:
    """Section 2.8: generateStealthAddress(stealthMetaAddress) implements
    Section 2.4 and returns address, ephemeralPubKey = epk || ct, and
    viewTag. `esk` and `m` come from the caller's CSPRNG (Section 2.4);
    returns None when the offset's range check fails (sender redraws)."""
    out = sender_derive(
        Ephemeral(esk=esk, epk=compress_point(*_g_mul(esk)), m=m), meta
    )
    if out is None:
        return None
    return {
        "address": out["address"],
        "ephemeralPubKey": out["epk"] + out["ct"],
        "viewTag": out["view_tag"],
    }


def check_stealth_address(
    stealth_address: bytes,
    ephemeral_pubkey: bytes,
    viewing_key: bytes,
    spending_pk: bytes,
) -> bool:
    """Section 2.8: checkStealthAddress(stealthAddress, ephemeralPubKey,
    viewingKey, spendingPubKey). For well-formed caller keys, returns false
    for a malformed ephemeralPubKey, an invalid offset or stealth public
    key, or an address mismatch; raises on malformed caller keys
    (viewingKey not 96 B / bad viewing_ec scalar, spendingPubKey not a
    valid compressed point). Receives no metadata: the view tag is checked
    separately by a scanner, per the ERC."""
    if len(spending_pk) != 33:
        raise KeygenError("spendingPubKey must be a 33-byte compressed point")
    spending_pk_point = decompress_point(spending_pk)  # raises on invalid
    try:
        ss, epk_point = _derive_ss_epk(ephemeral_pubkey, viewing_key)
    except _MalformedAnnouncement:
        return False
    h = H_ss_checked(ss)
    if h is None:
        return False  # invalid offset
    stealth_pk_point = _point_add(spending_pk_point, scalar_mult(h))
    if stealth_pk_point is None:
        return False  # invalid stealth public key
    full = bytes([4]) + stealth_pk_point[0].to_bytes(32, "big") + \
        stealth_pk_point[1].to_bytes(32, "big")
    return address_from_uncompressed(full) == stealth_address


def compute_stealth_key(
    stealth_address: bytes,
    ephemeral_pubkey: bytes,
    viewing_key: bytes,
    spending_sk: int,
) -> int:
    """Section 2.8: computeStealthKey(stealthAddress, ephemeralPubKey,
    viewingKey, spendingKey) implements Section 2.6. MUST fail rather than
    return a key when ephemeralPubKey is malformed or when
    address(stealth_sk*G) differs from stealthAddress; raises on a
    spendingKey that is not a valid scalar."""
    if not scalar_valid(spending_sk):
        raise KeygenError("spendingKey is not a valid scalar")
    try:
        ss, _epk_point = _derive_ss_epk(ephemeral_pubkey, viewing_key)
    except _MalformedAnnouncement as exc:
        raise KeygenError("malformed ephemeralPubKey") from exc
    h = H_ss_checked(ss)
    if h is None:
        raise KeygenError("invalid offset: no stealth key exists")
    stealth_sk = (spending_sk + h) % SECP_N
    pk_point = scalar_mult(stealth_sk)
    if pk_point is None:
        raise KeygenError("derived stealth key is the point at infinity")
    full = bytes([4]) + pk_point[0].to_bytes(32, "big") + \
        pk_point[1].to_bytes(32, "big")
    if address_from_uncompressed(full) != stealth_address:
        raise KeygenError("address(stealth_sk*G) differs from stealthAddress")
    return stealth_sk
