"""EIP-8164 native-key stealth addresses (crafted-signature form).

EIP-8164 ("Native Key Delegation for EOAs", Draft 2026-02-17) lets an
account's code become ``0xef0101 || pk`` (ML-DSA-44, 1,312-byte pk), after
which the protocol validates the account's ML-DSA-44 signatures itself and
rejects ECDSA for it permanently. The delegation is installed from a
``native_key_authorization_list`` tuple ``[chain_id, pubkey, nonce, y, r, s]``
that any party may include, and the EIP describes a *crafted signature*
whose recovered address has no known ECDSA key ("provably rootless").

For the stealth scheme that gives a second address form next to the
CREATE2 account (D-014/D-020): the sender derives the blinded ML-DSA-44
stealth pk exactly as today (construction A, `derive_stealth_pk`), crafts the
tuple deterministically from it, and the **stealth address is the address
that tuple recovers to**. The sender's payment transaction can carry the
tuple, so the funds and the PQ key land atomically. See
`docs/research/prefix-deploy-native-keys.md`.

Encoding choices the draft leaves open (recorded, easy to change):

* ``chain_id`` inside ``r_seed`` is a 32-byte big-endian integer.
* ``y_parity = 0``; ``s = 1`` as the draft says.
* ``r`` must also be ``< n`` (secp256k1 order) for ``ecrecover`` to accept
  it, so the upward search skips x-coordinates in ``[n, p)``.

Pure Python secp256k1 is used on purpose: this module is the executable
spec for the address derivation and must not depend on a native library.
"""

from dataclasses import dataclass

from .encoding import keccak256

# --------------------------------------------------------------------------
# EIP-8164 constants
# --------------------------------------------------------------------------
NATIVE_KEY_MAGIC = b"\x07"
ML_DSA_44_DESIGNATION = bytes.fromhex("ef0101")
ML_DSA_44_PK_BYTES = 1312
NKD_SEED_DOMAIN = b"nkd-v1"

# --------------------------------------------------------------------------
# secp256k1 (affine, pure Python — reference only, not constant-time)
# --------------------------------------------------------------------------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_INF = None


def _sqrt_mod_p(a: int) -> int | None:
    """Square root modulo P (P ≡ 3 mod 4), or None if a is a non-residue."""
    a %= P
    y = pow(a, (P + 1) // 4, P)
    return y if (y * y) % P == a else None


def is_valid_x(x: int) -> bool:
    """True iff x is the x-coordinate of a point on secp256k1."""
    return 0 <= x < P and _sqrt_mod_p((pow(x, 3, P) + 7) % P) is not None


def _lift_x(x: int, y_parity: int) -> tuple[int, int]:
    y = _sqrt_mod_p((pow(x, 3, P) + 7) % P)
    if y is None:
        raise ValueError("x is not on the curve")
    if (y & 1) != (y_parity & 1):
        y = P - y
    return x, y


def _add(a, b):
    if a is _INF:
        return b
    if b is _INF:
        return a
    (x1, y1), (x2, y2) = a, b
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return _INF
        lam = (3 * x1 * x1) * pow(2 * y1, P - 2, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, P - 2, P) % P
    x3 = (lam * lam - x1 - x2) % P
    return x3, (lam * (x1 - x3) - y1) % P


def _mul(k: int, pt):
    acc = _INF
    while k:
        if k & 1:
            acc = _add(acc, pt)
        pt = _add(pt, pt)
        k >>= 1
    return acc


def ecrecover(msg_hash: bytes, y_parity: int, r: int, s: int) -> bytes:
    """Address recovered by the ECRECOVER precompile semantics (r, s < n)."""
    if not (0 < r < N and 0 < s < N):
        raise ValueError("r, s out of range")
    R = _lift_x(r, y_parity)
    e = int.from_bytes(msg_hash, "big") % N
    r_inv = pow(r, N - 2, N)
    # Q = r^-1 * (s*R - e*G)
    sR = _mul(s, R)
    eG = _mul(e, (GX, GY))
    neg_eG = (eG[0], (P - eG[1]) % P)
    Q = _mul(r_inv, _add(sR, neg_eG))
    if Q is _INF:
        raise ValueError("recovered point at infinity")
    return keccak256(Q[0].to_bytes(32, "big") + Q[1].to_bytes(32, "big"))[12:]


# --------------------------------------------------------------------------
# Minimal RLP (only what the authorization tuple needs)
# --------------------------------------------------------------------------
def _rlp_len(length: int, offset: int) -> bytes:
    if length < 56:
        return bytes([offset + length])
    lb = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([offset + 55 + len(lb)]) + lb


def _rlp_bytes(b: bytes) -> bytes:
    if len(b) == 1 and b[0] < 0x80:
        return b
    return _rlp_len(len(b), 0x80) + b


def _rlp_int(i: int) -> bytes:
    if i == 0:
        return b"\x80"
    return _rlp_bytes(i.to_bytes((i.bit_length() + 7) // 8, "big"))


def rlp_list(items: list[bytes]) -> bytes:
    body = b"".join(items)
    return _rlp_len(len(body), 0xC0) + body


# --------------------------------------------------------------------------
# EIP-8164 derivation
# --------------------------------------------------------------------------
@dataclass(frozen=True)
class NativeKeyAuthorization:
    chain_id: int
    pubkey: bytes
    nonce: int
    y_parity: int
    r: int
    s: int
    msg_hash: bytes
    address: bytes      # 20 bytes — the stealth address

    @property
    def code(self) -> bytes:
        """The account code EIP-8164 installs: 0xef0101 || pk (1,315 B)."""
        return ML_DSA_44_DESIGNATION + self.pubkey


def authorization_msg_hash(chain_id: int, pubkey: bytes, nonce: int) -> bytes:
    """keccak256(NATIVE_KEY_MAGIC || rlp([chain_id, pubkey, nonce]))."""
    return keccak256(NATIVE_KEY_MAGIC + rlp_list(
        [_rlp_int(chain_id), _rlp_bytes(pubkey), _rlp_int(nonce)]))


def crafted_r(chain_id: int, pubkey: bytes) -> tuple[bytes, int]:
    """(r_seed, r): r_seed = keccak256("nkd-v1" || chain_id || pk); r is the
    smallest valid secp256k1 x-coordinate >= r_seed mod p (and < n)."""
    r_seed = keccak256(NKD_SEED_DOMAIN + chain_id.to_bytes(32, "big") + pubkey)
    x = int.from_bytes(r_seed, "big") % P
    while not (x < N and is_valid_x(x)):
        x += 1
    return r_seed, x


def craft_authorization(pubkey: bytes, chain_id: int,
                        nonce: int = 0) -> NativeKeyAuthorization:
    """Deterministic rootless authorization for `pubkey`; its recovered
    address is the native-key stealth address."""
    if len(pubkey) != ML_DSA_44_PK_BYTES:
        raise ValueError("EIP-8164 0xef0101 expects a 1,312-byte ML-DSA-44 pk")
    _, r = crafted_r(chain_id, pubkey)
    s = 1
    y_parity = 0
    msg_hash = authorization_msg_hash(chain_id, pubkey, nonce)
    address = ecrecover(msg_hash, y_parity, r, s)
    return NativeKeyAuthorization(chain_id, pubkey, nonce, y_parity, r, s,
                                  msg_hash, address)


def native_key_stealth_address(stealth_pk: bytes, chain_id: int) -> bytes:
    """Address form for a native-key (EIP-8164) stealth account."""
    return craft_authorization(stealth_pk, chain_id).address
