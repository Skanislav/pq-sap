"""The algebraic core: additive blinding of a secp256k1 key.

    t = KDF(ss) mod n                      # tweak from the ML-KEM shared secret
    P = K + t*G                            # one-time stealth public key
    p = (k + t) mod n                      # its private key: p*G = K + t*G = P

The sender runs only the public half (K, ss) to get P; the recipient runs
the private half (k, ss) to get p. This is the DKSAP blinding identity with
the shared secret sourced from ML-KEM instead of ECDH.

Unlike the ML-DSA scheme there is no error term: a fresh ss per payment
yields a uniform tweak t, and P is a uniform point given t, so there is no
reused-noise linkability vector to close.
"""

import hashlib

from coincurve import PrivateKey, PublicKey

from .params import N_CURVE

TWEAK_DOMAIN = b"pq-stealth/classical/tweak/v0"
TWEAK_SEED_BYTES = 48  # 384 bits, well above 256 for uniform reduction mod n


def derive_tweak(ss: bytes) -> int:
    """Derive the tweak scalar t in [1, n-1] from the KEM shared secret.

    The +1 offset maps the reduced value into [1, n-1], excluding 0 (which
    would make the stealth key equal the recipient's spending key)."""
    seed = hashlib.shake_256(TWEAK_DOMAIN + ss).digest(TWEAK_SEED_BYTES)
    return int.from_bytes(seed, "big") % (N_CURVE - 1) + 1


def _tweak_bytes(t: int) -> bytes:
    return t.to_bytes(32, "big")


def derive_stealth_pubkey(spend_pub: bytes, ss: bytes) -> PublicKey:
    """Compute the one-time stealth public key P = K + t*G. Public inputs
    only. Runnable by the sender and by any viewing-key holder."""
    t = derive_tweak(ss)
    tweak_point = PrivateKey(_tweak_bytes(t)).public_key
    return PublicKey.combine_keys([PublicKey(spend_pub), tweak_point])


def derive_stealth_privkey(spend_priv: bytes, ss: bytes) -> PrivateKey:
    """Compute the stealth private key p = (k + t) mod n. Requires the
    recipient's spending secret; controls the stealth EOA via plain ECDSA."""
    t = derive_tweak(ss)
    return PrivateKey(spend_priv).add(_tweak_bytes(t))
