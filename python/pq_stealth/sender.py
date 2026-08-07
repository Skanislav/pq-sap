"""Sender flow: encapsulate to the viewing key, derive the stealth
address, emit the announcement.

The announcement mirrors ERC-5564's Announcement event fields: the ML-KEM
ciphertext plays the role of the ephemeral public key, and the view tag
is the first byte(s) of SHA-256 of the shared secret.
"""

import hashlib
from dataclasses import dataclass

from .meta import MetaPublic
from .blinding import derive_stealth_pk
from .encoding import stealth_address


@dataclass(frozen=True)
class Announcement:
    stealth_address: bytes   # 20 bytes
    ephemeral_pub_key: bytes  # ML-KEM ciphertext R
    view_tag: bytes


def compute_view_tag(ss: bytes, view_tag_bytes: int) -> bytes:
    return hashlib.sha256(ss).digest()[:view_tag_bytes]


def send(meta_pub: MetaPublic, encaps_m: bytes | None = None) -> Announcement:
    """Derive a fresh stealth address for the recipient. Pass encaps_m
    (32 bytes) for deterministic encapsulation (test vectors only)."""
    p = meta_pub.params
    if encaps_m is not None:
        ss, ct = p.kem._encaps_internal(meta_pub.kem_ek, encaps_m)
    else:
        ss, ct = p.kem.encaps(meta_pub.kem_ek)

    pk, _t0 = derive_stealth_pk(meta_pub.rho, meta_pub.t, ss, p)
    return Announcement(stealth_address(pk), ct,
                        compute_view_tag(ss, p.view_tag_bytes))
