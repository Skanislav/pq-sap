"""Sender flow: encapsulate to the viewing key, derive the stealth EOA,
emit the announcement.

Reuses the ML-DSA scheme's `Announcement` and `compute_view_tag`: the
announcement rail is identical, only the stealth-address derivation differs
(secp256k1 blinding instead of ML-DSA).
"""

# the announcement rail is shared with the ML-DSA scheme
from ..sender import Announcement, compute_view_tag
from .blinding import derive_stealth_pubkey
from .encoding import eth_address
from .meta import MetaPublic


def send(meta_pub: MetaPublic, encaps_m: bytes | None = None) -> Announcement:
    """Derive a fresh stealth address for the recipient. Pass encaps_m
    (32 bytes) for deterministic encapsulation (test vectors only)."""
    p = meta_pub.params
    if encaps_m is not None:
        ss, ct = p.kem._encaps_internal(meta_pub.kem_ek, encaps_m)
    else:
        ss, ct = p.kem.encaps(meta_pub.kem_ek)

    stealth_pub = derive_stealth_pubkey(meta_pub.spend_pub, ss)
    return Announcement(eth_address(stealth_pub), ct,
                        compute_view_tag(ss, p.view_tag_bytes))
