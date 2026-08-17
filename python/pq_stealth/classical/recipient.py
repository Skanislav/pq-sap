"""Recipient / viewing-key-holder flow: scan announcements.

Detection needs only the viewing key (kem_dk) plus the public meta-address
material. Producing the stealth *private* key additionally requires the
secp256k1 spending secret that is the standard viewing/spending separation.
"""

from dataclasses import dataclass

from .meta import MetaPublic
from .blinding import derive_stealth_pubkey
from .encoding import eth_address

# the announcement rail is shared with the ML-DSA scheme
from ..sender import Announcement, compute_view_tag


@dataclass(frozen=True)
class Payment:
    announcement: Announcement
    shared_secret: bytes
    stealth_pub: bytes          # compressed secp256k1 stealth pubkey
    stealth_address: bytes      # 20-byte EOA address


def check_announcement(meta_pub: MetaPublic, kem_dk: bytes,
                       ann: Announcement) -> Payment | None:
    """View-tag fast path, then full derivation. Returns None on non-match;
    malformed ciphertexts also yield None (never an exception)."""
    p = meta_pub.params
    try:
        ss = p.kem.decaps(kem_dk, ann.ephemeral_pub_key)
    except (ValueError, IndexError):
        return None  # malformed ciphertext
    if compute_view_tag(ss, p.view_tag_bytes) != ann.view_tag:
        return None
    stealth_pub = derive_stealth_pubkey(meta_pub.spend_pub, ss)
    if eth_address(stealth_pub) != ann.stealth_address:
        return None
    return Payment(ann, ss, stealth_pub.format(compressed=True),
                   ann.stealth_address)


def scan(meta_pub: MetaPublic, kem_dk: bytes,
         announcements: list[Announcement]) -> list[Payment]:
    hits = []
    for ann in announcements:
        payment = check_announcement(meta_pub, kem_dk, ann)
        if payment is not None:
            hits.append(payment)
    return hits
