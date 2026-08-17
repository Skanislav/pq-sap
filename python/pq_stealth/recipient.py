"""Recipient / viewing-key-holder flow: scan announcements.

Detection needs only the viewing key (kem_dk) plus the public meta-address
material — the standard viewing/spending separation: a scanner can see
payments but cannot produce the blinded signing key, which additionally
requires the spending secrets (s1, s2).
"""

from dataclasses import dataclass

from .blinding import derive_stealth_pk
from .encoding import stealth_address
from .meta import MetaPublic
from .sender import Announcement, compute_view_tag


@dataclass(frozen=True)
class Payment:
    announcement: Announcement
    shared_secret: bytes
    stealth_pk: bytes
    t0: object   # low-order rounding part, needed later for signing


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
    pk, t0 = derive_stealth_pk(meta_pub.rho, meta_pub.t, ss, p)
    if stealth_address(pk) != ann.stealth_address:
        return None
    return Payment(ann, ss, pk, t0)


def scan(meta_pub: MetaPublic, kem_dk: bytes,
         announcements: list[Announcement]) -> list[Payment]:
    hits = []
    for ann in announcements:
        payment = check_announcement(meta_pub, kem_dk, ann)
        if payment is not None:
            hits.append(payment)
    return hits
