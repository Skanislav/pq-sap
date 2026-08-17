"""Classical-spend hybrid: ML-KEM key exchange + additive secp256k1 key
blinding. The stealth output is a normal EOA, spendable today with a plain
ECDSA transaction; confidentiality rests on ML-KEM.

Complements the ML-DSA scheme (fully post-quantum, but unspendable
on-chain until protocol-level PQ signatures exist) with a same-day
deployable interim that shares the recipient's ML-KEM viewing key, the
view-tag, the announcement, and the ERC-6538 registry. See
docs/classical-spend-hybrid.md.
"""

# the announcement rail is shared with the ML-DSA scheme
from ..sender import Announcement, compute_view_tag
from .blinding import derive_stealth_privkey, derive_stealth_pubkey, derive_tweak
from .encoding import decode_meta_address, encode_meta_address, eth_address
from .meta import MetaPublic, MetaSecret, gen_meta_address
from .params import DEFAULT, N_CURVE, PARAM_SETS, ClassicalParamSet
from .recipient import Payment, check_announcement, scan
from .sender import send

__all__ = [
    "DEFAULT",
    "N_CURVE",
    "PARAM_SETS",
    "Announcement",
    "ClassicalParamSet",
    "MetaPublic",
    "MetaSecret",
    "Payment",
    "check_announcement",
    "compute_view_tag",
    "decode_meta_address",
    "derive_stealth_privkey",
    "derive_stealth_pubkey",
    "derive_tweak",
    "encode_meta_address",
    "eth_address",
    "gen_meta_address",
    "scan",
    "send",
]
