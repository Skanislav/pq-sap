"""Classical-spend hybrid: ML-KEM key exchange + additive secp256k1 key
blinding. The stealth output is a normal EOA, spendable today with a plain
ECDSA transaction; confidentiality rests on ML-KEM.

Complements the ML-DSA scheme (fully post-quantum, but unspendable
on-chain until protocol-level PQ signatures exist) with a same-day
deployable interim that shares the recipient's ML-KEM viewing key, the
view-tag, the announcement, and the ERC-6538 registry. See
docs/classical-spend-hybrid.md.
"""

from .params import PARAM_SETS, DEFAULT, ClassicalParamSet, N_CURVE
from .meta import gen_meta_address, MetaPublic, MetaSecret
from .blinding import derive_tweak, derive_stealth_pubkey, derive_stealth_privkey
from .encoding import (encode_meta_address, decode_meta_address, eth_address)
from .sender import send
from .recipient import scan, check_announcement, Payment

# the announcement rail is shared with the ML-DSA scheme
from ..sender import Announcement, compute_view_tag

__all__ = [
    "PARAM_SETS", "DEFAULT", "ClassicalParamSet", "N_CURVE",
    "gen_meta_address", "MetaPublic", "MetaSecret",
    "derive_tweak", "derive_stealth_pubkey", "derive_stealth_privkey",
    "encode_meta_address", "decode_meta_address", "eth_address",
    "send", "scan", "check_announcement", "Payment",
    "Announcement", "compute_view_tag",
]
