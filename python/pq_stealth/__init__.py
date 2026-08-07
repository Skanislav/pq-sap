"""Executable spec / reference implementation of a post-quantum ERC-5564
stealth address scheme: ML-KEM key exchange + additive ML-DSA key blinding
(construction A), with a fresh error term per stealth key.

Receiving, detection, and proof of possession only — no send-value flow;
value sent to these addresses is unspendable on-chain until protocol-level
post-quantum signature support exists.
"""

from .params import PARAM_SETS, DEFAULT, ParamSet
from .meta import gen_meta_address, MetaPublic, MetaSecret
from .sender import send, Announcement, compute_view_tag
from .recipient import scan, check_announcement, Payment
from .blinding import derive_blinding, derive_stealth_pk
from .signing import (sign_blinded, verify, prove_possession,
                      verify_possession)
from .encoding import (encode_meta_address, decode_meta_address,
                       stealth_address, keccak256,
                       pack_blinded_sk, unpack_blinded_sk)

__all__ = [
    "PARAM_SETS", "DEFAULT", "ParamSet",
    "gen_meta_address", "MetaPublic", "MetaSecret",
    "send", "Announcement", "compute_view_tag",
    "scan", "check_announcement", "Payment",
    "derive_blinding", "derive_stealth_pk",
    "sign_blinded", "verify", "prove_possession", "verify_possession",
    "encode_meta_address", "decode_meta_address", "stealth_address",
    "keccak256", "pack_blinded_sk", "unpack_blinded_sk",
]
