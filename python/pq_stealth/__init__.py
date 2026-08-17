"""Executable spec / reference implementation of a post-quantum ERC-5564
stealth address scheme: ML-KEM key exchange + additive ML-DSA key blinding
(construction A), with a fresh error term per stealth key.

Receiving, detection, and proof of possession only — no send-value flow;
value sent to these addresses is unspendable on-chain until protocol-level
post-quantum signature support exists.
"""

from .blinding import derive_blinding, derive_stealth_pk
from .encoding import (
    decode_meta_address,
    encode_meta_address,
    keccak256,
    pack_blinded_sk,
    stealth_address,
    unpack_blinded_sk,
)
from .meta import MetaPublic, MetaSecret, gen_meta_address
from .params import DEFAULT, PARAM_SETS, ParamSet
from .recipient import Payment, check_announcement, scan
from .sender import Announcement, compute_view_tag, send
from .signing import prove_possession, sign_blinded, verify, verify_possession

__all__ = [
    "DEFAULT",
    "PARAM_SETS",
    "Announcement",
    "MetaPublic",
    "MetaSecret",
    "ParamSet",
    "Payment",
    "check_announcement",
    "compute_view_tag",
    "decode_meta_address",
    "derive_blinding",
    "derive_stealth_pk",
    "encode_meta_address",
    "gen_meta_address",
    "keccak256",
    "pack_blinded_sk",
    "prove_possession",
    "scan",
    "send",
    "sign_blinded",
    "stealth_address",
    "unpack_blinded_sk",
    "verify",
    "verify_possession",
]
