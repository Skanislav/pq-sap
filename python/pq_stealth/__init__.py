"""Executable spec / reference implementation of a post-quantum ERC-5564
stealth address scheme: ML-KEM key exchange + additive ML-DSA key blinding
(construction A), with a fresh error term per stealth key.

Receiving, detection, and proof of possession only — no send-value flow;
value sent to these addresses is unspendable on-chain until protocol-level
post-quantum signature support exists.
"""

from .blinding import derive_blinding, derive_stealth_pk
from .commit import (
    CommitAnnouncement,
    CommitMetaPublic,
    CommitPayment,
    Deployment,
    check_commit_announcement,
    decode_commit_meta_address,
    encode_commit_meta_address,
    gen_commit_meta_address,
    scan_commit,
    send_commit,
)
from .encoding import (
    decode_meta_address,
    encode_meta_address,
    keccak256,
    pack_blinded_sk,
    stealth_address,
    unpack_blinded_sk,
)
from .meta import MetaPublic, MetaSecret, gen_meta_address
from .native_key import (
    NativeKeyAuthorization,
    craft_authorization,
    native_key_stealth_address,
)
from .params import DEFAULT, PARAM_SETS, ParamSet
from .recipient import Payment, check_announcement, scan
from .sender import Announcement, compute_view_tag, send
from .signing import prove_possession, sign_blinded, verify, verify_possession

__all__ = [
    "DEFAULT",
    "PARAM_SETS",
    "Announcement",
    "CommitAnnouncement",
    "CommitMetaPublic",
    "CommitPayment",
    "Deployment",
    "MetaPublic",
    "MetaSecret",
    "NativeKeyAuthorization",
    "ParamSet",
    "Payment",
    "check_announcement",
    "check_commit_announcement",
    "compute_view_tag",
    "craft_authorization",
    "decode_commit_meta_address",
    "decode_meta_address",
    "derive_blinding",
    "derive_stealth_pk",
    "encode_commit_meta_address",
    "encode_meta_address",
    "gen_commit_meta_address",
    "gen_meta_address",
    "keccak256",
    "native_key_stealth_address",
    "pack_blinded_sk",
    "prove_possession",
    "scan",
    "scan_commit",
    "send",
    "send_commit",
    "sign_blinded",
    "stealth_address",
    "unpack_blinded_sk",
    "verify",
    "verify_possession",
]
