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
from .profiles import (
    ML_DSA_44_COMMIT_V0,
    PREIMAGE_V0,
    PROFILES,
    SPHINCS_C13_COMMIT_V0,
    AccountProfile,
    ProfileBinding,
    ProfileError,
    build_authorization,
    check_with_profile,
    gen_ml_dsa_recipient,
    parse_authorization,
    select_profile,
    send_with_profile,
    spend_key_from_ml_dsa_pk,
    verify_authorization,
)
from .recipient import Payment, check_announcement, scan
from .sender import Announcement, compute_view_tag, send
from .signing import prove_possession, sign_blinded, verify, verify_possession

__all__ = [
    "DEFAULT",
    "ML_DSA_44_COMMIT_V0",
    "PARAM_SETS",
    "PREIMAGE_V0",
    "PROFILES",
    "SPHINCS_C13_COMMIT_V0",
    "AccountProfile",
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
    "ProfileBinding",
    "ProfileError",
    "build_authorization",
    "check_announcement",
    "check_commit_announcement",
    "check_with_profile",
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
    "gen_ml_dsa_recipient",
    "keccak256",
    "native_key_stealth_address",
    "pack_blinded_sk",
    "parse_authorization",
    "prove_possession",
    "scan",
    "scan_commit",
    "select_profile",
    "send",
    "send_commit",
    "send_with_profile",
    "sign_blinded",
    "spend_key_from_ml_dsa_pk",
    "stealth_address",
    "unpack_blinded_sk",
    "verify",
    "verify_authorization",
    "verify_possession",
]
