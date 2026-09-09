"""Commitment meta-address (format 0x02): key exchange only, spend-scheme agnostic.

    meta-address = version(1) || spend_key(32) || kem_ek     (1,217 B at ML-KEM-768)
    opener       = SHA-256(OPEN_DOMAIN || ss)                 (ss = ML-KEM shared key)
    commitment   = keccak256(COMMIT_DOMAIN || spend_key || opener)
    address      = CREATE2(factory, 0, initcode(commitment, ...))  (deployment binding)

The recipient publishes a 32-byte commitment to its spending key (for
SPHINCS- C13 the key itself: pkSeed16 || pkRoot16, D-018; for any other
scheme a 32-byte hash of the public key) next to the ML-KEM viewing key.
The sender derives a per-payment commitment from the shared secret and pays
the counterfactual account bound to it; the recipient re-derives it with the
viewing key. Nothing about the spending key or scheme leaks at receive
time, and spending is whatever the account accepts for that commitment —
a revealed signature (`SphincsC13CommitSigner7913`), a zero-knowledge proof
(`Stealth8141ZkAccount`, D-023), or a future protocol-native dependency
(EIP-8288). Construction A's blinded ML-DSA key is not needed, which is what
drops the full-precision `t` (4,416 B) from the meta-address (D-012, D-024).

Domains are those of the deployed C13 commit signer and ZK circuit so the
live contracts accept this derivation unchanged; they are parameters.
"""

import hashlib
import os
from dataclasses import dataclass

from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024

from .encoding import keccak256

META_ADDRESS_VERSION_COMMIT = 0x02
SPEND_KEY_BYTES = 32


@dataclass(frozen=True)
class CommitDomains:
    open_domain: bytes
    commit_domain: bytes  # exactly 32 ASCII bytes: a bytes32 on chain


SPHINCS_C13_DOMAINS = CommitDomains(
    open_domain=b"pq-stealth/sphincs-c13/open/v0",
    commit_domain=b"pq-stealth/sphincs-c13/commit/v0",
)
assert len(SPHINCS_C13_DOMAINS.commit_domain) == 32

# Preimage-ownership spend (D-025): the spend key is a hash of a 32-byte secret
# and spending proves knowledge of the secret in zero knowledge
# (noir/preimage-ownership). No signature scheme at all.
PREIMAGE_DOMAINS = CommitDomains(
    open_domain=b"pq-stealth/preimage/open/v0",
    commit_domain=b"pq-stealth/preimage/commit/v0",
)
PREIMAGE_KEY_DOMAIN = b"pq-stealth/preimage/key/v0"


def spend_key_from_secret(sk: bytes, key_domain: bytes = PREIMAGE_KEY_DOMAIN) -> bytes:
    """spend_key = keccak256(key_domain || sk) — the 32-byte value published in
    the format-0x02 meta-address for the preimage-ownership scheme."""
    if len(sk) != 32:
        raise ValueError("spending secret must be 32 bytes")
    return keccak256(key_domain + sk)


@dataclass(frozen=True)
class KemSet:
    name: str
    kem: object
    ek_bytes: int
    ct_bytes: int
    view_tag_bytes: int = 1

    @property
    def meta_address_bytes(self) -> int:
        return 1 + SPEND_KEY_BYTES + self.ek_bytes


KEM_SETS = {
    "ML-KEM-512": KemSet("ML-KEM-512", ML_KEM_512, 800, 768),
    "ML-KEM-768": KemSet("ML-KEM-768", ML_KEM_768, 1184, 1088),
    "ML-KEM-1024": KemSet("ML-KEM-1024", ML_KEM_1024, 1568, 1568),
}
DEFAULT_KEM = KEM_SETS["ML-KEM-768"]


@dataclass(frozen=True)
class Deployment:
    """What binds a commitment to a payable address on one chain: the CREATE2
    factory, the account creation code, and the constructor arguments that
    precede/follow the commitment (`Stealth8141ZkFactory`: (commitment,
    verifier, frameCtx), salt 0)."""

    factory: bytes  # 20 bytes
    creation_code: bytes  # account creation code (without constructor args)
    verifier: bytes  # 20 bytes
    frame_ctx: bytes  # 20 bytes
    salt: bytes = b"\x00" * 32


@dataclass(frozen=True)
class CommitMetaPublic:
    spend_key: bytes  # 32-byte commitment to / encoding of the spending public key
    kem_ek: bytes
    kem: KemSet = DEFAULT_KEM

    def encode(self) -> bytes:
        return encode_commit_meta_address(self.spend_key, self.kem_ek, self.kem)


@dataclass(frozen=True)
class CommitAnnouncement:
    stealth_address: bytes  # 20 bytes: the counterfactual account
    ephemeral_pub_key: bytes  # ML-KEM ciphertext
    view_tag: bytes


@dataclass(frozen=True)
class CommitPayment:
    announcement: CommitAnnouncement
    shared_secret: bytes
    opener: bytes
    commitment: bytes


# --------------------------------------------------------------------------
# Encoding
# --------------------------------------------------------------------------
def encode_commit_meta_address(
    spend_key: bytes, kem_ek: bytes, kem: KemSet = DEFAULT_KEM
) -> bytes:
    if len(spend_key) != SPEND_KEY_BYTES:
        raise ValueError("spend key commitment must be 32 bytes")
    if len(kem_ek) != kem.ek_bytes:
        raise ValueError(f"{kem.name} ek must be {kem.ek_bytes} bytes")
    out = bytes([META_ADDRESS_VERSION_COMMIT]) + spend_key + kem_ek
    assert len(out) == kem.meta_address_bytes
    return out


def decode_commit_meta_address(
    data: bytes, kem: KemSet = DEFAULT_KEM
) -> CommitMetaPublic:
    if len(data) != kem.meta_address_bytes:
        raise ValueError(
            f"commit meta-address must be {kem.meta_address_bytes} bytes, "
            f"got {len(data)}"
        )
    if data[0] != META_ADDRESS_VERSION_COMMIT:
        raise ValueError(f"unsupported meta-address version {data[0]:#x}")
    return CommitMetaPublic(data[1:33], data[33:], kem)


def gen_commit_meta_address(
    spend_key: bytes,
    kem: KemSet = DEFAULT_KEM,
    kem_d: bytes | None = None,
    kem_z: bytes | None = None,
) -> tuple[CommitMetaPublic, bytes]:
    """Recipient side: pair a spend-key commitment with a fresh (or seeded)
    ML-KEM viewing keypair. Returns (public, kem_dk)."""
    if kem_d is not None or kem_z is not None:
        ek, dk = kem.kem._keygen_internal(
            kem_d or os.urandom(32), kem_z or os.urandom(32)
        )
    else:
        ek, dk = kem.kem.keygen()
    return CommitMetaPublic(spend_key, ek, kem), dk


# --------------------------------------------------------------------------
# Derivation
# --------------------------------------------------------------------------
def derive_opener(ss: bytes, domains: CommitDomains = SPHINCS_C13_DOMAINS) -> bytes:
    return hashlib.sha256(domains.open_domain + ss).digest()


def derive_commitment(
    spend_key: bytes, opener: bytes, domains: CommitDomains = SPHINCS_C13_DOMAINS
) -> bytes:
    return keccak256(domains.commit_domain + spend_key + opener)


def view_tag(ss: bytes, n: int = 1) -> bytes:
    return hashlib.sha256(ss).digest()[:n]


def account_address(commitment: bytes, dep: Deployment) -> bytes:
    """CREATE2 address of `Stealth8141ZkAccount(commitment, verifier, frameCtx)`
    deployed by `dep.factory` with `dep.salt`."""
    init_code = (
        dep.creation_code
        + commitment
        + dep.verifier.rjust(32, b"\x00")
        + dep.frame_ctx.rjust(32, b"\x00")
    )
    return keccak256(b"\xff" + dep.factory + dep.salt + keccak256(init_code))[12:]


# --------------------------------------------------------------------------
# Sender / recipient
# --------------------------------------------------------------------------
def send_commit(
    meta: CommitMetaPublic,
    dep: Deployment,
    encaps_m: bytes | None = None,
    domains: CommitDomains = SPHINCS_C13_DOMAINS,
) -> tuple[CommitAnnouncement, bytes]:
    """Encapsulate, derive the per-payment commitment, return the announcement
    and the commitment (the sender needs it only to deploy the account)."""
    if encaps_m is not None:
        ss, ct = meta.kem.kem._encaps_internal(meta.kem_ek, encaps_m)
    else:
        ss, ct = meta.kem.kem.encaps(meta.kem_ek)
    commitment = derive_commitment(meta.spend_key, derive_opener(ss, domains), domains)
    ann = CommitAnnouncement(
        account_address(commitment, dep), ct, view_tag(ss, meta.kem.view_tag_bytes)
    )
    return ann, commitment


def check_commit_announcement(
    meta: CommitMetaPublic,
    kem_dk: bytes,
    ann: CommitAnnouncement,
    dep: Deployment,
    domains: CommitDomains = SPHINCS_C13_DOMAINS,
) -> CommitPayment | None:
    """Viewing-key scan: view tag fast path, then re-derive the account."""
    try:
        ss = meta.kem.kem.decaps(kem_dk, ann.ephemeral_pub_key)
    except (ValueError, IndexError):
        return None
    if view_tag(ss, meta.kem.view_tag_bytes) != ann.view_tag:
        return None
    opener = derive_opener(ss, domains)
    commitment = derive_commitment(meta.spend_key, opener, domains)
    if account_address(commitment, dep) != ann.stealth_address:
        return None
    return CommitPayment(ann, ss, opener, commitment)


def scan_commit(
    meta: CommitMetaPublic,
    kem_dk: bytes,
    announcements: list[CommitAnnouncement],
    dep: Deployment,
    domains: CommitDomains = SPHINCS_C13_DOMAINS,
) -> list[CommitPayment]:
    hits = []
    for ann in announcements:
        p = check_commit_announcement(meta, kem_dk, ann, dep, domains)
        if p is not None:
            hits.append(p)
    return hits
