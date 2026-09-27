"""Explicit account profiles for the commitment meta-address (format 0x02).

A format-0x02 meta-address is `0x02 || spend_key(32) || kem_ek`. The 32-byte
`spend_key` is opaque: nothing in it says which spending scheme, hash domains,
chain, or account code interpret it. That interpretation is an *account
profile*, selected explicitly and out of band by the application before a
payment is sent or scanned. A profile is never inferred from the commitment,
guessed by trial verification, or deferred until the account is deployed.

Three identifiers with distinct roles:

* the meta-address **version byte** (`0x02`) describes the encoding of the
  published key material;
* the **ERC-5564 scheme ID** describes how an announcement is interpreted
  (KEM ciphertext as `ephemeralPubKey`, one-byte view tag) and is unchanged by
  anything here;
* the **account profile** (this module) describes the selected authorization
  and deployment behaviour: KEM, hash domains, signature scheme and its
  message convention, and the CREATE2 deployment binding.

Changing the profile changes destinations; it never changes the announcement
format or the scheme ID.

Profiles implemented:

* ``sphincs-c13-commit/v0`` — D-018/D-023: `spend_key` is the raw 32-byte C13
  public key; existing domains and fixtures, unchanged.
* ``preimage/v0`` — D-025: `spend_key = keccak256(KEY || sk)`; the browser demo
  proves knowledge of `(sk, opener)` with UltraHonk (not post-quantum sound).
* ``ml-dsa-44-commit/v0`` — this module: `spend_key = keccak256(KEY || pk)` for
  a canonical FIPS 204 ML-DSA-44 public key (1,312 bytes). Spending reveals
  `pk || opener || signature`; see :func:`build_authorization`.

The ML-DSA profile is ML-DSA-44 (FIPS 204, k = l = 4), not ML-DSA-65, because
the only ML-DSA verifier in this repository with an executable on-chain path
is the vendored ZKNOX `ZKNOX_dilithium` (rev df999ed, NIST/SHAKE profile,
level 2, fixed k = l = 4). ML-DSA-65 is the scheme's default parameter set for
Construction A and would need its own verifier and its own profile; the two
are not interchangeable and this module refuses to label one as the other.

Trust boundary. A profile descriptor and its deployment binding are trusted
*configuration*: a profile ID is a name, not an authentication of the factory,
verifier, or creation code behind it. Applications must obtain the binding
from a source they trust (pinned in the wallet, or supplied by the operator)
and :func:`select_profile` fails closed on any unknown profile, wrong KEM,
malformed binding, or chain mismatch. Nothing here authenticates a binding
received from a counterparty.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from dilithium_py.ml_dsa import ML_DSA_44

from .commit import (
    DEFAULT_KEM,
    META_ADDRESS_VERSION_COMMIT,
    PREIMAGE_DOMAINS,
    PREIMAGE_KEY_DOMAIN,
    SPEND_KEY_BYTES,
    SPHINCS_C13_DOMAINS,
    CommitAnnouncement,
    CommitDomains,
    CommitMetaPublic,
    CommitPayment,
    Deployment,
    KemSet,
    check_commit_announcement,
    derive_commitment,
    derive_opener,
    gen_commit_meta_address,
    send_commit,
)
from .encoding import keccak256

# --------------------------------------------------------------------------
# ML-DSA-44 committed-key profile constants (exact bytes; UTF-8 == ASCII here)
# --------------------------------------------------------------------------
ML_DSA_44_KEY_DOMAIN = b"pq-stealth/ml-dsa-44/key/v0"
ML_DSA_44_DOMAINS = CommitDomains(
    open_domain=b"pq-stealth/ml-dsa-44/open/v0",
    commit_domain=b"pq-stealth/ml-dsa-44/commit/v0",
)
ML_DSA_44_PK_BYTES = 1312
ML_DSA_44_SIG_BYTES = 2420
OPENER_BYTES = 32
DIGEST_BYTES = 32


@dataclass(frozen=True)
class Authorization:
    """How a spend is authorized under a profile (fixed by the profile)."""

    scheme: str  # human name, e.g. "ML-DSA-44"
    dsa: object | None  # dilithium_py instance for signature profiles
    key_domain: bytes | None  # spend_key = keccak256(key_domain || pk)
    pk_bytes: int | None
    sig_bytes: int | None
    # Message convention for the signature. "pure/empty-ctx/digest32" means
    # FIPS 204 pure ML-DSA (Algorithm 2/3) over the 32-byte account digest with
    # an empty context string — M' = 0x00 || 0x00 || digest — exactly what the
    # 3-argument ERC-7913 `verify(bytes,bytes32,bytes)` of the vendored ZKNOX
    # verifier hashes. No HashML-DSA prehash, no second hashing of the digest.
    message_convention: str

    @property
    def payload_bytes(self) -> int | None:
        if self.pk_bytes is None or self.sig_bytes is None:
            return None
        return self.pk_bytes + OPENER_BYTES + self.sig_bytes


@dataclass(frozen=True)
class AccountProfile:
    """A complete, stable interpretation of a format-0x02 spend_key."""

    profile_id: str
    revision: int
    meta_address_version: int
    kem: KemSet
    domains: CommitDomains
    authorization: Authorization
    # Description of the CREATE2 binding layout every Deployment for this
    # profile must follow (the code that computes it is commit.account_address).
    binding_layout: str
    # Implementation status of the on-chain spend route, kept honest here so a
    # caller cannot mistake a derivation-only profile for a spendable one.
    spend_route_status: str

    @property
    def name(self) -> str:
        return f"{self.profile_id}/v{self.revision}"


_BINDING_LAYOUT_8141 = (
    "CREATE2(factory, salt, keccak256(creation_code || commitment || "
    "leftpad32(verifier) || leftpad32(frame_ctx))) — Stealth8141ZkFactory shape"
)

SPHINCS_C13_COMMIT_V0 = AccountProfile(
    profile_id="sphincs-c13-commit",
    revision=0,
    meta_address_version=META_ADDRESS_VERSION_COMMIT,
    kem=DEFAULT_KEM,
    domains=SPHINCS_C13_DOMAINS,
    authorization=Authorization(
        scheme="SPHINCS- C13 (raw 32-byte key is the spend_key)",
        dsa=None,
        key_domain=None,
        pk_bytes=32,
        sig_bytes=3688,
        message_convention="C13 H_msg over the 32-byte digest, no envelope",
    ),
    binding_layout=_BINDING_LAYOUT_8141,
    spend_route_status="deployed (D-018 commit signer, D-023 ZK circuit)",
)

PREIMAGE_V0 = AccountProfile(
    profile_id="preimage",
    revision=0,
    meta_address_version=META_ADDRESS_VERSION_COMMIT,
    kem=DEFAULT_KEM,
    domains=PREIMAGE_DOMAINS,
    authorization=Authorization(
        scheme="preimage ZK proof of (sk, opener); spend_key = keccak256(KEY || sk)",
        dsa=None,
        key_domain=PREIMAGE_KEY_DOMAIN,
        pk_bytes=None,
        sig_bytes=None,
        message_convention="UltraHonk public inputs [digest_hi, digest_lo, "
        "commitment_hi, commitment_lo]; backend not PQ-sound",
    ),
    binding_layout=_BINDING_LAYOUT_8141,
    spend_route_status="deployed on the frames testnet (D-025 browser demo)",
)

ML_DSA_44_COMMIT_V0 = AccountProfile(
    profile_id="ml-dsa-44-commit",
    revision=0,
    meta_address_version=META_ADDRESS_VERSION_COMMIT,
    kem=DEFAULT_KEM,
    domains=ML_DSA_44_DOMAINS,
    authorization=Authorization(
        scheme="ML-DSA-44 (FIPS 204), canonical 1,312-byte public key",
        dsa=ML_DSA_44,
        key_domain=ML_DSA_44_KEY_DOMAIN,
        pk_bytes=ML_DSA_44_PK_BYTES,
        sig_bytes=ML_DSA_44_SIG_BYTES,
        message_convention="pure/empty-ctx/digest32",
    ),
    binding_layout=_BINDING_LAYOUT_8141,
    spend_route_status=(
        "reference + local contract path (MlDsa44CommitSigner7913 over the "
        "vendored ZKNOX ML-DSA-44 verifier); key setup needs a trusted "
        "registrar — no trustless deployment, nothing live"
    ),
)

PROFILES: dict[str, AccountProfile] = {
    p.name: p for p in (SPHINCS_C13_COMMIT_V0, PREIMAGE_V0, ML_DSA_44_COMMIT_V0)
}


class ProfileError(ValueError):
    """Raised when a profile or binding is unknown, malformed, or conflicting."""


@dataclass(frozen=True)
class ProfileBinding:
    """A selected profile bound to one chain and one deployment.

    This is the trusted configuration a sender needs before deriving an
    address and a scanner needs before accepting a payment. It is *not*
    authenticated by construction: whoever supplies it must be trusted.
    """

    profile: AccountProfile
    chain_id: int
    deployment: Deployment

    def for_chain(self, chain_id: int) -> ProfileBinding:
        """Fail closed when used on a different chain than it was bound to."""
        if chain_id != self.chain_id:
            raise ProfileError(
                f"binding is for chain {self.chain_id}, not chain {chain_id}"
            )
        return self


def _check_address(name: str, value: bytes) -> None:
    if not isinstance(value, bytes) or len(value) != 20:
        raise ProfileError(f"{name} must be 20 bytes")


def select_profile(
    profile_name: str, chain_id: int, deployment: Deployment
) -> ProfileBinding:
    """Resolve an explicitly named profile and validate its deployment binding.

    Rejects unknown profiles, non-positive chain IDs, and malformed bindings.
    Accepting a binding here means the application trusts it; the function
    cannot tell a genuine factory from a substituted one.
    """
    profile = PROFILES.get(profile_name)
    if profile is None:
        raise ProfileError(f"unknown or unsupported profile {profile_name!r}")
    if not isinstance(chain_id, int) or chain_id <= 0:
        raise ProfileError("chain_id must be a positive integer")
    _check_address("deployment.factory", deployment.factory)
    _check_address("deployment.verifier", deployment.verifier)
    _check_address("deployment.frame_ctx", deployment.frame_ctx)
    if len(deployment.salt) != 32:
        raise ProfileError("deployment.salt must be 32 bytes")
    if len(deployment.creation_code) == 0:
        raise ProfileError("deployment.creation_code must not be empty")
    return ProfileBinding(profile, chain_id, deployment)


def _check_meta(meta: CommitMetaPublic, profile: AccountProfile) -> None:
    if meta.kem is not profile.kem:
        raise ProfileError(
            f"meta-address KEM {meta.kem.name} does not match profile "
            f"{profile.name} ({profile.kem.name})"
        )
    if len(meta.spend_key) != SPEND_KEY_BYTES:
        raise ProfileError("spend_key must be 32 bytes")


# --------------------------------------------------------------------------
# ML-DSA key commitment
# --------------------------------------------------------------------------
def spend_key_from_ml_dsa_pk(
    pk: bytes, profile: AccountProfile = ML_DSA_44_COMMIT_V0
) -> bytes:
    """spend_key = keccak256(key_domain || pk), pk the canonical FIPS 204
    public-key encoding of the profile's exact parameter set. This is the
    32-byte value published in the meta-address; the outer commitment hashes
    it once more together with the opener — never hash pk twice here."""
    auth = profile.authorization
    if auth.key_domain is None or auth.pk_bytes is None:
        raise ProfileError(f"profile {profile.name} has no ML-DSA key commitment")
    if len(pk) != auth.pk_bytes:
        raise ProfileError(
            f"{auth.scheme} public key must be {auth.pk_bytes} bytes, got {len(pk)}"
        )
    return keccak256(auth.key_domain + pk)


def gen_ml_dsa_recipient(
    profile: AccountProfile = ML_DSA_44_COMMIT_V0,
    zeta: bytes | None = None,
    kem_d: bytes | None = None,
    kem_z: bytes | None = None,
) -> tuple[CommitMetaPublic, bytes, bytes, bytes]:
    """Recipient side: an ML-DSA signing keypair plus an ML-KEM viewing keypair.

    Returns (meta_public, kem_dk, dsa_pk, dsa_sk). Seeds are for deterministic
    vectors only. The signing secret never enters the meta-address; the KEM
    shared secret and opener are sender-known and are not credentials.
    """
    dsa = profile.authorization.dsa
    if dsa is None:
        raise ProfileError(f"profile {profile.name} is not a signature profile")
    zeta = zeta if zeta is not None else os.urandom(32)
    if len(zeta) != 32:
        raise ProfileError("zeta must be 32 bytes")
    dsa_pk, dsa_sk = dsa._keygen_internal(zeta)
    meta, kem_dk = gen_commit_meta_address(
        spend_key_from_ml_dsa_pk(dsa_pk, profile), profile.kem, kem_d, kem_z
    )
    return meta, kem_dk, dsa_pk, dsa_sk


# --------------------------------------------------------------------------
# Profile-aware send / scan (thin wrappers over commit.py, same bytes)
# --------------------------------------------------------------------------
def send_with_profile(
    meta: CommitMetaPublic, binding: ProfileBinding, encaps_m: bytes | None = None
) -> tuple[CommitAnnouncement, bytes]:
    """Sender: only the public meta-address, the trusted binding, and the
    sender-generated KEM result are needed."""
    _check_meta(meta, binding.profile)
    return send_commit(meta, binding.deployment, encaps_m, binding.profile.domains)


def check_with_profile(
    meta: CommitMetaPublic,
    kem_dk: bytes,
    ann: CommitAnnouncement,
    binding: ProfileBinding,
) -> CommitPayment | None:
    """Scanner: viewing secret + public spend_key + selected profile. Accepts
    only after re-deriving the destination; a matching view tag alone is not
    a payment. No spending secret is involved."""
    _check_meta(meta, binding.profile)
    return check_commit_announcement(
        meta, kem_dk, ann, binding.deployment, binding.profile.domains
    )


# --------------------------------------------------------------------------
# Authorization payload:  pk || opener || signature
# --------------------------------------------------------------------------
def build_authorization(
    dsa_sk: bytes,
    dsa_pk: bytes,
    opener: bytes,
    digest: bytes,
    profile: AccountProfile = ML_DSA_44_COMMIT_V0,
    deterministic: bool = False,
) -> bytes:
    """Recipient: sign the account's canonical 32-byte operation digest and
    open the commitment. The payload is what the account verifier consumes:

        payload = pk(1312) || opener(32) || sig(2420)      (3,764 bytes)

    `digest` is whatever the account defines as the thing to sign (an
    EIP-8141 frame `sig_hash`, an ERC-4337 `userOpHash`); it already binds
    chain, account, nonce, destination, value, and calldata. The signature is
    pure ML-DSA-44 with an empty context over those 32 bytes — the verifier
    does not hash the digest again.
    """
    auth = profile.authorization
    if auth.dsa is None or auth.pk_bytes is None:
        raise ProfileError(f"profile {profile.name} is not a signature profile")
    if len(dsa_pk) != auth.pk_bytes:
        raise ProfileError(f"public key must be {auth.pk_bytes} bytes")
    if len(opener) != OPENER_BYTES:
        raise ProfileError("opener must be 32 bytes")
    if len(digest) != DIGEST_BYTES:
        raise ProfileError("digest must be 32 bytes")
    sig = auth.dsa.sign(dsa_sk, digest, ctx=b"", deterministic=deterministic)
    assert len(sig) == auth.sig_bytes
    return dsa_pk + opener + sig


def parse_authorization(
    payload: bytes, profile: AccountProfile = ML_DSA_44_COMMIT_V0
) -> tuple[bytes, bytes, bytes]:
    """Split a payload into (pk, opener, sig); exact length only."""
    auth = profile.authorization
    if auth.payload_bytes is None:
        raise ProfileError(f"profile {profile.name} has no signature payload")
    if len(payload) != auth.payload_bytes:
        raise ProfileError(
            f"payload must be {auth.payload_bytes} bytes, got {len(payload)}"
        )
    pk = payload[: auth.pk_bytes]
    opener = payload[auth.pk_bytes : auth.pk_bytes + OPENER_BYTES]
    sig = payload[auth.pk_bytes + OPENER_BYTES :]
    return pk, opener, sig


def verify_authorization(
    commitment: bytes,
    digest: bytes,
    payload: bytes,
    profile: AccountProfile = ML_DSA_44_COMMIT_V0,
) -> bool:
    """Reference verifier — the same steps the on-chain wrapper performs:

    1. parse and length-check the payload for the profile's parameter set;
    2. spend_key = keccak256(key_domain || pk);
    3. commitment' = keccak256(commit_domain || spend_key || opener), which
       must equal the account's bound commitment;
    4. verify the signature under pk over the 32-byte digest (empty ctx).

    Returns False (never raises) on any mismatch or malformed input, so the
    caller can treat it like an ERC-7913 verifier's 0xffffffff.
    """
    auth = profile.authorization
    if auth.dsa is None:
        return False
    if len(commitment) != SPEND_KEY_BYTES or len(digest) != DIGEST_BYTES:
        return False
    try:
        pk, opener, sig = parse_authorization(payload, profile)
    except ProfileError:
        return False
    spend_key = spend_key_from_ml_dsa_pk(pk, profile)
    if derive_commitment(spend_key, opener, profile.domains) != commitment:
        return False
    try:
        return bool(auth.dsa.verify(pk, digest, sig, ctx=b""))
    except Exception:  # malformed signature bytes never raise
        return False


def opener_for_payment(ss: bytes, profile: AccountProfile) -> bytes:
    """Opener under the selected profile's domain (sender- and scanner-known)."""
    return derive_opener(ss, profile.domains)
