"""Explicit account profiles over format 0x02: selection, ML-DSA-44 key
commitment, profile-aware send/scan, and the authorization payload."""

import hashlib
import json
import pathlib

import pytest

from pq_stealth.commit import (
    SPHINCS_C13_DOMAINS,
    CommitAnnouncement,
    Deployment,
    account_address,
    check_commit_announcement,
    decode_commit_meta_address,
    derive_commitment,
    derive_opener,
    send_commit,
)
from pq_stealth.encoding import keccak256
from pq_stealth.profiles import (
    ML_DSA_44_COMMIT_V0,
    ML_DSA_44_DOMAINS,
    ML_DSA_44_KEY_DOMAIN,
    PREIMAGE_V0,
    PROFILES,
    SPHINCS_C13_COMMIT_V0,
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

VECTORS = pathlib.Path(__file__).resolve().parents[1] / "vectors" / "v0"
DEP = Deployment(
    factory=bytes.fromhex("303cb317624c74bb20acbb9e13c8d745c6379826"),
    creation_code=bytes.fromhex("60806040526001600055"),  # synthetic, vectors only
    verifier=bytes.fromhex("f01ecc1df1868c3b15f0edc4768812b9c435bbfb"),
    frame_ctx=bytes.fromhex("1adb9959eb142be128e6dfecc8d571f07cd66dee"),
)
PROFILE = ML_DSA_44_COMMIT_V0
DSA = PROFILE.authorization.dsa


def unhex(s: str) -> bytes:
    return bytes.fromhex(s.removeprefix("0x"))


@pytest.fixture(scope="module")
def binding():
    return select_profile("ml-dsa-44-commit/v0", 31337, DEP)


@pytest.fixture(scope="module")
def recipient():
    return gen_ml_dsa_recipient(
        PROFILE, zeta=b"\x91" * 32, kem_d=b"\x83" * 32, kem_z=b"\x84" * 32
    )


@pytest.fixture(scope="module")
def payment(recipient, binding):
    meta, dk, _pk, _sk = recipient
    ann, commitment = send_with_profile(meta, binding, encaps_m=b"\x47" * 32)
    hit = check_with_profile(meta, dk, ann, binding)
    assert hit is not None and hit.commitment == commitment
    return ann, hit, commitment


# --------------------------------------------------------------------------
# profile selection and trust boundary
# --------------------------------------------------------------------------
def test_profiles_are_explicit_and_distinct():
    assert set(PROFILES) == {
        "sphincs-c13-commit/v0", "preimage/v0", "ml-dsa-44-commit/v0"
    }
    # existing profiles keep their exact domain bytes (renaming moves funds)
    assert SPHINCS_C13_COMMIT_V0.domains is SPHINCS_C13_DOMAINS
    assert SPHINCS_C13_COMMIT_V0.domains.commit_domain == (
        b"pq-stealth/sphincs-c13/commit/v0"
    )
    assert PREIMAGE_V0.domains.commit_domain == b"pq-stealth/preimage/commit/v0"
    assert ML_DSA_44_KEY_DOMAIN == b"pq-stealth/ml-dsa-44/key/v0"
    assert ML_DSA_44_DOMAINS.open_domain == b"pq-stealth/ml-dsa-44/open/v0"
    assert ML_DSA_44_DOMAINS.commit_domain == b"pq-stealth/ml-dsa-44/commit/v0"
    # all three profiles share the wire format and the KEM
    for p in PROFILES.values():
        assert p.meta_address_version == 0x02 and p.kem.name == "ML-KEM-768"
    # the ML-DSA profile is explicitly ML-DSA-44 (k = l = 4), never 65
    assert DSA.k == 4 and DSA.l == 4
    assert PROFILE.authorization.pk_bytes == 1312
    assert PROFILE.authorization.sig_bytes == 2420
    assert PROFILE.authorization.payload_bytes == 3764
    assert "ML-DSA-44" in PROFILE.authorization.scheme
    assert "65" not in PROFILE.authorization.scheme


def test_select_profile_rejects_unknown_and_malformed():
    with pytest.raises(ProfileError):
        select_profile("ml-dsa-65-commit/v0", 1, DEP)
    with pytest.raises(ProfileError):
        select_profile("ml-dsa-44-commit/v1", 1, DEP)
    with pytest.raises(ProfileError):
        select_profile("ml-dsa-44-commit/v0", 0, DEP)
    with pytest.raises(ProfileError):
        select_profile("ml-dsa-44-commit/v0", 1, Deployment(
            b"\x01" * 19, DEP.creation_code, DEP.verifier, DEP.frame_ctx))
    with pytest.raises(ProfileError):
        select_profile("ml-dsa-44-commit/v0", 1, Deployment(
            DEP.factory, b"", DEP.verifier, DEP.frame_ctx))
    with pytest.raises(ProfileError):
        select_profile("ml-dsa-44-commit/v0", 1, Deployment(
            DEP.factory, DEP.creation_code, DEP.verifier, DEP.frame_ctx, b"\x00"))


def test_binding_fails_closed_on_chain_conflict(binding):
    assert binding.for_chain(31337) is binding
    with pytest.raises(ProfileError):
        binding.for_chain(1)
    assert isinstance(binding, ProfileBinding)


def test_profile_mismatch_with_meta_address_is_rejected(recipient, binding):
    from pq_stealth.commit import KEM_SETS, CommitMetaPublic

    meta, dk, _pk, _sk = recipient
    other_kem = KEM_SETS["ML-KEM-512"]
    bad = CommitMetaPublic(meta.spend_key, b"\x00" * other_kem.ek_bytes, other_kem)
    with pytest.raises(ProfileError):
        send_with_profile(bad, binding)
    with pytest.raises(ProfileError):
        check_with_profile(bad, dk, CommitAnnouncement(b"\x00" * 20, b"", b"\x00"),
                           binding)


# --------------------------------------------------------------------------
# derivation
# --------------------------------------------------------------------------
def test_spend_key_is_single_keccak_of_domain_and_pk(recipient):
    meta, _dk, pk, _sk = recipient
    assert len(pk) == 1312
    assert meta.spend_key == keccak256(ML_DSA_44_KEY_DOMAIN + pk)
    assert meta.spend_key == spend_key_from_ml_dsa_pk(pk)
    enc = meta.encode()
    assert len(enc) == 1217 and enc[0] == 0x02
    assert decode_commit_meta_address(enc).spend_key == meta.spend_key
    with pytest.raises(ProfileError):
        spend_key_from_ml_dsa_pk(pk[:-1])
    with pytest.raises(ProfileError):
        spend_key_from_ml_dsa_pk(pk, SPHINCS_C13_COMMIT_V0)


def test_send_scan_roundtrip_and_domain_separation(recipient, binding, payment):
    meta, dk, _pk, _sk = recipient
    ann, hit, commitment = payment
    ss = hit.shared_secret
    assert hit.opener == hashlib.sha256(ML_DSA_44_DOMAINS.open_domain + ss).digest()
    assert commitment == keccak256(
        ML_DSA_44_DOMAINS.commit_domain + meta.spend_key + hit.opener
    )
    assert ann.stealth_address == account_address(commitment, DEP)
    assert ann.view_tag == hashlib.sha256(ss).digest()[:1]
    # the same meta-address under the C13 or preimage domains is another account
    assert check_commit_announcement(meta, dk, ann, DEP) is None
    ann_c13, _ = send_commit(meta, DEP, encaps_m=b"\x47" * 32)
    assert ann_c13.stealth_address != ann.stealth_address
    assert check_with_profile(meta, dk, ann_c13, binding) is None
    # a different deployment binding is a different destination
    other = select_profile("ml-dsa-44-commit/v0", 31337, Deployment(
        b"\x01" * 20, DEP.creation_code, DEP.verifier, DEP.frame_ctx))
    assert check_with_profile(meta, dk, ann, other) is None
    # a matching view tag alone is not acceptance: same tag, wrong address
    forged = CommitAnnouncement(b"\x00" * 20, ann.ephemeral_pub_key, ann.view_tag)
    assert check_with_profile(meta, dk, forged, binding) is None


# --------------------------------------------------------------------------
# authorization
# --------------------------------------------------------------------------
def test_authorization_roundtrip(recipient, payment):
    _meta, _dk, pk, sk = recipient
    _ann, hit, commitment = payment
    digest = b"\x11" * 32
    payload = build_authorization(sk, pk, hit.opener, digest, deterministic=True)
    assert len(payload) == 3764
    ppk, popener, sig = parse_authorization(payload)
    assert ppk == pk and popener == hit.opener and len(sig) == 2420
    assert verify_authorization(commitment, digest, payload)
    # independent stock verifier agrees on the signature itself
    assert DSA.verify(pk, digest, sig, ctx=b"")
    # randomized signing also verifies
    assert verify_authorization(
        commitment, digest, build_authorization(sk, pk, hit.opener, digest))


def test_authorization_negatives(recipient, payment):
    _meta, _dk, pk, sk = recipient
    _ann, hit, commitment = payment
    digest = b"\x11" * 32
    payload = build_authorization(sk, pk, hit.opener, digest, deterministic=True)
    pk_len = 1312
    # different digest = different chain/account/nonce/action
    assert not verify_authorization(commitment, b"\x12" * 32, payload)
    # different account commitment
    assert not verify_authorization(b"\x00" * 32, digest, payload)
    # wrong opener
    bad = pk + b"\x00" * 32 + payload[pk_len + 32:]
    assert not verify_authorization(commitment, digest, bad)
    # tampered signature / pk
    for i in (pk_len + 32 + 7, 5):
        t = bytearray(payload)
        t[i] ^= 1
        assert not verify_authorization(commitment, digest, bytes(t))
    # malformed encodings: wrong lengths never raise, always False
    for bad in (payload[:-1], payload + b"\x00", b"", payload[:pk_len]):
        assert not verify_authorization(commitment, digest, bad)
    with pytest.raises(ProfileError):
        parse_authorization(payload[:-1])
    # wrong parameter set: an ML-DSA-65 key cannot be committed or verified here
    from dilithium_py.ml_dsa import ML_DSA_65

    pk65, sk65 = ML_DSA_65._keygen_internal(b"\x95" * 32)
    with pytest.raises(ProfileError):
        spend_key_from_ml_dsa_pk(pk65)
    sig65 = ML_DSA_65.sign(sk65, digest, deterministic=True)
    assert not verify_authorization(commitment, digest, pk65 + hit.opener + sig65)
    # wrong domain profile: the same key material under the C13 domains
    c13 = derive_commitment(
        spend_key_from_ml_dsa_pk(pk),
        derive_opener(hit.shared_secret, SPHINCS_C13_DOMAINS), SPHINCS_C13_DOMAINS)
    assert not verify_authorization(c13, digest, payload)
    # wrong digest length
    assert not verify_authorization(commitment, b"\x11" * 31, payload)
    with pytest.raises(ProfileError):
        build_authorization(sk, pk, hit.opener, b"\x11" * 31)


def test_sender_known_values_cannot_authorize(recipient, payment):
    """The sender knows ss and the opener. Keys derived from either sign fine
    but never open the recipient's commitment."""
    _meta, _dk, pk, _sk = recipient
    _ann, hit, commitment = payment
    digest = b"\x11" * 32
    for seed in (hit.shared_secret, hit.opener):
        apk, ask = DSA._keygen_internal(hashlib.sha256(b"kdf" + seed).digest())
        att = build_authorization(ask, apk, hit.opener, digest, deterministic=True)
        assert DSA.verify(apk, digest, att[1312 + 32:])
        assert not verify_authorization(commitment, digest, att)
    # the recipient's pk with another key's signature
    apk, ask = DSA._keygen_internal(b"\x93" * 32)
    forged = pk + hit.opener + DSA.sign(ask, digest, deterministic=True)
    assert not verify_authorization(commitment, digest, forged)


def test_two_direct_spends_are_linkable(recipient, binding):
    """Documented boundary: fresh openers give fresh commitments and addresses,
    but both payloads reveal the same pk, whose hash is the published
    spend_key. This test demonstrates the linkage; it is not a privacy claim."""
    meta, dk, pk, sk = recipient
    a1, c1 = send_with_profile(meta, binding, encaps_m=b"\x61" * 32)
    a2, c2 = send_with_profile(meta, binding, encaps_m=b"\x62" * 32)
    assert c1 != c2 and a1.stealth_address != a2.stealth_address
    h1 = check_with_profile(meta, dk, a1, binding)
    h2 = check_with_profile(meta, dk, a2, binding)
    p1 = build_authorization(sk, pk, h1.opener, b"\x01" * 32, deterministic=True)
    p2 = build_authorization(sk, pk, h2.opener, b"\x02" * 32, deterministic=True)
    assert parse_authorization(p1)[0] == parse_authorization(p2)[0]
    assert spend_key_from_ml_dsa_pk(parse_authorization(p1)[0]) == meta.spend_key


# --------------------------------------------------------------------------
# vectors
# --------------------------------------------------------------------------
def test_vectors_replay():
    doc = json.loads((VECTORS / "mldsa44_commit_vectors.json").read_text())
    assert doc["profile"]["name"] == PROFILE.name
    dep = Deployment(
        unhex(doc["binding"]["factory"]), unhex(doc["binding"]["creation_code"]),
        unhex(doc["binding"]["verifier"]), unhex(doc["binding"]["frame_ctx"]),
        unhex(doc["binding"]["salt"]))
    b = select_profile(doc["profile"]["name"], doc["binding"]["chain_id"], dep)
    for r in doc["recipients"].values():
        meta = decode_commit_meta_address(unhex(r["meta_address"]))
        assert meta.spend_key == spend_key_from_ml_dsa_pk(unhex(r["ml_dsa_pk"]))
    for c in doc["cases"]:
        r = doc["recipients"][c["recipient"]]
        meta = decode_commit_meta_address(unhex(r["meta_address"]))
        a = c["announcement"]
        ann = CommitAnnouncement(
            unhex(a["stealth_address"]), unhex(a["ephemeral_pub_key"]),
            unhex(a["view_tag"]))
        hit = check_with_profile(meta, unhex(r["kem_dk"]), ann, b)
        if c["expect"] == "no_match":
            assert hit is None
            continue
        assert hit is not None
        assert hit.shared_secret == unhex(c["shared_secret"])
        assert hit.opener == unhex(c["opener"])
        assert hit.commitment == unhex(c["commitment"])
    for a in doc["authorizations"]:
        got = verify_authorization(unhex(a["commitment"]), unhex(a["digest"]),
                                   unhex(a["payload"]))
        assert got is a["expect"], a["name"]


def test_vectors_are_reproducible(tmp_path):
    import subprocess
    import sys

    gen = VECTORS.parent / "generate_mldsa44_commit_vectors.py"
    subprocess.run([sys.executable, str(gen), "-o", str(tmp_path)], check=True)
    assert (tmp_path / "mldsa44_commit_vectors.json").read_bytes() == (
        VECTORS / "mldsa44_commit_vectors.json").read_bytes()
