#!/usr/bin/env python3
"""Emit the on-chain fixture for the SPHINCS- C13 (hash-based) ERC-7913 spend
route (D-018).

The counterpart to zknox_7913_demo.py (blinded ML-DSA) and
classical_7913_demo.py (secp256k1). Here the spend key is a SPHINCS- C13 key
-- the Verity Labs machine-checked hash-based verifier -- and the ERC-7913
signer comes in two forms, both covered by this fixture:

  SphincsC13Signer7913        key = pk (32 B)                       sig = 3,688 B
  SphincsC13CommitSigner7913  key = keccak(DOMAIN || pk || opener)   sig = pk || opener || c13sig

The commit form is the one that gives a hash-based key a sender-derivable
stealth address: the sender knows pk (meta-address) and derives `opener` from
the ML-KEM shared secret, so it can build the account initcode; the recipient
recovers the same `ss` on detection. Opening the commitment at spend time
reveals pk, i.e. the recipient (docs/research/hash-based-key-exchange.md row
B); see D-018 for the trade-off.

Fully deterministic: fixed seeds, fixed ML-KEM encapsulation randomness, and
the C13 signer's R / counter grinds are deterministic in sk_seed, so running
it twice yields byte-identical output. Signing needs the Rust CLI from
lfglabs-dev/SPHINCS- @ 2a40d0a (`cd signer-wasm && cargo build --release
--bin signer-c13`); pass it with --signer or SIGNER_C13.

Consumed by js-client/test/e2e-7913-sphincs.test.ts, which re-derives the
opener and commitment in TypeScript and asserts byte-equality.

Usage: sphincs_c13_7913_demo.py --signer PATH [-o OUTFILE]
"""

import argparse
import hashlib
import json
import os
import pathlib
import subprocess

from Crypto.Hash import keccak

from pq_stealth.meta import gen_meta_address
from pq_stealth.params import DEFAULT
from pq_stealth.recipient import check_announcement
from pq_stealth.sender import send

# Fixed inputs. Distinct from the other fixtures' seeds so the artifacts
# cannot be confused, but equally deterministic.
SPEND_SEED = b"\x81" * 32     # recipient's hash-based spend seed
ZETA = b"\x82" * 32           # ML-DSA half of the (default) meta-address; unused by C13
KEM_D = b"\x83" * 32
KEM_Z = b"\x84" * 32
ENCAPS_M = b"\x85" * 32

SIGNER_REV = "2a40d0a3351e8709094c699974a6d849c191bc08"
C13 = {"n": 16, "h": 22, "d": 2, "a": 19, "k": 7, "w": 8, "l": 43,
       "target_sum": 208, "sig_len": 3688, "sig_cap_log2": 22}

# Domain tags shared with js-client/src/sphincs.ts.
KEYGEN_DOMAIN = b"pq-stealth/sphincs-c13/keygen/v0"
OPEN_DOMAIN = b"pq-stealth/sphincs-c13/open/v0"
COMMIT_DOMAIN = b"pq-stealth/sphincs-c13/commit/v0"   # 32 bytes = bytes32 on-chain
assert len(COMMIT_DOMAIN) == 32

# Stands in for the message hash the account would actually be asked to
# validate (an ERC-191 / ERC-4337 userOp hash). The C13 verifier hashes it
# into H_msg together with R, seed and root; nothing else is prepended.
CHALLENGE = hashlib.sha256(b"pq-stealth/sphincs-c13/erc7913 spend demo").digest()


# Pointer-signature vault fixture: anvil dev account #0 deploys, in this order,
# from a fresh chain (js-client/test/e2e-pointer-sig.test.ts asserts the
# resulting addresses match before using the signatures).
ANVIL_DEPLOYER = bytes.fromhex("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
CHAIN_ID = 31337
DEPLOY_NONCES = {"c13_verifier": 0, "mldsa_verifier": 1, "registry": 2, "vault": 3}
WITHDRAW_TO = bytes(18) + b"\xbe\xef"
WITHDRAW_AMOUNT = 250_000_000_000_000_000   # 0.25 ether


def hx(b: bytes) -> str:
    return "0x" + b.hex()


def keccak256(b: bytes) -> bytes:
    return keccak.new(digest_bits=256, data=b).digest()


def create_address(sender: bytes, nonce: int) -> bytes:
    """CREATE address = keccak256(rlp([sender, nonce]))[12:], nonce < 128."""
    assert len(sender) == 20 and 0 <= nonce < 128
    return keccak256(b"\xd6\x94" + sender + (b"\x80" if nonce == 0 else bytes([nonce])))[12:]


def word(x: int | bytes) -> bytes:
    return x.rjust(32, b"\x00") if isinstance(x, bytes) else x.to_bytes(32, "big")


def withdraw_digest(vault: bytes, owner: bytes, to: bytes, amount: int, nonce: int) -> bytes:
    """PointerSigVault.withdrawDigest = keccak256(abi.encode(chainid, vault, owner, to, amount, nonce))."""
    return keccak256(word(CHAIN_ID) + word(vault) + word(owner) + word(to) + word(amount) + word(nonce))


def run_signer(signer: str, *args: str) -> str:
    res = subprocess.run([signer, *args], capture_output=True, text=True, check=True)
    return res.stdout.strip()


def build(signer: str) -> dict:
    # --- discovery: a real ML-KEM-768 exchange, exactly as the scheme does it
    meta_pub, meta_priv = gen_meta_address(
        DEFAULT, zeta=ZETA, kem_d=KEM_D, kem_z=KEM_Z)
    ann = send(meta_pub, encaps_m=ENCAPS_M)
    payment = check_announcement(meta_pub, meta_priv.kem_dk, ann)
    assert payment is not None, "recipient must detect its own payment"
    ss = payment.shared_secret

    # --- the recipient's C13 key: seed material from the spend seed only
    seed_material = hashlib.sha256(KEYGEN_DOMAIN + SPEND_SEED).digest()
    keys = json.loads(run_signer(signer, "keygen", hx(seed_material)))
    pk_seed = bytes.fromhex(keys["seed"][2:])
    sk_seed = bytes.fromhex(keys["sk_seed"][2:])
    pk_root = bytes.fromhex(keys["root"][2:])
    assert len(pk_seed) == len(pk_root) == 32
    assert pk_seed[16:] == bytes(16) and pk_root[16:] == bytes(16), "n = 16: halves top-aligned"
    pk = pk_seed[:16] + pk_root[:16]                       # the 32-byte ERC-7913 key

    # --- sign the challenge
    sig = bytes.fromhex(run_signer(
        signer, "sign-with", keys["seed"], keys["sk_seed"], keys["root"], hx(CHALLENGE))[2:])
    assert len(sig) == C13["sig_len"], f"C13 sig must be {C13['sig_len']} B, got {len(sig)}"

    # --- commit form: opener from ss (never ss itself), commitment on-chain
    opener = hashlib.sha256(OPEN_DOMAIN + ss).digest()
    commitment = keccak256(COMMIT_DOMAIN + pk + opener)
    commit_sig = pk + opener + sig

    # --- pointer-signature route (docs/pointer-signatures-poc.md, v = 0x52 / 0x53):
    # the vault's withdraw digest binds chain id, vault address, owner, to, amount
    # and nonce, so the fixture pins the e2e's deploy order (fresh anvil, account
    # #0, CREATE nonces) and signs the two digests the test will actually present.
    vault = create_address(ANVIL_DEPLOYER, DEPLOY_NONCES["vault"])
    pointer = {
        "chain_id": CHAIN_ID,
        "deployer": hx(ANVIL_DEPLOYER),
        "deploy_nonces": DEPLOY_NONCES,
        "vault": hx(vault),
        "to": hx(WITHDRAW_TO),
        "amount": str(WITHDRAW_AMOUNT),
        "v_sphincs": 0x52,
        "v_sphincs_commit": 0x53,
    }
    for form, word in (("raw", pk), ("commit", commitment)):
        owner = keccak256(word)[12:]
        digest = withdraw_digest(vault, owner, WITHDRAW_TO, WITHDRAW_AMOUNT, 0)
        vsig = bytes.fromhex(run_signer(
            signer, "sign-with", keys["seed"], keys["sk_seed"], keys["root"], hx(digest))[2:])
        assert len(vsig) == C13["sig_len"]
        pointer[form] = {
            "r": hx(word),
            "owner": hx(owner),
            "digest": hx(digest),
            "sig": hx(vsig),
            "blob": hx(vsig if form == "raw" else pk + opener + vsig),
        }

    return {
        "profile": "SPHINCS- C13 spend key + ML-KEM-768 discovery "
                   "(hash-based spend, ERC-7913 raw-key and commit forms)",
        "kem": "ML-KEM-768",
        "kem_ct": hx(ann.ephemeral_pub_key),
        "view_tag": hx(ann.view_tag),
        "shared_secret_DEMO_ONLY": hx(ss),
        "c13": C13,
        "signer_rev": SIGNER_REV,
        "pk_seed": hx(pk_seed),
        "pk_root": hx(pk_root),
        "key": hx(pk),
        "challenge": hx(CHALLENGE),
        "sig": hx(sig),
        "opener": hx(opener),
        "commitment": hx(commitment),
        "commit_signature": hx(commit_sig),
        "pointer": pointer,
        "sizes": {
            "key": len(pk),
            "kem_ct": len(ann.ephemeral_pub_key),
            "sig": len(sig),
            "commit_signature": len(commit_sig),
        },
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--signer", default=os.environ.get("SIGNER_C13"),
                    help="path to the signer-c13 binary (or env SIGNER_C13)")
    ap.add_argument("-o", "--outfile",
                    default=pathlib.Path(__file__).parent / "sphincs_c13_7913_demo.json")
    args = ap.parse_args()
    if not args.signer:
        ap.error("--signer (or SIGNER_C13) is required")

    doc = build(args.signer)
    out = pathlib.Path(args.outfile)
    out.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"wrote {out} ({out.stat().st_size} bytes): "
          f"key {doc['sizes']['key']} B, sig {doc['sizes']['sig']} B, "
          f"commit sig {doc['sizes']['commit_signature']} B")
