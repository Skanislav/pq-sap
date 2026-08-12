#!/usr/bin/env python3
"""Stretch-goal demo generator: blinded stealth key at the ZKNOX profile.

Instantiates construction A (additive blinding + fresh error term) on the
signature profile actually deployed by kohaku/ZKNOX — their vendored
dilithium-py `Dilithium2` (round-3 level-2 parameters, FIPS-204-style
keygen/sign/M' formatting, SHAKE XOFs / "NIST" mode) — and emits a JSON
blob for the on-chain counterfactual-CREATE2 test:

  * stealth_pk       — 1,312 B packed pk of the blinded key
  * public_key_data  — the expanded pk (A_hat, tr, NTT(t1*2^d)) ABI-encoded
                       exactly as ZKNOX's PKContract stores it; this is what
                       the account factory consumes, and the sender can
                       compute all of it from public data
  * challenge + sig  — possession proof signed with the blinded secret
                       (s1+s', s2+e', t0'), verified locally before output

Usage: zknox_counterfactual_demo.py --pythonref PATH/to/ETHDILITHIUM/pythonref -o out.json
"""

import argparse
import hashlib
import json
import pathlib
import sys


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pythonref", required=True)
    ap.add_argument("-o", "--out", required=True)
    ap.add_argument("--sign-challenge", default=None, metavar="HEX",
                    help="instead of the default demo challenge, sign this "
                         "hex message (e.g. a 32-byte ERC-4337 userOpHash) "
                         "with the blinded key and write {sig} JSON")
    args = ap.parse_args()
    sys.path.insert(0, args.pythonref)

    from dilithium_py.dilithium.default_parameters import Dilithium2 as D
    from dilithium_py.shake.shake_wrapper import shake128, shake256
    from eth_abi import encode
    from kyber_py.ml_kem import ML_KEM_512

    beta_blinded = D.tau * 2 * D.eta  # 156 for level-2 params

    # --- recipient master key (full-precision t kept) ----------------------
    zeta = b"\xd1" * 32
    seed = D._h(zeta + bytes([D.k]) + bytes([D.l]), 128)
    rho, rho_prime = seed[:32], seed[32:96]
    A_hat = D._expand_matrix_from_seed(rho)
    s1, s2 = D._expand_vector_from_seed(rho_prime)
    t = (A_hat @ s1.to_ntt()).from_ntt() + s2

    # --- viewing keypair + sender encapsulation (level-2 pairing) ----------
    ek, dk = ML_KEM_512._keygen_internal(b"\xd2" * 32, b"\xd3" * 32)
    ss, kem_ct = ML_KEM_512._encaps_internal(ek, b"\xd4" * 32)
    assert ML_KEM_512.decaps(dk, kem_ct) == ss

    # --- blinded derivation (construction A, fresh e') ---------------------
    s_p, e_p = D._expand_vector_from_seed(hashlib.shake_256(ss).digest(64))
    t_prime = (A_hat @ s_p.to_ntt()).from_ntt() + e_p + t
    t1, t0 = t_prime.power_2_round(D.d)
    stealth_pk = D._pack_pk(rho, t1)

    # --- possession proof with the blinded secret --------------------------
    if args.sign_challenge is not None:
        challenge = bytes.fromhex(args.sign_challenge.removeprefix("0x"))
    else:
        challenge = b"pq-stealth counterfactual possession challenge"
    ctx = b""
    m_prime = bytes([0, len(ctx)]) + ctx + challenge
    s1_b, s2_b = s1 + s_p, s2 + e_p
    tr = D._h(stealth_pk, 64)
    K = hashlib.shake_256(b"pq-stealth/zknox-demo/v0" + ss).digest(32)
    mu = D._h(tr + m_prime, 64)
    rho_prime_sig = D._h(K + bytes(32) + mu, 64)  # deterministic (rnd = 0^32)

    s1_hat, s2_hat, t0_hat = s1_b.to_ntt(), s2_b.to_ntt(), t0.to_ntt()
    kappa, alpha = 0, D.gamma_2 << 1
    rounds = 0
    while True:
        rounds += 1
        y = D._expand_mask_vector(rho_prime_sig, kappa)
        w = (A_hat @ y.to_ntt()).from_ntt()
        kappa += D.l
        w1 = w.high_bits(alpha)
        c_tilde = D._h(mu + w1.bit_pack_w(D.gamma_2), D.c_tilde_bytes)
        c_hat = D.R.sample_in_ball(c_tilde, D.tau).to_ntt()

        z = y + s1_hat.scale(c_hat).from_ntt()
        if z.check_norm_bound(D.gamma_1 - max(D.beta, beta_blinded)):
            continue
        c_s2 = s2_hat.scale(c_hat).from_ntt()
        r0 = (w - c_s2).low_bits(alpha)
        if r0.check_norm_bound(D.gamma_2 - max(D.beta, beta_blinded)):
            continue
        c_t0 = t0_hat.scale(c_hat).from_ntt()
        if c_t0.check_norm_bound(D.gamma_2):
            continue
        h = (-c_t0).make_hint(w - c_s2 + c_t0, alpha)
        if h.sum_hint() > D.omega:
            continue
        sig = D._pack_sig(c_tilde, z, h)
        break

    assert D.verify(stealth_pk, challenge, sig), \
        "blinded signature must pass the stock ZKNOX-profile verifier"

    # --- expanded pk, encoded exactly as PKContract stores it --------------
    # SHAKE/NIST profile, current (df999ed) contract format: A_hat in the NTT
    # domain, t1 PLAIN (the contract scales by 2^d and NTTs itself; upstream's
    # pk_for_eth is hardwired to the keccak-PRNG variant and unused here)
    rho_pk, t1_unpacked = D._unpack_pk(stealth_pk)
    tr_eth = D._h(stealth_pk, 64, _xof=shake256)
    A_hat_eth = D._expand_matrix_from_seed(rho_pk, _xof=shake128)
    t1_new = t1_unpacked
    assert tr_eth == tr
    a_hat_compact = A_hat_eth.compact_256(32)
    t1_compact = t1_new.compact_256(32)
    # Vector.compact_256 yields [k][1][32]; the contract wants uint256[][] = [k][32]
    if all(len(row) == 1 for row in t1_compact):
        t1_compact = [row[0] for row in t1_compact]
    public_key_data = encode(
        ["bytes", "bytes", "bytes"],
        [encode(["uint256[][][]"], [a_hat_compact]), tr,
         encode(["uint256[][]"], [t1_compact])])

    out = {
        "profile": "ZKNOX Dilithium2 (level-2, NIST/SHAKE mode)",
        "sign_rejection_rounds": rounds,
        "kem": "ML-KEM-512",
        "kem_ct": "0x" + kem_ct.hex(),
        "view_tag": "0x" + hashlib.sha256(ss).digest()[:1].hex(),
        "stealth_pk": "0x" + stealth_pk.hex(),
        "public_key_data": "0x" + public_key_data.hex(),
        "challenge": "0x" + challenge.hex(),
        "sig": "0x" + sig.hex(),
    }
    pathlib.Path(args.out).write_text(json.dumps(out, indent=2) + "\n")
    print(f"stealth_pk: {len(stealth_pk)} B, public_key_data: "
          f"{len(public_key_data)} B, sig: {len(sig)} B, "
          f"{rounds} rejection rounds -> {args.out}")


if __name__ == "__main__":
    main()
