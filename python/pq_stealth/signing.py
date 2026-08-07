"""Signing with the blinded stealth key, and proof of possession.

FIPS 204 Algorithm 7, run over the widened key material

    s1' = s1 + s',   s2' = s2 + e',   t0' from Power2Round(t')

with two deviations, both consequences of the doubled infinity norm
(||s1'||, ||s2'|| <= 2*eta):

  * the z rejection bound uses beta' = tau*2*eta (392 for ML-DSA-65)
    instead of beta = tau*eta; the VERIFIER's bound gamma_1 - beta is
    unchanged and beta' > beta, so produced signatures still pass a stock
    FIPS 204 verifier, at the cost of more rejection rounds;
  * the r0 low-bits bound is likewise tightened to gamma_2 - beta'.

Signatures are byte-identical in format to standard ML-DSA signatures and
verify under any conformant verifier (dilithium-py, liboqs, on-chain
ML-DSA verifiers).
"""

import hashlib
import os

from .params import ParamSet
from .meta import MetaSecret
from .blinding import derive_blinding

POP_CTX = b"pq-stealth/pop/v0"


def _format_message(m: bytes, ctx: bytes) -> bytes:
    """FIPS 204 message formatting: M' = 0x00 || len(ctx) || ctx || m."""
    if len(ctx) > 255:
        raise ValueError("ctx must be at most 255 bytes")
    return bytes([0, len(ctx)]) + ctx + m


def sign_blinded(meta_priv: MetaSecret, stealth_pk: bytes, t0, ss: bytes,
                 m: bytes, ctx: bytes = b"",
                 deterministic: bool = False) -> bytes:
    p = meta_priv.params
    dsa = p.dsa

    s_p, e_p = derive_blinding(ss, p)
    s1_b = meta_priv.s1 + s_p
    s2_b = meta_priv.s2 + e_p

    tr = dsa._h(stealth_pk, 64)
    K = hashlib.shake_256(b"pq-stealth/sign-key/v0" + ss).digest(32)
    mu = dsa._h(tr + _format_message(m, ctx), 64)
    rnd = bytes(32) if deterministic else os.urandom(32)
    rho_prime = dsa._h(K + rnd + mu, 64)

    rho = dsa._unpack_pk(stealth_pk)[0]
    A_hat = dsa._expand_matrix_from_seed(rho)
    s1_hat, s2_hat, t0_hat = s1_b.to_ntt(), s2_b.to_ntt(), t0.to_ntt()

    beta_b = p.beta_blinded
    kappa, alpha = 0, dsa.gamma_2 << 1
    while True:
        y = dsa._expand_mask_vector(rho_prime, kappa)
        w = (A_hat @ y.to_ntt()).from_ntt()
        kappa += dsa.l

        w1 = w.high_bits(alpha)
        c_tilde = dsa._h(mu + w1.bit_pack_w(dsa.gamma_2), dsa.c_tilde_bytes)
        c_hat = dsa.R.sample_in_ball(c_tilde, dsa.tau).to_ntt()

        z = y + s1_hat.scale(c_hat).from_ntt()
        if z.check_norm_bound(dsa.gamma_1 - beta_b):
            continue
        c_s2 = s2_hat.scale(c_hat).from_ntt()
        r0 = (w - c_s2).low_bits(alpha)
        if r0.check_norm_bound(dsa.gamma_2 - beta_b):
            continue
        c_t0 = t0_hat.scale(c_hat).from_ntt()
        if c_t0.check_norm_bound(dsa.gamma_2):
            continue
        h = (-c_t0).make_hint(w - c_s2 + c_t0, alpha)
        if h.sum_hint() > dsa.omega:
            continue
        return dsa._pack_sig(c_tilde, z, h)


def verify(params: ParamSet, stealth_pk: bytes, m: bytes, sig: bytes,
           ctx: bytes = b"") -> bool:
    """Stock FIPS 204 verification — no knowledge of the blinding needed."""
    return params.dsa.verify(stealth_pk, m, sig, ctx=ctx)


# --------------------------------------------------------------------------
# Proof of possession: show control of a stealth address, no transaction
# --------------------------------------------------------------------------
def prove_possession(meta_priv: MetaSecret, stealth_pk: bytes, t0,
                     ss: bytes, challenge: bytes,
                     deterministic: bool = False) -> bytes:
    from .encoding import stealth_address
    ctx = POP_CTX + stealth_address(stealth_pk)
    return sign_blinded(meta_priv, stealth_pk, t0, ss, challenge, ctx=ctx,
                        deterministic=deterministic)


def verify_possession(params: ParamSet, address: bytes, stealth_pk: bytes,
                      challenge: bytes, proof: bytes) -> bool:
    from .encoding import stealth_address
    if stealth_address(stealth_pk) != address:
        return False
    return params.dsa.verify(stealth_pk, challenge, proof,
                             ctx=POP_CTX + address)
