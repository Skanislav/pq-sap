"""The algebraic core: additive blinding of an ML-DSA key (construction A).

    (s', e') = ExpandS(SHAKE256(ss, 64))          # both derived from the
    t' = A*s' + e' + t                            # ML-KEM shared secret ss
    (t1', t0') = Power2Round(t', d)
    stealth_pk = pack_pk(rho, t1')                # a genuine ML-DSA pk

Correctness identity: t' = A*(s1 + s') + (s2 + e'), so (s1+s', s2+e', t0')
is a working (non-standard, widened-norm) ML-DSA secret key for stealth_pk.

The fresh error term e' departs from pq-sap v2 (which reuses the
recipient's s2 across every stealth key); deriving e' alongside s' closes
that linkability vector at no cost to the sender, who never needs any
secret to compute t'.
"""

import hashlib

from .params import ParamSet, D_ROUND

BLINDING_SEED_BYTES = 64


def derive_blinding(ss: bytes, params: ParamSet):
    """Derive the blinding pair (s', e') from the KEM shared secret."""
    seed = hashlib.shake_256(ss).digest(BLINDING_SEED_BYTES)
    return params.dsa._expand_vector_from_seed(seed)


def derive_stealth_pk(rho: bytes, t, ss: bytes, params: ParamSet):
    """Compute the blinded stealth public key. Public inputs only —
    runnable by the sender, the recipient, and any viewing-key holder.

    Returns (stealth_pk_bytes, t0') — t0' is needed only for signing and
    is simply discarded by the sender.
    """
    dsa = params.dsa
    A_hat = dsa._expand_matrix_from_seed(rho)
    s_p, e_p = derive_blinding(ss, params)
    t_prime = (A_hat @ s_p.to_ntt()).from_ntt() + e_p + t
    t1, t0 = t_prime.power_2_round(D_ROUND)
    return dsa._pack_pk(rho, t1), t0
