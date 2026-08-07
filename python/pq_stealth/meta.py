"""Recipient key generation and meta-address assembly."""

import os
from dataclasses import dataclass

from .params import ParamSet, DEFAULT
from .encoding import encode_meta_address


@dataclass(frozen=True)
class MetaPublic:
    """Published spending/viewing material (via ERC-6538 registry or ENS)."""
    rho: bytes      # ML-DSA matrix seed
    t: object       # full-precision t = A*s1 + s2 (Vector, k polys)
    kem_ek: bytes   # ML-KEM encapsulation (viewing) key
    params: ParamSet

    def encode(self) -> bytes:
        return encode_meta_address(self.rho, self.t, self.kem_ek, self.params)


@dataclass(frozen=True)
class MetaSecret:
    s1: object      # ML-DSA secret vector (l polys, eta-bounded)
    s2: object      # ML-DSA error vector (k polys, eta-bounded)
    kem_dk: bytes   # ML-KEM decapsulation key = the VIEWING key
    params: ParamSet


def gen_meta_address(params: ParamSet = DEFAULT,
                     zeta: bytes | None = None,
                     kem_d: bytes | None = None,
                     kem_z: bytes | None = None) -> tuple[MetaPublic, MetaSecret]:
    """Generate a recipient meta-address. Pass zeta/kem_d/kem_z (32 bytes
    each) for deterministic generation (test vectors); omit for random.

    The spending key mirrors FIPS 204 Algorithm 6 key expansion but keeps
    t at full precision instead of rounding to t1 — the sender's
    Power2Round(A*s' + e' + t) needs the unrounded value.
    """
    dsa = params.dsa
    zeta = zeta if zeta is not None else os.urandom(32)
    seed = dsa._h(zeta + bytes([dsa.k]) + bytes([dsa.l]), 128)
    rho, rho_prime = seed[:32], seed[32:96]

    A_hat = dsa._expand_matrix_from_seed(rho)
    s1, s2 = dsa._expand_vector_from_seed(rho_prime)
    t = (A_hat @ s1.to_ntt()).from_ntt() + s2

    if kem_d is not None or kem_z is not None:
        kem_ek, kem_dk = params.kem._keygen_internal(kem_d, kem_z)
    else:
        kem_ek, kem_dk = params.kem.keygen()

    return (MetaPublic(rho, t, kem_ek, params),
            MetaSecret(s1, s2, kem_dk, params))
