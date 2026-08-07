"""Parameter sets for the PQ stealth address scheme.

Each set pairs an ML-KEM instance (FIPS 203, key exchange / viewing keys)
with an ML-DSA instance (FIPS 204, blinded spending keys) at a matching
NIST security level. ML-KEM-768 + ML-DSA-65 is the default.
"""

from dataclasses import dataclass, field

from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024
from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87

# ML-DSA modulus, shared by every parameter set (FIPS 204)
Q = 8380417
Q_BITS = 23  # ceil(log2(Q))
N = 256      # ring degree
D_ROUND = 13  # Power2Round dropped bits

META_ADDRESS_VERSION = 0x01


@dataclass(frozen=True)
class ParamSet:
    name: str
    kem: object          # kyber_py ML_KEM instance
    dsa: object          # dilithium_py ML_DSA instance
    kem_ek_bytes: int
    kem_ct_bytes: int
    view_tag_bytes: int = 1

    @property
    def t_bytes(self) -> int:
        """Full-precision t: k polynomials, 23-bit coefficients."""
        return self.dsa.k * N * Q_BITS // 8

    @property
    def meta_address_bytes(self) -> int:
        return 1 + 32 + self.t_bytes + self.kem_ek_bytes

    @property
    def beta_blinded(self) -> int:
        """Signer-side rejection bound for the blinded key:
        ||c*(s1+s')||_inf <= tau * 2*eta (twice the standard beta)."""
        return self.dsa.tau * 2 * self.dsa.eta


PARAM_SETS = {
    "ML-KEM-512+ML-DSA-44": ParamSet(
        "ML-KEM-512+ML-DSA-44", ML_KEM_512, ML_DSA_44, 800, 768),
    "ML-KEM-768+ML-DSA-65": ParamSet(
        "ML-KEM-768+ML-DSA-65", ML_KEM_768, ML_DSA_65, 1184, 1088),
    "ML-KEM-1024+ML-DSA-87": ParamSet(
        "ML-KEM-1024+ML-DSA-87", ML_KEM_1024, ML_DSA_87, 1568, 1568),
}

DEFAULT = PARAM_SETS["ML-KEM-768+ML-DSA-65"]
