"""Parameter set for the classical-spend hybrid.

An ML-KEM instance (FIPS 203) supplies the key exchange / viewing keys,
exactly as in the ML-DSA scheme; the spending key is a secp256k1 keypair,
so there is no lattice signature parameter to pair. ML-KEM-768 is the
default, matching the ML-DSA scheme's default viewing key.
"""

from dataclasses import dataclass

from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024

# secp256k1 group order (SEC 2). The tweak scalar lives in [1, N_CURVE - 1].
N_CURVE = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

COMPRESSED_PUBKEY_BYTES = 33

META_ADDRESS_VERSION = 0x01


@dataclass(frozen=True)
class ClassicalParamSet:
    name: str
    kem: object          # kyber_py ML_KEM instance
    kem_ek_bytes: int    # ML-KEM encapsulation (viewing) key length
    kem_ct_bytes: int    # ML-KEM ciphertext length
    view_tag_bytes: int = 1

    @property
    def meta_address_bytes(self) -> int:
        return 1 + COMPRESSED_PUBKEY_BYTES + self.kem_ek_bytes


PARAM_SETS = {
    "secp256k1+ML-KEM-512": ClassicalParamSet("secp256k1+ML-KEM-512", ML_KEM_512, 800, 768),
    "secp256k1+ML-KEM-768": ClassicalParamSet("secp256k1+ML-KEM-768", ML_KEM_768, 1184, 1088),
    "secp256k1+ML-KEM-1024": ClassicalParamSet("secp256k1+ML-KEM-1024", ML_KEM_1024, 1568, 1568),
}

DEFAULT = PARAM_SETS["secp256k1+ML-KEM-768"]
