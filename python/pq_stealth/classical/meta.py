"""Recipient key generation and meta-address assembly."""

from dataclasses import dataclass

from coincurve import PrivateKey

from .encoding import encode_meta_address
from .params import DEFAULT, ClassicalParamSet


@dataclass(frozen=True)
class MetaPublic:
    """Published spending/viewing material (via ERC-6538 registry or ENS)."""
    spend_pub: bytes            # compressed secp256k1 spending pubkey (33 bytes)
    kem_ek: bytes               # ML-KEM encapsulation (viewing) key
    params: ClassicalParamSet

    def encode(self) -> bytes:
        return encode_meta_address(self.spend_pub, self.kem_ek, self.params)


@dataclass(frozen=True)
class MetaSecret:
    spend_priv: bytes           # secp256k1 spending secret
    kem_dk: bytes               # ML-KEM decapsulation key = the VIEWING key
    params: ClassicalParamSet


def gen_meta_address(params: ClassicalParamSet = DEFAULT,
                     spend_seed: bytes | None = None,
                     kem_d: bytes | None = None,
                     kem_z: bytes | None = None) -> tuple[MetaPublic, MetaSecret]:
    """Generate a recipient meta-address. Pass spend_seed (32 bytes) and
    kem_d/kem_z (32 bytes each) for deterministic generation (test
    vectors); omit for random."""
    spend = PrivateKey(spend_seed) if spend_seed is not None else PrivateKey()
    spend_pub = spend.public_key.format(compressed=True)

    if kem_d is not None or kem_z is not None:
        kem_ek, kem_dk = params.kem._keygen_internal(kem_d, kem_z)
    else:
        kem_ek, kem_dk = params.kem.keygen()

    return (MetaPublic(spend_pub, kem_ek, params),
            MetaSecret(spend.secret, kem_dk, params))
