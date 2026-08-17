"""Serialization: meta-addresses and Ethereum EOA addresses.

The meta-address carries the compressed secp256k1 spending key and the
ML-KEM encapsulation (viewing) key, behind a version byte. Layout:

    meta_address = version(1) || spend_pub(33, compressed) || kem_ek

The stealth address follows the standard EOA rule that is keccak256 of the
64-byte uncompressed public key, last 20 bytes, so the derived key spends
with any conformant wallet, no special address scheme.
"""

from coincurve import PublicKey

# reuse the ML-DSA scheme's keccak; the address rule below is EOA-specific
from ..encoding import keccak256
from .params import COMPRESSED_PUBKEY_BYTES, META_ADDRESS_VERSION, ClassicalParamSet


def eth_address(pubkey: PublicKey) -> bytes:
    """Ethereum EOA address: keccak256 of the uncompressed pubkey (minus the
    0x04 prefix), last 20 bytes."""
    uncompressed = pubkey.format(compressed=False)  # 65 bytes: 0x04 || X || Y
    return keccak256(uncompressed[1:])[12:]


def encode_meta_address(spend_pub: bytes, kem_ek: bytes,
                        params: ClassicalParamSet) -> bytes:
    assert len(spend_pub) == COMPRESSED_PUBKEY_BYTES
    assert len(kem_ek) == params.kem_ek_bytes
    out = bytes([META_ADDRESS_VERSION]) + spend_pub + kem_ek
    assert len(out) == params.meta_address_bytes
    return out


def decode_meta_address(data: bytes,
                        params: ClassicalParamSet) -> tuple[bytes, bytes]:
    if len(data) != params.meta_address_bytes:
        raise ValueError(
            f"meta-address must be {params.meta_address_bytes} bytes, "
            f"got {len(data)}")
    if data[0] != META_ADDRESS_VERSION:
        raise ValueError(f"unsupported meta-address version {data[0]:#x}")
    spend_pub = data[1:1 + COMPRESSED_PUBKEY_BYTES]
    kem_ek = data[1 + COMPRESSED_PUBKEY_BYTES:]
    return spend_pub, kem_ek
