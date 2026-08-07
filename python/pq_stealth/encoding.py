"""Serialization: full-precision t, meta-addresses, blinded secret keys,
and Ethereum-style addresses.

The meta-address must carry the spending key's t at FULL precision (23-bit
coefficients), not the rounded t1 of a standard ML-DSA public key: the
sender computes Power2Round(A*s' + e' + t), which is only well-defined on
the unrounded value. Layout (versioned):

    meta_address = version(1) || rho(32) || t_packed(k*256*23/8) || kem_ek

The blinded secret key (s1' = s1+s', s2' = s2+e') has infinity norm up to
2*eta and therefore does NOT fit the FIPS 204 secret-key encoding
(bit_pack_s assumes eta); pack_blinded_sk uses a widened range instead.
"""

from Crypto.Hash import keccak

from .params import ParamSet, Q, Q_BITS, N, D_ROUND, META_ADDRESS_VERSION


# --------------------------------------------------------------------------
# Generic fixed-width bit packing (little-endian bit order, as FIPS 204)
# --------------------------------------------------------------------------
def _bit_pack(values: list[int], bits: int) -> bytes:
    acc, acc_bits, out = 0, 0, bytearray()
    for v in values:
        acc |= v << acc_bits
        acc_bits += bits
        while acc_bits >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            acc_bits -= 8
    if acc_bits:
        out.append(acc & 0xFF)
    return bytes(out)


def _bit_unpack(data: bytes, bits: int, count: int) -> list[int]:
    acc, acc_bits, out = 0, 0, []
    it = iter(data)
    mask = (1 << bits) - 1
    while len(out) < count:
        while acc_bits < bits:
            acc |= next(it) << acc_bits
            acc_bits += 8
        out.append(acc & mask)
        acc >>= bits
        acc_bits -= bits
    return out


def _centered(c: int) -> int:
    """Map a mod-q coefficient to the centered representative in (-q/2, q/2]."""
    c %= Q
    return c - Q if c > Q // 2 else c


# --------------------------------------------------------------------------
# Full-precision t
# --------------------------------------------------------------------------
def pack_t(t, params: ParamSet) -> bytes:
    coeffs = [c % Q for row in t._data for c in row[0].coeffs]
    return _bit_pack(coeffs, Q_BITS)


def unpack_t(data: bytes, params: ParamSet):
    dsa = params.dsa
    coeffs = _bit_unpack(data, Q_BITS, dsa.k * N)
    polys = [dsa.R(coeffs[i * N:(i + 1) * N]) for i in range(dsa.k)]
    return dsa.M.vector(polys)


# --------------------------------------------------------------------------
# Meta-address
# --------------------------------------------------------------------------
def encode_meta_address(rho: bytes, t, kem_ek: bytes, params: ParamSet) -> bytes:
    assert len(rho) == 32 and len(kem_ek) == params.kem_ek_bytes
    out = bytes([META_ADDRESS_VERSION]) + rho + pack_t(t, params) + kem_ek
    assert len(out) == params.meta_address_bytes
    return out


def decode_meta_address(data: bytes, params: ParamSet):
    if len(data) != params.meta_address_bytes:
        raise ValueError(
            f"meta-address must be {params.meta_address_bytes} bytes, got {len(data)}")
    if data[0] != META_ADDRESS_VERSION:
        raise ValueError(f"unsupported meta-address version {data[0]:#x}")
    rho = data[1:33]
    t = unpack_t(data[33:33 + params.t_bytes], params)
    kem_ek = data[33 + params.t_bytes:]
    return rho, t, kem_ek


# --------------------------------------------------------------------------
# Blinded secret key (widened ranges; NOT the FIPS 204 sk encoding)
# --------------------------------------------------------------------------
def _range_bits(bound: int) -> int:
    return (2 * bound).bit_length()


def pack_blinded_sk(rho: bytes, s1_b, s2_b, t0, params: ParamSet) -> bytes:
    """rho || s1' || s2' (coeffs in [-2*eta, 2*eta]) || t0' (in (-2^12, 2^12])."""
    eta2 = 2 * params.dsa.eta
    sb = _range_bits(eta2)
    s_vals = [eta2 - _centered(c) for v in (s1_b, s2_b)
              for row in v._data for c in row[0].coeffs]
    t0_half = 1 << (D_ROUND - 1)
    t_vals = [t0_half - _centered(c) for row in t0._data for c in row[0].coeffs]
    return rho + _bit_pack(s_vals, sb) + _bit_pack(t_vals, D_ROUND + 1)


def unpack_blinded_sk(data: bytes, params: ParamSet):
    dsa = params.dsa
    eta2 = 2 * dsa.eta
    sb = _range_bits(eta2)
    rho, rest = data[:32], data[32:]
    n_s = (dsa.l + dsa.k) * N
    s_len = (n_s * sb + 7) // 8
    s_vals = [eta2 - v for v in _bit_unpack(rest[:s_len], sb, n_s)]
    t0_half = 1 << (D_ROUND - 1)
    t_vals = [t0_half - v
              for v in _bit_unpack(rest[s_len:], D_ROUND + 1, dsa.k * N)]

    def vec(vals, dim):
        return dsa.M.vector([dsa.R(vals[i * N:(i + 1) * N]) for i in range(dim)])

    s1_b = vec(s_vals[:dsa.l * N], dsa.l)
    s2_b = vec(s_vals[dsa.l * N:], dsa.k)
    t0 = vec(t_vals, dsa.k)
    return rho, s1_b, s2_b, t0


# --------------------------------------------------------------------------
# Addresses
# --------------------------------------------------------------------------
def keccak256(data: bytes) -> bytes:
    return keccak.new(digest_bits=256, data=data).digest()


def stealth_address(stealth_pk: bytes) -> bytes:
    """Ethereum-style address: last 20 bytes of keccak256 of the ML-DSA pk."""
    return keccak256(stealth_pk)[12:]
