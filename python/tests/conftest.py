import pytest

from pq_stealth import gen_meta_address, send, DEFAULT


@pytest.fixture(scope="session")
def recipient():
    """One deterministic recipient shared across the session (keygen and
    the blinded algebra are the slow parts of pure-Python ML-DSA)."""
    return gen_meta_address(DEFAULT, zeta=b"\x01" * 32,
                            kem_d=b"\x02" * 32, kem_z=b"\x03" * 32)


@pytest.fixture(scope="session")
def announcement(recipient):
    meta_pub, _ = recipient
    return send(meta_pub, encaps_m=b"\x04" * 32)
