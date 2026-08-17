# pq-stealth — executable spec

Reference implementation of the post-quantum ERC-5564 stealth address
scheme described in [`docs/TECHNICAL_SPEC.md`](../docs/TECHNICAL_SPEC.md):
ML-KEM key exchange + additive ML-DSA key blinding (construction A) with a
fresh error term per stealth key.

Pure Python (`kyber-py`, `dilithium-py`) — this is the spec and vector
generator, not a production library. The audited `liboqs` backend is used
as a cross-check verifier in the test suite.

## Setup

```sh
python -m venv venv && . venv/bin/activate
pip install -e ".[dev]"          # add .[audit] for the liboqs cross-check
```

## Run

```sh
pytest                            # 18 tests, ~3 s
python vectors/generate_vectors.py   # regenerate vectors/v0/vectors.json
                                     # (deterministic: byte-identical output)
```

## Docker

Self-contained image with the liboqs cross-check backend built in
(pinned to match `liboqs-python`):

```sh
docker build -t pq-stealth-py .
docker run --rm pq-stealth-py        # test suite (18 tests)

# conformance vectors: regenerate and confirm byte-identical
docker run --rm pq-stealth-py sh -c \
  "cp vectors/v0/vectors.json /tmp/ref.json \
   && python vectors/generate_vectors.py \
   && cmp vectors/v0/vectors.json /tmp/ref.json && echo vectors OK"
```

## Layout

| Module | Contents |
|---|---|
| `pq_stealth/params.py` | parameter sets (default ML-KEM-768 + ML-DSA-65) |
| `pq_stealth/blinding.py` | the algebraic core: `t' = A·s' + e' + t` |
| `pq_stealth/encoding.py` | meta-address / full-`t` / blinded-sk packing, keccak addresses |
| `pq_stealth/meta.py` | recipient keygen, meta-address assembly |
| `pq_stealth/sender.py` | encaps → stealth address → announcement |
| `pq_stealth/recipient.py` | scanning with view-tag fast path |
| `pq_stealth/signing.py` | blinded FIPS 204 signing, proof of possession |
| `pq_stealth/classical/` | classical-spend hybrid (secp256k1 + ML-KEM); see below |

**Warning:** value sent to these stealth addresses is unspendable on-chain
until protocol-level post-quantum signature support exists. No send-value
flow is shipped. The classical-spend hybrid below is the deployable-today
counterpart: a normal EOA output, spendable now with a plain ECDSA
transaction.

## Classical-spend hybrid (secp256k1)

An alternative construction that keeps the ML-KEM key exchange but blinds a **secp256k1** spending key, so the stealth output is a normal EOA,
**spendable today** with a plain ECDSA transaction. It reuses this package's `Announcement`, view-tag, and ERC-6538 registry rail; only the blinding
backend and the EOA address rule differ. Full write-up: [`docs/classical-spend-hybrid.md`](../docs/classical-spend-hybrid.md).

It is opt-in: the only dependency beyond the core is `coincurve` (the `bench` extra).

```sh
pip install -e ".[bench]"                     # adds coincurve (libsecp256k1)
pytest tests/test_classical_*.py              # roundtrip, negative, vectors (18 tests)
python vectors/generate_classical_vectors.py  # regenerate vectors/classical/v0
                                              # (deterministic: byte-identical output)
```

End-to-end in a few lines (send, detect, derive the EOA key, prove control):

```python
from pq_stealth.classical import (
    gen_meta_address, send, check_announcement,
    derive_stealth_privkey, eth_address,
)

meta_pub, meta_priv = gen_meta_address()                                # recipient: secp256k1 + ML-KEM keys
ann = send(meta_pub)                                                    # sender: ML-KEM encaps -> stealth EOA
pay = check_announcement(meta_pub, meta_priv.kem_dk, ann)               # recipient: scan + detect
priv = derive_stealth_privkey(meta_priv.spend_priv, pay.shared_secret)
assert eth_address(priv.public_key) == ann.stealth_address              # a plain ECDSA key controls it
```

Unlike the ML-DSA scheme above, value sent here is spendable immediately: `priv` is an ordinary secp256k1 key.

| Module | Contents |
|---|---|
| `pq_stealth/classical/params.py` | parameter sets (default secp256k1 + ML-KEM-768) |
| `pq_stealth/classical/blinding.py` | the algebraic core: `t = KDF(ss) mod n`, `P = K + t·G` |
| `pq_stealth/classical/encoding.py` | meta-address packing, EOA keccak addresses |
| `pq_stealth/classical/meta.py` | recipient keygen, meta-address assembly |
| `pq_stealth/classical/sender.py` | encaps → stealth EOA → announcement |
| `pq_stealth/classical/recipient.py` | scanning with view-tag fast path |
