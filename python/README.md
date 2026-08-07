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

**Warning:** value sent to these stealth addresses is unspendable on-chain
until protocol-level post-quantum signature support exists. No send-value
flow is shipped.
