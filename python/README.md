# pq-stealth — executable spec

Python is the byte-level source of truth for the
[key-exchange technical reference](../docs/TECHNICAL_SPEC.md).
Start with `pq_stealth/commit.py`: ML-KEM viewing keys, commitment-format
meta-addresses, sender derivation, and viewing-key scanning (D-024/D-025).
`pq_stealth/__init__.py` exposes the separate Construction A API; it is not
the commitment-format entry point.

Construction A's ML-DSA blinding/signing modules, classical hybrid, and spend
helpers are supporting implementations. See [ERC evidence](../docs/ERC_EVIDENCE.md)
and [spending research](../docs/SPENDING_RESEARCH.md) for their boundaries.
The Python library is an executable reference, not a hardened production signer.

## Setup

```sh
python -m venv venv && . venv/bin/activate
pip install -e ".[dev]"          # add .[audit] for the liboqs cross-check
```

## Run

```sh
pytest                            # full reference suite
pytest tests/test_commit.py        # commitment format / scan behavior
pytest tests/test_profiles.py      # explicit profiles, ML-DSA-44 key commitment, authorization
python vectors/generate_mldsa44_commit_vectors.py --outdir /tmp/pq-mldsa44
cmp vectors/v0/mldsa44_commit_vectors.json /tmp/pq-mldsa44/mldsa44_commit_vectors.json
python vectors/generate_commit_vectors.py --outdir /tmp/pq-commit-vectors
cmp vectors/v0/commit_vectors.json /tmp/pq-commit-vectors/commit_vectors.json
python vectors/generate_vectors.py   # regenerate vectors/v0/vectors.json
                                     # (deterministic: byte-identical output)
```

## Docker

Self-contained image with the liboqs cross-check backend built in
(pinned to match `liboqs-python`):

```sh
docker build -t pq-stealth-py .
docker run --rm pq-stealth-py        # full reference test suite

# conformance vectors: regenerate and confirm byte-identical
docker run --rm pq-stealth-py sh -c \
  "cp vectors/v0/vectors.json /tmp/ref.json \
   && python vectors/generate_vectors.py \
   && cmp vectors/v0/vectors.json /tmp/ref.json && echo vectors OK"
```

## Layout

| Module | Contents |
|---|---|
| `pq_stealth/commit.py` | commitment-format key exchange and address derivation (start here) |
| `pq_stealth/profiles.py` | explicit account profiles over `0x02`; ML-DSA-44 key commitment and `pk ‖ opener ‖ sig` authorization (D-027) |
| `pq_stealth/params.py` | parameter sets (default ML-KEM-768 + ML-DSA-65) |
| `pq_stealth/blinding.py` | the algebraic core: `t' = A·s' + e' + t` |
| `pq_stealth/encoding.py` | meta-address / full-`t` / blinded-sk packing, keccak addresses |
| `pq_stealth/meta.py` | recipient keygen, meta-address assembly |
| `pq_stealth/sender.py` | encaps → stealth address → announcement |
| `pq_stealth/recipient.py` | scanning with view-tag fast path |
| `pq_stealth/signing.py` | blinded FIPS 204 signing, proof of possession |
| `pq_stealth/classical/` | classical-spend hybrid (secp256k1 + ML-KEM); see below |

Account spendability depends on the selected deployment and verifier. The
reference functions derive announcements/addresses; transaction execution is
handled by the separate account integrations. A raw Construction A ML-DSA
public-key hash is not an ECDSA-controlled EOA.

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
