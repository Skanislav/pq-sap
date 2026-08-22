# POC: (v, r, s) as pointers — ABI-compatible PQ signatures

Prototype of the "re-interpret the 65-byte ECDSA tuple" hotfix (Circle, Aug 2026 PQ call).
Code: `docs/pointer-sig-poc/PointerSig.sol` (→ `ETHDILITHIUM/src/`), tests: `docs/pointer-sig-poc/PointerSig.t.sol` (→ `ETHDILITHIUM/test/`). `ETHDILITHIUM/` is a gitignored clone of ZKNoxHQ/ETHDILITHIUM; copy the two files in to run.

## Encoding

| field | classic | `v = 0x50` (pq) | `v = 0x51` (hybrid) |
|---|---|---|---|
| `v` | 27 / 28 | version | version |
| `r` | curve scalar | index into **key table** (ML-DSA pk) | index into key table (entry binds EOA + ML-DSA pk) |
| `s` | curve scalar | index into **signature table** | index of blob `abi.encode(ecdsaSig, pqSig)` |

`PointerSigRegistry.recover(digest, v, r, s) → address` is a drop-in for `ecrecover`.
Consumers keep their `(v, r, s)` ABI; `PointerSigVault.withdrawWithSig` is the example — one call site changed.

- Key table: `registerKey(expandedPk)` stores the ML-DSA-44 key via SSTORE2; the entry's address is `keccak256(pk)[12:]` (pure PQ) and `msg.sender` (hybrid binding).
- Signature table: `publishSignature(bytes)` — anyone can publish; a blob only has effect if it verifies against the digest at use time, so replay across digests fails (tested).
- Verification: ZKNOX `ZKNOX_ethdilithium.verify(pk, digest, sig)` (ERC-7913 interface, Dilithium2 / ETH-keccak profile).

## Measured (forge, default profile)

| op | gas |
|---|---|
| classic withdraw (unchanged path) | ~110k (whole test) |
| `publishSignature` (2420-byte ML-DSA sig, SSTORE2) | ~566k |
| `withdrawWithSig` pq (lookup + ML-DSA verify) | ~4.9M |
| hybrid (ECDSA + ML-DSA) | ~ same + ecrecover |

## Caveats this POC does not solve

- Two transactions per PQ spend (publish sig, then use it) unless a relayer/4337 bundler batches them; the `s` index is predictable (`signatureCount()`) so batching is feasible.
- Table indices are global and monotonic; production would scope keys per account and allow inline signature blobs (e.g. `v=0x52`, `s` = calldata offset) to skip storage.
- Verifier is the level-2 Dilithium2 profile, not ML-DSA-65; ~22 kB key storage per registration.
- `v` values 0/1 (EIP-2098 yParity) are untouched; 0x50/0x51 are arbitrary POC constants.

## Run

```
cd ETHDILITHIUM && python3 -m venv pythonref/myenv && pythonref/myenv/bin/pip install -r pythonref/requirements.txt
forge test --match-contract PointerSigTest -vv
```
