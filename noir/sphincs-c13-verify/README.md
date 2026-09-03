# sphincs-c13-verify — SPHINCS- C13 verification in a Noir circuit

Proves knowledge of a valid SPHINCS- C13 signature (D-018 parameter set, keccak
tweakable hash) over a public `message` under a key that opens a public D-018
`commitment`, without revealing the key. Used by `Stealth8141ZkAccount`
(`js-client/contracts/src/frames/`) as the spend authorization carried in an
EIP-8141 frame transaction. Design and measurements:
`docs/research/zk-sphincs-frames.md`.

| | |
|---|---|
| public inputs | `message_hi, message_lo, commitment_hi, commitment_lo` (128-bit halves, in this order) |
| private | `pk_seed[16]`, `pk_root[16]`, `opener[32]`, `sig[3688]`, `chain_hint[2][93]` |
| keccak calls | 335 (same as `SPHINCs-C13Asm.sol`; WOTS chains flattened to 93 hint-driven steps per layer) |
| size | 6,382,753 UltraHonk gates (2^23), 89,111 ACIR opcodes |
| toolchain | nargo 1.0.0-beta.19, bb 4.2.0, `noir-lang/keccak256` v0.1.2 |

## Run (fixture vector)

```
python/.venv/bin/python generate_prover.py --vector raw      # re-verifies in Python, writes Prover.toml
nargo compile && nargo execute
bb prove -b target/sphincs_c13_verify.json -w target/sphincs_c13_verify.gz -t evm --write_vk -o out
bb write_solidity_verifier -k out/vk -o out/Verifier.sol   # -> copy to contracts/src/frames/zk/
```

`bb prove` needs the 2^23 BN254 CRS (512 MB, fetched from crs.aztec-labs.com on
first use into `~/.bb-crs`). Peak memory about 8.4 GB. `out/{proof,public_inputs,
vk,vk_hash}` for the fixture are tracked so `contracts/test/ZkAccount.t.sol` runs
without a prover.

## Arbitrary instance

`generate_prover.py --inputs inputs.json` where the JSON carries `pk_seed`,
`pk_root` (32-B top-aligned hex), `opener`, `message`, `sig` and optionally
`commitment`. `ui/scripts/e2e-frames-zk.ts` drives this with the upstream
`signer-c13` CLI (lfglabs-dev/SPHINCS- @ 2a40d0a) to sign a live frame tx's
`sig_hash`.

## Faithfulness

`generate_prover.py::verify_c13` is an independent Python port of the Yul
verifier; it must accept the fixture (it does, for all three vectors) before a
witness is written, and the circuit mirrors the same steps. The two soundness
checks (forced-zero FORS index, WOTS+C digit sum) are `assert`s. The chain hint is
constrained: each chain must receive exactly `7 - digit` steps and the digit sum
is asserted, so every one of the 93 steps lands in a real chain in order.
