# A SPHINCS- C13 spend authorized by a zero-knowledge proof, over frame transactions

*2026-09-03. Companion artifacts: `noir/sphincs-c13-verify/` (circuit +
`generate_prover.py`), `js-client/contracts/src/frames/{Stealth8141ZkAccount,
Stealth8141ZkFactory}.sol` + `frames/zk/SphincsC13HonkVerifier.sol` (bb-generated),
`js-client/contracts/test/ZkAccount.t.sol`, `ui/scripts/{deploy-frames-zk.mjs,
e2e-frames-zk.ts}`. Follows D-022 (`prefix-deploy-native-keys.md`) and D-018's open
item "remove spend-time linkability by binding the SPHINCS- key through a ZK proof".*

## 1. Question and the user's framing

Given that the direct ML-DSA verify costs 13.7–14.9 M gas and precompiles are not
the way: prove the post-quantum verification inside a circuit and spend with the
proof. The pairing-based backend (UltraHonk on BN254/KZG) is not quantum-sound,
but the *statement* is fixed, so the backend can be swapped for a hash-based one
later. The user's choice for the spike: **SPHINCS- C13 verification in-circuit**,
pairing now / STARK later with the swap designed in, measured on the frames
testnet.

## 2. What the circuit proves

Public inputs: `message` (the frame tx `sig_hash`, TXPARAM 0x08) and the D-018
`commitment = keccak256("pq-stealth/sphincs-c13/commit/v0" ‖ pk ‖ opener)`, each
as two 128-bit field elements (4 public inputs). Private: `pkSeed`, `pkRoot`,
`opener`, the 3,688-B signature, and a chain-order hint. The circuit opens the
commitment and runs the exact `SPHINCs-C13Asm.sol` verification (Verity-refined
Yul, D-018): keccak-only tweakable hash over `seed ‖ ADRS ‖ payload`, FIPS 205
uncompressed ADRS, FORS+C forced-zero and WOTS+C constant-sum as **assertions**.

Because the key is a witness, a spend reveals nothing about which recipient key
signed it: the spend-time linkability of the commit signer (every spent address
of a recipient becomes linkable once the commitment is opened on chain) is gone.
The account address is `CREATE2(factory, 0, initcode(commitment, verifier,
frameCtx))`, sender-computable from the meta-address key and the KEM shared
secret exactly as before.

**Circuit-shape decision.** WOTS+C makes the *total* chain length fixed
(`L·(w−1) − target_sum = 43·7 − 208 = 93` steps per layer) while each chain's
length is data-dependent. A naive circuit hashes 7 steps for every chain
(301 per layer, 2.3× the work). Instead the prover supplies `chain_hint[layer][93]`,
the chain each step belongs to; the circuit hashes the steps in that order with a
per-chain running position and asserts every chain received exactly `7 − digit`
steps. The digit-sum assertion guarantees `Σ(7 − digit) = 93`, so all 93 steps must
land in real chains. Result: the same 335 keccak calls as the Solidity verifier.

## 3. Measured

Toolchain: nargo 1.0.0-beta.19, bb 4.2.0 (aztec bundle), `noir-lang/keccak256`
v0.1.2, forge 1.4.1, Apple silicon laptop.

| item | value |
|---|---|
| keccak256 in UltraHonk, 64-B input, one call (incl. I/O) | 40,626 gates |
| eight chained calls | 142,162 gates → **≈ 14.5 k gates per keccak-f** |
| C13 verify circuit (335 keccak calls, 358 permutations) | **6,382,753 gates** (89,111 ACIR opcodes; 2^23 circuit) |
| proving key | 18 s, 6.7 GB |
| proof (EVM target, ZK) | 11,456 B, 4 public inputs; prove 50–56 s, peak 8.4–10.9 GB (§3b) |
| `Stealth8141ZkAccount.executeFrame` with proof, forge | 3,526,632 gas; live 4,174,008 (§3b) |
| bb Solidity verifier, 2^16 test circuit, 32 public inputs, ZK flavour | **2,989,292 gas**, runtime code **26,317 B** |
| same, no-ZK flavour | proof 7,776 B (verifier not measured: the generator emits the ZK contract regardless) |
| Python re-implementation of the verifier on the three fixture vectors | valid; 93 + 93 hint steps |

### 3b. Live run (frames testnet, chain 81410, 2026-09-03)

Deployed (`ui/scripts/deploy-frames-zk.mjs`, `ui/public/frames-zk-deployment.json`):
`ZKTranscriptLib` `0x48b90e15…2b361` (6,577 B, 10.4 M gas — bb's verifier calls it
as an *external* library, so it is a second contract to link), `HonkVerifier`
`0xF01ecC1d…5BBfb` (26,318 B, 40.9 M gas — **accepted: the frames testnet does not
enforce EIP-170's 24,576 B**), `Stealth8141ZkFactory` `0x303CB317…9826`.

`ui/scripts/e2e-frames-zk.ts`, fixture recipient, fresh ML-KEM-768 encapsulation:

| step | result |
|---|---|
| receive: pay + announce, one 0x06 tx | `0xe1df05ee…b6cdb`, 295,489 gas |
| scan: decapsulate, re-derive commitment → account | match, `0x9cF91490…ac4F7` |
| C13 sign over the tx's `sig_hash` (Rust `signer-c13`) | 3.3 s |
| witness (`nargo execute`) | 0.5 s |
| UltraHonk prove, 2^23, EVM target (proving key 17 s of it) | **50.4 s**, peak 10.9 GB, proof 11,456 B |
| spend: `[VERIFY(sponsor), DEFAULT(factory.createAccount), DEFAULT(account.executeFrame)]`, 11,908 B raw | `0x0fef8acd…2bc1e`, status 1, block 85365 |
| frame receipts | sponsor VERIFY 100 · **account deploy 37,001** · **proof verify + transfer 4,174,008** |
| total gas billed (execution + state) | 9,249,124 |

Two lessons from the first attempt (`0x946ad48e…c0afd`, status 0): a 4 M
execution-gas spend frame died at 3,938,060 = exactly 63/64 of its limit, i.e.
out of gas inside the verifier staticcall — forge's 3.53 M undercounts what this
chain charges for copying the 11 KB proof (SIGDATACOPY + ABI return), two cold
contracts, and the EIP-8037 schedule; 9 M is comfortable and the total stays far
under the 16.78 M cap. And the account deploy fits *inside* the spend transaction
(3,099 B runtime, 37 k execution gas), unlike the ML-DSA route's 43 M type-2
deploy — the whole first spend is one frame transaction again.

Two consequences stand out before any testnet number:

- **The proof is cheaper than ML-DSA and dearer than SPHINCS- itself.** ~3 M for
  the Honk verify versus 13.7 M for ML-DSA on the EVM, but the direct C13 verify is
  188 k. For SPHINCS- the ZK route is a *privacy* purchase (unlinkability), not a
  cost cut; for ML-DSA it would be a cost cut, but that is the MLWE-ownership
  statement of D-008, not this circuit.
- **The bb verifier does not fit EIP-170.** 26.3 kB runtime against the 24,576-B
  limit. Mainnet needs EIP-7907 (removed from Fusaka, candidate for Glamsterdam,
  not final). The frames testnet runs Glamsterdam+Bogota; whether it enforces 170
  is exactly what the deploy step tests.

## 4. Backend question: pairing now, STARK later

The account holds the verifier as a **rotatable pointer** (`setVerifier`, callable
only by the account itself, i.e. through an authorized `executeFrame` covered by
`sig_hash`). The statement and its public-input layout are the contract; the
backend is replaceable. What that does and does not buy:

- Soundness of KZG/BN254 rests on discrete log. A CRQC forges proofs, so a Honk
  account is exactly as quantum-safe at rest as an ECDSA account: not at all. The
  swap must happen **before** a CRQC; after one, the attacker can authorize the
  swap too. Same posture as EIP-7702 accounts today, stated plainly.
- A hash-based backend (FRI/STARK, or a binary-field system) is plausibly PQ-sound
  and transparent, but its EVM verifier is the cost: hash-heavy, typically 1–5 M+
  gas with keccak Merkle paths and proofs of tens to hundreds of kB; with D-015's
  standard-hash policy there is no Poseidon shortcut. The verifier contract must
  also fit 170, which today means a wrapped/recursive proof.
- **Wrapping does not transfer post-quantum soundness.** A PQ inner proof folded
  into a pairing-based outer proof (the SP1/Groth16 "EVM wrapper" pattern) is only
  as PQ as the outer proof. The on-chain verifier is the trust root.

**Flock** (succinctlabs/flock, asked about 2026-09-03): "a prover and verifier for
R1CS-over-GF(2) statements, built on a zerocheck + lincheck PIOP with a multilinear
PCS (Ligerito) over the binary field F₂₁₂₈" — hash-based, transparent, plausibly
PQ-sound, aimed at "batched hash statements (BLAKE3 and SHA-256 compressions)" with
"a recursion tower that folds proofs into proofs"; 305 k SHA-256/s on a 32-core
Threadripper; Rust API only; research stage; **no keccak encoder and no EVM
verifier**. For this statement it would need a Keccak-f R1CS-over-GF(2) encoder
(Keccak is Boolean-native: 38,400 ANDs per permutation, 358 permutations ≈ 14 M
AND constraints, well inside its throughput) and, for on-chain use, either an EVM
Ligerito verifier (none exists; proofs are large) or a wrapper — which brings back
the paragraph above. Verdict: the right *shape* of prover for a hash-based
migration target, not something that can be plugged into the account today; watch
it alongside EIP-8288 (protocol-level STARK aggregation).

## 5. Where this leaves the routes

| route | per-spend on-chain | linkability | PQ-sound at rest | status |
|---|---|---|---|---|
| direct C13 verify (D-018) | 188 k | key revealed on spend | yes (hash-based) | live |
| C13 in-circuit, UltraHonk (this) | ≈ 3 M + call | none | **no** (until backend swap) | spike |
| C13 in-circuit, hash-based backend | 1–5 M+, verifier TBD | none | yes | no EVM verifier yet |
| ML-DSA direct (D-022) | 13.7 M | key revealed | yes (lattice) | live |
| EIP-8164 native key (D-022) | 50 k | key in code at receive | yes | Draft, no client |

## 6. Open

- EIP-170 on the frames testnet and on mainnet (EIP-7907).
- Prover on a phone/browser: 6.4 M gates, 2^23, ~7 GB proving key — laptop-class
  today. The no-ZK flavour and a recursion step are the obvious levers.
- Grindable `R` (upstream's own review note) is unchanged by proving; the circuit
  inherits the C13 security posture as is.
- Anonymity set: every ZK account shares one verifier and one commitment domain,
  so the set is "all ZK SPHINCS- stealth accounts", the same shape as D-022's
  "all 8164 accounts" remark.
