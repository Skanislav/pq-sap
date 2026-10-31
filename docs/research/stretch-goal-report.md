# Stretch goal closed — ERC-4337 spending with post-quantum key exchange and a zero-knowledge ownership proof

*2026-10-29. Closes the cohort proposal's second stretch goal: "measure the
speed, gas costs and end-to-end implementation of a stealth-address protocol
using ERC-4337 with post-quantum key exchange and a zero-knowledge ownership
proof, for cheaper spending during the transition". Every figure below is
measured on a committed harness or replayed from a committed fixture; where a
number is modelled or is a protocol proposal that is said in the row.*

Companion material: [cost report](cost-report.md) (all L1/L2 and scan costs,
provenance per row), [C13-in-circuit experiment](zk-sphincs-frames.md)
(gas breakdown, live frames run), [deployment/native-key experiments](prefix-deploy-native-keys.md)
(where the ML-DSA verify gas goes), [ML-DSA-44 committed-key profile](../ml-dsa-commit-profile.md)
(the profile route), [spending research map](../SPENDING_RESEARCH.md) (route
table), [D-020](../DECISIONS.md) (frame transactions as target),
[D-023](../DECISIONS.md) (C13 in-circuit), [D-025](../DECISIONS.md) (browser
preimage proof), [D-027](../DECISIONS.md) (ML-DSA-44 profile),
[D-031](../DECISIONS.md) (gas-exhaustion semantics).

## 0. Why this was a stretch goal, and why it is "done" now

The proposal split the work deliberately: the ERC's subject is the ML-KEM key
exchange and sender-computable address derivation (D-024), and every
protocol-dependent part — how a post-quantum key authorizes a transfer — was
listed as optional. That was the right call at proposal time and it is still
the right call: the spend side is gated on which PQ signature scheme Ethereum
adopts and on EIP-8141 shipping, neither of which this repository controls.

What changed is not the scope, it is the evidence. All four things the stretch
goal asked to *measure* now exist:

| Asked for | Status |
| --- | --- |
| Speed | scan throughput, blinded-signing latency, proving time, all measured (§2) |
| Gas costs | announce, deploy, verify, whole-spend, per route (§3) |
| End-to-end implementation | receive → scan → spend, on a real chain, twice: ERC-4337 on Sepolia and a frame transaction on the frames testnet (§4) |
| Zero-knowledge ownership proof | two statements implemented and proven client-side, one in a browser (§4) |
| "Cheaper spending during the transition" | measured, and the answer is nuanced — §5 |

So the item is closed as **delivered**, not as **required**. Nothing in the ERC
conformance package depends on it: a wallet that only implements receive/scan
never touches any code in this report.

## 1. What "the stretch goal" decomposed into

Three separable claims hide in one sentence. Keeping them apart is what makes
the measurements interpretable.

1. **ERC-4337 can carry a post-quantum stealth spend at all.** The stealth
   address must be an account whose validator is a PQ verifier, and the address
   the sender computes must equal the address that actually gets deployed and
   spent from.
2. **A zero-knowledge proof can replace the signature**, so a spend does not
   reveal the recipient's key.
3. **Either route is cheaper than the alternatives**, during the transition
   period before protocol-native PQ signatures exist.

(1) is answered yes, twice, with two different account models. (2) is answered
yes, with a caveat that dominates the result: the proof backend that is cheap
enough to ship today is not post-quantum sound. (3) is answered "cheaper than
ML-DSA on the EVM, not cheaper than a hash-based signature" — the ZK route buys
unlinkability at a gas premium, and the genuinely cheap spend is a different
route entirely.

## 2. Speed

All client-side figures on Apple M1 Max (10 cores, 32 GB), Python 3.12.1,
liboqs 0.16.0, best-of-3 (`python/benchmarks/*.json`); the native row is the
paper's Rust harness rebuilt locally.

| Operation | Measurement | Source |
| --- | --- | --- |
| Scan, Python + liboqs ML-KEM-768 | **44.31 µs**/announcement fitted slope, 2.5k→160k announcements, R² = 0.99923 | `registry_curve_20260802.json` |
| Scan, DKSAP baseline (libsecp256k1) | 27.50 µs/announcement fitted slope, R² = 0.99949 | same file |
| Scan, decaps + view-tag loop only | ~19 µs/announcement (the `1/256` full derivations excluded) | `python/benchmarks/README.md` |
| Scan, native Rust (`0x3327/pq-sap`, Kyber768) | **22.6 µs**/announcement at 80k (1,809 ms / 80,000) | `python/benchmarks/README.md` table |
| Scan, 1M announcements, projected from the Python slope | ~44 s single-core | arithmetic |
| Sender: `send` (encaps + derive) | 9.8 ms median / 9.5 ms best | `op_results.json` |
| Recipient: scan hit (decaps + tag + derive) | 10.7 ms median | same |
| Blinded ML-DSA-65 signing, pure Python | 116 ms median / 21.6 ms best | same |
| Blinded signing rejection rounds, L3 | 24.8 mean (stock 5.5), max seen 176 | `param_sweep_20260728.json` |
| UltraHonk prove, preimage statement, bb.js WASM | **0.65–1.3 s**, witness 42–61 ms, in a web worker | D-025 |
| UltraHonk prove, C13 statement, native | 50–56 s, peak 8.4–10.9 GB, proof 11,456 B | D-023 |

Two corrections to earlier prose, both from the committed data:

- The native scan figure is **22.6 µs** as arithmetic on the committed 80k row
  (1,809 ms / 80,000). The 23.8 µs quoted in the cost report and in the
  proposal text is from an earlier native run and does not reproduce from the
  table we keep. Either way the conclusion is unchanged and modest: native
  lattice scanning is *moderately faster* than DKSAP (22.6 vs 27.5–27.9 µs),
  not the paper's 3× headline, which was measured against Curvy. The
  Python reference client is 1.61× *slower* than DKSAP, because it pays ~N/256
  full derivations in interpreted code; that is a binding choice for wallets,
  not a property of the scheme.
- Pure Python is the executable spec, not a scanner: 4.2 ms/decaps, ~150×
  liboqs. Vector generation and tests are unaffected.

The one real client-side slowdown introduced by the scheme is **blinded
signing**: widening both secret vectors to `2η` shrinks the acceptance region
and costs ~4.5× ML-DSA's rejection rounds at L3. The penalty is not monotone in
the security level — η is 2/4/2 across ML-DSA-44/65/87, so the default L3 set
pays the most (24.8 rounds vs L5's 15.3 and L1's 14.4). A tighter probabilistic
norm bound than worst-case `2η` would recover most of it.

## 3. Gas

### 3.1 Announcement (the recurring path)

| Item | Gas | Regime / provenance |
| --- | --- | --- |
| PQ announcement on the canonical announcer | **67,580 measured** | Sepolia fork, `e2e-sepolia-fork.test.ts`; EIP-7623 calldata floor binds (standard cost 52,446) |
| Same, data-cost model | 67,550 | `onchain_cost.py` with scheme ID `2`; 30 gas below the measurement — see §6 |
| DKSAP announcement (33-byte point) | 27,342 **modelled**, not measured | `onchain_cost.py`, standard regime |
| Ratio, L1 | **2.5×** | arithmetic on the two rows above |
| `StealthKeyExchange.announce` wrapper overhead | **2,065** (~3% of the floor) | `test_announce_overhead_gas`, forge |
| Marginal L1 data cost, calldata regime | ~$1.35 | dated anchors ETH $3,200, L1 8 gwei (2026-07-28) |
| Marginal L1 data cost, EIP-4844 blob regime | **~$0.0042** | same anchors, blob 1 gwei; ~320× cut vs calldata |

The announcement is the only cost a recipient's counterparties impose on
everyone, and it is priced as bytes, not compute, since Pectra. That is why
the L2 blob row, not any EVM optimization, is the answer to the data footprint.

### 3.2 Spend (the one-shot path, per route)

Measured on forge/anvil 1.4.1, solc 0.8.30, `evm_version prague`, unless noted.
Full table with per-route caveats: [cost report §5](cost-report.md).

| Route | Verification gas | Setup gas | Notes |
| --- | --- | --- | --- |
| ECDSA (classical hybrid) | 21,000 | — | tx-level; quantum-vulnerable ownership |
| Direct SPHINCS-C13 (ERC-7913) | **188,092** | verifier deploy 310,750 | hash-based soundness; **key revealed at spend** |
| Same, commit form | 196,973 | account deploy 620,894 | commitment opens on spend |
| ML-DSA-44 committed key (D-027) | 14,966,788 internal / 15,038,028 tx | key setup 10.8–11.8 M + account 704,195 | trusted registrar on key setup |
| ML-DSA ERC-7913, blinded sig | 14,911,249 → **13,678,091** with key-setup NTT | PKContract 5.32–7.31 M, account 620,750 | verifier is level-2 Dilithium2, not ML-DSA-65 |
| Preimage ZK, forge | **2,942,272** execFrame | account deploy 37,001 in-frame | UltraHonk, not PQ-sound |
| Preimage ZK, live frames testnet | **3,544,107** proof verify + transfer | account deploy 37,001 in-frame | total billed 8,576,431 incl. state |
| C13-in-ZK, live frames testnet | 4,174,008 proof verify + transfer | account deploy 37,001 | total billed 9,249,124 |
| EIP-8164 native key | 50,000 **proposed** | +37.5 k authorization | Draft, no client implementation |

### 3.3 Where the ML-DSA gas actually goes

Profiled step by step at `df999ed` (`DilithiumProfile.t.sol`) — this is the
number that decides whether an EVM verifier is worth optimizing:

| Step | Gas | Share |
| --- | --- | --- |
| SHAKE256 in Solidity (SampleInBall 0.94 M + final `mu`/`c̃` hashes 4.05 M) | ≈5.0 M | 34% |
| `dilithiumCore2` (`expandMat`, NTT(z)×4, `A·z − c·t1`, invNTT, hints) | 5.69 M | 40% |
| key-dependent `<< d` + `nttFw(t1)` (moved to setup: −8%) | 1.41 M | 10% |
| unpack/norm checks, NTT(c), signature slicing | 2.24 M | 14% |

The 8.18 M figure that appears in older text was measured on an earlier
upstream revision and does not reproduce at `df999ed`; the 1.8× "regression"
attributed to a per-verify `NTT(t1·2^d)` was an inference and is wrong (that
step is 10%, not 45%). The largest single lever is replacing SHAKE with
`KECCAK256` — which is exactly what the 4.9 M `ZKNOX_ethdilithium` variant does,
and exactly why its keys are no longer ML-DSA keys.

## 4. End-to-end

Two independent end-to-end runs, two account models. Both start from the same
receive/scan layer, which is the point: the key exchange is genuinely
independent of who authorizes the spend.

### 4.1 ERC-4337 on Sepolia (real deployed contracts)

Stealth address = counterfactual address of a ZKNOX `mldsa_k1` account
(ECDSA secp256k1 **AND** ML-DSA-44/level-2), factory `0xF451…8C2e`, verifier
`0x092c…21ef`, EntryPoint v0.7 `0x0000…da032` — all already deployed, reused
as-is from `ethereum/kohaku`. Nothing PQ-specific was deployed for this.

- Receive: announce on the canonical announcer, fund the counterfactual
  address. Scan: decapsulate, view tag, re-derive — match.
- Spend: `createAccount` (~710 k gas), then a self-bundled `handleOps`
  userOp whose validation runs the on-chain lattice verifier (~8.35 M gas
  whole-transaction).
- **Gasless variant, live:** Pimlico `pm_sponsorUserOperation` accepted the
  estimation dummy signature and sponsored ~9.3 M gas of on-chain verification
  with no sponsorship policy — tx
  [`0x4cde53ee…d948f4`](https://sepolia.etherscan.io/tx/0x4cde53eef9027514cbf181f2f0baf0980dc49cd4af28cdc53412f986bad948f4).
  This also removes the funding-account privacy leak.
- Offline determinism: the whole path replays against recorded Sepolia state
  (`npm run e2e:fork`), including the on-chain `getUserOpHash` cross-check for
  both the self-bundled and the paymaster forms.

**Honest limit.** That account is *hybrid*: the userOp must also carry a valid
ECDSA signature. A PQ-only variant exists and passes (`e2e-fork-pq-only`:
deploy our own factory instance with the ML-DSA verifier in **both** validator
slots, fork Sepolia, spend with the blinded key signing both — no ECDSA in the
authorization), but it is not the deployed factory. So on the real Sepolia
infrastructure, ownership is not yet post-quantum only.

### 4.2 Frame transaction on the frames testnet (EIP-8141, PQ-only)

Stealth address = CREATE2 `Stealth8141ZkAccount` of a 32-byte commitment; one
`0x06` transaction does everything.

| Step | Result |
| --- | --- |
| receive: pay + announce in one frame tx | 295,489 gas |
| spend: `[VERIFY(sponsor), DEFAULT(createAccount), DEFAULT(executeFrame)]` | status 1, proof verify + transfer 3,544,107 exec, total billed 8,576,431 |
| proof | UltraHonk, 2 keccak calls, 40,626 gates, 8,768 B, proved **in the browser** (bb.js WASM, 0.65–1.3 s, web worker) |
| authorization | none — no signature, no signer service, no key on chain |
| deployed | `PreimageHonkVerifier` + `Stealth8141ZkFactory` (`ui/public/frames-zk-deployment.json`) |

The C13 variant of the same account (proving a *signature* in-circuit instead
of the *secret*) is also live on that testnet: 6,382,753 gates, 50.4 s proving,
11,456 B proof, 4,174,008 gas. It is the stronger statement — it keeps the
signature-scheme choice — and it is the one that cannot be proven in a browser.

**Honest limits, all three material.** The verifier is 26,317 B runtime, above
EIP-170's 24,576 B; the frames testnet does not enforce 170, so the run is valid
there and **would not deploy on mainnet** without EIP-7907 (removed from
Fusaka, a Glamsterdam candidate, not final). The proof backend is
UltraHonk/BN254-KZG, i.e. classically sound only — the account stores the
verifier as a rotatable pointer precisely so the statement survives a backend
swap, but the swap must happen before a CRQC, because after one the attacker
can authorize the swap too. And the statement is *ownership by hash preimage*:
post-quantum by assumption (a 256-bit preimage), with the proof system, not the
statement, setting the security level (D-007).

## 5. "Cheaper spending during the transition" — the honest verdict

The stretch goal's motivation was cheaper spending. Measured, per-spend
on-chain cost at the same boundary:

```
ECDSA                    21,000   classical ownership, deployable today
EIP-8164 native key      50,000   proposed charge, no client implementation
SPHINCS-C13 direct      188,092   PQ-sound, reveals the key at spend
preimage ZK           3,544,107   PQ assumption, hides the key, backend not PQ-sound
C13 in ZK             4,174,008   PQ assumption, hides the key, backend not PQ-sound
ML-DSA ERC-7913      13,678,091   PQ-sound, reveals the key at spend
```

So:

- **Against ML-DSA on the EVM, the ZK route is a real win:** 3.54 M vs 13.68 M,
  ~3.9× cheaper per spend. That is the number that says "a PQ account does not
  have to cost 14 M gas". It comes from proving the *relation* a spend needs
  rather than the *signature*, which is what makes the statement small enough
  to prove on a laptop or in a browser at all.
- **It is not the cheapest PQ spend.** A direct hash-based signature verifies
  for 188 k — 19× less than the preimage proof. The ZK route is a **privacy**
  purchase: it is the only route here where a spend reveals nothing, so two
  spends by one recipient are unlinkable. Direct C13 and direct ML-DSA both
  reveal the key at spend time and link the recipient's addresses from the
  first spend.
- **The cheapest spend of all is not an EVM verification.** EIP-8164 native
  keys (50 k) or EIP-8288 aggregation (3 k/30 k per dependency, proposed
  charges) remove the verifier from the EVM entirely. That is a protocol
  change, not something a scheme ID can deliver, which is exactly why the
  proposal put spending outside the core deliverable.
- **L2 changes the ranking's relevance, not its order.** Every row above is
  execution gas, which an L2 prices at a fraction of L1; the announcement row
  (bytes) is what blobs make ~320× cheaper. Spend is a one-shot operation per
  payment; detection is the every-payment path.

Framing that survives scrutiny: *post-quantum spending during the transition
is possible today at 0.19–3.5 M gas depending on what you are willing to
reveal, versus 13.7 M for a straightforward on-chain ML-DSA verify; the
fully-private option costs a non-PQ-sound proof system until a hash-based
verifier exists.*

## 6. Corrections this exercise produced

Grounding every number against committed data surfaced three defects, all now
fixed in the living documents (the dated decision entries keep their text and
gain a correction note):

1. **The announcement model is 30 gas off, not exact.** `onchain_cost.py`
   reproduces 67,550 on today's committed vectors against the 67,580 measured
   on the Sepolia fork; the residual is the zero/nonzero byte split of the
   encoded arguments (1,113/203 modelled vs 1,114/202 measured), so the model is
   anchored to 0.04%, not to the gas. Claims of "reproduces to the gas, 0.00%
   error" are now stated as ≤0.04%. The model and its conclusion (the EIP-7623
   floor binds, PQ is 2.5× DKSAP on L1) are unchanged.
2. **The DKSAP row carried a fake measurement.** `announce_dksap` reported the
   PQ measurement (67,580) in its `measured_gas` field with `error_pct`
   −59.54, because the field was set unconditionally in `model_announce`. DKSAP
   was never measured on chain; the field is now `null`.
3. **Two native scan figures were in circulation** (22.6 µs from the committed
   80k row, 23.8 µs from an earlier run). The report and the proposal now quote
   the one that reproduces from the committed table and say so.

## 7. Reproduce

```sh
# client-side: scan slopes, EC baseline, per-op latency, rejection rounds
cd python && python benchmarks/registry_curve.py --reps 3
python benchmarks/scan_bench.py --sizes 5000,20000,80000 --reps 3
python benchmarks/op_bench.py --reps 20
python benchmarks/param_sweep.py --n 20000 --reps 5 --sign-reps 50

# on-chain model (announcement, L2, registration)
python benchmarks/onchain_cost.py --json benchmarks/onchain_results.json

# Sepolia ERC-4337: receive -> scan -> deploy -> spend, offline replay
cd ../js-client && npm run e2e:fork

# frames testnet: proof-of-secret spend (needs a funded sponsor on chain 81410)
cd ../ui && npm run e2e:frames-preimage

# contract-level gas, including the ML-DSA profile breakdown
cd ../js-client && npm run test-contracts
```

The live Sepolia gasless run is `LIVE=1 npm run e2e:sepolia-live` and requires
`PIMLICO_API_KEY`, `SEPOLIA_PRIVATE_KEY`, `SEPOLIA_RPC_URL`; it broadcasts and
spends testnet ETH.

## 8. What is not claimed

- No ML-DSA-65 on-chain verifier exists here. Every ML-DSA row is the
  **level-2 Dilithium2** profile of the deployed ZKNOX verifier; nothing
  measured transfers to ML-DSA-65, and the keccak-PRNG variant (4.9 M) is not a
  FIPS measurement.
- The ZK accounts are **not post-quantum sound** today. The statement is, the
  backend is not.
- The browser preimage route is a **demo**; the secret is derived from a seed
  in the page and never transmitted, which is appropriate for a demo and not a
  wallet design.
- The Sepolia 4337 account is **hybrid** (ECDSA required); the PQ-only variant
  runs against a locally deployed factory instance on a fork.
- Blinded signing still runs in a Python service, not in the browser
  (`ui/scripts/signer-service.mjs`). That is a real operational weakness of
  the 4337 route, stated in `ui/README.md`.
- Registration, announcement, account creation, verification, transfer, and
  total billed gas are separate rows throughout; they are not summed into one
  "cost of a stealth payment".
