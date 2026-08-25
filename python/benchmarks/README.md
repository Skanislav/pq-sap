# Scan benchmarks

Methodology per ePrint 2025/112's own harness
(`pq-sap/src/benchmarks/pq_sap_benchmark.rs`): a registry of N announcements
addressed to random recipients (1-byte view tags → ~1/256 false-positive
rate), scanned by one recipient — decapsulate, check tag, run the full
stealth-key derivation only on tag match. Best-of-3 (min), single-threaded.

**Run conditions.** Re-run 2026-07-28 on Apple M1 Max (10 cores, 32 GB,
darwin/arm64), machine under moderate load (load avg ~4.5) — best-of-N is
robust to that; the `sign_blinded` *median* in op_bench is load-inflated,
`best` is the clean figure. Python 3.12.1, liboqs-python 0.16.0. The Rust
row is from the 2026-07-25 native run (not re-run; needs `cargo build`).
Fresh JSON in `results_20260728.json` / `op_results_20260728.json` /
`onchain_results_20260728.json`; the Python numbers reproduced the 07-25
run within noise (liboqs 80k 42.3 vs 42.8 µs, DKSAP 27.6 vs 27.9 µs).

## Results

| Harness | N=5,000 | N=20,000 | N=80,000 | per-announcement |
|---|---|---|---|---|
| pq-sap Rust (paper's code, Kyber768, native)² | 113 ms | 447 ms | 1,809 ms | **22.6 µs** |
| ours, Python + liboqs decaps¹ | 206 ms | 809 ms | 3,384 ms | 42.3 µs |
| DKSAP baseline, Python + libsecp256k1 | 137 ms | 550 ms | 2,207 ms | 27.6 µs |
| ours, pure Python (kyber-py decaps) | 21.0 s | — | — | ~4,190 µs |

² native Rust, re-run same-day 2026-07-28 (avg of 10, vs the Python rows'
best-of-3 — a minor methodology difference; the Rust harness `main` averages).
Rebuilt with `cargo build --release --bin pq_sap_benchmark --features kyber768`.
All backends are **Module-LWE** (see note below), so this is a like-for-like
lattice comparison, not cross-assumption.

¹ decaps via audited liboqs; the on-tag-match full derivation runs in pure
Python at **6.85 ms** per hit (measured separately; pure-python decaps is
4.20 ms). At N=80,000 the ~277 false-positive derivations account for
~1.9 s of the 3.4 s total — the decaps+view-tag loop alone is
**~19 µs/announcement, faster than the DKSAP EC baseline**, consistent
with the paper's lattice-beats-EC-scanning result. A production wallet
would have the derivation in native code too.

## Hardness assumption: Module-LWE throughout

Every lattice component of this scheme rests on **Module-LWE (MLWE)** — not
plain LWE, not Ring-LWE — over the same degree-256 power-of-two cyclotomic
ring `R_q = Z_q[X]/(X²⁵⁶+1)` (with `q = 3329` on the KEM side, `q = 8380417`
on the signature side):

- **Detection / KEM:** ML-KEM-768 (FIPS 203, ex-Kyber) — Module-LWE, module
  rank `k = 3`. The Rust baseline above uses `pqc_kyber` at `kyber768`, same
  assumption.
- **Spend / signature:** ML-DSA-65 (FIPS 204, ex-Dilithium) — Module-LWE +
  Module-SIS, dimensions `(k, l) = (6, 5)`.
- **Construction A / ownership:** the blinded-key relation `A·s + e = t`
  *is* an MLWE instance (`A` a matrix over `R_q`, `s, e` short module
  vectors). The ZK "decode-in-reverse" ownership statement (D-008) and the
  Lean `IsOwnershipWitness` are that same MLWE relation.

Why MLWE and not the others: plain LWE has impractically large keys;
Ring-LWE (the rank-1 special case) is less conservative and less flexible on
parameters. Module-LWE is the NIST-standardized middle ground, and picking it
for *both* KEM and signature means detection and spend share one ring and one
hardness family — the blinding algebra transfers across parameter sets
(512/768/1024) without changing the assumption.

## Honesty notes for the cost report

- **DKSAP is our only EC baseline; we don't use Curvy.** DKSAP (plain-ECDH
  secp256k1) is the EC scheme ERC-5564 actually deploys, so it's the honest
  bar. The paper's ~66.8% headline is versus Curvy (pairing-based), which
  nobody runs and which flatters the result — we don't carry that number.
  Against DKSAP on libsecp256k1, native lattice scanning is moderately
  faster (Rust 23.8 µs vs 27.9 µs), not 3×.
- Pure-Python is the executable spec, not a scanning engine: 4.2 ms per
  decaps makes it ~150× slower than liboqs. Vector generation and testing
  are unaffected; wallets must bind to native crypto.
- The Rust build needed one local patch: `pq-sap`'s REST module uses sqlx
  compile-time macros requiring a live `DATABASE_URL`; it is now behind a
  `rest` feature flag (see `pq-sap/src/lib.rs`), benchmarks unaffected.

## Discovery-KEM alternatives (`discovery_kem_bench.py`)

If spending is a ZK ownership proof, discovery is "just a KEM" — no
key-homomorphism constraint bleeds in from the spend side, so the KEM is
chosen purely on scan speed, footprint, and assumption. And the ZK-spend
reframe **already shrinks the meta-address on its own**: it no longer carries
the 4,416-B full-precision ML-DSA `t`, only `version + 32-B commitment + KEM
pk`. For ML-KEM-768 that's **5,633 B → 1,217 B (4.6× smaller)** before
changing the KEM at all.

Full design-space sweep 2026-08-01, M1 Max, liboqs 41-KEM build, grouped by
**matched security level** so rows compare like against like; ML-KEM-768 (our
default, L3) is the reference. `scan 80k` is the decaps-bound projection for
an 80,000-announcement registry (decaps runs once per announcement, so this
is the number a wallet feels). `announce gas` is the EIP-7623 calldata floor
(ML-KEM-768 lands at 67,700 with a random ciphertext, within 120 gas of the
measured 67,580 — the difference is ciphertext zero-byte count).

**Level 3 (our default level):**

| KEM | assumption | pk B | ct B | decaps ms | scan 80k | meta B | announce gas |
|---|---|---|---|---|---|---|---|
| **ML-KEM-768** (default) | Module-LWE | 1,184 | 1,088 | 0.017 | **1.4 s** | 1,217 | 67,700 |
| NTRU-HRSS-701 | NTRU | 1,138 | 1,138 | 0.051 | 4.1 s | 1,171 | 69,750 |
| NTRU-HPS-2048-677 | NTRU | 930 | 930 | 0.052 | 4.2 s | 963 | 61,680 |
| sntrup761 (~L2) | NTRU | 1,158 | 1,039 | 0.143 | 11.4 s | 1,191 | 65,880 |
| FrodoKEM-976 | LWE (unstructured) | 15,632 | 15,792 | 0.750 | 60 s | 15,665 | 654,190 |
| HQC-3 | quasi-cyclic codes | 4,514 | 8,978 | 7.114 | 9.5 min | 4,547 | 382,870 |
| BIKE-L3 | quasi-cyclic codes | 3,083 | 3,115 | 16.124 | 21.5 min | 3,116 | 148,780 |
| Classic-McEliece-460896 | Goppa codes | 524,160 | 156 | 43.697 | 58 min | 524,193 | 30,490 |

**Level 1** (smaller/faster across the board, same ordering): ML-KEM-512
0.9 s/80k · NTRU-HPS-509 7.7 s · Frodo-640 34 s · HQC-1 3.2 min · BIKE-L1
6.8 min · McEliece-348864 24 min.

**Literature rows** (not in liboqs, sizes from the papers): CSIDH-512
(isogeny NIKE, ~L1 *contested*): 64-B keys → 97-B meta-address, 26,740-gas
announcement, but ~80 ms/op → **~107 min per 80k scan**. Saber (Module-LWR,
L3): 992/1,088 B, essentially ML-KEM's footprint on a lapsed candidate.
NewHope-1024 (Ring-LWE): the rank-1 module, less conservative than MLWE,
round-2 exit.

**Findings.**
- **Scan cost is decaps, and the spread is now ~3,770× at matched level**
  (ML-KEM-768 1.4 s per 80k → McEliece-460896 58 min; CSIDH ~107 min from
  literature). Code-based decoders are disqualifying for scanning at L3:
  HQC 9.5 min, BIKE 21.5 min per 80k.
- **NTRU is the one genuinely competitive lattice alternative** — a finding
  the earlier sntrup761-only row (8× slower) understated. At matched L3,
  NTRU-HPS-2048-677 scans 80k in 4.2 s (3× ML-KEM, perfectly usable) with a
  **smaller footprint than ML-KEM** (930-B pk, 61,680-gas announcement, ~9%
  cheaper). If assumption diversity away from Module-LWE were ever needed,
  NTRU is the fallback with real numbers behind it.
- **Footprint splits two ways.** Classic-McEliece inverts the tradeoff —
  half-MB pk (a catastrophic meta-address) but a 156-B ciphertext, the
  cheapest announcement (30,490 gas). CSIDH would be tiny on both axes but
  pays ~107 min per 80k scan on a disputed assumption.
- **The practical shortlist: ML-KEM (fast, standard, balanced), NTRU (the
  credible hedge), CSIDH (footprint play for low-volume recipients only).**
  FrodoKEM is the conservative-assumption hedge at a 15.7 kB meta-address
  and 60 s scans; the code KEMs don't pay off for stealth scanning.

## Hash-only key exchange economics (`hash_kex_bench.py`)

Question (2026-08-25): can a SHA-256 / BLAKE3 commitment scheme replace the
discovery KEM, removing the lattice assumption? Theory caps any hash-only key
exchange at a polynomial gap — Impagliazzo–Rudich (STOC '89), Barak–Mahmoody
(CRYPTO '09: n honest oracle queries ⇒ O(n²)-query break; Merkle puzzles are
tight) — and against a *quantum* eavesdropper Merkle's scheme has **no gap at
all** (Brassard–Høyer–Kalach–Kaplan–Laplante–Salvail, CRYPTO '11; best
classical-party family only approaches n^{3/2}). The script measures hash
rates on this machine and converts the exponents into honest work, recipient
"public key" (puzzle set) size and calldata, against the ML-KEM rows of
`discovery_kem_20260801.json`. Run 2026-08-25, M1 Max, Python 3.12, `blake3`
1.0.9 → `hash_kex_20260825.json`.

| hash (64-B msg, Python-bound) | calls/s | bulk MB/s |
|---|---|---|
| SHA-256 | 3.36 M | 2,366 |
| BLAKE3 | 2.36 M | 1,768 |
| SHA3-256 | 1.77 M | 629 |
| keccak256 (pycryptodome) | 0.35 M | 554 |

Per-announcement scanner hashing (view tag over 32 B / KDF over 1,088 B) is
0.3–0.7 µs with SHA-256, 0.4–1.7 µs with BLAKE3 — vs 17.2 µs ML-KEM-768
decaps. The hash *choice* is irrelevant to scan time; the KEM is.

Merkle-puzzle cost to force attacker work 2^W (n = hash calls per honest
party = puzzles the recipient must publish, 40 B each; native core 2^24.5
H/s, GPU 2^34 H/s assumed; 40 gas/B calldata floor):

| attacker model | gap | W=2^80 | W=2^128 |
|---|---|---|---|
| classical Eve, Merkle 1974 (optimal) | n² | n=2^40: 64 GPU-s/payment, **44 TB** pubkey | n=2^64: 34 GPU-yr, **738 EB** pubkey |
| quantum Eve, classical parties, Merkle 1974 | n¹ | n=2^80 — no gap, broken | n=2^128 — broken |
| quantum Eve, classical parties, BHKKLS'11 concrete | n^{7/6} | n=2^68.6: 809 GPU-yr | n=2^109.7 |
| quantum Eve, classical parties, family limit | n^{3/2} | n=2^53.3: 184 GPU-h, 454 PB | n=2^85.3 |
| quantum Eve, **quantum** honest parties | n^{5/3} | n=2^48: 4.6 GPU-h, 11 PB | n=2^76.8 |

For scale: 2^80 hashes is ~17 minutes of the 2026 Bitcoin network (~2^70 H/s).
ML-KEM-768 gives L3 security against both attacker classes for a 1,184-B key,
1,088-B ciphertext, 17.2 µs decaps and 67,700 gas. Write-up and the
hash-only designs that *do* work (pre-shared-secret tag chains — already in
the design, seeded by one ML-KEM handshake): `docs/research/hash-based-key-exchange.md`.

## On-chain verification gas (kohaku / ZKNOX, stretch-goal route)

Measured via `ETHDILITHIUM`'s own KAT tests (forge, optimizer 10k runs,
cancun) in `ethereum/kohaku` `packages/pq-account/lib`:

| Verifier | Gas per signature verification |
|---|---|
| `ZKNOX_dilithium` (level-2 Dilithium profile, SHAKE) | 8,176,453 |
| `ZKNOX_ethdilithium` (keccak-PRNG variant) | 4,926,456 |

Counterfactual CREATE2 demo (construction A keys at the ZKNOX profile,
`js-client/test/e2e-counterfactual.test.ts`): account deployment via the
factory (22.4 kB expanded pk via SSTORE2) **6,167,566 gas**; on-chain
verification of a blinded-key possession signature **~8,151,911 gas**.

See `docs/TECHNICAL_SPEC.md` §7 for the compatibility analysis (their
profile is level-2 round-3 Dilithium with FIPS-style formatting — not
ML-DSA-65; our blinding algebra transfers, the parameter set does not).

## On-chain data cost — the real PQ tradeoff (`onchain_cost.py`)

The scheme is *data-heavy, not compute-heavy*. Scanning is competitive
(above); the price of post-quantum is footprint. The model is anchored to a
measured number and reproduces it to the gas.

**Announcement, L1.** The Sepolia-fork test posts a real vector announcement
to the canonical ERC-5564 announcer and measures **67,580 gas**. Our model
reconstructs the exact `announce(uint256,address,bytes,bytes)` calldata
(1,316 B: 1,114 nonzero, 202 zero → 4,658 EIP-7623 tokens) and lands on
**67,580 gas, 0.00% error**. The finding that falls out: this tx pays the
**EIP-7623 calldata floor** (`21,000 + 10 × 4,658 = 67,580`), not the
standard calldata+execution cost (52,446). A PQ announcement is bytes, and
post-Pectra you pay the floor for bytes. The EC-DKSAP baseline (33 B point)
models at 27,342 gas in the *standard* regime → PQ is **2.5× on L1** (the
fixed 21k base compresses the raw 33× data ratio).

**Announcement, L2 (marginal L1 data cost).** Assumptions, dated 2026-07-28:
ETH $3,200, L1 base 8 gwei, blob base 1 gwei. These are *marginal L1 data
costs*, not per-rollup fees — each rollup adds its own compression and
margin, which floats, so we don't invent a "$X on Base" figure.

| Announcement | calldata regime | blob regime (EIP-4844) |
|---|---|---|
| PQ (1,316 B) | ~$1.35 | ~$0.0042 |
| DKSAP (~130 B) | ~$0.30 | ~$0.0009 |

Blobs cut the PQ data cost ~**320×** vs calldata (40 gas/byte × 8 gwei →
1 gas/byte × 1 gwei). The footprint problem is a real L1 tax; on a
blob-posting L2 it costs sub-cent and largely dissolves.

**Meta-address registration (ERC-6538, one-time per recipient).** 5,633 B at
a naive per-word SSTORE is ~3.79M gas (177 words) vs ~62k for the 33 B EC
meta-address (~61×). SSTORE2 / code-blob storage (~200 gas/byte to deploy) is
the right pattern for a payload this size and is what the spec recommends.

## Per-operation micro-benchmarks (`op_bench.py`)

Secondary — scanning and data cost are the numbers that matter. Wall-clock
(median ms) for the one-shot off-chain operations, pure-Python reference
(a wallet binds native crypto), Apple Silicon:

| Operation | median ms |
|---|---|
| `gen_meta_address` | ~8 |
| `send` (encaps + stealth-pk derive) | ~10 |
| scan hit (decaps + view-tag + derive) | ~11 |
| `derive_stealth_pk` (isolated) | ~7 |
| `verify` (stock FIPS 204) | ~8 |
| `sign_blinded` (rejection loop) | ~20 best, ~120 median¹ |

¹ **Blinded signing is the one real slowdown.** It runs **~6× the rejection
rounds** of stock ML-DSA-65 (mean ≈ 30 vs ≈ 5, median 22 vs 4, N=200) —
because widening both secret vectors to `2η` doubles `β'` and shrinks the
`z`/`r0` acceptance region (the `r0` check dominates). This corrects an
earlier "a handful of extra rounds" note. It's a heavy-tailed geometric
(max seen 162 rounds), so median ms ≫ best ms. A tighter probabilistic norm
bound than the worst-case `2η` would recover most of it — one for the
security analysis.

## Registry-size scaling curve (`registry_curve.py`)

The challenges section promises the curve across registry sizes; here it is,
measured 2026-08-02 (7 sizes, 2,500 → 160,000, best-of-3, least-squares fit):

| Harness | marginal cost (slope) | intercept | R² |
|---|---|---|---|
| ours (ML-KEM-768, liboqs decaps) | **44.31 µs/announcement** | −31 ms | 0.99923 |
| DKSAP (libsecp256k1) | 27.50 µs/announcement | +25 ms | 0.99949 |

Both are linear to R² > 0.999 across a 64× size range — no superlinear
surprises at 160k. The fitted marginal ratio is **1.61×**. Our slope
*includes* the ~N/256 view-tag false positives (each pays a pure-Python
derivation, ~1.6 ms in this harness), so it is the honest steady-state
number; a native derivation shrinks that term. At 1M announcements the
projection is ~44 s vs ~28 s of single-core scanning, both embarrassingly
parallel.

## Today's real registries (`real_registries.py`)

Grounding the curve in current values: live `eth_getLogs` counts of the
deployed SAP registries (2026-08-02, drpc free tier, bounded query sets —
full-history scans only where cheap).

| Registry | measured | scan cost at our 44.3 µs/ann |
|---|---|---|
| ERC-5564 canonical announcer, mainnet | **202 total** (exact, verified on two endpoints); 1 in last 7d | **9 ms** |
| Umbra (own contract), mainnet | 1 announcement in last 7d | — |
| Canonical announcer on Base / Gnosis; Umbra on OP / Polygon | pending — free-tier RPC rate-limit exhausted mid-count; retry needs a cooled quota or paid tier | — |

The finding so far is itself informative: **mainnet SAP activity is
essentially dormant** (the canonical announcer's entire two-year history
scans in ~9 ms). Stealth-address volume lives on the L2s (Fluidkey on
Base/Gnosis, Umbra on OP/Polygon) — counting those is the open item.
Umbra Arbitrum exists but ~400M blocks at the 10k-window cap is impractical
to count on a free tier; noted, not counted.

Operational notes baked into the script: drpc free tier caps `eth_getLogs`
at 10k blocks AND batches at 3 requests regardless of key; dense L2 chains
need ~2k windows or requests time out server-side; rate-limit errors must be
retried-in-place, never split (splitting on throttle explodes the queue).

## EIP-8304 trustless scanning PoC (`eip8304_scan_poc.py`)

EIP-8304 (Draft, considered for inclusion) defines sorted, Merkleized
log-index tables. Sorted entries make **completeness provable** — for
stealth addresses the property that matters most, since an omitted
announcement is a payment the recipient never learns about. The PoC
implements the spec's entry encodings (types 2–6), table construction,
`List[Hash32]` SSZ Merkleization (SHA-256 → post-quantum sound), and a
range multiproof for the `topics[1] = schemeId` query, over a level-4
(256-block) table seeded with v0 vector announcements among noise logs:

| Measured (256 blocks, ~35.8k entries, 12 announcements) | |
|---|---|
| Scan proof (siblings + revealed entries) | **1,486 B** |
| Verification time | 0.04 ms |
| Completeness | proven (sorted-range boundary entries) |
| Receipt bandwidth (12 × 1,109 B bodies) | 13,308 B |
| …if view tags were an index row | 1,109 B |

Working-group items derived from implementation: (1) the **view tag is
invisible to the index** (it lives in unindexed `metadata` while ERC-5564's
topics are spent on schemeId/stealthAddress/caller) — a view-tag index row
or a successor event with the tag as a topic cuts light-client receipt
bandwidth ~256× at scale; (2) the spec's entry-size table (42/50/38/50 B)
is one byte larger than `type(1)+content+position` for every type — the
layout needs a clarifying sentence.

## Security-level sweep (`param_sweep.py`)

The scheme is parameter-agile across three NIST levels. Measured 2026-07-28,
M1 Max, N=20k scan, liboqs KEM:

| lvl | params | meta-addr | ct | sig | keygen | encaps | decaps | scan µs/ann |
|---|---|---|---|---|---|---|---|---|
| L1 | ML-KEM-512 + ML-DSA-44 | 3,777 B | 768 B | 2,420 B | 17 µs | 15 µs | 12 µs | 27.8 |
| L3 | ML-KEM-768 + ML-DSA-65 | 5,633 B | 1,088 B | 3,309 B | 19 µs | 19 µs | 17 µs | 43.7 |
| L5 | ML-KEM-1024 + ML-DSA-87 | 7,489 B | 1,568 B | 4,627 B | 25 µs | 26 µs | 25 µs | 66.5 |

**Non-obvious finding: the blinding penalty is not monotone in the level.**
The widened bound is `β' = τ·2η`, and `η` is not monotone — ML-DSA-44/87 use
`η=2`, ML-DSA-65 uses `η=4`. So the **default L3 set pays the worst blinding
cost**, not L5:

| lvl | η | τ | β' | blinded rounds | stock rounds | ratio |
|---|---|---|---|---|---|---|
| L1 | 2 | 39 | 156 | 14.4 | 4.6 | 3.1× |
| L3 | 4 | 49 | 392 | **24.8** | 5.5 | **4.5×** |
| L5 | 2 | 60 | 240 | 15.3 | 3.8 | 4.0× |

(rejection rounds, mean of 50 signatures). A tighter probabilistic norm bound
would help L3 the most, since it starts from the largest `η`.

## View-tag length sweep (`viewtag_sweep.py`)

A view tag rejects non-matching payments before the expensive derivation;
false-positive rate is `256^-b`. N=40k announcements to random recipients
(every match is a false positive), pure-Python derivation:

| tag bytes | FP rate | derivations | µs/ann |
|---|---|---|---|
| 1 | 1/256 | 181 | 48.2 |
| 2 | 1/65,536 | 0 | 17.8 |
| 3 | 1/16,777,216 | 0 | 17.6 |

The 1-byte tag's ~156-expected false-positive derivations cost ~30 µs/ann
here; a 2-byte tag removes them, dropping to the ~17.8 µs decaps+tag floor.
**But** each derivation is pure-Python (~ms) in this harness; in native code
it's ~µs, so at 1/256 the wasted work is negligible and 1 byte is already
near-optimal — hence `VIEW_TAG_BYTES = 1` as the spec default. The knob
matters most exactly when derivation is the bottleneck (i.e. slow clients).
Extra tag bytes are ~free on-chain (1–2 B next to a 1,088 B ciphertext).

## Reproduce

```sh
# Python harness (from python/, venv with pq-stealth + liboqs + coincurve)
python benchmarks/scan_bench.py --sizes 5000,20000,80000 --reps 3 --json benchmarks/results.json

# On-chain data cost model (needs eth_abi, eth_utils; reproduces 67,580 gas)
python benchmarks/onchain_cost.py --json benchmarks/onchain_results.json

# Per-operation micro-benchmarks + rejection-round comparison
python benchmarks/op_bench.py --reps 20 --json benchmarks/op_results.json

# Security-level sweep (sizes, KEM ops, scan, rejection rounds across L1/L3/L5)
python benchmarks/param_sweep.py --n 20000 --reps 5 --sign-reps 50 --json benchmarks/param_sweep.json

# View-tag length sweep (false-positive rate vs scan cost)
python benchmarks/viewtag_sweep.py --n 40000 --tags 1,2,3 --json benchmarks/viewtag_sweep.json

# Discovery-KEM alternatives (lattice vs code vs isogeny: scan/footprint/gas)
python benchmarks/discovery_kem_bench.py --reps 60 --json benchmarks/discovery_kem.json
python benchmarks/hash_kex_bench.py --reps 5 --json benchmarks/hash_kex.json   # needs `pip install blake3`

# Registry-size scaling curve (linearity fit, ours vs DKSAP)
python benchmarks/registry_curve.py --reps 3 --json benchmarks/registry_curve.json

# Live registry counts (bounded: last 7 days; --full for history; DRPC_KEY env optional)
python benchmarks/real_registries.py --days 7 --json benchmarks/real_registries.json

# EIP-8304 trustless-scan PoC (proof sizes, completeness verification)
python benchmarks/eip8304_scan_poc.py --blocks 256 --json benchmarks/eip8304_poc.json

# Paper reproduction (from pq-sap/)
cargo build --release --bin pq_sap_benchmark && ./target/release/pq_sap_benchmark

# Gas (from kohaku/packages/pq-account/lib/ETHDILITHIUM/, submodules initialized)
forge test --match-path "test/*KAT*" --gas-report
```
