# Cost report — measured L1/L2 gas and client-side scanning

*2026-09-30. Assembles the measured cost numbers for the scheme into one report
(the EPF project definition's "benchmarks + cost report" deliverable). Every
figure below is either measured on-chain (forge e2e / Sepolia fork), produced by
a committed benchmark harness, or computed by the gas model anchored to a
measured number — each cites its source. Dated assumptions are stated where
they are used; nothing here is a per-rollup fee quote.*

Companion material: the harness-level detail and methodology lives in
[`python/benchmarks/README.md`](../../python/benchmarks/README.md) (scan, KEM
sweep, view tags, registry curve, EIP-8304 PoC); the data-cost model is
[`python/benchmarks/onchain_cost.py`](../../python/benchmarks/onchain_cost.py)
(D-011); the decision records behind the framing are D-011 (cost is data),
D-025 (account routes), D-028 (key-exchange layer).

## 1. Headline

Categories are kept separate throughout (review F6): **setup/deployment**
(one-time), **recurring verification** (per spend), **whole-transaction**
(sponsor-visible), and **client-side**. Every row names its profile/parameter
set, verifier revision, toolchain, and measurement boundary.

| Cost (category) | Value | Exact provenance |
| --- | --- | --- |
| Announcement, L1 (recurring, per payment) | **67,580 gas** (EIP-7623 floor, binding) | measured, Sepolia fork e2e, forge/anvil, 2026-08-10; model reproduces 0.00% error |
| vs EC-DKSAP baseline (same boundary) | **2.5×** (27,342 gas, standard regime) | `onchain_cost.py` (modeled standard-regime baseline) |
| Key-exchange wrapper overhead (recurring marginal) | **2,065 gas** (~3% of the floor) | `test_announce_overhead_gas` (D-028), forge, CI toolchain |
| Announcement, L2 blob regime (recurring) | **~$0.0042** marginal L1 data | `onchain_cost.py` L2 model, anchors dated 2026-07-28 |
| Meta-address registration (one-time setup) | 3.79 M gas naive / **~1.13 M via SSTORE2** (5,633 B, `0x01`) | modeled, D-011; `0x02` is 1,217 B → ~264k SSTORE2 |
| Account deployment (one-time setup) | **620,750 gas** (ERC-7913 pointer route) | e2e-7913, anvil, 2026-08-10 |
| Signature verification (recurring, per spend — see §5 for the profile split) | 4.93 M (ZKNOX_ethdilithium, keccak-PRNG variant) – 8.18 M (ZKNOX_dilithium, SHAKE) – ~15 M (ERC-7913 route at df999ed) | ETHDILITHIUM KAT gas report at rev df999ed; e2e-7913 |
| Whole-spend transaction (recurring) | ~8.4 M (`handleOps`, blinded-key sig) | Sepolia fork, outer-tx measured |
| Scanning (client-side) | **44.3 µs/announcement** steady-state (Python client); 23.8 µs native | `scan_bench.py` / `registry_curve.py`; 0x3327 Rust harness |

The one-line story: **the scheme is data-heavy, not compute-heavy.** Detection
(scanning) is competitive with — and natively *faster* than — the EC scheme
ERC-5564 deploys today; the post-quantum premium is bytes on-chain (a 1,088 B
ciphertext where DKSAP posts a 33 B point), which the EIP-7623 floor prices
directly on L1 and which EIP-4844 blobs dissolve on L2.

## 2. Announcement cost, L1

The canonical `ERC5564Announcer.announce(uint256,address,bytes,bytes)` call
with our announcement (1,088 B ML-KEM-768 ciphertext, 1-byte view tag,
ABI-encoded to 1,316 B calldata: 1,114 nonzero / 202 zero bytes) costs
**67,580 gas measured** on the Sepolia fork, and the data-cost model
reconstructs the exact calldata and reproduces it to the gas (0.00% error):

- standard cost would be 52,446 (21,000 base + calldata + LOG4 execution);
- the **EIP-7623 calldata floor** `21,000 + 10 × 4,658 tokens = 67,580` is
  binding — post-Pectra a PQ announcement is priced as *bytes*, not compute
  (D-011's core finding).

The EC baseline (DKSAP, 33 B compressed point) models at **27,342 gas** in the
*standard* regime — its calldata is zero-dominated, so the floor never engages.
PQ is thus **2.5× on L1** (the fixed 21,000 base compresses the raw 33× data
ratio). At the D-011 anchors (L1 base 8 gwei, ETH $3,200 — dated 2026-07-28)
that is ~$1.73 per PQ announcement vs ~$0.70 for DKSAP; the figure scales
linearly with basefee, and both rows are dominated by bytes, not by anything
the scheme can optimize away without shrinking the ciphertext.

**Wrapper overhead (D-028).** Routing the announcement through
`StealthKeyExchange.announce` (shape-check: supported ciphertext length,
metadata present; byte-for-byte forward to the singleton under scheme ID 2)
costs **2,065 gas over a direct singleton call** — ~3% of the floor
(`test_announce_overhead_gas`, steady-state on the CI toolchain). The
shape-check contract is optional for wallets; the announcer stays the deployed
singleton and nothing about the scheme changes.

## 3. Announcement cost, L2

Rollups post transaction data to L1, so an L2 announcement's marginal cost is
L1 data cost. Two regimes (marginal L1 data cost per announcement; dated
anchors ETH $3,200, L1 base 8 gwei, blob base 1 gwei — 2026-07-28; each
rollup adds its own compression and margin on top, which floats, so we do not
quote per-rollup fees):

| Announcement | calldata regime | blob regime (EIP-4844) |
| --- | --- | --- |
| PQ (1,316 B) | ~$1.35 | **~$0.0042** |
| DKSAP (~130 B compressed) | ~$0.30 | ~$0.0009 |

Blobs price data at ~1 gas/byte against the blob basefee instead of ~40
gas/nonzero-byte against the execution basefee — a ~**320×** cut. The PQ
announcement costs **sub-cent on any blob-posting L2**, and the ~4.5×
modeled cost ratio over DKSAP persists in both regimes (both announcements
benefit from the regime change; the absolute gap falls to fractions of a
cent). Stealth-address
activity already lives on L2s (D-011's live-registry survey: the mainnet
canonical announcer has 202 announcements *ever*; the volume is Fluidkey on
Base/Gnosis and Umbra on OP/Polygon) — so the deployment story is: the L1
data tax is real but the L2 landing is where the scheme is cheap, and there
the footprint "largely dissolves" (D-011).

## 4. Meta-address registration (one-time per recipient)

Storing the 5,633 B Construction A meta-address (`0x01`) in ERC-6538-style
storage at a naive per-word SSTORE is ~**3.79 M gas** (177 words) vs ~62k for
the 33 B EC meta-address (~61×) — the meta-address, not the announcement, is
the big on-chain write. SSTORE2 / code-blob storage (~200 gas/byte to deploy)
brings it to **~1.13 M gas** and is the pattern the contracts use
(`StealthKeyExchange` ek-registry, D-028).

The commitment form (`0x02`, D-024) shrinks the meta-address 5,633 → **1,217 B**
(4.6×): ~850k naive / ~**264k gas** via SSTORE2 — one-time registration lands
in the same ballpark as a modest contract deployment, not a small fortune.
Meta-address distribution and the ERC-6538 registry are out of the proposal's
scope (D-014): naming services or off-chain sharing can carry the meta-address
and the deployment binding entirely off-chain, in which case this row is
optional for every recipient.

## 5. Spend-side on-chain costs (account routes, D-025)

The deployed-verifier reality is ZKNOX's ETHDILITHIUM profile (level-2 round-3
Dilithium, not ML-DSA-65 — issue #30). All figures measured (forge/anvil e2e,
2026-08-10; ETHDILITHIUM KAT gas report at rev df999ed):

| Operation | Category | Gas | Profile / verifier revision | Notes |
| --- | --- | --- | --- | --- |
| ERC-7913 account deploy (pointer route) | setup, one-time | **620,750** | ERC-7913 pointer route, df999ed verifier | initcode 2,952 B; keys behind SSTORE2 pointer (D-020/D-025) |
| PKContract deploy (22.4 kB expanded pk) | setup, one-time per stealth key | 5,324,168 | ZKNOX PKContract | expanded-key storage route |
| Account deploy via old factory+embedded-key | setup, one-time (superseded) | 6,167,566 | pre-D-025 route | the route D-025 replaced |
| `ZKNOX_ethdilithium.verify` | recurring verification | **4,926,456** | ETHDILITHIUM keccak-PRNG variant — **not a FIPS ML-DSA measurement** | see caveat below |
| `ZKNOX_dilithium.verify` | recurring verification | 8,176,453 | level-2 Dilithium2-shape, SHAKE | issue #30 territory: raw-key ML-DSA-65 verifier is open |
| ERC-7913 verify at df999ed | recurring verification | ~14.97 M | ERC-7913 route, df999ed | stores `t1` plain, recomputes `NTT(t1·2^d)` per verify |
| C13 `verify` (direct scheme) | recurring verification | **188,092** | SPHINCS-C13 direct signature, tx-level | hash-based; **its own soundness is that of the C13 parameter set** — the classical-only UltraHonk *wrapper* limitation (D-025) is a separate statement about a different route and does not transfer here |
| 4337 `handleOps` spend | whole-transaction | ~8.4 M | blinded-key sig, level-2 profile | Sepolia fork, outer-tx measured |

**Keccak-PRNG caveat (review F6):** `ZKNOX_ethdilithium` is a keccak-PRNG
*variant* of the level-2 profile. It is **not** interchangeable with a FIPS
ML-DSA measurement, and its 4.93 M figure must not be read as "the cost of
ML-DSA verification" — it is the cost of that specific variant's verify at
rev df999ed on the stated toolchain. The SHAKE-based `ZKNOX_dilithium` row
(8.18 M) is the closer-to-standard measurement; a genuine FIPS ML-DSA
verifier figure does not exist in this report (issue #30 records the
raw-key ML-DSA-65 verifier as open work).

Per-spend execution gas spans **single-digit millions to ~15 M depending on
the verifier revision and route** (review F6: the earlier
"single-digit-millions" framing contradicted the ~14.97 M ERC-7913 row in
this same table). At the dated anchors (8 gwei, ETH $3,200) a spend's
signature verification alone is ~$126 (ZKNOX_ethdilithium, 4.93 M) to ~$209
(ZKNOX_dilithium, 8.18 M), and the ERC-7913 route at df999ed (~14.97 M) is
~$383; at 30 gwei those become ~$473 / ~$785 / ~$1,437. The honest framing:
**spend is the expensive side of the scheme, and it is L1-only expensive** —
detection (the every-payment path) sits at the 67,580 data floor, while each
spend pays millions to ~15 M of *execution* gas for PQ signature
verification, which L2s price at a fraction of L1. Spend is a one-shot
operation per payment, not per-recipient per-announcement, and the account
deploy (620,750) is one-time per stealth address.

The ZK-ownership route (D-025 preimage proof, UltraHonk backend) changes the
profile, not the story: verification drops to the verifier's fixed cost but
**that specific backend is classical-only sound** (UltraHonk is BN254/KZG) —
a PQ-sound STARK verifier is ~5 M gas (D-007 measured/cited: STARK ~5 M vs
Groth16 <300 k which is classical). Route choice is the parameter-level
decision (#30/#31) and does not move the detection numbers.

**Security-assumption bookkeeping (review F6), kept separate:** the *direct*
C13 route (188,092) verifies a hash-based signature on-chain; its soundness
assumptions are those of the SPHINCS-C13 parameter set — post-quantum under
the hash-function security of its components, independent of any proof
system. The classical-only limitation above belongs to the *UltraHonk-wrapped*
preimage route (D-025), a different route whose statement happens to include
C13 inside a zk proof. The two must not share a security label; the table row
for direct C13 now carries its own.

## 6. Client-side scanning

Scan cost is decaps cost — one decapsulation per announcement, view-tag
pre-filter, full derivation only on tag match (~1/256):

- **Python client steady-state: 44.3 µs/announcement** (linear across
  2.5k–160k announcements, R² = 0.999, `registry_curve.py`) vs 27.5 µs for
  the DKSAP baseline on libsecp256k1 — a fitted **1.61×** ratio that includes
  the ~N/256 false-positive derivations. The decaps+view-tag loop alone is
  ~19 µs/announcement (liboqs ML-KEM-768 decaps 17.2 µs native), i.e.
  **the pure lattice loop is faster than the EC baseline**.
- **Native: 23.8 µs** (the 0x3327/pq-sap Rust harness we reproduced)
  vs 27.9 µs DKSAP — against the scheme ERC-5564 actually deploys, native
  lattice scanning is *moderately faster*, not the paper's 3×-vs-Curvy
  headline (D-011's honesty note: DKSAP is the only EC baseline we carry).
- **Today's registries are tiny**: the mainnet canonical announcer's entire
  history (202 announcements) scans in ~9 ms; at 1M announcements the
  projection is ~44 s single-core, embarrassingly parallel.

Per-operation microbenchmarks (`op_bench.py`): `gen_meta_address` ~8 ms,
`send` ~10 ms, scan hit ~11 ms, stock `verify` ~8 ms (pure-Python reference;
wallets bind native crypto). The one real slowdown is **blinded signing**:
widening both secret vectors to `2η` shrinks the acceptance region, costing
~4.5× ML-DSA's rejection rounds (mean 24.8 vs 5.5, median 22 vs 4; heavy-tailed
— max seen 162 rounds), i.e. ~20 ms best / ~120 ms median in pure Python. A
tighter probabilistic norm bound than worst-case `2η` would recover most of
it and helps the default L3 set most (η=4 there; the penalty is not monotone
in the security level — `param_sweep.py`).

## 7. Assumptions and caveats

- **Price anchors are dated 2026-07-28** (ETH $3,200, L1 base 8 gwei, blob base
  1 gwei, D-011) and scale linearly; the gas *quantities* are protocol
  constants plus measured execution, so they do not age, only the USD
  conversions do.
- USD conversions here were computed from the measured gas at 8 gwei and,
  for the spend rows, 8/30 gwei — illustrative, not fee quotes.
- Per-rollup fees float with each rollup's compression and margin; we quote
  only marginal L1 data cost.
- The gas model's dispatch overhead was fit once (700 gas) against the
  measured 67,580 and is fixed; the model is anchored, not tuned per use.
- Spend-side verification figures are the **deployed level-2 profile**
  (ZKNOX/ETHDILITHIUM at rev df999ed, forge/anvil, solc 0.8.30 / EVM
  `prague`), **not ML-DSA-65**: the keccak-PRNG variant (4.93 M) and the
  SHAKE level-2 shape (8.18 M) are separate measurements of separate
  verifier builds and are not interchangeable FIPS ML-DSA figures (#30 is
  the raw-key ML-DSA-65 verifier, open). Route and parameter-level selection
  (#30/#31) is a spec-freeze decision and will move the spend rows; it does
  not move §2–§4.
- Whole-spend rows (`handleOps` ~8.4 M) are outer-transaction measurements
  including EntryPoint overhead, on Sepolia fork replay — not pure
  verification cost and not comparable to per-verify figures without
  subtracting the wrapper (§5 table lists both categories separately).
- Blinded-signing round counts are stochastic; means/medians are over N=200
  (mean) and N=50 (per-level) signatures (`op_bench.py`, `param_sweep.py`).

## 8. Reproduce

Every number above is regenerable from `python/` (venv with the
`[dev,audit,bench]` extras) and `js-client/`:

```sh
# data-cost model (reproduces the measured 67,580 gas announcement)
python benchmarks/onchain_cost.py --json benchmarks/onchain_results.json
# scan steady-state + EC baseline + registry curve
python benchmarks/scan_bench.py --sizes 5000,20000,80000 --reps 3 --json benchmarks/results.json
python benchmarks/registry_curve.py --reps 3 --json benchmarks/registry_curve.json
# per-op + blinded-signing rounds + security-level sweep
python benchmarks/op_bench.py --reps 20 --json benchmarks/op_results.json
python benchmarks/param_sweep.py --n 20000 --reps 5 --sign-reps 50 --json benchmarks/param_sweep.json

# on-chain: wrapper overhead + account routes (from js-client/)
npm run test-contracts   # includes test_announce_overhead_gas (2,065)
npm run e2e-7913         # account deploy 620,750, PKContract 5,324,168
npm run e2e:fork         # announce 67,580 on the canonical announcer, handleOps ~8.4 M
```

Raw JSON outputs are committed alongside the harnesses in
`python/benchmarks/*.json`; the on-chain measurements are recorded in the
fork-replay fixtures (`js-client/test/`) so they reproduce offline.