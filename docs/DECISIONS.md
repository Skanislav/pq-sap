# Decisions & Findings (ADR-style log)

Locked decisions and empirical findings for the post-quantum ERC-5564 stealth
address project. Each entry is dated and states the rationale so the reasoning
survives, not just the conclusion. Newest context wins; superseded entries are
marked.

Status legend: **LOCKED** (decided) · **FINDING** (measured/verified fact) ·
**OPEN** (owed to a later phase).

---

## D-001 — Key exchange is post-quantum; spending is configurable — **LOCKED**

The KEM (detection/viewing) **must** be post-quantum (ML-KEM); the spend
authorization is a configurable security level, not necessarily PQ.

**Why.** The two quantum threats are not equally urgent. Harvest-now-decrypt-later
(HNDL) attacks *confidentiality*: announcements are public and permanent, so a
classical key exchange can be broken retroactively to link every past payment to
its recipient. Spend authentication is a *live* threat — forging a signature needs
a quantum computer to exist *now*, and only touches funds still parked. Ethereum's
own roadmap states this directly: "in blockchains, this risk mainly affects
confidentiality, not ownership… recording transactions today does not enable
retroactive theft" (pq.ethereum.org, 2026-06-27), and lists "privacy-preserving
transaction systems" among the HNDL-sensitive categories — which is exactly where
stealth addresses sit. So ML-KEM detection is the urgent, non-negotiable core;
spend-side PQ is future-proofing.

## D-002 — Alignment with Ethereum's PQ roadmap — **FINDING**

pq.ethereum.org designates **account abstraction** as the mechanism for the PQ
signature transition ("transition to quantum-safe authentication through account
abstraction, without a disruptive flag day"). Our ERC-4337 stealth-account spend
path uses the same mechanism — the project maps onto the official roadmap rather
than beside it. The roadmap's execution milestone **J\*** is a **vector-math
precompile** that will make on-chain lattice signature verification cheap; timeline
is L1 upgrades "by 2029, full execution-layer migration additional years beyond."
Application-layer ZK-proof migration is **not** covered by the roadmap — the ZK
direction here (D-008) is genuinely novel territory.

## D-003 — Construction A (blinded ML-DSA) is the ownership mechanism — **LOCKED**

"Prove ownership from the main account" and "derive a per-address key" are the same
thing: the blinded ML-DSA signature is a proof of ownership derived from the master
key (producible only from `master_secret + shared_secret`), and blinding keeps the
per-address key statistically independent, so it doesn't link. You cannot spend from
your public EOA (links every stealth account) and you cannot skip derivation (that
*is* the unlinkability). What's optional is whether the derived key is PQ (D-001).
Default fresh error term `e'` per stealth key (closes the pq-sap v2 reused-`s2`
linkability vector).

## D-004 — Gas sponsoring via paymaster + lazy initCode — **LOCKED (design)**

The live demo pre-funded the stealth account with ETH so it could pay its own gas —
a UX burden and a linkability leak (the funding tx is visible). Fix: an ERC-4337
**paymaster** pays gas so the stealth account holds zero ETH, and `initCode` lets the
account **deploy-and-spend in one sponsored UserOp** submitted by a **bundler**. Then
the chain sees only: a bundler submitted a UserOp, a paymaster paid, a valid ML-DSA
signature authorized it — no funding tx, no main-EOA footprint. Caveat: the paymaster
must be neutral (third-party or indirectly funded), else it re-links.

## D-005 — ZKNOX account is limited to ONE large PQ key (EIP-3860) — **FINDING**

The ZKNOX ERC-4337 account bakes both public keys into constructor initcode. Measured:
account creationCode 4,705 B + two 22.4 kB ML-DSA keys as args = **49,729 B initcode,
over the EIP-3860 cap of 49,152 B by 577 B** → `CREATE2` reverts. The hybrid (ECDSA +
one ML-DSA) is 27,361 B and deploys fine. Consequence: a **dual-PQ** ZKNOX account
(two ML-DSA keys, no ECDSA) is **undeployable** on any post-Shanghai chain. The second
slot must be a small key. Genuine PQ-only via ZKNOX would need a compact second PQ
scheme (Falcon-512 pk ≈ 897 B) or an account that sets keys post-deploy.

## D-006 — ZKNOX verifier is hardcoded to level-2 Dilithium2 — **FINDING**

`ZKNOX_dilithium.verify` slices signatures at fixed Dilithium2 offsets:
`cTilde=32, z=2304, h=84` → 2,420-byte sig, 1,312-byte pk. Our scheme's default
**ML-DSA-65** (level 3) is `cTilde=48, z=3200, h=61` → 3,309-byte sig, 1,952-byte pk,
which does **not** fit those slices — the deployed verifier would reject it. The live
Sepolia spend therefore used a purpose-built **level-2 Dilithium2** blinded key
(~128-bit PQ, round-3 non-FIPS). Spending our default ML-DSA-65 key on-chain needs a
deployed ML-DSA-65 verifier, which does not exist on Sepolia. This is why the spec
stays parameter-agile; the blinding algebra itself is level-agnostic.

## D-007 — On-chain: cheap OR post-quantum, not both (today) — **FINDING**

Every cheap EVM verification primitive (BN254 pairing precompiles) is classical.
Measured/cited costs: PlonK/Groth16 verify <300k gas but **not** PQ; STARK (PQ-sound)
~5M gas; direct ML-DSA verify ~8M gas. Groth16 is the far-cheap, far-classical corner
— Vitalik's roadmap explicitly lists "application-layer ZK proofs (KZG or groth16)" as
quantum-vulnerable. **Wrapping a STARK in a SNARK for cheap on-chain verification
destroys its post-quantum soundness** (a16z: the wrap "destroys transparency and
post-quantum security"), because the on-chain verifier only checks the classical outer
proof. So a PQ-sound *statement* proven with a classical proof system is only
classically sound — the proof system, not the statement, sets the security. D-001's
"proof system is a detail of implementation" holds for *modularity*, never for
*security*.

## D-008 — ZK ownership proof: decode-in-reverse relation, pluggable backend — **LOCKED (direction)**

Prove control of a stealth address by proving the MLWE relation "I know short `(s, e)`
with `A·s + e = t (mod q)`" bound to the userOpHash — **not** a full ML-DSA signature.
This is the spec's own parsing trick (subtract with the secret, the small error falls
out) as a ZK statement. It skips SHAKE/rejection/hints and is dramatically cheaper
in-circuit. Binding the message makes it a lattice signature-of-knowledge (Dilithium-
*like*), so it needs its own security analysis — it does not inherit FIPS-204's.

**PoC built** (`noir/`, UltraHonk): proves + verifies end to end; **2,168,651 gates**
at full ML-DSA-65 (schoolbook), projecting to **~100–200k gates** with NTT-domain
convolution. Confirms the ownership statement is practical. But per D-007 the UltraHonk
backend is classical, so this PoC delivers Direction A (gas/privacy), not PQ soundness.

**Architecture:** define the relation, treat the proof backend as per-user config, and
surface each backend's concrete security/cost level. Genuine PQ soundness = a FRI/STARK
or lattice-SNARK backend (Noir's only PQ path today is Noirky2/Plonky2 — a fork,
u32-limited, no EVM verifier). The elegant end state is "lattice all the way down":
MLWE statement + a lattice ZK proof (LNP/LaBRADOR), PQ-sound and native — blocked only
by the absence of an on-chain EVM verifier.

## D-009 — Two scheme variants, stated with threat models — **LOCKED**

The spec ships two variants, not one, each honest about what it protects:

| Variant | Detection | Spend auth | On-chain cost | Protects |
|---|---|---|---|---|
| PQ-detect / classical-spend (pq-sap v1) | ML-KEM | secp256k1 EOA | cheap, today | privacy (HNDL) |
| Full PQ (construction A) | ML-KEM | blinded ML-DSA + 4337 | ~6M deploy + ~8M verify | privacy + long-term funds |
| (Direction A) PQ-detect / ZK-spend | ML-KEM | ZK ownership proof | ~300k verify (classical) | privacy; funds until QC |

Given D-001, the **PQ-detect core is the urgent, differentiated deliverable**; the
spend-side variants are future-proofing that ride the account-abstraction rails the EF
is building (D-002).

## D-010 — Three algebra invariants machine-checked (Lean items 1–3) — **FINDING**

`lean/PqStealth/Invariants.lean`, sorry-free, `lake build` green (2,717 jobs):

- **Widened-bound (item 1):** `cInfNorm_add_le` — centered infinity norm is
  sub-additive (via mathlib `natAbs_valMinAbs_add_le`); hence `blinded_norm_bound`
  (`s₁+s'` is 2η-bounded) and `beta_blinded_eq_two_beta` (β' = τ·2η = 2·β against
  VCVio's `beta`). Machine-checks the D-006-adjacent spec finding.
- **Ownership↔signing (item 2):** `ownership_iff_signing` — the MLWE relation the
  Noir circuit (D-008) proves is definitionally signing-key possession;
  `blinded_is_ownership_witness` derives the witness from the correctness identity.
  Formally ties the ZK PoC to the scheme.
- **Encoding (item 3):** `stealth_pk_roundtrips` (via VCVio's encoding `Laws`) and
  `meta_address_roundtrips` (the wrapper roundtrips whenever inner packing does).

## D-012 — Discovery-only scope with ZK spend decouples the KEM; lattice wins discovery on decaps — **FINDING / direction**

Reframe (2026-07-29): the scheme's core is **discovery/detection**; spending is
a **ZK ownership proof** (D-008), not a blinded ML-DSA signature. Two
consequences, the second measured in `benchmarks/discovery_kem_bench.py`:

- **The KEM is decoupled from spend.** Construction A's key-homomorphism
  requirement (D-003) is what locked us to lattices; with ZK-spend it's gone,
  so discovery can use any PQ KEM/NIKE, chosen on scan speed + footprint +
  assumption. The ownership statement need not be MLWE either — a hash-preimage
  in a FRI/STARK is PQ-sound from hashes alone (D-007), so the scheme *can* be
  lattice-free end to end if desired.
- **ZK-spend shrinks the meta-address by itself.** It sheds the 4,416-B
  full-precision ML-DSA `t`; meta-address becomes `version + 32-B commitment +
  KEM pk`. ML-KEM-768: **5,633 B → 1,217 B (4.6×)**, before touching the KEM.
  Softens the D-011 ~61× meta-address registration finding substantially.
- **Lattice still wins *discovery*, on decaps.** A scanner decaps every
  announcement, so decaps latency is the scan bottleneck. Measured spread
  ~1,570×: ML-KEM-512 0.011 ms → Classic-McEliece 17.9 ms; every code decoder
  (HQC 2.5, BIKE 5.2, McEliece 17.9 ms) is a scanning tax, and even NTRU
  (sntrup761 0.147 ms) is ~8× slower than Module-LWE. So the lattice choice for
  discovery holds up on performance, independent of standardization.
- **Footprint outliers.** Classic-McEliece inverts it (261 kB pk kills the
  meta-address, but 96-B ct → cheapest announcement 28k gas). CSIDH (isogeny
  NIKE, not in liboqs; ~64-B keys, ~80 ms/op, contested params) would give a
  97-B meta-address — the one real footprint alternative, at a speed/assumption
  cost. Practical shortlist: **ML-KEM (default) or CSIDH (footprint play)**.
- **Matched-level sweep update (2026-08-01, full design space at L1+L3):**
  **NTRU is the one genuinely competitive alternative** — the earlier
  sntrup761-only row (8× slower) understated it. At matched L3,
  NTRU-HPS-2048-677 scans 80k in 4.2 s (3× ML-KEM, usable) with a *smaller*
  footprint than ML-KEM (930-B pk, 61,680-gas announcement, ~9% cheaper);
  NTRU-HRSS-701 is equivalent. Code KEMs are disqualifying at L3 (HQC-3
  9.5 min, BIKE-L3 21.5 min, McEliece-460896 58 min per 80k; spread ~3,770×).
  Shortlist becomes: **ML-KEM (default), NTRU (credible hedge with real
  numbers), CSIDH (footprint-only, low-volume recipients)**. Frodo at L3 is
  a 15.7 kB meta-address and 60 s scans — the conservative-assumption tax,
  quantified.

Not yet done: verify the exact ZK-spend address-binding that lets the
meta-address drop the `t` (assumed here; direction is clear, binding unproven).

## D-013 — Security games machine-checked in VCVio; the reduction skeleton is complete — **FINDING**

The security analysis's game layer is now formalized in Lean on VCVio
(2026-07-31, five new modules in `lean/PqStealth/`, all sorry-free, full
`lake build` green at 2,762 jobs, every theorem depending only on the three
standard axioms). This extends the plan's "Lean = algebra only" scope to
*game definitions + structural reductions*; the computational assumptions at
the bottom remain paper-level, exactly as scoped.

**The proved chain.** With the announcement modelled faithfully as
`(ciphertext, aux(sharedSecret))` — view tag and stealth address included:

```
unlinkability ≤ ssHidingTrue + (sprTrue + sprFalse) + ssHidingFalse   [Lean]
  ssHiding  = KEM IND-CPA (real-or-random)  → MLWE  [Lean bridge + VCVio]
  SPR       → 2·MLWE  (two-hop, documented — the one open lattice step)
spend forgery ≤ MSIS  (honest witness always valid)                   [Lean]
all of it instantiated on VCVio's concrete ML-KEM                     [Lean]
```

Key findings along the way:

- **Unlinkability is KEM *anonymity* (key privacy), not IND-CCA** — the hidden
  bit picks the recipient, not the message. VCVio (and FIPS 203's own proof
  chain) stops at IND-CCA; anonymity is absent. That gap is the novel piece.
- **VCVio already ships the assumption layer**: `LearningWithErrors`
  (LWE/MLWE, decision + search), `ShortIntegerSolution` (MSIS +
  SelfTargetMSIS), and proven `K-PKE IND-CPA ≤ MLWE`. No new MLWE
  formalization was needed — reductions land on their definitions. (Their
  `ind_cca_security` is a self-flagged placeholder; we do not lean on it.)
- **The tag/address caveat is a theorem, not a hope**: the auxiliary data
  hides the recipient *exactly insofar as* the shared secret is pseudorandom
  (`unlinkAdvantage_ofKEMFull_le`, proved via triangle inequality over
  real-vs-random-key intermediate games).
- **The open arrow is structured**: `anonymity ≤ SPR(b=1) + SPR(b=0)` is
  proved (GMP/Maram–Xagawa route); what remains is `SPR(K-PKE) ≤ 2·MLWE` —
  key hop (`t = A·s+e` → uniform) then ciphertext hop (`(u,v)` is an MLWE
  sample over `[A|t]`) — plus the ANO-CCA lift through the implicit-rejection
  FO transform. Both are documented in `AnonymityFromSPR.lean`.

Module map (`lean/PqStealth/`): `Games` (StealthScheme + unlinkability game),
`KEMAnonymity` (anonymity game, `ofKEM`/`ofKEMFull`, the bound),
`SharedSecretHiding` (hiding = real-or-random bias, typed IND-CPA reduction
adversaries), `MLKEMInstance` (bridge to VCVio's concrete ML-KEM),
`AnonymityFromSPR` (SPR games + full decomposition capstone),
`Ownership` (spend forgery as VCVio `SIS.Problem`, honest-witness validity).

## D-014 — Spend and registry authentication standardize on ERC-7913 signers — **LOCKED**

ERC-7913 (Signature Verifiers, Final 2025) represents a signer as the byte
string `verifier || key` and checks it via
`IERC7913SignatureVerifier(verifier).verify(key, bytes32 hash, signature) → 0x024ad318`;
an empty key falls back to ERC-1271/ecrecover. Decision (2026-08-10): the
spend route and the registry-authentication recommendation in the ERC draft
are expressed in this encoding — informative in the draft (`requires` stays
`5564, 6538`), demonstrated in `js-client/test/e2e-7913.test.ts`.

**Why.** One shared stateless verifier serves every stealth account, so the
per-account cost collapses to storing signer bytes; both spend modes fit the
same interface (blinded ML-DSA signature with `key` = stealth pk, or the
D-012 ZK ownership proof with `key` = the 32 B commitment); and the empty-key
fallback makes the hybrid ECDSA-co-signer account (D-002's AA migration rail)
a configuration, not a custom contract. It is also the standardized remedy
for the ERC-6538 overwrite hole our draft flags: registries accepting
ERC-7913 authorization from the registered PQ key turn TOFU-plus-PoP into an
enforceable update ratchet.

**Upstream finding.** ZKNOX's ETHDILITHIUM at HEAD (`df999ed`) is already
ERC-7913-native: `ZKNOX_dilithium`/`ZKNOX_ethdilithium` implement
`IERC7913SignatureVerifier`, `setKey` is **removed**, and `key` is a 20-byte
pointer to a `PKContract` (SSTORE2, `getPublicKey()`), so a full signer is
**40 bytes**. The Sepolia-deployed v0.0.10 (`0x092c…21ef`) predates this and
still uses the `setKey` flow. OpenZeppelin mainline 5.5.0 ships the account
side (`SignerERC7913`, `MultiSignerERC7913{,Weighted}`, `ERC7913Utils`) plus
P256/RSA/WebAuthn verifiers — no PQ verifier among them.

**What this dissolves.** D-005's EIP-3860 wall was an artifact of baking
keys into initcode (49,729 B > 49,152 B cap). With signer bytes in storage
and keys behind pointers, account initcode is small regardless of how many
PQ keys the account holds; dual-PQ accounts stop being undeployable.

**Measured (e2e-7913, anvil, 2026-08-10).** Account initcode **2,952 B**
(cap 49,152 B), account deploy **620,750** gas (vs 6.17 M via the old
factory+embedded-key route); PKContract deploy **5,324,168** gas (the 22.4 kB
expanded pk, one-time per stealth key, replaces the deployed v0.0.10's 5.2 M
`setKey`); ERC-7913 verify **~14.97 M** gas — *higher* than the old ~8.15 M
because df999ed stores `t1` plain and recomputes `NTT(t1·2^d)` inside every
`verify` (work the old flow did once at key-setup time). ERC-7913 is an
interface, not an accelerator, and this revision trades per-verify gas for
cheaper storage.

**Caveats.** The deployed verifier profile is still level-2 round-3
Dilithium, not ML-DSA-65 (D-006); the pythonref at df999ed hardwires
`pk_for_eth` to the keccak-PRNG variant, so the fixture generator inlines the
SHAKE/NIST expansion (plain `t1`); and the 3-arg `verify` forces an empty
FIPS 204 context (`M' = 0x00 || 0x00 || m`, `m` a bytes32), so PoP-style ctx
binding must move into the signed hash or a wrapper verifier.

**Open.** No published *stateless raw-key* ML-DSA-65 ERC-7913 verifier
exists anywhere (pk in calldata, no PKContract) — an unclaimed deliverable.
A ctx-binding PoP wrapper verifier and registry-v2 contract changes are
likewise deferred.

## D-015 — Hash policy: standard hashes everywhere, no arithmetization-oriented hash — **LOCKED**

Decision (2026-08-15): every hash site in the discovery design uses standard
bit-oriented hashes — **SHA-256 normative** for tag chains, announcement
accumulators and completeness proofs (EIP-8304-aligned); **SHAKE256 unchanged**
for KEM-side KDF/domain separation (FIPS 203/204 stack); BLAKE3/BLAKE2s
permitted as prover- or indexer-internal choices. No arithmetization-oriented
hash (Poseidon/Poseidon2, Vision Mark-32, Skyscraper, Monolith, Grøstl, …)
anywhere, including the circuit-heavy spend-membership path. The dual-root
accumulator of the 2026-08-05 discovery memo is dropped.

**Why.** Trigger: 2026-08-13, the EF announced it is abandoning Poseidon for
L1 ("pivoting to SHA or BLAKE", J. Drake — "the key was not SNARK-friendly
hashes, but hash-friendly SNARKs"). Two legs, both load-bearing for us:
(1) Flock-class binary-field provers (Flock eprint 2026/1329; Binius64;
binary GKR) collapsed the ~100× in-circuit penalty for standard hashes to a
single-digit per-core factor (82k BLAKE3 / 42k SHA-256 compressions/s on one
M4 Max core; 660k BLAKE3/s on 10 cores), removing Poseidon2's only advantage;
(2) the Poseidon Cryptanalysis Initiative's 2026 results (full-round CICO-2
on the KoalaBear instance via Slipway eprint 2026/1579; collision prize
paused 2026-08-01) plus resultant/FreeLunch attacks across the wider AO-hash
family (Griffin/Anemoi/Arion variants, a Rescue set — eprint 2025/259) make
any AO hash a research liability. Poseidon2 was never normative here, so this
resolves the "monitored risk" of D-013-era docs at zero code cost and makes
the discovery pipeline single-hash-family, PQ-sound from standard hashes
alone — the same assumption set lean Ethereum converges on. Full analysis:
`docs/research/hash-migration-blake2-binius.md`.

## D-016 — Hash-based commitments cannot replace the discovery KEM; the lattice (or another structured PQ KEM) is load-bearing — **FINDING**

Question (2026-08-25): can a SHA-256 / BLAKE3 commitment scheme stand in for
ML-KEM so the scheme needs no lattice assumption? Answer: **no, by theorem**,
and the argument for a structured assumption in discovery is closed.

- **Wrong shape.** A commitment's opening stays with the committer; a
  discovery step needs the *recipient* to recover a secret from a message the
  *sender* built from public data alone — a trapdoor, i.e. public-key
  structure. Any hash-only protocol is a random-oracle key exchange, and those
  are capped: n honest queries ⇒ O(n²)-query break (Barak–Mahmoody CRYPTO'09,
  tightening Impagliazzo–Rudich STOC'89); Merkle puzzles already sit at the cap.
  The cap is about the access model, so SHA-256 vs BLAKE3 is irrelevant to it.
- **Quantum makes it worse, not better.** Against a quantum eavesdropper
  Merkle's scheme with classical parties has **no gap** (Grover); the best
  known classical-party hash-only family only approaches n^{3/2}
  (Brassard–Høyer–Kalach–Kaplan–Laplante–Salvail CRYPTO'11). Hash-only key
  exchange is the one KEX family that gets *less* secure post-quantum.
- **Measured (`benchmarks/hash_kex_bench.py`, 2026-08-25).** Classical-attacker
  2^128 needs 2^64 hashes per party and a **738 EB** recipient key; even a
  2^80 budget (~17 min of the 2026 Bitcoin network) needs a 44 TB key and 64
  GPU-s per payment, with zero quantum security. ML-KEM-768: 1,184-B key,
  17.2 µs decaps, 67,700 gas, L3 against both. Scan-side hashing is 0.3–1.7 µs
  per announcement — the hash choice moves scan time <5%; the KEM decides it.
- **What hashes legitimately do.** (a) *Amortize* the KEM: pre-shared-secret
  tag chains (our §2.2 design, SHA-256 per D-015) pay the 1,088-B ciphertext
  once per relationship; the root secret still needs one PQ handshake — or an
  out-of-band channel, which is the honest "hash-only end to end" opt-out for
  pairs that have one. (b) Own spend/KDF/tags (D-008/D-012/D-015). A published
  one-time-address list is hash-only but has no unlinkability — not a stealth
  address.
- **The real comparison is ML-KEM vs structured non-lattice KEMs** (D-012):
  HQC (NIST backup, 2025-03-11; 2,241/4,433 B at L1, 2.37 ms decaps, 190 s
  per 80k scan, 201k-gas announcement), NTRU, Frodo, McEliece, CSIDH. ML-KEM
  wins on decaps and footprint. The assumption-diversity hedge, if wanted, is
  an **optional hybrid ML-KEM‖HQC parameter set** (additive cost, secure if
  either holds), not a hash construction.

Follow-ups: one Rationale sentence in the ERC citing Barak–Mahmoody so "why not
hashes" stays closed; permit out-of-band `cs` for tag chains; decide whether
to offer the hybrid set. Full analysis: `docs/research/hash-based-key-exchange.md`.

## D-011 — On-chain cost is data, not compute; announce hits the EIP-7623 floor — **FINDING**

Cost model in `python/benchmarks/onchain_cost.py`, anchored to the measured
67,580-gas Sepolia-fork announcement and reproducing it **to the gas (0.00%)**.

- **The announce tx pays the EIP-7623 calldata floor.** Its exact
  `announce(uint256,address,bytes,bytes)` calldata is 1,316 B → 4,658 tokens;
  floor `21,000 + 10·4,658 = 67,580` beats the standard cost (52,446), so the
  floor is binding. Post-Pectra, a PQ announcement is priced as *bytes*, not
  execution. EC-DKSAP (33 B point) models at 27,342 gas in the standard regime
  → PQ is **2.5× on L1** (the 21k base compresses the raw ~33× data ratio).
- **L2 dissolves the footprint tax.** Marginal L1 data cost per PQ
  announcement (dated 2026-07-28: ETH $3,200, L1 8 gwei, blob 1 gwei):
  ~$1.35 as calldata vs **~$0.004 as an EIP-4844 blob** (~320× cheaper).
  These are marginal L1 costs, not per-rollup fees (compression/margin float).
- **Meta-address registration** (ERC-6538, one-time): 5,633 B ≈ 3.79M gas
  naive SSTORE vs ~62k for EC (~61×); SSTORE2/code-blob (~200 gas/B) is the
  recommended store for a payload this size.
- **Blinded signing costs ~6× the rejection rounds** of stock ML-DSA-65
  (mean ≈30 vs ≈5, N=200, `op_bench.py`) — the `2η`-widened secrets dominate
  the `r0` check. Corrects the earlier "a handful of extra rounds" claim; a
  tighter probabilistic norm bound than worst-case `2η` would recover most.

Security-level sweep (`benchmarks/param_sweep.py`, 2026-07-28) adds a
non-obvious finding: **the blinding penalty is not monotone in the NIST
level.** Because `β' = τ·2η` and `η` is 2/4/2 across ML-DSA-44/65/87, the
**default L3 set pays the worst penalty** (blinded ≈24.8 rejection rounds,
4.5× stock) — worse than L5 (15.3, 4.0×) or L1 (14.4, 3.1×). Sizes scale
cleanly (meta-addr 3,777 / 5,633 / 7,489 B; sig 2,420 / 3,309 / 4,627 B) and
scan cost tracks ciphertext size (27.8 / 43.7 / 66.5 µs/ann). A view-tag
sweep (`viewtag_sweep.py`) confirms 1 byte is near-optimal for native
clients: at 1/256 the false-positive derivations are negligible in native
code (~µs each); longer tags only pay off when derivation is the bottleneck
(slow/pure-Python scanners), and cost ~nothing on-chain.

Baseline decision: **DKSAP is the only EC baseline; Curvy is dropped.** DKSAP
(plain-ECDH secp256k1) is the EC scheme ERC-5564 actually deploys, so it is
the honest apples-to-apples bar for detection cost. The paper's 66.8% headline
is vs Curvy (pairing-based), which nobody runs — comparing to it flatters the
result. We measure against DKSAP everywhere (scanning `scan_bench.py`, on-chain
`onchain_cost.py`) and do not carry a Curvy number.

## Open items — **OPEN**

- Security analysis of construction A (widened-`z` leakage; unlinkability;
  the Dilithium-like signature-of-knowledge in D-008). Fellow A's core work.
- Spec freeze + ERC draft + registered scheme ID (placeholder `0x5567`).
- Cost report: **L2 pricing + ~5.6 kB meta-address story DONE (D-011)**;
  DKSAP is the single EC baseline (Curvy dropped, D-011).
- NTT-domain + negacyclic + centered-range version of the ownership circuit.
