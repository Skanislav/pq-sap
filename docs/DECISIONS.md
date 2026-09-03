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

pq.ethereum.org and ethereum.org/roadmap/security/quantum-resistance (April 2026)
designate **account abstraction** as the mechanism for the PQ signature
transition ("transition to quantum-safe authentication through account abstraction,
without a disruptive flag day"), with post-quantum signature schemes expected to
become available following the Hegotá hard fork and EIP-8141. Our ERC-4337
stealth-account spend path uses the same mechanism — the project maps onto the
official roadmap rather than beside it. The roadmap's execution milestone **J\***
is a **vector-math precompile** that will make on-chain lattice signature
verification cheap; the target is core PQ infrastructure by approximately 2029,
with full execution-layer migration extending beyond that. Application-layer
ZK-proof migration is **not** covered by the roadmap — the ZK direction here
(D-008) is genuinely novel territory.

**Watch item (2026-08-26):** the ACDE call on 2026-08-27 is expected to decide
between EIP-8141 and EIP-8130 for Hegotá account abstraction. Update this entry
and `plan.md` once the call minutes land.

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

## D-012 — Discovery-only scope with ZK spend decouples the KEM; lattice wins discovery on decaps — **FINDING / stretch**

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

Status (2026-08-26): parked as **future work**. The exact ZK-spend
address-binding that lets the meta-address drop the `t` is unproven, so the
compact `version ‖ commitment ‖ ek` format is not normative for this ERC. The
Lean roundtrip for that format stays in `Invariants.lean` as a documented
variant.

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
- **VCVio already ships the assumption layer definitions**: `LearningWithErrors`
  (LWE/MLWE, decision + search), `ShortIntegerSolution` (MSIS +
  SelfTargetMSIS), and a `K-PKE IND-CPA ≤ MLWE` lemma. The latter is a
  `sorry` placeholder at the pinned VCVio commit — see `lean/README.md` and
  `lean/PqStealth/MLKEM.lean`. No new MLWE formalization was needed for our
  reductions to land on VCVio's definitions. (Their `ind_cca_security` is
  also a self-flagged placeholder; we do not lean on it.)
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

**Update (2026-08-27).** Added `Soundness.UniformCoordinate` with `card_fiber_eval'`
and `probOutput_map_get_uniformSample_vector`: a coordinate projection of a uniform
vector is uniform, giving a generic `1/|α|` view-tag fallback when the tag is a direct
function of a vector-shaped shared secret. `Axioms.lean` now freezes **118**
`#print axioms` blocks. Full `lake build` remains green and sorry-free.

**Update (2026-08-26).** The game layer expanded from the original five
modules to 18 content modules plus the root and `Axioms.lean`. The full
`lake build` remains green and sorry-free. `PqStealth/Axioms.lean` now
freezes **114** `#print axioms` blocks (up from 95 after round 3/4 added
`MultiUnlink`, `MultiRecipient`, `KEMAnonymity`, `ConstructionA`,
`BlindingROM`, `ROMUpToBad`, `SharedSecretHiding`, `AnonymityFromSPR`,
`MLKEM`, `SPRTwoHop`, `Ownership`, `Soundness`, `DKSAPOracle`, `Controls`,
`Demo`, and the renamed theorems). The build is the guard: a `sorry`
under any headline theorem's dependency cone turns the axiom mismatch into
a compile error. A full module map and the iteration queue live in
`docs/lean-iterations.md`.

## D-014 — Spend and registry authentication standardize on ERC-7913 signers — **LOCKED (interim; re-scoped by D-020)**

*Scope update (2026-08-31):* with EIP-8141 frame transactions SFI'd for
Hegotá, ERC-7913 is the **interim** spend/registry encoding (pre-Hegotá
chains and L2s without type `0x06`), not the destination — see D-020. The
measurements and the EIP-3860 finding below stand.

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
to offer the hybrid set (→ resolved in D-017: yes, and it is X-Wing, not
ML-KEM‖HQC). Full analysis: `docs/research/hash-based-key-exchange.md`.

## D-017 — Optional PQ/T hybrid parameter set: X-Wing replaces NTRU/HQC as the named hedge; default stays ML-KEM-768 — **LOCKED**

Question (2026-08-27): should the ERC offer a hybrid (PQ/T) discovery-KEM
parameter set against a *classical* break of Module-LWE, and which one?
Decision (user, 2026-08-27): **yes, as optional** — X-Wing
(X25519 + ML-KEM-768, bit-identical to CFRG's MLKEM768-X25519). The default
set is unchanged.

- **Best-value second assumption, measured** (`benchmarks/xwing_bench.py`,
  validated against the official draft test vectors byte-identically):
  hybrid decaps 48 µs (ML-KEM 17.2 + native X25519 30.2 + SHA3-256 0.6) →
  3.84 s per 80k scan — a 2.8× tax that is still *faster than every
  non-MLWE family we measured*, including the previous NTRU hedge
  (NTRU-HPS-2048-677: 4.19 s). Footprint: pk 1,216 B (+32), ct 1,120 B
  (+32, announce ≈ +1.8% gas at the EIP-7623 floor), decapsulation key =
  one 32-byte seed. The classical leg dominates the hybrid's scan cost —
  X25519 is ~1.8× the ML-KEM decapsulation.
- **Honest security scope (the reason the pitch must be worded carefully).**
  For parallel hybrids, ciphertext ANONYMITY is an AND of the components
  (both ciphertexts are visible), unlike IND-CCA's OR — stated explicitly
  in Bao–Pan, "Anonymity of X-Wing and its Variants" (PKC 2026, eprint
  2026/396), the first anonymity analysis of X-Wing. The X25519 ciphertext
  is an ephemeral public key — unconditionally weakly anonymous, an
  anonymity free-rider — so X-Wing's anonymity *equals ML-KEM's, full
  stop*. Consequence for us: the hybrid hedges the **shared-secret-hiding
  terms** of the Lean decomposition (view tag + derived stealth address
  become "MLWE OR strong-DH", per X-Wing's IND-CCA theorems, eprint
  2024/039) but **not the SPR/anonymity term** — announcement↔meta-address
  unlinkability keeps its single point of failure in ML-KEM ciphertext
  anonymity. Not "DKSAP-grade privacy if lattices fall." Against the HNDL
  quantum adversary the hybrid is exactly neutral (Shor kills the X25519
  leg; degrades to the default scheme).
- **Why X-Wing and not ML-KEM‖HQC** (corrects D-016's closing suggestion):
  the QSF combiner shape requires the PQ leg to be C2PRI (ciphertext
  second-preimage resistant), which **HQC fails** (Starfighters, eprint
  2025/1397; Krämer et al. 2025/1416) — HQC cannot be the second leg of an
  X-Wing-style combiner, on top of its 138× scan tax. NTRU keeps only a
  footprint edge and has no combiner spec, no anonymity analysis, and
  slower scans.
- **Standards/deployment footing**: draft-connolly-cfrg-xwing-kem-10 (not
  an RFC), but bit-identical MLKEM768-X25519 sits in
  draft-irtf-cfrg-concrete-hybrid-kems and draft-ietf-hpke-pq (IANA HPKE
  KEM 0x647a); Apple CryptoKit ships it (iOS/macOS 26); BoringSSL, CIRCL,
  filippo.io, RustCrypto, libcrux implement it; NIST SP 800-227 (final,
  2025-09) blesses the combiner shape. Not in liboqs/OpenSSL — irrelevant
  to us; both our stacks compose it from parts we already carry.
- **Normative consequences imported into the ERC**: hybrid meta-address
  version `0x02` with the 1,216-B X-Wing encapsulation key;
  `ephemeralPubKey` = 1,120-B X-Wing ciphertext; the decapsulation key
  MUST be stored/exchanged only as the 32-byte seed (X-Wing's
  MAL-BIND-K-{PK,CT} properties fail for expanded keys — Schmieg, eprint
  2024/523); the ML-KEM encapsulation-key check MUST run (X-Wing draft
  §Encapsulation). Everything downstream of `ss` (blinding derivation,
  view tag, scanning) is unchanged.
- OR-anonymity hybrids exist (nested/obfuscated combiner, Günther et al.
  CRYPTO 2025, eprint 2025/408: Elligator/Kemeleon encodings) but are
  research-grade with no spec — documented, not offered.

Follow-ups: add the hybrid vectors to the conformance set when the set is
implemented; Lean instantiation note — an SPR simulator for the X25519
component must sample a random *curve point*, not uniform bytes (curve
membership is distinguishable at ~1/2). Full analysis:
`docs/research/xwing-hybrid-kem.md`.

## D-018 — SPHINCS- C13 (hash-based) as an ERC-7913 spend signer: Verity-verified verifier vendored, two signer forms, spend-time linkability stated — **FINDING / option**

Question (2026-08-27, user): implement the Verity Labs SPHINCS- verifier
(https://veritylabs.dev/research/sphincs-minus-verifier) for spending.
Done (branch `worktree-sphincs-minus`): what was vendored, what it costs,
and where a hash-based key can honestly sit in this scheme.
*(Scope update 2026-08-31, D-020: the ERC-7913 wrapper is the interim
carrier; under EIP-8141 the same C13 verifier is called from the account's
VERIFY frame code. The commitment construction and the linkability finding
are carrier-independent and stand.)*

- **What was vendored.** `lfglabs-dev/SPHINCS-` `src/SPHINCs-C13Asm.sol`
  @ `2a40d0a` — byte-identical, sha256 recorded in
  `js-client/contracts/src/vendor/sphincs-minus/VENDORED_REV.txt` (the
  write-up prints the commit hash with a typo in its tail; the repo's HEAD
  is the object we pin). SPHINCS+ "+C" variant (WOTS+C / FORS+C grinding,
  ePrint 2025/2203): n=16, h=22, d=2, a=19, k=7, w=8, l=43, target sum 208,
  keccak256 over the FIPS 205 §11.2.2 uncompressed ADRS, 3,688-B signature,
  128-bit up to a 2^22-signatures-per-key cap (upstream's table). Verity
  Labs' Lean refinement (`c13_refines_spec`: EVM model → `verifyBytes` →
  `verifyParsed`; `propext`/`Classical.choice`/`Quot.sound` plus the
  residual assembly bridges in their AXIOMS.md) covers exactly this file.
  Compiled under upstream's settings (via-IR, 200 runs) through a per-path
  `compilation_restrictions` profile; nothing else in the tree changes
  profile. Upstream posture: research prototype, not audited; its own
  agent-assisted review flags a public-grindable message randomizer `R`
  (the few-time bound is unproven in-repo). Not FIPS 205.
- **Two ERC-7913 signers** (`js-client/contracts/src/SphincsC13Signer7913.sol`),
  both stateless, 52-byte signer strings (`verifier || key`), never
  reverting on well-typed input (lengths checked, key words built
  top-aligned so the verifier's two revert paths are unreachable; every
  soundness failure is a uniform `0xffffffff`):
  - **raw key**: `key = pkSeed[0:16] || pkRoot[0:16]`, `sig` = the 3,688-B
    C13 signature. For keys that are public anyway — the D-014 registry-
    authentication ratchet, an account co-signer / recovery key, or the
    key behind a D-012 ZK-bound stealth address.
  - **commit**: `key = keccak256("pq-stealth/sphincs-c13/commit/v0" || pk || opener)`,
    `sig = pk || opener || c13sig` (3,752 B),
    `opener = SHA-256("pq-stealth/sphincs-c13/open/v0" || ss)` (a
    derivative of the shared secret, never `ss` itself, so opening leaks
    no view-tag material). This is the form that gives a hash-based key a
    **sender-derivable** stealth address: the sender knows `pk` (a
    hash-based-spend meta-address would carry the 32-B key) and `ss`, so
    it can form the commitment → account initcode → CREATE2 address.
- **Measured (anvil, `npm run e2e-7913-sphincs`, 2026-08-27).** Verifier
  deploy 310,750 gas; raw C13 `verify` ≈ **188,092** tx-level (upstream's
  Sepolia figure: 188,278 — the vendored bytecode behaves as documented);
  ERC-7913 raw-key wrapper ≈ 194,768; commit form ≈ 196,973; account
  deploy 620,894 (initcode ≈ 2,984 B). Against the ML-DSA ERC-7913 route
  (D-014, ≈ 14.97 M): **≈ 77× cheaper per verify**, and no PKContract
  (the 5.3 M one-time key deploy disappears — the key is 32 bytes in the
  signer string). Signature 3,688 B vs 3,309 B (+11 %); signer 52 B vs 40 B.
- **The finding that governs placement.** Hash-based keys have no key
  homomorphism, so the sender cannot derive a per-payment public key
  (D-016; `hash-based-key-exchange.md` row B). The commit form recovers
  sender-side address derivation, but a spend *opens* the commitment on
  chain: `pk` is the recipient's registered key, so from the first spend
  every **spent** address of that recipient is linkable to the recipient
  (unspent addresses stay unlinkable — `ss` is 256 bits of KEM output and
  the commitment hides). Blinded ML-DSA has no such identifying event.
  So SPHINCS- is the right spend signer for (a) registry authentication,
  (b) co-signer / recovery, (c) the key *behind* a D-012 ZK ownership
  proof — where a keccak/hash-preimage STARK is what makes the spend side
  lattice-free end to end — and (d) a documented **linkable-on-spend
  option** for users who take ≈ 77× cheaper spends over spend-time
  unlinkability. It is not a replacement for construction A as the
  default. The ERC draft's informative spend section now says this.
- **Conventions and reproducibility.** Byte conventions live in
  `js-client/src/sphincs.ts` and `python/scripts/sphincs_c13_7913_demo.py`
  (fixture generator: a real ML-KEM-768 exchange with fixed seeds, the
  recipient's C13 seed material = `SHA-256("pq-stealth/sphincs-c13/keygen/v0" || spend_seed)`
  fed to upstream's Rust `signer-c13 keygen` (0.2 s) and `sign-with`;
  the R / counter grinds are deterministic in `sk_seed`, verified
  byte-identical on re-run). The e2e re-derives opener and commitment in
  TypeScript, asserts equality with the fixture and with the contract's
  `commitment()`, and runs the negative cases (wrong hash, tampered `R`,
  tampered auth path, short sig, wrong root, wrong key length, wrong
  opener, cross-form signatures) expecting `0xffffffff`, never a revert.
- **Caveats carried.** One C13 key across all of a recipient's stealth
  addresses draws on one 2^22 budget — a wallet MUST count signatures;
  the bare ERC-7913 `verify` has no ctx (as in D-014, PoP binding goes in
  the hash); H_msg takes the 32-byte hash directly (no envelope); the
  Verity proof is of the Solidity/Yul model, not of solc's output.

- **Pointer-signature form (same day, user: "pack the key as ecrecover").**
  Because the C13 key is one word, the `(v, r, s)` pointer trick of
  `docs/pointer-signatures-poc.md` needs no key table: `v = 0x52`, `r` = the
  key, `s` = signature index → address `keccak256(r)[12:]`; `v = 0x53`,
  `r` = the commitment above → a stealth address in plain address shape
  that the sender computes without any account. Measured
  (`npm run e2e-pointer-sig`): `withdrawWithSig` 0x52 **182,799** / 0x53
  183,237 vs classic 92,555 (2.0×) and ML-DSA `recover` ≈ 15.19 M;
  publishing the signature ≈ 0.9 M. **Constraint stated late and now
  written into the POC doc:** `recover` authorizes spends *inside adopting
  contracts*; `keccak256(r)[12:]` cannot hold ETH or tokens itself, so this
  is a spend-authorization shim for value already held by pointer-aware
  contracts, not a stealth-receive mechanism — an ERC-5564 payment to a
  bare address still needs the CREATE2 account route. The user reads the
  spend-time linkability as a feature (the spend is an explicit, auditable
  identification event) rather than a defect; recorded as such.

Follow-ups: a meta-address version carrying the 32-B C13 key (hash-based-
spend variant); link the Lean side — Verified-zkEVM/VCVio main ships a
pure-Lean C13 (`HashSig/SLHDSA/C13`) with a KAT against this very verifier,
which would let `lean/` state the spend-side assumption as a hash-only
EUF-CMA term; decide whether the linkable-on-spend option is offered in
the ERC beyond the informative paragraph.

## D-020 — Spend targets EIP-8141 frame transactions; ERC-7913/ERC-4337 become the interim route — **LOCKED**

Decision (2026-08-31, user): stop designing the spend path around ERC-7913
signer contracts and ERC-4337 accounts as the destination. EIP-8141
("Frame Transactions", tx type `0x06`) was moved from CFI to **SFI for
Hegotá** on ACDE #244 (2026-08-27), so protocol-native account abstraction
is the scheduled substrate and the spend design is expressed against it.
(D-019 is allocated on the tagchain branch — SHAKE256 tag chains.)

**What EIP-8141 gives this scheme natively.** A frame transaction splits
into VERIFY frames (read-only validation run as the sender) and EXECUTE
frames; the account is literally an address with code, and validation is
arbitrary EVM code ending in `APPROVE` (opcode `0xaa`). The pieces that map
onto our stack:

- **Signature carriage.** The `ARBITRARY (0x0)` signature scheme carries
  the PQ signature in the transaction's `signatures` array (100 gas
  intrinsic; raw bytes are EVM-introspectable via `SIGDATACOPY` *only* for
  arbitrary-scheme entries). The account's VERIFY code calls the same
  vendored verifiers we already measure — `SPHINCs-C13Asm` or
  ETHDILITHIUM — directly. The ERC-7913 `verifier || key` indirection
  stops being load-bearing; the verifiers survive as libraries.
- **Counterfactual receive.** The mempool-recognized validation prefix
  `[deploy, self_verify]` deploys the account at `tx.sender` in the same
  transaction (deterministic factory, e.g. the EIP-7997 predeploy) — the
  announced stealth address is the counterfactual frame-tx account
  address. This replaces the CREATE2 + EntryPoint + bundler dance;
  `ENTRY_POINT (0xaa)` is a protocol constant, not deployed code.
- **Native sponsorship.** `[deploy, only_verify, pay]` is a recognized
  prefix: a paymaster frame pays gas so the stealth account spends only
  the value it holds. This natively removes both the AA21-prefund problem
  and the privacy leak of funding gas from a linkable EOA — the whole
  reason the Pimlico integration exists.

**What survives from D-014/D-018.** The EIP-3860 lesson stands (keys never
go in initcode; the deploy frame stays small, key or pointer in account
state). The D-018 commit-signer construction and its linkable-on-spend
trade-off are unchanged — they are about key derivation, not the account
standard. ERC-7913/4337 remain the *interim* route: chains before Hegotá,
and L2s that do not adopt type `0x06`. D-014 is re-scoped accordingly.

**The new hard constraint — validation gas.** Public-mempool admission
simulates the validation prefix under `MAX_VERIFY_GAS = 100,000` execution
gas (500,000 state gas), with storage reads limited to the sender.
Measured against that budget: C13 verify is 188,092 gas tx-level (≈166k
net of intrinsic + calldata) — **even the cheapest PQ verifier we have
does not fit the default mempool prefix**, and ML-DSA at ~15 M is out by
two orders of magnitude. Protocol-validated schemes exist for SECP256K1
(2,800 gas) and P256 (6,700 gas) but no PQ scheme has an identifier.
Consequences: (a) near-term PQ frame-tx spends ride builder/private
inclusion, not the public mempool; (b) **WG feedback item the user can
bring**: a protocol-validated PQ signature id (SLH-DSA/ML-DSA) or a
raised/negotiable verify budget is what makes PQ stealth spends
first-class citizens of the `0x06` mempool. Also to check against the
final spec: whether `EXTCODECOPY` of an immutable key blob at another
address (the SSTORE2/PKContract pattern) is admissible in the validation
prefix, or whether key material must live in the sender's own code/storage.

**Repo impact.** `docs/erc-draft.md` spend sections reframed: frame-tx
account model is the target, ERC-7913 demoted to the interim expression
(still informative, `requires` unchanged). The 4337 contracts, EntryPoint
wiring, bundler/Pimlico paths in `js-client/` and `ui/` are kept as the
working interim demo, not extended further. Open: a `Stealth8141Account`
sketch (VERIFY code calling C13/ML-DSA + APPROVE) once client devnets
expose type `0x06`.

## D-021 — Frame-tx nonce independence: expiring nonces for the spend, keyed nonces only where a nullifier is real — **FINDING / direction**

Two Draft EIPs landed after D-020 and change its inherited replay model —
EIP-8141's single linear sender nonce. Full analysis and citations in
`docs/research/keyed-nonces-as-nullifiers.md`.

- **EIP-8250 (Keyed Nonces, Draft 2026-04-16)** replaces `nonce` with
  `(nonce_keys, nonce_seq)`; non-zero keys get permanent slots in the
  `NONCE_MANAGER` predeploy at `keccak(pad32(sender) ‖ bytes32(key))`, and
  consumption is tied to EIP-8141's payment-approval step. Its own Rationale
  offers this to "single-use-key applications, such as nullifiers" as an
  atomic spent-once guarantee.
- **EIP-8266 (Expiring Nonces, Draft 2026-05-15)** replaces the nonce with a
  ≤60 s deadline plus a `2^18`-slot ring buffer: `EXPIRING_NONCE_GAS = 13,000`
  flat, **zero net state growth**, and nodes MAY admit multiple pending
  transactions per sender.

**Finding: we need freshness, not a nullifier.** A nullifier exists because a
note is a commitment nothing on-chain stops you presenting twice. pq-sap has no
notes — value is native ETH at an account, and the balance is the double-spend
defence. So the mainline construction-A spend should take **8266** (13,000 gas,
no permanent state) rather than **8250** (`KEYED_NONCE_FIRST_USE_STATE_GAS =
97,920` state gas and one permanent slot *per payment, forever* — the wrong
direction for a project whose headline cost finding is D-011's "cost is data").
8250 is the fallback if the 60 s deadline is too tight for pre-signed spends,
and the right tool only where the authorization is detachable from the balance.

**What it fixes: the sponsor.** `Stealth8141Account` is not the tx `sender` — a
sponsor EOA is (the demo's in-page throwaway key), so today's spend carries a
unique public sender that must be funded from somewhere, and every sponsored
spend serializes on one nonce (`ui/src/lib/frames.ts` `pendingNonce`, "rapid
back-to-back frame txs collide on `latest`"). EIP-8250's Rationale names this
case exactly. Either EIP unblocks a **shared public sponsor**: one funded
account carrying every stealth spend, each in its own replay domain, nothing for
the recipient to fund. This completes D-020's gas-funding-privacy item —
paymaster frames fix *who pays*, nonce independence fixes *whose nonce orders
the transaction*. Note what happened: ERC-4337 got this free (the bundler is the
on-chain sender), EIP-8141 gave it up with the bundler, and these EIPs give it
back. No contract change is needed for binding — EIP-8141's `sig_hash` is keccak
over the RLP body and 8250 replaces the `nonce` field *inside* it, so
`executeFrame`'s existing `FRAME_CTX.sigHash()` check already authenticates
`(sender, nonce_keys_hash, nonce_seq)` as 8250 asks. `frame-tx/serialize.ts`
would need the new body layout, but it tracks *deployed* ethrex, so not yet.

**What it does for generation.** A ZK spend (D-008/D-012) owes (a) address
binding and (b) non-replay. Under construction A (b) was free and invisible — the
one-time account's own nonce serialized it. A keyed nonce discharges (b) at the
protocol layer for the price of picking a key. This does **not** unpark D-012:
(a) is the harder half and is untouched. But the variant should now be costed as
"binding + one `nonce_key`", not "binding + a nullifier subsystem", with D-012's
prize unchanged (meta-address 5,633 B → 1,217 B; KEM decoupled from spend).

**Security rule — nonce keys MUST NOT derive from `ss`.** `nonce_keys` are public
payload fields (`TXPARAM 0x0F`/`0x10`) and consumed slots are permanent public
state. In a stealth scheme the *sender* computes `ss`, so `k = H(ss)` hands every
payer a permanent, publicly checkable "has my payment been spent, and where"
oracle. Scoped honestly: in today's construction-A shape this is *cheaper*
lookup, not new information — the payer knows the stealth address and watches
value leave it, and a shared sponsor mixes the `sender` field without hiding
that value edge. It becomes decisive where the nonce key is the **only** public
per-payment tag: the pooled/ZK-spend variant, or any separate entitlement draw
(a gas-bank draw is exactly this shape). The rule is free, so adopt it
unconditionally rather than when the variant that needs it arrives. Required
derivation:

```
k = SHAKE256("PQSAP-nonce-key-v1" ‖ K_null ‖ ct)  truncated to 256 bits, k != 0
```

with `K_null` a **nullifying key** from the recipient's master seed under its own
domain separator (sender-uncomputable), and `ct` the announcement ciphertext
(public, per-payment, no new bytes). Domain separation and `k != 0` are 8250's
own MUSTs; **sender-uncomputable is ours** — 8250 has no party that knows the
payment secret and is not the spender, so its Security Considerations do not
state it. Spec consequence: a third key beside detection (`dk`) and spend, with
viewing-key disclosure semantics — anyone holding `K_null` can read every
payment's spent flag retroactively; a watch-only export must omit it. Free side
effect for the owner: `slot(sender, k)` answers "which payments are unspent" with
a storage read instead of a transfer scan.

**Budget impact on the D-020 ask.** Neither EIP touches `MAX_VERIFY_GAS`
(100,000 execution), but 8250 spends 97,920 of the prefix's 500,000 **state** gas
per fresh key — a fifth, before validation begins, capping the prefix at ≤5 fresh
keys. The working-group ask therefore grows a second half: alongside a
protocol-validated PQ signature identifier or a raised execution budget, the
*state* budget must accommodate a first-use keyed nonce next to a PQ verification.

**Not fixed:** verification cost (D-007/D-020), announcement size (D-011), the
value graph (a shared sponsor mixes sender and gas-funding edges only — value
still leaves a unique stealth address), per-address deployment (D-014/D-020).
Both EIPs are Draft and unscheduled; EIP-8141 itself is only SFI for Hegotá.

Follow-ups: fold the derivation rule and `K_null` into `docs/erc-draft.md` and
the key hierarchy before the ERC freeze; adopt the shared-sponsor shape in
`ui/`/`js-client/` when a chain exposes either mode; carry both WG items
(sender-uncomputable in 8250's Security Considerations; state gas in the D-020
ask) to the authors.

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
- Spec freeze + ERC draft + declared scheme ID `2` (placeholder `0x5567` retired).
- Cost report: **L2 pricing + ~5.6 kB meta-address story DONE (D-011)**;
  DKSAP is the single EC baseline (Curvy dropped, D-011).
- NTT-domain + negacyclic + centered-range version of the ownership circuit.
- Hash-based spend (D-018): remove spend-time linkability by binding the
  SPHINCS- key through the D-012 ZK ownership proof instead of an opened
  commitment; meta-address variant carrying the 32-B C13 key.
