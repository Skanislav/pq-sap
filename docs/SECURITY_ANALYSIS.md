# Security Analysis

Status: pre-freeze working draft for the post-quantum ERC-5564 stealth address scheme.
Every displayed bound below is either a theorem in `lean/PqStealth/ConstructionASecurity.lean`
(or one of its dependencies) or an explicitly named assumption record.
No claim is unconditional unless the statement says so.

---

## Notation

- `Adv_unlink` — single-announcement unlinkability advantage for Construction A.
- `Adv_unlink_q` — `q`-announcement unlinkability advantage against two fixed recipients.
- `Adv_relatedSpend_q` — related-key EUF-CMA advantage for `q` derived stealth keys.
- `qH` — number of adversarial queries to the address-hash random oracle.
- `qS` — number of signing-oracle queries in the related-key game.
- `epsilonBlindExpand` — bound on `ConstructionA.ExpandIsIdeal` (joint view tag / blinding pair).
- `Adv_blindMLWE` — seeded decision-MLWE advantage against the blinding sampler.
- `betaAddr` — point-mass bound for one address-point guess (`BlindPointMassBound`); for ML-DSA
  proven as `((2^d : ℝ≥0∞) / MLDSA.modulus) ^ (k * 256)` (`blindPointMassBound_mldsa`, ML-DSA-65:
  `blindPointMassBound_mldsa65`) when the primitive's `power2Round` is the concrete coefficient-wise
  `Power2Round` and `pack rho` is injective.
- `epsilonPrim` — primitive-idealization loss in the SPR decomposition (ROM/PRF assumption).
- `epsilonEnc` — encoding-regularity loss in the SPR decomposition.
- `Adv_keyHop_b`, `Adv_ctHop_b` — seeded-MLWE advantages for the two SPR hops.
- `Adv_keyRestore_b` — the key-restoration gap; by `keyRestoration_le_mlwe_add_keyIdealization` it is
  at most the seeded-MLWE advantage of `keyRestorationAdv` plus `keyIdealization` (the ROM/PRF step
  for key generation alone).
- `Adv_maskIdealization` — distance between deterministic `expandMask` and independent mask draws.
- `zetaWide` — `widenedHvzkDistance` for the widened ML-DSA identification scheme.
- `delta` — commitment-regularity failure bound.
- `Adv_spendForge(b)` — `spendForgeryAdvantage` at shortness bound `b`: forging an ownership witness
  for the master stealth key (`Ownership.lean`; equal to a matrix-SIS advantage).
- `CmaToNmaLossNN` — classical-ROM CMA-to-NMA statistical loss (signature layer; defined, not composed).
- `TruncationLossNN` — loss from capping the signer at `maxAttempts` retries (signature layer).
- `UnboundedSigningAssumption` — bridge from the production unbounded loop to the capped game.

---

## 1. Single-announcement unlinkability

The Construction A unlinkability experiment is `StealthScheme.unlinkAdvantage` instantiated at
`ConstructionA.scheme` (`ConstructionA.lean`).  The faithful announcement model is
`StealthScheme.ofKEMFull` (`KEMAnonymity.lean`), with the four-term decomposition

```
Adv_unlink ≤ sharedSecretHiding_true + auxKeyIndependence + KEM.anonAdvantage + sharedSecretHiding_false
```

stated as `ConstructionA.unlinkAdvantage_scheme_le` (`ConstructionASecurity.lean`). The full closed bound is `PqStealth.ConstructionA.unlinkAdvantage_full_bound`.

### 1.1 Shared-secret hiding = IND-CPA

`sharedSecretHiding` is exactly the VCVio KEM IND-CPA advantage for the underlying ML-KEM instance.
For ML-KEM-768 this is reduced to the SPR terms below; the IND-CPA advantages themselves remain
named hypotheses until a sound KEM-level FO-to-MLWE theorem is available in the pinned VCVio tree.

### 1.2 From KEM anonymity to SPR

`KEM.anonAdvantage_le_sprAdv` bounds the KEM anonymity term by two per-branch SPR advantages against
a key-independent simulator.  The SPR term decomposes in `SPRTwoHop.lean` as

```
KEM.sprAdv ≤ epsilonPrim + Adv_keyHop + Adv_ctHop + epsilonEnc + Adv_keyRestore
```

per branch, where the two MLWE hops are exact game identities and the three remaining terms are named
assumption records (`primitiveIdealizationBound`, `encodingRegularityBound`, `keyRestorationMLWE`).
The generic theorem is `PqStealth.sprAdv_le_mlwe` and the ML-KEM-768 instance is `PqStealth.mlkem768_sprAdv_le_mlwe` (both `SPRTwoHop.lean`).

### 1.2a Widened signing mask acceptance

The widened identification scheme (`MLDSA.widenedIdentificationScheme`, `WidenedSigning.lean`) draws
the mask `y` uniformly from the FIPS 204 cube `[-(γ₁-1), γ₁]` (`sampleMaskCube`) and widens both
response gates to `‖z‖∞ < γ₁ - β'` and `‖r₀‖∞ < γ₂ - β'` with `β' = 2·β`. Its key relation
`widenedValidKeyPair` requires the public-key identity `t₁·2^d + t₀ = A·s₁ + s₂` and each secret
vector to be a sum of two `η`-short vectors, which the blinded key `(s₁+s', s₂+e')` satisfies
(`widenedValidKeyPair_blinded`). Under `Primitives.Laws` the scheme is complete
(`MLDSA.widened_ids_complete`).

The accepted-`z` probability is exact and independent of the secret: for any shift `‖δ‖∞ ≤ β'`,
a cube-uniform mask passes the `z` gate with probability `((2·(γ₁-β')-1)/(2·γ₁))^(l·256)`
(`MLDSA.cube_shift_accept_prob`, instantiated at `δ = c·s₁` as
`MLDSA.widened_z_accepted_independent`). The ML-DSA-65 value is
`MLDSA.mldsa65_widened_z_accept_prob`. All of these are sorry-free and guarded in `Axioms.lean`.

### 1.3 Blinding and ROM query bound

`auxKeyIndependence` for Construction A is bounded in `BlindingROM.lean` and `BlindingEntropy.lean` by

```
auxKeyIndependence ≤ epsilonBlindExpand + Adv_blindMLWE + 2 * qH * betaAddr
```

where `BlindPointMassBound` captures the min-entropy of `pack rho (power2Round (u + t))` on a uniform
mask `u`.  The ROM part is proven sorry-free: for an adversary making at most `qH` address-oracle
queries (`IsQueryBoundP … qH`) and a point-mass bound `beta ≠ ⊤`,
`PqStealth.ConstructionA.probOutput_blindBadQuery_le` / `blindBadProb_le_queryBound` give
`blindBadProb b ≤ qH * beta` per branch (tracking flag = point cached, at most `qH` cache keys, union
bound over the keys — `ROMUpToBad` § query budget), and
`PqStealth.ConstructionA.blindingAdvantageRO_le_queryBound` yields the `2 * qH * beta` term.

The final single-announcement bound is

```
Adv_unlink ≤ INDCPA_true + INDCPA_false + epsilonBlindExpand + Adv_blindMLWE + 2*qH*betaAddr
             + Σ b∈{false,true}, (epsilonPrim + Adv_keyHop_b + Adv_ctHop_b + epsilonEnc + Adv_keyRestore_b)
```

as `PqStealth.ConstructionA.unlinkAdvantageMulti_full_bound`.

---

## 2. q-announcement unlinkability

For `q` announcements to the same two recipients, `MultiUnlink.lean` gives the generic hybrid bound
`unlinkAdvantageMulti_le_mul`.  Instantiating the per-hybrid single-announcement bound above yields

```
Adv_unlink_q ≤ q * epsilonSingle
```

where `epsilonSingle` is the right-hand side of the single-announcement bound.
This is `ConstructionA.unlinkAdvantageMulti_full_bound`.

---

## 3. Related-key spend security

All of a recipient's stealth keys derive from one master ML-DSA key `(A, t = A·s₁ + s₂)`:
announcement `i` adds a blinding offset `(s'ᵢ, e'ᵢ)` and the derived key is
`tᵢ = t + A·s'ᵢ + e'ᵢ`. A malicious sender knows the offsets it created. The related-key game
(`SpendSecurity.lean`, `relatedSpendRun` / `relatedSpendAdvantage`) therefore gives the adversary the
master public key and all `q` offsets, and it wins by producing a valid spend witness — a short
`(s, e)` with `A·s + e = tᵢ` — for any derived key `i`. This is the search-witness model of
`Ownership.lean`; the signature-of-knowledge layer on top of it is the follow-up noted there (§4).

The spend bound is proven, sorry-free:

```
Adv_relatedSpend_q ≤ Σᵢ Adv_relatedSpend_at(i)            (union bound over the targeted key)
                   ≤ q * max_i Adv_spendForge(b + η)[reductionᵢ]
```

where `reductionᵢ` (`relatedSpendReduction`) samples the offsets itself, runs the adversary, and
subtracts offset `i` from the returned witness: a `b`-short witness for `tᵢ` minus an `η`-short
offset is a `(b + η)`-short witness for `t` (`ownershipValid_subtractOffset`,
`mldsaShort_subtractOffset`). The theorems are `relatedSpendAdvantage_le_sum`,
`relatedSpendAdvantage_le_mul`, `relatedSpendAdvantageAt_le_spendForgery`,
`relatedSpendAdvantage_le_mul_spendForgery`, and at `Rq` with the ML-DSA range check
`mldsa_relatedSpendAdvantage_le`, re-exported as
`PqStealth.ConstructionA.relatedSpendAdvantage_le_mul_capstone` (`ConstructionASecurity.lean`).
`Adv_spendForge` is in turn a matrix-SIS advantage (`mldsa_spendForgeryAdvantage_eq_sis_advantage`).

Not yet composed — the signature layer. The deployed spend is a Fiat-Shamir-with-aborts signature
over the ownership relation, and its EUF-CMA reduction to the game above costs

- `CmaToNmaLossNN` — the classical-ROM statistical loss `FiatShamirWithAbort.cmaToNmaLoss`, as a
  nonnegative real under `CmaToNmaAssumption` (`CmaToNmaLossNN_val`);
- `TruncationLossNN = qS * pAbort ^ maxAttempts` — the loss from capping signer retries;
- `UnboundedSigningAssumption` — the bridge from the production `while True` signer to the capped game.

These are defined in `SpendSecurity.lean` §6 but nothing consumes them: VCVio's `euf_cma_bound` is a
placeholder at the pin, and the widened-scheme HVZK distance is still the trivial `1`.

---

## 4. Construction A / B decision

**D-021 — Construction A retained; Construction B rejected for the ERC-5564 sender-address flow — LOCKED.**

Construction A is normative because the sender computes the destination address from the recipient's
meta-address and the shared secret.  Construction B would require the recipient to participate in
key generation and therefore changes who can compute the destination; it is documented only as a
separate account-transfer protocol and does not share the Construction A scheme ID.

The decision is contingent on the explicit assumptions listed below, not on any unconditional proof.

---

## 5. Assumptions

The following are named assumption records in the Lean development.  Each is quantified explicitly;
none is claimed to follow from the standard model alone.

1. `ConstructionA.ExpandIsIdeal` / `BlindExpandIdealizationBound` — XOF idealization for the joint
   `(viewTag, s', e')` derivation.
2. `BlindPointMassBound` — min-entropy of the address point `pack rho (power2Round (u + t))`.
3. `primitiveIdealizationBound` — ROM/PRF step in the SPR decomposition.
4. `encodingRegularityBound` — compress-and-encode regularity for uniform ML-KEM ring elements.
5. `keyRestorationMLWE` — named bound on the key-restoration gap, i.e. a seeded-MLWE advantage
   (`keyRestorationAdv`, games `game0/game1_keyRestorationAdv`) plus the key-only ROM/PRF
   idealization `keyIdealization`.
6. `MaskIdealizationAdv` / `widenedHvzkDistance` — mask and transcript idealization for widened signing.
7. `CmaToNmaAssumption` — sign conditions on the CMA-to-NMA loss parameters (signature layer,
   not yet composed).
8. `UnboundedSigningAssumption` — bridge from unbounded signer retries to the capped game
   (signature layer, not yet composed).

---

## 6. ANO-CCA strengthening (active attacks, literature)

The repository's normative unlinkability result is the passive ANO-CPA/SPR-to-MLWE decomposition
above.  Maram and Xagawa, "Post-Quantum Anonymity of Kyber" (ePrint 2022/1696,
`https://eprint.iacr.org/2022/1696`), prove an implicit-rejection ANO-CCA result for Kyber under
its FO transform.  Any use of this result for FIPS 203 ML-KEM-768 requires mapping the Kyber variant
and oracle model; until that mapping is formalized, the ANO-CCA claim is kept in this separate
literature section and is not claimed as a Lean corollary.

---

## 7. Exclusions

The formal result covers serialized transcripts in the classical random-oracle model.
It explicitly excludes:

- Timing and retry-count leakage.
- Quantum random-oracle access.
- Side-channel analysis of the reference implementation.
- HNF absorption / ring-specific uniform-MSIS reductions for the ownership reshaping.

These exclusions are stated in `docs/SECURITY_ANALYSIS.md`, `docs/TECHNICAL_SPEC.md` §4.2, and
`docs/erc-draft.md` Security Considerations.


## 8. Widened ML-DSA statement list

Formal capstones in `lean/PqStealth/WidenedSigning.lean` (all sorry-free):
- `MLDSA.sampleInBall_smul_widened_bound` — `‖c·(a+b)‖∞ ≤ 2·β` for `η`-short `a`, `b`.
- `MLDSA.widenedValidKeyPair_blinded` — the blinded key satisfies the widened key relation.
- `MLDSA.cube_shift_accept_prob` — cube-mask acceptance probability for any `β'`-short shift.
- `MLDSA.widened_z_accepted_independent` — acceptance probability and independence of `z`.
- `MLDSA.mldsa65_widened_z_accept_prob` — concrete ML-DSA-65 probability `(1047791/1048576)^1280`.
- `MLDSA.widened_ids_complete` — widened IDS completeness under `Primitives.Laws`.
- `MLDSA.widened_ids_hvzk` — widened IDS HVZK at `zetaWide = widenedHvzkDistance`; this bound is
  currently the trivial `1`, so the theorem fixes the statement shape only.
