# PqStealth (Lean) — proposed improvements, drafted as GitHub issues

Prepared 2026-08-17 after (a) reading *Functional Programming in Lean* and
*Theorem Proving in Lean 4* (digest in `lean-study-notes.md`) and (b) a full
read of the 13 modules in `lean/PqStealth/` against the pinned VCVio
(`a5f474fd`). Build state at time of writing: `lake build` green, 2768 jobs,
sorry-free.

Each entry is written so it can be pasted into a GitHub issue as-is (title →
issue title, body → issue body). Suggested labels: `lean`, plus one of
`model-gap` (the formal model says less than the prose claims),
`proof` (new theorem work), `infra` (build/CI/tooling), `cleanup`
(idiom/hygiene, no new theorems). Priority is my estimate of value ÷ effort.

Line references are to the current tree; VCVio references are relative to
`lean/.lake/packages/VCVio/`.


## Status (2026-08-18, branches `lean-improvements`, `lean-simplify`, `lean-round2`)

Landed, all sorry-free and axiom-guarded in `PqStealth/Axioms.lean` (67
theorems), full `lake build` green (2779 jobs, no warnings). Names below are
the post-refactor ones.

Simplification refactor landed on `lean-simplify`: 13 modules (12 content
modules plus the axiom audit) and 2,579 lines, down from 17 modules and 3,685
lines — 1,334 code / 827 prose / 418 blank, against 1,590 / 1,638 / 457 before.
`KEM` is now VCVio's `KEMScheme ProbComp` outright, the unlinkability adversary
is a function, every hidden-bit game is indexed by the bit instead of duplicated
per branch, the module essays moved to `docs/*.md`, and no `omit … in` remains.
No theorem was weakened; the generic-`(ring, encoding, prims)` ML-KEM
restatements were dropped as subsumed by the ML-KEM-768 capstones, which have
strictly fewer hypotheses, and the missing `mlkem768_unlinkAdvantage_le_indCpa`
was added.

| # | Outcome |
|---|---|
| 1 | Done — `ofKEMFull` scan recomputes the aux data (`MetaPriv = SK × PK`); correctness is VCVio's `KEMScheme.PerfectlyCorrect`; `perfectlyComplete_ofKEMFull`. |
| 2 | Done — `MLKEM.lean`: `DecidableEq` instances, `mlkem768_unlinkAdvantage_le{,_full_decomposition,_le_indCpa}` with no instance hypotheses on ML-KEM types. Sharper than the issue text: `SampleableType (Ciphertext mlkem768 …)` is provably **uninhabited** (`ByteArray` is infinite), so the generic ML-KEM capstone now takes an explicit `sim`. Upstream asks for VCVio recorded in the module docstring. |
| 3 | Done (model + sanity lemma + reduction adversary) — `ConstructionA.lean`; `auxKeyIndependence_eq_zero_of_pk_independent`, `stealthAddr_eq_blinded_pk`, seeded-MLWE `mlweAdvOfUnlinkAdv`, `idealAux_indep_of_t`. **Correction to the issue text:** the blinding term is not bounded by MLWE alone — `rho` sits outside the mask, so closing it needs the address hash as a random oracle (documented; new follow-up). |
| 4 | Done (two recipients, `q` challenges) — `MultiUnlink.lean`: `UnlinkExpMulti`, `unlinkAdvantageMulti_le_sum` (`≤ ∑ k ∈ range q, unlinkAdvantage (hybridAdv k (q-k-1))`) and `unlinkAdvantageMulti_le_mul` (`≤ q * ε`), over the general `boolDistAdvantage_le_sum_hybrids`. **Loss factor `q`, linear** — the two recipients are fixed, so only the announcements are hybridised. The `n`-recipient game (adversary picks the pair, factor `n·(n−1)/2`) is documented as a follow-up in `announcement-model.md`: it is a conditioning argument, not a chain of triangle inequalities. |
| 5 | Done — `Games.lean` `falsePositiveRate` / `SoundWithin`; `Soundness.lean`. **Correction to the issue text:** DKSAP's false-positive rate is *exactly* `1 / |F|` for **every** hash `h` (`dksap_falsePositiveRate_eq`) — it is neither `0` nor a hash-collision term; the leak is recipient 1's uniform spending scalar. For `ofKEMFull`, `falsePositiveRate_ofKEMFull_le` gives `ε + decapsRoR` with `ε` a tag-collision bound and `decapsRoR` a named real-or-random term (KEM IND-CPA again, unbounded here, exactly as `sharedSecretHiding` is); `soundWithin_ofKEMFull_oneByteTag` is the ERC's `1/256`. |
| 6 | Done — `sharedSecretHiding_eq_indCpaAdvantage` (one theorem, `∀ b`), `unlinkAdvantage_ofKEMFull_le_indCpa`, `mlkem768_unlinkAdvantage_le_indCpa`. **Finding:** VCVio's `kpke_ind_cpa_security` / `kpke_delta_correct` / `ind_cca_security` are `sorry` at the pinned commit and concern K-PKE, so KEM-IND-CPA → MLWE stays paper-level; the missing lemma is stated in `MLKEM.lean` (elaborates as written). Stale prose claiming otherwise was scrubbed from the Lean files and README; `docs/DECISIONS.md` D-013 still says "→ MLWE [Lean bridge + VCVio]" and should be corrected. |
| 8 | Done (a–c, d documented) — `IsShortPair`, honest `IsSigningKey`, `blinded_is_signing_key`; `[A | I | -t]` reshaping with `spendForgeryAdvantage_eq_sis_advantage` scored by exactly `SIS.matrixProblem`'s predicate; `spendForgeryAdvantageReal`; `honest_witness_relation` removed. Uniform-challenge gap (HNF absorption + MLWE pseudorandomness of `t`) documented. |
| 9 | Done (a) / partial (b) — new `DKSAPOracle.lean` over `unifSpec + (G →ₒ F)`. **(a)** `dlogAttack` makes `IsTotalQueryBound … 2` and `¬ IsTotalQueryBound … 1` — **exactly two queries, and neither statement mentions the announcement list** (the HNDL retroactivity claim, now a theorem); `dlogImpl` simulates the oracle by a real `dlog` with `hdlog : ∀ y, dlog y • g = y`, giving `dlogAttack_key_recovery` (output list = the recipient's own spending scalars, exactly) and the `List.Forall` form `dlogAttack_forall_key_recovery`; `dksapAnnounce_mem_announce_support` keeps the input shape honest. **(b)** ROM game over VCVio's lazy `randomOracle`: `dksapROIdeal_boolDistAdvantage_eq_zero` (**the idealized RO game is perfectly unlinkable, adversary holding the oracle**), `dksap_unlinkAdvantageRO_le_hashedDHRO`, `dksapRORun_eq` (real game = ideal game against a cache programmed at the DH point), the bad event `dksapROBad`/`dksapROBadProb`, and the CDH reduction `cdhOfUnlinkAdvRO` type-checked against `DiffieHellman.CDHAdversary`. **Gap:** `hashedDHRO ≤ dksapROBadProb` is NOT proved — it needs a lazy-RO switching lemma (VCVio's `IdenticalUntilBad` compares two *handlers*, not two game bodies), and hence `Pr[bad] ≤ q_H · Adv_CDH` is open too. Both stated precisely in `docs/dksap-asymmetry.md`. |
| 10 | Done (outer layout concrete; inner packers still parameters) — `Invariants.lean` §3: `Bytes n = Vector UInt8 n`, `splitBytes`/`splitBytes_append`, `metaAddressEncode`/`Decode` at `Bytes (1 + (32 + (nt + nek)))`, `meta_address_roundtrips{,_5633}`, the D-012 `meta_address_zk_roundtrips{,_1217}`, and the length theorems `metaAddress_size_mldsa65_mlkem768 = 5633` / `metaAddressZk_size_mlkem768 = 1217` (`ek` length from VCVio's `MLKEM.Params.publicKeyBytes`). **Correction to the issue text:** `pkEncode` cannot be used — it packs the rounded `t1`, and `EncodedPK`/`EncodedTHat` are abstract `Type`s whose concrete instances are `ByteArray`; `mlkem768EncodingLaws` covers only ciphertext/message. So `packT`/`packEk` stay parameters with roundtrip hypotheses; gap written up in `docs/encodings.md`. |
| 11 | Done (untested by nature) — `.github/workflows/lean.yml`. |
| 12 | Done — `PqStealth/Axioms.lean`, 67 `#guard_msgs (whitespace := lax) in #print axioms` blocks; wrong list ⇒ build error (verified). |
| 13 | Done — `Controls.lean`: leaky scheme advantage `= 1 − Pr[key collision]` exactly, leaky KEM, dead KEM not complete, tag-ignoring scan complete-but-not-sound. |
| 14 | Done except the doc-gen facet (deferred with #16's license headers) — `lakefile.toml` `[leanOptions]`: `autoImplicit = false`, `relaxedAutoImplicit = false`, `linter.missingDocs = true`. No binder needed fixing (the tree never relied on auto-bound implicits; checked with a probe declaration). Batteries `#lint in PqStealth` plus the non-default `docBlameThm`: **0 errors in 244 declarations, 16 linters**, after naming three anonymous `DecidableEq` instances in `MLKEM.lean` (`defsWithUnderscore`) and adding eleven missing docstrings. **Not adopted:** VCVio's `weak.linter.mathlibStandardSet` — its `style.commandStart` linter is structurally incompatible with the 3-line `#guard_msgs … in #print axioms` form (`docs/vcvio-pin.md`). |
| 15 | Done — `Demo.lean` `#eval`s guarded; build is silent. |
| 16 | Done except the license headers (deferred until the repo goes public). Every module has a `/-! … -/` docstring after the imports, in proved/assumed/docs-pointer form, with no change-log wording; the root carries the module map. |
| 17 | Closed by the simplification refactor — `abbrev KEM (PK SK C K : Type) := KEMScheme ProbComp K PK SK C` (`KEMAnonymity.lean:30`); both bridges deleted. |
| 18 | Done — no bare `simp` left in `PqStealth/`: `dksap_perfectlyComplete`'s terminal `simp [...]` and the seven `simpa` sites in `Demo`/`Controls`/`Soundness` are `simp only` / `simpa only` with `simp?`-generated lists (16 names for the first, 1–3 for the rest). It is a smaller job than the issue text implies: the simplification refactor had already fixed the second example it cites (`meta_address_roundtrips`, `Invariants.lean`). **No `@[simp]` projection lemmas added:** unfolding `ofKEM`/`ofKEMFull` costs one name today and would cost three as projections, so the "shorter lists in ≥2 proofs" measure is not met. |
| 19 | Closed by the simplification refactor — zero `omit [...] in` and zero `(F := F)` in the tree. |
| 20 | Done — README rewritten around the module map and the decomposition block; `KEM` is an `abbrev` for VCVio's `KEMScheme ProbComp`; reading order updated. |
| 21 | Done — `docs/vcvio-pin.md`: the pin table, the bump procedure (the axiom guard *is* the build), the two upstream files to diff, the three upstream asks (`DecidableEq` beside `mlkem768Encoding`, de-privatize `byteEncode_size`, a KEM-level `kem_ind_cpa_security`), and what in this tree is bump-sensitive. |

Open: #7, #9(b) (the lazy-RO switching lemma and the `q_H` guessing step), #16
(headers), plus the follow-ups above (random-oracle model
for the address hash; the `n`-recipient unlinkability game; upstream VCVio
`DecidableEq`/`byteEncode_size`/KEM-IND-CPA lemma).

---

## P0 — model gaps (the formal statement is weaker than it reads)

### 1. Detection is vacuous on the concrete ML-KEM instance: `scan` always returns `true`

**Labels:** `lean`, `model-gap`, `proof` · **Priority:** P0

**Context.** `StealthScheme.ofKEM` and `ofKEMFull` define detection as
"decapsulation returns `some`" (`PqStealth/KEMAnonymity.lean:109-111`,
`:170-172`). VCVio's concrete ML-KEM has implicit rejection, so its
`decaps` is `fun dk c => return some (decapsInternal …)`
(`LatticeCrypto/MLKEM/KEM.lean:98`) — it *never* returns `none`. Hence
`mlkemStealthScheme … |>.scan sk c = pure true` for every `sk`, `c`:
every recipient "detects" every announcement. This is exactly the failure
mode `Falsification.lean` warns about ("if the detection test were trivially
true, the proof would still go through"), and it also means the view tag,
which is what real scanning tests, is not modelled on the recipient side at
all (`ofKEMFull.scan` ignores the `Aux` component).

The unlinkability theorems are unaffected (they never run `scan`), but the
README's "detection completeness" bullet for the KEM-based scheme is empty on
ML-KEM, and no *soundness* statement (a non-recipient does not detect) can
even be stated.

**Proposal.**
1. Make `scan` recompute the auxiliary data and compare:
   `scan sk (c, aux) := do let some k ← kem.decaps sk c | pure false; pure (aux == auxGen k pk)`.
   This needs the recipient's own `pk` on the scan side — either carry it in
   the secret (`SK × PK`, mirroring the real meta-address wallet state) or
   add a `pkOf : SK → PK` field to `KEM`. It also needs `[DecidableEq Aux]`
   (or `[BEq Aux]`).
2. Prove `PerfectlyComplete` for `ofKEMFull` from a KEM correctness
   hypothesis (VCVio's `KEMScheme.PerfectlyCorrect`,
   `VCVio/CryptoFoundations/KeyEncapMech.lean:51`), and note the δ-correct
   variant (`MLKEM/Security.lean:70 kpke_delta_correct`) for the concrete
   instance.
3. Add the negative control (see #13): a variant whose scan drops the tag
   comparison is *not* sound.
4. Re-check `unlinkAdvantage_ofKEMFull_le` and `cipherOf` still go through
   (they should — the announcement side is unchanged).

**Acceptance.** `mlkemStealthScheme.scan` is not the constant `true`;
`PerfectlyComplete (ofKEMFull kem auxGen)` proved under `kem` correctness;
README updated.

---

### 2. Discharge the free instance hypotheses on the ML-KEM capstones

**Labels:** `lean`, `model-gap`, `proof` · **Priority:** P0

**Context.** `mlkem_unlinkAdvantage_le` and
`mlkem_unlinkAdvantage_le_full_decomposition` are stated under section
variables `[SampleableType SharedSecret]`,
`[SampleableType (Ciphertext params encoding)]`, and three `DecidableEq`
instances on the encoding types (`PqStealth/MLKEMInstance.lean:39-44`,
`AnonymityFromSPR.lean:122-128`). Checked against the pinned VCVio with
`lake env lean` on a scratch file (2026-08-17):

- `SampleableType SharedSecret` — **resolves** (`Vector Byte 32` via
  `instSampleableTypeVector`, `UInt8` via a generic `FinEnum` instance).
  The variable is redundant and can be dropped.
- `DecidableEq mlkem768Encoding.EncodedTHat/EncodedU/EncodedV` — **fails**
  on the concrete instance
  (`MLKEM.Concrete.mlkem768Encoding`, `LatticeCrypto/MLKEM/Concrete/Instance.lean:119`).
  The underlying types are `ByteArray`, but `concreteEncoding` is a plain
  `def`, so instance search cannot see through it — the FPIL `def` vs
  `abbrev` gotcha, on VCVio's side.
- `SampleableType (Ciphertext mlkem768 mlkem768Encoding)` — **fails**;
  `Ciphertext` is a two-field structure with no instance, and its
  components have none either.

Consequence: `mlkemStealthScheme concreteNTTRingOps mlkem768Encoding mlkem768Primitives`
does not currently elaborate ("failed to synthesize DecidableEq
mlkem768Encoding.EncodedTHat"), so the "instantiated on real ML-KEM"
claim holds only for the abstract `(ring, encoding, prims)` triple, and the
uniform-ciphertext simulator `$ᵗ (Ciphertext …)` is uniform only relative
to an instance nobody has built. (VCVio's own `MLKEM/Security.lean:118`
carries the same hypotheses, so this is inherited, but for our headline
theorems it should be closed.)

**Proposal.**
- Drop `[SampleableType SharedSecret]` from both variable blocks.
- Provide the concrete `DecidableEq`s: either
  `instance : DecidableEq mlkem768Encoding.EncodedU := by unfold mlkem768Encoding concreteEncoding; infer_instance`
  in a small `PqStealth/MLKEM768.lean`, or upstream a `@[reducible]`/`abbrev`
  on `concreteEncoding` to VCVio (preferred; open the issue there too).
- `instance [SampleableType encoding.EncodedU] [SampleableType encoding.EncodedV] : SampleableType (Ciphertext params encoding)`
  as the product sampler through `Ciphertext.mk`; then the concrete one via
  the fixed-length byte representation (this is the "uniform ciphertext
  bytes" simulator the SPR docstring talks about; if the encoded type is a
  raw `ByteArray`, sample a `Vector Byte n` and convert).
- State one theorem `mlkem768_unlinkAdvantage_le …` at
  `concreteNTTRingOps`/`mlkem768Encoding`/`mlkem768Primitives`
  (`Concrete/NTT.lean:324`, `Concrete/Instance.lean:119,147`) with **no**
  instance hypotheses.

**Acceptance.** A theorem about `mlkem768` whose only hypotheses are the
adversary and `auxGen`; `#print axioms` unchanged; the scratch check above
becomes an `example` in the tree.

---

### 3. Connect the algebraic core to the game layer: instantiate `auxGen` with construction A

**Labels:** `lean`, `model-gap`, `proof` · **Priority:** P0

**Context.** The two layers never meet. `Blinding.lean`/`Invariants.lean`
prove facts about `A *ᵥ s' + e' + t`; the game layer takes an opaque
`auxGen : K → PK → Aux`. Nothing in Lean says the stealth address in the
announcement *is* `keccak(pack(rho, Power2Round(A·s'+e'+t)))` with `(s',e')`
derived from the shared secret, so `blinded_key_correctness` is never used by
any security statement, and the term the model was extended to express,
`auxKeyIndependence` (`KEMAnonymity.lean:226-230`), is a named real number
with no theorem about it.

**Proposal.**
1. Define `constructionA.auxGen (ss : SharedSecret) (pk : MetaPub) : ViewTag × StealthAddr`
   over VCVio's `MLDSA` types (`Rq`, `Power2RoundOps`, `Encoding.pkEncode`),
   with the `(s', e')` derivation abstracted as a function
   `expand : SharedSecret → (Fin l → Rq) × (Fin k → Rq)` (the SHAKE
   expansion is not in scope to model).
2. Prove the sanity lemma `auxKeyIndependence kem auxGen adv = 0` whenever
   `auxGen` ignores its `PK` argument (constant in `pk`) — this pins the
   term's meaning and is a cheap positive control.
3. State the blinding hop as a reduction to VCVio's decision-MLWE
   (`LatticeCrypto/HardnessAssumptions/LearningWithErrors.lean:132 moduleMatrixProblem`,
   `.advantage`): an adversary distinguishing `randAuxBranchTrue` from the
   `cipherOf` game yields an MLWE distinguisher for `(A, A·s'+e')`. Even
   just the reduction *adversary* (type-checked, as was done for IND-CPA in
   `SharedSecretHiding.lean`) is progress; the advantage equality is the
   real target.
4. Use `blinded_key_correctness` in the completeness proof of the resulting
   concrete scheme (recipient recomputes the same stealth key) — that is
   where the identity finally earns its place in the chain.

**Acceptance.** `PqStealth/ConstructionA.lean` (or similar) importing both
`Blinding` and `KEMAnonymity`; at least (2) proved and (3) type-checked.

---

### 4. Multi-recipient / multi-announcement unlinkability (hybrid argument)

**Labels:** `lean`, `model-gap`, `proof` · **Priority:** P1

**Context.** `UnlinkExp` (`Games.lean:84-107`) has exactly two recipients
and one challenge announcement. plan.md's deliverable is "unlinkability
across payments": many announcements to many recipients, adversary sees all
meta-addresses and all announcements. The standard hybrid argument gives
`Adv_{n,q} ≤ n·q·Adv_{2,1}` (or a tighter `q`-fold), and the loss factor
matters for the parameter write-up.

**Proposal.** Define `UnlinkExpMulti n q` with the adversary choosing
`(i₀, i₁)` per challenge (or the "left-or-right" many-challenge form), and
prove the hybrid bound against `unlinkAdvantage`. VCVio has the
`MultiTarget` hardness scaffolding
(`VCVio/CryptoFoundations/HardnessAssumptions/MultiTarget.lean`) that may
give the loop for free.

**Acceptance.** A theorem `unlinkAdvantageMulti_le_mul` with an explicit
loss factor; README/DECISIONS updated with the factor.

---

### 5. Detection soundness (false-positive statement)

**Labels:** `lean`, `model-gap`, `proof` · **Priority:** P1 (blocked by #1)

**Context.** Only completeness (`PerfectlyComplete`) is defined. Nothing
states that a *non*-recipient does not detect (up to the view-tag
false-positive rate 2⁻⁸ per byte of tag). This is the property the scanning
benchmarks and the ERC's tag-length rationale rely on.

**Proposal.** `SoundnessExp`: keygen two recipients, announce to 1, scan
with 0; prove `Pr[= true | …] ≤ ε` where `ε` comes from `auxGen`'s tag
being uniform when the shared secret is (KEM IND-CPA again, plus a
counting argument on `Fin 256`).

**Acceptance.** `dksap` (exact `0` false positives modulo hash collisions of
`h`) and `ofKEMFull` (tag-length bound) both instantiated.

---

## P1 — closing documented gaps in the proved chain

### 6. Prove the "documented glue": `sharedSecretHiding* = IND_CPA_Advantage indCpaAdv*`

**Labels:** `lean`, `proof` · **Priority:** P1

**Context.** `SharedSecretHiding.lean:86-114` builds the VCVio
`IND_CPA_Adversary`s and the docstring says the advantage equality is
"documented glue" (sample reordering, `ProbCompRuntime.probComp` bridge).
Until this equality is proved, the hop "ssHiding → MLWE via VCVio" is a
paper step, not a Lean one, although VCVio's `kpke_ind_cpa_security`
(`MLKEM/Security.lean:99`) is sitting there waiting to be composed.

**Proposal.** Prove
`sharedSecretHidingTrue kem auxGen adv = IND_CPA_Advantage ProbCompRuntime.probComp (indCpaAdvTrue kem auxGen adv)`
(and `False`). The proof is a bind-reordering of independent samples —
`bind_comm`-style lemmas (`VCVio/EvalDist/Monad/Basic.lean`) plus
`probOutput_bind_eq_tsum` and `tsum_comm`. Then compose with VCVio's KEM
IND-CPA → K-PKE IND-CPA → MLWE chain to get an MLWE bound on the ssHiding
terms for `mlkem`.

**Acceptance.** Two equalities proved; a corollary bounding
`sharedSecretHidingTrue (mlkem …)` by an MLWE advantage.

---

### 7. Formalize `SPR(K-PKE) ≤ 2·MLWE` (the two-hop)

**Labels:** `lean`, `proof` · **Priority:** P1

**Context.** `AnonymityFromSPR.lean:15-25` documents the key hop
(`t = A·s+e` → uniform) and the ciphertext hop (`(u,v)` is an MLWE sample
over `[A | t]`) as paper work. Both land on
`LearningWithErrors.advantage`. This is the last lattice step of the
unlinkability chain and the one item that would make the reduction
end-to-end in Lean at the CPA level.

**Proposal.** Prove `sprAdvTrue (mlkem …) ($ᵗ Ciphertext) adv ≤ mlwe₁ + mlwe₂`
against `KPKE.encrypt`'s definition in `LatticeCrypto/MLKEM/KPKE.lean`,
reusing whatever `kpke_ind_cpa_security` already proves about the
ciphertext distribution (its key hop is probably identical). Record the
ANO-CCA / implicit-rejection caveat as a separate issue rather than
blocking on it.

**Acceptance.** Theorem in Lean; module docstring's "remaining lattice
step" paragraph rewritten to point at it.

---

### 8. Spend side: honest MSIS statement and the SoK route

**Labels:** `lean`, `proof`, `model-gap` · **Priority:** P1

**Context.**
- `IsSigningKey` (`Invariants.lean:84-87`) is literally the same
  definition as `IsOwnershipWitness`, so `ownership_iff_signing` is
  `Iff.rfl`. A signing key is a *short* `(s₁,s₂)`; the bridge should carry
  `cInfNorm sᵢ ≤ η` and use `blinded_norm_bound` for the `2η` version.
- `ownershipSISProblem` (`Ownership.lean:46-51`) uses VCVio's *generic*
  `SIS.Problem` with an abstract `isShort : … → Bool`, so
  "spendForgeryAdvantage is bounded by MSIS hardness" is by naming, not by
  a theorem: nothing links it to `SIS.matrixProblem`
  (`ShortIntegerSolution.lean:86`) at `Rq` with the actual norm bound.
- `spendForgeryAdvantage : ℝ≥0∞` while every other advantage in the
  development is `ℝ` (`Ownership.lean:56-60`); mixing the two blocks
  composing bounds.

**Proposal.** (a) Strengthen `IsSigningKey` with the norm bound and reprove
the bridge (`blinded_is_ownership_witness` + `blinded_norm_bound`). (b)
Instantiate `ownershipSISProblem` at `R := Rq`, `isShort w := decide (cInfNorm-bound)`
and prove it *equals* (or reduces to) `SIS.matrixProblem`/the module
variant so the MSIS claim is a theorem. (c) Return `ℝ` (`.toReal`) or
provide both. (d) Open a follow-up for the SoK unforgeability via
`SelfTargetMSIS` + `VCVio/CryptoFoundations/SigmaProtocol.lean`/`FiatShamir`
(the ZK-spend path from D-012).

**Acceptance.** `spendForgeryAdvantage_le_msis` stated against VCVio's
concrete MSIS problem; advantage types uniform.

---

### 9. DKSAP: real discrete-log oracle and query counting; DDH+ROM positive proof

**Labels:** `lean`, `proof` · **Priority:** P2

**Context.** `DKSAP.lean` takes the dlog answers as hypotheses
(`hM : xM • g = m • g`) rather than as oracle queries, so the "2 queries per
victim regardless of payment count" statement (the HNDL retroactivity
argument) is not expressible; and `DKSAPClassical.lean` bounds
unlinkability by two `hashedDH*` terms that are *defined*, not reduced to
DDH with `h` a random oracle.

**Proposal.** (a) Restate the attack in
`OracleComp (unifSpec + (G →ₒ F))` with VCVio's query-tracking
(`VCVio/OracleComp/QueryTracking/QueryCost.lean`) to prove the query bound.
(b) Model `h` as a random oracle (VCVio has ROM machinery in
`GPVHashAndSign.lean`/`PRF.lean`; check for a reusable `randomOracle` spec)
and prove `hashedDHTrue ≤ DDH advantage` via
`VCVio/CryptoFoundations/HardnessAssumptions/DiffieHellman.lean` — this is
the most publishable single item ("DKSAP is unlinkable under DDH in the
ROM", which nobody has machine-checked).

**Acceptance.** Either half landing is a separate PR.

---

### 10. Byte-level encoding roundtrip for the meta-address

**Labels:** `lean`, `model-gap` · **Priority:** P2

**Context.** `MetaAddress`/`encodeMeta`/`decodeMeta`
(`Invariants.lean:126-147`) is a three-field record with
`version : Nat`; the roundtrip theorem is `simp` on a structural record and
says nothing about the wire format `version ‖ rho ‖ pack23(t) ‖ ek`
(TECHNICAL_SPEC, 5,633 B) or about the reduced ZK-spend layout
(`version ‖ commitment ‖ ek`, D-012).

**Proposal.** Model the meta-address as `Bytes n` built with VCVio's
`MLDSA.Encoding.pkEncode` and the ML-KEM `EncapsulationKey` encoder, and
prove decode∘encode = id from their `Laws` (VCVio has
`mlkem768EncodingLaws`, `Concrete/Instance.lean:133`). Use `UInt8`/`Fin 256`
for `version`.

**Acceptance.** A roundtrip theorem whose statement mentions concrete byte
lengths.

---

## P1 — infrastructure (the build should enforce what the README claims)

### 11. CI: build + axiom audit on every push

**Labels:** `lean`, `infra` · **Priority:** P1

**Context.** There is no `.github/workflows` for the Lean package. The
README's job counts drift (2715/2717/2762/2768 across README, DECISIONS,
memory), "sorry-free" and "only three axioms" are checked by hand.

**Proposal.** Workflow: `elan` toolchain from `lean-toolchain`,
`lake exe cache get`, `lake build`, then build the axiom-guard module (#12).
Cache `.lake/packages` and mathlib oleans keyed on `lake-manifest.json`.
Remove job counts from prose (or generate them).

**Acceptance.** Green badge; a `sorry` or a new axiom fails CI.

---

### 12. Build-checked axiom audit with `#guard_msgs in #print axioms`

**Labels:** `lean`, `infra` · **Priority:** P1

**Context.** TPIL ch. 6/12: `#guard_msgs in cmd` asserts the exact
messages a command emits, and `#print axioms` lists `propext`,
`Classical.choice`, `Quot.sound`, `sorryAx`. Today the audit is a scratch
file someone runs.

**Proposal.** `PqStealth/Axioms.lean` (imported by the root) with one
```lean
/-- info: 'PqStealth.unlinkAdvantage_ofKEMFull_le' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs in #print axioms unlinkAdvantage_ofKEMFull_le
```
block per headline theorem (the ~17 listed in memory/DECISIONS). Verified
2026-08-17 with `lake env lean` on a scratch file: the block above passes
silently on the current tree with exactly that message text. Any
`sorry` anywhere upstream changes the message and breaks the build. Also
consider `leanOptions = [{ name = "warningAsError", value = true }]` scoped
to this package if it does not fire on dependency warnings.

**Acceptance.** `lake build` fails when a `sorry` is introduced into any
headline theorem's dependency cone.

---

### 13. Positive/negative controls for the game layer (extend `Falsification.lean`)

**Labels:** `lean`, `proof`, `infra` · **Priority:** P1

**Context.** `Falsification.lean` covers one completeness claim (DKSAP).
The unlinkability game has no control at all: nothing shows that a scheme
which *leaks* the recipient is caught by `unlinkAdvantage`.

**Proposal.** (a) `leakyScheme`: announcement includes `pk`; the trivial
adversary comparing to `pk1` has `unlinkAdvantage = 1/2` (or `1` in the
bias normalisation used by `boolBiasAdvantage` — check `SecExp.lean`) —
proved. (b) After #1: `ofKEMFull` variant whose scan ignores the tag is not
sound; a KEM with `decaps := none` gives a scheme that is not complete.
(c) A `KEM` whose ciphertext *is* the public key has anonymity advantage
`1` (shows `anonAdvantage` has teeth). Same recipe as
`dksapBroken_not_perfectlyComplete`: `probOutput_eq_one_iff_forall`,
exhibit the witness.

**Acceptance.** Three theorems, all in the build.

---

### 14. `lakefile.toml`: `autoImplicit = false`, linters, doc-gen

**Labels:** `lean`, `infra`, `cleanup` · **Priority:** P2

**Context.** FPIL/TPIL both flag auto-bound implicits: a typo in a binder
silently becomes a fresh universe-polymorphic variable. VCVio sets
`autoImplicit = false` globally in its lakefile; our `lakefile.toml` sets no
`leanOptions`, so the package compiles with auto-implicits on. Also no
`#lint`, no doc build.

**Proposal.**
```toml
[leanOptions]
autoImplicit = false
relaxedAutoImplicit = false
linter.missingDocs = true
```
Fix whatever fails (expect a few `{n}` binders). Add a `docs` facet with
`doc-gen4` (`lake -R -Kenv=doc build PqStealth:docs`) once #16 lands so
the module docstrings actually render. Run mathlib's `#lint` once and fix
the reported items (unused arguments, `Iff.rfl`-style simp candidates,
naming).

**Acceptance.** Options in the lakefile; `lake build` green; a `docs/`
target exists.

---

### 15. `Demo.lean` prints during every build

**Labels:** `lean`, `cleanup` · **Priority:** P2

**Context.** `Demo.lean:98-103` has six bare `#eval`s, so every
`lake build` ends with six `info:` lines. FPIL: `#eval` is for the
interactive loop; checked expectations belong in `#guard_msgs in #eval` or
`example … := by decide`.

**Proposal.** Wrap each `#eval` in `/-- info: 22 -/ #guard_msgs in #eval M`
(keeps them runnable *and* asserted), or move the walkthrough into a
`lean_exe pqstealth-demo` with a `main : IO Unit` so `lake exe` runs it and
`lake build` is silent. Keep the three `example … := by decide` — they are
the actual test.

**Acceptance.** `lake build` output ends at `Build completed successfully`
with no `info:` lines.

---

## P2 — cleanup / idiom (from the books; no new theorems)

### 16. Module docstrings and file headers

**Labels:** `lean`, `cleanup` · **Priority:** P2

**Context.** Every file opens with a plain `/- … -/` comment
(`Blinding.lean:1-8`, etc.); TPIL/VCVio convention is a `/-! … -/` module
docstring after the imports so `doc-gen4` renders it, plus
copyright/authors header if the repo goes public with the ERC. Some
docstrings still describe history ("added 2026-07-31", "the earlier model
…") — VCVio's guide asks for intrinsic descriptions.

**Proposal.** Convert headers to `/-! -/`, move them below the imports,
add license header, strip change-log wording (it lives in DECISIONS.md).
Root `PqStealth.lean` gets a docstring listing the module map (and loses
the stray blank line at line 5).

---

### 17. Deduplicate `KEM` against VCVio's `KEMScheme ProbComp`

**Labels:** `lean`, `cleanup` · **Priority:** P2

**Context.** `KEM PK SK C K` (`KEMAnonymity.lean:44-47`) has fields
identical to `KEMScheme ProbComp K PK SK C`; we maintain two bridges
(`KEM.toKEMScheme`, `KEM.ofKEMScheme`) with no roundtrip lemmas. FPIL:
`abbrev` is transparent to instance search and `simp`, `def` is not.

**Proposal.** Either `abbrev KEM PK SK C K := KEMScheme ProbComp K PK SK C`
and delete both bridges (dot-notation `kem.keygen` keeps working), or keep
the structure and add `@[simp] theorem toKEMScheme_ofKEMScheme` /
`ofKEMScheme_toKEMScheme`. Prefer the abbrev unless the argument order
matters for readability (it can be preserved with the abbrev).

---

### 18. Simp-set and proof-robustness hygiene

**Labels:** `lean`, `cleanup` · **Priority:** P2

**Context.** TPIL: `simp` with the default set depends on every upstream
`@[simp]` attribute, so bare terminal `simp` calls
(`dksap_perfectlyComplete`, `DKSAP.lean:119-121`;
`meta_address_roundtrips`, `Invariants.lean:147`) are the first thing to
break on a VCVio/mathlib bump. Conversely the seven-name `simp only [...]`
unfold list in `unlinkAdvantage_ofKEM_eq_anonAdvantage`
(`KEMAnonymity.lean:123-126`) suggests missing `@[simp]` projection lemmas
for `ofKEM`/`ofKEMFull`/`unlinkSetup`/`anonSetup`.

**Proposal.** Run `simp?` on the bare `simp`s and pin the lemma lists; add
`@[simp]` lemmas for the scheme constructors' fields (`ofKEM_keygen`,
`ofKEMFull_announce`, …) and the four `*Setup`/`*Branch*` unfoldings; try
`rfl` where the two experiments are definitionally the same computation.
Consider `attribute [local simp]` blocks per section instead of global
attributes (TPIL §5: global `@[simp]` cannot be removed downstream).

---

### 19. Section/variable hygiene in the DKSAP files

**Labels:** `lean`, `cleanup` · **Priority:** P3

**Context.** TPIL §6: a `variable` is included in a theorem only if
mentioned in the statement; instance binders follow their dependencies.
`DKSAPClassical.lean` needs `omit [DecidableEq G] in` three times
(`:85`, `:108`, `:120`) because `[DecidableEq G]` is declared in the same
section as theorems that do not need it, and `dksapIdeal (F := F) g` is
repeated eight times because `F` only occurs in the discarded `MetaPriv`
type.

**Proposal.** Split the section: instance-free probability lemmas in one
section, the scheme + `hashedDH*` in another; make `F` an explicit
argument of `dksapIdeal` (`def dksapIdeal (F) (g : G)`) so call sites read
`dksapIdeal F g`. Same pattern check for `Games.lean`'s
`variable (adv : UnlinkAdv …)`.

---

### 20. Small duplications and naming

**Labels:** `lean`, `cleanup` · **Priority:** P3

- `honest_witness_relation` (`Ownership.lean:65-68`) is
  `blinded_is_ownership_witness` restated; keep one, or make the second a
  `@[simp]`-oriented corollary with a reason in the docstring.
- `IsOwnershipWitness`/`IsSigningKey` are `def`s returning `Prop`; the
  mathlib linter flags Prop-valued `def`s that are used with `simp` —
  either `abbrev` or add `@[simp] theorem …_iff` unfoldings (and see #8 for
  the semantic fix).
- Experiments are named `CorrectExp`/`UnlinkExp`/`AnonExp` (UpperCamel,
  mirroring VCVio) while values elsewhere are lowerCamel
  (`rorGameTrue`, `randAuxBranchTrue`); pick one convention for
  `ProbComp Bool`-valued definitions and apply it (mathlib: lowerCamel for
  terms, UpperCamel for `Prop`/`Type`).
- README `lean/README.md:8, :97`: drop the job counts (see #11) and add
  the reading order (Demo → DKSAP → Blinding → Games → KEMAnonymity) that
  the handbook artifact already documents.

---

### 21. Track the VCVio pin

**Labels:** `lean`, `infra` · **Priority:** P3

**Context.** VCVio is pinned at `a5f474fd` (2026-07-15) with a documented
"don't float on main" policy. Its `MLKEM.ind_cca_security` is a
self-flagged placeholder, and KEM anonymity is absent — both are things
upstream may land. A bump is also when #18's `simp` fragility bites.

**Proposal.** A standing issue with the bump checklist: update `rev` in
`lakefile.toml` + `lake update VCVio`, `lake exe cache get`, `lake build`,
re-run the axiom guard (#12), diff `LatticeCrypto/MLKEM/Security.lean` and
`KeyEncapMech.lean` for new anonymity/ANO-CCA definitions to adopt, and
record the new pin date in README. Cadence: once per month or when
upstream announces KEM anonymity.

---

## Suggested order

1. #12 axiom guard and #15 demo noise (an afternoon; makes every later PR
   self-checking), then #11 CI.
2. #1 scan fix + #13 controls (the model-integrity items).
3. #2 concrete instances, then #6 glue equality — these turn two
   "documented" arrows into Lean ones cheaply.
4. #3 construction-A bridge (biggest conceptual gain: the algebra finally
   feeds the games).
5. #7, #8, #5 — the remaining theorem work, in the order the security
   write-up needs them.
6. Cleanup batch #14, #16–#20 as a single PR when convenient.

## Creating the issues

Once reviewed, each `### N. Title` block above maps to one
`gh issue create --title "<Title>" --label lean,<label> --body-file <block>`.
No issues have been created; this file is the review copy.
