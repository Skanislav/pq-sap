import PqStealth.Ownership
import PqStealth.WidenedSigning
import VCVio.CryptoFoundations.FiatShamir.WithAbort.Security

/-! # Related-key spend security for Construction A

A recipient's stealth keys are all derived from one master ML-DSA key
`(A, t = A·s₁ + s₂)`: announcement `i` contributes a blinding offset
`(s'ᵢ, e'ᵢ)` and the derived key is `tᵢ = t + A·s'ᵢ + e'ᵢ`. A malicious sender
KNOWS the offsets it created, so the honest adversary model hands the attacker
the master public key together with all `q` offsets and asks for a spend
witness for any one derived key. This file:

1. defines that game in the search-witness model of `Ownership.lean`
   (`relatedSpendRun`, `relatedSpendAdvantage`);
2. proves the `q`-fold union bound over the targeted key
   (`relatedSpendAdvantage_le_mul`);
3. proves the offset-subtraction reduction: a witness for derived key `i`
   minus the known offset is a witness for the master key at a wider bound
   (`relatedSpendAdvantageAt_le_spendForgery`), so the related-key game is at
   most `q` times the master's ownership-forgery advantage
   (`relatedSpendAdvantage_le_mul_spendForgery`);
4. instantiates at `Rq` with the ML-DSA range check: witnesses at bound `b`
   and offsets at bound `η` give master witnesses at bound `b + η`
   (`mldsa_relatedSpendAdvantage_le`).

What is NOT here: the signature-of-knowledge layer. The deployed spend is a
Fiat-Shamir-with-aborts signature over the ownership relation; its EUF-CMA to
ownership-forgery reduction (CMA-to-NMA loss, retry truncation) is the
follow-up recorded in `Ownership.lean` §4. The two loss quantities it will
need are defined at the end as nonnegative reals with their hypotheses made
explicit, but nothing composes them yet.
-/

open OracleComp OracleSpec Matrix ENNReal

namespace PqStealth

variable {R : Type} [CommRing R] {k l : ℕ}

/-! ## 1. Offsets and derived keys -/

/-- A blinding offset `(s', e')`, the per-announcement shift of the master secret. -/
abbrev Offset (R : Type) (k l : ℕ) := (Fin l → R) × (Fin k → R)

/-- Offsets restricted to a shortness predicate. Carrying the proof in the type
is what lets the reduction below use the bound without a support lemma for the
i.i.d. sampler. -/
abbrev ShortOffset (R : Type) (k l : ℕ) (offShort : Offset R k l → Bool) :=
  {off : Offset R k l // offShort off = true}

/-- The derived stealth key: same matrix, target shifted by `A·s' + e'`. -/
def deriveKey (key : OwnershipKey R k l) (off : Offset R k l) : OwnershipKey R k l :=
  ⟨key.A, key.t + (key.A *ᵥ off.1 + off.2)⟩

/-- Subtract a known offset from a witness. -/
def subtractOffset (off : Offset R k l) (w : (Fin l → R) × (Fin k → R)) :
    (Fin l → R) × (Fin k → R) :=
  (w.1 - off.1, w.2 - off.2)

section Search

variable [DecidableEq (Fin k → R)]

/-- A witness for the derived key, minus the offset, is a witness for the master
key: the relation transports exactly, the shortness through `hshort`. -/
theorem ownershipValid_subtractOffset
    {isShort isShort' : ((Fin l → R) × (Fin k → R)) → Bool}
    {offShort : Offset R k l → Bool}
    (hshort : ∀ w off, isShort w = true → offShort off = true →
      isShort' (subtractOffset off w) = true)
    (key : OwnershipKey R k l) (off : Offset R k l) (hoff : offShort off = true)
    (w : (Fin l → R) × (Fin k → R))
    (hw : ownershipValid isShort (deriveKey key off) w = true) :
    ownershipValid isShort' key (subtractOffset off w) = true := by
  simp only [ownershipValid, Bool.and_eq_true, decide_eq_true_eq, deriveKey] at hw ⊢
  refine ⟨hshort w off hw.1 hoff, ?_⟩
  simp only [subtractOffset, Matrix.mulVec_sub]
  calc key.A *ᵥ w.1 - key.A *ᵥ off.1 + (w.2 - off.2)
      = (key.A *ᵥ w.1 + w.2) - (key.A *ᵥ off.1 + off.2) := by abel
    _ = key.t := by rw [hw.2]; abel

/-! ## 2. The related-key game -/

variable {offShort : Offset R k l → Bool}

/-- A related-key spend adversary: given the master public key and all `q`
offsets, name a derived key and produce a witness for it. -/
abbrev RelatedSpendAdv (R : Type) [CommRing R] (k l : ℕ) (offShort : Offset R k l → Bool)
    (q : ℕ) :=
  OwnershipKey R k l → (Fin q → ShortOffset R k l offShort) →
    ProbComp (Fin q × ((Fin l → R) × (Fin k → R)))

/-- The joint run of the game: master key, offsets, adversary output. -/
def relatedSpendRun (keyGen : ProbComp (OwnershipKey R k l))
    (offGen : ProbComp (ShortOffset R k l offShort)) (q : ℕ)
    (adv : RelatedSpendAdv R k l offShort q) :
    ProbComp (OwnershipKey R k l × (Fin q → ShortOffset R k l offShort) ×
      (Fin q × ((Fin l → R) × (Fin k → R)))) := do
  let key ← keyGen
  let offs ← ProbComp.sampleIID q offGen
  let out ← adv key offs
  pure (key, offs, out)

/-- Winning: the returned witness is valid for the named derived key. -/
def RelatedSpendWins (isShort : ((Fin l → R) × (Fin k → R)) → Bool) {q : ℕ}
    (x : OwnershipKey R k l × (Fin q → ShortOffset R k l offShort) ×
      (Fin q × ((Fin l → R) × (Fin k → R)))) : Prop :=
  ownershipValid isShort (deriveKey x.1 (x.2.1 x.2.2.1).1) x.2.2.2 = true

/-- Related-key spend advantage: the probability of forging a witness for any
of the `q` derived keys, knowing all the offsets. -/
noncomputable def relatedSpendAdvantage (keyGen : ProbComp (OwnershipKey R k l))
    (offGen : ProbComp (ShortOffset R k l offShort))
    (isShort : ((Fin l → R) × (Fin k → R)) → Bool) (q : ℕ)
    (adv : RelatedSpendAdv R k l offShort q) : ℝ≥0∞ :=
  Pr[RelatedSpendWins isShort | relatedSpendRun keyGen offGen q adv]

/-- The advantage restricted to forgeries against derived key `i`. -/
noncomputable def relatedSpendAdvantageAt (keyGen : ProbComp (OwnershipKey R k l))
    (offGen : ProbComp (ShortOffset R k l offShort))
    (isShort : ((Fin l → R) × (Fin k → R)) → Bool) (q : ℕ)
    (adv : RelatedSpendAdv R k l offShort q) (i : Fin q) : ℝ≥0∞ :=
  Pr[fun x => x.2.2.1 = i ∧ RelatedSpendWins isShort x | relatedSpendRun keyGen offGen q adv]

/-! ## 3. The union bound over the targeted key -/

variable (keyGen : ProbComp (OwnershipKey R k l)) (offGen : ProbComp (ShortOffset R k l offShort))
  (isShort : ((Fin l → R) × (Fin k → R)) → Bool) (q : ℕ) (adv : RelatedSpendAdv R k l offShort q)

/-- **Union bound.** Winning means winning against the key the adversary names. -/
theorem relatedSpendAdvantage_le_sum :
    relatedSpendAdvantage keyGen offGen isShort q adv ≤
      ∑ i, relatedSpendAdvantageAt keyGen offGen isShort q adv i := by
  unfold relatedSpendAdvantage relatedSpendAdvantageAt
  refine (probEvent_mono'' fun x hx => ?_).trans
    (probEvent_exists_finset_le_sum Finset.univ _
      (fun i x => x.2.2.1 = i ∧ RelatedSpendWins isShort x))
  exact ⟨x.2.2.1, Finset.mem_univ _, rfl, hx⟩

/-- **`q`-fold loss.** A uniform per-key bound gives `q` times that bound. -/
theorem relatedSpendAdvantage_le_mul {ε : ℝ≥0∞}
    (h : ∀ i, relatedSpendAdvantageAt keyGen offGen isShort q adv i ≤ ε) :
    relatedSpendAdvantage keyGen offGen isShort q adv ≤ q * ε := by
  refine (relatedSpendAdvantage_le_sum keyGen offGen isShort q adv).trans ?_
  calc ∑ i, relatedSpendAdvantageAt keyGen offGen isShort q adv i
      ≤ ∑ _i : Fin q, ε := Finset.sum_le_sum fun i _ => h i
    _ = q * ε := by rw [Finset.sum_const, Finset.card_univ, Fintype.card_fin, nsmul_eq_mul]

/-! ## 4. The offset-subtraction reduction -/

/-- **Reduction to the master key's ownership problem.** Sample the offsets
yourself, run the related-key adversary, and return its witness minus the
offset of key `i`. -/
def relatedSpendReduction (isShort' : ((Fin l → R) × (Fin k → R)) → Bool) (i : Fin q) :
    SIS.Adversary (ownershipSISProblem keyGen isShort') := fun key => do
  let offs ← ProbComp.sampleIID q offGen
  let out ← adv key offs
  pure (subtractOffset (offs i).1 out.2)

/-- **Forging against derived key `i` forges against the master key** at the
widened shortness `isShort'`, with the reduction's own advantage. -/
theorem relatedSpendAdvantageAt_le_spendForgery
    (isShort' : ((Fin l → R) × (Fin k → R)) → Bool)
    (hshort : ∀ w off, isShort w = true → offShort off = true →
      isShort' (subtractOffset off w) = true) (i : Fin q) :
    relatedSpendAdvantageAt keyGen offGen isShort q adv i ≤
      spendForgeryAdvantage keyGen isShort'
        (relatedSpendReduction keyGen offGen q adv isShort' i) := by
  have hexp : SIS.experiment (ownershipSISProblem keyGen isShort')
      (relatedSpendReduction keyGen offGen q adv isShort' i) =
      (fun x => ownershipValid isShort' x.1 (subtractOffset (x.2.1 i).1 x.2.2.2)) <$>
        relatedSpendRun keyGen offGen q adv := by
    simp only [SIS.experiment, ownershipSISProblem, relatedSpendReduction, relatedSpendRun,
      map_eq_bind_pure_comp, Function.comp_def, bind_assoc, pure_bind]
  unfold relatedSpendAdvantageAt spendForgeryAdvantage SIS.advantage
  rw [hexp, probOutput_map]
  refine probEvent_mono'' fun x hx => ?_
  obtain ⟨hi, hwin⟩ := hx
  subst hi
  exact ownershipValid_subtractOffset hshort x.1 (x.2.1 x.2.2.1).1 (x.2.1 x.2.2.1).2 x.2.2.2 hwin

/-- **The related-key spend bound.** `q` times the master key's ownership
forgery advantage, over the `q` offset-subtraction reductions. -/
theorem relatedSpendAdvantage_le_mul_spendForgery
    (isShort' : ((Fin l → R) × (Fin k → R)) → Bool)
    (hshort : ∀ w off, isShort w = true → offShort off = true →
      isShort' (subtractOffset off w) = true)
    {ε : ℝ≥0∞}
    (hε : ∀ i, spendForgeryAdvantage keyGen isShort'
      (relatedSpendReduction keyGen offGen q adv isShort' i) ≤ ε) :
    relatedSpendAdvantage keyGen offGen isShort q adv ≤ q * ε :=
  relatedSpendAdvantage_le_mul keyGen offGen isShort q adv fun i =>
    (relatedSpendAdvantageAt_le_spendForgery keyGen offGen isShort q adv isShort' hshort i).trans
      (hε i)

end Search

/-! ## 5. The ML-DSA instance -/

section MLDSAInstance

open LatticeCrypto MLDSA MLDSA.Concrete

/-- Centered infinity norm is sub-additive under subtraction. -/
theorem cInfNorm_sub_le (f g : Rq) : cInfNorm (f - g) ≤ cInfNorm f + cInfNorm g := by
  apply cInfNorm_le_of_coeff_le
  intro i
  rw [Rq.get_sub, sub_eq_add_neg, centeredRepr_eq_valMinAbs]
  calc ((f.get i + -g.get i).valMinAbs).natAbs
      ≤ ((f.get i).valMinAbs + (-g.get i).valMinAbs).natAbs :=
        ZMod.natAbs_valMinAbs_add_le _ _
    _ ≤ ((f.get i).valMinAbs).natAbs + ((-g.get i).valMinAbs).natAbs :=
        Int.natAbs_add_le _ _
    _ = ((f.get i).valMinAbs).natAbs + ((g.get i).valMinAbs).natAbs := by
        rw [ZMod.natAbs_valMinAbs_neg]
    _ ≤ cInfNorm f + cInfNorm g := by
        rw [← centeredRepr_eq_valMinAbs, ← centeredRepr_eq_valMinAbs]
        exact Nat.add_le_add (coeff_le_cInfNorm f i) (coeff_le_cInfNorm g i)

/-- A `b`-short witness minus an `η`-short offset is `(b + η)`-short. -/
theorem mldsaShort_subtractOffset (b eta : ℕ) (w : (Fin l → Rq) × (Fin k → Rq))
    (off : Offset Rq k l) (hw : mldsaShort b w = true) (hoff : mldsaShort eta off = true) :
    mldsaShort (b + eta) (subtractOffset off w) = true := by
  simp only [mldsaShort, decide_eq_true_eq, subtractOffset, Pi.sub_apply] at hw hoff ⊢
  exact ⟨fun i => (cInfNorm_sub_le _ _).trans (Nat.add_le_add (hw.1 i) (hoff.1 i)),
    fun i => (cInfNorm_sub_le _ _).trans (Nat.add_le_add (hw.2 i) (hoff.2 i))⟩

/-- **ML-DSA related-key spend bound.** With `b`-short spend witnesses and
`η`-short offsets, the related-key advantage is at most `q` times the master
key's ownership-forgery advantage at bound `b + η`. -/
theorem mldsa_relatedSpendAdvantage_le
    (keyGen : ProbComp (OwnershipKey Rq k l)) (b eta q : ℕ)
    (offGen : ProbComp (ShortOffset Rq k l (mldsaShort eta)))
    (adv : RelatedSpendAdv Rq k l (mldsaShort eta) q) {ε : ℝ≥0∞}
    (hε : ∀ i, spendForgeryAdvantage keyGen (mldsaShort (b + eta))
      (relatedSpendReduction keyGen offGen q adv (mldsaShort (b + eta)) i) ≤ ε) :
    relatedSpendAdvantage keyGen offGen (mldsaShort b) q adv ≤ q * ε :=
  relatedSpendAdvantage_le_mul_spendForgery keyGen offGen (mldsaShort b) q adv
    (mldsaShort (b + eta)) (mldsaShort_subtractOffset b eta) hε

end MLDSAInstance

/-! ## 6. Signature-layer losses (defined, not composed)

The deployed spend signs with Fiat-Shamir-with-aborts over the ownership
relation. Reducing its EUF-CMA security to the ownership-forgery game above
costs the classical-ROM CMA-to-NMA loss (`FiatShamirWithAbort.cmaToNmaLoss`)
and, for a signer capped at `maxAttempts` retries, a truncation loss. Both are
recorded here as nonnegative reals with their sign hypotheses explicit; the
reduction that consumes them is the follow-up in `Ownership.lean` §4, and
VCVio's own `euf_cma_bound` is still a placeholder at the pin. -/

/-- Sign conditions under which the CMA-to-NMA loss is a nonnegative real. -/
structure CmaToNmaAssumption (eps pAbort zetaWide delta : ℝ) : Prop where
  /-- Commitment-guessing bound. -/
  eps_nonneg : 0 ≤ eps
  /-- Effective abort probability. -/
  p_nonneg : 0 ≤ pAbort
  /-- Abort probability is strictly below one. -/
  p_lt_one : pAbort < 1
  /-- HVZK simulator error. -/
  zeta_nonneg : 0 ≤ zetaWide
  /-- Regularity failure bound. -/
  delta_nonneg : 0 ≤ delta

/-- The CMA-to-NMA loss of `FiatShamirWithAbort.cmaToNmaLoss` as a nonnegative
real, under `CmaToNmaAssumption`. -/
noncomputable def CmaToNmaLossNN (qS qH : ℕ) (eps pAbort zetaWide delta : ℝ)
    (h : CmaToNmaAssumption eps pAbort zetaWide delta) : NNReal :=
  ⟨2 * qS * (qH + 1) * eps / (1 - pAbort)
     + qS * eps * (qS + 1) / (2 * (1 - pAbort) ^ 2)
     + qS * zetaWide + delta, by
    have h1 : 0 < 1 - pAbort := by linarith [h.p_lt_one]
    have := h.eps_nonneg
    have := h.zeta_nonneg
    have := h.delta_nonneg
    positivity⟩

/-- The value of `CmaToNmaLossNN` is `FiatShamirWithAbort.cmaToNmaLoss`. -/
theorem CmaToNmaLossNN_val (qS qH : ℕ) (eps pAbort zetaWide delta : ℝ)
    (h : CmaToNmaAssumption eps pAbort zetaWide delta) :
    (CmaToNmaLossNN qS qH eps pAbort zetaWide delta h).1 =
      FiatShamirWithAbort.cmaToNmaLoss qS qH eps pAbort zetaWide delta h.p_lt_one := rfl

/-- Loss from capping the signer at `maxAttempts` retries: `qS · pAbort^maxAttempts`. -/
def TruncationLossNN (qS : ℕ) (pAbort : ℝ) (hp : 0 ≤ pAbort) (maxAttempts : ℕ) : NNReal :=
  ⟨qS * pAbort ^ maxAttempts, by positivity⟩

/-- Bridge from an unbounded-retry signer to the `maxAttempts`-capped game: the
unbounded advantage exceeds the capped one by at most the truncation loss. Stated
on two abstract advantages because the signature-layer game is not defined here. -/
structure UnboundedSigningAssumption (qS maxAttempts : ℕ) (pAbort : ℝ) (hp : 0 ≤ pAbort)
    (advUnbounded advCapped : ℝ) : Prop where
  /-- The truncation bridge. -/
  bridge : advUnbounded ≤ advCapped + (TruncationLossNN qS pAbort hp maxAttempts).1

end PqStealth
