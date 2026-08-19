import PqStealth.Invariants
import LatticeCrypto.HardnessAssumptions.ShortIntegerSolution

/-!
# The spend side: ownership forgery as matrix-SIS

Proved: spend forgery -- producing a short `(s, e)` with `A *ᵥ s + e = t` for a
target you were not given -- cast as a VCVio `SIS.Problem`, with the honest
blinded witness always valid; the `[A | I | -t]` augmentation reshaping that
inhomogeneous instance into VCVio's HOMOGENEOUS matrix-SIS, with an EQUALITY of
advantages and a validity predicate equal on the nose to `SIS.matrixProblem`'s;
and the ML-DSA instance, where winning the game is literally producing a signing
key (`ownershipValid_mldsaShort_iff_isSigningKey`).

Assumed: HNF absorption and MLWE pseudorandomness of `t` -- the challenge here
is the scheme's distribution, not uniform -- and the whole Fiat-Shamir /
signature-of-knowledge layer. See `docs/msis-reshaping.md`.
-/

open OracleComp OracleSpec Matrix ENNReal

namespace PqStealth

variable {R : Type} [CommRing R] {k l : ℕ}

/-! ## 1. Spend forgery as a search problem -/

/-- A stealth public key viewed as an ownership statement: the public matrix `A`
and the target `t`. -/
structure OwnershipKey (R : Type) [CommRing R] (k l : ℕ) where
  /-- The public matrix of the ownership relation. -/
  A : Matrix (Fin k) (Fin l) R
  /-- The target vector: the stealth public key proper. -/
  t : Fin k → R

section Search

variable [DecidableEq (Fin k → R)]

/-- A spend witness `(s, e)` is valid when it is short and satisfies the
ownership relation `A * s + e = t`. -/
def ownershipValid
    (isShort : ((Fin l → R) × (Fin k → R)) → Bool)
    (key : OwnershipKey R k l) (w : (Fin l → R) × (Fin k → R)) : Bool :=
  isShort w && decide (key.A *ᵥ w.1 + w.2 = key.t)

/-- The spend / ownership forgery problem in VCVio's SIS framework: sample a
stealth key, the adversary must produce a valid witness. An inhomogeneous MSIS
instance; bound to the message via Fiat-Shamir it is `SelfTargetMSIS`. -/
def ownershipSISProblem (keyGen : ProbComp (OwnershipKey R k l))
    (isShort : ((Fin l → R) × (Fin k → R)) → Bool) :
    SIS.Problem (OwnershipKey R k l) ((Fin l → R) × (Fin k → R)) where
  sampleChallenge := keyGen
  isValid := ownershipValid isShort

/-- Spend unforgeability advantage: the probability of forging a valid ownership
witness for a fresh stealth key. Definitionally VCVio's SIS advantage. -/
noncomputable def spendForgeryAdvantage (keyGen : ProbComp (OwnershipKey R k l))
    (isShort : ((Fin l → R) × (Fin k → R)) → Bool)
    (adv : SIS.Adversary (ownershipSISProblem keyGen isShort)) : ℝ≥0∞ :=
  SIS.advantage (ownershipSISProblem keyGen isShort) adv

/-- The forgery advantage is a probability, hence finite. -/
theorem spendForgeryAdvantage_ne_top (keyGen : ProbComp (OwnershipKey R k l))
    (isShort : ((Fin l → R) × (Fin k → R)) → Bool)
    (adv : SIS.Adversary (ownershipSISProblem keyGen isShort)) :
    spendForgeryAdvantage keyGen isShort adv ≠ ⊤ :=
  ne_top_of_le_ne_top ENNReal.one_ne_top probOutput_le_one

/-- The forgery advantage as a real number: the `ℝ` view used when a spend bound
is chained with the distinguishing advantages, which are all `ℝ`. Nothing is
lost (`spendForgeryAdvantage_ne_top`). -/
noncomputable def spendForgeryAdvantageReal (keyGen : ProbComp (OwnershipKey R k l))
    (isShort : ((Fin l → R) × (Fin k → R)) → Bool)
    (adv : SIS.Adversary (ownershipSISProblem keyGen isShort)) : ℝ :=
  (spendForgeryAdvantage keyGen isShort adv).toReal

/-- A short honest witness is a fully valid spend witness for its stealth key:
the relation half is the correctness identity (`blinded_is_ownership_witness`),
the shortness half is the hypothesis. Honest spending never fails. -/
theorem honest_witness_valid (A : Matrix (Fin k) (Fin l) R) (s₁ s' : Fin l → R) (s₂ e' : Fin k → R)
    (isShort : ((Fin l → R) × (Fin k → R)) → Bool)
    (hshort : isShort (s₁ + s', s₂ + e') = true) :
    ownershipValid isShort ⟨A, A *ᵥ s' + e' + (A *ᵥ s₁ + s₂)⟩ (s₁ + s', s₂ + e')
      = true := by
  simp only [ownershipValid, hshort, Bool.true_and, decide_eq_true_eq]
  exact blinded_is_ownership_witness A s₁ s' s₂ e'

end Search

/-! ## 2. Reshaping into homogeneous matrix-SIS

`M = [A | I | -t]` gives `M *ᵥ (s, e, 1) = A *ᵥ s + e - t`; carrying the marker
`1` in the shortness predicate makes the correspondence a bijection on VALID
solutions, so the advantages are equal, not merely comparable. -/

/-- The `[A | I | -t]` augmentation of an ownership key: the `k × (l+k+1)`
matrix whose homogeneous kernel elements with last coordinate `1` are exactly
the ownership witnesses for `(A, t)`. -/
def augmentedMatrix (key : OwnershipKey R k l) :
    Matrix (Fin k) (Fin (l + k + 1)) R :=
  Matrix.of fun i =>
    Fin.append (Fin.append (key.A i) ((1 : Matrix (Fin k) (Fin k) R) i)) ![-key.t i]

/-- The witness embedding `(s, e) ↦ (s, e, 1)` into the augmented solution
space. -/
def augmentedWitness (w : (Fin l → R) × (Fin k → R)) : Fin (l + k + 1) → R :=
  Fin.append (Fin.append w.1 w.2) ![1]

/-- Read the ownership key back off an augmented matrix: `A` is the left block,
`t` the negated last column. Left inverse of `augmentedMatrix`, which is what
lets a forger for the homogeneous problem be built from an ownership forger. -/
def readKey (M : Matrix (Fin k) (Fin (l + k + 1)) R) : OwnershipKey R k l where
  A := fun i j => M i ((j.castAdd k).castAdd 1)
  t := fun i => -M i (Fin.natAdd (l + k) 0)

/-- Shortness on the augmented space: the original bound on `(s, e)`, plus the
affine marker coordinate being `1` — which is what pins a kernel vector to the
inhomogeneous solution it came from. -/
def augmentedShort [DecidableEq R]
    (isShort : ((Fin l → R) × (Fin k → R)) → Bool)
    (z : Fin (l + k + 1) → R) : Bool :=
  isShort (fun j => z ((j.castAdd k).castAdd 1),
      fun j => z ((Fin.natAdd l j).castAdd 1)) &&
    decide (z (Fin.natAdd (l + k) 0) = 1)

/-- Reading the ownership key back off the augmented matrix `[A | I | -t]`
recovers it exactly. -/
@[simp] theorem readKey_augmentedMatrix (key : OwnershipKey R k l) :
    readKey (augmentedMatrix key) = key := by
  obtain ⟨A, t⟩ := key
  simp only [readKey, augmentedMatrix, Matrix.of_apply, Fin.append_left,
    Fin.append_right, Matrix.cons_val_fin_one, neg_neg]

/-- The augmented shortness test agrees with the original one on augmented
witnesses: the appended marker coordinate `1` is not scored. -/
@[simp] theorem augmentedShort_augmentedWitness [DecidableEq R]
    (isShort : ((Fin l → R) × (Fin k → R)) → Bool)
    (w : (Fin l → R) × (Fin k → R)) :
    augmentedShort isShort (augmentedWitness w) = isShort w := by
  simp only [augmentedShort, augmentedWitness, Fin.append_left, Fin.append_right,
    Matrix.cons_val_fin_one, decide_true, Bool.and_true, Prod.mk.eta]

/-- The augmented witness is never the zero vector: its marker coordinate is
`1`. This is the `x ≠ 0` conjunct of VCVio's matrix-SIS validity. -/
theorem augmentedWitness_ne_zero [Nontrivial R]
    (w : (Fin l → R) × (Fin k → R)) : augmentedWitness w ≠ 0 := by
  intro h
  have : augmentedWitness w (Fin.natAdd (l + k) 0) = 0 := by rw [h]; rfl
  simp only [augmentedWitness, Fin.append_right, Matrix.cons_val_fin_one] at this
  exact one_ne_zero this

/-- The defining computation: `[A | I | -t] *ᵥ (s, e, 1) = A *ᵥ s + e - t`. -/
theorem augmentedMatrix_mulVec_augmentedWitness (key : OwnershipKey R k l)
    (w : (Fin l → R) × (Fin k → R)) :
    augmentedMatrix key *ᵥ augmentedWitness w = key.A *ᵥ w.1 + w.2 - key.t := by
  funext i
  simp only [Matrix.mulVec, dotProduct, augmentedMatrix, augmentedWitness,
    Matrix.of_apply, Pi.add_apply, Pi.sub_apply]
  rw [Fin.sum_univ_add, Fin.sum_univ_add]
  simp only [Fin.append_left, Fin.append_right, Matrix.cons_val_fin_one,
    Fin.sum_univ_one, Matrix.one_apply, ite_mul, one_mul, zero_mul,
    Finset.sum_ite_eq, Finset.mem_univ, if_true, mul_one]
  ring

/-- Validity transfers exactly: the augmented vector `(s, e, 1)` passes VCVio's
homogeneous matrix-SIS check against `[A | I | -t]` iff `(s, e)` is a valid
ownership witness for `(A, t)`. -/
theorem augmented_isValid_eq_ownershipValid [DecidableEq R] [Nontrivial R]
    (isShort : ((Fin l → R) × (Fin k → R)) → Bool) (key : OwnershipKey R k l)
    (w : (Fin l → R) × (Fin k → R)) :
    (decide (augmentedWitness w ≠ 0) &&
        augmentedShort isShort (augmentedWitness w) &&
        decide (augmentedMatrix key *ᵥ augmentedWitness w = 0))
      = ownershipValid isShort key w := by
  rw [augmentedMatrix_mulVec_augmentedWitness]
  simp only [augmentedShort_augmentedWitness, augmentedWitness_ne_zero,
    ne_eq, not_false_eq_true, decide_true, Bool.true_and, ownershipValid,
    sub_eq_zero]

/-- The homogeneous reshaping: hand the adversary `[A | I | -t]` and ask for a
short nonzero kernel vector carrying the marker. The validity predicate is
LITERALLY VCVio's; only the challenge distribution is the scheme's. -/
def augmentedSISProblem [DecidableEq R]
    (keyGen : ProbComp (OwnershipKey R k l))
    (isShort : ((Fin l → R) × (Fin k → R)) → Bool) :
    SIS.Problem (Matrix (Fin k) (Fin (l + k + 1)) R) (Fin (l + k + 1) → R) where
  sampleChallenge := do
    let key ← keyGen
    return augmentedMatrix key
  isValid M z := decide (z ≠ 0) && augmentedShort isShort z && decide (M *ᵥ z = 0)

/-- The reshaped adversary: recover `(A, t)` from the augmented matrix, run the
ownership forger, embed its witness as a kernel vector. -/
def augmentedAdversary [DecidableEq R]
    (keyGen : ProbComp (OwnershipKey R k l))
    (isShort : ((Fin l → R) × (Fin k → R)) → Bool)
    (adv : SIS.Adversary (ownershipSISProblem keyGen isShort)) :
    SIS.Adversary (augmentedSISProblem keyGen isShort) :=
  fun M => do
    let w ← adv (readKey M)
    return augmentedWitness w

/-- **Spend forgery in homogeneous matrix-SIS form.** An EQUALITY, not a bound:
the augmentation and the marker make valid solutions correspond one-to-one. The
challenge distribution is the scheme's, not a uniform matrix. -/
theorem spendForgeryAdvantage_eq_sis_advantage [DecidableEq R] [Nontrivial R]
    (keyGen : ProbComp (OwnershipKey R k l))
    (isShort : ((Fin l → R) × (Fin k → R)) → Bool)
    (adv : SIS.Adversary (ownershipSISProblem keyGen isShort)) :
    spendForgeryAdvantage keyGen isShort adv
      = SIS.advantage (augmentedSISProblem keyGen isShort)
          (augmentedAdversary keyGen isShort adv) := by
  simp only [spendForgeryAdvantage, SIS.advantage, SIS.experiment,
    ownershipSISProblem, augmentedSISProblem, augmentedAdversary,
    bind_assoc, pure_bind, readKey_augmentedMatrix,
    augmented_isValid_eq_ownershipValid]

/-- The `≤` form, for chaining: spend forgery is bounded by the SIS advantage
on the AUGMENTED problem. NOT yet "bounded by the MSIS assumption": the
challenge is the scheme's key distribution, and only the scoring function is
VCVio's. See `docs/msis-reshaping.md`. -/
theorem spendForgeryAdvantage_le_augmentedSIS [DecidableEq R] [Nontrivial R]
    (keyGen : ProbComp (OwnershipKey R k l))
    (isShort : ((Fin l → R) × (Fin k → R)) → Bool)
    (adv : SIS.Adversary (ownershipSISProblem keyGen isShort)) :
    spendForgeryAdvantage keyGen isShort adv
      ≤ SIS.advantage (augmentedSISProblem keyGen isShort)
          (augmentedAdversary keyGen isShort adv) :=
  le_of_eq (spendForgeryAdvantage_eq_sis_advantage keyGen isShort adv)

/-- Non-vacuity: the honest blinded witness, when short, passes the augmented
check too, so the equality above is not between two unsatisfiable predicates. -/
theorem honest_augmented_witness_valid [DecidableEq R] [Nontrivial R]
    (keyGen : ProbComp (OwnershipKey R k l))
    (A : Matrix (Fin k) (Fin l) R) (s₁ s' : Fin l → R) (s₂ e' : Fin k → R)
    (isShort : ((Fin l → R) × (Fin k → R)) → Bool)
    (hshort : isShort (s₁ + s', s₂ + e') = true) :
    (augmentedSISProblem keyGen isShort).isValid
        (augmentedMatrix ⟨A, A *ᵥ s' + e' + (A *ᵥ s₁ + s₂)⟩)
        (augmentedWitness (s₁ + s', s₂ + e')) = true := by
  simp only [augmentedSISProblem, augmented_isValid_eq_ownershipValid]
  exact honest_witness_valid A s₁ s' s₂ e' isShort hshort

section VCVioMatrixSIS

variable [DecidableEq R] [SampleableType R]

/-- The reshaped problem's validity predicate IS VCVio's `SIS.matrixProblem`
predicate at `n = k`, `m = l + k + 1`: a spend forger is scored by exactly the
function `SIS.matrixProblem` scores solutions by. -/
theorem augmentedSISProblem_isValid_eq_matrixProblem
    (keyGen : ProbComp (OwnershipKey R k l))
    (isShort : ((Fin l → R) × (Fin k → R)) → Bool) :
    (augmentedSISProblem keyGen isShort).isValid
      = (SIS.matrixProblem k (l + k + 1) (augmentedShort isShort)).isValid :=
  rfl

end VCVioMatrixSIS

/-! ### What is proved and what is assumed

The equality above is an exact RESHAPING, not yet a reduction to uniform MSIS:
the challenge is `keyGen >>= (pure ∘ augmentedMatrix)`, not `$ᵗ Matrix …`. Two
statements close that gap, neither proved here -- HNF absorption, and MLWE
pseudorandomness of `t`. Both are spelled out in `docs/msis-reshaping.md`. -/

/-! ## 3. The ML-DSA instance

Everything above at `R := Rq` with the real range check, so that winning the SIS
game and producing a signing key one was never given are the same statement. -/

open LatticeCrypto MLDSA MLDSA.Concrete

/-- `Rq` is nontrivial: the constant polynomial `1` differs from `0` in its
degree-zero coefficient. Needed for the `z ≠ 0` conjunct of matrix-SIS
validity. -/
theorem rq_one_ne_zero : (1 : Rq) ≠ (0 : Rq) := by
  intro h
  have h1 : (1 : Rq) =
      Vector.ofFn (fun i : Fin ringDegree => if (i : ℕ) = 0 then (1 : Coeff) else 0) := rfl
  rw [h1] at h
  have h0 := congrArg (fun v : Vector Coeff ringDegree => v.get ⟨0, by norm_num [ringDegree]⟩) h
  rw [Vector.get_ofFn, Rq.get_zero] at h0
  simp only [↓reduceIte] at h0
  exact absurd h0 (by decide)

/-- `Rq` is nontrivial, from `rq_one_ne_zero`. -/
instance instNontrivialRq : Nontrivial Rq := ⟨1, 0, rq_one_ne_zero⟩

/-- The ML-DSA range check on an ownership witness: every coordinate of `s` and
of `e` is `bound`-short in the centered infinity norm. This is the Boolean form
of `IsShortPair`. -/
def mldsaShort (bound : ℕ) (w : (Fin l → Rq) × (Fin k → Rq)) : Bool :=
  decide ((∀ i, cInfNorm (w.1 i) ≤ bound) ∧ (∀ i, cInfNorm (w.2 i) ≤ bound))

/-- Winning the ML-DSA spend-forgery game is exactly producing a signing key: the
game's Boolean validity predicate holds iff `IsSigningKey` does. -/
theorem ownershipValid_mldsaShort_iff_isSigningKey (bound : ℕ)
    (key : OwnershipKey Rq k l) (w : (Fin l → Rq) × (Fin k → Rq)) :
    ownershipValid (mldsaShort bound) key w = true
      ↔ IsSigningKey key.A key.t w.1 w.2 bound := by
  simp only [ownershipValid, mldsaShort, Bool.and_eq_true, decide_eq_true_eq,
    IsSigningKey, IsOwnershipWitness, IsShortPair]
  exact and_comm

/-- **The ML-DSA spend bound.** At `Rq` with the real range check, forging an
ML-DSA signing key for a fresh stealth key has exactly the matrix-SIS advantage
of the reshaped adversary against `[A | I | -t]`. -/
theorem mldsa_spendForgeryAdvantage_eq_sis_advantage
    (keyGen : ProbComp (OwnershipKey Rq k l)) (bound : ℕ)
    (adv : SIS.Adversary (ownershipSISProblem keyGen (mldsaShort bound))) :
    spendForgeryAdvantage keyGen (mldsaShort bound) adv
      = SIS.advantage (augmentedSISProblem keyGen (mldsaShort bound))
          (augmentedAdversary keyGen (mldsaShort bound) adv) :=
  spendForgeryAdvantage_eq_sis_advantage keyGen (mldsaShort bound) adv

/-! ## 4. Follow-up: signature-of-knowledge unforgeability

What is proved above is the SEARCH core. The deployed spend is a signature of
knowledge, so full unforgeability is EUF-CMA of a Fiat-Shamir-with-aborts
signature reducing to `SelfTargetMSIS`. The route -- Sigma protocol at the
widened bound, special soundness and HVZK, Fiat-Shamir, forking lemma -- is laid
out in `docs/msis-reshaping.md`; none of it is implemented here. -/

end PqStealth
