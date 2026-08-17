/-
Spend-side security: the ownership proof as a hard search problem (MSIS).

Spending a stealth account means proving knowledge of a short `(s, e)` with
`A * s + e = t` (the signing-key relation from `Invariants`), bound to the
transaction. Forging a spend therefore means producing such a witness for a
target `t` you were not given -- an inhomogeneous Short Integer Solution
instance.

This file
  1. casts spend forgery as a VCVio `SIS.Problem`, with the honest side proved
     trivial (the blinded secret is always a valid witness);
  2. reshapes that inhomogeneous instance into the *homogeneous* matrix-SIS
     shape VCVio's `SIS.matrixProblem` uses, via the standard `[A | I | -t]`
     augmentation, and proves the two advantages are *equal* -- so the MSIS
     claim is a theorem about VCVio's predicate rather than a naming
     convention;
  3. instantiates all of it at the ML-DSA ring `Rq` with the real centered
     infinity-norm bound, and shows the game-level validity predicate is
     exactly `IsSigningKey`.

Scope: this captures the SEARCH core (produce a witness = solve MSIS). The full
signature-of-knowledge unforgeability -- message binding via Fiat-Shamir, the
forking-lemma extraction, HVZK -- is the deeper reduction to `SelfTargetMSIS`;
see the follow-up section at the end of this file.
-/

import PqStealth.Invariants
import LatticeCrypto.HardnessAssumptions.ShortIntegerSolution

open OracleComp OracleSpec Matrix ENNReal

namespace PqStealth

variable {R : Type} [CommRing R] {k l : ℕ}

/-! ## 1. Spend forgery as a search problem -/

/-- A stealth public key viewed as an ownership statement: the public matrix `A`
and the target `t`. -/
structure OwnershipKey (R : Type) [CommRing R] (k l : ℕ) where
  A : Matrix (Fin k) (Fin l) R
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

/-- The forgery advantage as a real number.

VCVio states search advantages in `ℝ≥0∞` (`SIS.advantage` is a `probOutput`),
while every distinguishing advantage in this development
(`ProbComp.boolDistAdvantage` and the KEM/MLWE bounds built on it) is `ℝ`. The
`ℝ≥0∞` form is kept as the definition -- it is the one that is definitionally
VCVio's -- and this is the `ℝ` view used when a spend bound has to be added to,
or chained with, those advantages. Nothing is lost in the conversion:
`spendForgeryAdvantage_ne_top`. -/
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

VCVio's `SIS.matrixProblem` is the *homogeneous* problem: find a short nonzero
`z` with `M *ᵥ z = 0`. The ownership problem is inhomogeneous (`A *ᵥ s + e = t`).
The standard bridge is the augmentation `M = [A | I | -t]`, under which
`M *ᵥ (s, e, 1) = A *ᵥ s + e - t`: kernel vectors whose last coordinate is `1`
are exactly the ownership witnesses, with `e` absorbed by the identity block.
Carrying the marker `1` in the shortness predicate makes the correspondence a
bijection on *valid* solutions, so the advantages are equal, not merely
comparable.
-/

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

/-- Shortness lifted to the augmented solution space: the original bound on the
`(s, e)` block, plus the requirement that the affine marker coordinate is `1`.
The marker check is what pins the kernel vector to the inhomogeneous solution
it came from. -/
def augmentedShort [DecidableEq R]
    (isShort : ((Fin l → R) × (Fin k → R)) → Bool)
    (z : Fin (l + k + 1) → R) : Bool :=
  isShort (fun j => z ((j.castAdd k).castAdd 1),
      fun j => z ((Fin.natAdd l j).castAdd 1)) &&
    decide (z (Fin.natAdd (l + k) 0) = 1)

@[simp] theorem readKey_augmentedMatrix (key : OwnershipKey R k l) :
    readKey (augmentedMatrix key) = key := by
  obtain ⟨A, t⟩ := key
  simp only [readKey, augmentedMatrix, Matrix.of_apply, Fin.append_left,
    Fin.append_right, Matrix.cons_val_fin_one, neg_neg]

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

/-- The homogeneous reshaping of the ownership problem: sample a stealth key and
hand the adversary `[A | I | -t]`; a solution is a short nonzero kernel vector
carrying the affine marker. The validity predicate is *literally* VCVio's
matrix-SIS predicate (`augmentedSISProblem_isValid_eq_matrixProblem`); only the
challenge distribution is the scheme's rather than uniform. -/
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

/-- **Spend forgery in homogeneous matrix-SIS form.** The ownership forgery
advantage equals the advantage of the reshaped adversary against
`[A | I | -t]` -- an equality, not a bound: the augmentation and the marker
coordinate make valid solutions correspond one-to-one. The right-hand side uses
the scheme's challenge distribution, not a uniform matrix; see *What is proved
and what is assumed* below. -/
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

/-- The `≤` form of `spendForgeryAdvantage_eq_sis_advantage`, for chaining into
larger bounds.

Read the right-hand side precisely: it is `augmentedSISProblem`, whose
`sampleChallenge` is the scheme's `keyGen >>= pure ∘ augmentedMatrix`, *not*
VCVio's uniform `SIS.matrixProblem`. Only the scoring function is VCVio's, and
that on the nose (`augmentedSISProblem_isValid_eq_matrixProblem`). So this is
not yet "spend forgery is bounded by the MSIS assumption"; it is that bound
modulo the two lemmas stated in *What is proved and what is assumed* below. -/
theorem spendForgeryAdvantage_le_msis [DecidableEq R] [Nontrivial R]
    (keyGen : ProbComp (OwnershipKey R k l))
    (isShort : ((Fin l → R) × (Fin k → R)) → Bool)
    (adv : SIS.Adversary (ownershipSISProblem keyGen isShort)) :
    spendForgeryAdvantage keyGen isShort adv
      ≤ SIS.advantage (augmentedSISProblem keyGen isShort)
          (augmentedAdversary keyGen isShort adv) :=
  le_of_eq (spendForgeryAdvantage_eq_sis_advantage keyGen isShort adv)

/-- Non-vacuity of the reshaping: the honest blinded witness, when short, passes
the augmented homogeneous check too. A real ownership solution maps to a real
kernel vector, so `spendForgeryAdvantage_eq_sis_advantage` is not an equality
between two unsatisfiable predicates. -/
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

/-- The reshaped problem's validity predicate *is* VCVio's `SIS.matrixProblem`
predicate at `n = k`, `m = l + k + 1`. This is the literal link to VCVio's MSIS:
after `spendForgeryAdvantage_eq_sis_advantage`, a spend forger is scored by
exactly the function `SIS.matrixProblem` scores solutions by. -/
theorem augmentedSISProblem_isValid_eq_matrixProblem
    (keyGen : ProbComp (OwnershipKey R k l))
    (isShort : ((Fin l → R) × (Fin k → R)) → Bool) :
    (augmentedSISProblem keyGen isShort).isValid
      = (SIS.matrixProblem k (l + k + 1) (augmentedShort isShort)).isValid :=
  rfl

end VCVioMatrixSIS

/-! ### What is proved and what is assumed

`spendForgeryAdvantage_eq_sis_advantage` is an exact *reshaping*: it puts spend
forgery into VCVio's homogeneous matrix-SIS shape and shows the two advantages
are equal, with the scoring function equal on the nose to `SIS.matrixProblem`'s
(`augmentedSISProblem_isValid_eq_matrixProblem`). It is *not* yet a reduction to
the standard uniform-MSIS assumption, because
`(augmentedSISProblem keyGen isShort).sampleChallenge` is the scheme's
distribution `keyGen >>= (pure ∘ augmentedMatrix)`, whereas
`(SIS.matrixProblem k (l+k+1) isShort').sampleChallenge` is
`$ᵗ Matrix (Fin k) (Fin (l+k+1)) R`. Two statements close that gap; neither is
proved here.

* **HNF absorption.** A challenge of the shape `[A | I | -t]` is as hard as a
  uniform one. Precisely: for every `adv` there exists `adv'` with

  `SIS.advantage (augmentedSISProblem uniformKeyGen isShort) adv ≤`
  `SIS.advantage (SIS.matrixProblem k (l+k+1) (augmentedShort isShort)) adv'`

  where `uniformKeyGen` samples `A` and `t` uniformly. The textbook proof
  column-reduces a uniform challenge into Hermite normal form, which over a
  module ring needs an invertible `k × k` block -- the `Rq`-specific step.

* **Target pseudorandomness.** The real `keyGen` is an MLWE sample: `A` is
  uniform but `t = A *ᵥ s₁ + s₂` with `(s₁, s₂)` short. Replacing it by
  `uniformKeyGen` costs the MLWE distinguishing advantage. Precisely, for every
  `adv` the two advantages
  `SIS.advantage (augmentedSISProblem mlweKeyGen isShort) adv` and
  `SIS.advantage (augmentedSISProblem uniformKeyGen isShort) adv` differ by at
  most the advantage of the derived distinguisher against
  `LearningWithErrors.moduleMatrixProblem` -- the same assumption the detection
  side of this development already uses.

Chaining the equality proved here with those two gives
`spendForgeryAdvantage ≤ msisAdvantage + mlweAdvantage`, the bound the spec
claims.
-/

/-! ## 3. The ML-DSA instance

Everything above at `R := Rq`, with `isShort` the real ML-DSA range check: every
coordinate polynomial of `s` and of `e` has centered infinity norm at most the
bound. The Boolean predicate the game uses is then decidably equivalent to
`IsSigningKey` from `Invariants`, so "the adversary wins the SIS game" and "the
adversary produced a signing key it was never given" are the same statement.
-/

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

instance : Nontrivial Rq := ⟨1, 0, rq_one_ne_zero⟩

/-- The ML-DSA range check on an ownership witness: every coordinate of `s` and
of `e` is `bound`-short in the centered infinity norm. This is the Boolean form
of `IsShortPair`. -/
def mldsaShort (bound : ℕ) (w : (Fin l → Rq) × (Fin k → Rq)) : Bool :=
  decide ((∀ i, cInfNorm (w.1 i) ≤ bound) ∧ (∀ i, cInfNorm (w.2 i) ≤ bound))

/-- Winning the ML-DSA spend-forgery game is exactly producing a signing key:
the game's Boolean validity predicate holds iff `IsSigningKey` does. This is the
join between the game layer of this file and the algebraic bridge in
`Invariants`. -/
theorem ownershipValid_mldsaShort_iff_isSigningKey (bound : ℕ)
    (key : OwnershipKey Rq k l) (w : (Fin l → Rq) × (Fin k → Rq)) :
    ownershipValid (mldsaShort bound) key w = true
      ↔ IsSigningKey key.A key.t w.1 w.2 bound := by
  simp only [ownershipValid, mldsaShort, Bool.and_eq_true, decide_eq_true_eq,
    IsSigningKey, IsOwnershipWitness, IsShortPair]
  exact and_comm

/-- **The ML-DSA spend bound.** At `Rq` with the real range check, the
probability of forging an ML-DSA signing key for a freshly sampled stealth key
equals the matrix-SIS advantage of the reshaped adversary against
`[A | I | -t]`. -/
theorem mldsa_spendForgeryAdvantage_eq_sis_advantage
    (keyGen : ProbComp (OwnershipKey Rq k l)) (bound : ℕ)
    (adv : SIS.Adversary (ownershipSISProblem keyGen (mldsaShort bound))) :
    spendForgeryAdvantage keyGen (mldsaShort bound) adv
      = SIS.advantage (augmentedSISProblem keyGen (mldsaShort bound))
          (augmentedAdversary keyGen (mldsaShort bound) adv) :=
  spendForgeryAdvantage_eq_sis_advantage keyGen (mldsaShort bound) adv

/-! ## 4. Follow-up: signature-of-knowledge unforgeability

What is proved above is the *search* core: a spend is a witness for an MSIS
instance, and forging one is solving that instance. The spend actually deployed
(decision D-012) is a signature of knowledge -- the ownership witness proved in
zero knowledge and bound to the transaction -- so full unforgeability is EUF-CMA
of a Fiat-Shamir-with-aborts signature, not just hardness of the search problem.

The route, none of which is implemented here:

* Package the ownership relation as a Sigma protocol
  (`VCVio/CryptoFoundations/SigmaProtocol.lean`): commitment `A *ᵥ y`,
  challenge `c` from `sampleInBall`, response `z = y + c * s` with rejection
  sampling at the widened bound `2*beta` (`beta_blinded_eq_two_beta`).
* Prove special soundness and HVZK for it; the widened bound is exactly what
  the blinded secret needs (`blinded_is_signing_key`).
* Apply VCVio's Fiat-Shamir transform to get a signature of knowledge, with the
  transaction as the bound message.
* Reduce EUF-CMA of the result to `SelfTargetMSIS.Problem`
  (`LatticeCrypto/HardnessAssumptions/ShortIntegerSolution.lean`), which is the
  assumption ML-DSA's own unforgeability rests on; the extraction step is the
  forking lemma over the random oracle already modelled by
  `SelfTargetMSIS.experiment`.
-/

end PqStealth
