/-
Spend-side security: the ownership proof as a hard search problem (MSIS).

Spending a stealth account means proving knowledge of a short `(s, e)` with
`A * s + e = t` (the ownership relation from `Invariants`), bound to the
transaction. Forging a spend therefore means producing such a witness for a
target `t` you were not given -- exactly a Short Integer Solution instance.

This file casts spend-forgery into VCVio's `SIS` framework, so unforgeability
reduces to MSIS: the same search assumption as `SelfTargetMSIS`, which is what
Dilithium's own unforgeability rests on. The honest side is proved trivial --
the blinded secret is always a valid witness (via the correctness identity) --
so honest spending never fails while forgery is MSIS-hard.

Scope: this captures the SEARCH core (produce a witness = solve MSIS). The full
signature-of-knowledge unforgeability -- message binding via Fiat-Shamir, the
forking-lemma extraction, HVZK -- is the deeper reduction to `SelfTargetMSIS`;
VCVio ships the Sigma-protocol and SelfTargetMSIS scaffolding for it.
-/

import PqStealth.Invariants
import LatticeCrypto.HardnessAssumptions.ShortIntegerSolution

open OracleComp OracleSpec Matrix ENNReal

namespace PqStealth

variable {R : Type} [CommRing R] {k l : ℕ}

/-- A stealth public key viewed as an ownership statement: the public matrix `A`
and the target `t`. -/
structure OwnershipKey (R : Type) [CommRing R] (k l : ℕ) where
  A : Matrix (Fin k) (Fin l) R
  t : Fin k → R

/-- A spend witness `(s, e)` is valid when it is short and satisfies the
ownership relation `A * s + e = t`. -/
def ownershipValid [DecidableEq (Fin k → R)]
    (isShort : ((Fin l → R) × (Fin k → R)) → Bool)
    (key : OwnershipKey R k l) (w : (Fin l → R) × (Fin k → R)) : Bool :=
  isShort w && decide (key.A *ᵥ w.1 + w.2 = key.t)

/-- The spend / ownership forgery problem in VCVio's SIS framework: sample a
stealth key, the adversary must produce a valid witness. An inhomogeneous MSIS
instance; bound to the message via Fiat-Shamir it is `SelfTargetMSIS`. -/
def ownershipSISProblem [DecidableEq (Fin k → R)]
    (keyGen : ProbComp (OwnershipKey R k l))
    (isShort : ((Fin l → R) × (Fin k → R)) → Bool) :
    SIS.Problem (OwnershipKey R k l) ((Fin l → R) × (Fin k → R)) where
  sampleChallenge := keyGen
  isValid := ownershipValid isShort

/-- Spend unforgeability advantage: the probability of forging a valid ownership
witness for a fresh stealth key. Definitionally VCVio's SIS advantage, so it is
bounded by MSIS hardness. -/
noncomputable def spendForgeryAdvantage [DecidableEq (Fin k → R)]
    (keyGen : ProbComp (OwnershipKey R k l))
    (isShort : ((Fin l → R) × (Fin k → R)) → Bool)
    (adv : SIS.Adversary (ownershipSISProblem keyGen isShort)) : ℝ≥0∞ :=
  SIS.advantage (ownershipSISProblem keyGen isShort) adv

/-- The honest blinded secret satisfies the ownership relation for its stealth
key -- the relation half of validity, straight from the correctness identity in
`Invariants`. Forgery is MSIS-hard, but honest spending is immediate. -/
theorem honest_witness_relation
    (A : Matrix (Fin k) (Fin l) R) (s₁ s' : Fin l → R) (s₂ e' : Fin k → R) :
    A *ᵥ (s₁ + s') + (s₂ + e') = A *ᵥ s' + e' + (A *ᵥ s₁ + s₂) :=
  blinded_is_ownership_witness A s₁ s' s₂ e'

/-- A short honest witness is a fully valid spend witness for its stealth key. -/
theorem honest_witness_valid [DecidableEq (Fin k → R)]
    (A : Matrix (Fin k) (Fin l) R) (s₁ s' : Fin l → R) (s₂ e' : Fin k → R)
    (isShort : ((Fin l → R) × (Fin k → R)) → Bool)
    (hshort : isShort (s₁ + s', s₂ + e') = true) :
    ownershipValid isShort ⟨A, A *ᵥ s' + e' + (A *ᵥ s₁ + s₂)⟩ (s₁ + s', s₂ + e')
      = true := by
  simp only [ownershipValid, hshort, Bool.true_and, decide_eq_true_eq]
  exact honest_witness_relation A s₁ s' s₂ e'

end PqStealth
