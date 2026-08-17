/-
Machine-checked algebraic core for the PQ stealth address scheme
(docs/TECHNICAL_SPEC.md, Section 4): the blinded-key correctness identity
and the Power2Round rounding-error bound, built on VCVio's LatticeCrypto
layer (pinned commit a5f474fd, validated by the week-1 gate build).

Deliberately algebra-only (per plan.md): no game-based security proofs.
-/

import Mathlib.Data.Matrix.Mul
import LatticeCrypto.Ring.Rounding
import LatticeCrypto.MLDSA.Concrete.Rounding

open LatticeCrypto Matrix

namespace PqStealth

/-!
## 1. The blinded-key correctness identity

The recipient's meta key is `t = A *ᵥ s₁ + s₂`; the sender derives the
blinding pair `(s', e')` from the ML-KEM shared secret and publishes (the
rounding of) `t' = A *ᵥ s' + e' + t`. The identity says `t'` is exactly
the ML-DSA public key of the widened secret `(s₁ + s', s₂ + e')` — which
is why the recipient can sign for the stealth key.

Stated over an arbitrary commutative ring, so it instantiates at
`R_q = Z_q[X]/(X^256 + 1)` for every ML-DSA parameter set.
-/

theorem blinded_key_correctness {R : Type*} [CommRing R] {k l : ℕ}
    (A : Matrix (Fin k) (Fin l) R) (s₁ s' : Fin l → R) (s₂ e' : Fin k → R) :
    A *ᵥ s' + e' + (A *ᵥ s₁ + s₂) = A *ᵥ (s₁ + s') + (s₂ + e') := by
  rw [Matrix.mulVec_add]
  abel

/-- The form actually used by the scheme, with the meta key `t` abstracted:
whenever `t = A *ᵥ s₁ + s₂`, the sender's value `A *ᵥ s' + e' + t` equals
the honest public key of the widened secret `(s₁ + s', s₂ + e')`. -/
theorem stealth_pk_eq_blinded_keypair {R : Type*} [CommRing R] {k l : ℕ}
    (A : Matrix (Fin k) (Fin l) R) (s₁ s' : Fin l → R) (s₂ e' t : Fin k → R)
    (ht : t = A *ᵥ s₁ + s₂) :
    A *ᵥ s' + e' + t = A *ᵥ (s₁ + s') + (s₂ + e') := by
  subst ht
  exact blinded_key_correctness A s₁ s' s₂ e'

/-!
## 2. Rounding-error bound

The announced stealth key is `t₁' = Power2Round(t')`; signing needs the
dropped part `t₀'`. The rounding error is bounded by `2^(d-1)` — this is
`Power2RoundOps.Laws.power2Round_bound` in VCVio, restated generically and
then instantiated at the concrete ML-DSA parameters (`q = 8380417`,
`d = 13`), giving the concrete bound `2^12 = 4096`.
-/

theorem stealth_pk_rounding_error {Coeff : Type*} [CommRing Coeff]
    {ring : NegacyclicRing Coeff} [AddCommGroup ring.Poly] {d : ℕ}
    (ops : Power2RoundOps ring d) (cnorm : ring.Poly → ℕ)
    (laws : Power2RoundOps.Laws ops cnorm) (t' : ring.Poly) :
    cnorm (t' - ops.shift2 (ops.power2Round t')) ≤ 2 ^ (d - 1) :=
  laws.power2Round_bound t'

open MLDSA MLDSA.Concrete in
/-- Concrete instantiation at the ML-DSA parameters (`d = 13`): the
rounding error of every announced stealth public key is at most `2^12`.
Uses the proven (sorry-free) `MLDSA.Concrete.concretePower2RoundLaws`. -/
theorem stealth_pk_rounding_error_concrete (t' : Rq) :
    cInfNorm (t' - concretePower2RoundOps.shift2
        (concretePower2RoundOps.power2Round t')) ≤ 2 ^ 12 :=
  concretePower2RoundLaws.power2Round_bound t'

end PqStealth
