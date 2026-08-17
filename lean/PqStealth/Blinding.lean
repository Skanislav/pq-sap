import Mathlib.Data.Matrix.Mul
import LatticeCrypto.Ring.Rounding
import LatticeCrypto.MLDSA.Concrete.Rounding

/-!
# The algebraic core: blinded-key correctness

Proved: `A·s' + e' + (A·s₁ + s₂) = A·(s₁ + s') + (s₂ + e')` over any commutative
ring -- the sender's published value is the honest ML-DSA public key of the
widened secret, which is why the recipient can sign -- and the `Power2Round`
rounding-error bound for the announced key, generic and at the concrete ML-DSA
parameters (`docs/TECHNICAL_SPEC.md` §4).

Assumed: nothing. Pure algebra over VCVio's LatticeCrypto layer.
-/

open LatticeCrypto Matrix

namespace PqStealth

/-! ## 1. The blinded-key correctness identity -/

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

/-! ## 2. Rounding-error bound

`Power2RoundOps.Laws.power2Round_bound` restated for the announced key, then
instantiated at `q = 8380417`, `d = 13`, giving `2^12 = 4096`. -/

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
