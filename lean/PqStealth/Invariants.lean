/-
Three machine-checked invariants extending the correctness core
(docs/DECISIONS.md, in-scope Lean items 1-3):

  1. Widened-bound signing invariant  -- the blinded secret's norm doubles to
     2*eta, so the signer-side bound is beta' = tau*(2*eta) = 2*beta.
  2. Ownership <-> signing-key bridge  -- the MLWE relation the ZK circuit
     proves, together with the coefficient bound on the witness, is exactly
     "holds an ML-DSA signing key for t", and the blinded secret is such a
     signing key at the widened bound 2*eta.
  3. Encoding roundtrip                -- decode after encode is the identity,
     both for the on-chain stealth public key (via VCVio's encoding laws) and
     for the meta-address wrapper.

Algebra-only, sorry-free, built on VCVio's LatticeCrypto layer.
-/

import Mathlib.Data.Matrix.Mul
import Mathlib.Data.ZMod.ValMinAbs
import PqStealth.Blinding
import LatticeCrypto.MLDSA.Params
import LatticeCrypto.MLDSA.Encoding

open LatticeCrypto Matrix

namespace PqStealth

/-! ## 1. Widened-bound signing invariant

The blinded secret is `s1 + s'` with each summand `eta`-bounded. Its centered
infinity norm is at most `2*eta` by the triangle inequality, so the challenge
product bound `beta = tau * eta` doubles to `beta' = tau * (2*eta)`. We prove
the norm sub-additivity (the reusable core), the doubled coefficient bound, and
the `beta' = 2*beta` identity against VCVio's `beta` definition.
-/

open MLDSA MLDSA.Concrete

/-- Centered infinity norm is sub-additive: `‖f + g‖ ≤ ‖f‖ + ‖g‖`.
The centered representative is `ZMod.valMinAbs`, which is sub-additive in
absolute value (`natAbs_valMinAbs_add_le`), lifted coefficient-wise. -/
theorem cInfNorm_add_le (f g : Rq) :
    cInfNorm (f + g) ≤ cInfNorm f + cInfNorm g := by
  apply cInfNorm_le_of_coeff_le
  intro i
  rw [Rq.get_add, centeredRepr_eq_valMinAbs]
  calc ((f.get i + g.get i).valMinAbs).natAbs
      ≤ ((f.get i).valMinAbs + (g.get i).valMinAbs).natAbs :=
        ZMod.natAbs_valMinAbs_add_le _ _
    _ ≤ ((f.get i).valMinAbs).natAbs + ((g.get i).valMinAbs).natAbs :=
        Int.natAbs_add_le _ _
    _ ≤ cInfNorm f + cInfNorm g := by
        rw [← centeredRepr_eq_valMinAbs, ← centeredRepr_eq_valMinAbs]
        exact Nat.add_le_add (coeff_le_cInfNorm f i) (coeff_le_cInfNorm g i)

/-- The blinded secret coefficient is `2*eta`-bounded when each summand is
`eta`-bounded. This is the invariant behind the doubled signer-side bound. -/
theorem blinded_norm_bound {f g : Rq} {eta : ℕ}
    (hf : cInfNorm f ≤ eta) (hg : cInfNorm g ≤ eta) :
    cInfNorm (f + g) ≤ 2 * eta :=
  (cInfNorm_add_le f g).trans (by omega)

/-- The widened challenge-product bound equals twice the standard `beta`:
`beta' = tau * (2*eta) = 2 * (tau * eta) = 2 * beta`. -/
theorem beta_blinded_eq_two_beta (params : Params) :
    params.tau * (2 * params.eta) = 2 * params.beta := by
  unfold MLDSA.Params.beta; ring

/-! ## 2. Ownership relation <-> signing-key possession

The ZK ownership circuit proves knowledge of a *short* `(s, e)` with
`A * s + e = t`. Those are exactly the two halves of an ML-DSA signing key for
the public key `t`: the linear key-generation relation, and the `eta`
coefficient bound. The relation alone holds over any commutative ring
(`IsOwnershipWitness`); the bound needs the centered infinity norm, so
signing-key possession is stated at the ML-DSA ring `Rq`. The blinded secret
satisfies both, with the bound widened to `2*eta` by section 1.
-/

/-- The MLWE ownership relation the ZK circuit proves: `A *ᵥ s + e = t`.
This is the linear half only; shortness is `IsShortPair`. -/
def IsOwnershipWitness {R : Type*} [CommRing R] {k l : ℕ}
    (A : Matrix (Fin k) (Fin l) R) (t : Fin k → R)
    (s : Fin l → R) (e : Fin k → R) : Prop :=
  A *ᵥ s + e = t

/-- Shortness of a candidate ML-DSA secret at bound `eta`: every coordinate
polynomial of `s` and of `e` has centered infinity norm at most `eta`. -/
def IsShortPair {k l : ℕ} (eta : ℕ) (s : Fin l → Rq) (e : Fin k → Rq) : Prop :=
  (∀ i, cInfNorm (s i) ≤ eta) ∧ (∀ i, cInfNorm (e i) ≤ eta)

/-- Possession of an ML-DSA signing key for the public key `t` at bound `eta`:
a *short* secret `(s, e)` satisfying `A *ᵥ s + e = t`. Both halves are needed —
the linear relation on its own is satisfied by `(0, t)` for every `t`, which is
neither a signing key nor hard to find. -/
def IsSigningKey {k l : ℕ}
    (A : Matrix (Fin k) (Fin l) Rq) (t : Fin k → Rq)
    (s : Fin l → Rq) (e : Fin k → Rq) (eta : ℕ) : Prop :=
  IsOwnershipWitness A t s e ∧ IsShortPair eta s e

/-- The bridge: the ownership relation *together with the coefficient bound* is
possession of an ML-DSA signing key for `t`. The proof is a definitional
unfolding, but the two sides are genuinely different predicates: on the left the
ZK circuit's linear statement plus its range check on the witness, on the right
ML-DSA key generation. A ZK proof of ownership authorizes exactly what a spend
needs precisely when the circuit enforces the bound; the relation alone would
not. -/
theorem ownership_iff_signing {k l : ℕ}
    (A : Matrix (Fin k) (Fin l) Rq) (t : Fin k → Rq)
    (s : Fin l → Rq) (e : Fin k → Rq) (eta : ℕ) :
    (IsOwnershipWitness A t s e ∧
        (∀ i, cInfNorm (s i) ≤ eta) ∧ (∀ i, cInfNorm (e i) ≤ eta)) ↔
      IsSigningKey A t s e eta :=
  Iff.rfl

/-- The blinded secret `(s₁+s', s₂+e')` is an ownership witness for the derived
stealth key — the ZK statement is satisfiable exactly because the correctness
identity holds. -/
theorem blinded_is_ownership_witness {R : Type*} [CommRing R] {k l : ℕ}
    (A : Matrix (Fin k) (Fin l) R) (s₁ s' : Fin l → R) (s₂ e' : Fin k → R) :
    IsOwnershipWitness A (A *ᵥ s' + e' + (A *ᵥ s₁ + s₂)) (s₁ + s') (s₂ + e') :=
  (blinded_key_correctness A s₁ s' s₂ e').symm

/-- The blinded secret is a genuine ML-DSA signing key for the derived stealth
key at the widened bound `2*eta`: the relation comes from the correctness
identity, the bound from `blinded_norm_bound`. This is the honest-spending
guarantee — the recipient always holds a real signing key, never merely a
solution of the linear relation. -/
theorem blinded_is_signing_key {k l : ℕ}
    (A : Matrix (Fin k) (Fin l) Rq) (s₁ s' : Fin l → Rq) (s₂ e' : Fin k → Rq)
    {eta : ℕ}
    (hs₁ : ∀ i, cInfNorm (s₁ i) ≤ eta) (hs' : ∀ i, cInfNorm (s' i) ≤ eta)
    (hs₂ : ∀ i, cInfNorm (s₂ i) ≤ eta) (he' : ∀ i, cInfNorm (e' i) ≤ eta) :
    IsSigningKey A (A *ᵥ s' + e' + (A *ᵥ s₁ + s₂)) (s₁ + s') (s₂ + e')
      (2 * eta) :=
  ⟨blinded_is_ownership_witness A s₁ s' s₂ e',
    fun i => blinded_norm_bound (hs₁ i) (hs' i),
    fun i => blinded_norm_bound (hs₂ i) (he' i)⟩

/-! ## 3. Encoding roundtrip

The on-chain stealth public key is a standard ML-DSA public key, so it
roundtrips through VCVio's encoding laws directly. The meta-address wraps a
version byte and the ML-KEM key around the packed spending key; modelled as a
structural record, it roundtrips whenever the inner key packing does.
-/

open MLDSA.Encoding

/-- The stealth public key roundtrips: decoding the encoded `(rho, t1)` returns
it unchanged — a direct consequence of VCVio's public-key encoding law. -/
theorem stealth_pk_roundtrips {p : Params} {prims : Primitives p}
    (enc : Encoding p prims) (laws : enc.Laws)
    (rho : Bytes 32) (t1 : Vector prims.Power2High p.k) :
    enc.pkDecode (enc.pkEncode rho t1) = (rho, t1) :=
  laws.pkDecode_pkEncode rho t1

/-- The meta-address: a version tag, the packed spending key, and the ML-KEM
viewing key. Generic over the packed-key and viewing-key representations. -/
structure MetaAddress (Packed Kem : Type*) where
  version : Nat
  spendKey : Packed
  viewKey : Kem

/-- Encode a meta-address given a packing of the full-precision spending key. -/
def encodeMeta {T Packed Kem : Type*} (packT : T → Packed)
    (version : Nat) (t : T) (ek : Kem) : MetaAddress Packed Kem :=
  ⟨version, packT t, ek⟩

/-- Decode a meta-address back to its components given an unpacking. -/
def decodeMeta {T Packed Kem : Type*} (unpackT : Packed → T)
    (m : MetaAddress Packed Kem) : Nat × T × Kem :=
  (m.version, unpackT m.spendKey, m.viewKey)

/-- The meta-address roundtrips whenever the inner spending-key packing does. -/
theorem meta_address_roundtrips {T Packed Kem : Type*}
    (packT : T → Packed) (unpackT : Packed → T)
    (hpack : ∀ t, unpackT (packT t) = t)
    (version : Nat) (t : T) (ek : Kem) :
    decodeMeta unpackT (encodeMeta packT version t ek) = (version, t, ek) := by
  simp [decodeMeta, encodeMeta, hpack]

end PqStealth
