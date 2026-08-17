import Mathlib.Data.Matrix.Mul
import Mathlib.Data.ZMod.ValMinAbs
import PqStealth.Blinding
import LatticeCrypto.MLDSA.Params
import LatticeCrypto.MLDSA.Encoding

/-!
# Signing invariants, the ownership bridge, encoding roundtrips

Proved: centered-norm sub-additivity, hence the blinded secret is `2·eta`-short
and the signer bound doubles (`beta' = tau·(2·eta) = 2·beta`); the ownership
relation TOGETHER WITH the coefficient bound IS possession of an ML-DSA signing
key, and the blinded secret is such a key; the stealth public key and the
meta-address wrapper roundtrip through their encodings
(`docs/DECISIONS.md`, Lean items 1-3).

Assumed: nothing. Algebra over VCVio's LatticeCrypto layer.
-/

open LatticeCrypto Matrix

namespace PqStealth

/-! ## 1. Widened-bound signing invariant -/

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

The relation alone holds over any commutative ring; the bound needs the centered
infinity norm, so signing-key possession is stated at `Rq`. -/

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

/-- Possession of an ML-DSA signing key for `t` at bound `eta`: a SHORT `(s, e)`
with `A *ᵥ s + e = t`. Both halves are needed — the relation alone is satisfied
by `(0, t)`, which is neither a signing key nor hard to find. -/
def IsSigningKey {k l : ℕ}
    (A : Matrix (Fin k) (Fin l) Rq) (t : Fin k → Rq)
    (s : Fin l → Rq) (e : Fin k → Rq) (eta : ℕ) : Prop :=
  IsOwnershipWitness A t s e ∧ IsShortPair eta s e

/-- **The bridge.** The ownership relation TOGETHER WITH the coefficient bound is
possession of an ML-DSA signing key: the circuit's statement on the left, ML-DSA
key generation on the right. Definitional, but the predicates differ. -/
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

/-- The honest-spending guarantee: the blinded secret is a genuine ML-DSA signing
key for the derived stealth key at the widened bound `2*eta` — the relation from
the correctness identity, the bound from `blinded_norm_bound`. -/
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

/-! ## 3. Encoding roundtrip -/

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
