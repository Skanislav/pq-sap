/-
Three machine-checked invariants extending the correctness core
(docs/DECISIONS.md, in-scope Lean items 1-3):

  1. Widened-bound signing invariant  -- the blinded secret's norm doubles to
     2*eta, so the signer-side bound is beta' = tau*(2*eta) = 2*beta.
  2. Ownership <-> signing-key bridge  -- the MLWE relation the ZK circuit
     proves is exactly "holds a signing key for t", and the blinded secret
     is such a witness (from the correctness identity).
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

The ZK ownership circuit proves knowledge of a short `(s, e)` with
`A * s + e = t`. That relation is *identical* to holding an ML-DSA signing key
for the public key `t` — so a proof of the former is a proof of the latter.
And the blinded secret from the correctness identity is exactly such a witness.
-/

/-- The MLWE ownership relation the ZK circuit proves. -/
def IsOwnershipWitness {R : Type*} [CommRing R] {k l : ℕ}
    (A : Matrix (Fin k) (Fin l) R) (t : Fin k → R)
    (s : Fin l → R) (e : Fin k → R) : Prop :=
  A *ᵥ s + e = t

/-- Possession of a signing key for `t`: the secret `(s, e)` with `A*s + e = t`
(the key-generation relation). -/
def IsSigningKey {R : Type*} [CommRing R] {k l : ℕ}
    (A : Matrix (Fin k) (Fin l) R) (t : Fin k → R)
    (s : Fin l → R) (e : Fin k → R) : Prop :=
  A *ᵥ s + e = t

/-- The bridge: proving the ownership relation IS proving possession of a
signing key — they are the same relation. A ZK proof of ownership therefore
authorizes exactly what a spend needs. -/
theorem ownership_iff_signing {R : Type*} [CommRing R] {k l : ℕ}
    (A : Matrix (Fin k) (Fin l) R) (t : Fin k → R)
    (s : Fin l → R) (e : Fin k → R) :
    IsOwnershipWitness A t s e ↔ IsSigningKey A t s e :=
  Iff.rfl

/-- The blinded secret `(s₁+s', s₂+e')` is an ownership witness for the derived
stealth key — the ZK statement is satisfiable exactly because the correctness
identity holds. -/
theorem blinded_is_ownership_witness {R : Type*} [CommRing R] {k l : ℕ}
    (A : Matrix (Fin k) (Fin l) R) (s₁ s' : Fin l → R) (s₂ e' : Fin k → R) :
    IsOwnershipWitness A (A *ᵥ s' + e' + (A *ᵥ s₁ + s₂)) (s₁ + s') (s₂ + e') :=
  (blinded_key_correctness A s₁ s' s₂ e').symm

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
