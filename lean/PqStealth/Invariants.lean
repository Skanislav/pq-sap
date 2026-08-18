import Mathlib.Data.Matrix.Mul
import Mathlib.Data.ZMod.ValMinAbs
import PqStealth.Blinding
import LatticeCrypto.MLDSA.Params
import LatticeCrypto.MLDSA.Encoding
import LatticeCrypto.MLKEM.Params

/-!
# Signing invariants, the ownership bridge, encoding roundtrips

Proved: centered-norm sub-additivity, hence the blinded secret is `2·eta`-short
and the signer bound doubles (`beta' = tau·(2·eta) = 2·beta`); the ownership
relation TOGETHER WITH the coefficient bound IS possession of an ML-DSA signing
key, and the blinded secret is such a key; the stealth public key roundtrips,
and so do both meta-address wire formats as CONCRETE byte strings at their
spec lengths (5,633 B and 1,217 B) (`docs/DECISIONS.md`, Lean items 1-3).

Assumed: the two inner packers (`pack23` of full-precision `t`, the ML-KEM
encapsulation key) are parameters with roundtrip hypotheses — VCVio has no
fixed-length byte encoder with a proven law (`docs/encodings.md`).
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

/-! ## 3. Byte-level encoding roundtrips -/

open MLDSA.Encoding

/-- The stealth public key roundtrips: decoding the encoded `(rho, t1)` returns
it unchanged — a direct consequence of VCVio's public-key encoding law. -/
theorem stealth_pk_roundtrips {p : Params} {prims : Primitives p}
    (enc : Encoding p prims) (laws : enc.Laws)
    (rho : Bytes 32) (t1 : Vector prims.Power2High p.k) :
    enc.pkDecode (enc.pkEncode rho t1) = (rho, t1) :=
  laws.pkDecode_pkEncode rho t1

/-! ### Fixed-offset splitting of byte strings -/

/-- Split a byte string of length `m + n` at offset `m`. -/
def splitBytes {m n : ℕ} (v : Bytes (m + n)) : Bytes m × Bytes n :=
  ((v.extract 0 m).cast (by omega), (v.extract m (m + n)).cast (by omega))

/-- Splitting a concatenation at the seam returns the two halves — the only
byte-level fact the wire-format roundtrips need. -/
theorem splitBytes_append {m n : ℕ} (a : Bytes m) (b : Bytes n) :
    splitBytes (a ++ b) = (a, b) := by
  have h₁ : ((a ++ b).extract 0 m).cast (by omega) = a := by
    refine Vector.ext fun i hi => ?_
    simp only [Vector.getElem_cast, Vector.getElem_extract, Nat.zero_add,
      Vector.getElem_append]
    rw [dif_pos hi]
  have h₂ : ((a ++ b).extract m (m + n)).cast (by omega) = b := by
    refine Vector.ext fun i hi => ?_
    simp only [Vector.getElem_cast, Vector.getElem_extract, Vector.getElem_append,
      Nat.add_sub_cancel_left]
    rw [dif_neg (by omega)]
  rw [splitBytes, h₁, h₂]

/-! ### The meta-address wire format -/

/-- Bit width of a full-precision ML-DSA coefficient: `q = 8380417 < 2^23`
(the spec's `Q_BITS`; a standard public key would instead carry `t1`). -/
def qBits : ℕ := 23

/-- Bytes taken by a full-precision `t`: `k * 256` coefficients at `qBits` bits
each. The division is exact for every approved set, because `8 ∣ 256`. -/
def packedTBytes (p : Params) : ℕ := p.k * ringDegree * qBits / 8

/-- ML-DSA-65 (`k = 6`) packs `t` into `6 * 736 = 4416` bytes. -/
theorem packedTBytes_mldsa65 : packedTBytes mldsa65 = 4416 := rfl

/-- The meta-address wire format, `version(1) ‖ rho(32) ‖ pack(t) ‖ ek`
(TECHNICAL_SPEC §3). Generic over the two inner packers. -/
def metaAddressEncode {T Ek : Type*} {nt nek : ℕ}
    (packT : T → Bytes nt) (packEk : Ek → Bytes nek)
    (version : UInt8) (rho : Bytes 32) (t : T) (ek : Ek) :
    Bytes (1 + (32 + (nt + nek))) :=
  #v[version] ++ (rho ++ (packT t ++ packEk ek))

/-- Decode a meta-address by splitting at the fixed offsets `1`, `33`,
`33 + nt`. -/
def metaAddressDecode {T Ek : Type*} {nt nek : ℕ}
    (unpackT : Bytes nt → T) (unpackEk : Bytes nek → Ek)
    (m : Bytes (1 + (32 + (nt + nek)))) : UInt8 × Bytes 32 × T × Ek :=
  let s := splitBytes m
  let r := splitBytes s.2
  let b := splitBytes r.2
  (s.1[0], r.1, unpackT b.1, unpackEk b.2)

/-- The meta-address roundtrips byte-for-byte whenever the two inner packings
do: the outer layout loses nothing. -/
theorem meta_address_roundtrips {T Ek : Type*} {nt nek : ℕ}
    (packT : T → Bytes nt) (unpackT : Bytes nt → T)
    (hT : ∀ t, unpackT (packT t) = t)
    (packEk : Ek → Bytes nek) (unpackEk : Bytes nek → Ek)
    (hEk : ∀ ek, unpackEk (packEk ek) = ek)
    (version : UInt8) (rho : Bytes 32) (t : T) (ek : Ek) :
    metaAddressDecode unpackT unpackEk
        (metaAddressEncode packT packEk version rho t ek) = (version, rho, t, ek) := by
  simp only [metaAddressEncode, metaAddressDecode, splitBytes_append, hT, hEk]
  rfl

/-- The default pairing ML-DSA-65 + ML-KEM-768: `1 + 32 + 4416 + 1184 = 5633`
bytes, the size the spec and the Python reference measure. -/
theorem metaAddress_size_mldsa65_mlkem768 :
    1 + (32 + (packedTBytes mldsa65 + MLKEM.Params.publicKeyBytes MLKEM.mlkem768)) = 5633 :=
  rfl

/-- The roundtrip on the wire at the default pairing: 5,633 bytes in, the four
components out. -/
theorem meta_address_roundtrips_5633 {T Ek : Type*}
    (packT : T → Bytes 4416) (unpackT : Bytes 4416 → T)
    (hT : ∀ t, unpackT (packT t) = t)
    (packEk : Ek → Bytes 1184) (unpackEk : Bytes 1184 → Ek)
    (hEk : ∀ ek, unpackEk (packEk ek) = ek)
    (version : UInt8) (rho : Bytes 32) (t : T) (ek : Ek) :
    metaAddressDecode unpackT unpackEk
        (metaAddressEncode packT packEk version rho t ek : Bytes 5633)
      = (version, rho, t, ek) :=
  meta_address_roundtrips packT unpackT hT packEk unpackEk hEk version rho t ek

/-! ### The reduced ZK-spend layout (D-012) -/

/-- The ZK-spend meta-address, `version(1) ‖ commitment(32) ‖ ek`: with a ZK
ownership proof the full-precision `t` is replaced by a 32-byte commitment. -/
def metaAddressZkEncode {Ek : Type*} {nek : ℕ} (packEk : Ek → Bytes nek)
    (version : UInt8) (commitment : Bytes 32) (ek : Ek) : Bytes (1 + (32 + nek)) :=
  #v[version] ++ (commitment ++ packEk ek)

/-- Decode the ZK-spend layout by splitting at the fixed offsets `1`, `33`. -/
def metaAddressZkDecode {Ek : Type*} {nek : ℕ} (unpackEk : Bytes nek → Ek)
    (m : Bytes (1 + (32 + nek))) : UInt8 × Bytes 32 × Ek :=
  let s := splitBytes m
  let r := splitBytes s.2
  (s.1[0], r.1, unpackEk r.2)

/-- The ZK-spend meta-address roundtrips byte-for-byte. -/
theorem meta_address_zk_roundtrips {Ek : Type*} {nek : ℕ}
    (packEk : Ek → Bytes nek) (unpackEk : Bytes nek → Ek)
    (hEk : ∀ ek, unpackEk (packEk ek) = ek)
    (version : UInt8) (commitment : Bytes 32) (ek : Ek) :
    metaAddressZkDecode unpackEk (metaAddressZkEncode packEk version commitment ek)
      = (version, commitment, ek) := by
  simp only [metaAddressZkEncode, metaAddressZkDecode, splitBytes_append, hEk]
  rfl

/-- ZK-spend at ML-KEM-768: `1 + 32 + 1184 = 1217` bytes, the 4.6× shrink
recorded in `docs/DECISIONS.md` D-012. -/
theorem metaAddressZk_size_mlkem768 :
    1 + (32 + MLKEM.Params.publicKeyBytes MLKEM.mlkem768) = 1217 := rfl

/-- The ZK-spend roundtrip on the wire at ML-KEM-768: 1,217 bytes. -/
theorem meta_address_zk_roundtrips_1217 {Ek : Type*}
    (packEk : Ek → Bytes 1184) (unpackEk : Bytes 1184 → Ek)
    (hEk : ∀ ek, unpackEk (packEk ek) = ek)
    (version : UInt8) (commitment : Bytes 32) (ek : Ek) :
    metaAddressZkDecode unpackEk
        (metaAddressZkEncode packEk version commitment ek : Bytes 1217)
      = (version, commitment, ek) :=
  meta_address_zk_roundtrips packEk unpackEk hEk version commitment ek

end PqStealth
