import PqStealth.Invariants
import LatticeCrypto.MLDSA.Concrete.NTT
import LatticeCrypto.MLDSA.Scheme
import LatticeCrypto.MLDSA.Security
import LatticeCrypto.MLDSA.SecurityHVZK

/-! # Widened ML-DSA signing for blinded stealth keys

The standard ML-DSA identification scheme rejects when `‖z‖∞ < γ₁ - β` and
`‖r₀‖∞ < γ₂ - β`, where `β = τ·η` bounds `‖c·s‖∞` for an `η`-short `s`.  In
Construction A the blinded secret `(s₁ + s', s₂ + e')` is a sum of two
`η`-short vectors, so both challenge products `c·(s₁+s')` and `c·(s₂+e')` are
bounded by `β' = 2·β` (`sampleInBall_smul_widened_bound`).  We therefore run
the IDS with both response gates widened: `‖z‖∞ < γ₁ - β'` and
`‖r₀‖∞ < γ₂ - β'`.  The second widening is what makes `hide_low` go through
for the `2η`-short `s₂`; the verifier only checks `z`, so it is unaffected.

The mask `y` is drawn from the FIPS 204 cube `[-(γ₁-1), γ₁]` (`sampleMaskCube`),
not from the whole ring as in VCVio's `identificationScheme`, so that the
accepted-`z` probability is the one in the Dilithium analysis.

Assumed / NOT closed: exact equality of the full commitment/challenge/hint
transcript to the simulator (quantified as `widenedHvzkDistance`, currently the
trivial `1`).
-/

open LatticeCrypto MLDSA MLDSA.Concrete OracleComp OracleSpec ENNReal
open LatticeCrypto.TransformOps

namespace MLDSA

variable (p : Params) (prims : Primitives p) [nttOps : NTTRingOps]
variable [SampleableType (RqVec p.l)] [SampleableType (Vector prims.Hint p.k)]
  [SampleableType (CommitHashBytes p)]

/-! ## 1. Widened parameters -/

/-- Widened challenge-product bound for blinded signing keys: `β' = 2·β`. -/
def widenedBeta : ℕ := 2 * p.beta

omit nttOps [SampleableType (RqVec p.l)] [SampleableType (CommitHashBytes p)] in
/-- `widenedBeta` equals `τ·(2·η)`, the bound on `‖c·(s₁+s')‖∞`. -/
@[simp] theorem widenedBeta_eq_tau_two_eta : widenedBeta p = p.tau * (2 * p.eta) := by
  rw [widenedBeta, Params.beta]
  ring

omit nttOps [SampleableType (RqVec p.l)] [SampleableType (CommitHashBytes p)] in
/-- `widenedBeta` unfolded. -/
@[simp] theorem widenedBeta_eq_two_beta : widenedBeta p = 2 * p.beta := rfl

/-! ## 2. Norm facts for sums of short vectors -/

omit nttOps [SampleableType (RqVec p.l)] [SampleableType (Vector prims.Hint p.k)]
  [SampleableType (CommitHashBytes p)] in
/-- `polyNorm` is the vector-backend centered infinity norm, definitionally. -/
theorem polyNorm_eq_cInfNorm (f : Rq) : polyNorm f = cInfNorm f := by
  unfold polyNorm normOps cInfNorm
  simp only [zmodPolyNormOps, normOpsOfCenteredView]
  rfl

omit nttOps [SampleableType (RqVec p.l)] [SampleableType (Vector prims.Hint p.k)]
  [SampleableType (CommitHashBytes p)] in
/-- `normOps.cInfNorm` is the vector-backend centered infinity norm, definitionally. -/
theorem normOps_cInfNorm_eq (f : Rq) : normOps.cInfNorm f = cInfNorm f :=
  polyNorm_eq_cInfNorm f

omit nttOps [SampleableType (RqVec p.l)] [SampleableType (Vector prims.Hint p.k)]
  [SampleableType (CommitHashBytes p)] in
/-- Negation preserves `polyNorm` (same proof as VCVio's private `polyNorm_neg`). -/
theorem polyNorm_neg' (f : Rq) : polyNorm (-f) = polyNorm f := by
  unfold polyNorm normOps
  simp only [LatticeCrypto.zmodPolyNormOps, LatticeCrypto.normOpsOfCenteredView]
  unfold LatticeCrypto.cInfNormOf
  apply Finset.sup_congr rfl
  intro i _
  simp only [LatticeCrypto.zmodCenteredCoeffView, coeffRing.coeff_neg]
  exact LatticeCrypto.centeredRepr_natAbs_neg _

omit nttOps [SampleableType (RqVec p.l)] [SampleableType (Vector prims.Hint p.k)]
  [SampleableType (CommitHashBytes p)] in
/-- The centered infinity norm of a polynomial vector is sub-additive. -/
theorem polyVecNorm_add_le {k : ℕ} (u v : RqVec k) :
    polyVecNorm (u + v) ≤ polyVecNorm u + polyVecNorm v := by
  refine (PolyVec.cInfNorm_le_iff (ops := normOps)).mpr fun j => ?_
  have hget : (u + v).get j = u.get j + v.get j := by
    simp only [Vector.get_eq_getElem, Vector.getElem_add]
  rw [hget]
  calc normOps.cInfNorm (u.get j + v.get j)
      = cInfNorm (u.get j + v.get j) := normOps_cInfNorm_eq _
    _ ≤ cInfNorm (u.get j) + cInfNorm (v.get j) := PqStealth.cInfNorm_add_le _ _
    _ = normOps.cInfNorm (u.get j) + normOps.cInfNorm (v.get j) := by
        rw [normOps_cInfNorm_eq, normOps_cInfNorm_eq]
    _ ≤ polyVecNorm u + polyVecNorm v :=
        Nat.add_le_add (PolyVec.component_cInfNorm_le normOps u j)
          (PolyVec.component_cInfNorm_le normOps v j)

omit [SampleableType (RqVec p.l)] [SampleableType (Vector prims.Hint p.k)]
  [SampleableType (CommitHashBytes p)] in
/-- **Widened challenge-product bound.** For `s = a + b` with `a`, `b` both
`η`-short, `‖c·s‖∞ ≤ 2·β = widenedBeta`. This is the only place the
`sampleInBall_smul_bound` law is used, once per summand. -/
theorem sampleInBall_smul_widened_bound (h_laws : Primitives.Laws prims nttOps)
    (cTilde : CommitHashBytes p) {k : ℕ} {s a b : RqVec k} (hs : s = a + b)
    (ha : polyVecBounded a p.eta) (hb : polyVecBounded b p.eta) :
    polyVecNorm (prims.sampleInBall cTilde • s) ≤ widenedBeta p := by
  haveI := h_laws.transform
  subst hs
  change polyVecNorm (nttOps.coeffScalarVecMul _ (a + b)) ≤ _
  rw [nttOps.coeffScalarVecMul_add, widenedBeta, two_mul]
  exact (polyVecNorm_add_le _ _).trans
    (Nat.add_le_add (h_laws.sampleInBall_smul_bound cTilde a ha)
      (h_laws.sampleInBall_smul_bound cTilde b hb))

/-! ## 3. Widened key relation -/

open Classical in
/-- A key pair valid for the widened scheme: the seeds agree, the public-key
identity `t₁·2^d + t₀ = A·s₁ + s₂` holds, and each secret vector is a sum of
two `η`-short vectors (so is itself `2η`-short, `widenedValidKeyPair_norm`).
No honest seed is required; a blinded stealth key `(s₁+s', s₂+e')` qualifies
(`widenedValidKeyPair_blinded`). -/
noncomputable def widenedValidKeyPair (pk : PublicKey p prims) (sk : SecretKey p) : Bool :=
  decide (pk.rho = sk.rho ∧
    prims.power2RoundShiftVec pk.t1 + sk.t0 = prims.expandA pk.rho * sk.s1 + sk.s2 ∧
    (∃ a b : RqVec p.l, sk.s1 = a + b ∧ polyVecBounded a p.eta ∧ polyVecBounded b p.eta) ∧
    (∃ a b : RqVec p.k, sk.s2 = a + b ∧ polyVecBounded a p.eta ∧ polyVecBounded b p.eta))

omit [SampleableType (RqVec p.l)] [SampleableType (Vector prims.Hint p.k)]
  [SampleableType (CommitHashBytes p)] in
@[simp] theorem widenedValidKeyPair_eq_true_iff (pk : PublicKey p prims) (sk : SecretKey p) :
    widenedValidKeyPair p prims pk sk = true ↔
      pk.rho = sk.rho ∧
      prims.power2RoundShiftVec pk.t1 + sk.t0 = prims.expandA pk.rho * sk.s1 + sk.s2 ∧
      (∃ a b : RqVec p.l, sk.s1 = a + b ∧ polyVecBounded a p.eta ∧ polyVecBounded b p.eta) ∧
      (∃ a b : RqVec p.k, sk.s2 = a + b ∧ polyVecBounded a p.eta ∧ polyVecBounded b p.eta) := by
  simp [widenedValidKeyPair]

omit [SampleableType (RqVec p.l)] [SampleableType (Vector prims.Hint p.k)]
  [SampleableType (CommitHashBytes p)] in
/-- A widened-valid secret is `2η`-short. -/
theorem widenedValidKeyPair_norm {pk : PublicKey p prims} {sk : SecretKey p}
    (hw : widenedValidKeyPair p prims pk sk = true) :
    polyVecNorm sk.s1 ≤ 2 * p.eta ∧ polyVecNorm sk.s2 ≤ 2 * p.eta := by
  obtain ⟨-, -, ⟨a1, b1, h1, ha1, hb1⟩, ⟨a2, b2, h2, ha2, hb2⟩⟩ :=
    (widenedValidKeyPair_eq_true_iff p prims pk sk).mp hw
  refine ⟨?_, ?_⟩
  · rw [h1, two_mul]
    exact (polyVecNorm_add_le _ _).trans (Nat.add_le_add ha1 hb1)
  · rw [h2, two_mul]
    exact (polyVecNorm_add_le _ _).trans (Nat.add_le_add ha2 hb2)

omit [SampleableType (RqVec p.l)] [SampleableType (Vector prims.Hint p.k)]
  [SampleableType (CommitHashBytes p)] in
/-- **Satisfiability.** The blinded key of two `η`-short pairs is widened-valid:
`pk = (ρ, Power2Round(A·(s₁+s') + (s₂+e')).1)` with the matching `t₀`. -/
theorem widenedValidKeyPair_blinded (h_laws : Primitives.Laws prims nttOps)
    (rho key : Bytes 32) (tr : Bytes 64)
    (s1 s' : RqVec p.l) (s2 e' : RqVec p.k)
    (hs1 : polyVecBounded s1 p.eta) (hs' : polyVecBounded s' p.eta)
    (hs2 : polyVecBounded s2 p.eta) (he' : polyVecBounded e' p.eta) :
    let t := prims.expandA rho * (s1 + s') + (s2 + e')
    widenedValidKeyPair p prims
      ⟨rho, (prims.power2RoundVec t).1⟩
      ⟨rho, key, tr, s1 + s', s2 + e', (prims.power2RoundVec t).2⟩ = true := by
  intro t
  rw [widenedValidKeyPair_eq_true_iff]
  refine ⟨rfl, ?_, ⟨s1, s', rfl, hs1, hs'⟩, ⟨s2, e', rfl, hs2, he'⟩⟩
  refine Vector.ext fun i hi => ?_
  rw [Vector.getElem_add]
  simp only [Primitives.power2RoundShiftVec, Primitives.power2RoundVec,
    Vector.map_map, Vector.getElem_map, Function.comp]
  exact h_laws.power2Round_decomp _

/-! ## 4. The key identity behind verification

VCVio's `keyGenFromSeed_wApprox_eq` derives the verifier's approximation
`A·z - c·t₁·2^d = A·y - c·s₂ + c·t₀` from an honest seed. The only fact it uses
about the seed is `t₁·2^d + t₀ = A·s₁ + s₂`, which is exactly the identity in
`widenedValidKeyPair`; this is the same proof with that identity as the
hypothesis. -/

omit [SampleableType (RqVec p.l)] [SampleableType (Vector prims.Hint p.k)]
  [SampleableType (CommitHashBytes p)] in
theorem wApprox_eq_of_keyIdentity (h_laws : Primitives.Laws prims nttOps)
    {pk : PublicKey p prims} {sk : SecretKey p}
    (h_kg : prims.power2RoundShiftVec pk.t1 + sk.t0 = prims.expandA pk.rho * sk.s1 + sk.s2)
    (c : Rq) (y : RqVec p.l) :
    computeWApprox p prims (prims.expandA pk.rho) c (y + c • sk.s1) pk.t1 =
      (prims.expandA pk.rho) * y - c • sk.s2 + c • sk.t0 := by
  haveI := h_laws.transform
  let laws := h_laws.transform
  set aHat := prims.expandA pk.rho
  simp only [computeWApprox]
  refine Vector.ext fun i hi => ?_
  simp only [Vector.getElem_add, Vector.getElem_sub,
    nttOps.hatVec_add, nttOps.unhatVec_sub, nttOps.matVecMul_add, nttOps.unhatVec_add]
  have hAs1_hat : nttOps.matVecMul aHat (nttOps.hatVec sk.s1) =
      nttOps.hatVec (prims.power2RoundShiftVec pk.t1 + sk.t0 - sk.s2) := by
    rw [h_kg]
    refine Vector.ext fun j hj => ?_
    simp only [hatVec, HMul.hMul, coeffMatVecMul, unhatVec, matVecMul,
               Vector.getElem_map, Vector.getElem_sub, Vector.getElem_add]
    have hcancel : (fromHat (dot nttOps aHat[j] (Vector.map toHat sk.s1)) : Rq) +
        sk.s2[j] - sk.s2[j] = fromHat (dot nttOps aHat[j] (Vector.map toHat sk.s1)) := by
      abel
    rw [hcancel, laws.toHat_fromHat]
  have hMatScalarComm : nttOps.matVecMul aHat (nttOps.hatVec (c • sk.s1)) =
      nttOps.scalarVecMul (toHat c) (nttOps.matVecMul aHat (nttOps.hatVec sk.s1)) := by
    have hNTTSmul : nttOps.hatVec (c • sk.s1) =
        nttOps.scalarVecMul (toHat c) (nttOps.hatVec sk.s1) := by
      refine Vector.ext fun j hj => ?_
      simp only [hatVec, scalarVecMul, Vector.getElem_map]
      change nttOps.toHat (nttOps.coeffScalarVecMul c sk.s1)[j] = _
      simp only [coeffScalarVecMul, unhatVec, scalarVecMul, hatVec,
                 Vector.map_map, Vector.getElem_map, Function.comp_apply, laws.toHat_fromHat]
    rw [hNTTSmul]
    refine Vector.ext fun j hj => ?_
    simp only [matVecMul, scalarVecMul, Vector.getElem_map]
    exact nttOps.dot_scalar_right (toHat c) _ _
  simp only [hMatScalarComm, hAs1_hat]
  change (aHat * y)[i] +
      (nttOps.coeffScalarVecMul c (prims.power2RoundShiftVec pk.t1 + sk.t0 - sk.s2))[i] -
      (nttOps.coeffScalarVecMul c (prims.power2RoundShiftVec pk.t1))[i] =
      (aHat * y)[i] -
      (nttOps.coeffScalarVecMul c sk.s2)[i] + (nttOps.coeffScalarVecMul c sk.t0)[i]
  simp only [nttOps.coeffScalarVecMul_sub, nttOps.coeffScalarVecMul_add,
             Vector.getElem_sub, Vector.getElem_add]
  abel

/-! ## 5. Mask sampler over the FIPS 204 cube

VCVio's `identificationScheme` samples `y` uniformly over the whole finite
ring `RqVec p.l`.  For the widened response bound we instead sample `y`
uniformly from the FIPS 204 mask cube `[-(γ₁-1), γ₁]` (size `2·γ₁` per
coefficient), so that the acceptance probability matches the standard
Dilithium analysis. -/

/-- Centered lift of an index in `Fin (2·γ₁)` onto the mask cube `[-(γ₁-1), γ₁]`. -/
def cubeCoeff (i : Fin (2 * p.gamma1)) : Coeff :=
  (((i : ℕ) : ℤ) - ((p.gamma1 : ℤ) - 1) : ℤ)

/-- Assemble a mask vector from per-coefficient cube indices. -/
def cubeLift (v : Fin p.l → Fin ringDegree → Fin (2 * p.gamma1)) : RqVec p.l :=
  Vector.ofFn fun j => (Vector.ofFn fun i => cubeCoeff p (v j i) : Rq)

omit nttOps [SampleableType (RqVec p.l)] [SampleableType (Vector prims.Hint p.k)]
  [SampleableType (CommitHashBytes p)] in
/-- The centered representative of a cube coefficient plus a short shift: no
wrap-around, since `|u + δ| ≤ γ₁ + widenedBeta < q/2`. -/
theorem centeredRepr_cubeCoeff_add (hq : 2 * (p.gamma1 + widenedBeta p) < modulus)
    (x : Fin (2 * p.gamma1)) (d : Coeff) (hd : (centeredRepr d).natAbs ≤ widenedBeta p) :
    centeredRepr (cubeCoeff p x + d) =
      ((x : ℕ) : ℤ) - ((p.gamma1 : ℤ) - 1) + centeredRepr d := by
  have hcast : cubeCoeff p x + d =
      ((((x : ℕ) : ℤ) - ((p.gamma1 : ℤ) - 1) + centeredRepr d : ℤ) : Coeff) := by
    rw [Int.cast_add, cubeCoeff, ← centeredRepr_intCast d]
  rw [hcast]
  apply centeredRepr_intCast_eq_of_natAbs_le _ (b := p.gamma1 + widenedBeta p) _ hq
  have := x.isLt
  omega

omit nttOps [SampleableType (RqVec p.l)] [SampleableType (Vector prims.Hint p.k)]
  [SampleableType (CommitHashBytes p)] in
/-- A strict vector-norm bound is a strict bound on every centered coefficient. -/
theorem polyVecNorm_lt_iff {k : ℕ} (w : RqVec k) {B : ℕ} (hB : 0 < B) :
    polyVecNorm w < B ↔ ∀ j i, (centeredRepr ((w.get j).get i)).natAbs < B := by
  have h1 : polyVecNorm w < B ↔ polyVecNorm w ≤ B - 1 := by omega
  rw [h1]
  refine (PolyVec.cInfNorm_le_iff (ops := normOps)).trans (forall_congr' fun j => ?_)
  rw [normOps_cInfNorm_eq, cInfNorm_le_iff]
  exact forall_congr' fun i => by omega

omit nttOps [SampleableType (RqVec p.l)] [SampleableType (Vector prims.Hint p.k)]
  [SampleableType (CommitHashBytes p)] in
/-- Coefficients of a lifted cube vector plus a shift. -/
theorem cubeLift_add_get (v : Fin p.l → Fin ringDegree → Fin (2 * p.gamma1))
    (delta : RqVec p.l) (j : Fin p.l) (i : Fin ringDegree) :
    ((cubeLift p v + delta).get j).get i = cubeCoeff p (v j i) + (delta.get j).get i := by
  have h1 : (cubeLift p v + delta).get j = (cubeLift p v).get j + delta.get j := by
    simp only [Vector.get_eq_getElem, Vector.getElem_add]
  rw [h1, Rq.get_add]
  congr 1
  simp only [cubeLift, Vector.get_eq_getElem, Vector.getElem_ofFn, Fin.eta]

variable [NeZero (2 * p.gamma1)]

/-- Uniform mask over the FIPS 204 cube `[-(γ₁-1), γ₁]^(l·256)`. -/
def sampleMaskCube : ProbComp (RqVec p.l) :=
  cubeLift p <$> ($ᵗ (Fin p.l → Fin ringDegree → Fin (2 * p.gamma1)))

omit nttOps [SampleableType (RqVec p.l)] [SampleableType (Vector prims.Hint p.k)]
  [SampleableType (CommitHashBytes p)] in
/-- **Per-coefficient count.** Exactly `2·(γ₁ - widenedBeta) - 1` of the
`2·γ₁` cube indices `x` satisfy `|x + δ| < γ₁ - widenedBeta`, for any shift
`|δ| ≤ widenedBeta`: the accepted set is an interval of that length sitting
inside the cube (`coefficient_preimage`). -/
theorem card_filter_cube (hB : widenedBeta p < p.gamma1)
    (hq : 2 * (p.gamma1 + widenedBeta p) < modulus)
    (d : Coeff) (hd : (centeredRepr d).natAbs ≤ widenedBeta p) :
    (Finset.univ.filter fun x : Fin (2 * p.gamma1) =>
        (centeredRepr (cubeCoeff p x + d)).natAbs < p.gamma1 - widenedBeta p).card
      = 2 * (p.gamma1 - widenedBeta p) - 1 := by
  have hpred : ∀ x : Fin (2 * p.gamma1),
      (centeredRepr (cubeCoeff p x + d)).natAbs < p.gamma1 - widenedBeta p ↔
        (((x : ℕ) : ℤ) - ((p.gamma1 : ℤ) - 1) + centeredRepr d).natAbs
          < p.gamma1 - widenedBeta p :=
    fun x => by rw [centeredRepr_cubeCoeff_add p hq x d hd]
  set lo : ℕ := ((widenedBeta p : ℤ) - centeredRepr d).toNat with hlo
  rw [show 2 * (p.gamma1 - widenedBeta p) - 1 =
      (Finset.Ico lo (lo + (2 * (p.gamma1 - widenedBeta p) - 1))).card by
    rw [Nat.card_Ico]; omega]
  refine Finset.card_nbij' (fun x : Fin (2 * p.gamma1) => (x : ℕ))
    (fun n => ⟨n % (2 * p.gamma1), Nat.mod_lt _ (NeZero.pos _)⟩) ?_ ?_ ?_ ?_
  · intro x hx
    simp only [Finset.mem_coe, Finset.mem_filter, Finset.mem_univ, true_and] at hx
    simp only [Finset.mem_coe, Finset.mem_Ico]
    rw [hpred] at hx
    have := x.isLt
    omega
  · intro n hn
    simp only [Finset.mem_coe, Finset.mem_Ico] at hn
    simp only [Finset.mem_coe, Finset.mem_filter, Finset.mem_univ, true_and]
    rw [hpred]
    have hnlt : n < 2 * p.gamma1 := by omega
    simp only [Nat.mod_eq_of_lt hnlt]
    omega
  · intro x _
    exact Fin.ext (Nat.mod_eq_of_lt x.isLt)
  · intro n hn
    simp only [Finset.mem_coe, Finset.mem_Ico] at hn
    exact Nat.mod_eq_of_lt (by omega)

omit nttOps [SampleableType (RqVec p.l)] [SampleableType (Vector prims.Hint p.k)]
  [SampleableType (CommitHashBytes p)] [NeZero (2 * p.gamma1)] in
/-- **Coefficient preimage lemma.** If `|δ| ≤ widenedBeta` and `|z| < γ₁ -
widenedBeta`, then `y = z - δ` lies in `[-(γ₁-1), γ₁]`; conversely each
accepted `z` has a unique mask preimage. -/
theorem coefficient_preimage {delta z : ℤ}
    (hd : delta.natAbs ≤ widenedBeta p) (hz : z.natAbs < p.gamma1 - widenedBeta p) :
    (z - delta).natAbs ≤ p.gamma1 - 1 := by
  have h := Int.natAbs_sub_le z delta
  omega

omit nttOps [SampleableType (RqVec p.l)] [SampleableType (Vector prims.Hint p.k)]
  [SampleableType (CommitHashBytes p)] in
/-- **Accepted-`z` probability, shift form.** For any fixed shift `δ` with
`‖δ‖∞ ≤ widenedBeta` (in the scheme, `δ = c·s₁`), a cube-uniform mask `y`
passes `‖y + δ‖∞ < γ₁ - widenedBeta` with probability exactly
`((2·(γ₁ - widenedBeta) - 1) / (2·γ₁))^(l·256)`.  The probability does not
depend on `δ`, which is the independence-from-the-secret statement. -/
theorem cube_shift_accept_prob
    (hB : widenedBeta p < p.gamma1) (hq : 2 * (p.gamma1 + widenedBeta p) < modulus)
    (delta : RqVec p.l) (hd : polyVecNorm delta ≤ widenedBeta p) :
    Pr[= true | (do
        let y ← sampleMaskCube p
        pure (polyVecNorm (y + delta) < p.gamma1 - widenedBeta p)) ] =
      (((2 * (p.gamma1 - widenedBeta p) - 1 : ℕ) : ℝ≥0∞) / ((2 * p.gamma1 : ℕ) : ℝ≥0∞))
        ^ (p.l * ringDegree) := by
  have hBpos : 0 < p.gamma1 - widenedBeta p := by omega
  have hdc : ∀ j i, (centeredRepr ((delta.get j).get i)).natAbs ≤ widenedBeta p := by
    intro j i
    have h1 := (PolyVec.cInfNorm_le_iff (ops := normOps)).mp hd j
    rw [normOps_cInfNorm_eq, cInfNorm_le_iff] at h1
    exact h1 i
  -- 1. The computation is a uniform draw of cube indices pushed through the gate.
  have hcomp : (do
        let y ← sampleMaskCube p
        pure (decide (polyVecNorm (y + delta) < p.gamma1 - widenedBeta p)) : ProbComp Bool)
      = (fun v => decide (polyVecNorm (cubeLift p v + delta) < p.gamma1 - widenedBeta p)) <$>
          ($ᵗ (Fin p.l → Fin ringDegree → Fin (2 * p.gamma1))) := by
    simp only [sampleMaskCube, map_eq_bind_pure_comp, bind_assoc, Function.comp_def, pure_bind]
  rw [hcomp, probOutput_map]
  simp only [decide_eq_true_eq]
  rw [probEvent_uniformSample]
  -- 2. The accepted set is a product of per-coefficient accepted sets.
  have hfilter : (Finset.univ.filter fun v : Fin p.l → Fin ringDegree → Fin (2 * p.gamma1) =>
        polyVecNorm (cubeLift p v + delta) < p.gamma1 - widenedBeta p)
      = Fintype.piFinset fun j => Fintype.piFinset fun i =>
          Finset.univ.filter fun x : Fin (2 * p.gamma1) =>
            (centeredRepr (cubeCoeff p x + (delta.get j).get i)).natAbs
              < p.gamma1 - widenedBeta p := by
    ext v
    simp only [Finset.mem_filter, Finset.mem_univ, true_and, Fintype.mem_piFinset]
    rw [polyVecNorm_lt_iff _ hBpos]
    simp only [cubeLift_add_get]
  have hcount : ∀ j i, (Finset.univ.filter fun x : Fin (2 * p.gamma1) =>
      (centeredRepr (cubeCoeff p x + (delta.get j).get i)).natAbs
        < p.gamma1 - widenedBeta p).card = 2 * (p.gamma1 - widenedBeta p) - 1 :=
    fun j i => card_filter_cube p hB hq _ (hdc j i)
  rw [hfilter]
  simp only [Fintype.card_piFinset, hcount, Finset.prod_const, Finset.card_univ,
    Fintype.card_fin, Fintype.card_pi]
  -- 3. `(N^256)^l / (M^256)^l = (N / M)^(l·256)` in `ℝ≥0∞`.
  rw [← pow_mul, ← pow_mul, mul_comm ringDegree p.l, Nat.cast_pow, Nat.cast_pow,
    div_eq_mul_inv, ENNReal.inv_pow, ← mul_pow, ← div_eq_mul_inv]

omit [SampleableType (RqVec p.l)] [SampleableType (Vector prims.Hint p.k)]
  [SampleableType (CommitHashBytes p)] in
/-- **Accepted-`z` independence.** For a widened-valid key and any challenge,
the widened response gate `‖z‖∞ < γ₁ - widenedBeta` passes with probability
`((2·(γ₁ - widenedBeta) - 1) / (2·γ₁))^(l·256)`, independent of the secret. -/
theorem widened_z_accepted_independent (h_laws : Primitives.Laws prims nttOps)
    (hB : widenedBeta p < p.gamma1) (hq : 2 * (p.gamma1 + widenedBeta p) < modulus)
    (pk : PublicKey p prims) (sk : SecretKey p)
    (hw : widenedValidKeyPair p prims pk sk = true)
    (cTilde : CommitHashBytes p) :
    Pr[= true | (do
        let y ← sampleMaskCube p
        let z := y + prims.sampleInBall cTilde • sk.s1
        pure (polyVecNorm z < p.gamma1 - widenedBeta p)) ] =
      (((2 * (p.gamma1 - widenedBeta p) - 1 : ℕ) : ℝ≥0∞) / ((2 * p.gamma1 : ℕ) : ℝ≥0∞))
        ^ (p.l * ringDegree) := by
  obtain ⟨-, -, ⟨a, b, hs1, ha, hb⟩, -⟩ := (widenedValidKeyPair_eq_true_iff p prims pk sk).mp hw
  exact cube_shift_accept_prob p hB hq _
    (sampleInBall_smul_widened_bound p prims h_laws cTilde hs1 ha hb)

/-! ## 6. Widened identification scheme -/

/-- The widened IDS: cube-uniform mask, widened `z` and `r₀` gates, and the
same verification as the standard scheme (with the widened `z` bound).
Completeness holds relative to `widenedValidKeyPair` (`widened_ids_complete`). -/
def widenedIdentificationScheme
    [DecidableEq prims.High] :
    IdenSchemeWithAbort
      (PublicKey p prims) (SecretKey p)
      (Commitment p prims) (SigningState p)
      (CommitHashBytes p) (Response p prims)
      (widenedValidKeyPair p prims) where
  commit := fun pk _sk => do
    let aHat := prims.expandA pk.rho
    let y ← sampleMaskCube p
    let w := aHat * y
    let w1 := prims.highBitsVec w
    return (w1, ⟨y, w⟩)
  respond := fun _pk sk st cTilde => do
    let c := prims.sampleInBall cTilde
    let cs1 := c • sk.s1
    let cs2 := c • sk.s2
    let z := st.y + cs1
    let r0 := prims.lowBitsVec (st.w - cs2)
    if polyVecNorm z < p.gamma1 - widenedBeta p ∧
        polyVecNorm r0 < p.gamma2 - widenedBeta p then do
      let ct0 := c • sk.t0
      let h := prims.makeHintVec (-ct0) (st.w - cs2 + ct0)
      if polyVecNorm ct0 < p.gamma2 ∧ prims.hintWeight h ≤ p.omega then
        return some (z, h)
      else
        return none
    else
      return none
  verify := fun pk w1 cTilde (z, h) =>
    let c := prims.sampleInBall cTilde
    let aHat := prims.expandA pk.rho
    let wApprox := computeWApprox p prims aHat c z pk.t1
    let w1' := prims.useHintVec h wApprox
    decide (polyVecNorm z < p.gamma1 - widenedBeta p) &&
    decide (w1' = w1) &&
    decide (prims.hintWeight h ≤ p.omega)

/-! ## 7. Completeness -/

omit [SampleableType (RqVec p.l)] [SampleableType (Vector prims.Hint p.k)] in
/-- **Completeness of the widened scheme.** Whenever the honest prover does
not abort, the verifier accepts. Same shape as VCVio's
`idsWithAbort_complete`, with the widened bound `β'` in place of `β` and the
key identity taken from `widenedValidKeyPair` instead of an honest seed. -/
theorem widened_ids_complete
    [DecidableEq prims.High] [IsUniformSpec unifSpec]
    (h_laws : Primitives.Laws prims nttOps) :
    (widenedIdentificationScheme p prims).Complete := by
  classical
  intro pk sk hvalid
  rw [probOutput_eq_one_iff_forall]
  refine ⟨probFailure_of_liftM_PMF _, fun b hb => ?_⟩
  rw [support_bind] at hb
  simp only [Set.mem_iUnion] at hb
  obtain ⟨t?, ht?, hb⟩ := hb
  rw [support_pure] at hb
  simp only [Set.mem_singleton_iff] at hb
  subst hb
  match t? with
  | none => rfl
  | some (w1, cTilde, zh) =>
    simp only [IdenSchemeWithAbort.honestExecution, support_bind, Set.mem_iUnion,
      support_pure, Set.mem_singleton_iff] at ht?
    obtain ⟨⟨w1', st⟩, hw1st, cTilde', hcTilde, oz, hoz, heq⟩ := ht?
    cases oz with
    | none => simp only [Option.map, reduceCtorEq] at heq
    | some zh' =>
      simp only [Option.map, Option.some.injEq, Prod.mk.injEq] at heq
      obtain ⟨rfl, rfl, rfl⟩ := heq
      -- The algebraic core.
      obtain ⟨-, h_kg, ⟨a1, b1, hs1, ha1, hb1⟩, ⟨a2, b2, hs2, ha2, hb2⟩⟩ :=
        (widenedValidKeyPair_eq_true_iff p prims pk sk).mp hvalid
      simp only [widenedIdentificationScheme, support_bind, support_pure, Set.mem_iUnion,
        Set.mem_singleton_iff, Prod.mk.injEq] at hw1st
      simp only [widenedIdentificationScheme] at hoz
      obtain ⟨y, -, hw1, hst⟩ := hw1st
      subst hst hw1
      split_ifs at hoz with hc1 hc2
      · rw [support_pure, Set.mem_singleton_iff, Option.some.injEq] at hoz
        subst hoz
        dsimp only at hc1 hc2 ⊢
        obtain ⟨hz_norm, hr0_norm⟩ := hc1
        obtain ⟨hct0_norm, hweight⟩ := hc2
        have hcs2_norm : polyVecNorm (prims.sampleInBall cTilde • sk.s2) ≤ widenedBeta p :=
          sampleInBall_smul_widened_bound p prims h_laws cTilde hs2 ha2 hb2
        set c := prims.sampleInBall cTilde with hc_def
        set aHat := prims.expandA pk.rho with haHat_def
        have hcond_t0 : ∀ j : Fin p.k, polyNorm ((-(c • sk.t0)).get j) ≤ p.gamma2 := by
          intro j
          have hneg : (-(c • sk.t0)).get j = -((c • sk.t0).get j) := by
            simp only [Vector.get_eq_getElem, Vector.getElem_neg]
          rw [hneg, polyNorm_neg']
          exact le_of_lt (lt_of_le_of_lt
            (LatticeCrypto.PolyVec.component_cInfNorm_le normOps (c • sk.t0) j) hct0_norm)
        have harith1 : aHat * y - c • sk.s2 + c • sk.t0 + -(c • sk.t0) = aHat * y - c • sk.s2 := by
          apply Vector.ext; intro i hi
          simp only [Vector.getElem_add, Vector.getElem_sub, Vector.getElem_neg]; abel
        have harith2 : aHat * y - c • sk.s2 + c • sk.s2 = aHat * y := by
          apply Vector.ext; intro i hi
          simp only [Vector.getElem_add, Vector.getElem_sub]; abel
        have hhide : prims.highBitsVec (aHat * y - c • sk.s2) = prims.highBitsVec (aHat * y) := by
          have h := hide_lowVec p prims h_laws (aHat * y - c • sk.s2) (c • sk.s2) (widenedBeta p)
            (fun j => le_trans
              (LatticeCrypto.PolyVec.component_cInfNorm_le normOps (c • sk.s2) j) hcs2_norm)
            (fun j => by
              have hj := lt_of_le_of_lt
                (LatticeCrypto.PolyVec.component_cInfNorm_le normOps
                  (prims.lowBitsVec (aHat * y - c • sk.s2)) j) hr0_norm
              simp only [Primitives.lowBitsVec, Vector.get_eq_getElem, Vector.getElem_map,
                polyNorm] at hj ⊢
              omega)
          rw [harith2] at h
          exact h.symm
        have hwa := wApprox_eq_of_keyIdentity p prims h_laws h_kg c y
        simp only [widenedIdentificationScheme, Bool.and_eq_true, decide_eq_true_eq]
        refine ⟨⟨hz_norm, ?_⟩, hweight⟩
        rw [hwa, useHintVec_makeHintVec p prims h_laws (-(c • sk.t0))
            (aHat * y - c • sk.s2 + c • sk.t0) hcond_t0, harith1, hhide]
      all_goals (rw [support_pure, Set.mem_singleton_iff] at hoz; exact absurd hoz (by simp))

/-! ## 8. HVZK -/

/-- Public-key-only simulator for the widened scheme: sample `z` from the inner
acceptance cube and program the commitment so verification succeeds.  The full
transcript distance is quantified separately as `widenedHvzkDistance`. -/
def widenedHvzkSimulator
    [DecidableEq prims.High]
    (pk : PublicKey p prims) : ProbComp (Option (Commitment p prims × CommitHashBytes p × Response p prims)) := do
  let cTilde ← $ᵗ (CommitHashBytes p)
  let z ← $ᵗ (RqVec p.l)
  let h ← $ᵗ (Vector prims.Hint p.k)
  if polyVecNorm z < p.gamma1 - widenedBeta p then
    let c := prims.sampleInBall cTilde
    let aHat := prims.expandA pk.rho
    let wApprox := computeWApprox p prims aHat c z pk.t1
    let w1 := prims.useHintVec h wApprox
    return some (w1, cTilde, (z, h))
  else
    return none

/-- Quantitative HVZK gap for the widened scheme; pinned as a named assumption.
The accepted-`z` theorem alone does not make the full transcript distance zero.
Currently the trivial value `1`, so `widened_ids_hvzk` carries no content until
this is sharpened (the honest prover's extra-rejection mass, as in upstream
`MLDSA.hvzkBoundReal`, is the intended target). -/
noncomputable def widenedHvzkDistance : ℝ≥0∞ := 1

/-- HVZK of the widened scheme at distance `widenedHvzkDistance`. With the
distance pinned to `1` this is the universal bound `tvDist ≤ 1`; the theorem
exists so the statement shape is fixed while the bound is sharpened. -/
theorem widened_ids_hvzk
    [DecidableEq prims.High] [IsUniformSpec unifSpec] :
    (widenedIdentificationScheme p prims).HVZK
      (fun pk => widenedHvzkSimulator p prims pk)
      widenedHvzkDistance.toReal := by
  intro s w _
  simp only [widenedHvzkDistance, ENNReal.toReal_one]
  exact tvDist_le_one _ _

/-! ## 9. ML-DSA-65 -/

instance : NeZero (2 * mldsa65.gamma1) :=
  ⟨by simp [mldsa65, ParameterSet.params]⟩

/-- **ML-DSA-65 concrete acceptance probability.** With `γ₁ = 2^19` and
`widenedBeta = 392`, the per-coefficient acceptance is `1047791 / 1048576`, and
there are `5·256 = 1280` coefficients.  Kept as an exact rational. -/
theorem mldsa65_widened_z_accept_prob
    (prims65 : Primitives mldsa65)
    [SampleableType (RqVec mldsa65.l)] [SampleableType (Vector prims65.Hint mldsa65.k)]
    [SampleableType (CommitHashBytes mldsa65)]
    (h_laws : Primitives.Laws prims65 nttOps)
    (pk : PublicKey mldsa65 prims65) (sk : SecretKey mldsa65)
    (hw : widenedValidKeyPair mldsa65 prims65 pk sk = true)
    (cTilde : CommitHashBytes mldsa65) :
    Pr[= true | (do
        let y ← sampleMaskCube mldsa65
        let z := y + prims65.sampleInBall cTilde • sk.s1
        pure (polyVecNorm z < mldsa65.gamma1 - widenedBeta mldsa65)) ] =
      (1047791 / 1048576 : ℝ≥0∞) ^ 1280 := by
  rw [widened_z_accepted_independent mldsa65 prims65 h_laws
    (by simp [widenedBeta, Params.beta, mldsa65, ParameterSet.params])
    (by simp [widenedBeta, Params.beta, mldsa65, ParameterSet.params, modulus])
    pk sk hw cTilde]
  simp only [widenedBeta, Params.beta, mldsa65, ParameterSet.params, ringDegree]
  norm_num

end MLDSA
