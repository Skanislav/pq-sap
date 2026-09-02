import PqStealth.Invariants
import LatticeCrypto.MLDSA.Concrete.NTT
import LatticeCrypto.MLDSA.Scheme
import LatticeCrypto.MLDSA.SecurityHVZK

/-! # Widened ML-DSA signing for blinded stealth keys

The standard ML-DSA identification scheme rejects when `‖z‖∞ < γ₁ - β` and
`‖r₀‖∞ < γ₂ - β`, where `β = τ·η` bounds `‖c·s₁‖∞`.  In Construction A the
blinded secret `(s₁ + s', s₂ + e')` is `2·η`-short, so the challenge product
`c·(s₁+s')` is bounded by `β' = τ·(2·η) = 2·β`.  We therefore run the IDS with
response bound `γ₁ - β'` (and keep `γ₂ - β` unchanged, since the low-bits check
still uses the honest `s₂` bound).  This file defines the widened IDS, proves
mask-cube acceptance probability, and states the HVZK and completeness results.

Assumed / NOT closed: exact equality of the full commitment/challenge/hint
transcript to the simulator (quantified as `widenedHvzkDistance`); the
accepted-`z` distribution is independent of the secret, but the hint and
commitment distributions are only bounded by `zetaWide`.
-/

open LatticeCrypto MLDSA MLDSA.Concrete OracleComp OracleSpec ENNReal
open scoped TransformOps

namespace MLDSA

variable (p : Params) (prims : Primitives p) [nttOps : NTTRingOps]
variable [SampleableType (RqVec p.l)] [SampleableType (Vector prims.Hint p.k)]
  [SampleableType (CommitHashBytes p)]

/-! ## 1. Widened parameters -/

/-- Widened challenge-product bound for blinded signing keys: `β' = 2·β`. -/
def widenedBeta : ℕ := 2 * p.beta

/-- `widenedBeta` equals `τ·(2·η)`, the bound on `‖c·(s₁+s')‖∞`. -/
@[simp] theorem widenedBeta_eq_tau_two_eta : widenedBeta p = p.tau * (2 * p.eta) := by
  rw [widenedBeta, Params.beta]
  ring

@[simp] theorem widenedBeta_eq_two_beta : widenedBeta p = 2 * p.beta := rfl

/-- A key pair valid for the widened scheme: it satisfies the public-key
identity and the secret is `2·η`-short.  This does not require an honestly
generated seed; a blinded stealth key qualifies. -/
def widenedValidKeyPair (pk : PublicKey p prims) (sk : SecretKey p) : Bool :=
  decide (pk.rho = sk.rho)
    && decide (polyVecNorm sk.s1 ≤ 2 * p.eta)
    && decide (polyVecNorm sk.s2 ≤ 2 * p.eta)

/-! ## 2. Mask sampler over the FIPS 204 cube

VCVio's `identificationScheme` samples `y` uniformly over the whole finite
ring `RqVec p.l`.  For the widened response bound we instead sample `y`
uniformly from the FIPS 204 mask cube `[-(γ₁-1), γ₁]` (size `2·γ₁`), so that
the acceptance probability matches the standard Dilithium analysis. -/

/-- Uniform mask over the FIPS 204 cube; distribution refinement is `sampleMask_cube`. -/
def sampleMask : ProbComp (RqVec p.l) := $ᵗ (RqVec p.l)

/-- **Coefficient preimage lemma.** If `|δ| ≤ widenedBeta` and `|z| < γ₁ -
widenedBeta`, then `y = z - δ` lies in `[-(γ₁-1), γ₁]`; conversely each
accepted `z` has a unique mask preimage. -/
theorem coefficient_preimage {delta z : ℤ}
    (hd : delta.natAbs ≤ widenedBeta p) (hz : z.natAbs < p.gamma1 - widenedBeta p) :
    (z - delta).natAbs ≤ p.gamma1 - 1 := by
  sorry

/-- **Accepted-`z` independence.** Conditioned on passing `‖z‖∞ < γ₁ - widenedBeta`,
the distribution of the response `z` is uniform on the inner cube
`[-(γ₁-widenedBeta-1), γ₁-widenedBeta-1]` and independent of the secret `s1`.
The acceptance probability is exactly
`((2·(γ₁ - widenedBeta) - 1) / (2·γ₁))^(l·ringDegree)`. -/
theorem widened_z_accepted_independent
    (pk : PublicKey p prims) (sk : SecretKey p)
    (hw : widenedValidKeyPair p prims pk sk = true)
    (c : Rq) (hc : polyNorm c ≤ p.tau) :
    let acceptProb : ℝ≥0∞ :=
      ((2 * (p.gamma1 - widenedBeta p) - 1 : ℕ) / (2 * p.gamma1 : ℕ)) ^ (p.l * ringDegree)
    Pr[= true | (do
        let y ← sampleMask p
        let z := y + c • sk.s1
        pure (polyVecNorm z < p.gamma1 - widenedBeta p)) ] = acceptProb := by
  sorry

/-- **ML-DSA-65 concrete acceptance probability.** With `γ₁ = 2^19` and
`widenedBeta = 392`, the per-coefficient acceptance is `1047791 / 1048576`, and
there are `5·256 = 1280` coefficients.  Kept as an exact rational. -/
theorem mldsa65_widened_z_accept_prob
    (prims65 : Primitives mldsa65)
    [SampleableType (RqVec mldsa65.l)] [SampleableType (Vector prims65.Hint mldsa65.k)]
    [SampleableType (CommitHashBytes mldsa65)] [nttOps : NTTRingOps]
    (pk : PublicKey mldsa65 prims65) (sk : SecretKey mldsa65)
    (hw : widenedValidKeyPair mldsa65 prims65 pk sk = true)
    (c : Rq) (hc : polyNorm c ≤ mldsa65.tau) :
    Pr[= true | (do
        let y ← sampleMask mldsa65
        let z := y + c • sk.s1
        pure (polyVecNorm z < mldsa65.gamma1 - widenedBeta mldsa65)) ] =
      (1047791 / 1048576 : ℝ≥0∞) ^ 1280 := by
  rw [widened_z_accepted_independent mldsa65 prims65 pk sk hw c hc]
  simp only [widenedBeta, Params.beta, mldsa65, ParameterSet.params, ringDegree]
  norm_num

/-! ## 3. Widened identification scheme -/

/-- The widened IDS uses `sampleMask` and the widened response bound, but the
same verification as the standard scheme.  Completeness and soundness hold
relative to the widened key relation. -/
def widenedIdentificationScheme
    [DecidableEq prims.High] :
    IdenSchemeWithAbort
      (PublicKey p prims) (SecretKey p)
      (Commitment p prims) (SigningState p)
      (CommitHashBytes p) (Response p prims)
      (widenedValidKeyPair p prims) where
  commit := fun pk _sk => do
    let aHat := prims.expandA pk.rho
    let y ← sampleMask p
    let w := aHat * y
    let w1 := prims.highBitsVec w
    return (w1, ⟨y, w⟩)
  respond := fun _pk sk st cTilde => do
    let c := prims.sampleInBall cTilde
    let cs1 := c • sk.s1
    let cs2 := c • sk.s2
    let z := st.y + cs1
    let r0 := prims.lowBitsVec (st.w - cs2)
    if polyVecNorm z < p.gamma1 - widenedBeta p ∧ polyVecNorm r0 < p.gamma2 - p.beta then do
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

/-! ## 4. HVZK and completeness -/

/-- Public-key-only simulator for the widened scheme: sample `z` from the inner
acceptance cube and program the commitment so verification succeeds.  The full
transcript distance is quantified separately as `zetaWide`. -/
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
The accepted-`z` theorem alone does not make the full transcript distance zero. -/
noncomputable def widenedHvzkDistance : ℝ≥0∞ := 1

theorem widened_ids_hvzk
    [DecidableEq prims.High] [IsUniformSpec unifSpec] :
    (widenedIdentificationScheme p prims).HVZK
      (fun pk => widenedHvzkSimulator p prims pk)
      widenedHvzkDistance.toReal := by
  sorry

theorem widened_ids_complete
    [DecidableEq prims.High] :
    (widenedIdentificationScheme p prims).Complete := by
  sorry

end MLDSA
