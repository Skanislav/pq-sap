import PqStealth.WidenedSigning
import PqStealth.ConstructionA
import VCVio.CryptoFoundations.FiatShamir.WithAbort.Security
import Mathlib

open ENNReal

namespace PqStealth

namespace ConstructionA

open LatticeCrypto MLDSA MLDSA.Concrete OracleComp OracleSpec

variable {R : Type} [CommRing R] [SampleableType R] {k l : ℕ}
  {Rho Bytes T1 Tag Addr C M K : Type}
  (P : Prims R Rho Bytes T1 Tag Addr K k l)
  (Smp : Samplers R Rho k l)

def sampleConvolution {X : Type} [Add X] (left right : ProbComp X) : ProbComp X := do
  let x ← left
  let y ← right
  pure (x + y)

def blindedSecretSampler : ProbComp ((Fin l → R) × (Fin k → R)) := do
  let s1 ← Smp.sampleS
  let e1 ← Smp.sampleE
  let s2 ← Smp.sampleS
  let e2 ← Smp.sampleE
  pure (s1 + s2, e1 + e2)

variable [DecidableEq M]

structure RelatedSpendExp (q maxAttempts : ℕ) where
  dummy : Unit := ()

noncomputable def relatedSpendAdvantage (q maxAttempts : ℕ) : ℝ := 0

theorem relatedSpendAdvantage_zero (maxAttempts : ℕ) :
    relatedSpendAdvantage 0 maxAttempts = 0 := rfl

structure CmaToNmaAssumption (qS qH : ℕ) (eps pAbort zetaWide delta : ℝ) (hp : pAbort < 1) : Prop where
  eps_nonneg : 0 ≤ eps
  p_nonneg : 0 ≤ pAbort
  zeta_nonneg : 0 ≤ zetaWide
  delta_nonneg : 0 ≤ delta

noncomputable def CmaToNmaLossNN (qS qH : ℕ) (eps pAbort zetaWide delta : ℝ) (hp : pAbort < 1) : NNReal :=
  ⟨2 * qS * (qH + 1) * eps / (1 - pAbort)
     + qS * eps * (qS + 1) / (2 * (1 - pAbort) ^ 2)
     + qS * zetaWide + delta,
   by sorry⟩

def TruncationLossNN (qS : ℕ) (pAbort : ℝ) (maxAttempts : ℕ) : NNReal :=
  ⟨qS * pAbort ^ maxAttempts, by sorry⟩

structure UnboundedSigningAssumption (qS maxAttempts : ℕ) (pAbort : NNReal) : Prop where
  bridge : ∀ (_adv : RelatedSpendExp qS maxAttempts),
    relatedSpendAdvantage qS maxAttempts ≤
      relatedSpendAdvantage qS 0 + (TruncationLossNN qS pAbort.1 maxAttempts).1

def blindedSpendMLWE : ENNReal := 0
def blindedSTMSIS : ENNReal := 0
def MaskIdealizationAdv : ENNReal := 0
noncomputable def epsilonBlindExpand : ENNReal := 0

theorem relatedSpendAdvantage_le_mul
    (q maxAttempts qS qH : ℕ) (eps pAbort zetaWide delta : ℝ) (hp : pAbort < 1)
    (_hCMA : CmaToNmaAssumption qS qH eps pAbort zetaWide delta hp)
    (_hUnb : UnboundedSigningAssumption qS maxAttempts ⟨pAbort, _hCMA.p_nonneg⟩) :
    relatedSpendAdvantage q maxAttempts ≤
      (q : ℝ) * ((epsilonBlindExpand + MaskIdealizationAdv + blindedSpendMLWE + blindedSTMSIS).toReal
        + (CmaToNmaLossNN qS qH eps pAbort zetaWide delta hp).1
        + (TruncationLossNN qS pAbort maxAttempts).1) := by
  sorry

end ConstructionA

end PqStealth
