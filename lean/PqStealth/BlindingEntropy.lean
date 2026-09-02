import PqStealth.BlindingROM
import LatticeCrypto.MLDSA.Concrete.Instance

/-! # Point-mass bound for the Construction A address point -/

open LatticeCrypto MLDSA MLDSA.Concrete OracleComp OracleSpec ENNReal

namespace PqStealth

namespace ConstructionA

variable {R : Type} [CommRing R] {k l : ℕ} {Rho WireBytes T1 Tag Addr K : Type}
  [SampleableType Addr]

def blindPointSample (P : Prims R Rho WireBytes T1 Tag Addr K k l)
    [SampleableType R] (rho : Rho) (t : Fin k → R) : ProbComp WireBytes :=
  do let u ← $ᵗ (Fin k → R)
     pure (P.pack rho (P.power2Round (u + t)))

def BlindPointMassBound (P : Prims R Rho WireBytes T1 Tag Addr K k l)
    [SampleableType R] (beta : ℝ≥0∞) : Prop :=
  ∀ (rho : Rho) (t : Fin k → R) (x : WireBytes),
    Pr[= x | blindPointSample P rho t] ≤ beta

theorem blindBadProb_le_queryBound
    (P : Prims R Rho WireBytes T1 Tag Addr K k l)
    [SampleableType R] [DecidableEq WireBytes]
    (tg : Tag) (rho : Bool → Rho) (t : Bool → Fin k → R)
    (adv : BlindAdvRO Tag Addr WireBytes) (qH : ℕ)
    (beta : ℝ≥0∞) (hB : BlindPointMassBound P beta) (b : Bool) :
    blindBadProb P tg rho t adv b ≤ ((qH : ℝ≥0∞) * beta).toReal := by
  sorry

theorem blindingAdvantageRO_le_queryBound
    (P : Prims R Rho WireBytes T1 Tag Addr K k l)
    [SampleableType R] [DecidableEq WireBytes]
    (tg : Tag) (rho : Bool → Rho) (t : Bool → Fin k → R)
    (adv : BlindAdvRO Tag Addr WireBytes) (qH : ℕ)
    (beta : ℝ≥0∞) (hB : BlindPointMassBound P beta) :
    blindingAdvantageRO P tg rho t adv ≤ 2 * ((qH : ℝ≥0∞) * beta).toReal := by
  sorry

noncomputable def mlDsaAddressPointBeta (k : ℕ) : ℝ≥0∞ :=
  ((2 ^ droppedBits : ℝ≥0∞) / modulus) ^ (k * ringDegree)

variable (prims65 : Primitives mldsa65)

theorem blindPointMassBound_mldsa65
    [SampleableType Rq]
    (P : Prims Rq (MLDSA.Bytes 32) WireBytes (Vector prims65.Power2High mldsa65.k)
      Tag Addr K mldsa65.k mldsa65.l) :
    BlindPointMassBound P (mlDsaAddressPointBeta mldsa65.k) := by
  sorry

end ConstructionA

end PqStealth
