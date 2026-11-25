import VCVio.OracleComp.EvalDist.Measure
import VCVio.OracleComp.EvalDist.AnswerMeasure
import VCVio.OracleComp.ProbComp
import VCVio.OracleComp.Constructions.SampleableType
import ToMathlib.MeasureTheory.Measure.Bool
import VCVio.EvalDist.Monad.Bool

/-!
# Advantage currency: the ℝ interface over the measure API

Advantages of Boolean-valued games in this development are real numbers: the
bias `|Pr{true} - Pr{false}|` of a single game and the distinguishing
advantage `|Pr{true} - Pr{true}'|` of a pair, at the real level. The measure
API (`ToMathlib.MeasureTheory.Measure.Bool`) carries the same quantities as
`ℝ≥0∞`: `Measure.boolBias` and `Measure.boolDist`. This module fixes the real
interface and its toolkit: the definitions (on computations and on measures),
the commutation and triangle laws, the fair-coin mass of the uniform bit, and
the hidden-bit decomposition — the bias of a fair hidden-bit guessing game is
exactly the distinguishing advantage of its two branches.

Every argument is the mass of a `{true}` singleton computed by `Measure.boolBias` /
`Measure.boolDist`, so the real-valued and `ℝ≥0∞`-valued interfaces agree by
`toReal`; nothing changes value in the bridge.

The computation-level definitions are declared in `PFunctor.FreeM` — the head
namespace of `ProbComp` — so that generalized field notation
`p.boolBiasAdvantage` resolves; the measure-level definitions live in
`MeasureTheory.Measure` for the same reason.
-/

open MeasureTheory OracleComp

namespace PqStealth

section Defs

/-- Bias advantage of a Boolean-valued computation: the gap between the
probabilities of the two outputs, at the real level. -/
@[expose]
noncomputable def _root_.PFunctor.FreeM.boolBiasAdvantage (p : ProbComp Bool) : ℝ :=
  𝒟[p].boolBias.toReal

/-- Distinguishing advantage between two Boolean-valued computations, measured
on the `true` branch. -/
@[expose]
noncomputable def _root_.PFunctor.FreeM.boolDistAdvantage (p q : ProbComp Bool) : ℝ :=
  𝒟[p].boolDist 𝒟[q] |>.toReal

/-- Bias advantage of a Boolean-valued measure, at the real level. -/
@[expose]
noncomputable def _root_.MeasureTheory.Measure.boolBiasAdvantage (μ : Measure Bool) : ℝ :=
  μ.boolBias.toReal

/-- Distinguishing advantage between two Boolean-valued measures, measured on
the `true` branch. -/
@[expose]
noncomputable def _root_.MeasureTheory.Measure.boolDistAdvantage (μ ν : Measure Bool) : ℝ :=
  μ.boolDist ν |>.toReal

end Defs

section Bridges

/-- Distinguishing advantage is symmetric: it is the absolute value of a
difference of one mass, so the two argument orders agree. -/
theorem _root_.PFunctor.FreeM.boolDistAdvantage_comm (p q : ProbComp Bool) :
    p.boolDistAdvantage q = q.boolDistAdvantage p := by
  unfold PFunctor.FreeM.boolDistAdvantage
  exact congrArg ENNReal.toReal (Measure.boolDist_comm _ _)

/-- Distinguishing advantage is symmetric at the measure level. -/
theorem _root_.MeasureTheory.Measure.boolDistAdvantage_comm (μ ν : Measure Bool) :
    μ.boolDistAdvantage ν = ν.boolDistAdvantage μ := by
  unfold MeasureTheory.Measure.boolDistAdvantage
  exact congrArg ENNReal.toReal (Measure.boolDist_comm _ _)

/-- The triangle inequality for distinguishing advantage, at the real level:
distance through an intermediate branch is bounded by the two distances. The
measures need only be finite, which every game observation is. -/
theorem _root_.MeasureTheory.Measure.boolDistAdvantage_triangle {μ ν ρ : Measure Bool}
    [IsFiniteMeasure μ] [IsFiniteMeasure ν] [IsFiniteMeasure ρ] :
    μ.boolDistAdvantage ρ ≤ μ.boolDistAdvantage ν + ν.boolDistAdvantage ρ := by
  unfold MeasureTheory.Measure.boolDistAdvantage
  calc (μ.boolDist ρ).toReal ≤ (μ.boolDist ν + ν.boolDist ρ).toReal := by
        exact ENNReal.toReal_le_toReal (by simpa using Measure.boolDist_ne_top μ ρ)
          (add_ne_top.mpr ⟨Measure.boolDist_ne_top μ ν, Measure.boolDist_ne_top ν ρ⟩)
          (Measure.boolDist_triangle μ ν ρ)
    _ = _ := ENNReal.toReal_add (Measure.boolDist_ne_top μ ν) (Measure.boolDist_ne_top ν ρ)

/-- The triangle inequality for computations: the measures behind the games are
probability measures (lossless denotation), hence finite. -/
theorem _root_.PFunctor.FreeM.boolDistAdvantage_triangle (p q r : ProbComp Bool) :
    p.boolDistAdvantage r ≤ p.boolDistAdvantage q + q.boolDistAdvantage r :=
  MeasureTheory.Measure.boolDistAdvantage_triangle 𝒟[p] 𝒟[q] 𝒟[r]

end Bridges

section FairCoin

/-- The uniform Boolean sample assigns mass `1 / 2` to each outcome: a uniform
sample over a two-element type has reciprocal-cardinality singleton masses. -/
theorem evalDist_uniformBool_apply (x : Bool) :
    𝒟[($ᵗ Bool : ProbComp Bool)] {x} = 1 / 2 := by
  rw [SampleableType.evalDist_uniformSample_singleton]
  simp [Fintype.card_bool]

end FairCoin

/-! ## The hidden-bit decomposition

A fair hidden-bit guessing game over two total Boolean branches has real bias
exactly the distinguishing advantage between its branches. This lifts
upstream's monad-general `evalDist_boolBias_bind_coin` to the real interface:
the bias of the game measure is the bias of `𝒟` of the game computation, and
the branch measures are the output measures of the branch computations. -/

section CoinBranch

/-- Hidden-bit decomposition at the computation level: the real bias of a fair
hidden-bit guessing game over two Boolean branches is the distinguishing
advantage between the branches. Coin fairness is the reciprocal-cardinality
singleton mass of the uniform `Bool` sample, and branch totality is the
`IsProbabilityMeasure` instance every lossless computation's output measure
satisfies. -/
theorem boolBiasAdvantage_coinBranch (real rand : ProbComp Bool) :
    (do
      let b ← ($ᵗ Bool : ProbComp Bool)
      let z ← if b then real else rand
      pure (b == z)).boolBiasAdvantage
      = real.boolDistAdvantage rand := by
  unfold PFunctor.FreeM.boolBiasAdvantage PFunctor.FreeM.boolDistAdvantage
  exact congrArg ENNReal.toReal
    (evalDist_boolBias_bind_coin ($ᵗ Bool : ProbComp Bool) real rand
      (evalDist_uniformBool_apply true) (evalDist_uniformBool_apply false))

/-- Hidden-bit decomposition at the measure level, on the real interface: the
real bias of the fair hidden-bit composite over two Boolean measures is the real
distinguishing distance between them. This is the one-`toReal` transport of
upstream's `Measure.boolBias_bind_coin`; the branch totality it needs is stated
as mass sums, and the coin masses as equalities to `1 / 2`. -/
theorem _root_.MeasureTheory.Measure.boolBiasAdvantage_bind_coin {coin μ ν : Measure Bool}
    (hcT : coin {true} = 1 / 2) (hcF : coin {false} = 1 / 2)
    (hμ : μ {true} + μ {false} = 1) (hν : ν {true} + ν {false} = 1) :
    (coin.bind fun b => (if b then μ else ν).bind
        fun z => Measure.dirac (b == z)).boolBiasAdvantage
      = μ.boolDistAdvantage ν := by
  unfold MeasureTheory.Measure.boolBiasAdvantage MeasureTheory.Measure.boolDistAdvantage
  exact congrArg ENNReal.toReal
    (Measure.boolBias_bind_coin coin μ ν hcT hcF hμ hν)

end CoinBranch

end PqStealth
