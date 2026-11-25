import VCVio.OracleComp.EvalDist.Measure
import VCVio.OracleComp.EvalDist.AnswerMeasure
import VCVio.OracleComp.ProbComp
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
-/

open MeasureTheory OracleComp

namespace PqStealth

section Defs

/-- Bias advantage of a Boolean-valued computation: the gap between the
probabilities of the two outputs, at the real level. -/
@[expose]
noncomputable def ProbComp.boolBiasAdvantage (p : ProbComp Bool) : ℝ :=
  𝒟[p].boolBias.toReal

/-- Distinguishing advantage between two Boolean-valued computations, measured
on the `true` branch. -/
@[expose]
noncomputable def ProbComp.boolDistAdvantage (p q : ProbComp Bool) : ℝ :=
  𝒟[p].boolDist 𝒟[q] |>.toReal

/-- Bias advantage of a Boolean-valued measure, at the real level. -/
@[expose]
noncomputable def Measure.boolBiasAdvantage (μ : Measure Bool) : ℝ :=
  μ.boolBias.toReal

/-- Distinguishing advantage between two Boolean-valued measures, measured on
the `true` branch. -/
@[expose]
noncomputable def Measure.boolDistAdvantage (μ ν : Measure Bool) : ℝ :=
  μ.boolDist ν |>.toReal

end Defs

section Bridges

/-- Distinguishing advantage is symmetric: it is the absolute value of a
difference of one mass, so the two argument orders agree. -/
theorem ProbComp.boolDistAdvantage_comm (p q : ProbComp Bool) :
    p.boolDistAdvantage q = q.boolDistAdvantage p := by
  unfold ProbComp.boolDistAdvantage
  exact congrArg ENNReal.toReal (Measure.boolDist_comm _ _)

/-- Distinguishing advantage is symmetric at the measure level. -/
theorem Measure.boolDistAdvantage_comm (μ ν : Measure Bool) :
    μ.boolDistAdvantage ν = ν.boolDistAdvantage μ := by
  unfold Measure.boolDistAdvantage
  exact congrArg ENNReal.toReal (Measure.boolDist_comm _ _)

/-- The triangle inequality for distinguishing advantage, at the real level:
distance through an intermediate branch is bounded by the two distances. The
measures need only be finite, which every game observation is. -/
theorem Measure.boolDistAdvantage_triangle {μ ν ρ : Measure Bool}
    [IsFiniteMeasure μ] [IsFiniteMeasure ν] [IsFiniteMeasure ρ] :
    μ.boolDistAdvantage ρ ≤ μ.boolDistAdvantage ν + ν.boolDistAdvantage ρ := by
  unfold Measure.boolDistAdvantage
  calc (μ.boolDist ρ).toReal ≤ (μ.boolDist ν + ν.boolDist ρ).toReal := by
        exact ENNReal.toReal_le_toReal (by simpa using Measure.boolDist_ne_top μ ρ)
          (add_ne_top.mpr ⟨Measure.boolDist_ne_top μ ν, Measure.boolDist_ne_top ν ρ⟩)
          (Measure.boolDist_triangle μ ν ρ)
    _ = _ := ENNReal.toReal_add (Measure.boolDist_ne_top μ ν) (Measure.boolDist_ne_top ν ρ)

/-- The triangle inequality for computations: the measures behind the games are
probability measures. -/
theorem ProbComp.boolDistAdvantage_triangle (p q r : ProbComp Bool) :
    p.boolDistAdvantage r ≤ p.boolDistAdvantage q + q.boolDistAdvantage r :=
  Measure.boolDistAdvantage_triangle 𝒟[p] 𝒟[q] 𝒟[r]

/-- Every Boolean-valued measure on a subprobability observation has finite
`boolDist`/`boolBias`, the side condition the real bridge needs. -/
instance {m : Type → Type} [Monad m] [EvalDistSemantics m] {α : Type}
    (mx : m Bool) : IsFiniteMeasure 𝒟[mx] where
  measure_univ_lt_top := by
    have h : 𝒟[mx] Set.univ ≤ 1 := evalDist_apply_univ_le_one mx
    exact lt_of_le_of_lt' h (by norm_num)

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
exactly the distinguishing advantage between its branches. This transports
upstream's `Measure.boolBias_bind_coin` along `evalDist`: the bias of the game
measure is the bias of `𝒟` of the game computation, and the branch measures are
the output measures of the branch computations. -/

section CoinBranch

/-- Hidden-bit decomposition at the computation level: the real bias of a fair
hidden-bit guessing game over two Boolean branches is the distinguishing
advantage between the branches. This lifts upstream's monad-general
`evalDist_boolBias_bind_coin` to the real interface with the two `toReal`
bridges; coin fairness is the reciprocal-cardinality singleton mass of the
uniform `Bool` sample, and branch totality is the `IsProbabilityMeasure`
instance every `ProbComp` output measure satisfies. -/
theorem boolBiasAdvantage_coinBranch (real rand : ProbComp Bool) :
    (do
      let b ← ($ᵗ Bool : ProbComp Bool)
      let z ← if b then real else rand
      pure (b == z)).boolBiasAdvantage
      = real.boolDistAdvantage rand := by
  unfold ProbComp.boolBiasAdvantage ProbComp.boolDistAdvantage
  rw [Measure.toReal_boolBias, Measure.toReal_boolDist,
    evalDist_boolBias_bind_coin ($ᵗ Bool : ProbComp Bool) real rand
      (by rw [SampleableType.evalDist_uniformSample_singleton]; simp [Fintype.card_bool])
      (by rw [SampleableType.evalDist_uniformSample_singleton]; simp [Fintype.card_bool])]

end CoinBranch

namespace Measure

/-- Hidden-bit decomposition at the measure level, on the real interface: the
real bias of the fair hidden-bit composite over two Boolean measures is the real
distinguishing distance between them. This is the one-`toReal` transport of
upstream's `Measure.boolBias_bind_coin`; the branch totality it needs is stated
as mass sums, and the coin masses as equalities to `1 / 2`. -/
theorem boolBiasAdvantage_bind_coin {coin μ ν : Measure Bool}
    (hcT : coin {true} = 1 / 2) (hcF : coin {false} = 1 / 2)
    (hμ : μ {true} + μ {false} = 1) (hν : ν {true} + ν {false} = 1) :
    (coin.bind fun b => (if b then μ else ν).bind
        fun z => Measure.dirac (b == z)).boolBiasAdvantage
      = μ.boolDistAdvantage ν := by
  unfold Measure.boolBiasAdvantage Measure.boolDistAdvantage
  exact congrArg ENNReal.toReal
    (Measure.boolBias_bind_coin coin μ ν hcT hcF hμ hν)

end Measure
