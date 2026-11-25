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

/-- The uniform Boolean sample assigns mass `1 / 2` to each outcome: the
singleton masses of a uniform answer measure over a two-element type. -/
theorem evalDist_uniformBool_apply (x : Bool) :
    𝒟[($ᵗ Bool : ProbComp Bool)] {x} = 1 / 2 := by
  have h : 𝒟[($ᵗ Bool : ProbComp Bool)] = (toMeasure (spec := unifSpec) ()).trim le_top := by
    simp [uniformSample]
  rw [h, MeasureTheory.trim_eq_self]
  rw [UniformAnswerMeasure.toMeasure_singleton]
  simp [Fintype.card_bool]

end FairCoin

/-! ## The hidden-bit decomposition

A fair hidden-bit guessing game over two total Boolean branches has real bias
exactly the distinguishing advantage between the branches. This is the real
reading of upstream's `Measure.boolBias_bind_coin`: the game measure's masses
are `(Pr{true | X} + Pr{!x | Y}) / 2`, so the bias halves the branch distance. -/

section CoinBranch

/-- The singleton masses of the hidden-bit game measure, for fixed branches
`X Y : ProbComp Bool` under a fair coin. -/
theorem evalDist_coinBranch_apply (X Y : ProbComp Bool) (b x : Bool) :
    𝒟[do
      let b ← ($ᵗ Bool : ProbComp Bool)
      let z ← if b then X else Y
      pure (b == z)] {x} = (𝒟[X] {x} + 𝒟[Y] {!x}) / 2 := by
  rw [evalDist_bind_of_discrete ($ᵗ Bool : ProbComp Bool) _ Measurable.of_discrete]
  rw [Measure.bind_apply (MeasurableSet.singleton x) Measurable.of_discrete.aemeasurable,
    lintegral_fintype, Fintype.sum_bool, evalDist_uniformBool_apply true,
    evalDist_uniformBool_apply false]
  cases x <;> simp [evalDist_bind_of_discrete, evalDist_pure,
    Measure.dirac_apply']
    all_goals ring_nf <;> simp [mul_comm, div_eq_mul_inv, mul_div_assoc']

/-- Hidden-bit decomposition at the computation level: with the coin fair and
both branches total, the game's real bias is the distinguishing advantage
between its branches. Totality hypotheses are on the real masses, exactly as
upstream's `Measure.boolBias_bind_coin`. -/
theorem boolBiasAdvantage_coinBranch (X Y : ProbComp Bool)
    (hX : Pr{let x ← X}[x = true] + Pr{let x ← X}[x = false] = 1)
    (hY : Pr{let x ← Y}[x = true] + Pr{let x ← Y}[x = false] = 1) :
    (do
      let b ← ($ᵗ Bool : ProbComp Bool)
      let z ← if b then X else Y
      pure (b == z)).boolBiasAdvantage
      = X.boolDistAdvantage Y := by
  have hmass : ∀ x : Bool,
      𝒟[do
        let b ← ($ᵗ Bool : ProbComp Bool)
        let z ← if b then X else Y
        pure (b == z)] {x}
        = (𝒟[X] {x} + 𝒟[Y] {!x}) / 2 := evalDist_coinBranch_apply X Y
  have htotTrue : 𝒟[do
      let b ← ($ᵗ Bool : ProbComp Bool)
      let z ← if b then X else Y
      pure (b == z)] {true} + 𝒟[do
      let b ← ($ᵗ Bool : ProbComp Bool)
      let z ← if b then X else Y
      pure (b == z)] {false} = 1 := by
    rw [hmass true, hmass false]
    have hYf : 𝒟[Y] {false} = 1 - 𝒟[Y] {true} := by
      have := hY
      rw [prEvent_eq_evalDist_singleton, prEvent_eq_evalDist_singleton] at this
      linarith [Measure.apply_true_add_apply_false_eq_one 𝒟[Y]]
    have hXf : 𝒟[X] {false} = 1 - 𝒟[X] {true} := by
      have := hX
      rw [prEvent_eq_evalDist_singleton, prEvent_eq_evalDist_singleton] at this
      linarith [Measure.apply_true_add_apply_false_eq_one 𝒟[X]]
    rw [hXf, hYf]
    simp [two_ne_zero, ENNReal.add_div_self]
  have hne : ∀ x : Bool, 𝒟[do
      let b ← ($ᵗ Bool : ProbComp Bool)
      let z ← if b then X else Y
      pure (b == z)] {x} ≠ ⊤ := by
    intro x
    rw [hmass x]
    exact div_ne_top (add_ne_top.mpr ⟨measure_ne_top _ _, measure_ne_top _ _⟩) two_ne_zero
  unfold ProbComp.boolBiasAdvantage ProbComp.boolDistAdvantage
  rw [← Measure.apply_true_add_apply_false_eq_one (𝒟[do
      let b ← ($ᵗ Bool : ProbComp Bool)
      let z ← if b then X else Y
      pure (b == z)]), htotTrue]
  rw [Measure.toReal_boolBias, hmass true, hmass false,
    Measure.toReal_boolDist]
  rw [show (𝒟[X] {true} + 𝒟[Y] {!true}).toReal - (𝒟[X] {false} + 𝒟[Y] {!false}).toReal =
      (𝒟[X] {true}).toReal - (𝒟[Y] {true}).toReal from by
    have hYc : (𝒟[Y] {!false}).toReal = 1 - (𝒟[Y] {true}).toReal := by
      rw [Bool.not_false]
      have := hY
      rw [prEvent_eq_evalDist_singleton, prEvent_eq_evalDist_singleton] at this
      have h1 := (Measure.apply_true_add_apply_false_eq_one 𝒟[Y])
      rw [Measure.toReal_boolBias] at h1
      simp only [ENNReal.toReal_add (measure_ne_top _ _) (measure_ne_top _ _),
        ENNReal.toReal_one] at h1
      linarith
    have hXc : (𝒟[X] {!true}).toReal = 1 - (𝒟[X] {true}).toReal := by
      rw [Bool.not_true]
      have := hX
      rw [prEvent_eq_evalDist_singleton, prEvent_eq_evalDist_singleton] at this
      have h1 := (Measure.apply_true_add_apply_false_eq_one 𝒟[X])
      simp only [ENNReal.toReal_add (measure_ne_top _ _) (measure_ne_top _ _),
        ENNReal.toReal_one] at h1
      linarith
    rw [hXc, hYc, Bool.not_true, Bool.not_false]
    simp [sub_add_eq_iff, sub_eq_sub]
    ring]

end CoinBranch
