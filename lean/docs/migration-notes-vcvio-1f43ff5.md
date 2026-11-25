# PR 60 — deep proof migration: architecture decisions (recorded 2026-11-25)

## Facts verified at pin 1f43ff5 (#1187)

1. **SPMF is deleted upstream entirely** (zero occurrences outside docs). The codemod
   left `: SPMF Bool` ascriptions in our 16 files — they no longer resolve. All become
   `Measure Bool` (= the codomain of the new `runtime.evalDist`).
2. **`VCVio.CryptoFoundations.SecExp` is deleted.** Its four ℝ-valued advantage
   definitions (`ProbComp/SPMF.boolBiasAdvantage`, `.boolDistAdvantage`) and toolkit
   (`_eq_two_mul_abs_sub_half`, `_triangle`, `boolBiasAdvantage_eq_boolDistAdvantage_coin_branch`,
   `boolBiasAdvantage_bind_uniformBool_eq_boolDistAdvantage`) must be re-created locally
   as a new module `PqStealth/Advantage.lean`, in the `Measure` namespace so dot-notation
   survival keeps every consumer call site unchanged.
3. **Upstream advantage currency is now `Measure.boolBias` / `Measure.boolDist` : ℝ≥0∞**
   (`ToMathlib.MeasureTheory.Measure.Bool`): `boolBias μ = absDiff μ{true} μ{false}`,
   `boolDist μ ν = absDiff μ{true} ν{true}` — **no factor difference** vs our old
   `|p_true - p_false|` / `|p_true - q_true|` defs. `toReal_boolBias`/`toReal_boolDist`
   give the ℝ bridge.
4. Upstream's merged `ANO.lean` = key-revealing mirror of our ANO section (transport
   via `wrapper` with `Adv_KR(wrapper A) = Adv_CO(A)`); CPA=CCA game equality only, no
   reduction theorem. `KEMDEM/Measure.lean` (`bias_compose_le`) is the pattern for
   measure-level coin-branch decompositions: `hbranch` + `Measure.boolBias_bind_coin`.
5. **`ProbCompRuntime` re-architected**: fields `toSemanticsVia : SemanticsVia m`,
   `toProbCompLift : ProbCompLift m`, plus law `evalDist_map_eq`. Observations are
   `Measure`-valued. **No bundled bind law** (only `evalDist_map`/`evalDist_bind_pure`).
   Upstream's own measure-level reductions (`KEMDEM/Measure`) are stated runtime-free
   with `[EvalDistSemantics m]`/`[LawfulEvalDistSemantics m]`; runtime-specific games
   are only related at the canonical `probComp` runtime (`probComp_evalDist`).

## Decisions

- **D1 (ℝ vs ℝ≥0∞): keep the ℝ-valued advantage interface.** Consumers pin ℝ down:
  `ANOAssumption.epsilonANO : ℝ`, `SPRTwoHop`, `ConstructionA/S`, `MLKEM`, `Multi*`,
  `Controls` (`1 - keyCollisionProb`), ERC statements. New defs measure-native:
  `Measure.boolBiasAdvantage μ = (μ.boolBias).toReal` etc. — semantics unchanged
  (same abs-diff values).
- **D2 (runtime generality for the SPR bounds): the old heval bundle's bind law has no
  successor on `ProbCompRuntime`.** Options weighed: (a) carry a new measure-form
  coherence bundle (bind law with Measurable f — measurability of keygen/state
  continuations becomes an explicit obligation per branch); (b) restate the two SPR
  theorems runtime-free in the upstream `KEMDEM/Measure` form
  (`[EvalDistSemantics (OracleComp spec)]`), with games interpreted as `𝒟[...]`, and
  keep the runtime-parameterized games as `def`s whose `probComp` instance is
  discharged by `probComp_evalDist`; (c) restrict the theorems to the canonical
  `probComp` runtime (loses the stated generality, docstrings must change).
  **Chosen: (b)** — runtime-free measure-level statements + a `probComp`
  specialization lemma; this matches upstream's own reduction pattern exactly and
  avoids inventing a measurability-heavy coherence class per branch. The
  `ProbCompRuntime` parameter stays on the games/advantage *definitions* (so call
  sites in `ANOAssumption`/`SPRTwoHop` keep compiling with `probComp`), and the two
  bound theorems get the runtime discharged by rewriting `probComp_evalDist` under
  `[OracleSpec.AnswerMeasure spec]` (the answer-measure instance gives `𝒟` ==
  runtime observation at probComp; verify `ProbCompRuntime.probComp` ↔ `𝒟[...]`
  rewriting direction at build time).
- **D3 (coin-branch toolkit):** new local lemmas in PqStealth namespace, mirroring
  `Measure.boolBias_bind_coin` + `boolDist_triangle` + `toReal` bridges; games' bind
  swaps mirror upstream `KEMDEM/Measure`'s `evalDist_bind_bind_swap` +
  `measurable_from_prod_countable_{left,right}` idiom (countability is on the coin
  component, never on key/state types).
- **D4 (fair-coin mass):** `probOutput_uniformSample` replacements are
  `SampleableType.evalDist_uniformSample` / `.evalDistEq_uniformSample`; coin
  singleton masses at `𝒟[($ᵗ Bool)]` come from the uniform measure instance
  (`evalDist_liftM_unifSpec_query` / direct instance mass), not the old
  `Fintype.card` route. Verify which form typechecks when writing.
- **D5 (prEvent replacements):** `prEvent_map`, `prEvent_le_one`, `prEvent_mono`
  survive (event laws now in `PolyFun.Control.Monad.Measure.Event` via
  `VCVio.EvalDist.ProbabilityNotation`); `probOutput_true_add_false` →
  instance-level: under a never-fail runtime observation the branch measure is a
  probability measure (`prFail_eq_zero` + `1 - prFail` univ mass at probComp);
  `probOutput_true_eq_one_of_imp` restated via `prEvent_mono` +
  `prEvent_eq_evalDist_singleton` form; `NeverFail` gone on `OracleComp`.

## Files touched by the rewrite (from codemod report, 16 files, ~148 hand sites)

KEMAnonymity 38, ROMUpToBad 27, Soundness 26, Games 9, DKSAPOracle 16,
BlindingROM 12, Axioms 8, DKsap/DKSAP 11, SPRTwoHop 38, MultiUnlink 24, plus ≤9 in
AnonymityFromSPR, ConstructionA, Controls, MultiRecipient, SharedSecretHiding.
`improvements.md` needed NO change (verifier was right; checker 0 problems).

## Consumer call-site compatibility (D1 consequence)

Every `X.boolDistAdvantage Y` / `.boolBiasAdvantage` site keeps working via dot
notation against `Measure.boolDistAdvantage`/`.boolBiasAdvantage` defined in
`PqStealth/Advantage.lean`. `Measure.boolDist_comm` etc. come from upstream
directly (`ToMathlib.MeasureTheory.Measure.Bool`), drop our `ProbComp.` dupes.
