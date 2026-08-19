# Probability reasoning (EvalDist, ProbComp)

Condensed from VCVio `docs/agents/probability.md` + `notation.md` @ main `ea9916db` (2026-08-19).

## Definitions and notation (`VCVio/EvalDist/Defs/Basic.lean`, `Support.lean`)

| Def | Type | Notation |
|---|---|---|
| `evalDist mx` | `SPMF α` | `𝒟[mx]` |
| `probOutput mx x` | `ℝ≥0∞` | `Pr[= x \| mx]` |
| `probEvent mx p` | `ℝ≥0∞` | `Pr[p \| mx]`, `Pr[cond \| var ← src]` |
| `probFailure mx` | `ℝ≥0∞` | `Pr[⊥ \| mx]` |
| `support mx` / `finSupport mx` | `Set α` / `Finset α` | |

Dead: `[= x | c]` (→ `Pr[= x | c]`), `++ₒ` (→ `+`).

## Sampling (`ProbComp α = OracleComp unifSpec α`)

| Notation | Function | Needs |
|---|---|---|
| `$ᵗ T` | `uniformSample` | `[SampleableType T]` |
| `$[0..n]` | `uniformFin n : ProbComp (Fin (n+1))` | |
| `$[n⋯m]` | `uniformRange n m` | `n < m` |
| `$ xs` | `uniformSelect : OptionT ProbComp β` (List/Finset/Array, may fail) | `[HasUniformSelect]` |
| `$! xs` | `uniformSelect!` (`Vector α (n+1)`, never fails) | `[HasUniformSelect!]` |

`SampleableType`: `Bool`, `Fin n` (`[NeZero n]`), `ZMod n`, `BitVec n`, `α × β`, `Vector α n`,
`Fin n → α`, `Matrix`. Build others with `SampleableType.ofFintype` / `ofEquiv` (beware
`Fintype.ofFinite` closures — gotcha 8).

## Simp-lemma catalog

Pure: `evalDist_pure`, `probOutput_pure` (`if x = y then 1 else 0`), `probOutput_pure_self`,
`probEvent_pure`, `probFailure_pure`, `support_pure`.

Bind: `evalDist_bind`, `probOutput_bind_eq_tsum` (`∑' x, Pr[= x|mx] * Pr[= y|my x]`, **grind-only**),
`probEvent_bind_eq_tsum`, `probFailure_bind_eq_add_tsum`, `support_bind`, `finSupport_bind`.
Constant continuation: `probOutput_bind_const` / `probEvent_bind_const`
(`(1 - Pr[⊥|mx]) * Pr[…|my]`).

Map: `evalDist_map`, `probEvent_map` (`Pr[q ∘ f | mx]`), `probOutput_map` (grind), `probFailure_map`,
`support_map`, `probOutput_map_injective`; non-injective: `probOutput_map_eq_tsum_subtype`,
`probOutput_map_eq_sum_finSupport_ite`.

Swapping/congruence: `probEvent_bind_bind_swap`, `evalDist_bind_bind_swap`,
`probOutput_bind_congr`, `probEvent_bind_congr`, `evalDist_bind_congr'`.

Zero/membership: `probOutput_eq_zero_of_not_mem_support`, `probOutput_bind_eq_tsum_subtype`,
`probOutput_bind_eq_sum_finSupport` (needs `[DecidableEq α] [HasEvalFinset m]`),
`probOutput_eq_zero_iff`, `probOutput_pos_iff`, `mem_finSupport_iff`.

Product: `probOutput_seq_map_prod_mk_eq_mul` (`@[simp high, grind norm]`, applicative spelling only).

Failure-capable monads (`OptionT`, `ExceptT`): `Pr[= y | mx *> my] = (1 - Pr[⊥|mx]) * Pr[= y|my]`;
`probFailure_orElse` etc. for `<|>`.

## Which lemma? (decision tree)

1. `Pr[= y | mx >>= my] = …` → `probOutput_bind_eq_tsum` (or `vcstep`)
2. `Pr[p | mx >>= my] = …` → `probEvent_bind_eq_tsum`
3. swap two binds → `vcstep` (closes) / `vcstep rw [under n]` (rewrite and continue)
4. `Pr[= y | f <$> mx]` → injective: `probOutput_map_injective`; else `…_eq_tsum_subtype`
5. restrict sum to support → `probOutput_bind_eq_tsum_subtype` / `…_sum_finSupport`
6. continuation ignores result → `probOutput_bind_const` / `probEvent_bind_const`
7. same distribution → show `evalDist oa = evalDist ob`, or `relTriple_eqRel_of_evalDist_eq` / `by_equiv`

## grind vs simp

- `simp` computes (`Pr[= x | $ᵗ T]`, uniform products, `Fintype.card` arithmetic). `grind` won't.
- `grind` for symbolic/membership/directed-iff (`x ∈ support …`, equiprobability,
  `Pr[= x|mx] = 0 ↔ x ∉ support mx`).
- Simp-only by design (grind saturation hub `probEvent_eq_one_iff` family):
  `probEvent_eq_zero_iff(')`, `probEvent_ne_zero_iff(')`, `probEvent_eq_one_iff(')`,
  `one_eq_probEvent_iff(')`, `probOutput_eq_one_iff`, `one_eq_probOutput_iff`,
  `probFailure_eq_one_iff`; `mem_support_bind_iff` untagged. Opt in: `grind [probEvent_eq_zero_iff]`.
- Grind-friendly `Nonempty` companions: `probFailure_eq_one_iff_not_nonempty`,
  `probEvent_eq_zero_iff_not_nonempty`, `support_uniformSample_nonempty`.
- Monad laws `bind_pure`, `bind_assoc`, `map_pure` are `@[grind =]` (`pure_bind` from core) so grind
  normalises structure first. `bind_pure_comp`/`map_eq_bind` deliberately not.
- Structural extras in default grind set: `OracleComp.replicate` unfolds, `Functor.map_map`,
  `probEvent_False/false`, `simulateQ` routing, `withBadFlag`/`withBadUpdate`/`flattenStateT`.
- Downstream escape: `grind [-bind_pure]`, `grind only [...]`, `attribute [-grind] bind_pure`, `grind?`.
- Gates/benchmarks upstream: `VCVioTest/{ProbabilityTactics,MonadProbability,LongChainPrograms,GrindFailFast}.lean`.

## Common mistakes

1. Missing `[IsProbabilitySpec spec]` / `[IsUniformSpec spec]` (symptom: can't synthesize
   `MonadLiftT (OracleComp spec) SPMF`, `EvalDistCompatible`).
2. Carrying both instances — ambiguous; `IsUniformSpec extends IsProbabilitySpec`.
3. `support` where `finSupport` is needed.
4. Forgetting `probOutput_eq_zero_of_not_mem_support` when restricting sums.
5. `evalDist (query t)` — ascribe `(query t : OracleComp spec _)`.
