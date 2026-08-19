# Program logic tactics and proof workflows

Condensed from VCVio `docs/agents/program-logic.md` + `proof-workflows.md` @ main `ea9916db`
(2026-08-19). Import `VCVio.ProgramLogic.Tactics` (not just `.Notation`). Walkthroughs:
`Examples/ProgramLogic/{UnaryStep,RelationalStep,RelationalDerived,ProofMode}.lean`,
`VCVio/ProgramLogic/Relational/Examples.lean`.

## Notation (`VCVio/ProgramLogic/NotationCore.lean`, `Notation.lean`)

| Notation | Meaning |
|---|---|
| `𝟙⟦P⟧` | indicator `propInd P` |
| `⌜P⌝` | pure proposition assertion |
| `wp⟦c⟧` | quantitative WP |
| `⦃P⦄ c ⦃Q⦄` | unary Hoare triple (`Std.Do'.Triple`) |
| `g₁ ≡ₚ g₂` | `GameEquiv` |
| `⟪c₁ ~ c₂ \| R⟫` | pRHL coupling `RelTriple c₁ c₂ R` |
| `⟪c₁ ≈[ε] c₂ \| R⟫` | `ApproxRelTriple ε …` |
| `⦃f⦄ c₁ ≈ₑ c₂ ⦃g⦄` | quantitative relational triple (eRHL) |

## Proof-mode entry

| Tactic | Goal | Does |
|---|---|---|
| `by_equiv` | `g₁ ≡ₚ g₂` / `evalDist g₁ = evalDist g₂` | enter `RelTriple` coupling mode |
| `game_trans g₂` | `g₁ ≡ₚ g₃` | split into `g₁ ≡ₚ g₂`, `g₂ ≡ₚ g₃` |
| `by_dist [ε]` | `AdvBound game ε` | TV-distance mode (`ε` pins the contribution) |
| `by_upto bad` | identical-until-bad TV goals | applies `simulateQ` up-to-bad bound |
| `by_hoare` | `Pr[p \| oa] = …` | legacy; prefer `vcstep` |

## Unary / quantitative (`vcstep`, `vcgen`)

| Tactic | Does |
|---|---|
| `vcgen` | exhaustive decomposition of `Triple`/probability goals (spec-aware, auto loop invariants, support/indicator leaf closure) |
| `vcstep` | one step: probability lowering → bind → ite → match → loop → leaf |
| `vcstep?` / `vcgen?` | same + `Try this` script (surfaces `as ⟨…⟩`, `using cut`, `inv I`, `with thm`) |
| `vcstep using cut` | explicit intermediate postcondition for a bind |
| `vcstep with thm` | force a specific unary theorem/hypothesis |
| `vcstep as ⟨x, hx⟩` | name binders |
| `vcstep inv I` / `vcgen inv I` | loop invariant for `replicate`/`foldlM`/`mapM` |
| `vcstep rw` | one top-level bind-swap rewrite on `Pr[…] = Pr[…]` |
| `vcstep rw under n` | swap under `n` shared outer binds |
| `vcstep rw normalize` | run the bounded planner explicitly |
| `vcstep rw congr` / `congr'` | reduce `Pr[…\| mx >>= f₁] = Pr[…\| mx >>= f₂]` pointwise, with / without `hx : x ∈ support mx`; `as ⟨x, y⟩` peels several |
| `exp_norm` | normalise `propInd`/`wp` arithmetic |
| `handler_step` | one `simp only [handler_nf, handler_simp]` pass on handler-heavy goals |

Probability goals handled automatically: `Pr[p|oa] = 1` → `Triple 1 oa ⌜p⌝`; `r ≤ Pr[…]` →
`Triple r oa …`; `Pr[…] = Pr[…]` → normalise then swap/congruence plan; others → raw `wp`.
`vcstep` may *close* a probability equality — use `vcstep rw` when you wanted a rewrite.
Support cut: if no spec for `oa`, `vcgen` tries `fun x => ⌜x ∈ support oa⌝`.
Registries: `@[vcspec]` (unary `Triple`/raw `wp`, relational `RelTriple`/`RelWP`/quantitative),
`@[wpStep]` (`wp comp post = …`), `@[vcspec (prio := 200)]`. Budget:
`set_option vcvio.vcgen.maxPasses 128 in`; trace: `set_option vcvio.vcgen.traceSteps true in`.
Manual swap pattern: `simp only [← probEvent_eq_eq_probOutput]; rw [probEvent_bind_bind_swap]; simp only [probEvent_eq_eq_probOutput]`.

## Relational (pRHL) tactics

| Tactic | Does |
|---|---|
| `rvcstep` | lower if needed, apply one relational step |
| `rvcstep using R` | bind cut relation |
| `rvcstep using f` | coupling bijection on sample/query (uses `relTriple_uniformSample_bij` / `relTriple_query_bij`, leaves `Function.Bijective f`) |
| `rvcstep using Rin` / `using R_state` | `mapM`/`foldlM` input relation / `simulateQ` state invariant |
| `rvcstep with thm`, `rvcstep as ⟨a₁, a₂, h⟩`, `rvcstep?` | |
| `rvcstep left/right` | one-sided bind step on raw `rwp`/folded `RelTriple` |
| `rvcstep sym`, `rvcstep upto R`, `rvcstep trans mid`, `rvcstep swap left/right [using R]` | explicit strategies (EqRel transport) |
| `rvcgen [using t \| using [t₁,…] \| with thm]` | exhaustive; `rvcgen!` adds `rvcfinish`; `rvcgen?` prints script |
| `rel_conseq [with R]`, `rel_inline foo`, `rel_dist` | weaken post / unfold / back to `evalDist` equality |

Plain `rvcstep`/`rvcgen` auto-consume a *unique* viable local hint; 0 or ≥2 → falls back to
`EqRel` — disambiguate with `using`. Bind-normalisation pre-pass:
`simp only [bind_assoc, pure_bind, bind_pure_comp, Functor.map_map, map_pure]`.

RelTriple rules: `relTriple_pure_pure`, `relTriple_bind`, `relTriple_refl`,
`relTriple_eqRel_of_eq`, `relTriple_eqRel_of_evalDist_eq`, `relTriple_query`,
`relTriple_query_bij`, `relTriple_uniformSample_bij`, `relTriple_if`, `relTriple_post_mono`,
`evalDist_eq_of_relTriple_eqRel`.

Relational simulateQ: `relTriple_simulateQ_run` (state invariant `R_state`);
unary-to-relational lift `relTriple_simulateQ_run_of_triples` and siblings
(`…_run'_of_triples`, `…_of_impl_eq_triple`, `…_writerT[']`, `…_writerT_of_impl_eq`,
`probOutput_simulateQ_run_writerT_eq_of_impl_eq`, `evalDist_simulateQ_run_writerT_eq_of_impl_eq`,
`relTriple_run_of_triple`, `relTriple_run_writerT_of_triple[_monoid]`,
`support_preservesInv_of_triple`, `writerPreservesInv_of_triple`) in
`VCVio/ProgramLogic/Relational/HandlerFromUnary.lean`.

Handler `@[spec]` catalogue (`Unary/HandlerSpecs.lean`, for `mvcgen`): `cachingOracle_triple`
(`cache₀ ≤ cache' ∧ cache' t = some v`), `seededOracle_triple`, `loggingOracle_triple`
(`log' = log₀ ++ [⟨t, v⟩]`), `countingOracle_triple`, `costOracle_triple`. Invariant
preservation: `QueryImpl.PreservesInv`, `WriterPreservesInv(.of_mul_closed)`,
`simulateQ_run_preservesInv`, `simulateQ_triple_preserves_invariant` (`SimSemantics/PreservesInv.lean`).

## Identical until bad
```lean
tvDist_simulateQ_le_probEvent_bad :
  (¬bad s₀) → (∀ t s, ¬bad s → (impl₁ t).run s = (impl₂ t).run s) → (bad monotone) →
  tvDist ((simulateQ impl₁ oa).run' s₀) ((simulateQ impl₂ oa).run' s₀)
    ≤ Pr[bad ∘ Prod.snd | (simulateQ impl₁ oa).run s₀].toReal
```
(`StateSeparating/IdenticalUntilBad.lean` compares two *handlers* with an explicit bad flag; a
game-body / lazy-RO switching lemma does not exist upstream — our `vcvio-upstream.md` item 8.)
Worked ROM example with caching, logging, birthday bound: `Examples/CommitmentScheme.lean`
(`tvDist_simulateQ_le_probEvent_bad_dist`, `probEvent_cacheCollision_le_birthday_total_tight`).

## eRHL design note
`⦃f⦄ c₁ ≈ₑ c₂ ⦃g⦄` = `pre ≤ eRelWP oa ob post`; `ApproxRelTriple ε` = `1 - ε ≤ eRelWP … (indicator R)`;
pRHL is `ε = 0`. Quantitative foundation first, pRHL/apRHL as special cases (paper: *A Quantitative
Probabilistic Relational Hoare Logic*, ERHL25). Don't add a pRHL-only layer.

## Game-hopping recipe
1. State `advantage (myExp A) ≤ q * ε(reduction A)`.
2. Define hybrids `hybridGame A k`.
3. `game_trans (hybridGame A 1)` … telescope.
4. Per hop, reduction adversary embedding the challenge at position `k`.
5. Prove real ↔ hybrid k, random ↔ hybrid k+1.
Generic one-time → q-query lift for IND-CPA: `VCVio/CryptoFoundations/AsymmEncAlg/INDCPA/GenericLift.lean`
(`AsymmEncAlg.IND_CPA_advantage_toReal_le_q_mul_of_oneTime_signedAdvantageReal_bound`, used by ElGamal).
Asymptotic: `secureAgainst_of_reduction`, `…_of_poly_reduction`, `…_of_close`, `…_of_hybrid`
(`VCVio/CryptoFoundations/Asymptotics/Security.lean`).

## `monad_norm`
Prefer `simp [monad_norm]` (Mathlib set: `pure_bind, bind_assoc, bind_pure, map_pure, pure_seq,
seq_assoc, seq_eq_bind_map, map_eq_bind_pure_comp`) over hand lists. Exceptions: proofs that must
keep `<$>` form (StateT-heavy, `ReplayFork.lean`), tuned two-pass `simp only` chains, `rw` lists,
low-level `ToMathlib/Control/Monad/` files without `Mathlib.Tactic.Attr.Register`. Leave a
one-line comment when you keep a manual list.

## Parallel work
One `git worktree` per task; same-file follow-ups sequential; warm-start `.lake/build` from a
built donor (gotcha 21).
