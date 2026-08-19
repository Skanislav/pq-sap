# OracleComp, SubSpec, QueryImpl, simulateQ

Condensed from VCVio `docs/agents/oracle-comp.md` @ main `ea9916db` (2026-08-19). The pinned copy
at `lean/.lake/packages/VCVio/docs/agents/oracle-comp.md` may differ in detail.

## OracleSpec

`def OracleSpec (ι : Type u) : Type _ := ι → Type v` — `spec t` is the response type at index `t`.
`spec.toPFunctor` / `OracleSpec.ofPFunctor` are `rfl`-inverse.

| Constructor | Notation | Example |
|---|---|---|
| singleton | `A →ₒ B` | `Bool →ₒ Fin 6` |
| empty | `[]ₒ` | |
| combine | `spec₁ + spec₂` | `unifSpec + (M →ₒ C)` |

Typeclasses for probability: `[spec.Fintype]`, `[spec.Inhabited]` (bundled, with uniform
semantics, by `[IsUniformSpec spec]`; `[IsProbabilitySpec spec]` for arbitrary per-query PMFs).

## OracleComp

`OracleComp spec : Type w → Type _ := PFunctor.FreeM spec.toPFunctor` (free monad).

| API | Purpose |
|---|---|
| `query t` | monadic query (`HasQuery.query`, exported; needs expected type) |
| `spec.query t` / `OracleSpec.query t` | primitive `OracleQuery spec (spec.Range t)` (for `liftM`, `OracleQuery.cont`, induction) |
| `OracleComp.inductionOn` | induction: `pure` + `query_bind` |
| `OracleComp.construct` | same, result in `Type*` |
| `isPure`, `totalQueries` | |

Lemmas: `bind_eq_pure_iff`, `pure_ne_query`.

Elimination pattern (never match on `PFunctor.FreeM.pure/roll`):
```lean
induction oa using OracleComp.inductionOn with
| pure x => ...
| query_bind t oa ih => ...   -- simp [simulateQ_bind, simulateQ_query, simulateQ_pure]
```

## SubSpec `spec ⊂ₒ superSpec`

```lean
class SubSpec (spec : OracleSpec ι) (superSpec : OracleSpec τ)
    extends MonadLift (OracleQuery spec) (OracleQuery superSpec) where
  onQuery    : spec.Domain → superSpec.Domain
  onResponse : (t : spec.Domain) → superSpec.Range (onQuery t) → spec.Range t
  liftM_eq_lift : ∀ {β} (q : OracleQuery spec β),
      monadLift q = ⟨onQuery q.input, q.cont ∘ onResponse q.input⟩ := by intros; rfl
```
`onQuery`/`onResponse` form a `PFunctor.Lens` (`h.toLens`); instances spell `monadLift` by
hand so lifted queries reduce under `isDefEq` (makes `probEvent_liftComp` fire).
`LawfulSubSpec` = every `onResponse t` bijective = lens `IsCartesian`
(`LawfulSubSpec.toLens_isCartesian`); this is what pushes uniform distributions through the lift
(`LawfulSubSpec.evalDist_liftM_query`). Weaker than `Lens.Equiv` on purpose (embeddings
`spec₁ ⊂ₒ spec₁ + spec₂` with `onQuery = Sum.inl` must be allowed).

| Lemma | Needs | Statement |
|---|---|---|
| `liftComp_pure`, `liftComp_bind` | `[MonadLift (OracleQuery spec) (OracleQuery superSpec)]` | structural |
| `evalDist_liftComp`, `probOutput_liftComp`, `probEvent_liftComp` | `[spec ⊂ₒ superSpec] [LawfulSubSpec …]` + uniform specs both sides | `Pr[…\| liftComp mx superSpec] = Pr[…\| mx]` |

Universe hygiene: `{ι : Type*}` not `{ι : Type u}`; keep `α β : Type`.

## QueryImpl and simulateQ

`@[reducible] def QueryImpl (spec) (m) := (x : spec.Domain) → m (spec.Range x)` ≡
`PFunctor.Handler m spec.toPFunctor` (`QueryImpl.eq_handler`).

| Constructor | Use |
|---|---|
| `QueryImpl.id spec` / `QueryImpl.id' spec` | identity (raw / into `OracleComp`) |
| `QueryImpl.ofLift spec m` | from `MonadLift` |
| `QueryImpl.ofFn f` | from pure `f : (t : Domain) → Range t` |
| `impl.liftTarget n` | lift target monad via `MonadLiftT` |
| `so' ∘ₛ so` (`QueryImpl.compose`) | `simulateQ (so' ∘ₛ so) oa = simulateQ so' (simulateQ so oa)` |

`simulateQ [Monad r] (impl : QueryImpl spec r) : OracleComp spec α → r α` — the unique monad
morphism agreeing with `impl` on queries (`PFunctor.FreeM.mapM`). Target `r` effectful
(`StateT`, `WriterT`, `OptionT`, `OracleComp spec'`, `IO`) → effect handler; target semantic
(`PMF`, `SPMF`, `Set`, `Finset`) → denotation. Both are the same primitive.

`@[simp, grind =]`: `simulateQ_pure`, `simulateQ_bind`, `simulateQ_query`
(`simulateQ impl (liftM q) = q.cont <$> impl q.input`), `simulateQ_map`, `simulateQ_id'`.
Routing layer also in grind set: `QueryImpl.add_apply_inl/inr`, `simulateQ_add_liftComp_left/right`.

### evalDist IS simulateQ
`support` ≡ `simulateQ` into `SetM` (queries ↦ `Set.univ`), always available.
`evalDist : OracleComp spec α → SPMF α` ≡ `simulateQ IsProbabilitySpec.toPMF` lifted to `SPMF`
(`instMonadLiftTPMF`), under `[IsProbabilitySpec spec]`; `[IsUniformSpec spec]` says `toPMF` is
`PMF.uniformOfFintype`. Bridge `support ↔ SPMF.support 𝒟[…]` is `EvalDistCompatible` (needs
`IsUniformSpec`).

Syntactic alternative staying in `ProbComp`: `uniformSampleImpl [∀ i, SampleableType (spec.Range i)]
: QueryImpl spec ProbComp := fun t => $ᵗ spec.Range t`; preservation is a **lemma**
`uniformSampleImpl.evalDist_simulateQ` (+ `probOutput_simulateQ`, `probEvent_simulateQ`,
`support_simulateQ`, `finSupport_simulateQ`) in `VCVio/OracleComp/Constructions/SampleableType.lean`.

## Wrapping a QueryImpl: `preInsert` / `postInsert`

`VCVio/OracleComp/SimSemantics/QueryImpl/Constructions.lean`:
```lean
def preInsert  (so : QueryImpl spec m) (nx : spec.Domain → n α) : QueryImpl spec n
def postInsert (so : QueryImpl spec m) (nx : (t : spec.Domain) → spec.Range t → n α) : QueryImpl spec n
```
| | `preInsert` | `postInsert` |
|---|---|---|
| side effect runs | before handler | after handler |
| sees response | no | yes |
| handler fails | effect still happens | effect skipped |

Generic theory you get for free: `simulateQ_preInsert.induct`/`simulateQ_postInsert.induct`,
`proj_simulateQ_preInsert/postInsert`, `probFailure_proj_simulateQ_*`,
`NeverFail_proj_simulateQ_*_iff`, `evalDist_proj_simulateQ_*`, `probOutput_proj_simulateQ_*`,
`support_proj_simulateQ_*`, `finSupport_proj_simulateQ_*`, and
`isTotalQueryBound_simulateQ_preInsert/postInsert` (+ `IsQueryBoundP`) in `QueryTracking/QueryBound.lean`.
Projection `proj` is typically `Prod.fst <$> WriterT.run ·` or `(·.run s) >>= …`.

Existing wrappers (use directly):

| Wrapper | File | Built on |
|---|---|---|
| `withTraceBefore` / `withTrace` | `QueryTracking/Tracing.lean` | `preInsert` / `postInsert` |
| `withTraceAppendBefore` / `withTraceAppend` | `QueryTracking/Tracing.lean` | same, `Append` flavour |
| `withCost`, `withCounting` | `QueryTracking/CountingOracle.lean` | `withTraceBefore` |
| `withAddCost`, `withUnitCost` | `QueryTracking/WriterCost.lean` | `withCost` |
| `withLogging` | `QueryTracking/LoggingOracle.lean` | `withTraceAppend` |
| `appendInputLog` | `QueryTracking/LoggingOracle.lean` | `preInsert` |

**Not** the right shape when control flow depends on state or the would-be response — write a
custom `QueryImpl`: `withCaching` (`CachingOracle.lean`), `withPregen` (`SeededOracle.lean`),
`enforceOracle` (`Enforcement.lean`: per-index budget in `StateT (ι → ℕ)`, over-budget returns
`default`; key result `enforceOracle.fst_map_run_simulateQ`), game-state/bad-flag handlers.

Random oracles: `OracleSpec.randomOracle` (`VCVio/OracleComp/QueryTracking/RandomOracle/Basic.lean`,
lazily sampled cache), `DeferredSampling.lean`, `Simulation.lean`. At the pin these are **not**
reachable from VCVio's root import (our `vcvio-upstream.md` item 9) — import them explicitly.

Stateful pattern:
```lean
def myImpl : QueryImpl spec (StateT MyState ProbComp) := fun t => do
  let st ← get; …; set st'; return resp
-- run: (simulateQ myImpl comp).run s₀
```
