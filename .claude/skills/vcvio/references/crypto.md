# Crypto primitives, security experiments, reductions, cost

Condensed from VCVio `docs/agents/crypto.md`, `query-tracking.md`, `end-to-end-examples.md` @ main
`ea9916db` (2026-08-19), plus the KEM/LWE signatures checked at our pin `a5f474fd`.

## Algorithm structures (monad-parametric; pick the monad at the experiment boundary)

```lean
structure AsymmEncAlg (m) [Monad m] (M PK SK C : Type) where
  keygen : m (PK × SK); encrypt : PK → M → m C; decrypt : SK → C → m (Option M)
structure SymmEncAlg (m) [Monad m] (M K C : Type) where
  keygen : m K; encrypt : K → M → m C; decrypt : K → C → m (Option M)
structure SignatureAlg (m) [Monad m] (M PK SK S : Type) where
  keygen : m (PK × SK); sign (pk) (sk) (msg) : m S; verify (pk) (msg) (σ) : m Bool
structure KEMScheme (m) [Monad m] (K PK SK C : Type) where        -- VCVio/CryptoFoundations/KeyEncapMech.lean
  keygen : m (PK × SK); encaps : PK → m (C × K); decaps : SK → C → m (Option K)
structure CommitmentScheme (PP M C D : Type) where                  -- CommitmentScheme.lean
  setup : ProbComp PP; commit pp m : ProbComp (C × D); verify pp m c d : Bool
structure SigmaProtocol (Stmt Wit Commit PrvState Chal Resp) (rel : Stmt → Wit → Bool) where
  commit; respond; verify; sim; extract                             -- coerces to IdenSchemeWithAbort
structure IdenSchemeWithAbort … where respond : … → ProbComp (Option Resp)   -- ML-DSA, FS-with-aborts
structure GenerableRelation (X W) (r : X → W → Bool) where gen : ProbComp (X × W); gen_sound
```
Instantiate with `@[simps!] def myAlg : AsymmEncAlg ProbComp M PK SK C where …`.
Probability/failure semantics come from the experiment or `[SPMFSemantics m]`, not the structure.

KEM surface at the pin (`KeyEncapMech.lean`): `CorrectExp`, `PerfectlyCorrect (runtime :
ProbCompRuntime m)` (`Pr[= true | runtime.evalDist kem.CorrectExp] = 1`; runtime for `ProbComp` is
`ProbCompRuntime.probComp`, `VCVio/OracleComp/ProbCompLift.lean`), `IND_CPA_Adversary` (two-phase,
`[SampleableType K]`), `IND_CPA_Exp/Game/Advantage` (`IND_CPA_Advantage_eq_game_bias`),
`IND_CCA_oracleSpec/Adversary/Game/Advantage`, `IND_CPA_Adversary.toIND_CCA`. **No anonymity
(ANO-CPA/CCA) notion** — we define `PqStealth.KEM.AnonExp` ourselves (`vcvio-upstream.md` item 7).

## Security experiments and advantages (`VCVio/CryptoFoundations/SecExp.lean`)

`structure SecExp (m) [Monad m] extends SPMFSemantics m where main : m Unit`; `advantage = 1 - Pr[⊥]`
(failure-based — always 1 on `ProbComp`; use distinguishing/guessing games instead).
`BoundedAdversary spec α β` = `run`, `qb : ι → ℕ`, `qb_isQueryBound`, `activeOracles`.

| Function | Input | Measures |
|---|---|---|
| `ProbComp.guessAdvantage` | `ProbComp Unit` | `\|1/2 - Pr[= ()].toReal\|` |
| `ProbComp.boolBiasAdvantage` | `ProbComp Bool` | `\|Pr[true] - Pr[false]\|` |
| `ProbComp.distAdvantage` | two `ProbComp Unit` | `\|Pr[= ()\|p] - Pr[= ()\|q]\|` |
| `ProbComp.boolDistAdvantage` | two `ProbComp Bool` | `\|Pr[true\|p] - Pr[true\|q]\|` (also `SPMF.*`) |
All `ℝ` via `.toReal` (ENNReal subtraction truncates). Triangle: `boolDistAdvantage_triangle`.
Avoid `guard` in experiments — `return (b == b')` / `return decide (r x w)`.

## Hardness assumptions

DLog/CDH/DDH (`VCVio/CryptoFoundations/HardnessAssumptions/DiffieHellman.lean`): additive
notation `a • g`; `[Field F] [Fintype F] [DecidableEq F] [SampleableType F]`, `[AddCommGroup G]
[Module F G] [SampleableType G] [DecidableEq G]`, generator `g`. `DLogAdversary F G = G → G → ProbComp F`
/ `dlogExp g adv`; `CDHAdversary`, `cdhExp`; `DDHAdversary F G = G → G → G → G → ProbComp Bool` /
`ddhExp` (samples `$ᵗ Bool`, checks `b == b'`).

LWE/MLWE (`LatticeCrypto/HardnessAssumptions/LearningWithErrors.lean`):
```lean
structure Problem (Sample Secret Output : Type) where
  sampleChallenge : ProbComp Sample; sampleSecret : ProbComp Secret; sampleError : ProbComp Output
  noiseless : Secret → Sample → Output; sampleUniform : ProbComp Output
```
`distr`, `uniformDistr`, `Adversary`, `experiment`, `advantage`, `game0`/`game1`,
`SearchAdversary`/`searchExperiment`/`searchAdvantage`, `matrixProblem`, `zmodMatrixProblem`,
`moduleMatrixProblem`. Missing at the pin: `advantage = game0.boolDistAdvantage game1` bridge (we
declare it in `SPRTwoHop.lean`; `vcvio-upstream.md` item 4) and `SampleableType` on `Rq`/`Tq`
(item 3). SIS: `ShortIntegerSolution.lean` (`SIS.matrixProblem`).

## Building a reduction
1. Define the reduction adversary embedding the challenge (`fun g A B T => do …`).
2. Prove the probability identity/bound (`advantage ≤ …`).
3. Multi-query: hybrid argument (`HybridGame A k`, telescope `≤ q * step`); or reuse the generic
   one-time lift `VCVio/CryptoFoundations/AsymmEncAlg/INDCPA/GenericLift.lean`.
4. Stateful reductions: `QueryImpl spec (StateT MyState ProbComp)`.
Hypothesis bundles must be inhabitable (gotcha 14): ship a witness.

## Asymptotics (`VCVio/CryptoFoundations/Asymptotics/`)
`negligible f := SuperpolynomialDecay atTop (↑) f`; closure `negligible_add/const_mul/sum/of_le/pow_mul/polynomial_mul`.
`SecurityExp { advantage : ℕ → ℝ≥0∞ }`, `SecurityGame Adv { advantage : Adv → ℕ → ℝ≥0∞ }`;
`.secure`, `.secureAgainst isPPT`. Constructors `ofSecExp` (`1 - Pr[⊥]`), `ofDistGame`, `ofGuessGame`.
Lemmas `secureAgainst_of_reduction`, `…_of_poly_reduction`, `…_of_close`, `…_of_hybrid`.

## Cost / query tracking (`VCVio/OracleComp/QueryTracking/`)
Weighted-first: `QueryCost[ oa in runtime by costFn ] = / ≤ / ≥ w`, `Queries[ oa in runtime ] …`
(unit cost), `ExpectedQueryCost[ oa in runtime by costFn via val ]`, `ExpectedQueries[ … ]`.
Layers: `AddWriterT` pathwise cost (`Cost[oa] ≤ w`, `CostsAs`) in `WriterCost.lean` /
`ToMathlib/Control/WriterT.lean`; generic `HasQuery.Program` accounting in `QueryCost.lean`;
`CostModel.lean` is an `OracleComp` facade (`costDist`, `expectedCost`, `WorstCaseCostBound`,
`ExpectedCostBound`, `WorstCasePolyTime`, `ExpectedPolyTime`, Markov
`probEvent_cost_gt_le_expectedCost_div`); tail sums in
`ToMathlib/Probability/ProbabilityMassFunction/TailSums.lean`. Recipe: pathwise exact/bound first →
`UsesCostAs` if output-determined → expectation via bridges → tail-sum for stopping times.
Query bounds: `IsPerIndexQueryBound`, `IsTotalQueryBound`, `IsQueryBoundP` (`QueryBound.lean`).
Examples: `FiatShamir/Sigma.lean` (exact one query), `Fischlin.lean` (bounded), `FujisakiOkamoto/
{TTransform,UTransform}.lean`, `FiatShamir/WithAbort/{Cost,ExpectedCost}.lean` (stopping time).
Typeclass hygiene: localise `MonadLiftT _ SPMF`, `IsProbabilitySpec`, `LawfulMonad` etc. to the
smallest section; avoid wide sections + repeated `omit … in`.

## End-to-end examples (reading order)
- Schnorr EUF-CMA: `Examples/Schnorr/SigmaProtocol.lean` → `VCVio/CryptoFoundations/FiatShamir/Sigma.lean`
  → `FiatShamir/Sigma/Security.lean` (`euf_cma_to_nma`, `euf_nma_bound`, `euf_cma_bound`) →
  `ReplayFork.lean` / `FiatShamir/Sigma/Fork.lean` → `Examples/Schnorr/Signature.lean`
  (`Schnorr.signature_euf_cma`, Pointcheval–Stern bound). Seeded fork: `SeededFork.lean`.
- ROM commitment: `Examples/CommitmentScheme/{Common,Binding,Extractability}.lean`,
  `Hiding/Main.lean` (`hiding_bound_finite ≤ t/|S|`, identical-until-bad, birthday).
- OTP: `Examples/OneTimePad/Basic.lean` (`probOutput_map_injective`); UC: `Examples/OneTimePad/UC.lean`.
- ElGamal IND-CPA: `Examples/ElGamal/Basic.lean` (one-time DDH → `q * 2ε`).
