# How this repo (lean/PqStealth) uses VCVio

Pointers into `lean/docs/` and `lean/PqStealth/` — the authoritative text lives there; this page
only says where to look and what is VCVio-specific. State as of 2026-08-19.

## The pin
| | |
|---|---|
| `lean/lakefile.toml` | `require VCVio … rev = "a5f474fd0e9a26266cc599d100267411690dfeb7"` (2026-07-15) |
| toolchain | `leanprover/lean4:v4.32.0` (upstream main is `v4.32.2`) |
| lakefile options | `autoImplicit = false`, `relaxedAutoImplicit = false`, `linter.missingDocs = true` (not `mathlibStandardSet` — see gotchas) |
| manifest | frozen (`lake-manifest.json`: mathlib `v4.32.0`, PolyFun, loom2, …) |
| local VCVio checkout | `lean/.lake/packages/VCVio/` — grep there for the API *we actually build against* |

**Bump procedure, cadence, sensitive files, axiom-guard behaviour:** `lean/docs/vcvio-pin.md`.
Never `lake update` casually; a bump drags mathlib + toolchain and rebuilds VCVio from source
(hours). Validate with `lake build` green and no warnings from `PqStealth/`.

## What we carry because upstream lacks it
`lean/docs/vcvio-upstream.md` — 11 items with proposed upstream changes and a filing order.
The ones that touch code:
- `PqStealth/MLKEM.lean:16-25` — `DecidableEq mlkem768Encoding.Encoded{THat,U,V}` via
  `inferInstanceAs (DecidableEq ByteArray)` (item 1; upstream tests have the same workaround in
  `LatticeCryptoTest/MLKEM/Helpers.lean`).
- `PqStealth/MLKEM.lean` — FIPS 203 `v` byte count taken from the standard because
  `byteEncode_size` is `private` (item 2); "the missing upstream lemma" `MLKEM.kem_ind_cpa_security`
  recorded verbatim (item 5).
- `PqStealth/SPRTwoHop.lean` — `instSampleableTypeRq/Tq`, `NeZero` for the modulus (item 3);
  `PqStealth.LearningWithErrors.advantage_eq_boolDistAdvantage` (item 4; scoped under `PqStealth` since 2026-08-19, like the four `PqStealth.ProbComp.boolDistAdvantage_*` helpers in `Games`/`MultiUnlink`, item 4b);
  seeded-on-`rho` MLWE hop shapes `keyHopProblem`/`ctHopProblem` (item 6).
- `PqStealth/KEMAnonymity.lean` — `KEM.AnonExp` / `anonAdvantage` (item 7; adopt upstream's if it lands).
- `PqStealth/ROMUpToBad.lean` — item 8 was **retracted 2026-08-19**: VCVio has the lemma
  (`ProgramLogic/Relational/ProgrammingOracle.lean`, `withProgramming`/`withCachingTrackingPolicy`
  + engine `tvDist_simulateQ_run_le_probEvent_output_bad`). We instantiate the engine for the
  `unifSpec + hashSpec` shape (uniform forwarding) there; `DKSAPOracle`/`BlindingROM` close their
  identical-until-bad steps with `boolDistAdvantage_run'_cacheQuery_run'_empty_le`. Residual asks:
  upstream's per-step agreement lemma is `private`; no `unifFwdImpl + so` bridge; symmetric half of
  the fundamental lemma (`Pr[flag|programmed] = Pr[flag|tracking]`) not stated.
- `PqStealth/Soundness.lean` — view-tag uniformity as hypothesis (item 10).

## Build-enforced guards
- `PqStealth/Axioms.lean`: 114 `#guard_msgs (whitespace := lax) in #print axioms …` blocks; any
  `sorry`/new axiom in a headline theorem's cone is a compile error. Don't edit the expected
  lists to make a bump pass without understanding the upstream change. Keep commands one-line
  (mathlib `style.commandStart` linter interaction).
- `PqStealth/Demo.lean`: 8 `#guard_msgs` around `#eval` (frozen numeric output; two run the
  instantiated `dksap` scheme through `OracleComp.runIO`).
- `PqStealth/Controls.lean`: "the definitions have teeth" — non-vacuity/controls.

## Round-4 idioms that worked (2026-08-19)
- `by_equiv` → `rvcstep` / `rvcstep swap left|right` / `rvcgen` closes sample-reorder game
  equalities in ~6 lines (`SPRTwoHop.KEM.evalDist_anonSetup_bind_anonBranch`). After a
  `rvcstep swap right`, plain `rvcstep` can fail with "unexpected bound variable" — use
  `refine relTriple_bind (relTriple_refl _) ?_; intro a b hab; cases hab` instead.
- `vcstep rw normalize` planner does not reach 5-draw permutations; `Reorder.evalDist_pull₃…₆`
  (generic "pull the k-th independent draw to the front", via `evalDist_bind_bind_swap` under
  `evalDist_bind_congr'`) + `evalDist_bind_congr'` descent + one `rw [mul_comm …]` does.
- Named assumptions beat game-gap definitions: DKSAP's `hashedDH` is now bounded by
  `DiffieHellman.ddhDistAdvantage` + `EntropySmoothing.advantage` of explicit reductions written
  in the *sampling order of VCVio's experiments* (`ddhExpRand`, `EntropySmoothing.realExp`) so
  each hop is a permutation; hash key `Fin 1` for an unkeyed hash (no `SampleableType Unit`).
- `$[0..n]` is `Fin (n+1)` — index a list of length `l` with `$[0..l-1]`.
- `probFailure_of_liftM_PMF` makes every `Pr[⊥ | mx] = 0` hypothesis on a `ProbComp` vacuous.
- Two-phase adversaries carry a `State` (`UnlinkChooseN … St`, `UnlinkGuessN … St`).
- `OracleComp.runIO` runs a `ProbComp` in `IO` for `#eval` demos (`Demo.lean`).

## Proof-style policy in our tree
- `simp only [...]` with explicit lemma lists; no bare `simp` (issue #18) — upstream renames fail
  by name. Exposed VCVio-internal names: `probOutput_bind_const`, `probFailure_of_liftM_PMF`,
  `probOutput_map_const`, `bind_map_left`, `support_bind`, `probFailure_bind_eq_zero_iff`,
  `evalDist_bind_bind_swap`, `evalDist_bind_congr'`.
- Deepest reach into VCVio's monadic API: `PqStealth/SharedSecretHiding.lean`
  (`evalDist` normal-form proofs). If upstream reworks `evalDist`/bind normal form, start there.
- Reduction lemmas naming VCVio hypotheses: `probOutput_bind_bijective_uniform_cross` (`DKSAP.lean`),
  `probOutput_bind_add_right_uniform` (`ConstructionA.lean`),
  `KEMScheme.PerfectlyCorrect ProbCompRuntime.probComp`, `SIS.matrixProblem` (`Ownership.lean`).
- No `omit … in` (deliberate); `explicitVarsOfIff` and `unusedSectionVars` findings are known
  and intentionally not acted on (see `vcvio-pin.md`).
- Lean-language notes (abbrev vs def transparency, `#guard_msgs`, section/variable scoping):
  `lean/docs/lean-study-notes.md`.

## VCVio imports we use (grep targets when bumping)
`VCVio.CryptoFoundations.KeyEncapMech`, `VCVio.CryptoFoundations.SecExp`,
`VCVio.CryptoFoundations.HardnessAssumptions.DiffieHellman`,
`VCVio.OracleComp.QueryTracking.{QueryBound, RandomOracle.Basic, RandomOracle.DeferredSampling, RandomOracle.Simulation}`,
`LatticeCrypto.HardnessAssumptions.{LearningWithErrors, ShortIntegerSolution}`,
`LatticeCrypto.MLKEM.{Params, KEM, Concrete.Instance}`, `LatticeCrypto.MLDSA.{Params, Encoding, Concrete.Rounding}`,
`LatticeCrypto.Ring.Rounding`.
On upstream main `LatticeCrypto.MLKEM.Concrete.Instance` no longer exists (→ `Extern.MLKEM.Instance`,
which proof libraries may not import) — a bump past #496 needs a decision on where our ML-KEM-768
instantiation gets its `mlkem768Encoding`/`mlkem768Primitives` from.

## Design essays (read before changing statements)
`lean/docs/announcement-model.md` (announcement, `auxGen`, decomposition, construction A, controls),
`spr-two-hop.md` (KEM anonymity from SPR, ML-KEM instantiation, missing upstream lemma),
`msis-reshaping.md` (spend side as matrix-SIS), `dksap-asymmetry.md` (classical comparison),
`encodings.md` (byte-level formats; what VCVio doesn't supply), `improvements.md` (issue drafts).
Module reading order: `lean/README.md`.
