---
name: vcvio
description: Use when reading, writing, or proving anything against the VCVio Lean framework (OracleComp/ProbComp, security games, reductions, LatticeCrypto ML-KEM/ML-DSA) — including all work in lean/PqStealth/ and any upstream VCVio PR. Covers the mental model, probability/tactic lemma choice, gotchas, and VCVio's own contribution rules.
---

# VCVio — usage and design

Condensed from VCVio's own agent guide (`AGENTS.md` + `docs/agents/*.md`, upstream `main`
`ea9916db`, read 2026-08-19). The pinned copy we build against lives at
`lean/.lake/packages/VCVio/` (pin `a5f474fd`, 2026-07-15, Lean 4.32.0) and its
`docs/agents/` may lag what is written here — when a name doesn't resolve, grep the pin.

Open the `references/` file for the area you are touching (table at the end). This page is the
part you should have in your head before writing a line.

## 1. Mental model (read once)

- `OracleSpec ι := ι → Type` — response type per query index. Build with `A →ₒ B`, `[]ₒ`,
  `spec₁ + spec₂` (`++ₒ` is dead).
- `OracleComp spec α` — the **free monad** on `spec.toPFunctor` (PolyFun `PFunctor.FreeM`).
  `ProbComp α := OracleComp unifSpec α` (only uniform sampling). `query t` is the monadic
  `HasQuery.query`; `spec.query t` is the primitive `OracleQuery`.
- `QueryImpl spec m := (t : spec.Domain) → m (spec.Range t)` — an effect handler.
  `simulateQ impl : OracleComp spec α → m α` is the **unique** monad morphism extending it. There
  is no other interpreter: running, caching, logging, counting, lazy RO sampling, *and* the
  semantics are all `simulateQ` with a different target monad.
- `support` ≡ `simulateQ` into `SetM`; `evalDist`/`Pr[= x | mx]`/`Pr[p | mx]`/`Pr[⊥ | mx]` ≡
  `simulateQ` into `PMF` (definitional, `rfl`) — needs `[IsProbabilitySpec spec]`; uniform
  response semantics + cardinality + `support ↔ Pr ≠ 0` need `[IsUniformSpec spec]`.
- Crypto surfaces are monad-parametric structures (`AsymmEncAlg m …`, `SymmEncAlg`,
  `SignatureAlg`, `KEMScheme`, `SigmaProtocol`, …); experiments are `ProbComp Bool`/`Unit`;
  advantages are real numbers via `.toReal` (`boolDistAdvantage`, `guessAdvantage`,
  `distAdvantage`, `SecExp.advantage = 1 - Pr[⊥]`).

## 2. Before you write a proof — pick the tool

| Goal shape | Reach for |
|---|---|
| `g₁ ≡ₚ g₂` / `evalDist g₁ = evalDist g₂` | `by_equiv` → `rvcstep [using R \| f]` / `rvcgen` (`rvcgen!` adds consequence search); `rvcstep?` prints the script |
| multi-hop `g₁ ≡ₚ gₙ` | `game_trans g₂` repeatedly |
| `advantage ≤ ε` / TV distance | `by_dist [ε]`; identical-until-bad: `tvDist_simulateQ_le_probEvent_bad` / `by_upto bad` |
| `Pr[= x \| mx >>= f] = …` | `vcstep` (may close it); `vcstep rw [under n \| congr \| congr']` for a controlled step; manual: `rw [probOutput_bind_eq_tsum]` |
| `Pr[p \| …] = 1`, `r ≤ Pr[…]` | `vcgen` (lowers to `Triple`, auto loop invariants; `vcstep inv I`, `vcstep using cut`) |
| swap two independent samples | `vcstep` / `vcstep rw`; lemma is `probEvent_bind_bind_swap` (bridge `probEvent_eq_eq_probOutput`) |
| wrapper on a `QueryImpl` (trace/cost/log) | build on `preInsert`/`postInsert` (or `withTraceBefore`/`withCost`/`withLogging`) and use the `proj_simulateQ_*` / `probOutput_proj_simulateQ_*` bridges — don't re-induct |
| handler goal stuck behind combinators | `handler_step`, then continue |
| monadic normalisation | `simp [monad_norm]` by default; explicit `bind_assoc, pure_bind, …` only when the proof needs `<$>` form kept |

**`simp` vs `grind`.** `simp` computes concrete probabilities (`Pr[= x | $ᵗ T]`, products).
`grind` does symbolic/membership/iff goals. `probOutput_bind_eq_tsum` is `@[grind =]` **not**
`@[simp]`. Support-characterisation iffs (`probEvent_eq_zero_iff`, `probEvent_eq_one_iff`,
`probOutput_eq_one_iff`, `probFailure_eq_one_iff`, `mem_support_bind_iff`) are simp-only on
purpose (grind saturation) — opt in with `grind [probEvent_eq_zero_iff]`; use the `Nonempty`
companions (`probFailure_eq_one_iff_not_nonempty`, `probEvent_eq_zero_iff_not_nonempty`) when
grind must reason about failure. Escape hatches downstream: `grind [-lemma]`, `grind only […]`,
`attribute [-grind] lemma`, `grind?`.

**Our tree's policy (PqStealth):** `simp only [...]` with explicit lists, no bare `simp`, so an
upstream rename fails by name, not by silently changing a proof.

## 3. Instance checklist (the #1 source of "failed to synthesize")

- `Pr[…]`/`evalDist` on `OracleComp spec` → `[IsProbabilitySpec spec]`.
- uniform facts, `PMF.uniformOfFintype`, `support ↔ Pr ≠ 0`, `EvalDistCompatible` →
  `[IsUniformSpec spec]` (bundles `spec.Fintype`, `spec.Inhabited`, `IsProbabilitySpec`). Have
  `[spec.Fintype] [spec.Inhabited]` only? `IsUniformSpec.ofFintypeInhabited spec` as a local instance.
- **Never carry both** `[IsProbabilitySpec]` and `[IsUniformSpec]` — ambiguous search.
- `$ᵗ T` needs `[SampleableType T]` (`Bool`, `Fin n` with `[NeZero n]`, `ZMod n`, `BitVec n`,
  products, `Vector α n`, `Fin n → α`, `Matrix`). `ByteArray`/infinite types are *not* sampleable.
- `finSupport`/`probOutput_bind_eq_sum_finSupport` need `[DecidableEq α]` + `[HasEvalFinset m]`.
- Generic ML-KEM API (`KEM.lean`, `KPKE.lean`) demands `[DecidableEq encoding.Encoded{THat,U,V}]`;
  the concrete encodings don't provide them at the pin (our `PqStealth/MLKEM.lean:16-25` does).

## 4. Top gotchas (full list: `references/gotchas.md`)

1. Missing `IsProbabilitySpec`/`IsUniformSpec` (above).
2. `autoImplicit = false` package-wide (VCVio and ours) — never re-set per file.
3. `evalDist` IS `simulateQ` — `evalDist_eq_simulateQ` is `rfl`; `uniformSampleImpl` preservation is a *lemma* (`uniformSampleImpl.evalDist_simulateQ`).
4. `++ₒ` → `+`; `[= x | c]` → `Pr[= x | c]`; commented-out code is legacy — follow `Examples/OneTimePad/Basic.lean`.
5. Core types are reducible PFunctor wrappers: eliminate with `OracleComp.inductionOn` (`| pure x | query_bind t oa ih`), state lemmas in prefix form (dot-notation on `oa >>= ob` fails), never `attribute [local reducible]` something instance keys mention, `OracleSpec.toPFunctor_add` is deliberately not simp.
6. `query t` needs an expected monad (`(query t : OracleComp spec _)`); `spec.query t` for `liftM`/`OracleQuery.cont`.
7. Lean ≥ 4.29 `do` desugaring can dodge `pure_bind`/`bind_assoc`; upstream's doc points at `LawfulMonad.do_bind_assoc` etc. in `ToMathlib.Control.Lawful.Basic` — **that file/lemmas exist neither at our pin nor on main (checked 2026-08-19)**; grep before relying, fall back to `simp [monad_norm]` / manual `show`.
8. Universe errors around `SubSpec`: `{ι : Type*}`, keep `α β : Type`.
9. `Fintype.ofFinite`-backed samplers are whnf-hostile — anonymous constructor, or abstract + pin with an equality hypothesis.
10. Hypothesis satisfiability is *your* obligation: `#print axioms` can't see a vacuous theorem; ship an inhabitance witness for new hypothesis bundles (relation-pinning pairs, cardinality mismatches).
11. `lake env lean`/LSP can see stale oleans — `lake build <target>` before believing a phantom error.
12. Preserve broken proof attempts with `stop`; delete dead commented code.

## 5. Repo map and layering (VCVio)

```
ToMathlib → Prelude → EvalDist/Defs → OracleComp core → EvalDist bridge
  → {SimSemantics, QueryTracking, Constructions, Coercions, ProbComp}
  → {ProgramLogic, CryptoFoundations, CryptoFoundations/Asymptotics} → Examples
LatticeCrypto: {Ring/*, DiscreteGaussian} → HardnessAssumptions → {MLDSA, MLKEM, Falcon}
  → Concrete/ → Extern/ (FFI, native stubs when third_party absent) → LatticeCryptoTest/
```
Hard rules: `EvalDist/` never imports `OracleComp/`; **no proof library may `import Extern.…`**
(`VCVio/`, `ToMathlib/`, `LatticeCrypto/`, `HashSig/`, `Examples/`, `VCVioWidgets/`, `Interop/`)
— enforced by `scripts/check-extern-isolation.sh`; nothing in core imports `Interop.…`
(`scripts/check-interop-isolation.sh`). Scheme code in `LatticeCrypto/` may import
`VCVio/CryptoFoundations`, never the reverse. Naming: Mathlib `{head}_{op}_{rhs}`
(`probOutput_bind_eq_tsum`, `simulateQ_map`); structures UpperCamelCase.

## 6. Contributing to VCVio (PRs, issues)

Full text: `references/contributing.md`. The non-negotiables:
- `lake exe cache get && lake build` (Mathlib cache; VCVio itself builds from source). New
  `.lean` files → `./scripts/update-lib.sh`. Toolchain and Mathlib in sync (`v4.32.2` on main).
- Standard header (`Copyright (c) YEAR Name. … Apache 2.0 … Authors:`), then `module`, public
  imports, module docstring. Preserve headers on routine edits; **no AI-attribution line**.
- Active files use the module system: `@[expose] public section` for ordinary sources,
  `public import` for transitive API deps, plain `import` for implementation deps; never
  `backward.privateInPublic`/`proofsInPublic`.
- Docstrings intrinsic and descriptive (no "renamed from"/"replaces"); section breaks are
  `/-! ## Title -/`, never ASCII banners. No sub-directory umbrella imports.
- **Never** `set_option linter.* false` / `weak.linter.*` / lakefile lint-offs (one documented
  exception: `unicodeLinter`). Fix the root cause.
- Full cutover, no compat shims/deprecated aliases. No leftover `sorry` unless the PR says so.
- Filing an issue: include the failing snippet and the proposed change.
- **House rule (this user):** prepare locally, show the diff, and get an explicit OK before any
  commit/push/fork/PR — upstream or here.

## 7. This repo (lean/PqStealth) — VCVio-specific facts

- Pinned, not floating: `lean/lakefile.toml` `rev = a5f474fd…`, manifest frozen. A bump is a
  reviewed act — procedure, sensitive files, and the axiom-guard behaviour are in
  `lean/docs/vcvio-pin.md`. Don't run `lake update` casually.
- Things we carry because upstream lacks them (with proposed upstream changes):
  `lean/docs/vcvio-upstream.md` (11 items; #1 DecidableEq on concrete ML-KEM encodings, #2
  private `byteEncode_size`, #5 KEM-level IND-CPA, #7 KEM anonymity, #8 game-body
  identical-until-bad lemma, #9 RO modules unreachable from root import).
- `PqStealth/Axioms.lean` freezes `#print axioms` of every headline theorem via `#guard_msgs`;
  a `sorry` or moved axiom anywhere in the cone is a build error. Keep it.
- Upstream `main` vs pin: ML-KEM concrete instances moved to `Extern/MLKEM/Instance.lean` (we
  import `LatticeCrypto.MLKEM.Concrete.Instance` at the pin); `concreteEncoding` is now
  `@[expose] def`; upstream tests (`LatticeCryptoTest/MLKEM/Helpers.lean`) carry the same
  `DecidableEq` workaround we do. Details: `references/pqstealth-notes.md`.

## 8. Where to look

| Need | Open |
|---|---|
| OracleSpec/OracleComp/SubSpec/QueryImpl/simulateQ, `preInsert`/`postInsert` family | `references/oracle-comp.md` |
| probability notations, simp-lemma catalog, which-lemma tree, grind/simp rules | `references/probability.md` |
| tactic tables (`vcstep`/`vcgen`/`rvcstep`/`rvcgen`/`by_*`), RelTriple rules, handler specs, identical-until-bad | `references/program-logic.md` |
| algorithm structures, SecExp/advantages, DDH/DLog, hybrid recipe, asymptotics, cost model, query tracking | `references/crypto.md` |
| the full 30-item gotcha list | `references/gotchas.md` |
| LatticeCrypto layout, ML-KEM/ML-DSA/Falcon entry points, Extern | `references/lattice.md` |
| build/header/module/linter/PR rules | `references/contributing.md` |
| our pin, workarounds, sensitive files, upstream asks | `references/pqstealth-notes.md` |

Canonical upstream files to copy style from: `Examples/OneTimePad/Basic.lean`,
`Examples/ElGamal/Basic.lean`, `Examples/Schnorr/{SigmaProtocol,Signature}.lean`,
`Examples/CommitmentScheme.lean` (ROM, caching/logging, birthday, identical-until-bad),
`VCVio/CryptoFoundations/KeyEncapMech.lean`, `LatticeCrypto/MLKEM/{KPKE,Internal,KEM,Security}.lean`,
`VCVio/OracleComp/SimSemantics/QueryImpl/Constructions.lean`, `VCVio/ProgramLogic/Tactics.lean`,
`Examples/ProgramLogic/*.lean`.
