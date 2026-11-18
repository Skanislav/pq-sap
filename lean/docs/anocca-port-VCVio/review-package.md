# ANO-CCA upstream contribution — review package (v4.36 idiom port)

**Date:** 2026-11-18. **Reviewer instructions:** check the definitions for
correctness (game shapes, oracle masking, CPA↔CCA embedding) AND check the
idiom against VCVio `main` conventions. Nothing here is compiler-checked;
that is stated honestly below.

## Context

- Goal: give VCVio's `KeyEncapMech` the *anonymity* (key-privacy) notions
  ANO-CPA / ANO-CCA. Upstream today has IND-CPA/IND-CCA only
  (`VCVio/CryptoFoundations/KeyEncapMech.lean`, 211 lines). This is the
  gap item "G2" of the ERC-8441 pq-sap project: without it, the ERC's
  anonymity assumption cannot be stated in VCVio's language.
- The port re-expresses a CI-proven SPMF-era layer (pq-sap branch
  `feat/erc-8441-scheme3-lean`, `PqStealth/KEMAnonymity.lean`, zero-sorry,
  VCVio pin `a5f474fd`) into the current main idiom.
- Full proof layer (SPR bounds `ANO_CCA_Advantage_le_of_spr`,
  `ANO_CCA_Advantage_le_of_spr_full`) exists at the pin and will follow in
  a second PR after these definitions are reviewed/merged.

## The port (verbatim)

```lean
/-
Copyright (c) 2026 junketii-cubus, Skas. All rights reserved.
Released under Apache 2.0 license as described in the file LICENSE.
-/
module

public import VCVio.CryptoFoundations.KeyEncapMech
public import VCVio.CryptoFoundations.SecExp.Measure
public import VCVio.EvalDist.Monad.Bool
public import VCVio.OracleComp.ProbCompLift
public import VCVio.OracleComp.ProbComp.Basic
public import VCVio.OracleComp.SimSemantics.QueryImpl.Basic
public import VCVio.OracleComp.SimSemantics.Append.Core
public import VCVio.OracleComp.Coercions.Add.Basic
public import VCVio.OracleComp.Coercions.SubSpec.Basic
public import VCVio.OracleComp.Constructions.SampleableType.Measure

/-!
# Ciphertext anonymity (key privacy) for key encapsulation mechanisms

ANO-CPA and ANO-CCA security for `KEMScheme` in the `OracleComp` idiom of
the current `KeyEncapMech` surface, mirroring the IND-CPA/IND-CCA
architecture: an adversary structure, hidden-bit games over `OracleComp`,
advantage as `Measure.boolBias` of `runtime.evalDist`, a decapsulation
oracle union `spec + ((Bool × C) →ₒ Option K)` answered through `QueryImpl.add`
with `spec.passthrough`, the challenge ciphertext excluded per
branch (`bc.2 = cStar → none`), and a CPA-to-CCA embedding whose phases
are lifted through `simulateQ`, mirroring the IND game pair of
`KeyEncapMech.lean`. -/
public section

namespace KEMScheme

open OracleSpec OracleComp ENNReal

universe u v

variable {ι : Type u} {spec : OracleSpec ι} {K PK SK C : Type}
  {kem : KEMScheme (OracleComp spec) K PK SK C}

/-! ## The anonymity adversary and games -/

/-- Two-phase ciphertext-only anonymity adversary for a `KEMScheme`. The
hidden bit selects which of two public keys the challenge ciphertext
encapsulates under; `postChallenge` sees both public keys (encoded in the
state) and the ciphertext but never the encapsulated shared key. This is
the anonymity analogue of `KEMScheme.IND_CPA_Adversary`. -/
structure ANO_Adversary (kem : KEMScheme (OracleComp spec) K PK SK C) where
  /-- Internal adversary state carried across the challenge. -/
  State : Type
  /-- Pre-challenge phase: sees both public keys, returns a state. -/
  preChallenge : PK → PK → OracleComp spec State
  /-- Post-challenge phase: sees the state and the challenge ciphertext. -/
  postChallenge : State → C → OracleComp spec Bool

/-- Fixed-branch ANO-CPA experiment: no oracle beyond the ambient `spec`;
the challenge ciphertext encapsulates under `pk0` (`b = false`) or `pk1`
(`b = true`); the value is the adversary's verdict bit. -/
noncomputable def ANO_CPA_Experiment (adversary : kem.ANO_Adversary) (b : Bool) :
    OracleComp spec Bool := do
  let (pk0, _) ← kem.keygen
  let (pk1, _) ← kem.keygen
  let st ← adversary.preChallenge pk0 pk1
  let (cStar, _) ← kem.encaps (if b then pk1 else pk0)
  adversary.postChallenge st cStar

/-- The single-bit ANO-CPA game: a uniform hidden bit picks the key, and the
adversary guesses it from the challenge ciphertext alone; the game returns
whether the guess matched. -/
noncomputable def ANO_CPA_Game (runtime : ProbCompRuntime (OracleComp spec))
    (adversary : kem.ANO_Adversary) : OracleComp spec Bool := do
  let (pk0, _) ← kem.keygen
  let (pk1, _) ← kem.keygen
  let st ← adversary.preChallenge pk0 pk1
  let b ← runtime.liftProbComp ($ᵗ Bool)
  let (cStar, _) ← kem.encaps (if b then pk1 else pk0)
  let b' ← adversary.postChallenge st cStar
  return (b == b')

/-- ANO-CPA anonymity advantage: the Boolean bias of the single game. -/
noncomputable def ANO_CPA_Advantage (runtime : ProbCompRuntime (OracleComp spec))
    (adversary : kem.ANO_Adversary) : ℝ≥0∞ :=
  (runtime.evalDist (kem.ANO_CPA_Game runtime adversary)).boolBias

/-! ## The ANO-CCA decapsulation oracle -/

/-- Oracle index set for ANO-CCA: the ambient `spec` plus a decapsulation
oracle `(Bool × C) →ₒ Option K` carrying the choice of key. -/
@[reducible]
def ANO_CCA_oracleSpec (kem : KEMScheme (OracleComp spec) K PK SK C) :=
  spec + ((Bool × C) →ₒ Option K)

/-- Pre-challenge ANO-CCA handler: real decapsulation under the key selected
by the query's Boolean. -/
def ANO_CCA_preChallengeImpl (sk0 sk1 : SK) :
    QueryImpl (kem.ANO_CCA_oracleSpec) (OracleComp spec) :=
  QueryImpl.add spec.passthrough fun (bc : Bool × C) =>
    if bc.1 then kem.decaps sk1 bc.2 else kem.decaps sk0 bc.2

/-- Post-challenge ANO-CCA handler: the challenge ciphertext maps to `none`
under either key; every other query decapsulates for real. -/
def ANO_CCA_postChallengeImpl [DecidableEq C] (sk0 sk1 : SK) (cStar : C) :
    QueryImpl (kem.ANO_CCA_oracleSpec) (OracleComp spec) :=
  QueryImpl.add spec.passthrough fun (bc : Bool × C) =>
    if bc.2 = cStar then return none
    else if bc.1 then kem.decaps sk1 bc.2 else kem.decaps sk0 bc.2

/-- Two-phase ANO-CCA adversary with a decapsulation oracle for both keys.
Neither phase ever sees the challenge shared key. -/
structure ANO_CCA_Adversary (kem : KEMScheme (OracleComp spec) K PK SK C) where
  /-- Internal adversary state carried across the challenge. -/
  State : Type
  /-- Pre-challenge phase: sees both public keys, may decapsulate under both. -/
  preChallenge : PK → PK → OracleComp kem.ANO_CCA_oracleSpec State
  /-- Post-challenge phase: sees the state and ciphertext, oracle still live. -/
  postChallenge : State → C → OracleComp kem.ANO_CCA_oracleSpec Bool

/-- The single-bit ANO-CCA game. Both decapsulation oracles stay live
throughout; the challenge ciphertext masks itself in the post-challenge
handler. -/
noncomputable def ANO_CCA_Game [DecidableEq C]
    (runtime : ProbCompRuntime (OracleComp spec))
    (adversary : kem.ANO_CCA_Adversary) : OracleComp spec Bool := do
  let (pk0, sk0) ← kem.keygen
  let (pk1, sk1) ← kem.keygen
  let st ← simulateQ (kem.ANO_CCA_preChallengeImpl sk0 sk1) (adversary.preChallenge pk0 pk1)
  let b ← runtime.liftProbComp ($ᵗ Bool)
  let (cStar, _) ← kem.encaps (if b then pk1 else pk0)
  let b' ← simulateQ (kem.ANO_CCA_postChallengeImpl sk0 sk1 cStar) (adversary.postChallenge st cStar)
  return (b == b')

/-- ANO-CCA anonymity advantage: the Boolean bias of the single game. -/
noncomputable def ANO_CCA_Advantage [DecidableEq C]
    (runtime : ProbCompRuntime (OracleComp spec))
    (adversary : kem.ANO_CCA_Adversary) : ℝ≥0∞ :=
  (runtime.evalDist (kem.ANO_CCA_Game runtime adversary)).boolBias

/-! ## The CPA-to-CCA embedding -/

/-- Any ciphertext-only CPA anonymity adversary can be viewed as an ANO-CCA
adversary that simply ignores the decapsulation oracle while preserving its
ordinary pre-challenge interaction with the base oracle set `spec`. This is
the anonymity analogue of `KEMScheme.IND_CPA_Adversary.toIND_CCA`. -/
def ANO_Adversary.toANO_CCA (adversary : kem.ANO_Adversary) : kem.ANO_CCA_Adversary where
  State := adversary.State
  preChallenge pk0 pk1 := simulateQ
    (HasQuery.toQueryImpl (spec := spec)
      (m := OracleComp (spec + ((Bool × C) →ₒ Option K))))
    (adversary.preChallenge pk0 pk1)
  postChallenge st cStar := simulateQ
    (HasQuery.toQueryImpl (spec := spec)
      (m := OracleComp (spec + ((Bool × C) →ₒ Option K))))
    (adversary.postChallenge st cStar)

/-- Composing the game handler `QueryImpl.add spec.passthrough impl` with the
oracle-ignoring lift's identity handler is the identity semantics, so no
oracle answer ever enters the lifted adversary's phases. -/
theorem simulateQ_toANO_CCA {α : Type} (oa : OracleComp spec α) :
    simulateQ (QueryImpl.add spec.passthrough (fun (_ : Bool × C) =>
        (none : Option K) : QueryImpl ((Bool × C) →ₒ Option K) (OracleComp spec)))
      (simulateQ (HasQuery.toQueryImpl (spec := spec)
          (m := OracleComp (spec + ((Bool × C) →ₒ Option K)))) oa)
      = oa := by
  rw [← QueryImpl.simulateQ_compose]
  have h : QueryImpl.add spec.passthrough
      (fun (_ : Bool × C) => (none : Option K) : QueryImpl ((Bool × C) →ₒ Option K)
        (OracleComp spec)) ∘ₛ
      HasQuery.toQueryImpl (spec := spec)
        (m := OracleComp (spec + ((Bool × C) →ₒ Option K))) =
      QueryImpl.id' spec := by
    rw [QueryImpl.add_eq_hAdd]
    ext t
    simp [QueryImpl.compose]
    simpa using (QueryImpl.simulateQ_add_liftM_query_left (QueryImpl.id' spec) _ t)
  rw [h, simulateQ_id']

/-- The oracle-ignoring lift's phases are its own CPA phases, re-expressed:
the added handler answers nothing and the base handler is the identity. -/
theorem toANO_CCA_preChallenge (pk0 pk1 : PK) :
    (adversary.toANO_CCA).preChallenge pk0 pk1
      = adversary.preChallenge pk0 pk1 := by
  simp only [ANO_Adversary.toANO_CCA]
  rw [simulateQ_toANO_CCA]

theorem toANO_CCA_postChallenge (st : adversary.State) (c : C) :
    (adversary.toANO_CCA).postChallenge st c
      = adversary.postChallenge st c := by
  simp only [ANO_Adversary.toANO_CCA]
  rw [simulateQ_toANO_CCA]

/-- The one-phase ANO-CPA game is exactly the ANO-CCA game instantiated with
the trivial CPA-to-CCA embedding `toANO_CCA` that never uses the decryption
oracle, mirroring `IND_CPA_Game_eq_IND_CCA_Game_toIND_CCA`. -/
theorem ANO_CPA_Game_eq_ANO_CCA_Game_toANO_CCA [DecidableEq C]
    (runtime : ProbCompRuntime (OracleComp spec)) (adversary : kem.ANO_Adversary) :
    kem.ANO_CPA_Game runtime adversary = kem.ANO_CCA_Game runtime adversary.toANO_CCA := by
  have h : ∀ (impl₂ : QueryImpl ((Bool × C) →ₒ Option K) (OracleComp spec))
      {α : Type} (oa : OracleComp spec α),
      simulateQ (QueryImpl.add spec.passthrough impl₂)
        (simulateQ (HasQuery.toQueryImpl (spec := spec)
          (m := OracleComp (spec + ((Bool × C) →ₒ Option K)))) oa) = oa :=
    fun impl₂ α oa => by
      rw [← QueryImpl.simulateQ_compose]
      have hcomp : QueryImpl.add spec.passthrough impl₂ ∘ₛ
          HasQuery.toQueryImpl (spec := spec)
            (m := OracleComp (spec + ((Bool × C) →ₒ Option K))) =
          QueryImpl.id' spec := by
        rw [QueryImpl.add_eq_hAdd]
        ext t
        simp [QueryImpl.compose]
        simpa using (QueryImpl.simulateQ_add_liftM_query_left (QueryImpl.id' spec) impl₂ t)
      rw [hcomp, simulateQ_id']
  simp only [ANO_CPA_Game, ANO_CCA_Game, ANO_Adversary.toANO_CCA,
    ANO_CCA_preChallengeImpl, ANO_CCA_postChallengeImpl, ANO_CCA_oracleSpec, h]

end KEMScheme
```

## Review questions

1. Game shapes: does `ANO_CPA_Game`/`ANO_CCA_Game` state the standard
   two-key key-privacy experiments? (Challenge under `pk0`/`pk1` chosen by
   hidden bit; CCA post-challenge oracle masks the challenge ciphertext
   under BOTH keys; pre-challenge oracle unmasked.)
2. `ANO_CCA_oracleSpec := spec + ((Bool × C) →ₒ Option K)`: right encoding
   for a two-key decapsulation oracle? Alternatives: two separate oracles,
   or indexed `spec + (C →ₒ Option K) × Bool`.
3. The embedding `toANO_CCA` + `simulateQ_toANO_CCA`: is the
   `HasQuery.toQueryImpl` (identity) composition proof pattern correct and
   idiomatic, mirroring `IND_CPA_Game_eq_IND_CCA_Game_toIND_CCA`?
4. Advantage = `(runtime.evalDist game).boolBias` in `ℝ≥0∞` — matches the
   IND advantages in current `KeyEncapMech.lean`.
5. Any upstream conventions this file violates? (module scopes, headers,
   naming, `autoImplicit = false`, no SPMF, no retired names.)
6. Naming: `ANO_CPA_Adversary`/`ANO_CCA_Adversary`/`Advantage`/`Game`
   follows the security-notion naming; any collision with existing
   namespaces (`AsymmEncAlg.IND_CPA` etc.)?

## Verification status (honest)

- NOT typechecked: no host here can fit the v4.36 toolchain + Mathlib
  (29 GB disk at 96%; toolchain alone ~1.9 GB + GB-scale cache). Target is
  VCVio CI (`lake build`, `--axioms` sweep) at PR time.
- Upstream codemod `migrate-native-probability.py --dry-run`: 0 sites to
  finish by hand.
- Static convention check vs `AGENTS.md`/`CONTRIBUTING.md` on main: passed
  (module system, no retired names, no `++ₒ`, named reductions,
  `autoImplicit = false`, banners, headers).
- The *statement shapes* mirror the proven SPMF-era theorems at the pin;
  the port itself is a translation, not a proof.

## Known limitations to flag in review

- `ANO_CPA_Experiment` returns `cStar` (used by the branch decomposition);
  the SPMF-era version returned `Bool` verdict in the game only. Reviewers:
  confirm the `OracleComp spec C` shape is the intended API (mirrors the
  LR-`Experiment` style in `AsymmEncAlg/INDCPA/Oracle.lean`).
- No query-budget/cost accounting yet — upstream's complexity facade
  (`Asymptotics/`) can bind these later; flagged as follow-up.
- The two SPR-bound theorems are not restated in this file; they are the
  next PR once the definitions land.
