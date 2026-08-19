import VCVio.OracleComp.QueryTracking.RandomOracle.DeferredSampling
import VCVio.OracleComp.Constructions.SampleableType

/-!
# Reordering independent draws

`OracleComp`'s `bind` is syntactic, so two games that draw the same independent
samples in different orders are not equal on the nose; they are equal under
`evalDist`, which is all an advantage sees. The lemmas here pull the `k`-th of
`k` independent draws to the front (`k = 3 … 6`), each a composition of VCVio's
`evalDist_bind_bind_swap` under `evalDist_bind_congr'`. A game that differs from
another by a permutation of independent draws is rewritten with a few of them.
-/

open OracleComp OracleSpec

namespace PqStealth

variable {α₁ α₂ α₃ α₄ α₅ α₆ β : Type}

/-- Pull the third of three independent draws to the front. -/
theorem evalDist_pull₃ (o₁ : ProbComp α₁) (o₂ : ProbComp α₂) (o₃ : ProbComp α₃)
    (k : α₁ → α₂ → α₃ → ProbComp β) :
    𝒟[do let a ← o₁; let b ← o₂; let c ← o₃; k a b c] =
      𝒟[do let c ← o₃; let a ← o₁; let b ← o₂; k a b c] := by
  calc 𝒟[do let a ← o₁; let b ← o₂; let c ← o₃; k a b c]
      = 𝒟[do let a ← o₁; let c ← o₃; let b ← o₂; k a b c] :=
        evalDist_bind_congr' _ fun a => evalDist_bind_bind_swap o₂ o₃ (k a)
    _ = 𝒟[do let c ← o₃; let a ← o₁; let b ← o₂; k a b c] :=
        evalDist_bind_bind_swap o₁ o₃ _

/-- Pull the fourth of four independent draws to the front. -/
theorem evalDist_pull₄ (o₁ : ProbComp α₁) (o₂ : ProbComp α₂) (o₃ : ProbComp α₃)
    (o₄ : ProbComp α₄) (k : α₁ → α₂ → α₃ → α₄ → ProbComp β) :
    𝒟[do let a ← o₁; let b ← o₂; let c ← o₃; let d ← o₄; k a b c d] =
      𝒟[do let d ← o₄; let a ← o₁; let b ← o₂; let c ← o₃; k a b c d] := by
  calc 𝒟[do let a ← o₁; let b ← o₂; let c ← o₃; let d ← o₄; k a b c d]
      = 𝒟[do let a ← o₁; let d ← o₄; let b ← o₂; let c ← o₃; k a b c d] :=
        evalDist_bind_congr' _ fun a => evalDist_pull₃ o₂ o₃ o₄ (k a)
    _ = 𝒟[do let d ← o₄; let a ← o₁; let b ← o₂; let c ← o₃; k a b c d] :=
        evalDist_bind_bind_swap o₁ o₄ _

/-- Pull the fifth of five independent draws to the front. -/
theorem evalDist_pull₅ (o₁ : ProbComp α₁) (o₂ : ProbComp α₂) (o₃ : ProbComp α₃)
    (o₄ : ProbComp α₄) (o₅ : ProbComp α₅) (k : α₁ → α₂ → α₃ → α₄ → α₅ → ProbComp β) :
    𝒟[do let a ← o₁; let b ← o₂; let c ← o₃; let d ← o₄; let e ← o₅; k a b c d e] =
      𝒟[do let e ← o₅; let a ← o₁; let b ← o₂; let c ← o₃; let d ← o₄; k a b c d e] := by
  calc 𝒟[do let a ← o₁; let b ← o₂; let c ← o₃; let d ← o₄; let e ← o₅; k a b c d e]
      = 𝒟[do let a ← o₁; let e ← o₅; let b ← o₂; let c ← o₃; let d ← o₄; k a b c d e] :=
        evalDist_bind_congr' _ fun a => evalDist_pull₄ o₂ o₃ o₄ o₅ (k a)
    _ = 𝒟[do let e ← o₅; let a ← o₁; let b ← o₂; let c ← o₃; let d ← o₄; k a b c d e] :=
        evalDist_bind_bind_swap o₁ o₅ _

/-- Pull the sixth of six independent draws to the front. -/
theorem evalDist_pull₆ (o₁ : ProbComp α₁) (o₂ : ProbComp α₂) (o₃ : ProbComp α₃)
    (o₄ : ProbComp α₄) (o₅ : ProbComp α₅) (o₆ : ProbComp α₆)
    (k : α₁ → α₂ → α₃ → α₄ → α₅ → α₆ → ProbComp β) :
    𝒟[o₁ >>= fun a => o₂ >>= fun b => o₃ >>= fun c => o₄ >>= fun d => o₅ >>= fun e =>
        o₆ >>= fun f => k a b c d e f] =
      𝒟[o₆ >>= fun f => o₁ >>= fun a => o₂ >>= fun b => o₃ >>= fun c => o₄ >>= fun d =>
        o₅ >>= fun e => k a b c d e f] := by
  calc 𝒟[o₁ >>= fun a => o₂ >>= fun b => o₃ >>= fun c => o₄ >>= fun d => o₅ >>= fun e =>
          o₆ >>= fun f => k a b c d e f]
      = 𝒟[o₁ >>= fun a => o₆ >>= fun f => o₂ >>= fun b => o₃ >>= fun c => o₄ >>= fun d =>
          o₅ >>= fun e => k a b c d e f] :=
        evalDist_bind_congr' _ fun a => evalDist_pull₅ o₂ o₃ o₄ o₅ o₆ (k a)
    _ = 𝒟[o₆ >>= fun f => o₁ >>= fun a => o₂ >>= fun b => o₃ >>= fun c => o₄ >>= fun d =>
          o₅ >>= fun e => k a b c d e f] :=
        evalDist_bind_bind_swap o₁ o₆ _

/-- An unused uniform draw does not change the output distribution (a `ProbComp` never
fails, so VCVio's `evalDist_bind_const_neverFails` applies). -/
theorem evalDist_uniformSample_bind_const {α γ : Type} [SampleableType α] (p : ProbComp γ) :
    𝒟[(($ᵗ α) >>= fun _ => p)] = 𝒟[p] :=
  OracleComp.DeferredSampling.evalDist_bind_const_neverFails _ (probFailure_of_liftM_PMF _) p

end PqStealth
