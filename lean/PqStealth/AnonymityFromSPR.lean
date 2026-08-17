import PqStealth.KEMAnonymity

/-!
# KEM anonymity from ciphertext pseudorandomness

Proved: anonymity is bounded by the two per-branch SPR advantages -- hop through
a game whose challenge ciphertext comes from a key-independent simulator, hence
carries no information about the hidden bit -- and, chaining into
`unlinkAdvantage_ofKEMFull_le`, the full decomposition of stealth unlinkability
into five named advantages with no unnamed slack.

Assumed: `SPR(K-PKE) ≤ 2·MLWE` (key hop, then ciphertext hop) is the remaining
lattice step, and lifting to ANO-CCA must track ML-KEM's implicit-rejection FO
transform. Neither VCVio nor FIPS 203 supplies `anonymity → MLWE`.
See `docs/spr-two-hop.md`.
-/

open OracleComp OracleSpec

namespace PqStealth

variable {PK SK C K : Type}

namespace KEM

/-! ## The simulated branch and per-branch SPR advantages

`sim` is a key-independent ciphertext simulator; for ML-KEM, uniform bytes. -/

/-- The anonymity experiment's branch with a simulated (key-independent)
challenge ciphertext. -/
def simBranch (sim : ProbComp C) (adv : StealthScheme.UnlinkAdv PK C)
    (a : PK × PK) : ProbComp Bool := do
  let c ← sim
  adv a.1 a.2 c

/-- SPR advantage on branch `b`: distinguishing a real encapsulation to key `b`
from a simulated ciphertext, in the full anonymity context. For ML-KEM this is
bounded by 2·MLWE (key hop + ciphertext hop). -/
noncomputable def sprAdv (kem : KEM PK SK C K) (sim : ProbComp C)
    (adv : StealthScheme.UnlinkAdv PK C) (b : Bool) : ℝ :=
  (kem.anonSetup >>= kem.anonBranch adv b).boolDistAdvantage
    (kem.anonSetup >>= simBranch sim adv)

/-- **The structured open arrow.** Anonymity is bounded by the two per-branch SPR
advantages, by hopping through the simulated game. All that then separates
ML-KEM anonymity from MLWE is the SPR-of-K-PKE step. -/
theorem anonAdvantage_le_sprAdv (kem : KEM PK SK C K) (sim : ProbComp C)
    (adv : StealthScheme.UnlinkAdv PK C) :
    kem.anonAdvantage adv ≤ kem.sprAdv sim adv true + kem.sprAdv sim adv false := by
  rw [KEM.anonAdvantage_eq_branchDistAdvantage, KEM.sprAdv, KEM.sprAdv,
    ProbComp.boolDistAdvantage_comm (kem.anonSetup >>= kem.anonBranch adv false)]
  exact ProbComp.boolDistAdvantage_triangle _ _ _

end KEM

/-! ## Capstone: the full unlinkability decomposition -/

variable {Aux : Type} [DecidableEq Aux] [SampleableType K]

/-- **Full-chain unlinkability bound.** The complete announcement decomposes into
five named advantages with no unnamed slack: the whole reduction skeleton of the
scheme's privacy. -/
theorem unlinkAdvantage_ofKEMFull_le_full_decomposition
    (kem : KEM PK SK C K) (auxGen : K → PK → Aux) (sim : ProbComp C)
    (adv : StealthScheme.UnlinkAdv PK (C × Aux)) :
    (StealthScheme.ofKEMFull kem auxGen).unlinkAdvantage adv ≤
      sharedSecretHiding kem auxGen adv true
      + auxKeyIndependence kem auxGen adv
      + (kem.sprAdv sim (adv.cipherOf auxGen) true
         + kem.sprAdv sim (adv.cipherOf auxGen) false)
      + sharedSecretHiding kem auxGen adv false := by
  calc (StealthScheme.ofKEMFull kem auxGen).unlinkAdvantage adv
      ≤ sharedSecretHiding kem auxGen adv true
        + auxKeyIndependence kem auxGen adv
        + kem.anonAdvantage (adv.cipherOf auxGen)
        + sharedSecretHiding kem auxGen adv false :=
        unlinkAdvantage_ofKEMFull_le kem auxGen adv
    _ ≤ sharedSecretHiding kem auxGen adv true
        + auxKeyIndependence kem auxGen adv
        + (kem.sprAdv sim (adv.cipherOf auxGen) true
           + kem.sprAdv sim (adv.cipherOf auxGen) false)
        + sharedSecretHiding kem auxGen adv false := by
        gcongr
        exact kem.anonAdvantage_le_sprAdv sim (adv.cipherOf auxGen)

end PqStealth
