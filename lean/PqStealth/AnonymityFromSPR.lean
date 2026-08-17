/-
The open arrow, structured: KEM anonymity from ciphertext pseudorandomness.

Neither VCVio nor FIPS 203 supplies `anonymity -> MLWE` for ML-KEM. The route
the literature takes (Grubbs-Maram-Paterson EC'22; Maram-Xagawa PKC'23 for
Kyber) goes through SPR -- strong pseudorandomness of ciphertexts: a challenge
ciphertext is indistinguishable from one produced by a key-independent
simulator (for ML-KEM: uniform bytes). If ciphertexts are (indistinguishable
from) key-independent, they cannot reveal which key they were made for.

This file machine-checks that implication and leaves the lattice content as
two named per-branch SPR quantities:

  anonymity  ≤  SPR(branch 1) + SPR(branch 0)        [proved here, sorry-free]
  SPR(ML-KEM)  ≤  2·MLWE                             [the remaining lattice step]

The remaining step is the standard two-hop argument, recorded here for the
paper analysis: (1) replace the challenge public key `t = A·s + e` by uniform
(Decision-MLWE, secret `s`); (2) with `t` uniform, the ciphertext
`(u, v) = (Aᵀr + e₁, tᵀr + e₂ + m)` is itself an MLWE sample with secret `r`
over the extended matrix `[A | t]`, hence pseudorandom (Decision-MLWE again).
Both hops land on VCVio's `LearningWithErrors.advantage`. Caveats for the
analysis: this is the CPA-level statement; lifting to ANO-CCA must track
ML-KEM's implicit-rejection FO transform (Maram-Xagawa), and FIPS 203's final
KDF (no ciphertext hash) is what makes the modular route applicable.

Capstone, also sorry-free: chaining into `unlinkAdvantage_ofKEMFull_le` bounds
stealth unlinkability by named terms, every one of which is either
KEM IND-CPA (proved equal to VCVio's advantage in `SharedSecretHiding`; -> MLWE
is paper-level, VCVio's own K-PKE lemma being a `sorry` placeholder), the
blinding term (`ConstructionA`), or SPR (-> 2·MLWE, the step above).
-/

import PqStealth.MLKEMInstance

open OracleComp OracleSpec

namespace PqStealth

variable {PK SK C K : Type}

namespace KEM

/-! ## The simulated branch and per-branch SPR advantages

`sim` is a key-independent ciphertext simulator (for ML-KEM: uniform sampling
over the ciphertext space). The simulated branch runs the anonymity experiment
with the challenge ciphertext replaced by a simulated one -- computable without
either public key, so it carries no information about the hidden bit. -/

/-- The anonymity experiment's branch with a simulated (key-independent)
challenge ciphertext. -/
def simBranch (sim : ProbComp C) (adv : StealthScheme.UnlinkAdv PK C)
    (a : PK × PK) : ProbComp Bool := do
  let c ← sim
  adv a.1 a.2 c

/-- SPR advantage on the `b = 1` branch: distinguishing a real encapsulation to
key 1 from a simulated ciphertext, in the full anonymity context. For ML-KEM
this is bounded by 2·MLWE (key hop + ciphertext hop). -/
noncomputable def sprAdvTrue (kem : KEM PK SK C K) (sim : ProbComp C)
    (adv : StealthScheme.UnlinkAdv PK C) : ℝ :=
  (kem.anonSetup >>= kem.anonBranchTrue adv).boolDistAdvantage
    (kem.anonSetup >>= simBranch sim adv)

/-- SPR advantage on the `b = 0` branch. -/
noncomputable def sprAdvFalse (kem : KEM PK SK C K) (sim : ProbComp C)
    (adv : StealthScheme.UnlinkAdv PK C) : ℝ :=
  (kem.anonSetup >>= simBranch sim adv).boolDistAdvantage
    (kem.anonSetup >>= kem.anonBranchFalse adv)

/-- **The structured open arrow, sorry-free.** Anonymity is bounded by the two
per-branch SPR advantages: hop through the simulated game, whose ciphertext is
key-independent. All that separates ML-KEM anonymity from MLWE after this is
the SPR-of-K-PKE step (2·MLWE per branch, the two-hop argument in the module
docstring). -/
theorem anonAdvantage_le_sprAdv (kem : KEM PK SK C K) (sim : ProbComp C)
    (adv : StealthScheme.UnlinkAdv PK C) :
    kem.anonAdvantage adv ≤ kem.sprAdvTrue sim adv + kem.sprAdvFalse sim adv := by
  rw [KEM.anonAdvantage_eq_branchDistAdvantage]
  exact ProbComp.boolDistAdvantage_triangle _ _ _

end KEM

/-! ## Capstone: the full unlinkability decomposition -/

variable {Aux : Type} [DecidableEq Aux] [SampleableType K]

/-- **Full-chain unlinkability bound, sorry-free.** Stealth unlinkability with
the complete announcement decomposes into five named advantages: two
shared-secret-hiding terms (each a KEM IND-CPA advantage, `SharedSecretHiding`;
-> MLWE paper-level), the auxiliary-data key-independence term (the blinding
argument, `ConstructionA`; needs a random-oracle model of the address hash), and
two SPR terms (each -> 2·MLWE by the two-hop argument). No unnamed slack: this is
the complete reduction skeleton of the scheme's privacy. -/
theorem unlinkAdvantage_ofKEMFull_le_full_decomposition
    (kem : KEM PK SK C K) (auxGen : K → PK → Aux) (sim : ProbComp C)
    (adv : StealthScheme.UnlinkAdv PK (C × Aux)) :
    (StealthScheme.ofKEMFull kem auxGen).unlinkAdvantage adv ≤
      sharedSecretHidingTrue kem auxGen adv
      + auxKeyIndependence kem auxGen adv
      + (kem.sprAdvTrue sim (adv.cipherOf auxGen)
         + kem.sprAdvFalse sim (adv.cipherOf auxGen))
      + sharedSecretHidingFalse kem auxGen adv := by
  calc (StealthScheme.ofKEMFull kem auxGen).unlinkAdvantage adv
      ≤ sharedSecretHidingTrue kem auxGen adv
        + auxKeyIndependence kem auxGen adv
        + kem.anonAdvantage (adv.cipherOf auxGen)
        + sharedSecretHidingFalse kem auxGen adv :=
        unlinkAdvantage_ofKEMFull_le kem auxGen adv
    _ ≤ sharedSecretHidingTrue kem auxGen adv
        + auxKeyIndependence kem auxGen adv
        + (kem.sprAdvTrue sim (adv.cipherOf auxGen)
           + kem.sprAdvFalse sim (adv.cipherOf auxGen))
        + sharedSecretHidingFalse kem auxGen adv := by
        gcongr
        exact kem.anonAdvantage_le_sprAdv sim (adv.cipherOf auxGen)

/-! ## ML-KEM: the simulator is an explicit key-independent ciphertext sampler -/

section MLKEMSPR

open MLKEM

variable {params : Params} (ring : NTTRingOps) (encoding : Encoding params)
  (prims : Primitives params encoding)
  [DecidableEq encoding.EncodedTHat] [DecidableEq encoding.EncodedU]
  [DecidableEq encoding.EncodedV]
  {Aux : Type} [DecidableEq Aux]
  (auxGen : SharedSecret → EncapsulationKey params encoding → Aux)

/-- **Unlinkability on real ML-KEM, fully decomposed.** The simulator `sim` is
an explicit key-independent ciphertext sampler; for the two-hop MLWE argument
it is uniform over the encoded ciphertext space. It is a parameter rather than
`$ᵗ (Ciphertext params encoding)` because on the concrete encodings that
uniform sample does not exist — the encoded types are `ByteArray`, which is
infinite, so `SampleableType` is uninhabited there
(`isEmpty_sampleableType_mlkem768Ciphertext` in `MLKEM768`); the ML-KEM-768
instantiation supplies the uniform-1088-byte sampler instead. The hiding terms
are KEM IND-CPA advantages (`SharedSecretHiding`); the SPR terms are the key
hop and the ciphertext hop of the module docstring. -/
theorem mlkem_unlinkAdvantage_le_full_decomposition
    (sim : ProbComp (Ciphertext params encoding))
    (adv : StealthScheme.UnlinkAdv (EncapsulationKey params encoding)
      (Ciphertext params encoding × Aux)) :
    (mlkemStealthScheme ring encoding prims auxGen).unlinkAdvantage adv ≤
      sharedSecretHidingTrue (mlkem ring encoding prims) auxGen adv
      + auxKeyIndependence (mlkem ring encoding prims) auxGen adv
      + ((mlkem ring encoding prims).sprAdvTrue sim (adv.cipherOf auxGen)
         + (mlkem ring encoding prims).sprAdvFalse sim (adv.cipherOf auxGen))
      + sharedSecretHidingFalse (mlkem ring encoding prims) auxGen adv :=
  unlinkAdvantage_ofKEMFull_le_full_decomposition (mlkem ring encoding prims) auxGen sim adv

end MLKEMSPR

end PqStealth
