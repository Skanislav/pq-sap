import PqStealth.MLKEM
import PqStealth.SPRTwoHop

/-!
# Closed ML-KEM-768 unlinkability bound

`SPRTwoHop` proves `mlkem768_sprAdv_le_three_mlwe_compressed`; `MLKEM` has
`mlkem768_unlinkAdvantage_le_full_decomposition` and defines `mlkem768KEM`.
This module chains them so the stealth unlinkability advantage is named directly
against the three seeded-MLWE adversaries, the two named primitive idealizations,
and the correctness terms. The encoding term is zero because the simulator is
the compressed-uniform distribution.
-/

open OracleComp OracleSpec MLKEM MLKEM.Concrete

namespace PqStealth

section Closed

variable {Aux : Type} [DecidableEq Aux]
  (auxGen : SharedSecret → EncapsulationKey mlkem768 mlkem768Encoding → Aux)
  (adv : StealthScheme.UnlinkAdv (EncapsulationKey mlkem768 mlkem768Encoding)
    (Ciphertext mlkem768 mlkem768Encoding × Aux))

/-- **ML-KEM-768 unlinkability, SPR terms opened against the compressed-uniform
simulator.** Both `sprAdv` terms are replaced by their named MLWE reductions:
one `keyHopAdv` and one `ctHopAdv` per branch, plus one `keyRestorationAdv` per
branch, plus the primitive and key-generation idealization epsilons. The encoding
term is zero by `encodingRegularity_mlkem768CompressedUniformCiphertext`.
The remaining non-MLWE terms are `epsilonPrim` and `epsilonKeyIdeal`, the
explicit FIPS primitive idealizations. -/
theorem mlkem768_unlinkAdvantage_le_three_mlwe_compressed
    (epsilonPrim epsilonKeyIdeal : ℝ)
    (hPrim : ∀ b : Bool, ∀ advT : StealthScheme.UnlinkAdv
        (EncapsulationKey mlkem768 mlkem768Encoding)
        (Ciphertext mlkem768 mlkem768Encoding),
      primitiveIdealization concreteNTTRingOps mlkem768Encoding
        mlkem768Primitives advT b ≤ epsilonPrim)
    (hKeyIdeal : ∀ b : Bool, ∀ advT : StealthScheme.UnlinkAdv
        (EncapsulationKey mlkem768 mlkem768Encoding)
        (Ciphertext mlkem768 mlkem768Encoding),
      keyIdealization concreteNTTRingOps mlkem768Encoding
        mlkem768Primitives advT mlkem768CompressedUniformCiphertext b ≤ epsilonKeyIdeal) :
    (mlkem768StealthScheme auxGen).unlinkAdvantage adv ≤
      sharedSecretHiding mlkem768KEM auxGen adv true
      + auxKeyIndependence mlkem768KEM auxGen adv
      + sharedSecretHiding mlkem768KEM auxGen adv false
      + (2 * epsilonPrim
          + 2 * epsilonKeyIdeal
          + LearningWithErrors.advantage mlkem768KeyHopProblem
              (keyHopAdv concreteNTTRingOps mlkem768Encoding mlkem768Primitives
                (adv.cipherOf auxGen) true)
          + LearningWithErrors.advantage mlkem768CtHopProblem
              (ctHopAdv concreteNTTRingOps mlkem768Encoding mlkem768Primitives
                (adv.cipherOf auxGen) true)
          + LearningWithErrors.advantage mlkem768KeyHopProblem
              (keyRestorationAdv concreteNTTRingOps mlkem768Encoding mlkem768Primitives
                (adv.cipherOf auxGen) mlkem768CompressedUniformCiphertext true)
          + LearningWithErrors.advantage mlkem768KeyHopProblem
              (keyHopAdv concreteNTTRingOps mlkem768Encoding mlkem768Primitives
                (adv.cipherOf auxGen) false)
          + LearningWithErrors.advantage mlkem768CtHopProblem
              (ctHopAdv concreteNTTRingOps mlkem768Encoding mlkem768Primitives
                (adv.cipherOf auxGen) false)
          + LearningWithErrors.advantage mlkem768KeyHopProblem
              (keyRestorationAdv concreteNTTRingOps mlkem768Encoding mlkem768Primitives
                (adv.cipherOf auxGen) mlkem768CompressedUniformCiphertext false)) := by
  calc (mlkem768StealthScheme auxGen).unlinkAdvantage adv
      ≤ sharedSecretHiding mlkem768KEM auxGen adv true
          + auxKeyIndependence mlkem768KEM auxGen adv
          + (mlkem768KEM.sprAdv mlkem768CompressedUniformCiphertext (adv.cipherOf auxGen) true
            + mlkem768KEM.sprAdv mlkem768CompressedUniformCiphertext (adv.cipherOf auxGen) false)
          + sharedSecretHiding mlkem768KEM auxGen adv false :=
        unlinkAdvantage_ofKEMFull_le_full_decomposition mlkem768KEM auxGen
          mlkem768CompressedUniformCiphertext adv
    _ ≤ sharedSecretHiding mlkem768KEM auxGen adv true
          + auxKeyIndependence mlkem768KEM auxGen adv
          + sharedSecretHiding mlkem768KEM auxGen adv false
          + (2 * epsilonPrim
              + 2 * epsilonKeyIdeal
              + LearningWithErrors.advantage mlkem768KeyHopProblem
                  (keyHopAdv concreteNTTRingOps mlkem768Encoding mlkem768Primitives
                    (adv.cipherOf auxGen) true)
              + LearningWithErrors.advantage mlkem768CtHopProblem
                  (ctHopAdv concreteNTTRingOps mlkem768Encoding mlkem768Primitives
                    (adv.cipherOf auxGen) true)
              + LearningWithErrors.advantage mlkem768KeyHopProblem
                  (keyRestorationAdv concreteNTTRingOps mlkem768Encoding mlkem768Primitives
                    (adv.cipherOf auxGen) mlkem768CompressedUniformCiphertext true)
              + LearningWithErrors.advantage mlkem768KeyHopProblem
                  (keyHopAdv concreteNTTRingOps mlkem768Encoding mlkem768Primitives
                    (adv.cipherOf auxGen) false)
              + LearningWithErrors.advantage mlkem768CtHopProblem
                  (ctHopAdv concreteNTTRingOps mlkem768Encoding mlkem768Primitives
                    (adv.cipherOf auxGen) false)
              + LearningWithErrors.advantage mlkem768KeyHopProblem
                  (keyRestorationAdv concreteNTTRingOps mlkem768Encoding mlkem768Primitives
                    (adv.cipherOf auxGen) mlkem768CompressedUniformCiphertext false)) := by
        have hT := mlkem768_sprAdv_le_three_mlwe_compressed (adv.cipherOf auxGen) true
          epsilonPrim epsilonKeyIdeal
          (fun b => hPrim b (adv.cipherOf auxGen))
          (fun b => hKeyIdeal b (adv.cipherOf auxGen))
        have hF := mlkem768_sprAdv_le_three_mlwe_compressed (adv.cipherOf auxGen) false
          epsilonPrim epsilonKeyIdeal
          (fun b => hPrim b (adv.cipherOf auxGen))
          (fun b => hKeyIdeal b (adv.cipherOf auxGen))
        rw [show mlkem768KeyHopProblem =
            keyHopProblem concreteNTTRingOps mlkem768Encoding mlkem768Primitives from rfl,
          show mlkem768CtHopProblem =
            ctHopProblem concreteNTTRingOps mlkem768Encoding mlkem768Primitives from rfl]
        linarith [hT, hF]

end Closed

end PqStealth
