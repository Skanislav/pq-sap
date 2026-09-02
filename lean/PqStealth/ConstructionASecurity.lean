import PqStealth.ConstructionA
import PqStealth.MultiUnlink
import PqStealth.SPRTwoHop
import PqStealth.BlindingEntropy
import PqStealth.WidenedSigning
import PqStealth.SpendSecurity

open LatticeCrypto MLDSA MLDSA.Concrete OracleComp OracleSpec ENNReal

namespace PqStealth

namespace ConstructionA

variable {R : Type} [CommRing R] [SampleableType R]
  {k l : ℕ}
  {Rho Bytes T1 Tag Addr KEMpk KEMsk C K : Type}
  (P : Prims R Rho Bytes T1 Tag Addr K k l)
  (Smp : Samplers R Rho k l)

theorem unlinkAdvantage_full_bound
    [SampleableType K] [DecidableEq Tag] [DecidableEq Addr] [SampleableType Addr]
    (kem : KEM KEMpk KEMsk C K)
    (adv : StealthScheme.UnlinkAdv (MetaPub KEMpk Rho R k) (C × (Tag × Addr)))
    (qH : ℕ) (beta : ENNReal) (_hB : BlindPointMassBound P beta)
    (epsilonBlindExpand Adv_blindMLWE epsilonPrim epsilonEnc Adv_keyHop Adv_ctHop Adv_keyRestore : ENNReal)
    (indCpaTrue indCpaFalse : ℝ)
    (hBlind : auxKeyIndependence (metaKem P Smp kem) (auxGen P) adv ≤
                (epsilonBlindExpand + Adv_blindMLWE + (2 * qH : ENNReal) * beta).toReal)
    (hSPR : (metaKem P Smp kem).anonAdvantage (adv.cipherOf (auxGen P)) ≤
                (epsilonPrim + Adv_keyHop + Adv_ctHop + epsilonEnc + Adv_keyRestore).toReal)
    (hInd_true : sharedSecretHiding (metaKem P Smp kem) (auxGen P) adv true ≤ indCpaTrue)
    (hInd_false : sharedSecretHiding (metaKem P Smp kem) (auxGen P) adv false ≤ indCpaFalse) :
    (scheme P Smp kem).unlinkAdvantage adv ≤
      indCpaTrue + indCpaFalse
        + (epsilonBlindExpand + Adv_blindMLWE + (2 * qH : ENNReal) * beta).toReal
        + 2 * (epsilonPrim + Adv_keyHop + Adv_ctHop + epsilonEnc + Adv_keyRestore).toReal := by
  sorry

theorem unlinkAdvantageMulti_full_bound
    [SampleableType K] [DecidableEq Tag] [DecidableEq Addr]
    (kem : KEM KEMpk KEMsk C K)
    (advM : StealthScheme.UnlinkAdvMulti (MetaPub KEMpk Rho R k) (C × (Tag × Addr)))
    (q : ℕ) (epsilonSingle : ℝ)
    (hSingle : ∀ (adv' : StealthScheme.UnlinkAdv (MetaPub KEMpk Rho R k) (C × (Tag × Addr))),
               (scheme P Smp kem).unlinkAdvantage adv' ≤ epsilonSingle) :
    (scheme P Smp kem).unlinkAdvantageMulti advM q ≤ q * epsilonSingle :=
  (scheme P Smp kem).unlinkAdvantageMulti_le_mul advM q fun i j =>
    hSingle ((scheme P Smp kem).hybridAdv advM i j)

theorem relatedSpendAdvantage_le_mul_capstone
    [DecidableEq Bytes] (q maxAttempts qS qH : ℕ)
    (eps pAbort zetaWide delta : ℝ) (hp : pAbort < 1)
    (hCMA : CmaToNmaAssumption qS qH eps pAbort zetaWide delta hp)
    (hUnb : UnboundedSigningAssumption qS maxAttempts ⟨pAbort, hCMA.p_nonneg⟩) :
    relatedSpendAdvantage q maxAttempts ≤
      (q : ℝ) * ((epsilonBlindExpand + MaskIdealizationAdv + blindedSpendMLWE + blindedSTMSIS).toReal
        + (CmaToNmaLossNN qS qH eps pAbort zetaWide delta hp).1
        + (TruncationLossNN qS pAbort maxAttempts).1) :=
  relatedSpendAdvantage_le_mul q maxAttempts qS qH eps pAbort zetaWide delta hp hCMA hUnb

end ConstructionA

end PqStealth
