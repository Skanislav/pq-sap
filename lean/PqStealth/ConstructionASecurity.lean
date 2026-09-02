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

omit [SampleableType R] in
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

/-- **Related-key spend capstone at ML-DSA.** A malicious sender who knows all
`q` blinding offsets forges a spend witness for some derived stealth key with
probability at most `q` times the master key's ownership-forgery advantage at
the widened bound `b + η` (`SpendSecurity.lean`). -/
theorem relatedSpendAdvantage_le_mul_capstone
    (keyGen : ProbComp (OwnershipKey Rq k l)) (b eta q : ℕ)
    (offGen : ProbComp (ShortOffset Rq k l (mldsaShort eta)))
    (adv : RelatedSpendAdv Rq k l (mldsaShort eta) q) {ε : ℝ≥0∞}
    (hε : ∀ i, spendForgeryAdvantage keyGen (mldsaShort (b + eta))
      (relatedSpendReduction keyGen offGen q adv (mldsaShort (b + eta)) i) ≤ ε) :
    relatedSpendAdvantage keyGen offGen (mldsaShort b) q adv ≤ q * ε :=
  mldsa_relatedSpendAdvantage_le keyGen b eta q offGen adv hε

end ConstructionA

end PqStealth
