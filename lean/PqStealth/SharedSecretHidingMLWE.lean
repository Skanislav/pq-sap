/-
Composing the shared-secret-hiding equalities with VCVio's ML-KEM chain.

`SharedSecretHiding.lean` proves that each shared-secret-hiding term of
`unlinkAdvantage_ofKEMFull_le` IS a `KEMScheme.IND_CPA_Advantage`. On the
concrete instance the scheme in question is VCVio's own `MLKEM.asKEMScheme`:
`mlkem` IS that scheme (`KEM` is `KEMScheme ProbComp` with the type arguments
reordered), so the reduction adversaries built here are
literally IND-CPA adversaries against `MLKEM.asKEMScheme`, and the ML-KEM
unlinkability bound can be restated with those advantages in place of the hiding
terms.

That is as far as the chain reaches today, and the obstruction is upstream. To
turn the IND-CPA terms into MLWE terms one needs a lemma VCVio does not have.
The statement below elaborates as written against the pinned VCVio, under
`import LatticeCrypto.HardnessAssumptions.LearningWithErrors` and `open MLKEM`:

  theorem MLKEM.kem_ind_cpa_security {params : Params} (ring : NTTRingOps)
      (encoding : Encoding params) (prims : Primitives params encoding)
      [DecidableEq encoding.EncodedTHat] [DecidableEq encoding.EncodedU]
      [DecidableEq encoding.EncodedV] [SampleableType SharedSecret] :
      ∃ mlwe : LearningWithErrors.Problem
          (TqMatrix params.k params.k) (TqVec params.k) (TqVec params.k),
        ∀ cpaAdv : (MLKEM.asKEMScheme ring encoding prims).IND_CPA_Adversary,
          ∃ mlweAdv : LearningWithErrors.Adversary mlwe,
            KEMScheme.IND_CPA_Advantage ProbCompRuntime.probComp cpaAdv ≤
              |LearningWithErrors.advantage mlwe mlweAdv|

What `LatticeCrypto/MLKEM/Security.lean` supplies instead is
`kpke_ind_cpa_security`, which bounds `AsymmEncAlg.IND_CPA_advantage` of K-PKE --
the underlying public-key encryption scheme -- rather than
`KEMScheme.IND_CPA_Advantage` of the KEM, and which is `sorry` upstream. The
step between the two is the T-transform half of Fujisaki-Okamoto: the KEM's
shared secret is derived from a uniformly random message via a hash modelled as
a random oracle, so KEM IND-CPA follows from K-PKE IND-CPA plus message entropy.
Neither that reduction nor `kpke_ind_cpa_security` itself is in scope here, so
this file states equalities and a restated bound, never an MLWE bound; importing
one would import `sorryAx`.
-/

import PqStealth.SharedSecretHiding
import PqStealth.MLKEMInstance

open OracleComp OracleSpec MLKEM

namespace PqStealth

section MLKEMHiding

variable {params : Params} (ring : NTTRingOps) (encoding : Encoding params)
  (prims : Primitives params encoding)
  [DecidableEq encoding.EncodedTHat] [DecidableEq encoding.EncodedU]
  [DecidableEq encoding.EncodedV]
  {Aux : Type} [DecidableEq Aux]
  (auxGen : SharedSecret → EncapsulationKey params encoding → Aux)
  (adv : StealthScheme.UnlinkAdv (EncapsulationKey params encoding)
    (Ciphertext params encoding × Aux))

/-- Each shared-secret-hiding term of the ML-KEM stealth scheme is the KEM
IND-CPA advantage of `indCpaAdv … b` against `MLKEM.asKEMScheme`. -/
theorem mlkem_sharedSecretHiding_eq_indCpaAdvantage (b : Bool) :
    sharedSecretHiding (mlkem ring encoding prims) auxGen adv b =
      KEMScheme.IND_CPA_Advantage ProbCompRuntime.probComp
        (indCpaAdv (mlkem ring encoding prims) auxGen adv b) :=
  sharedSecretHiding_eq_indCpaAdvantage _ _ _ b

/-- **The ML-KEM unlinkability bound in IND-CPA form.** `mlkem_unlinkAdvantage_le`
with both hiding terms replaced by VCVio KEM IND-CPA advantages of explicit
reduction adversaries against `MLKEM.asKEMScheme`. Bounding those two terms by
MLWE is exactly the missing upstream lemma described in this module's header;
the remaining two terms (auxiliary-data key independence, ML-KEM anonymity) are
not KEM IND-CPA questions at all. -/
theorem mlkem_unlinkAdvantage_le_indCpa :
    (mlkemStealthScheme ring encoding prims auxGen).unlinkAdvantage adv ≤
      KEMScheme.IND_CPA_Advantage ProbCompRuntime.probComp
        (indCpaAdv (mlkem ring encoding prims) auxGen adv true)
      + auxKeyIndependence (mlkem ring encoding prims) auxGen adv
      + (mlkem ring encoding prims).anonAdvantage (adv.cipherOf auxGen)
      + KEMScheme.IND_CPA_Advantage ProbCompRuntime.probComp
        (indCpaAdv (mlkem ring encoding prims) auxGen adv false) :=
  unlinkAdvantage_ofKEMFull_le_indCpa (mlkem ring encoding prims) auxGen adv

end MLKEMHiding

end PqStealth
