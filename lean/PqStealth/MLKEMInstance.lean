/-
Instantiating the stealth scheme on VCVio's concrete ML-KEM.

The abstract games (Games.lean) and the anonymity reduction (KEMAnonymity.lean)
are generic over a KEM. VCVio ships a concrete ML-KEM whose checked interface is
packaged as `MLKEM.asKEMScheme : KEMScheme ProbComp ...`, over the same
`ProbComp` monad our `KEM` uses. This file bridges the two and instantiates the
full stealth scheme -- discovery via real ML-KEM, announcement = ciphertext plus
auxiliary data derived from the shared secret -- so the proved unlinkability
bound holds for the actual ML-KEM construction.

What this buys: the terms of `unlinkAdvantage_ofKEMFull_le`, specialized here,
are now about VCVio's ML-KEM. The shared-secret-hiding terms are its KEM IND-CPA
advantage, which VCVio's `MLKEM/Security.lean` reduces to MLWE; the anonymity
term is the one link neither VCVio nor FIPS 203 supplies (Grubbs-Maram-Paterson),
i.e. the novel piece. (`MLKEM.ind_cca_security` is a work-in-progress placeholder
in VCVio, so we connect to the ML-KEM scheme and its IND-CPA/MLWE structure, not
to a final CCA theorem.)
-/

import PqStealth.KEMAnonymity
import VCVio.CryptoFoundations.KeyEncapMech
import LatticeCrypto.MLKEM.KEM

open OracleComp OracleSpec MLKEM

namespace PqStealth

/-- Bridge VCVio's `KEMScheme` (over `ProbComp`) to our `KEM`. The fields are
identical; only the type-parameter order differs. -/
def KEM.ofKEMScheme {K PK SK C : Type} (kem : KEMScheme ProbComp K PK SK C) :
    KEM PK SK C K where
  keygen := kem.keygen
  encaps := kem.encaps
  decaps := kem.decaps

section MLKEMStealth

variable {params : Params} (ring : NTTRingOps) (encoding : Encoding params)
  (prims : Primitives params encoding)
  [DecidableEq encoding.EncodedTHat] [DecidableEq encoding.EncodedU]
  [DecidableEq encoding.EncodedV] [SampleableType SharedSecret]
  {Aux : Type}
  (auxGen : SharedSecret → EncapsulationKey params encoding → Aux)

/-- Our `KEM`, backed by VCVio's concrete ML-KEM. -/
def mlkem : KEM (EncapsulationKey params encoding) (DecapsulationKey params encoding)
    (Ciphertext params encoding) SharedSecret :=
  KEM.ofKEMScheme (MLKEM.asKEMScheme ring encoding prims)

/-- The concrete ML-KEM-based post-quantum stealth scheme: discovery via ML-KEM,
announcement = `(ciphertext, auxGen sharedSecret encapsulationKey)` -- the view
tag and stealth address folded in, the latter depending on the recipient's own
key as well as the shared secret. -/
def mlkemStealthScheme :
    StealthScheme (EncapsulationKey params encoding)
      (DecapsulationKey params encoding)
      (Ciphertext params encoding × Aux) :=
  StealthScheme.ofKEMFull (mlkem ring encoding prims) auxGen

/-- **The unlinkability bound on real ML-KEM.** A direct specialization of
`unlinkAdvantage_ofKEMFull_le`: unlinkability of the ML-KEM stealth scheme is
bounded by ML-KEM's anonymity advantage, its two shared-secret-hiding (IND-CPA)
terms, and the auxiliary-data key-independence term. The IND-CPA terms reduce to
MLWE (VCVio); the key-independence term is the blinding argument; the anonymity
term is the open piece. -/
theorem mlkem_unlinkAdvantage_le
    (adv : StealthScheme.UnlinkAdv (EncapsulationKey params encoding)
      (Ciphertext params encoding × Aux)) :
    (mlkemStealthScheme ring encoding prims auxGen).unlinkAdvantage adv ≤
      sharedSecretHidingTrue (mlkem ring encoding prims) auxGen adv
      + auxKeyIndependence (mlkem ring encoding prims) auxGen adv
      + (mlkem ring encoding prims).anonAdvantage (adv.cipherOf auxGen)
      + sharedSecretHidingFalse (mlkem ring encoding prims) auxGen adv :=
  unlinkAdvantage_ofKEMFull_le (mlkem ring encoding prims) auxGen adv

end MLKEMStealth

end PqStealth
