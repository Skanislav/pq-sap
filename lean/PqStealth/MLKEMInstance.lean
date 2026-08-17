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
are now about VCVio's ML-KEM. The shared-secret-hiding terms are exactly its
KEM IND-CPA advantage (`SharedSecretHiding`, `SharedSecretHidingMLWE`); the
anonymity term is the one link neither VCVio nor FIPS 203 supplies
(Grubbs-Maram-Paterson), i.e. the novel piece. Note that VCVio's own ML-KEM
security theorems (`kpke_ind_cpa_security`, `kpke_delta_correct`,
`ind_cca_security` in `LatticeCrypto/MLKEM/Security.lean`) are `sorry`
placeholders at the pinned commit and concern K-PKE rather than the KEM, so
the KEM-IND-CPA -> MLWE step is NOT machine-checked anywhere; the exact missing
lemma is recorded in `SharedSecretHidingMLWE`.
-/

import PqStealth.KEMAnonymity
import VCVio.CryptoFoundations.KeyEncapMech
import LatticeCrypto.MLKEM.KEM

open OracleComp OracleSpec MLKEM

namespace PqStealth

section MLKEMStealth

variable {params : Params} (ring : NTTRingOps) (encoding : Encoding params)
  (prims : Primitives params encoding)
  [DecidableEq encoding.EncodedTHat] [DecidableEq encoding.EncodedU]
  [DecidableEq encoding.EncodedV]
  {Aux : Type} [DecidableEq Aux]
  (auxGen : SharedSecret → EncapsulationKey params encoding → Aux)

/-- Our `KEM`, backed by VCVio's concrete ML-KEM. Since `KEM` is `KEMScheme`
over `ProbComp` with the type arguments reordered, this is `MLKEM.asKEMScheme`
itself, not a transport of it. -/
def mlkem : KEM (EncapsulationKey params encoding) (DecapsulationKey params encoding)
    (Ciphertext params encoding) SharedSecret :=
  MLKEM.asKEMScheme ring encoding prims

/-- The concrete ML-KEM-based post-quantum stealth scheme: discovery via ML-KEM,
announcement = `(ciphertext, auxGen sharedSecret encapsulationKey)` -- the view
tag and stealth address folded in, the latter depending on the recipient's own
key as well as the shared secret. -/
def mlkemStealthScheme :
    StealthScheme (EncapsulationKey params encoding)
      (DecapsulationKey params encoding × EncapsulationKey params encoding)
      (Ciphertext params encoding × Aux) :=
  StealthScheme.ofKEMFull (mlkem ring encoding prims) auxGen

/-- **The unlinkability bound on real ML-KEM.** A direct specialization of
`unlinkAdvantage_ofKEMFull_le`: unlinkability of the ML-KEM stealth scheme is
bounded by ML-KEM's anonymity advantage, its two shared-secret-hiding (IND-CPA)
terms, and the auxiliary-data key-independence term. The IND-CPA terms are
VCVio's `KEMScheme.IND_CPA_Advantage` on the nose (`SharedSecretHidingMLWE`);
their reduction to MLWE is not yet available in VCVio (see the module
docstring); the key-independence term is the blinding argument
(`ConstructionA`); the anonymity term is the open piece. -/
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
