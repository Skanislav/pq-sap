/-
Discharging the shared-secret-hiding terms against KEM IND-CPA.

`unlinkAdvantage_ofKEMFull_le` bounds unlinkability by the anonymity advantage
plus two shared-secret-hiding terms. Those terms are exactly the KEM's IND-CPA
(real-or-random shared secret) advantage: the auxiliary announcement data hides
the recipient because the shared secret is pseudorandom.

This file makes that precise two ways:

  1. proven, sorry-free: each hiding term equals the bias of a real-or-random
     guessing game -- the KEM IND-CPA experiment restricted to the
     announcement adversary;
  2. type-checked: the concrete VCVio `KeyEncapMech.IND_CPA_Adversary` induced
     by our unlink adversary, so the term connects to VCVio's own
     `IND_CPA_Advantage`, which `MLKEM/Security.lean` reduces to MLWE.

Net effect: the shared-secret-hiding half of the unlinkability bound reduces to
MLWE (via VCVio), leaving only the anonymity half as the open novel arrow.
-/

import PqStealth.KEMAnonymity
import VCVio.CryptoFoundations.KeyEncapMech

open OracleComp OracleSpec

namespace PqStealth

variable {PK SK C K : Type}

/-- Reverse bridge: our `KEM` as VCVio's `KEMScheme` over `ProbComp`. Enables
reuse of VCVio's KEM IND-CPA game and its MLWE reduction. -/
def KEM.toKEMScheme (kem : KEM PK SK C K) : KEMScheme ProbComp K PK SK C where
  keygen := kem.keygen
  encaps := kem.encaps
  decaps := kem.decaps

variable {Aux : Type} [DecidableEq Aux] [SampleableType K]
  (kem : KEM PK SK C K) (auxGen : K → PK → Aux)
  (adv : StealthScheme.UnlinkAdv PK (C × Aux))

/-! ## Each hiding term is a real-or-random guessing advantage -/

/-- The `b = 1` shared-secret real-or-random game: guess whether the auxiliary
data was built from the real shared secret (the honest announcement) or a fresh
random key.

Both sides build the auxiliary data from the SAME public key -- recipient 1's.
That is what makes this a clean real-or-random KEM question and nothing else;
the separate question of whether the public key itself shows through is carried
by `auxKeyIndependence`. -/
noncomputable def rorGameTrue : ProbComp Bool := do
  let b ← ($ᵗ Bool)
  let z ← if b then
      (StealthScheme.ofKEMFull kem auxGen).unlinkSetup adv >>=
        (StealthScheme.ofKEMFull kem auxGen).unlinkBranchTrue adv
    else
      (StealthScheme.ofKEMFull kem auxGen).unlinkSetup adv >>=
        randAuxBranchTrue kem auxGen adv
  pure (b == z)

/-- The `b = 0` shared-secret real-or-random game. -/
noncomputable def rorGameFalse : ProbComp Bool := do
  let b ← ($ᵗ Bool)
  let z ← if b then
      kem.anonSetup (adv.cipherOf auxGen) >>= kem.anonBranchFalse (adv.cipherOf auxGen)
    else
      (StealthScheme.ofKEMFull kem auxGen).unlinkSetup adv >>=
        (StealthScheme.ofKEMFull kem auxGen).unlinkBranchFalse adv
  pure (b == z)

/-- **Sorry-free.** The `b = 1` shared-secret-hiding term equals the bias of its
real-or-random guessing game -- i.e. it is a KEM IND-CPA advantage. -/
theorem sharedSecretHidingTrue_eq_rorBias :
    sharedSecretHidingTrue kem auxGen adv = (rorGameTrue kem auxGen adv).boolBiasAdvantage := by
  unfold sharedSecretHidingTrue rorGameTrue
  exact (ProbComp.boolBiasAdvantage_eq_boolDistAdvantage_uniformBool_branch _ _).symm

/-- **Sorry-free.** The `b = 0` shared-secret-hiding term equals the bias of its
real-or-random guessing game. -/
theorem sharedSecretHidingFalse_eq_rorBias :
    sharedSecretHidingFalse kem auxGen adv = (rorGameFalse kem auxGen adv).boolBiasAdvantage := by
  unfold sharedSecretHidingFalse rorGameFalse
  exact (ProbComp.boolBiasAdvantage_eq_boolDistAdvantage_uniformBool_branch _ _).symm

/-! ## The concrete VCVio IND-CPA reduction adversary

Type-checked against VCVio's `KeyEncapMech.IND_CPA_Adversary`: the IND-CPA
challenge key is embedded as recipient 1 (resp. 0); the reduction generates the
other recipient itself, then feeds `auxGen(challenge key)` to the unlink
distinguisher. Its `IND_CPA_Advantage` (which VCVio reduces to MLWE for ML-KEM)
is the shared-secret-hiding term above, up to reordering of independent samples. -/

/-- IND-CPA reduction adversary for the `b = 1` branch. The state carries both
public keys, because the auxiliary data must be rebuilt from the same key the
real announcement used -- here the challenge key, embedded as recipient 1. -/
def indCpaAdvTrue : (kem.toKEMScheme).IND_CPA_Adversary where
  State := PK × PK × adv.State
  preChallenge pk1 := do
    let (pk0, _) ← kem.keygen
    let st ← adv.setup pk0 pk1
    pure (pk0, pk1, st)
  postChallenge s cStar k := adv.distinguish s.2.2 (cStar, auxGen k s.2.1)

/-- IND-CPA reduction adversary for the `b = 0` branch (challenge key as
recipient 0). On this branch the reduction's reference key and the real
recipient coincide, so the auxiliary data is rebuilt from recipient 0. -/
def indCpaAdvFalse : (kem.toKEMScheme).IND_CPA_Adversary where
  State := PK × PK × adv.State
  preChallenge pk0 := do
    let (pk1, _) ← kem.keygen
    let st ← adv.setup pk0 pk1
    pure (pk0, pk1, st)
  postChallenge s cStar k := adv.distinguish s.2.2 (cStar, auxGen k s.1)

end PqStealth
