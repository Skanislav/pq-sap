/-
Discharging the shared-secret-hiding terms against KEM IND-CPA.

`unlinkAdvantage_ofKEMFull_le` bounds unlinkability by the anonymity advantage
plus two shared-secret-hiding terms. Those terms are exactly the KEM's IND-CPA
(real-or-random shared secret) advantage: the auxiliary announcement data hides
the recipient because the shared secret is pseudorandom.

This file proves that identity, sorry-free, in two steps:

  1. each hiding term is the bias of a real-or-random guessing game -- the KEM
     IND-CPA experiment restricted to the announcement adversary;
  2. that bias equals VCVio's own `KEMScheme.IND_CPA_Advantage` of a concrete
     reduction adversary against `KEM.toKEMScheme`. The two experiments draw the
     same independent samples (two keypairs, the hidden bit, the encapsulation,
     an idealized shared secret) in different orders and with one draw left
     unused on one branch; `OracleComp`'s `bind` is a syntactic constructor, so
     neither reordering nor dropping holds on the nose, but both hold after
     `evalDist`, which is all an advantage sees.

Net effect: the shared-secret-hiding half of the unlinkability bound IS a KEM
IND-CPA advantage in VCVio's own formulation, so any bound proved for
`KEMScheme.IND_CPA_Advantage` transfers to it verbatim.

What is NOT proved here, because VCVio does not supply it: a bound on
`KEMScheme.IND_CPA_Advantage` for ML-KEM in terms of MLWE.
`LatticeCrypto/MLKEM/Security.lean` offers `kpke_ind_cpa_security`, which is
about `AsymmEncAlg.IND_CPA_advantage` of K-PKE rather than the KEM, and is
itself `sorry` upstream. `PqStealth/SharedSecretHidingMLWE.lean` records the
exact shape of the missing lemma and specializes the equalities below to
`MLKEM.asKEMScheme`, so that the composition is a one-line `calc` the day the
lemma lands.
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

variable {Aux : Type} [SampleableType K]
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

Built against VCVio's `KeyEncapMech.IND_CPA_Adversary`: the IND-CPA challenge
key is embedded as recipient 1 (resp. 0); the reduction generates the other
recipient itself, then feeds `auxGen(challenge key)` to the unlink
distinguisher. Its `IND_CPA_Advantage` is the corresponding shared-secret-hiding
term -- proved below. -/

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

/-! ## Distribution-level bridges

The reduction games and the real-or-random games differ only in the order of
independent draws and in one draw that a branch ignores. `OracleComp`'s `bind`
is a free-monad constructor, so neither difference is a definitional equality;
both vanish under `evalDist`. -/

section Bridges

/-- An unused uniform draw does not change a computation's output distribution. -/
theorem evalDist_uniformSample_bind_const {α γ : Type} [SampleableType α] (p : ProbComp γ) :
    𝒟[(($ᵗ α) >>= fun _ => p)] = 𝒟[p] := by
  refine evalDist_ext fun x => ?_
  simp only [probOutput_bind_const, probFailure_of_liftM_PMF, tsub_zero, one_mul]

/-- An independent draw may be pulled to the front of a three-step prefix. -/
theorem evalDist_bind_pull_front {α β γ δ ζ : Type}
    (oa : ProbComp α) (ob : α → ProbComp β) (oc : α → β → ProbComp γ)
    (od : ProbComp δ) (k : α → β → γ → δ → ProbComp ζ) :
    𝒟[(do let a ← oa; let b ← ob a; let c ← oc a b; let d ← od; k a b c d)] =
      𝒟[(do let d ← od; let a ← oa; let b ← ob a; let c ← oc a b; k a b c d)] := by
  calc 𝒟[(do let a ← oa; let b ← ob a; let c ← oc a b; let d ← od; k a b c d)]
      = 𝒟[(do let a ← oa; let b ← ob a; let d ← od; let c ← oc a b; k a b c d)] := by
        refine evalDist_bind_congr' _ fun a => evalDist_bind_congr' _ fun b => ?_
        exact evalDist_bind_bind_swap (oc a b) od fun c d => k a b c d
    _ = 𝒟[(do let a ← oa; let d ← od; let b ← ob a; let c ← oc a b; k a b c d)] := by
        refine evalDist_bind_congr' _ fun a => ?_
        exact evalDist_bind_bind_swap (ob a) od fun b d => oc a b >>= fun c => k a b c d
    _ = 𝒟[(do let d ← od; let a ← oa; let b ← ob a; let c ← oc a b; k a b c d)] :=
        evalDist_bind_bind_swap oa od _

/-- Boolean games with the same output distribution have the same bias. -/
theorem boolBiasAdvantage_congr {p q : ProbComp Bool} (h : 𝒟[p] = 𝒟[q]) :
    p.boolBiasAdvantage = q.boolBiasAdvantage := by
  simp only [ProbComp.boolBiasAdvantage, probOutput_def, h]

end Bridges

/-! ## The hiding terms ARE VCVio IND-CPA advantages

Both sides are put in a common normal form: hidden bit first, then the two
keypairs in the order recipient 0, recipient 1, then the challenge
encapsulation, then the idealized shared secret. VCVio's game draws the
challenge keypair first and the hidden bit after the adversary's pre-challenge
phase; the real-or-random game draws the bit first and never draws the
idealized secret on the real branch. -/

/-- Normal form of the `b = 1` reduction game: hidden bit first, challenge
keypair (recipient 1) drawn after recipient 0, and the idealized shared secret
drawn on both branches. -/
noncomputable def rorNormalFormTrue : ProbComp Bool := do
  let b ← ($ᵗ Bool)
  let pk0 ← kem.keygen
  let pk1 ← kem.keygen
  let st ← adv.setup pk0.1 pk1.1
  let ck ← kem.encaps pk1.1
  let kRand ← ($ᵗ K)
  let z ← adv.distinguish st (ck.1, auxGen (if b then ck.2 else kRand) pk1.1)
  pure (b == z)

/-- Normal form of the `b = 0` reduction game, in which the challenge
encapsulation goes to recipient 0. Note the orientation: `b = 1` is the REAL
shared secret, matching VCVio's convention rather than `rorGameFalse`'s. -/
noncomputable def rorNormalFormFalse : ProbComp Bool := do
  let b ← ($ᵗ Bool)
  let pk0 ← kem.keygen
  let pk1 ← kem.keygen
  let st ← adv.setup pk0.1 pk1.1
  let ck ← kem.encaps pk0.1
  let kRand ← ($ᵗ K)
  let z ← adv.distinguish st (ck.1, auxGen (if b then ck.2 else kRand) pk0.1)
  pure (b == z)

/-- The `b = 1` real-or-random game has the normal form's output distribution:
on the real branch the idealized secret is drawn and ignored. -/
theorem evalDist_rorGameTrue_eq_normalForm :
    𝒟[rorGameTrue kem auxGen adv] = 𝒟[rorNormalFormTrue kem auxGen adv] := by
  unfold rorGameTrue rorNormalFormTrue
  refine evalDist_bind_congr' _ fun b => ?_
  cases b with
  | true =>
    simp only [StealthScheme.unlinkSetup, StealthScheme.unlinkBranchTrue,
      StealthScheme.ofKEMFull, bind_assoc, pure_bind, if_true]
    refine evalDist_bind_congr' _ fun pk0 => evalDist_bind_congr' _ fun pk1 =>
      evalDist_bind_congr' _ fun st => evalDist_bind_congr' _ fun ck => ?_
    exact (evalDist_uniformSample_bind_const _).symm
  | false =>
    simp only [StealthScheme.unlinkSetup, randAuxBranchTrue,
      StealthScheme.ofKEMFull, bind_assoc, pure_bind, Bool.false_eq_true, if_false]

/-- VCVio's IND-CPA game for the `b = 1` reduction adversary is the normal form:
the two keypair draws commute, and the hidden bit commutes to the front past the
whole pre-challenge phase. -/
theorem indCpaGameTrue_eq_evalDist_normalForm :
    KEMScheme.IND_CPA_Game ProbCompRuntime.probComp (indCpaAdvTrue kem auxGen adv) =
      𝒟[rorNormalFormTrue kem auxGen adv] := by
  have hgame : KEMScheme.IND_CPA_Game ProbCompRuntime.probComp (indCpaAdvTrue kem auxGen adv) =
      𝒟[(do
        let pk1 ← kem.keygen
        let pk0 ← kem.keygen
        let st ← adv.setup pk0.1 pk1.1
        let b ← ($ᵗ Bool)
        let ck ← kem.encaps pk1.1
        let kRand ← ($ᵗ K)
        let z ← adv.distinguish st (ck.1, auxGen (if b then ck.2 else kRand) pk1.1)
        pure (b == z) : ProbComp Bool)] := by
    simp only [KEMScheme.IND_CPA_Game, indCpaAdvTrue, KEM.toKEMScheme, bind_assoc, pure_bind,
      ProbCompRuntime.probComp, ProbCompRuntime.liftProbComp, ProbCompLift.id]
    rfl
  rw [hgame, evalDist_bind_bind_swap kem.keygen kem.keygen
    (fun pk1 pk0 => do
      let st ← adv.setup pk0.1 pk1.1
      let b ← ($ᵗ Bool)
      let ck ← kem.encaps pk1.1
      let kRand ← ($ᵗ K)
      let z ← adv.distinguish st (ck.1, auxGen (if b then ck.2 else kRand) pk1.1)
      pure (b == z))]
  exact evalDist_bind_pull_front kem.keygen (fun _ => kem.keygen)
    (fun pk0 pk1 => adv.setup pk0.1 pk1.1) ($ᵗ Bool)
    (fun _pk0 pk1 st b => do
      let ck ← kem.encaps pk1.1
      let kRand ← ($ᵗ K)
      let z ← adv.distinguish st (ck.1, auxGen (if b then ck.2 else kRand) pk1.1)
      pure (b == z))

/-- **The glue, proved.** The `b = 1` shared-secret-hiding term is exactly the
VCVio KEM IND-CPA advantage of the reduction adversary `indCpaAdvTrue`. -/
theorem sharedSecretHidingTrue_eq_indCpaAdvantage :
    sharedSecretHidingTrue kem auxGen adv =
      KEMScheme.IND_CPA_Advantage ProbCompRuntime.probComp (indCpaAdvTrue kem auxGen adv) := by
  rw [sharedSecretHidingTrue_eq_rorBias, KEMScheme.IND_CPA_Advantage,
    indCpaGameTrue_eq_evalDist_normalForm,
    boolBiasAdvantage_congr (evalDist_rorGameTrue_eq_normalForm kem auxGen adv)]
  rfl

/-- The `b = 0` normal form's bias is the `b = 0` shared-secret-hiding term. The
normal form puts the real shared secret on `b = 1` while `rorGameFalse` puts it
on `b = 0`; the two games are mirror images, so their output distributions
differ but their biases -- absolute values of the same difference -- agree. -/
theorem boolBiasAdvantage_rorNormalFormFalse :
    (rorNormalFormFalse kem auxGen adv).boolBiasAdvantage =
      sharedSecretHidingFalse kem auxGen adv := by
  have hbranch : 𝒟[(do
      let b ← ($ᵗ Bool)
      let z ← if b then
          (StealthScheme.ofKEMFull kem auxGen).unlinkSetup adv >>=
            (StealthScheme.ofKEMFull kem auxGen).unlinkBranchFalse adv
        else
          kem.anonSetup (adv.cipherOf auxGen) >>= kem.anonBranchFalse (adv.cipherOf auxGen)
      pure (b == z) : ProbComp Bool)] = 𝒟[rorNormalFormFalse kem auxGen adv] := by
    unfold rorNormalFormFalse
    refine evalDist_bind_congr' _ fun b => ?_
    cases b with
    | true =>
      simp only [StealthScheme.unlinkSetup, StealthScheme.unlinkBranchFalse,
        StealthScheme.ofKEMFull, bind_assoc, pure_bind, if_true]
      refine evalDist_bind_congr' _ fun pk0 => evalDist_bind_congr' _ fun pk1 =>
        evalDist_bind_congr' _ fun st => evalDist_bind_congr' _ fun ck => ?_
      exact (evalDist_uniformSample_bind_const _).symm
    | false =>
      simp only [KEM.anonSetup, KEM.anonBranchFalse, StealthScheme.UnlinkAdv.cipherOf,
        bind_assoc, pure_bind, Bool.false_eq_true, if_false]
  rw [← boolBiasAdvantage_congr hbranch,
    ProbComp.boolBiasAdvantage_eq_boolDistAdvantage_uniformBool_branch]
  unfold sharedSecretHidingFalse ProbComp.boolDistAdvantage
  exact abs_sub_comm _ _

/-- VCVio's IND-CPA game for the `b = 0` reduction adversary is the normal form.
Here the challenge keypair is already recipient 0, so only the hidden bit has to
commute to the front. -/
theorem indCpaGameFalse_eq_evalDist_normalForm :
    KEMScheme.IND_CPA_Game ProbCompRuntime.probComp (indCpaAdvFalse kem auxGen adv) =
      𝒟[rorNormalFormFalse kem auxGen adv] := by
  have hgame : KEMScheme.IND_CPA_Game ProbCompRuntime.probComp (indCpaAdvFalse kem auxGen adv) =
      𝒟[(do
        let pk0 ← kem.keygen
        let pk1 ← kem.keygen
        let st ← adv.setup pk0.1 pk1.1
        let b ← ($ᵗ Bool)
        let ck ← kem.encaps pk0.1
        let kRand ← ($ᵗ K)
        let z ← adv.distinguish st (ck.1, auxGen (if b then ck.2 else kRand) pk0.1)
        pure (b == z) : ProbComp Bool)] := by
    simp only [KEMScheme.IND_CPA_Game, indCpaAdvFalse, KEM.toKEMScheme, bind_assoc, pure_bind,
      ProbCompRuntime.probComp, ProbCompRuntime.liftProbComp, ProbCompLift.id]
    rfl
  rw [hgame]
  exact evalDist_bind_pull_front kem.keygen (fun _ => kem.keygen)
    (fun pk0 pk1 => adv.setup pk0.1 pk1.1) ($ᵗ Bool)
    (fun pk0 _pk1 st b => do
      let ck ← kem.encaps pk0.1
      let kRand ← ($ᵗ K)
      let z ← adv.distinguish st (ck.1, auxGen (if b then ck.2 else kRand) pk0.1)
      pure (b == z))

/-- **The glue, proved.** The `b = 0` shared-secret-hiding term is exactly the
VCVio KEM IND-CPA advantage of the reduction adversary `indCpaAdvFalse`. -/
theorem sharedSecretHidingFalse_eq_indCpaAdvantage :
    sharedSecretHidingFalse kem auxGen adv =
      KEMScheme.IND_CPA_Advantage ProbCompRuntime.probComp (indCpaAdvFalse kem auxGen adv) := by
  rw [← boolBiasAdvantage_rorNormalFormFalse, KEMScheme.IND_CPA_Advantage,
    indCpaGameFalse_eq_evalDist_normalForm]
  rfl

/-- **The unlinkability bound with the hiding terms discharged.** Restatement of
`unlinkAdvantage_ofKEMFull_le` in which both shared-secret-hiding terms are KEM
IND-CPA advantages, in VCVio's own formulation, of explicit reduction
adversaries. What is left are the two genuinely non-IND-CPA terms: the auxiliary
data's independence of the recipient's key (the blinding argument) and the KEM's
anonymity. -/
theorem unlinkAdvantage_ofKEMFull_le_indCpa :
    (StealthScheme.ofKEMFull kem auxGen).unlinkAdvantage adv ≤
      KEMScheme.IND_CPA_Advantage ProbCompRuntime.probComp (indCpaAdvTrue kem auxGen adv)
      + auxKeyIndependence kem auxGen adv
      + kem.anonAdvantage (adv.cipherOf auxGen)
      + KEMScheme.IND_CPA_Advantage ProbCompRuntime.probComp (indCpaAdvFalse kem auxGen adv) := by
  rw [← sharedSecretHidingTrue_eq_indCpaAdvantage, ← sharedSecretHidingFalse_eq_indCpaAdvantage]
  exact unlinkAdvantage_ofKEMFull_le kem auxGen adv

end PqStealth
