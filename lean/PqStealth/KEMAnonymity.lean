/-
KEM anonymity (key privacy) and the unlinkability reduction.

The teaching point made concrete: a stealth scheme's UNLINKABILITY reduces to
the KEM's ANONYMITY (does a ciphertext hide which public key it was
encapsulated to), NOT to IND-CCA (which hides the message). VCVio ships ML-KEM
IND-CCA statements (their MLWE reductions are `sorry` at the pinned commit),
but NOT anonymity -- so we state the
anonymity assumption here, in the same shape VCVio uses for its own games, and
prove the reduction.

This file:
  1. defines an abstract `KEM` and its anonymity game (reusing the two-phase
     distinguisher `UnlinkAdv`, whose shape is exactly a key-privacy adversary);
  2. instantiates `StealthScheme` from a KEM, with the announcement modelled as
     the KEM ciphertext (the only recipient-dependent part);
  3. proves, sorry-free, that unlinkability of that scheme EQUALS the KEM's
     anonymity advantage.

Scope of the model: `ofKEM` treats the announcement as just the ciphertext.
`ofKEMFull` below is the faithful version, in which the announcement also
carries a view tag and a stealth address. Those two are NOT alike: the view tag
comes from the shared secret alone, but the stealth address is built from the
recipient's own `rho` and `t` as well. Modelling the auxiliary data as a
function of the shared secret only would understate what an announcement
publishes, so `auxGen` takes the public key too, and the bound gains a term
(`auxKeyIndependence`) for the question that the coarser model could not even
express.

Detection: `ofKEMFull.scan` decapsulates and then RECOMPUTES the auxiliary data
from the recovered shared secret and the recipient's own public key, accepting
only when it matches the announced one. Testing merely that decapsulation
returned `some` would be vacuous on any KEM with implicit rejection -- ML-KEM's
`decaps` is `fun dk c => return some ...` and never rejects, so that test is the
constant `true` and every recipient "detects" every announcement. This is why
the recipient's private state is `SK x PK`: a scanning wallet holds its own
meta-address next to the decapsulation key, and needs both.

Still open beyond this file: anonymity -> MLWE for ML-KEM, the deeper piece
VCVio does not cover (Grubbs-Maram-Paterson), which is where the novel work
sits.
-/

import PqStealth.Games

open OracleComp OracleSpec

namespace PqStealth

/-! ## An abstract KEM -/

/-- A key encapsulation mechanism: key generation, encapsulation (producing a
ciphertext and a shared secret), and decapsulation. -/
structure KEM (PK SK C K : Type) where
  keygen : ProbComp (PK × SK)
  encaps : PK → ProbComp (C × K)
  decaps : SK → C → ProbComp (Option K)

namespace KEM

variable {PK SK C K : Type} (kem : KEM PK SK C K)
  (adv : StealthScheme.UnlinkAdv PK C)

/-! ## Correctness -/

/-- Perfect correctness of a KEM: honest key generation and encapsulation never
fail, and decapsulation of an honestly produced ciphertext returns exactly the
shared secret that was encapsulated.

This is VCVio's `KEMScheme.PerfectlyCorrect`
(`VCVio/CryptoFoundations/KeyEncapMech.lean`) spelled out stage by stage. That
definition is `Pr[= true | CorrectExp] = 1` for the experiment "generate a
keypair, encapsulate, decapsulate, compare"; `probOutput_eq_one_iff` says a
probability-one statement is exactly "never fails" together with "the support is
the single intended value", and the fields below are that pair applied to each
stage. Splitting it this way is what lets the completeness proof consume the
hypothesis pointwise, on the keypair and ciphertext actually drawn. -/
structure PerfectlyCorrect : Prop where
  /-- Honest key generation never fails. -/
  keygen_neverFails : Pr[⊥ | kem.keygen] = 0
  /-- Encapsulation to an honestly generated public key never fails. -/
  encaps_neverFails : ∀ pk sk, (pk, sk) ∈ support kem.keygen → Pr[⊥ | kem.encaps pk] = 0
  /-- Decapsulation recovers the encapsulated shared secret with certainty. -/
  decaps_eq_encapsulated : ∀ pk sk, (pk, sk) ∈ support kem.keygen →
    ∀ c k, (c, k) ∈ support (kem.encaps pk) → Pr[= some k | kem.decaps sk c] = 1

/-! ## Anonymity (key privacy)

The hidden bit selects which of two public keys the challenge ciphertext is
encapsulated to; the adversary, given both public keys and the ciphertext, must
guess. The two-phase distinguisher is exactly `UnlinkAdv PK C`. -/

/-- Shared prefix: two keypairs, adversary inspects both public keys. -/
def anonSetup : ProbComp (PK × PK × adv.State) := do
  let (pk0, _) ← kem.keygen
  let (pk1, _) ← kem.keygen
  let st ← adv.setup pk0 pk1
  pure (pk0, pk1, st)

/-- `b = 1` branch: encapsulate to public key 1. -/
def anonBranchTrue (a : PK × PK × adv.State) : ProbComp Bool := do
  let (c, _) ← kem.encaps a.2.1
  adv.distinguish a.2.2 c

/-- `b = 0` branch: encapsulate to public key 0. -/
def anonBranchFalse (a : PK × PK × adv.State) : ProbComp Bool := do
  let (c, _) ← kem.encaps a.1
  adv.distinguish a.2.2 c

/-- Anonymity experiment in VCVio hidden-bit form. -/
def AnonExp : ProbComp Bool := do
  let a ← kem.anonSetup adv
  let b ← ($ᵗ Bool)
  let z ← if b then kem.anonBranchTrue adv a else kem.anonBranchFalse adv a
  pure (b == z)

/-- Anonymity advantage. -/
noncomputable def anonAdvantage : ℝ := (kem.AnonExp adv).boolBiasAdvantage

/-- The anonymity advantage decomposes into the advantage of distinguishing an
encapsulation to key 1 from one to key 0 -- same VCVio lemma as unlinkability. -/
theorem anonAdvantage_eq_branchDistAdvantage :
    kem.anonAdvantage adv =
      (kem.anonSetup adv >>= kem.anonBranchTrue adv).boolDistAdvantage
      (kem.anonSetup adv >>= kem.anonBranchFalse adv) :=
  ProbComp.boolBiasAdvantage_bind_uniformBool_eq_boolDistAdvantage _ _ _

end KEM

/-! ## The KEM-based stealth scheme and the reduction -/

variable {PK SK C K : Type}

/-- Instantiate a stealth scheme from a KEM: the announcement is the KEM
ciphertext (the recipient-dependent part), and detection tests whether
decapsulation succeeds.

A teaching model for the unlinkability reduction, not the scheme. With nothing
but a ciphertext in the announcement there is nothing for the recipient to check
against, so detection is only as strong as the KEM's rejection behaviour -- and
on a KEM with implicit rejection (ML-KEM) that is no strength at all: `decaps`
never returns `none`, so `scan` is the constant `true`. `ofKEMFull` is the
version with a detectable announcement. -/
def StealthScheme.ofKEM (kem : KEM PK SK C K) : StealthScheme PK SK C where
  keygen := kem.keygen
  announce pk := do
    let (c, _) ← kem.encaps pk
    pure c
  scan sk c := do
    let k ← kem.decaps sk c
    pure k.isSome

/-- **The reduction, sorry-free.** Unlinkability of the KEM-based stealth scheme
equals the KEM's anonymity advantage: with the announcement modelled as the
ciphertext, the two experiments are the same computation. What remains for the
analysis is (a) folding in the view tag / stealth address without leaking the
recipient, and (b) the open `anonymity -> MLWE` step for ML-KEM. -/
theorem unlinkAdvantage_ofKEM_eq_anonAdvantage
    (kem : KEM PK SK C K) (adv : StealthScheme.UnlinkAdv PK C) :
    (StealthScheme.ofKEM kem).unlinkAdvantage adv = kem.anonAdvantage adv := by
  unfold StealthScheme.unlinkAdvantage KEM.anonAdvantage
  congr 1
  simp only [StealthScheme.UnlinkExp, KEM.AnonExp, StealthScheme.unlinkSetup,
    KEM.anonSetup, StealthScheme.unlinkBranchTrue, StealthScheme.unlinkBranchFalse,
    KEM.anonBranchTrue, KEM.anonBranchFalse, StealthScheme.ofKEM, bind_assoc,
    pure_bind]

/-! ## Folding in the view tag and stealth address

The real announcement is not just the ciphertext: it also carries a view tag and
a stealth address. Model both with `auxGen : K -> PK -> Aux`, so the
announcement is `(ciphertext, auxGen sharedSecret pk)` and detection still works
(the recipient recomputes the shared secret). The public-key argument is what
makes this faithful: the view tag is a function of the shared secret alone, but
the stealth address folds in the recipient's own `rho` and `t`.

Unlinkability then rests on three separate things, and the bound below names
each rather than merging them:

  * the auxiliary data hides the recipient insofar as the shared secret is
    pseudorandom -- a KEM IND-CPA question (VCVio's
    `KeyEncapMech.IND_CPA_Advantage`, proved equal in `SharedSecretHiding`;
    its reduction to MLWE is the paper-level FO step), one term per branch;
  * once the secret is idealized, the auxiliary data must still not betray WHICH
    public key produced it -- `auxKeyIndependence`, which for this scheme is the
    blinding argument (`A * s' + e'` masking `t`) and is again MLWE, not a KEM
    property;
  * and the ciphertext itself must hide the recipient -- KEM anonymity.

The middle term is the one a shared-secret-only model cannot state at all. -/

variable {Aux : Type} [SampleableType K]

/-- Stealth scheme from a KEM with a full announcement: the ciphertext plus
auxiliary data (view tag, stealth address).

`auxGen` takes the recipient's public key as well as the shared secret, and
that second argument is load-bearing rather than cosmetic. The view tag is a
function of the shared secret alone, but the stealth address is not: it is
`keccak(pack_pk(rho, Power2Round(A * s' + e' + t)))`, in which `rho` and `t`
are the RECIPIENT's own meta-address material and only `(s', e')` come from the
shared secret. An announcement therefore carries recipient-dependent data even
once the shared secret is idealized, and a model with `auxGen : K -> Aux`
understates what is published.

Detection recomputes: the recipient decapsulates, rebuilds the auxiliary data
from the recovered shared secret and its OWN public key, and accepts only on a
match. That is what a scanner actually does, and it is why the private state is
`SK x PK` -- the decapsulation key alone does not determine the tag. -/
def StealthScheme.ofKEMFull [DecidableEq Aux] (kem : KEM PK SK C K)
    (auxGen : K → PK → Aux) : StealthScheme PK (SK × PK) (C × Aux) where
  keygen := do
    let ks ← kem.keygen
    pure (ks.1, (ks.2, ks.1))
  announce pk := do
    let ck ← kem.encaps pk
    pure (ck.1, auxGen ck.2 pk)
  scan sk ca := do
    let k? ← kem.decaps sk.1 ca.1
    pure (k?.elim false fun k => decide (ca.2 = auxGen k sk.2))

omit [SampleableType K] in
/-- **Detection completeness, sorry-free.** A recipient always detects an
announcement addressed to them, given only that the KEM is perfectly correct.

The content is that the two sides compute the same auxiliary data: the sender
builds it from the encapsulated shared secret and the recipient's public key,
the recipient rebuilds it from the decapsulated secret and its own public key,
and KEM correctness identifies the two secrets. The correctness hypothesis is
doing the work: `deadKEM_ofKEMFull_not_perfectlyComplete` (GameControls)
isolates the decapsulation clause and proves the conclusion false without it. -/
theorem perfectlyComplete_ofKEMFull [DecidableEq Aux] (kem : KEM PK SK C K)
    (auxGen : K → PK → Aux) (hkem : kem.PerfectlyCorrect) :
    (StealthScheme.ofKEMFull kem auxGen).PerfectlyComplete := by
  have hCE : (StealthScheme.ofKEMFull kem auxGen).CorrectExp =
      (do let ks ← kem.keygen
          let ck ← kem.encaps ks.1
          let k? ← kem.decaps ks.2 ck.1
          pure (k?.elim false fun k => decide (auxGen ck.2 ks.1 = auxGen k ks.1))) := by
    simp only [StealthScheme.CorrectExp, StealthScheme.ofKEMFull, bind_assoc, pure_bind]
  have hdec : ∀ ks ∈ support kem.keygen, ∀ ck ∈ support (kem.encaps ks.1),
      Pr[⊥ | kem.decaps ks.2 ck.1] = 0 ∧
        support (kem.decaps ks.2 ck.1) = {some ck.2} := fun ks hks ck hck =>
    probOutput_eq_one_iff.1 (hkem.decaps_eq_encapsulated ks.1 ks.2 (by simpa using hks)
      ck.1 ck.2 (by simpa using hck))
  rw [StealthScheme.PerfectlyComplete, hCE, probOutput_eq_one_iff_forall]
  refine ⟨?_, ?_⟩
  · simp only [probFailure_bind_eq_zero_iff, probFailure_pure, implies_true, and_true]
    exact ⟨hkem.keygen_neverFails, fun ks hks =>
      ⟨hkem.encaps_neverFails ks.1 ks.2 (by simpa using hks), fun ck hck =>
        (hdec ks hks ck hck).1⟩⟩
  · intro y hy
    simp only [support_bind, support_pure, Set.mem_iUnion, Set.mem_singleton_iff] at hy
    obtain ⟨ks, hks, ck, hck, k?, hk?, rfl⟩ := hy
    rw [(hdec ks hks ck hck).2] at hk?
    simp only [Set.mem_singleton_iff] at hk?
    subst hk?
    simp

/-- The ciphertext-anonymity adversary induced by a full-announcement
adversary: it synthesizes the auxiliary data from a FRESH random shared secret
and a FIXED public key -- recipient 0, which the anonymity game hands it during
setup. Both choices carry weight. The random secret removes the dependence on
the real encapsulation; the fixed key is what makes the reduction constructible
at all, since a derived adversary cannot consult "whichever key the challenger
used" without already knowing the hidden bit. -/
def StealthScheme.UnlinkAdv.cipherOf
    (adv : StealthScheme.UnlinkAdv PK (C × Aux)) (auxGen : K → PK → Aux) :
    StealthScheme.UnlinkAdv PK C where
  State := PK × adv.State
  setup pk0 pk1 := do
    let st ← adv.setup pk0 pk1
    pure (pk0, st)
  distinguish st c := do
    let k' ← ($ᵗ K)
    adv.distinguish st.2 (c, auxGen k' st.1)

variable (kem : KEM PK SK C K) (auxGen : K → PK → Aux)
  (adv : StealthScheme.UnlinkAdv PK (C × Aux))

/-- The intermediate game on the `b = 1` branch: the challenge ciphertext still
goes to recipient 1, and the auxiliary data is still built from recipient 1's
own public key, but from a fresh random shared secret rather than the real one.
This game is what separates the two distinct assumptions that a
shared-secret-only model silently merged into one term. -/
def randAuxBranchTrue (a : PK × PK × adv.State) : ProbComp Bool := do
  let (c, _) ← kem.encaps a.2.1
  let k' ← ($ᵗ K)
  adv.distinguish a.2.2 (c, auxGen k' a.2.1)

variable [DecidableEq Aux]

/-- Shared-secret-hiding advantage on the `b = 1` branch: distinguishing an
announcement whose auxiliary data uses the REAL shared secret from one whose
auxiliary data uses a fresh RANDOM key. This is a KEM IND-CPA (real-or-random)
advantage (`sharedSecretHidingTrue_eq_indCpaAdvantage`); reducing that to
MLWE is the paper-level step. -/
noncomputable def sharedSecretHidingTrue : ℝ :=
  ((StealthScheme.ofKEMFull kem auxGen).unlinkSetup adv >>=
      (StealthScheme.ofKEMFull kem auxGen).unlinkBranchTrue adv).boolDistAdvantage
    ((StealthScheme.ofKEMFull kem auxGen).unlinkSetup adv >>=
      randAuxBranchTrue kem auxGen adv)

/-- **The term the shared-secret-only model was missing.** Even after the shared
secret is replaced by a fresh random key, the auxiliary data is still computed
from a public key -- recipient 1's on one side, recipient 0's on the other. This
advantage measures whether that difference is observable.

It is a genuinely separate assumption from shared-secret hiding, and for this
scheme it is where the blinding does its work: with `(s', e')` drawn from a
random secret, `A * s' + e' + t` masks the recipient's `t`, which is an MLWE
statement rather than a statement about the KEM. A model whose auxiliary data
ignores the public key cannot see this term at all -- it is not that the term
was small, it is that it was invisible. -/
noncomputable def auxKeyIndependence : ℝ :=
  ((StealthScheme.ofKEMFull kem auxGen).unlinkSetup adv >>=
      randAuxBranchTrue kem auxGen adv).boolDistAdvantage
    (kem.anonSetup (adv.cipherOf auxGen) >>=
      kem.anonBranchTrue (adv.cipherOf auxGen))

/-- Shared-secret-hiding advantage on the `b = 0` branch (see
`sharedSecretHidingTrue`). -/
noncomputable def sharedSecretHidingFalse : ℝ :=
  (kem.anonSetup (adv.cipherOf auxGen) >>=
      kem.anonBranchFalse (adv.cipherOf auxGen)).boolDistAdvantage
    ((StealthScheme.ofKEMFull kem auxGen).unlinkSetup adv >>=
      (StealthScheme.ofKEMFull kem auxGen).unlinkBranchFalse adv)

/-- **The faithful reduction, sorry-free.** With the view tag and stealth
address folded in, unlinkability is bounded by the KEM's anonymity advantage
plus a shared-secret-hiding term per branch. The auxiliary data hides the
recipient exactly insofar as the shared secret is pseudorandom; when those
hiding terms are negligible (KEM IND-CPA, assumed -> MLWE), unlinkability collapses back
to anonymity. Proved by the triangle inequality over the intermediate games
that replace the real shared secret with a random one. -/
theorem unlinkAdvantage_ofKEMFull_le :
    (StealthScheme.ofKEMFull kem auxGen).unlinkAdvantage adv ≤
      sharedSecretHidingTrue kem auxGen adv
      + auxKeyIndependence kem auxGen adv
      + kem.anonAdvantage (adv.cipherOf auxGen)
      + sharedSecretHidingFalse kem auxGen adv := by
  rw [StealthScheme.unlinkAdvantage_eq_branchDistAdvantage,
    KEM.anonAdvantage_eq_branchDistAdvantage]
  unfold sharedSecretHidingTrue auxKeyIndependence sharedSecretHidingFalse
  set Pt := (StealthScheme.ofKEMFull kem auxGen).unlinkSetup adv >>=
    (StealthScheme.ofKEMFull kem auxGen).unlinkBranchTrue adv
  set Pf := (StealthScheme.ofKEMFull kem auxGen).unlinkSetup adv >>=
    (StealthScheme.ofKEMFull kem auxGen).unlinkBranchFalse adv
  set Mt := (StealthScheme.ofKEMFull kem auxGen).unlinkSetup adv >>=
    randAuxBranchTrue kem auxGen adv
  set Qt := kem.anonSetup (adv.cipherOf auxGen) >>=
    kem.anonBranchTrue (adv.cipherOf auxGen)
  set Qf := kem.anonSetup (adv.cipherOf auxGen) >>=
    kem.anonBranchFalse (adv.cipherOf auxGen)
  calc Pt.boolDistAdvantage Pf
      ≤ Pt.boolDistAdvantage Mt + Mt.boolDistAdvantage Pf :=
        ProbComp.boolDistAdvantage_triangle Pt Mt Pf
    _ ≤ Pt.boolDistAdvantage Mt + (Mt.boolDistAdvantage Qt + Qt.boolDistAdvantage Pf) := by
        gcongr
        exact ProbComp.boolDistAdvantage_triangle Mt Qt Pf
    _ ≤ Pt.boolDistAdvantage Mt + (Mt.boolDistAdvantage Qt
          + (Qt.boolDistAdvantage Qf + Qf.boolDistAdvantage Pf)) := by
        gcongr
        exact ProbComp.boolDistAdvantage_triangle Qt Qf Pf
    _ = Pt.boolDistAdvantage Mt + Mt.boolDistAdvantage Qt
          + Qt.boolDistAdvantage Qf + Qf.boolDistAdvantage Pf := by
        ring

end PqStealth
