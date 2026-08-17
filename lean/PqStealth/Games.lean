/-
Game-based security definitions for the PQ stealth address scheme, built on
VCVio's OracleComp / ProbComp framework (the same stack the algebraic core
uses). This is the "state the games" layer of the security analysis: it
defines the scheme as an abstract randomized algorithm and writes the
security experiments as probabilistic computations, exactly mirroring VCVio's
own AsymmEncAlg / IND-CPA idiom (CryptoFoundations/AsymmEncAlg).

The headline property for a stealth scheme is UNLINKABILITY (recipient
anonymity): given an announcement you cannot tell which recipient it is for.
That is the key-privacy sibling of IND-CPA -- the hidden bit selects the
RECIPIENT, not the message. We state the game and prove the one structural
fact that holds before any assumption enters: the unlinkability advantage
equals the adversary's advantage in distinguishing an announcement to
recipient 1 from one to recipient 0 (the first game hop). The reduction of
that distinguishing advantage to ML-KEM anonymity (ANO-CCA, not IND-CCA) is
the paper-level work this scaffolding is built to receive.

Abstract in the scheme by design: MetaPub / MetaPriv / Announcement are
opaque, so the definitions commit to no parameter set. Concrete
instantiation with ML-KEM + construction A is future work.
-/

import PqStealth.Blinding
import VCVio.CryptoFoundations.SecExp

open OracleComp OracleSpec

namespace PqStealth

/-! ## The scheme as an abstract randomized algorithm

Mirrors `AsymmEncAlg` (VCVio): the algorithmic data lives in `ProbComp`, and
security experiments are built on top. `announce` is the sender's operation
(produce an announcement addressed to a meta-address); `scan` is the
recipient's detection test. -/

/-- A stealth address scheme: key generation, sender-side announcing, and
recipient-side detection, all as probabilistic computations. -/
structure StealthScheme (MetaPub MetaPriv Announcement : Type) where
  keygen : ProbComp (MetaPub × MetaPriv)
  announce : MetaPub → ProbComp Announcement
  scan : MetaPriv → Announcement → ProbComp Bool

namespace StealthScheme

variable {MetaPub MetaPriv Announcement : Type}
  (S : StealthScheme MetaPub MetaPriv Announcement)

/-! ## Detection completeness

A recipient detects a payment actually addressed to them. This is the
correctness side (cf. VCVio's `CorrectExp` / `PerfectlyCorrect`). -/

/-- Completeness experiment: announce to a freshly generated recipient, then
scan with that recipient's secret; should return `true`. -/
def CorrectExp : ProbComp Bool := do
  let (pk, sk) ← S.keygen
  let c ← S.announce pk
  S.scan sk c

/-- The scheme is perfectly complete when detection of an honestly generated
announcement always succeeds. -/
def PerfectlyComplete : Prop := Pr[= true | S.CorrectExp] = 1

/-! ## Unlinkability (recipient anonymity)

The hidden bit selects which of two recipients an announcement is for; the
adversary sees both public meta-addresses and the challenge announcement and
must guess. This is the anonymity / key-privacy game, NOT message IND-CPA. -/

/-- Two-phase unlinkability adversary: given both public meta-addresses it
prepares state, then given the challenge announcement it guesses the
recipient. Depends only on the public types, not on the scheme. -/
structure UnlinkAdv (MetaPub Announcement : Type) where
  State : Type
  setup : MetaPub → MetaPub → ProbComp State
  distinguish : State → Announcement → ProbComp Bool

variable (adv : UnlinkAdv MetaPub Announcement)

/-- Shared prefix of the unlinkability game: generate two recipients and let
the adversary inspect both public meta-addresses. -/
def unlinkSetup : ProbComp (MetaPub × MetaPub × adv.State) := do
  let (pk0, _) ← S.keygen
  let (pk1, _) ← S.keygen
  let st ← adv.setup pk0 pk1
  pure (pk0, pk1, st)

/-- The `b = 1` branch: the challenge announcement goes to recipient 1. -/
def unlinkBranchTrue (a : MetaPub × MetaPub × adv.State) : ProbComp Bool := do
  let c ← S.announce a.2.1
  adv.distinguish a.2.2 c

/-- The `b = 0` branch: the challenge announcement goes to recipient 0. -/
def unlinkBranchFalse (a : MetaPub × MetaPub × adv.State) : ProbComp Bool := do
  let c ← S.announce a.1
  adv.distinguish a.2.2 c

/-- Unlinkability experiment: flip a hidden bit, announce to the selected
recipient, and return whether the adversary's guess matches. In VCVio's
hidden-bit form so the branch-decomposition lemma applies directly. -/
def UnlinkExp : ProbComp Bool := do
  let a ← S.unlinkSetup adv
  let b ← ($ᵗ Bool)
  let z ← if b then S.unlinkBranchTrue adv a else S.unlinkBranchFalse adv a
  pure (b == z)

/-- Unlinkability advantage: the bias of the hidden-bit guessing game. -/
noncomputable def unlinkAdvantage : ℝ := (S.UnlinkExp adv).boolBiasAdvantage

/-- **First game hop, sorry-free.** The unlinkability advantage equals the
adversary's advantage in distinguishing an announcement to recipient 1 from
an announcement to recipient 0. This is the definitional heart of anonymity;
what remains for the analysis is to bound the right-hand distinguishing
advantage by ML-KEM's anonymity advantage. -/
theorem unlinkAdvantage_eq_branchDistAdvantage :
    S.unlinkAdvantage adv =
      (S.unlinkSetup adv >>= S.unlinkBranchTrue adv).boolDistAdvantage
      (S.unlinkSetup adv >>= S.unlinkBranchFalse adv) :=
  ProbComp.boolBiasAdvantage_bind_uniformBool_eq_boolDistAdvantage
    (S.unlinkSetup adv) (S.unlinkBranchTrue adv) (S.unlinkBranchFalse adv)

end StealthScheme

end PqStealth
