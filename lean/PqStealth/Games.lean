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

/-! ## Hidden-bit games with a bit-indexed branch

VCVio states its hidden-bit decomposition for an explicit `if b then real else
rand`. The games below are indexed by the bit instead — one definition per game
rather than two — so this is the form of
`ProbComp.boolBiasAdvantage_bind_uniformBool_eq_boolDistAdvantage` they use. -/

/-- Bias of a hidden-bit guessing game whose branch is selected by the bit:
the distinguishing advantage between the two branches. -/
theorem ProbComp.boolBiasAdvantage_bind_uniformBool_branch {α : Type} (pref : ProbComp α)
    (branch : Bool → α → ProbComp Bool) :
    (do
      let a ← pref
      let b ← ($ᵗ Bool)
      let z ← branch b a
      pure (b == z)).boolBiasAdvantage
      = (pref >>= branch true).boolDistAdvantage (pref >>= branch false) := by
  have h : (do let a ← pref; let b ← ($ᵗ Bool); let z ← branch b a; pure (b == z))
      = (do
          let a ← pref
          let b ← ($ᵗ Bool)
          let z ← if b then branch true a else branch false a
          pure (b == z)) :=
    bind_congr fun a => bind_congr fun b => by cases b <;> rfl
  rw [h]
  exact ProbComp.boolBiasAdvantage_bind_uniformBool_eq_boolDistAdvantage pref
    (branch true) (branch false)

/-- Distinguishing advantage is symmetric: it is the absolute value of a
difference. Used whenever a game hop is traversed in the opposite direction to
the one a definition fixes. -/
theorem ProbComp.boolDistAdvantage_comm (p q : ProbComp Bool) :
    p.boolDistAdvantage q = q.boolDistAdvantage p :=
  abs_sub_comm _ _

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

/-! ## The false-positive experiment

Detection soundness's counterpart to `CorrectExp`: the scanner is not the
recipient. A quantitative bound on this probability for the real scan is
separate work (it is the view-tag length argument); what is used in `Controls`
is only that a tag-ignoring scan makes it `1`. -/

/-- False-positive experiment: two independent recipients, an announcement
addressed to the second, scanned with the first one's private state. `true` is a
false positive. -/
def FalsePositiveExp : ProbComp Bool := do
  let (_, sk0) ← S.keygen
  let (pk1, _) ← S.keygen
  let c ← S.announce pk1
  S.scan sk0 c

/-! ## Unlinkability (recipient anonymity)

The hidden bit selects which of two recipients an announcement is for; the
adversary sees both public meta-addresses and the challenge announcement and
must guess. This is the anonymity / key-privacy game, NOT message IND-CPA. -/

/-- Unlinkability adversary: given both public meta-addresses and the challenge
announcement, guess which recipient the announcement is for. Depends only on the
public types, not on the scheme, so the same type is also a KEM key-privacy
adversary (`KEMAnonymity`).

A function rather than a two-phase `setup`/`distinguish` structure: the games
are non-adaptive, so the two formulations are interchangeable (see
`docs/announcement-model.md`), and the function form keeps the shared game
prefix free of the adversary — which is what lets the unlinkability and
anonymity prefixes be recognized as the same computation. -/
abbrev UnlinkAdv (MetaPub Announcement : Type) :=
  MetaPub → MetaPub → Announcement → ProbComp Bool

/-- Shared prefix of the unlinkability game: generate two recipients and publish
both public meta-addresses. -/
def unlinkSetup : ProbComp (MetaPub × MetaPub) := do
  let (pk0, _) ← S.keygen
  let (pk1, _) ← S.keygen
  pure (pk0, pk1)

variable (adv : UnlinkAdv MetaPub Announcement)

/-- The branch of the unlinkability game selected by the hidden bit: the
challenge announcement goes to recipient `b`. -/
def unlinkBranch (b : Bool) (a : MetaPub × MetaPub) : ProbComp Bool := do
  let c ← S.announce (if b then a.2 else a.1)
  adv a.1 a.2 c

/-- Unlinkability experiment: flip a hidden bit, announce to the selected
recipient, and return whether the adversary's guess matches. In VCVio's
hidden-bit form so the branch-decomposition lemma applies directly. -/
def UnlinkExp : ProbComp Bool := do
  let a ← S.unlinkSetup
  let b ← ($ᵗ Bool)
  let z ← S.unlinkBranch adv b a
  pure (b == z)

/-- Unlinkability advantage: the bias of the hidden-bit guessing game. -/
noncomputable def unlinkAdvantage : ℝ := (S.UnlinkExp adv).boolBiasAdvantage

/-- **First game hop, sorry-free.** The unlinkability advantage equals the
adversary's advantage in distinguishing an announcement to recipient 1 from
an announcement to recipient 0. This is the definitional heart of anonymity;
what remains for the analysis is to bound the right-hand distinguishing
advantage by ML-KEM anonymity (ANO-CCA, not IND-CCA). -/
theorem unlinkAdvantage_eq_branchDistAdvantage :
    S.unlinkAdvantage adv =
      (S.unlinkSetup >>= S.unlinkBranch adv true).boolDistAdvantage
      (S.unlinkSetup >>= S.unlinkBranch adv false) :=
  ProbComp.boolBiasAdvantage_bind_uniformBool_branch S.unlinkSetup (S.unlinkBranch adv)

end StealthScheme

end PqStealth
