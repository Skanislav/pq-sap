import PqStealth.Blinding
import VCVio.CryptoFoundations.SecExp

/-!
# The stealth scheme as a game

Proved: `StealthScheme` as an abstract randomized algorithm over VCVio's
`ProbComp` (mirroring its own `AsymmEncAlg` idiom); detection completeness and
the false-positive experiment; unlinkability -- recipient anonymity -- as a
hidden-bit game, and the first hop, `unlinkAdvantage_eq_branchDistAdvantage`:
the advantage IS the advantage of distinguishing an announcement to recipient 1
from one to recipient 0.

Assumed: nothing. The hidden bit selects the RECIPIENT, not the message, so
this is key privacy, not IND-CPA. See `docs/announcement-model.md`.
-/

open OracleComp OracleSpec

namespace PqStealth

/-! ## Hidden-bit games with a bit-indexed branch

The games below are indexed by the hidden bit rather than written as an explicit
`if b then real else rand`, so this is the form of VCVio's decomposition lemma
they need. -/

/-- Bias of a hidden-bit guessing game whose branch is selected by the bit:
the distinguishing advantage between the two branches. (Scoped under `PqStealth`
so a future upstream lemma of the same name cannot clash; upstream candidate,
see `docs/vcvio-upstream.md`.) -/
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

/-! ## The scheme as an abstract randomized algorithm -/

/-- A stealth address scheme: key generation, sender-side announcing, and
recipient-side detection, all as probabilistic computations. -/
structure StealthScheme (MetaPub MetaPriv Announcement : Type) where
  /-- Recipient key generation: a meta-address and its private counterpart. -/
  keygen : ProbComp (MetaPub × MetaPriv)
  /-- Sender side: publish an announcement for a recipient's meta-address. -/
  announce : MetaPub → ProbComp Announcement
  /-- Recipient side: decide whether an announcement is addressed to us. -/
  scan : MetaPriv → Announcement → ProbComp Bool

namespace StealthScheme

variable {MetaPub MetaPriv Announcement : Type}
  (S : StealthScheme MetaPub MetaPriv Announcement)

/-! ## Detection completeness -/

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
recipient. Quantitative bounds for the real scans live in `Soundness`. -/

/-- False-positive experiment: two independent recipients, an announcement
addressed to the second, scanned with the first one's private state. `true` is a
false positive. -/
def FalsePositiveExp : ProbComp Bool := do
  let (_, sk0) ← S.keygen
  let (pk1, _) ← S.keygen
  let c ← S.announce pk1
  S.scan sk0 c

/-- False-positive rate: how often a non-recipient's scan fires. `.toReal`
because every advantage in the development is an `ℝ`, and this number is added
to distinguishing advantages in `Soundness`. -/
noncomputable def falsePositiveRate : ℝ := (Pr[= true | S.FalsePositiveExp]).toReal

/-- Detection soundness within `ε`: a non-recipient false-positives with
probability at most `ε`. The counterpart of `PerfectlyComplete`. -/
def SoundWithin (ε : ℝ) : Prop := S.falsePositiveRate ≤ ε

/-! ## Unlinkability (recipient anonymity) -/

/-- Unlinkability adversary: given both public meta-addresses and the challenge
announcement, guess which recipient it is for. A function rather than a
two-phase structure — the games are non-adaptive (`docs/announcement-model.md`). -/
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

/-- **First game hop.** The unlinkability advantage equals the advantage of
distinguishing an announcement to recipient 1 from one to recipient 0 — the
definitional heart of anonymity. -/
theorem unlinkAdvantage_eq_branchDistAdvantage :
    S.unlinkAdvantage adv =
      (S.unlinkSetup >>= S.unlinkBranch adv true).boolDistAdvantage
      (S.unlinkSetup >>= S.unlinkBranch adv false) :=
  ProbComp.boolBiasAdvantage_bind_uniformBool_branch S.unlinkSetup (S.unlinkBranch adv)

end StealthScheme

end PqStealth
