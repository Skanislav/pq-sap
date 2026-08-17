/-
Controls for the model: leaks the advantages must catch, detection tests they
must reject, and a scheme that is deliberately wrong.

A proof closed by `simp` can be correct about something other than what was
intended, and a completeness theorem is especially exposed to this -- if the
model were vacuous, or the detection test trivially true, the proof would still
go through and nothing would look amiss. The usual defence is to break the
scheme on purpose and check that the same proof script stops working. That is
worth doing interactively, but it is a poor regression test: a failing tactic
script is not checked by the build. The durable version is the one below --
state the negation as an ordinary theorem and prove it.

A definition can be wrong in two opposite ways, so the controls come in two
kinds. An advantage that no scheme can make large measures nothing: the
positive controls answer that. `leakyScheme` publishes the recipient's
meta-address outright, and `unlinkAdvantage` is proved to be maximal on it --
maximal meaning `1 - Pr[the two recipients drew the same key]`, which is the
true ceiling, since on a key collision the two branches of the game are the same
computation and no adversary can separate them. The same construction as a KEM
does the same for `anonAdvantage`.

A detection test that no scheme can fail asserts nothing: the negative controls
answer that, and they are what makes the tag comparison in `ofKEMFull.scan`
load-bearing. A KEM that always rejects gives a scheme that is not complete, and
dropping the tag comparison gives a scheme that is complete but flags every
announcement, including those addressed to someone else. The tag comparison is
exactly what separates those two failures. `dksapBroken` closes the set on the
classical side: it drops the recipient's spending key from the detection test,
which is the single most plausible way to get DKSAP wrong.

See `docs/announcement-model.md` (controls rationale) and
`docs/dksap-asymmetry.md` (the broken variant).
-/

import PqStealth.KEMAnonymity
import PqStealth.DKSAP

open OracleComp OracleSpec

namespace PqStealth

/-! ## Positive control: a scheme that publishes the recipient -/

section Leaky

variable {PK SK : Type} [DecidableEq PK]

/-- The trivial recipient-identifying adversary: remember the second public
meta-address, then report whether the announcement equals it. -/
def leakyAdv : StealthScheme.UnlinkAdv PK PK :=
  fun _ pk1 c => pure (decide (c = pk1))

/-- The probability that two independent runs of `keygen` produce the same
public meta-address.

This is the exact obstruction to a unlinkability advantage of `1`, not a proof
artifact: the unlinkability game draws its two recipients independently from the
same `keygen`, so whenever they collide its two branches are literally the same
computation and no adversary whatsoever can distinguish them. Any unlinkability
or anonymity advantage against a scheme with this `keygen` is therefore capped
at `1 - keyCollisionProb`, and the one-comparison adversary below attains the
cap. -/
noncomputable def keyCollisionProb (keygen : ProbComp (PK × SK)) : ℝ :=
  (Pr[= true | do
      let (pk0, _) ← keygen
      let (pk1, _) ← keygen
      pure (decide (pk0 = pk1))]).toReal

/-- A stealth scheme whose announcement IS the recipient's public meta-address:
the maximal leak. Detection is unconditional, which is deliberate -- this
control is about unlinkability, and a scheme can be perfectly complete and still
worthless. -/
def leakyScheme (keygen : ProbComp (PK × SK)) : StealthScheme PK SK PK where
  keygen := keygen
  announce pk := pure pk
  scan _ _ := pure true

/-- **The positive control, proved.** Any scheme whose announcement is the
recipient's public meta-address has the largest unlinkability advantage the game
admits: `1` less the probability that the two recipients collide. So
`unlinkAdvantage` does detect a recipient leak -- it is not a quantity that
happens to be small for structural reasons.

Stated for an arbitrary scheme with `announce pk = pure pk` rather than for
`leakyScheme` alone, so that the KEM control below reuses it. -/
theorem unlinkAdvantage_leakyAdv_eq_one_sub_keyCollisionProb
    (S : StealthScheme PK SK PK) (hkg : Pr[⊥ | S.keygen] = 0)
    (hann : ∀ pk, S.announce pk = pure pk) :
    S.unlinkAdvantage leakyAdv = 1 - keyCollisionProb S.keygen := by
  have hT : S.unlinkSetup >>= S.unlinkBranch leakyAdv true
      = (do let (_, _) ← S.keygen; let (_, _) ← S.keygen; pure true) := by
    simp only [leakyAdv, StealthScheme.unlinkSetup, bind_pure_comp, map_pure, bind_assoc,
      bind_map_left, StealthScheme.unlinkBranch, hann, if_true, decide_true]
  have hF : S.unlinkSetup >>= S.unlinkBranch leakyAdv false
      = (do let (pk0, _) ← S.keygen; let (pk1, _) ← S.keygen; pure (decide (pk0 = pk1))) := by
    simp only [leakyAdv, StealthScheme.unlinkSetup, bind_pure_comp, map_pure, bind_assoc,
      bind_map_left, StealthScheme.unlinkBranch, hann, Bool.false_eq_true, if_false]
  have hTrue : Pr[= true | S.unlinkSetup >>= S.unlinkBranch leakyAdv true] = 1 := by
    rw [hT, probOutput_eq_one_iff_forall]
    refine ⟨?_, ?_⟩
    · simp only [probFailure_bind_eq_zero_iff, probFailure_pure, implies_true, and_true]
      exact ⟨hkg, fun _ _ => hkg⟩
    · intro y hy
      simp only [support_bind, support_pure, Set.mem_iUnion, Set.mem_singleton_iff] at hy
      obtain ⟨-, -, -, -, hy⟩ := hy
      exact hy
  have hle : keyCollisionProb S.keygen ≤ 1 := by
    simpa [keyCollisionProb] using
      ENNReal.toReal_mono ENNReal.one_ne_top (probOutput_le_one (x := true))
  rw [StealthScheme.unlinkAdvantage_eq_branchDistAdvantage, ProbComp.boolDistAdvantage,
    hTrue, hF, ENNReal.toReal_one]
  unfold keyCollisionProb at hle ⊢
  exact abs_of_nonneg (by linarith)

/-- The leak is visible: a scheme that publishes the recipient has a strictly
positive unlinkability advantage whenever key generation is not degenerate. -/
theorem unlinkAdvantage_leakyAdv_pos (S : StealthScheme PK SK PK)
    (hkg : Pr[⊥ | S.keygen] = 0) (hann : ∀ pk, S.announce pk = pure pk)
    (hcoll : keyCollisionProb S.keygen < 1) :
    0 < S.unlinkAdvantage leakyAdv := by
  rw [unlinkAdvantage_leakyAdv_eq_one_sub_keyCollisionProb S hkg hann]
  linarith

/-- The leaky scheme, specialized. -/
theorem leakyScheme_unlinkAdvantage_eq (keygen : ProbComp (PK × SK))
    (hkg : Pr[⊥ | keygen] = 0) :
    (leakyScheme keygen).unlinkAdvantage leakyAdv = 1 - keyCollisionProb keygen :=
  unlinkAdvantage_leakyAdv_eq_one_sub_keyCollisionProb _ hkg (fun _ => rfl)

/-! ## Positive control: a KEM whose ciphertext is the public key -/

variable {K : Type}

/-- A KEM that encapsulates by echoing the public key. Whenever `keygen` never
fails it is a perfectly correct KEM -- decapsulation returns exactly the shared
secret that was encapsulated -- and anonymous it is not. -/
def leakyKEM (keygen : ProbComp (PK × SK)) (k₀ : K) : KEM PK SK PK K where
  keygen := keygen
  encaps pk := pure (pk, k₀)
  decaps _ _ := pure (some k₀)

/-- **`anonAdvantage` has teeth.** A KEM whose ciphertext is the public key it
was encapsulated to has the maximal anonymity advantage, against the same
one-comparison adversary. Via `unlinkAdvantage_ofKEM_eq_anonAdvantage`, so the
two controls are literally the same fact seen through the reduction. -/
theorem leakyKEM_anonAdvantage_eq (keygen : ProbComp (PK × SK)) (k₀ : K)
    (hkg : Pr[⊥ | keygen] = 0) :
    (leakyKEM keygen k₀).anonAdvantage leakyAdv = 1 - keyCollisionProb keygen := by
  rw [← unlinkAdvantage_ofKEM_eq_anonAdvantage]
  exact unlinkAdvantage_leakyAdv_eq_one_sub_keyCollisionProb _ hkg
    (fun _ => by simp only [StealthScheme.ofKEM, leakyKEM, bind_pure_comp, map_pure])

end Leaky

/-! ## Negative control: a KEM that never decapsulates -/

/-- A KEM whose decapsulation always rejects. Everything else is trivial, so
the only thing the control can be measuring is the rejection. -/
def deadKEM : KEM Unit Unit Unit Unit where
  keygen := pure ((), ())
  encaps _ := pure ((), ())
  decaps _ _ := pure none

/-- **The completeness control, proved.** `perfectlyComplete_ofKEMFull` is not
vacuous: drop the KEM correctness hypothesis and the conclusion is false. Being
a theorem rather than a tactic script that fails, the build keeps it honest. -/
theorem deadKEM_ofKEMFull_not_perfectlyComplete :
    ¬ (StealthScheme.ofKEMFull deadKEM (fun _ _ => ())).PerfectlyComplete := by
  intro hComplete
  rw [StealthScheme.PerfectlyComplete, probOutput_eq_one_iff_forall] at hComplete
  obtain ⟨-, hall⟩ := hComplete
  have hmem : false ∈ support ((StealthScheme.ofKEMFull deadKEM (fun _ _ => ())).CorrectExp) := by
    simp only [StealthScheme.CorrectExp, StealthScheme.ofKEMFull, deadKEM, bind_pure_comp,
      map_pure, decide_true, Option.elim_none, support_pure, Set.mem_singleton_iff]
  simpa using hall false hmem

/-! ## Negative control: the scan that ignores the tag -/

section NoTag

variable {PK SK C K Aux : Type} (kem : KEM PK SK C K) (auxGen : K → PK → Aux)

/-- `ofKEMFull` with the tag comparison removed: detection is "decapsulation
returned `some`". Announcement and private state are unchanged, so the pair
`ofKEMFull` / `ofKEMFullNoTag` isolates exactly the comparison. -/
def StealthScheme.ofKEMFullNoTag : StealthScheme PK (SK × PK) (C × Aux) where
  keygen := do
    let ks ← kem.keygen
    pure (ks.1, (ks.2, ks.1))
  announce pk := do
    let ck ← kem.encaps pk
    pure (ck.1, auxGen ck.2 pk)
  scan sk ca := do
    let k? ← kem.decaps sk.1 ca.1
    pure k?.isSome

/-- The tag-ignoring variant IS complete, under the same hypothesis. Half of
the control: completeness alone does not distinguish the two scans, so it cannot
be the property that justifies the comparison. -/
theorem perfectlyComplete_ofKEMFullNoTag [DecidableEq K]
    (hkem : kem.PerfectlyCorrect ProbCompRuntime.probComp) :
    (StealthScheme.ofKEMFullNoTag kem auxGen).PerfectlyComplete := by
  have hCE : (StealthScheme.ofKEMFullNoTag kem auxGen).CorrectExp =
      (do let a ← kem.run; pure a.2.2.isSome) := by
    simp only [StealthScheme.CorrectExp, StealthScheme.ofKEMFullNoTag, KEM.run,
      bind_assoc, pure_bind]
  rw [StealthScheme.PerfectlyComplete, hCE]
  refine probOutput_true_eq_one_of_imp (p := fun a => decide (a.2.2 = some a.2.1.2))
    kem.run ?_ ?_
  · intro a _ ha
    simp only [decide_eq_true_eq] at ha
    simp only [ha, Option.isSome_some]
  · rw [← kem.correctExp_eq]
    exact hkem

/-- **The soundness control, proved.** On a KEM with implicit rejection --
`decaps` always returns `some`, which is exactly what ML-KEM does -- the
tag-ignoring scan flags an announcement addressed to a different recipient with
probability `1`. Detection is then not detection: every scanner "receives" every
payment.

This is what the tag comparison in `ofKEMFull.scan` buys, and it is why the
recipient's private state has to carry its own public key. A quantitative
false-positive bound for the real scan is the separate view-tag argument. -/
theorem probOutput_falsePositiveExp_ofKEMFullNoTag_eq_one (k₀ : K)
    (hkg : Pr[⊥ | kem.keygen] = 0) (henc : ∀ pk, Pr[⊥ | kem.encaps pk] = 0)
    (hdec : ∀ sk c, kem.decaps sk c = pure (some k₀)) :
    Pr[= true | (StealthScheme.ofKEMFullNoTag kem auxGen).FalsePositiveExp] = 1 := by
  have hFP : (StealthScheme.ofKEMFullNoTag kem auxGen).FalsePositiveExp =
      (do let _ ← kem.keygen
          let ks1 ← kem.keygen
          let _ ← kem.encaps ks1.1
          pure true) := by
    simp only [StealthScheme.FalsePositiveExp, StealthScheme.ofKEMFullNoTag, hdec,
      bind_assoc, pure_bind, Option.isSome_some]
  rw [hFP, probOutput_eq_one_iff_forall]
  refine ⟨?_, ?_⟩
  · simp only [probFailure_bind_eq_zero_iff, probFailure_pure, implies_true, and_true]
    exact ⟨hkg, fun _ _ => ⟨hkg, fun x _ => henc x.1⟩⟩
  · intro y hy
    simp only [support_bind, support_pure, Set.mem_iUnion, Set.mem_singleton_iff] at hy
    obtain ⟨-, -, -, -, -, -, hy⟩ := hy
    exact hy

end NoTag

/-! ## Negative control: DKSAP with the spending key dropped -/

section BrokenDKSAP

variable {F : Type} [Field F] {G : Type} [AddCommGroup G] [Module F G]

/-- The algebraic reason the broken variant fails: dropping a nonzero spending
key changes the derived public key. Stated for the recipient whose spending
secret is `1`, which is enough to refute a claim quantified over all
recipients. -/
theorem dksapBroken_key_mismatch (g : G) (hg : g ≠ 0) (s : F) :
    ((1 : F) + s) • g ≠ s • g := by
  intro hEq
  rw [add_smul, one_smul] at hEq
  exact hg (by simpa using congrArg (· - s • g) hEq)

variable [SampleableType F] [DecidableEq G] (g : G) (h : G → F)

/-- A deliberately incorrect DKSAP: the recipient recomputes the shared scalar
correctly but forgets to add their own spending key, so the key they check
against is `s • g` instead of `(m + s) • g`. Announcing is unchanged. -/
def dksapBroken : StealthScheme (G × G) (F × F) (G × G) where
  keygen := do
    let m ← ($ᵗ F)
    let v ← ($ᵗ F)
    pure ((m • g, v • g), (m, v))
  announce MV := do
    let r ← ($ᵗ F)
    pure (r • g, MV.1 + (h (r • MV.2)) • g)
  scan mv Rp := pure (decide (Rp.2 = (h (mv.2 • Rp.1)) • g))

/-- **The negative control, proved.** The broken variant is not perfectly
complete: there is a recipient and a payment for which detection fails. Because
this is a theorem rather than a tactic script that happens to fail, the build
keeps it honest -- if some future change made the broken scheme "work", this
would stop compiling.

Together with `dksap_perfectlyComplete` it pins the completeness result from
both sides: the real scheme always detects, and a scheme differing from it only
in dropping the spending key does not. -/
theorem dksapBroken_not_perfectlyComplete (hg : g ≠ 0) :
    ¬ (dksapBroken g h).PerfectlyComplete := by
  intro hComplete
  rw [StealthScheme.PerfectlyComplete, probOutput_eq_one_iff_forall] at hComplete
  obtain ⟨-, hall⟩ := hComplete
  have hmem : false ∈ support ((dksapBroken g h).CorrectExp) := by
    simp only [StealthScheme.CorrectExp, dksapBroken, support_bind, support_pure,
      Set.mem_iUnion, Set.mem_singleton_iff]
    refine ⟨(((1 : F) • g, (1 : F) • g), (1 : F), (1 : F)),
      ⟨1, mem_support_uniformSample _, 1, mem_support_uniformSample _, rfl⟩,
      ((1 : F) • g, (1 : F) • g + h ((1 : F) • ((1 : F) • g)) • g),
      ⟨1, mem_support_uniformSample _, rfl⟩, ?_⟩
    symm
    simp only [decide_eq_false_iff_not, ← add_smul]
    exact dksapBroken_key_mismatch g hg _
  simpa using hall false hmem

end BrokenDKSAP

end PqStealth
