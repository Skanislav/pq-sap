/-
Controls for the game layer: leaks the advantages must catch, and detection
tests they must reject.

`Falsification.lean` pins one completeness claim (DKSAP) from below by proving a
deliberately broken variant broken. The game layer needs the same treatment on
both sides, because a definition can be wrong in two opposite ways: an advantage
that no scheme can make large measures nothing, and a detection test that no
scheme can fail asserts nothing.

The positive controls answer the first: `leakyScheme` publishes the recipient's
meta-address outright, and `unlinkAdvantage` is proved to be maximal on it --
maximal meaning `1 - Pr[the two recipients drew the same key]`, which is the
true ceiling, since on a key collision the two branches of the game are the same
computation and no adversary can separate them. The same construction as a KEM
does the same for `anonAdvantage`.

The negative controls answer the second, and they are what makes the tag
comparison in `ofKEMFull.scan` load-bearing: a KEM that always rejects gives a
scheme that is not complete, and dropping the tag comparison gives a scheme that
is complete but flags every announcement, including those addressed to someone
else. The tag comparison is exactly what separates those two failures.
-/

import PqStealth.KEMAnonymity

open OracleComp OracleSpec

namespace PqStealth

/-! ## The false-positive experiment

Detection soundness's counterpart to `CorrectExp`: the scanner is not the
recipient. A quantitative bound on this probability for the real scan is
separate work (it is the view-tag length argument); what is used here is only
that a tag-ignoring scan makes it `1`. -/

/-- False-positive experiment: two independent recipients, an announcement
addressed to the second, scanned with the first one's private state. `true` is a
false positive. -/
def StealthScheme.FalsePositiveExp {MetaPub MetaPriv Announcement : Type}
    (S : StealthScheme MetaPub MetaPriv Announcement) : ProbComp Bool := do
  let (_, sk0) ← S.keygen
  let (pk1, _) ← S.keygen
  let c ← S.announce pk1
  S.scan sk0 c

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

end PqStealth
