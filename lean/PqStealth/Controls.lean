import PqStealth.KEMAnonymity
import PqStealth.DKSAP

/-!
# Controls: the definitions have teeth

Proved, all as ordinary theorems so the build keeps them honest: a scheme whose
announcement IS the recipient's meta-address attains the maximal unlinkability
advantage `1 − keyCollisionProb` -- the true ceiling, since on a key collision
the two branches are the same computation -- and likewise a KEM whose ciphertext
is the public key, for `anonAdvantage`; a KEM that always rejects gives a scheme
that is NOT complete; the tag-ignoring scan IS complete yet false-positives with
probability `1` on an implicit-rejection KEM; and a DKSAP variant that drops the
recipient's spending key is not complete.

Assumed: nothing. See `docs/announcement-model.md` (controls rationale) and
`docs/dksap-asymmetry.md` (the broken variant).
-/

open OracleComp OracleSpec

namespace PqStealth

/-! ## Positive control: a scheme that publishes the recipient -/

section Leaky

variable {PK SK : Type} [DecidableEq PK]

/-- The trivial recipient-identifying adversary: remember the second public
meta-address, then report whether the announcement equals it. -/
def leakyAdv : StealthScheme.UnlinkAdv PK PK :=
  fun _ pk1 c => pure (decide (c = pk1))

/-- The probability that two independent runs of `keygen` collide -- the exact
obstruction to an advantage of `1`, not a proof artifact, since on a collision
the game's two branches are literally the same computation. -/
noncomputable def keyCollisionProb (keygen : ProbComp (PK × SK)) : ℝ :=
  (Pr[= true | do
      let (pk0, _) ← keygen
      let (pk1, _) ← keygen
      pure (decide (pk0 = pk1))]).toReal

/-- A stealth scheme whose announcement IS the recipient's public meta-address:
the maximal leak. Detection is unconditional on purpose -- a scheme can be
perfectly complete and still worthless. -/
def leakyScheme (keygen : ProbComp (PK × SK)) : StealthScheme PK SK PK where
  keygen := keygen
  announce pk := pure pk
  scan _ _ := pure true

/-- **The positive control.** A scheme announcing the recipient's meta-address
has the largest advantage the game admits, so `unlinkAdvantage` does detect a
leak. Stated for any `announce pk = pure pk`, so the KEM control reuses it. -/
theorem unlinkAdvantage_leakyAdv_eq_one_sub_keyCollisionProb
    (S : StealthScheme PK SK PK) (hann : ∀ pk, S.announce pk = pure pk) :
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
    · exact probFailure_of_liftM_PMF _
    · intro y hy
      simp only [support_bind, support_pure, Set.mem_iUnion, Set.mem_singleton_iff] at hy
      obtain ⟨-, -, -, -, hy⟩ := hy
      exact hy
  have hle : keyCollisionProb S.keygen ≤ 1 := by
    simpa only [keyCollisionProb, bind_pure_comp, ENNReal.toReal_one] using
      ENNReal.toReal_mono ENNReal.one_ne_top (probOutput_le_one (x := true))
  rw [StealthScheme.unlinkAdvantage_eq_branchDistAdvantage, ProbComp.boolDistAdvantage,
    hTrue, hF, ENNReal.toReal_one]
  unfold keyCollisionProb at hle ⊢
  exact abs_of_nonneg (by linarith)

/-- The leak is visible: a scheme that publishes the recipient has a strictly
positive unlinkability advantage whenever key generation is not degenerate. -/
theorem unlinkAdvantage_leakyAdv_pos (S : StealthScheme PK SK PK)
    (hann : ∀ pk, S.announce pk = pure pk)
    (hcoll : keyCollisionProb S.keygen < 1) :
    0 < S.unlinkAdvantage leakyAdv := by
  rw [unlinkAdvantage_leakyAdv_eq_one_sub_keyCollisionProb S hann]
  linarith

/-- The leaky scheme, specialized. -/
theorem leakyScheme_unlinkAdvantage_eq (keygen : ProbComp (PK × SK)) :
    (leakyScheme keygen).unlinkAdvantage leakyAdv = 1 - keyCollisionProb keygen :=
  unlinkAdvantage_leakyAdv_eq_one_sub_keyCollisionProb _ (fun _ => rfl)

/-! ## Positive control: a KEM whose ciphertext is the public key -/

variable {K : Type}

/-- A KEM that encapsulates by echoing the public key. Whenever `keygen` never
fails it is a perfectly correct KEM -- decapsulation returns exactly the shared
secret that was encapsulated -- and anonymous it is not. -/
def leakyKEM (keygen : ProbComp (PK × SK)) (k₀ : K) : KEM PK SK PK K where
  keygen := keygen
  encaps pk := pure (pk, k₀)
  decaps _ _ := pure (some k₀)

/-- **`anonAdvantage` has teeth.** A KEM whose ciphertext is the public key has
the maximal anonymity advantage -- via `unlinkAdvantage_ofKEM_eq_anonAdvantage`,
so the two controls are the same fact seen through the reduction. -/
theorem leakyKEM_anonAdvantage_eq (keygen : ProbComp (PK × SK)) (k₀ : K) :
    (leakyKEM keygen k₀).anonAdvantage leakyAdv = 1 - keyCollisionProb keygen := by
  rw [← unlinkAdvantage_ofKEM_eq_anonAdvantage]
  exact unlinkAdvantage_leakyAdv_eq_one_sub_keyCollisionProb _
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
  simpa only [Bool.false_eq_true] using hall false hmem

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

/-- **The soundness control.** On an implicit-rejection KEM -- exactly what
ML-KEM is -- the tag-ignoring scan flags someone else's announcement with
probability `1`. This is what the tag comparison in `ofKEMFull.scan` buys. -/
theorem probOutput_falsePositiveExp_ofKEMFullNoTag_eq_one (k₀ : K)
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
  · exact probFailure_of_liftM_PMF _
  · intro y hy
    simp only [support_bind, support_pure, Set.mem_iUnion, Set.mem_singleton_iff] at hy
    obtain ⟨-, -, -, -, -, -, hy⟩ := hy
    exact hy

/-- The same control in the soundness vocabulary of `Soundness`: the tag-ignoring
scan's false-positive RATE is `1`, the largest `SoundWithin` admits. -/
theorem falsePositiveRate_ofKEMFullNoTag_eq_one (k₀ : K)
    (hdec : ∀ sk c, kem.decaps sk c = pure (some k₀)) :
    (StealthScheme.ofKEMFullNoTag kem auxGen).falsePositiveRate = 1 := by
  rw [StealthScheme.falsePositiveRate,
    probOutput_falsePositiveExp_ofKEMFullNoTag_eq_one kem auxGen k₀ hdec,
    ENNReal.toReal_one]

end NoTag

/-! ## Negative control: DKSAP with the spending key dropped -/

section BrokenDKSAP

variable {F : Type} [Field F] {G : Type} [AddCommGroup G] [Module F G]

/-- The algebraic reason the broken variant fails: dropping a nonzero spending
key changes the derived public key. Stated at spending secret `1`, enough to
refute a claim quantified over all recipients. -/
theorem dksapBroken_key_mismatch (g : G) (hg : g ≠ 0) (s : F) :
    ((1 : F) + s) • g ≠ s • g := by
  intro hEq
  rw [add_smul, one_smul] at hEq
  exact hg (by simpa only [add_sub_cancel_right, sub_self] using congrArg (· - s • g) hEq)

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

/-- **The negative control.** The broken variant is not perfectly complete.
Together with `dksap_perfectlyComplete` this pins completeness from both sides,
and being a theorem rather than a failing tactic script, the build checks it. -/
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
  simpa only [Bool.false_eq_true] using hall false hmem

end BrokenDKSAP

end PqStealth
