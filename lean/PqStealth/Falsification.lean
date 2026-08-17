/-
Negative controls: schemes that are deliberately wrong, proved wrong.

A proof closed by `simp` can be correct about something other than what was
intended, and a completeness theorem is especially exposed to this -- if the
model were vacuous, or the detection test trivially true, the proof would still
go through and nothing would look amiss.

The usual defence is to break the scheme on purpose and check that the same
proof script stops working. That is worth doing interactively, but it is a poor
regression test: a failing tactic script is not checked by the build, and it
silently stops being evidence the moment a tactic gets stronger. The durable
version is the one below -- state the negation as an ordinary theorem and prove
it. Then the build itself guarantees that the broken variant really is broken,
and hence that the completeness theorem next door has content.

`dksapBroken` drops the recipient's spending key from the detection test, which
is the single most plausible way to get this scheme wrong.
-/

import PqStealth.DKSAP

open OracleComp OracleSpec

namespace PqStealth

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

section Broken

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

end Broken

end PqStealth
