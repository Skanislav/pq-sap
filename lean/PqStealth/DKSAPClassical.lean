/-
The other half of the DKSAP story: why it is a sound design classically.

`DKSAP.lean` shows the deployed scheme collapses completely once discrete
logarithms are computable. On its own that is a weak claim -- in a world where
every discrete log is available, every discrete-log-based scheme dies, and
showing one of them die proves little about the design.

What makes the break meaningful is the contrast. This file supplies it: DKSAP
is unlinkable, and all of that unlinkability rests on a single assumption about
the hashed Diffie-Hellman value. Put the two files together and the same scheme,
in one framework, is sound under a classical assumption and totally broken given
a discrete-log oracle. That is a statement about the quantum transition rather
than about DKSAP being weak.

## The shape of the argument

The sender derives the stealth key as `M + h(r * V) * g`. Replace the scalar
`h(r * V)` by a uniformly random one and the announcement becomes independent of
the recipient outright -- proved below, not assumed. So the entire question is
whether the real scalar is distinguishable from uniform, which is the hashed
Diffie-Hellman assumption (implied by DDH with `h` modelled as a random oracle).

This mirrors how the ML-KEM side is organized: the structural hops are proved
here, and one named hardness assumption carries the weight. The classical
assumption is stated, not proved, exactly as MLWE is on the other side.
-/

import PqStealth.DKSAP

open OracleComp OracleSpec

namespace PqStealth

variable {F : Type} [Field F] {G : Type} [AddCommGroup G] [Module F G]

section Classical

variable [SampleableType F] [DecidableEq G] (g : G)

/-- DKSAP with an idealized sender: the shared scalar is drawn uniformly at
random instead of being derived as `h(r * V)`. Everything else is unchanged.

This is a proof device, not a scheme anyone could run -- a recipient cannot
recompute a random scalar, so detection does not work. It is only ever used as
the middle game of a hop. -/
def dksapIdeal : StealthScheme (G × G) (F × F) (G × G) where
  keygen := do
    let m ← ($ᵗ F)
    let v ← ($ᵗ F)
    pure ((m • g, v • g), (m, v))
  announce MV := do
    let r ← ($ᵗ F)
    let s ← ($ᵗ F)
    pure (r • g, MV.1 + s • g)
  scan _ _ := pure false

variable (h : G → F) (adv : StealthScheme.UnlinkAdv (G × G) (G × G))

/-! ## The two hops

Each branch of the unlinkability game moves from the real derived scalar to a
uniform one; the gap is the hashed Diffie-Hellman advantage on that branch. -/

/-- Hashed-DH advantage on the `b = 1` branch: distinguishing an announcement
whose scalar is the real `h(r * V)` from one whose scalar is uniform. Under DDH
with `h` a random oracle this is negligible; it is the classical assumption the
scheme rests on, and it is exactly what a discrete-log oracle destroys. -/
noncomputable def hashedDHTrue : ℝ :=
  ((dksap g h).unlinkSetup adv >>= (dksap g h).unlinkBranchTrue adv).boolDistAdvantage
    ((dksapIdeal (F := F) g).unlinkSetup adv >>= (dksapIdeal (F := F) g).unlinkBranchTrue adv)

/-- Hashed-DH advantage on the `b = 0` branch. -/
noncomputable def hashedDHFalse : ℝ :=
  ((dksapIdeal (F := F) g).unlinkSetup adv >>= (dksapIdeal (F := F) g).unlinkBranchFalse adv).boolDistAdvantage
    ((dksap g h).unlinkSetup adv >>= (dksap g h).unlinkBranchFalse adv)

/-! ## The idealized scheme is perfectly unlinkable

Not "negligibly" -- exactly zero. With a uniform scalar the announced stealth
key is a uniformly distributed group element whatever the recipient's key was,
so the two branches are the same distribution and no adversary, however
powerful, does better than guessing. -/

omit [DecidableEq G] in
/-- With a uniform scalar, announcing to `M1` and announcing to `M0` are the
same computation. The substitution is `s |-> d + s`, where `d` is the discrete
log of `M1 - M0`; it is a bijection of the scalar field, so it carries the
uniform distribution to itself. -/
theorem dksapIdeal_announce_indep
    (hbij : Function.Bijective (fun x : F => x • g))
    (M0 M1 : G) (cont : G → ProbComp Bool) (z : Bool) :
    Pr[= z | ($ᵗ F) >>= fun s => cont (M1 + s • g)] =
      Pr[= z | ($ᵗ F) >>= fun s => cont (M0 + s • g)] := by
  obtain ⟨d, hd⟩ := hbij.surjective (M1 - M0)
  simp only at hd
  have key : ∀ s : F, M0 + (d + s) • g = M1 + s • g := by
    intro s
    rw [add_smul, ← add_assoc, hd, add_sub_cancel]
  have hbij' : Function.Bijective (fun s : F => d + s) := (Equiv.addLeft d).bijective
  calc Pr[= z | ($ᵗ F) >>= fun s => cont (M1 + s • g)]
      = Pr[= z | ($ᵗ F) >>= fun s => (fun s' => cont (M0 + s' • g)) (d + s)] := by
        simp only [key]
    _ = Pr[= z | ($ᵗ F) >>= fun s' => cont (M0 + s' • g)] :=
        probOutput_bind_bijective_uniform_cross F (fun s : F => d + s) hbij'
          (fun s' => cont (M0 + s' • g)) z

omit [DecidableEq G] in
/-- The same independence for a whole announcement, ephemeral key included. -/
theorem dksapIdeal_branch_indep
    (hbij : Function.Bijective (fun x : F => x • g))
    (M0 M1 : G) (cont : G × G → ProbComp Bool) (z : Bool) :
    Pr[= z | ($ᵗ F) >>= fun r => ($ᵗ F) >>= fun s => cont (r • g, M1 + s • g)] =
      Pr[= z | ($ᵗ F) >>= fun r => ($ᵗ F) >>= fun s => cont (r • g, M0 + s • g)] := by
  have inner := fun (r : F) =>
    dksapIdeal_announce_indep g hbij M0 M1 (fun P => cont (r • g, P)) z
  simp only [probOutput_bind_eq_tsum] at inner ⊢
  exact tsum_congr fun r => by rw [inner r]

omit [DecidableEq G] in
/-- **Perfect unlinkability of the idealized scheme, sorry-free.** The
unlinkability advantage is exactly zero: an announcement built from a uniform
scalar carries no information whatsoever about which recipient it was for. -/
theorem dksapIdeal_unlinkAdvantage_eq_zero
    (hbij : Function.Bijective (fun x : F => x • g)) :
    (dksapIdeal (F := F) g).unlinkAdvantage adv = 0 := by
  rw [StealthScheme.unlinkAdvantage_eq_branchDistAdvantage, ProbComp.boolDistAdvantage]
  refine abs_eq_zero.mpr (sub_eq_zero.mpr ?_)
  congr 1
  simp only [probOutput_bind_eq_tsum]
  refine tsum_congr fun a => ?_
  congr 1
  simp only [StealthScheme.unlinkBranchTrue, StealthScheme.unlinkBranchFalse,
    dksapIdeal, bind_assoc, pure_bind]
  exact dksapIdeal_branch_indep g hbij _ _ _ _

/-! ## The classical security statement -/

/-- **DKSAP's unlinkability rests entirely on hashed Diffie-Hellman.** Its
advantage is bounded by the two per-branch hashed-DH advantages and nothing
else: the idealized middle game contributes exactly zero, so there is no
residual slack in the reduction.

Read alongside `dksap_key_recovery`, this is the point of the whole exercise.
The same scheme, in the same framework, is sound under a classical assumption
and completely broken -- key recovery, not merely distinguishing -- once
discrete logarithms become available. The break is therefore a statement about
the quantum transition, not a weakness anyone could exploit today. -/
theorem dksap_unlinkAdvantage_le_hashedDH
    (hbij : Function.Bijective (fun x : F => x • g)) :
    (dksap g h).unlinkAdvantage adv ≤ hashedDHTrue g h adv + hashedDHFalse g h adv := by
  rw [StealthScheme.unlinkAdvantage_eq_branchDistAdvantage]
  unfold hashedDHTrue hashedDHFalse
  set Pt := (dksap g h).unlinkSetup adv >>= (dksap g h).unlinkBranchTrue adv
  set Pf := (dksap g h).unlinkSetup adv >>= (dksap g h).unlinkBranchFalse adv
  set It := (dksapIdeal (F := F) g).unlinkSetup adv >>=
    (dksapIdeal (F := F) g).unlinkBranchTrue adv
  set If := (dksapIdeal (F := F) g).unlinkSetup adv >>=
    (dksapIdeal (F := F) g).unlinkBranchFalse adv
  have hzero : It.boolDistAdvantage If = 0 := by
    rw [← StealthScheme.unlinkAdvantage_eq_branchDistAdvantage]
    exact dksapIdeal_unlinkAdvantage_eq_zero g adv hbij
  calc Pt.boolDistAdvantage Pf
      ≤ Pt.boolDistAdvantage It + It.boolDistAdvantage Pf :=
        ProbComp.boolDistAdvantage_triangle Pt It Pf
    _ ≤ Pt.boolDistAdvantage It + (It.boolDistAdvantage If + If.boolDistAdvantage Pf) := by
        gcongr
        exact ProbComp.boolDistAdvantage_triangle It If Pf
    _ = Pt.boolDistAdvantage It + If.boolDistAdvantage Pf := by
        rw [hzero, zero_add]

end Classical

end PqStealth
