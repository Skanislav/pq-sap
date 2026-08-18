import PqStealth.Games

/-!
# DKSAP: the deployed scheme, its break, and its classical soundness

Proved: DKSAP (ERC-5564 scheme 1, the only stealth scheme deployed today) as a
`StealthScheme`, and its detection completeness; given the discrete logs of the
PUBLISHED meta-address, an adversary recomputes the recipient's honest stealth
spending key EXACTLY -- key recovery, hence universal forgery, with no
probability slack; and, on the other side, DKSAP's unlinkability is bounded by
two hashed-Diffie-Hellman terms and nothing else, the idealized middle game
contributing exactly zero.

Assumed: the discrete-log oracle's answers are hypotheses (no quantum
computation is formalized), and hashed-DH is stated, not proved -- exactly as
MLWE is on the lattice side. See `docs/dksap-asymmetry.md`.
-/

open OracleComp OracleSpec

namespace PqStealth

/-! ## The group model

`F` the scalar field, `G` the group, `a • g` the additive rendering of `g^a`.
Abstract on purpose: the attack uses only the group law. -/

variable {F : Type} [Field F] {G : Type} [AddCommGroup G] [Module F G]

/-- The Diffie-Hellman step: sender and recipient reach the same scalar because
`r • (v • g) = v • (r • g)`. This is the identity the whole scheme rests on,
and also the reason the attack works once `v` is known. -/
theorem dksap_derivation_agrees (g : G) (h : G → F) (m v r : F) :
    (m • g) + (h (r • (v • g))) • g = (m + h (v • (r • g))) • g := by
  rw [add_smul, smul_smul, smul_smul, mul_comm]

/-! ## The scheme

A recipient holds `(m, v)` and publishes `(M, V) = (m • g, v • g)`: `m` the
spending key, `v` the viewing key; `h` abstracts the hash. -/

section Scheme

variable [SampleableType F] [DecidableEq G] (g : G) (h : G → F)

/-- DKSAP as a stealth scheme: the announcement is `(R, P) = (r • g,
M + h(r • V) • g)`, and the recipient recomputes the scalar as `h(v • R)`. `P`
stands in for the on-chain address, whose hashing is irrelevant here. -/
def dksap : StealthScheme (G × G) (F × F) (G × G) where
  keygen := do
    let m ← ($ᵗ F)
    let v ← ($ᵗ F)
    pure ((m • g, v • g), (m, v))
  announce MV := do
    let r ← ($ᵗ F)
    pure (r • g, MV.1 + (h (r • MV.2)) • g)
  scan mv Rp := pure (decide (Rp.2 = (mv.1 + h (mv.2 • Rp.1)) • g))

/-- **Detection completeness.** A recipient always detects an announcement
addressed to them: every run of the completeness experiment returns `true`,
because the two derivations of the shared scalar agree. -/
theorem dksap_perfectlyComplete : (dksap g h).PerfectlyComplete := by
  simp [StealthScheme.PerfectlyComplete, StealthScheme.CorrectExp, dksap,
    dksap_derivation_agrees]

end Scheme

/-! ## Key recovery from the published meta-address

The discrete logs of the published `(M, V)` are the entire effect of the
oracle. -/

section KeyRecovery

variable (h : G → F) (g : G)

/-- What the adversary computes: the spending scalar of the announcement `R`,
from the two recovered discrete logs. No secret of the recipient is used. -/
def recover (xM xV : F) (R : G) : F := xM + h (xV • R)

/-- Injectivity of `x ↦ x • g` pins a discrete log to the exact scalar, not
merely one with the same image. Genuinely needed: the recovered viewing scalar
is fed to `h`. See `docs/dksap-asymmetry.md`. -/
theorem dksap_recover_eq_honest
    (hinj : Function.Injective (fun x : F => x • g))
    (m v xM xV : F) (hM : xM • g = m • g) (hV : xV • g = v • g) (R : G) :
    recover h xM xV R = m + h (v • R) := by
  rw [recover, hinj hM, hinj hV]

/-- **The break.** From the published meta-address, its discrete logs, and an
announcement addressed to that recipient, the adversary outputs a valid secret
key for the announced stealth key -- in fact the recipient's own. -/
theorem dksap_key_recovery
    (hinj : Function.Injective (fun x : F => x • g))
    (m v r xM xV : F) (hM : xM • g = m • g) (hV : xV • g = v • g) :
    (recover h xM xV (r • g)) • g = (m • g) + (h (r • (v • g))) • g := by
  rw [dksap_recover_eq_honest h g hinj m v xM xV hM hV, dksap_derivation_agrees]

end KeyRecovery

/-! ## DKSAP under a classical adversary -/

section Ideal

variable [SampleableType F] (g : G) (adv : StealthScheme.UnlinkAdv (G × G) (G × G))

variable (F) in
/-- DKSAP with an idealized sender: the shared scalar is uniform instead of
`h(r * V)`. A proof device, not a runnable scheme -- detection cannot work --
used only as the middle game of a hop. -/
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

/-! ## The idealized scheme is perfectly unlinkable

Not "negligibly" -- exactly zero, so the reduction has no residual slack. -/

/-- With a uniform scalar, announcing to `M1` and to `M0` are the same
computation: substitute `s ↦ d + s` for `d` the discrete log of `M1 - M0`. -/
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

/-- **Perfect unlinkability of the idealized scheme, sorry-free.** The
unlinkability advantage is exactly zero: an announcement built from a uniform
scalar carries no information whatsoever about which recipient it was for. -/
theorem dksapIdeal_unlinkAdvantage_eq_zero
    (hbij : Function.Bijective (fun x : F => x • g)) :
    (dksapIdeal F g).unlinkAdvantage adv = 0 := by
  rw [StealthScheme.unlinkAdvantage_eq_branchDistAdvantage, ProbComp.boolDistAdvantage]
  refine abs_eq_zero.mpr (sub_eq_zero.mpr ?_)
  congr 1
  simp only [probOutput_bind_eq_tsum]
  refine tsum_congr fun a => ?_
  congr 1
  simp only [StealthScheme.unlinkBranch, dksapIdeal, bind_assoc, pure_bind,
    if_true, Bool.false_eq_true, if_false]
  exact dksapIdeal_branch_indep g hbij _ _ _ _

end Ideal

section Classical

variable [SampleableType F] [DecidableEq G] (g : G) (h : G → F)
  (adv : StealthScheme.UnlinkAdv (G × G) (G × G))

/-! ## The two hops

Each branch of the unlinkability game moves from the real derived scalar to a
uniform one; the gap is the hashed Diffie-Hellman advantage on that branch. -/

/-- Hashed-DH advantage on branch `b`: real `h(r * V)` versus uniform. The
classical assumption the scheme rests on, and exactly what a discrete-log oracle
destroys. -/
noncomputable def hashedDH (b : Bool) : ℝ :=
  ((dksap g h).unlinkSetup >>= (dksap g h).unlinkBranch adv b).boolDistAdvantage
    ((dksapIdeal F g).unlinkSetup >>= (dksapIdeal F g).unlinkBranch adv b)

/-! ## The classical security statement -/

/-- **DKSAP's unlinkability rests entirely on hashed Diffie-Hellman**, with no
residual slack. Read alongside `dksap_key_recovery`: the same scheme is sound
classically and totally broken given a discrete-log oracle. -/
theorem dksap_unlinkAdvantage_le_hashedDH
    (hbij : Function.Bijective (fun x : F => x • g)) :
    (dksap g h).unlinkAdvantage adv ≤ hashedDH g h adv true + hashedDH g h adv false := by
  rw [StealthScheme.unlinkAdvantage_eq_branchDistAdvantage]
  unfold hashedDH
  rw [ProbComp.boolDistAdvantage_comm
    ((dksap g h).unlinkSetup >>= (dksap g h).unlinkBranch adv false)]
  set Pt := (dksap g h).unlinkSetup >>= (dksap g h).unlinkBranch adv true
  set Pf := (dksap g h).unlinkSetup >>= (dksap g h).unlinkBranch adv false
  set It := (dksapIdeal F g).unlinkSetup >>=
    (dksapIdeal F g).unlinkBranch adv true
  set If := (dksapIdeal F g).unlinkSetup >>=
    (dksapIdeal F g).unlinkBranch adv false
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
