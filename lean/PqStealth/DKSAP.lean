import PqStealth.Games
import PqStealth.Reorder
import VCVio.CryptoFoundations.HardnessAssumptions.DiffieHellman
import VCVio.CryptoFoundations.HardnessAssumptions.EntropySmoothing

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
  simp only [StealthScheme.PerfectlyComplete, StealthScheme.CorrectExp, dksap,
    bind_pure_comp, Functor.map_map, bind_assoc, bind_map_left, dksap_derivation_agrees,
    decide_true, probOutput_bind_const, probFailure_of_liftM_PMF, tsub_zero,
    probOutput_map_const, probOutput_pure, ↓reduceIte, mul_one]

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

/-- **DKSAP's unlinkability is two hashed-DH gaps**, the idealized middle game
contributing exactly zero. `hashedDH` is itself a game distance; it is bounded
by VCVio's named DDH and entropy-smoothing advantages below
(`hashedDH_le_ddh_add_es`). Read alongside `dksap_key_recovery`: the same scheme
is sound classically and totally broken given a discrete-log oracle. -/
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

/-! ## The hashed-DH term from named assumptions

`hashedDH` is a game gap. It is bounded by VCVio's decisional Diffie–Hellman
advantage plus the entropy-smoothing advantage of `h`, each of an explicit
reduction — exactly as VCVio's hashed ElGamal (`Examples/ElGamal/Hash.lean`),
whose ciphertext `(y • g, hash (y • pk) + m)` is DKSAP's announcement with the
spending key in place of the message. The intermediate games are written in
the sampling order of `ddhExpRand` / `EntropySmoothing.realExp`, so that each
hop is a permutation of independent draws (`Reorder`) and one `mul_comm`. -/

section NamedAssumptions

variable [SampleableType F] (g : G) (h : G → F) (adv : StealthScheme.UnlinkAdv (G × G) (G × G))

/-- The DDH reduction on branch `b`: the challenge `A` is the target's viewing
key, `B` the ephemeral key, `T` the point to hash; the remaining keys are drawn
in the order `mT, mO, vO`. -/
def ddhReductionDKSAP (b : Bool) : DiffieHellman.DDHAdversary F G := fun g A B T => do
  let mT ← ($ᵗ F); let mO ← ($ᵗ F); let vO ← ($ᵗ F)
  let pkT : G × G := (mT • g, A)
  let pkO : G × G := (mO • g, vO • g)
  adv (if b then pkO else pkT) (if b then pkT else pkO) (B, mT • g + h T • g)

/-- The middle game: the hashed point is a uniform group element. In the
sampling order of `ddhExpRand`, so the DDH-random branch is this game on the
nose. -/
def dksapDHGame (b : Bool) : ProbComp Bool := do
  let vT ← ($ᵗ F); let r ← ($ᵗ F); let c ← ($ᵗ F)
  let mT ← ($ᵗ F); let mO ← ($ᵗ F); let vO ← ($ᵗ F)
  let pkT : G × G := (mT • g, vT • g)
  let pkO : G × G := (mO • g, vO • g)
  adv (if b then pkO else pkT) (if b then pkT else pkO) (r • g, mT • g + h (c • g) • g)

/-- The entropy-smoothing reduction on branch `b`: the sample (the hash of a
uniform point, or uniform) is the shared scalar. The hash key is `Fin 1`, `h`
being unkeyed. -/
def esReductionDKSAP (b : Bool) : Fin 1 × F → ProbComp Bool := fun x => do
  let vT ← ($ᵗ F); let r ← ($ᵗ F)
  let mT ← ($ᵗ F); let mO ← ($ᵗ F); let vO ← ($ᵗ F)
  let pkT : G × G := (mT • g, vT • g)
  let pkO : G × G := (mO • g, vO • g)
  adv (if b then pkO else pkT) (if b then pkT else pkO) (r • g, mT • g + x.2 • g)

/-- The real branch is the DDH-real experiment of the reduction. -/
theorem evalDist_unlinkBranch_dksap_eq_ddhExpReal [DecidableEq G] (b : Bool) :
    𝒟[(dksap g h).unlinkSetup >>= (dksap g h).unlinkBranch adv b] =
      𝒟[DiffieHellman.ddhExpReal g (ddhReductionDKSAP h adv b)] := by
  cases b
  · simp only [StealthScheme.unlinkSetup, StealthScheme.unlinkBranch, dksap, ddhReductionDKSAP,
      DiffieHellman.ddhExpReal, bind_assoc, pure_bind, Bool.false_eq_true, if_false, smul_smul]
    rw [evalDist_bind_bind_swap]
    refine evalDist_bind_congr' _ fun v0 => ?_
    rw [evalDist_pull₄]
    refine evalDist_bind_congr' _ fun r => evalDist_bind_congr' _ fun m0 =>
      evalDist_bind_congr' _ fun m1 => evalDist_bind_congr' _ fun v1 => ?_
    rw [mul_comm r v0]
  · simp only [StealthScheme.unlinkSetup, StealthScheme.unlinkBranch, dksap, ddhReductionDKSAP,
      DiffieHellman.ddhExpReal, bind_assoc, pure_bind, if_true, smul_smul]
    rw [evalDist_pull₄]
    refine evalDist_bind_congr' _ fun v1 => ?_
    rw [evalDist_pull₄]
    refine evalDist_bind_congr' _ fun r => ?_
    rw [evalDist_pull₃]
    refine evalDist_bind_congr' _ fun m1 => evalDist_bind_congr' _ fun m0 =>
      evalDist_bind_congr' _ fun v0 => ?_
    rw [mul_comm r v1]

/-- The DDH-random experiment of the reduction is the middle game. -/
theorem evalDist_ddhExpRand_eq_dksapDHGame (b : Bool) :
    𝒟[DiffieHellman.ddhExpRand g (ddhReductionDKSAP h adv b)] = 𝒟[dksapDHGame g h adv b] := by
  simp only [DiffieHellman.ddhExpRand, ddhReductionDKSAP, dksapDHGame]

/-- The middle game is the real entropy-smoothing experiment of the reduction. -/
theorem evalDist_dksapDHGame_eq_esReal (b : Bool) :
    𝒟[dksapDHGame g h adv b] =
      𝒟[EntropySmoothing.realExp F g (fun (_ : Fin 1) => h) (esReductionDKSAP g adv b)] := by
  simp only [EntropySmoothing.realExp, esReductionDKSAP, dksapDHGame]
  rw [evalDist_uniformSample_bind_const, evalDist_pull₃]

/-- The ideal entropy-smoothing experiment of the reduction is the idealized branch. -/
theorem evalDist_esIdeal_eq_unlinkBranch_dksapIdeal (b : Bool) :
    𝒟[EntropySmoothing.idealExp (HK := Fin 1) (M := F) (esReductionDKSAP g adv b)] =
      𝒟[(dksapIdeal F g).unlinkSetup >>= (dksapIdeal F g).unlinkBranch adv b] := by
  simp only [EntropySmoothing.idealExp, esReductionDKSAP, StealthScheme.unlinkSetup,
    StealthScheme.unlinkBranch, dksapIdeal, bind_assoc, pure_bind]
  rw [evalDist_uniformSample_bind_const]
  symm
  cases b
  · simp only [Bool.false_eq_true, if_false]
    rw [evalDist_pull₆]
    refine evalDist_bind_congr' _ fun s => ?_
    rw [evalDist_bind_bind_swap]
    refine evalDist_bind_congr' _ fun v0 => ?_
    rw [evalDist_pull₄]
  · simp only [if_true]
    rw [evalDist_pull₆]
    refine evalDist_bind_congr' _ fun s => ?_
    rw [evalDist_pull₄]
    refine evalDist_bind_congr' _ fun v1 => ?_
    rw [evalDist_pull₄]
    refine evalDist_bind_congr' _ fun r => ?_
    rw [evalDist_pull₃]

/-- **The hashed-DH term from named assumptions.** On each branch it is at most
the DDH advantage of `ddhReductionDKSAP` plus the entropy-smoothing advantage of
`h` against `esReductionDKSAP`. -/
theorem hashedDH_le_ddh_add_es [DecidableEq G] (b : Bool) :
    hashedDH g h adv b ≤
      DiffieHellman.ddhDistAdvantage g (ddhReductionDKSAP h adv b) +
        EntropySmoothing.advantage F g (fun (_ : Fin 1) => h) (esReductionDKSAP g adv b) := by
  unfold hashedDH DiffieHellman.ddhDistAdvantage EntropySmoothing.advantage
    ProbComp.boolDistAdvantage
  rw [probOutput_congr rfl (evalDist_unlinkBranch_dksap_eq_ddhExpReal g h adv b),
    ← probOutput_congr rfl (evalDist_esIdeal_eq_unlinkBranch_dksapIdeal g adv b),
    probOutput_congr rfl (evalDist_ddhExpRand_eq_dksapDHGame g h adv b),
    probOutput_congr rfl (evalDist_dksapDHGame_eq_esReal g h adv b)]
  exact abs_sub_le _ _ _

/-- **DKSAP's classical unlinkability from DDH and entropy smoothing**: the
sum over both branches of the two named advantages of the explicit reductions. -/
theorem dksap_unlinkAdvantage_le_ddh_add_es [DecidableEq G]
    (hbij : Function.Bijective (fun x : F => x • g)) :
    (dksap g h).unlinkAdvantage adv ≤
      (DiffieHellman.ddhDistAdvantage g (ddhReductionDKSAP h adv true) +
          EntropySmoothing.advantage F g (fun (_ : Fin 1) => h) (esReductionDKSAP g adv true)) +
        (DiffieHellman.ddhDistAdvantage g (ddhReductionDKSAP h adv false) +
          EntropySmoothing.advantage F g (fun (_ : Fin 1) => h) (esReductionDKSAP g adv false)) :=
  (dksap_unlinkAdvantage_le_hashedDH g h adv hbij).trans
    (add_le_add (hashedDH_le_ddh_add_es g h adv true) (hashedDH_le_ddh_add_es g h adv false))

end NamedAssumptions

end PqStealth
