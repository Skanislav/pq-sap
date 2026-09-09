import PqStealth.Invariants
import PqStealth.KEMAnonymity
import LatticeCrypto.HardnessAssumptions.LearningWithErrors

/-!
# Construction A inside the game model

Proved: the `auxGen` the real scheme uses -- view tag plus
`hashAddr (pack rho (power2Round (A *ᵥ s' + e' + t)))`, symmetric primitives
bundled uninterpreted as `Prims` -- so the announcement in the model is the
announcement in the spec; the announced key is `power2Round` of the honest
ML-DSA key of the widened secret and an ownership witness for it;
`auxKeyIndependence` vanishes for any `auxGen` ignoring the public key; and the
seeded-MLWE `blindingProblem` with its reduction adversary.

Assumed / NOT closed: `hashAddr ∘ pack` as a random oracle (`rho` sits outside
the mask), `ExpandIsIdeal`, and a bind commutation -- so no advantage
inequality is claimed for the blinding hop. See `docs/announcement-model.md`.
-/

open OracleComp OracleSpec Matrix

namespace PqStealth

/-! ## 1. Positive control for `auxKeyIndependence` -/

section AuxKeyIndependence

variable {PK SK C K Aux : Type} [SampleableType K] [DecidableEq Aux]

/-- **The term's meaning, pinned.** When `auxGen` ignores its public-key argument
the two computations compared by `auxKeyIndependence` are equal, so the
advantage is `0`. -/
theorem auxKeyIndependence_eq_zero_of_pk_independent
    (kem : KEM PK SK C K) (auxGen : K → PK → Aux)
    (adv : StealthScheme.UnlinkAdv PK (C × Aux))
    (h : ∀ (kk : K) (pk pk' : PK), auxGen kk pk = auxGen kk pk') :
    auxKeyIndependence kem auxGen adv = 0 := by
  have key : ((StealthScheme.ofKEMFull kem auxGen).unlinkSetup >>=
        randAuxBranch kem auxGen adv true) =
      (kem.anonSetup >>= kem.anonBranch (adv.cipherOf auxGen) true) := by
    simp only [StealthScheme.unlinkSetup, StealthScheme.ofKEMFull, KEM.anonSetup,
      StealthScheme.UnlinkAdv.cipherOf, randAuxBranch, KEM.anonBranch,
      bind_assoc, pure_bind, if_true]
    refine bind_congr fun x => bind_congr fun y =>
      bind_congr fun c => bind_congr fun kk => ?_
    rw [h kk _ _]
  rw [auxKeyIndependence, key, ProbComp.boolDistAdvantage, sub_self, abs_zero]

/-- The hypothesis is inhabited, so the control is not vacuous: a view-tag-only
announcement contributes nothing to `auxKeyIndependence` — which is exactly what
the coarser shared-secret-only model could not see. -/
theorem auxKeyIndependence_tagOnly_eq_zero
    (kem : KEM PK SK C K) (tag : K → Aux)
    (adv : StealthScheme.UnlinkAdv PK (C × Aux)) :
    auxKeyIndependence kem (fun kk _ => tag kk) adv = 0 :=
  auxKeyIndependence_eq_zero_of_pk_independent kem _ adv fun _ _ _ => rfl

end AuxKeyIndependence

namespace ConstructionA

/-! ## 2. The announcement

`R` is the polynomial ring, `k`/`l` the module dimensions; the six symmetric
primitives are uninterpreted parameters bundled as one `Prims` record. -/

/-- The symmetric primitives of construction A, bundled and uninterpreted, so
everything proved holds for every instantiation. -/
structure Prims (R Rho Bytes T1 Tag Addr K : Type) (k l : ℕ) where
  /-- SHAKE128 expansion of the matrix seed. -/
  expandA : Rho → Matrix (Fin k) (Fin l) R
  /-- The blinding pair `(s', e')` derived from the shared secret. -/
  expandBlind : K → (Fin l → R) × (Fin k → R)
  /-- The high-order part of a stealth key. -/
  power2Round : (Fin k → R) → T1
  /-- `pack_pk`: the seed and the rounded key as bytes. -/
  pack : Rho → T1 → Bytes
  /-- The address hash. -/
  hashAddr : Bytes → Addr
  /-- The view tag derived from the shared secret. -/
  viewTag : K → Tag

/-- The three samplers key generation draws the ML-DSA spending keypair from.
Separate rather than one joint sampler because the MLWE reduction has to
resample `(s₁, s₂)` for a `rho` handed to it by the challenger. -/
structure Samplers (R Rho : Type) (k l : ℕ) where
  /-- The matrix seed. -/
  sampleRho : ProbComp Rho
  /-- The short secret `s₁`. -/
  sampleS : ProbComp (Fin l → R)
  /-- The short error `s₂`. -/
  sampleE : ProbComp (Fin k → R)

variable {R : Type} [CommRing R] {k l : ℕ}
  {Rho Bytes T1 Tag Addr KEMpk KEMsk C : Type} {K : Type}

/-- The recipient's meta-address: ML-KEM encapsulation key, matrix seed `rho`,
and the FULL-precision spending key `t` (rounding is only well defined on the
unrounded value). -/
abbrev MetaPub (KEMpk Rho R : Type) (k : ℕ) : Type := KEMpk × Rho × (Fin k → R)

/-- The recipient's private material: the ML-KEM decapsulation key and the
ML-DSA spending secret `(s₁, s₂)`. -/
abbrev MetaPriv (KEMsk R : Type) (k l : ℕ) : Type := KEMsk × (Fin l → R) × (Fin k → R)

variable (P : Prims R Rho Bytes T1 Tag Addr K k l)

/-- The auxiliary data of a construction-A announcement: view tag and stealth
address. The address folds in the recipient's own `rho` and `t`, which is why
`auxGen` takes the public key. -/
def auxGen (kk : K) (pk : MetaPub KEMpk Rho R k) : Tag × Addr :=
  (P.viewTag kk,
    P.hashAddr (P.pack pk.2.1 (P.power2Round
      (P.expandA pk.2.1 *ᵥ (P.expandBlind kk).1 + (P.expandBlind kk).2 + pk.2.2))))

/-- **Where the correctness identity enters the game model.** For an honest
meta-address the announced address is `power2Round` of the honest ML-DSA key of
the widened secret `(s₁ + s', s₂ + e')`. -/
theorem stealthAddr_eq_blinded_pk (kk : K) (ek : KEMpk) (rho : Rho)
    (s₁ : Fin l → R) (s₂ : Fin k → R) :
    (auxGen (KEMpk := KEMpk) P kk (ek, rho, P.expandA rho *ᵥ s₁ + s₂)).2 =
      P.hashAddr (P.pack rho (P.power2Round
        (P.expandA rho *ᵥ (s₁ + (P.expandBlind kk).1) + (s₂ + (P.expandBlind kk).2)))) := by
  rw [auxGen, stealth_pk_eq_blinded_keypair (P.expandA rho) s₁ (P.expandBlind kk).1 s₂
    (P.expandBlind kk).2 _ rfl]

/-- The widened secret behind an announced stealth key is an ownership witness
for it, so the ZK spend statement of `Invariants.lean` is satisfiable for every
announcement construction A produces. -/
theorem announced_key_isOwnershipWitness (kk : K) (rho : Rho)
    (s₁ : Fin l → R) (s₂ : Fin k → R) :
    IsOwnershipWitness (P.expandA rho)
      (P.expandA rho *ᵥ (P.expandBlind kk).1 + (P.expandBlind kk).2
        + (P.expandA rho *ᵥ s₁ + s₂))
      (s₁ + (P.expandBlind kk).1) (s₂ + (P.expandBlind kk).2) :=
  blinded_is_ownership_witness _ _ _ _ _

/-! ## 3. The KEM whose public key is a meta-address

Key generation additionally draws `rho` and `(s₁, s₂)` and publishes
`t = A *ᵥ s₁ + s₂`; the ciphertext is still a plain ML-KEM ciphertext. -/

variable (Smp : Samplers R Rho k l)

/-- The composite KEM: an ML-KEM keypair plus the ML-DSA spending keypair, with
the meta-address as the public key. -/
def metaKem (kem : KEM KEMpk KEMsk C K) :
    KEM (MetaPub KEMpk Rho R k) (MetaPriv KEMsk R k l) C K where
  keygen := do
    let (ek, dk) ← kem.keygen
    let rho ← Smp.sampleRho
    let s₁ ← Smp.sampleS
    let s₂ ← Smp.sampleE
    pure ((ek, rho, P.expandA rho *ᵥ s₁ + s₂), (dk, s₁, s₂))
  encaps pk := kem.encaps pk.1
  decaps sk c := kem.decaps sk.1 c

section Scheme

variable [DecidableEq Tag] [DecidableEq Addr] [SampleableType K]

/-- Construction A as a `StealthScheme`: ML-KEM ciphertext plus view tag plus
stealth address, addressed to a full meta-address. -/
def scheme (kem : KEM KEMpk KEMsk C K) :
    StealthScheme (MetaPub KEMpk Rho R k)
      (MetaPriv KEMsk R k l × MetaPub KEMpk Rho R k) (C × (Tag × Addr)) :=
  StealthScheme.ofKEMFull (metaKem P Smp kem) (auxGen P)

/-- **The algebraic core feeding the game layer, in one statement.**
`unlinkAdvantage_ofKEMFull_le` at `metaKem` and `auxGen` — the content is that
those two are the spec's objects, so `auxKeyIndependence` is the blinding term. -/
theorem unlinkAdvantage_scheme_le (kem : KEM KEMpk KEMsk C K)
    (adv : StealthScheme.UnlinkAdv (MetaPub KEMpk Rho R k) (C × (Tag × Addr))) :
    (scheme P Smp kem).unlinkAdvantage adv ≤
      sharedSecretHiding (metaKem P Smp kem) (auxGen P) adv true
        + auxKeyIndependence (metaKem P Smp kem) (auxGen P) adv
        + (metaKem P Smp kem).anonAdvantage (adv.cipherOf (auxGen P))
        + sharedSecretHiding (metaKem P Smp kem) (auxGen P) adv false :=
  unlinkAdvantage_ofKEMFull_le _ _ adv

end Scheme

/-! ## 4. The blinding hop towards decision-MLWE

The challenge is the SEED `rho`, not the matrix, because the reduction must
compute `pack rho …` and cannot invert `expandA`. -/

section MLWE

open ENNReal

variable [SampleableType R] (sampleTag : ProbComp Tag)

/-- Seeded decision-MLWE: given `(rho, y)`, decide whether
`y = expandA rho *ᵥ s + e` for short `(s, e)` or `y` is uniform. An instance of
VCVio's `LearningWithErrors.Problem`. -/
def blindingProblem : LearningWithErrors.Problem Rho (Fin l → R) (Fin k → R) where
  sampleChallenge := Smp.sampleRho
  sampleSecret := Smp.sampleS
  sampleError := Smp.sampleE
  noiseless := fun s rho => P.expandA rho *ᵥ s
  sampleUniform := $ᵗ (Fin k → R)

section Reduction

variable [SampleableType K]

/-- Quantitative bound on `ExpandIsIdeal`: the total-variation distance between
the real joint `(viewTag, s', e')` draw and the ideal independent draw is at
most `epsilonBlindExpand`.  This is the same `epsilonBlindExpand` used in the
unlinkability capstone and in the related-spend capstone. -/
def BlindExpandIdealizationBound (epsilonBlindExpand : ℝ≥0∞) : Prop :=
  ∀ (D : Tag × (Fin l → R) × (Fin k → R) → ProbComp Bool),
    ProbComp.boolDistAdvantage
      (do let kk ← ($ᵗ K)
          let tg := P.viewTag kk
          let s' := (P.expandBlind kk).1
          let e' := (P.expandBlind kk).2
          D (tg, s', e'))
      (do let tg ← sampleTag
          let s' ← Smp.sampleS
          let e' ← Smp.sampleE
          D (tg, s', e')) ≤ epsilonBlindExpand.toReal

/-- The random-oracle abstraction the reduction needs, named rather than assumed
silently: for a uniform shared secret, view tag and blinding pair are jointly
three independent samples. False for the concrete primitives, true in the ROM. -/
def ExpandIsIdeal : Prop :=
  ∀ x : Tag × (Fin l → R) × (Fin k → R),
    Pr[= x | (do let kk ← ($ᵗ K)
                 pure (P.viewTag kk, (P.expandBlind kk).1, (P.expandBlind kk).2))] =
      Pr[= x | (do let tg ← sampleTag
                   let s ← Smp.sampleS
                   let e ← Smp.sampleE
                   pure (tg, s, e))]

/-- **The blinding hop as a reduction, type-checked.** An adversary against the
`b = 1` branch of `auxKeyIndependence` becomes a `blindingProblem` distinguisher:
install the seed as recipient 1's `rho`, splice the vector in as the mask. -/
def mlweAdvOfUnlinkAdv (kem : KEM KEMpk KEMsk C K)
    (adv : StealthScheme.UnlinkAdv (MetaPub KEMpk Rho R k) (C × (Tag × Addr))) :
    LearningWithErrors.Adversary (blindingProblem P Smp) :=
  fun chal => do
    let (ek0, _) ← kem.keygen
    let rho0 ← Smp.sampleRho
    let s₁ ← Smp.sampleS
    let s₂ ← Smp.sampleE
    let (ek1, _) ← kem.keygen
    let s₁' ← Smp.sampleS
    let s₂' ← Smp.sampleE
    let t₁ := P.expandA chal.1 *ᵥ s₁' + s₂'
    let (c, _) ← kem.encaps ek1
    let tg ← sampleTag
    adv (ek0, rho0, P.expandA rho0 *ᵥ s₁ + s₂) (ek1, chal.1, t₁)
      (c, (tg, P.hashAddr (P.pack chal.1 (P.power2Round (chal.2 + t₁)))))

end Reduction

/-! ### The middle game

The lattice analogue of `dksapIdeal_announce_indep`, with the shift
`u ↦ u + (t - t')` in place of the group translation. -/

/-- **The middle-game independence lemma.** A uniform mask absorbs the offset, so
the blinding does erase `t`. Note what is NOT quantified over: `rho`, which
enters outside the mask and therefore has to be shared between the two sides. -/
theorem idealAux_indep_of_t (cont : Tag × Addr → ProbComp Bool) (tg : Tag)
    (rho : Rho) (t t' : Fin k → R) (z : Bool) :
    Pr[= z | (do let u ← ($ᵗ (Fin k → R))
                 cont (tg, P.hashAddr (P.pack rho (P.power2Round (u + t)))))] =
      Pr[= z | (do let u ← ($ᵗ (Fin k → R))
                   cont (tg, P.hashAddr (P.pack rho (P.power2Round (u + t')))))] := by
  rw [probOutput_bind_add_right_uniform (Fin k → R) t
      (fun v => cont (tg, P.hashAddr (P.pack rho (P.power2Round v)))) z,
    probOutput_bind_add_right_uniform (Fin k → R) t'
      (fun v => cont (tg, P.hashAddr (P.pack rho (P.power2Round v)))) z]

end MLWE

end ConstructionA

end PqStealth
