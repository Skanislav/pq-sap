/-
Construction A: the algebraic core wired into the game layer.

`Blinding.lean` / `Invariants.lean` prove facts about `A *ᵥ s' + e' + t`;
`Games.lean` / `KEMAnonymity.lean` take an opaque `auxGen : K → PK → Aux`.
This file is the bridge: it defines the `auxGen` the real scheme uses
(`docs/TECHNICAL_SPEC.md` §1, §4), so that the announcement in the model is
the announcement in the spec, and the correctness identity finally enters a
security statement.

## What is modelled, and what is abstracted

The announcement is `(ciphertext, viewTag, stealthAddress)` with

    (s', e')        = expandBlind ss
    stealthKey      = A *ᵥ s' + e' + t          -- A = expandA rho
    stealthAddress  = hashAddr (pack rho (power2Round stealthKey))
    viewTag         = viewTag ss

matching the spec's `keccak256(pack_pk(rho, Power2Round(A*s' + e' + t)))[12:32]`
and `SHA-256(ss)[0:1]`. Every *symmetric* primitive is a parameter, not a
definition: `expandA` (SHAKE128 matrix expansion), `expandBlind`
(`ExpandS ∘ SHAKE256`), `power2Round`, `pack` (`pack_pk`), `hashAddr`
(`keccak256 … [12:32]`), `viewTag` (`SHA-256`). "Faithful" here means the
*algebraic* shape is the spec's — which key material enters which slot, and in
particular that `rho` and `t` are the RECIPIENT's while only `(s', e')` come
from the shared secret. It does NOT mean the hash functions are modelled; they
are uninterpreted functions, so any statement proved here holds for every
instantiation of them, and any statement that NEEDS them to behave randomly
cannot be proved here at all. Section 4 below is exactly such a statement.

## Contents

1. `auxGen` and `stealthAddr_eq_blinded_pk`: the announced stealth key is
   `power2Round` of the honest ML-DSA public key of the widened secret
   `(s₁ + s', s₂ + e')` — `stealth_pk_eq_blinded_keypair` used in the game
   model — and that widened secret is an ownership witness for it.
2. `metaKem` / `scheme`: the KEM whose public key is a whole meta-address, the
   resulting `StealthScheme`, and `unlinkAdvantage_scheme_le` — the
   `KEMAnonymity.lean` bound instantiated at the real announcement.
3. `auxKeyIndependence_eq_zero_of_pk_independent` (and its corollary
   `auxKeyIndependence_tagOnly_eq_zero`): the positive control pinning the
   meaning of `auxKeyIndependence` — it is `0` for any `auxGen` that ignores
   the public key, in particular for a view-tag-only announcement.
4. The blinding hop towards decision-MLWE: the seeded-MLWE problem
   `blindingProblem`, the reduction adversary `mlweAdvOfUnlinkAdv`, and the
   middle-game lemma `idealAux_indep_of_t` (a uniform mask erases the
   recipient's `t`).

## Documented gaps (not `sorry`s — statements this model cannot support)

* **`auxKeyIndependence` is not `0` for construction A, and no MLWE bound
  closes it.** A uniform mask erases `t` (proved: `idealAux_indep_of_t`) but
  `rho` sits OUTSIDE the masked term, in `pack rho …`. The adversary is handed
  both meta-addresses, hence both `rho`s, in `adv.setup`; with `hashAddr` an
  arbitrary function (take it to be the identity, and `pack rho _ = rho`) the
  address reveals which `rho` produced it. The scheme is fine — `keccak` is
  not the identity — but the missing ingredient is `hashAddr ∘ pack` as a
  random oracle, not more proof effort. Closing this term therefore needs a
  ROM extension of the model, and `unlinkAdvantage_scheme_le` should be read
  with that in mind. (The non-vanishing is an argument, NOT machine-checked; a
  counterexample scheme exhibiting it belongs with the negative controls of
  `Falsification.lean`.)
* **The reduction's game 0 is faithful only under `ExpandIsIdeal`.** In the
  real scheme the view tag and the blinding pair come from the same shared
  secret; the reduction must take the mask from the MLWE challenger and
  therefore samples the tag separately. `ExpandIsIdeal` names precisely that
  assumption (`(viewTag ss, expandBlind ss)` for uniform `ss` is distributed
  as three independent samples), which is the SHAKE/SHA-as-random-oracle step.
* **Both games of the reduction still need a bind commutation.**
  `LearningWithErrors.distr` / `uniformDistr` fix the seed and the mask BEFORE
  the adversary runs, whereas `randAuxBranchTrue` draws the shared secret AFTER
  `adv.setup`. So identifying `LearningWithErrors.game0` with the real game
  (on top of `ExpandIsIdeal`) and `game1` with the ideal-blinding game both
  require commuting independent samples past one another
  (`probOutput_bind_eq_tsum` + `tsum_comm`). `idealAux_indep_of_t` is proved in
  the form the second identification consumes; the plumbing is not done, so no
  advantage inequality is claimed.
-/

import PqStealth.Invariants
import PqStealth.KEMAnonymity
import LatticeCrypto.HardnessAssumptions.LearningWithErrors

open OracleComp OracleSpec Matrix

namespace PqStealth

/-! ## 1. Positive control for `auxKeyIndependence`

`auxKeyIndependence` (`KEMAnonymity.lean`) measures whether auxiliary data
built from a fresh random shared secret still betrays WHICH public key it was
built from. If `auxGen` does not look at the public key there is nothing to
betray, and the two games are literally the same computation. -/

section AuxKeyIndependence

variable {PK SK C K Aux : Type} [SampleableType K]

/-- **The term's meaning, pinned.** When `auxGen` ignores its public-key
argument the two computations compared by `auxKeyIndependence` differ only in
which public key they feed to `auxGen`, hence are equal, hence the advantage is
`0`. This is the cheap positive control for the definition: a model in which
`auxKeyIndependence` failed to vanish here would be measuring the wrong thing. -/
theorem auxKeyIndependence_eq_zero_of_pk_independent
    (kem : KEM PK SK C K) (auxGen : K → PK → Aux)
    (adv : StealthScheme.UnlinkAdv PK (C × Aux))
    (h : ∀ (kk : K) (pk pk' : PK), auxGen kk pk = auxGen kk pk') :
    auxKeyIndependence kem auxGen adv = 0 := by
  have key : ((StealthScheme.ofKEMFull kem auxGen).unlinkSetup adv >>=
        randAuxBranchTrue kem auxGen adv) =
      (kem.anonSetup (adv.cipherOf auxGen) >>=
        kem.anonBranchTrue (adv.cipherOf auxGen)) := by
    simp only [StealthScheme.unlinkSetup, StealthScheme.ofKEMFull, KEM.anonSetup,
      StealthScheme.UnlinkAdv.cipherOf, randAuxBranchTrue, KEM.anonBranchTrue,
      bind_assoc, pure_bind]
    refine bind_congr fun x => bind_congr fun y => bind_congr fun st =>
      bind_congr fun c => bind_congr fun kk => ?_
    rw [h kk _ _]
  rw [auxKeyIndependence, key, ProbComp.boolDistAdvantage, sub_self, abs_zero]

/-- The hypothesis above is inhabited, so the control is not vacuous: an
announcement carrying only a view tag (auxiliary data derived from the shared
secret alone) contributes nothing to `auxKeyIndependence`. That is precisely
the coarser model `StealthScheme.ofKEMFull` was introduced to improve on — in
it the term is identically zero, which is why it could not see the blinding
question at all. -/
theorem auxKeyIndependence_tagOnly_eq_zero
    (kem : KEM PK SK C K) (tag : K → Aux)
    (adv : StealthScheme.UnlinkAdv PK (C × Aux)) :
    auxKeyIndependence kem (fun kk _ => tag kk) adv = 0 :=
  auxKeyIndependence_eq_zero_of_pk_independent kem _ adv fun _ _ _ => rfl

end AuxKeyIndependence

namespace ConstructionA

/-! ## 2. The announcement

`R` is the polynomial ring (`R_q = Z_q[X]/(X^256+1)` at ML-DSA-65), `k`/`l` the
module dimensions. Everything else is an uninterpreted parameter standing for a
symmetric primitive; see the module docstring. -/

variable {R : Type} [CommRing R] {k l : ℕ}
  {Rho Bytes T1 Tag Addr KEMpk KEMsk C : Type} {K : Type}

/-- The recipient's meta-address as the model sees it: the ML-KEM
encapsulation key, the matrix seed `rho`, and the FULL-precision spending key
`t` (the spec requires full precision, since `Power2Round(A*s' + e' + t)` is
only well defined on the unrounded value). -/
abbrev MetaPub (KEMpk Rho R : Type) (k : ℕ) : Type := KEMpk × Rho × (Fin k → R)

/-- The recipient's private material: the ML-KEM decapsulation key and the
ML-DSA spending secret `(s₁, s₂)`. -/
abbrev MetaPriv (KEMsk R : Type) (k l : ℕ) : Type := KEMsk × (Fin l → R) × (Fin k → R)

variable (expandA : Rho → Matrix (Fin k) (Fin l) R)
  (expandBlind : K → (Fin l → R) × (Fin k → R))
  (power2Round : (Fin k → R) → T1)
  (pack : Rho → T1 → Bytes)
  (hashAddr : Bytes → Addr)
  (viewTag : K → Tag)

/-- The auxiliary data of a construction-A announcement: the view tag and the
stealth address. The view tag is a function of the shared secret alone; the
stealth address folds in the recipient's own `rho` and `t`, which is why
`StealthScheme.ofKEMFull` gives `auxGen` the public key. -/
def auxGen (kk : K) (pk : MetaPub KEMpk Rho R k) : Tag × Addr :=
  (viewTag kk,
    hashAddr (pack pk.2.1 (power2Round
      (expandA pk.2.1 *ᵥ (expandBlind kk).1 + (expandBlind kk).2 + pk.2.2))))

/-- **Where the correctness identity enters the game model.** For an honestly
generated meta-address (`t = A *ᵥ s₁ + s₂`), the address announced by
`auxGen` is `power2Round` of the honest ML-DSA public key of the widened secret
`(s₁ + s', s₂ + e')` — i.e. the announced stealth key is a real public key that
the recipient holds a signing key for. Immediate from
`stealth_pk_eq_blinded_keypair`. -/
theorem stealthAddr_eq_blinded_pk (kk : K) (ek : KEMpk) (rho : Rho)
    (s₁ : Fin l → R) (s₂ : Fin k → R) :
    (auxGen expandA expandBlind power2Round pack hashAddr viewTag kk
        (ek, rho, expandA rho *ᵥ s₁ + s₂)).2 =
      hashAddr (pack rho (power2Round
        (expandA rho *ᵥ (s₁ + (expandBlind kk).1) + (s₂ + (expandBlind kk).2)))) := by
  rw [auxGen, stealth_pk_eq_blinded_keypair (expandA rho) s₁ (expandBlind kk).1 s₂
    (expandBlind kk).2 _ rfl]

/-- The widened secret behind an announced stealth key is an ownership witness
for it, so the ZK spend statement of `Invariants.lean` is satisfiable for every
announcement construction A produces. -/
theorem announced_key_isOwnershipWitness (kk : K) (rho : Rho)
    (s₁ : Fin l → R) (s₂ : Fin k → R) :
    IsOwnershipWitness (expandA rho)
      (expandA rho *ᵥ (expandBlind kk).1 + (expandBlind kk).2
        + (expandA rho *ᵥ s₁ + s₂))
      (s₁ + (expandBlind kk).1) (s₂ + (expandBlind kk).2) :=
  blinded_is_ownership_witness _ _ _ _ _

/-! ## 3. The KEM whose public key is a meta-address

`StealthScheme.ofKEMFull` needs a `KEM` whose public key is exactly the
argument `auxGen` reads. The ML-KEM keypair alone is not that, so we adapt: key
generation additionally draws the ML-DSA seed `rho` and secret `(s₁, s₂)` and
publishes `t = A *ᵥ s₁ + s₂`. Encapsulation and decapsulation ignore the extra
components — the ciphertext is still a plain ML-KEM ciphertext. -/

variable (sampleRho : ProbComp Rho) (sampleS : ProbComp (Fin l → R))
  (sampleE : ProbComp (Fin k → R))

/-- The composite KEM: an ML-KEM keypair plus the ML-DSA spending keypair, with
the meta-address as the public key.

The spending keypair is drawn from three separate samplers rather than one
opaque joint one; the MLWE reduction below has to resample `(s₁, s₂)` for a
`rho` handed to it by the challenger, which a joint sampler cannot support. -/
def metaKem (kem : KEM KEMpk KEMsk C K) :
    KEM (MetaPub KEMpk Rho R k) (MetaPriv KEMsk R k l) C K where
  keygen := do
    let (ek, dk) ← kem.keygen
    let rho ← sampleRho
    let s₁ ← sampleS
    let s₂ ← sampleE
    pure ((ek, rho, expandA rho *ᵥ s₁ + s₂), (dk, s₁, s₂))
  encaps pk := kem.encaps pk.1
  decaps sk c := kem.decaps sk.1 c

/-- Construction A as a `StealthScheme`: ML-KEM ciphertext plus view tag plus
stealth address, addressed to a full meta-address. -/
def scheme [SampleableType K] (kem : KEM KEMpk KEMsk C K) :
    StealthScheme (MetaPub KEMpk Rho R k) (MetaPriv KEMsk R k l)
      (C × (Tag × Addr)) :=
  StealthScheme.ofKEMFull (metaKem expandA sampleRho sampleS sampleE kem)
    (auxGen expandA expandBlind power2Round pack hashAddr viewTag)

/-- **The algebraic core feeding the game layer, in one statement.** The
unlinkability advantage of construction A — the concrete announcement, with the
stealth address built from the recipient's own `rho` and `t` — is bounded by a
shared-secret-hiding term per branch, the KEM's anonymity advantage, and
`auxKeyIndependence`, which is now the construction-A blinding term rather than
an opaque parameter. Definitionally `unlinkAdvantage_ofKEMFull_le` at
`metaKem` and `auxGen`; the content is that those two are the spec's objects.

See the module docstring for what the `auxKeyIndependence` summand costs: it is
not zero for this `auxGen`, and bounding it needs `hashAddr ∘ pack` modelled as
a random oracle. -/
theorem unlinkAdvantage_scheme_le [SampleableType K] (kem : KEM KEMpk KEMsk C K)
    (adv : StealthScheme.UnlinkAdv (MetaPub KEMpk Rho R k) (C × (Tag × Addr))) :
    (scheme expandA expandBlind power2Round pack hashAddr viewTag
        sampleRho sampleS sampleE kem).unlinkAdvantage adv ≤
      sharedSecretHidingTrue (metaKem expandA sampleRho sampleS sampleE kem)
          (auxGen expandA expandBlind power2Round pack hashAddr viewTag) adv
        + auxKeyIndependence (metaKem expandA sampleRho sampleS sampleE kem)
          (auxGen expandA expandBlind power2Round pack hashAddr viewTag) adv
        + (metaKem expandA sampleRho sampleS sampleE kem).anonAdvantage
          (adv.cipherOf (auxGen expandA expandBlind power2Round pack hashAddr viewTag))
        + sharedSecretHidingFalse (metaKem expandA sampleRho sampleS sampleE kem)
          (auxGen expandA expandBlind power2Round pack hashAddr viewTag) adv :=
  unlinkAdvantage_ofKEMFull_le _ _ adv

/-! ## 4. The blinding hop towards decision-MLWE

The hop replaces the real mask `A *ᵥ s' + e'` inside the announced stealth key
by a uniform vector. That is a decision-MLWE step, stated here in the SEEDED
form the scheme actually uses: the challenge is the seed `rho`, not the matrix,
because the reduction must be able to compute `pack rho …` and cannot invert
`expandA`. It coincides with `LearningWithErrors.moduleMatrixProblem` (up to
the transpose, since `matrixProblem` uses `vecMul`) whenever
`expandA <$> sampleRho` is uniform on matrices — the standard "expansion is a
random oracle" reading, which is not proved here. -/

section MLWE

variable [SampleableType R] (sampleTag : ProbComp Tag)

/-- Seeded decision-MLWE over the module: given a matrix seed `rho` and a
vector `y`, decide whether `y = expandA rho *ᵥ s + e` for short `(s, e)` or `y`
is uniform. An instance of VCVio's generic `LearningWithErrors.Problem`, so
`LearningWithErrors.advantage` applies to it unchanged. -/
def blindingProblem : LearningWithErrors.Problem Rho (Fin l → R) (Fin k → R) where
  sampleChallenge := sampleRho
  sampleSecret := sampleS
  sampleError := sampleE
  noiseless := fun s rho => expandA rho *ᵥ s
  sampleUniform := $ᵗ (Fin k → R)

variable [SampleableType K]

/-- The random-oracle abstraction the reduction needs, named rather than
assumed silently: for a uniform shared secret, the view tag and the blinding
pair are jointly distributed as three independent samples. In the real scheme
both are deterministic functions of the same `ss` (`SHA-256(ss)` and
`ExpandS(SHAKE256(ss, 64))`), so this is false for the concrete primitives and
true in the random-oracle model. The reduction below must draw the mask from
the MLWE challenger and the tag separately, so its game 0 matches the real
`randAuxBranchTrue` game exactly under this hypothesis and not otherwise. -/
def ExpandIsIdeal : Prop :=
  ∀ x : Tag × (Fin l → R) × (Fin k → R),
    Pr[= x | (do let kk ← ($ᵗ K)
                 pure (viewTag kk, (expandBlind kk).1, (expandBlind kk).2))] =
      Pr[= x | (do let tg ← sampleTag
                   let s ← sampleS
                   let e ← sampleE
                   pure (tg, s, e))]

/-- **The blinding hop as a reduction, type-checked.** An adversary against the
`b = 1` branch of `auxKeyIndependence` — one that distinguishes an announcement
whose stealth key is masked by the real `A *ᵥ s' + e'` from one masked by a
uniform vector — becomes a distinguisher for `blindingProblem`.

The reduction receives `(rho, y)`, installs `rho` as recipient 1's matrix seed,
draws recipient 1's spending secret itself (this is why key generation takes
three separate samplers), simulates recipient 0 honestly, and splices `y` in as
the mask: the announced address is `hashAddr (pack rho (power2Round (y + t₁)))`.
With `y` real this is the construction-A announcement to recipient 1 (under
`ExpandIsIdeal`, which decouples the tag from the mask); with `y` uniform it is
the ideal-blinding announcement of `idealAux_indep_of_t`. -/
def mlweAdvOfUnlinkAdv (kem : KEM KEMpk KEMsk C K)
    (adv : StealthScheme.UnlinkAdv (MetaPub KEMpk Rho R k) (C × (Tag × Addr))) :
    LearningWithErrors.Adversary
      (blindingProblem expandA sampleRho sampleS sampleE) :=
  fun chal => do
    let (ek0, _) ← kem.keygen
    let rho0 ← sampleRho
    let s₁ ← sampleS
    let s₂ ← sampleE
    let (ek1, _) ← kem.keygen
    let s₁' ← sampleS
    let s₂' ← sampleE
    let t₁ := expandA chal.1 *ᵥ s₁' + s₂'
    let st ← adv.setup (ek0, rho0, expandA rho0 *ᵥ s₁ + s₂) (ek1, chal.1, t₁)
    let (c, _) ← kem.encaps ek1
    let tg ← sampleTag
    adv.distinguish st
      (c, (tg, hashAddr (pack chal.1 (power2Round (chal.2 + t₁)))))

/-! ### The middle game

Once the mask is uniform the announcement no longer depends on the recipient's
spending key. This is the lattice analogue of `dksapIdeal_announce_indep`, with
the shift `u ↦ u + (t - t')` in place of the group translation. -/

/-- A uniform mask absorbs any fixed offset: `u + t` for uniform `u` is
distributed as `u`. -/
theorem uniform_mask_absorb {β : Type} (cont : (Fin k → R) → ProbComp β)
    (t : Fin k → R) (z : β) :
    Pr[= z | (do let u ← ($ᵗ (Fin k → R)); cont (u + t))] =
      Pr[= z | (do let u ← ($ᵗ (Fin k → R)); cont u)] :=
  probOutput_bind_add_right_uniform (Fin k → R) t cont z

/-- **The middle-game independence lemma.** With the mask drawn uniformly, the
announcement to a recipient with spending key `t` and one to a recipient with
spending key `t'` are the same distribution — the blinding does erase `t`.

Note what the statement does NOT quantify over: `rho` is shared between the two
sides. It has to be. `rho` enters through `pack`, outside the masked argument,
so the two sides with different seeds are genuinely different distributions for
a general `hashAddr`; see the module docstring. -/
theorem idealAux_indep_of_t (cont : Tag × Addr → ProbComp Bool) (tg : Tag)
    (rho : Rho) (t t' : Fin k → R) (z : Bool) :
    Pr[= z | (do let u ← ($ᵗ (Fin k → R))
                 cont (tg, hashAddr (pack rho (power2Round (u + t)))))] =
      Pr[= z | (do let u ← ($ᵗ (Fin k → R))
                   cont (tg, hashAddr (pack rho (power2Round (u + t')))))] := by
  rw [uniform_mask_absorb (fun v => cont (tg, hashAddr (pack rho (power2Round v)))) t z,
    uniform_mask_absorb (fun v => cont (tg, hashAddr (pack rho (power2Round v)))) t' z]

end MLWE

end ConstructionA

end PqStealth
