import PqStealth.DKSAP
import PqStealth.KEMAnonymity

/-!
# Detection soundness: the false-positive rate

Proved: DKSAP's false-positive rate is EXACTLY `1 / |F|`, for every hash `h` --
the leak is the uniform spending scalar, not a hash collision; and for the
KEM-based scheme, `falsePositiveRate ≤ ε + decapsRoR`, where `ε` bounds tag
collisions over a uniform secret and `decapsRoR` is the real-or-random gap of
recipient 0's decapsulated key (a KEM IND-CPA question, as everywhere else),
with `decapsRoR = 0` under an ideal decapsulation; and the view-tag instance,
`SoundWithin (1/256 + decapsRoR)` for a one-byte tag.

Assumed: tag collision-freeness and the uniformity of `viewTag` on a uniform
key are hypotheses, as is the ideal decapsulation. See
`docs/announcement-model.md`.
-/

open OracleComp OracleSpec

namespace PqStealth

/-! ## Bookkeeping for `Pr[= true | …]` over a bind

Three shapes recur below: reading off a uniform draw, bounding a bind by a
uniform bound on its continuation, and collapsing a prefix. Each is a one-line
specialisation of a VCVio lemma (`probOutput_map` + `probEvent_eq_eq_probOutput`,
`probEvent_bind_le_of_forall_le`, `probOutput_bind_of_const`) to the
`Pr[= true | …]` spelling the games use. -/

/-- Testing a draw against a fixed value returns `true` exactly as often as the
draw hits it. -/
theorem probOutput_true_bind_decide_eq {α : Type} [DecidableEq α] (p : ProbComp α) (t : α) :
    Pr[= true | (do let x ← p; pure (decide (x = t)))] = Pr[= t | p] := by
  rw [bind_pure_comp, probOutput_map]
  simp only [decide_eq_true_eq]
  exact probEvent_eq_eq_probOutput p t

/-- A bind is bounded by any bound holding uniformly over its continuation. The
workhorse for the KEM false-positive bound. -/
theorem probOutput_true_bind_le {α : Type} (p : ProbComp α) (f : α → ProbComp Bool)
    (c : ENNReal) (h : ∀ a, Pr[= true | f a] ≤ c) :
    Pr[= true | p >>= f] ≤ c := by
  rw [← probEvent_eq_eq_probOutput]
  exact probEvent_bind_le_of_forall_le fun a _ => by
    rw [probEvent_eq_eq_probOutput]; exact h a

/-- A prefix whose continuation has a constant verdict probability contributes
nothing (a `ProbComp` never fails). The equality counterpart of
`probOutput_true_bind_le`. -/
theorem probOutput_true_bind_eq {α : Type} (p : ProbComp α) (f : α → ProbComp Bool)
    (c : ENNReal) (h : ∀ a, Pr[= true | f a] = c) :
    Pr[= true | p >>= f] = c := by
  rw [probOutput_bind_of_const p (fun a _ => h a), probFailure_of_liftM_PMF, tsub_zero, one_mul]

/-! ## DKSAP: the exact false-positive rate

A stranger's scan fires iff `m1 + h(r • V1) = m0 + h(v0 • R)`. Recipient 1's
spending scalar `m1` is uniform and independent of everything else in that
equation, so for every value of the other four draws exactly one `m1` out of
`|F|` triggers, whatever `h` does. -/

section DKSAP

variable {F : Type} [Field F] [SampleableType F] [Fintype F] [DecidableEq F]
  {G : Type} [AddCommGroup G] [Module F G] [DecidableEq G]

/-- The false-positive probability of DKSAP is exactly `|F|⁻¹`, for every hash
`h`: injectivity of `x ↦ x • g` turns the scan test into a linear equation in
recipient 1's uniform spending scalar. -/
theorem probOutput_falsePositiveExp_dksap_eq (g : G) (h : G → F)
    (hinj : Function.Injective (fun x : F => x • g)) :
    Pr[= true | (dksap g h).FalsePositiveExp] = (Fintype.card F : ENNReal)⁻¹ := by
  have key : ∀ m0 v0 m1 v1 r : F,
      (m1 • g + h (r • v1 • g) • g = (m0 + h (v0 • r • g)) • g)
        ↔ (m1 = m0 + h (v0 • r • g) - h (r • v1 • g)) := by
    intro m0 v0 m1 v1 r
    rw [← add_smul, eq_sub_iff_add_eq]
    exact ⟨fun hEq => hinj hEq, fun hEq => congrArg (fun x : F => x • g) hEq⟩
  have base : ∀ c : F, Pr[= true | (do let m1 ← ($ᵗ F); pure (decide (m1 = c)))]
      = (Fintype.card F : ENNReal)⁻¹ := fun c => by
    rw [probOutput_true_bind_decide_eq, probOutput_uniformSample]
  simp only [StealthScheme.FalsePositiveExp, dksap, bind_assoc, pure_bind, key]
  refine probOutput_true_bind_eq _ _ _ fun m0 => ?_
  refine probOutput_true_bind_eq _ _ _ fun v0 => ?_
  rw [probOutput_bind_bind_swap]
  refine probOutput_true_bind_eq _ _ _ fun v1 => ?_
  rw [probOutput_bind_bind_swap]
  refine probOutput_true_bind_eq _ _ _ fun r => ?_
  exact base _

/-- **DKSAP's false-positive rate, exactly.** Not zero and not a hash-collision
term: `1 / |F|`, the chance that two independent recipients' spending scalars
line up. See `docs/announcement-model.md`. -/
theorem dksap_falsePositiveRate_eq (g : G) (h : G → F)
    (hinj : Function.Injective (fun x : F => x • g)) :
    (dksap g h).falsePositiveRate = 1 / (Fintype.card F : ℝ) := by
  rw [StealthScheme.falsePositiveRate, probOutput_falsePositiveExp_dksap_eq g h hinj,
    ENNReal.toReal_inv, ENNReal.toReal_natCast, one_div]

/-- DKSAP is sound within `1 / |F|`, the acceptance form of the exact rate. -/
theorem dksap_falsePositiveRate_le (g : G) (h : G → F)
    (hinj : Function.Injective (fun x : F => x • g)) :
    (dksap g h).SoundWithin (1 / (Fintype.card F : ℝ)) :=
  le_of_eq (dksap_falsePositiveRate_eq g h hinj)

end DKSAP

/-! ## The KEM scheme: tag collisions plus a real-or-random term

A stranger's scan fires when `auxGen` of THEIR decapsulated key and THEIR own
public key hits the announced tag. Idealize the decapsulated key to a uniform
one and what is left is a pure tag-collision probability; the gap is
`decapsRoR`. -/

section KEMSoundness

variable {PK SK C K Aux : Type} [SampleableType K] [DecidableEq Aux]
  (kem : KEM PK SK C K) (auxGen : K → PK → Aux)

/-- The tag is `ε`-collision-free: over a UNIFORM secret, `auxGen` hits any
prescribed value with probability at most `ε`. For a view tag this is a counting
argument on the tag alphabet. -/
def AuxCollisionFree (auxGen : K → PK → Aux) (ε : ℝ) : Prop :=
  ∀ (a : Aux) (pk : PK),
    (Pr[= true | (do let k ← ($ᵗ K); pure (decide (a = auxGen k pk)))]).toReal ≤ ε

/-- The false-positive experiment with recipient 0's decapsulated key replaced
by a fresh uniform one: the announcement is unchanged, only the scanner's secret
is idealized. -/
def falsePositiveIdeal : ProbComp Bool := do
  let ks0 ← kem.keygen
  let ks1 ← kem.keygen
  let ck ← kem.encaps ks1.1
  let k ← ($ᵗ K)
  pure (decide (auxGen ck.2 ks1.1 = auxGen k ks0.1))

/-- Real-or-random advantage of the decapsulated key INSIDE the false-positive
experiment: how far a stranger's decapsulation is from a fresh uniform key. A
KEM IND-CPA question, like `sharedSecretHiding`. -/
noncomputable def decapsRoR : ℝ :=
  (StealthScheme.ofKEMFull kem auxGen).FalsePositiveExp.boolDistAdvantage
    (falsePositiveIdeal kem auxGen)

/-- In the idealized experiment the verdict is a tag collision against a uniform
secret, so `AuxCollisionFree` bounds it directly. -/
theorem probOutput_falsePositiveIdeal_le (ε : ℝ) (hε : 0 ≤ ε)
    (hTag : AuxCollisionFree auxGen ε) :
    (Pr[= true | falsePositiveIdeal kem auxGen]).toReal ≤ ε := by
  have hbound : Pr[= true | falsePositiveIdeal kem auxGen] ≤ ENNReal.ofReal ε := by
    refine probOutput_true_bind_le _ _ _ fun ks0 => ?_
    refine probOutput_true_bind_le _ _ _ fun ks1 => ?_
    refine probOutput_true_bind_le _ _ _ fun ck => ?_
    exact (ENNReal.le_ofReal_iff_toReal_le
      (ne_top_of_le_ne_top ENNReal.one_ne_top probOutput_le_one) hε).2
      (hTag (auxGen ck.2 ks1.1) ks0.1)
  exact (ENNReal.le_ofReal_iff_toReal_le
    (ne_top_of_le_ne_top ENNReal.one_ne_top probOutput_le_one) hε).1 hbound

/-- **Detection soundness of the KEM scheme.** A stranger false-positives with
probability at most the tag-collision bound plus the real-or-random gap of their
own decapsulated key. Triangle inequality over `falsePositiveIdeal`. -/
theorem falsePositiveRate_ofKEMFull_le (ε : ℝ) (hε : 0 ≤ ε)
    (hTag : AuxCollisionFree auxGen ε) :
    (StealthScheme.ofKEMFull kem auxGen).SoundWithin (ε + decapsRoR kem auxGen) := by
  have hgap : (StealthScheme.ofKEMFull kem auxGen).falsePositiveRate
      - (Pr[= true | falsePositiveIdeal kem auxGen]).toReal ≤ decapsRoR kem auxGen :=
    le_abs_self _
  have hideal := probOutput_falsePositiveIdeal_le kem auxGen ε hε hTag
  unfold StealthScheme.SoundWithin
  linarith

/-- Under an ideal decapsulation the real and idealized experiments are the same
computation. No perfectly correct KEM satisfies this hypothesis globally -- it
pins down that `decapsRoR` is the ONLY gap, it is not a security claim. -/
theorem decapsRoR_eq_zero_of_decaps_uniform
    (hdec : ∀ sk c, kem.decaps sk c = (do let k ← ($ᵗ K); pure (some k))) :
    decapsRoR kem auxGen = 0 := by
  have hEq : (StealthScheme.ofKEMFull kem auxGen).FalsePositiveExp
      = falsePositiveIdeal kem auxGen := by
    simp only [StealthScheme.FalsePositiveExp, StealthScheme.ofKEMFull, falsePositiveIdeal,
      hdec, bind_assoc, pure_bind, Option.elim_some]
  simp only [decapsRoR, hEq, ProbComp.boolDistAdvantage, sub_self, abs_zero]

/-- With the decapsulated key ideal, detection soundness is the tag-collision
bound outright. -/
theorem falsePositiveRate_ofKEMFull_le_of_decaps_uniform (ε : ℝ) (hε : 0 ≤ ε)
    (hTag : AuxCollisionFree auxGen ε)
    (hdec : ∀ sk c, kem.decaps sk c = (do let k ← ($ᵗ K); pure (some k))) :
    (StealthScheme.ofKEMFull kem auxGen).SoundWithin ε := by
  have h := falsePositiveRate_ofKEMFull_le kem auxGen ε hε hTag
  rw [decapsRoR_eq_zero_of_decaps_uniform kem auxGen hdec, add_zero] at h
  exact h

end KEMSoundness

/-! ## A coordinate of a uniform vector is uniform

The fiber of `v ↦ v.get i` over `x` has one free slot at `i` and `n - 1` arbitrary
slots, so it has cardinality `|α| ^ (n - 1)`; dividing by the `|α| ^ n` vectors
leaves exactly `1 / |α|`. This discharges the `hUnif` hypothesis pattern of the
view-tag theorems below whenever the shared secret `K` is sampled as a vector and
the tag is a coordinate projection of it. In-tree view tags are instead
hash-derived (`ConstructionA.viewTag : K → Tag`), so the pending instantiation of
`soundWithin_ofKEMFull_oneByteTag` to concrete bytes is not made here. -/

section UniformCoordinate

variable {α : Type} [Fintype α] [DecidableEq α] [SampleableType α]

/-- The equivalence underlying `instFintypeVector`, named so the fiber of a
coordinate projection can be transferred from `Vector α n` to `Fin n → α`. -/
noncomputable def vectorEquivPi (n : ℕ) : Vector α n ≃ (Fin n → α) where
  toFun := fun v i => v.get i
  invFun := Vector.ofFn
  left_inv := fun v => Vector.ext fun i hi => by simp [Vector.ofFn, Vector.get]
  right_inv := fun f => funext fun i => by simp [Vector.get, Vector.ofFn]

/-- The fiber of the evaluation `f ↦ f i` under `x` — equivalently, functions on
`{j // j ≠ i}` — has cardinality `|α| ^ (n - 1)`. -/
theorem card_fiber_eval' {α : Type} [Fintype α] [DecidableEq α] [Nonempty α] {n : ℕ}
    (i : Fin n) (x : α) :
    Fintype.card { f : Fin n → α // x = f i } = Fintype.card α ^ (n - 1) := by
  classical
  let e : { f : Fin n → α // x = f i } ≃ ({ j : Fin n // j ≠ i } → α) :=
  { toFun := fun f j => f.1 j.1
    invFun := fun g =>
      ⟨fun j => if h : j = i then x else g ⟨j, h⟩, by simp⟩
    left_inv := fun f => by
      apply Subtype.ext; funext j
      dsimp only
      split_ifs with h
      · subst h; simp only [f.2]
      · rfl
    right_inv := fun g => by
      funext j
      dsimp only
      split_ifs with h
      · exact (j.2 h).elim
      · exact congrArg g (Subtype.ext rfl) }
  rw [Fintype.card_congr e, Fintype.card_fun, Fintype.card_subtype_compl (· = i),
    Fintype.card_fin, Fintype.card_subtype_eq i]

/-- **A coordinate projection of a uniform vector is uniform.** Under
`vectorEquivPi` the fiber of the coordinate projection over `x` has cardinality
`|α| ^ (n - 1)` (`card_fiber_eval'`); dividing by the `|α| ^ n` vectors leaves
`1 / |α|`. -/
theorem probOutput_map_get_uniformSample_vector {n : ℕ} (i : Fin n) (x : α) :
    Pr[= x | (fun v : Vector α n => v.get i) <$> ($ᵗ (Vector α n))]
      = (Fintype.card α : ENNReal)⁻¹ := by
  classical
  rw [probOutput_map_eq_sum_fintype_ite]
  simp only [probOutput_uniformSample]
  rw [← Finset.sum_filter]
  rw [Finset.sum_const, nsmul_eq_mul]
  -- The filtered count is the fiber cardinality `|α| ^ (n - 1)`.
  have hfilt : (Finset.univ.filter (fun v : Vector α n => x = v.get i)).card
      = Fintype.card α ^ (n - 1) := by
    have hcard_eq : (Finset.univ.filter (fun v : Vector α n => x = v.get i)).card
        = (Finset.univ.filter (fun f : Fin n → α => x = f i)).card := by
      apply Finset.card_equiv (vectorEquivPi n)
      intro v
      simp [vectorEquivPi, Finset.mem_filter, Finset.mem_univ, true_and]
    rw [hcard_eq]
    rw [← @Fintype.card_of_subtype (Fin n → α) (fun f => x = f i)
        (Finset.univ.filter (fun f : Fin n → α => x = f i))
        (fun f => by simp only [Finset.mem_filter, Finset.mem_univ, true_and])]
    exact card_fiber_eval' i x
  rw [hfilt, Nat.cast_pow]
  -- The total count `|α| ^ n`; cast through and cancel one factor.
  have hC0 : (Fintype.card α : ENNReal) ≠ 0 := by
    exact_mod_cast Fintype.card_ne_zero
  have hCtop : (Fintype.card α : ENNReal) ≠ (⊤ : ENNReal) := ENNReal.natCast_ne_top _
  have hcard : (Fintype.card (Vector α n) : ENNReal) = (Fintype.card α : ENNReal) ^ n := by
    have h1 : Fintype.card (Vector α n) = Fintype.card (Fin n → α) :=
      Fintype.card_congr (vectorEquivPi n)
    rw [h1, Fintype.card_fun, Fintype.card_fin, Nat.cast_pow]
  have hCn : (Fintype.card α : ENNReal) ^ n
      = (Fintype.card α : ENNReal) ^ (n - 1) * (Fintype.card α : ENNReal) := by
    have hn : NeZero n := Fin.neZero i
    rw [← pow_succ, Nat.sub_add_cancel hn.pos]
  have hCpow0 : (Fintype.card α : ENNReal) ^ (n - 1) ≠ 0 := ENNReal.pow_ne_zero hC0 (n - 1)
  have hCpowtop : (Fintype.card α : ENNReal) ^ (n - 1) ≠ (⊤ : ENNReal) := ENNReal.pow_ne_top hCtop
  -- Algebra: C^(n-1) * (C^(n-1) * C)⁻¹ = C⁻¹.
  rw [hcard, hCn]
  rw [ENNReal.mul_inv (Or.inl hCpow0) (Or.inr hC0)]
  rw [ENNReal.mul_inv_cancel_left hCpow0 hCpowtop]

end UniformCoordinate

/-! ## The view tag

`auxGen k pk = (viewTag k, …)`: the announcement leads with a short tag derived
from the shared secret alone. Its alphabet size is the whole collision bound,
which is where the ERC's "one byte" gets its `1/256`. -/

section ViewTag

variable {PK K T Rest : Type} [SampleableType K] [Fintype T] [DecidableEq T]
  [DecidableEq Rest]

/-- Auxiliary data led by a view tag: the tag depends on the shared secret
alone, the remainder (stealth address, ciphertext hash, …) may depend on both. -/
def taggedAux (viewTag : K → T) (rest : K → PK → Rest) : K → PK → T × Rest :=
  fun k pk => (viewTag k, rest k pk)

/-- **The tag-length bound.** If `viewTag` maps a uniform secret to a uniform
tag, tag-led auxiliary data is `1/|T|`-collision-free: the remainder can only
help, so the alphabet size is the whole story. -/
theorem auxCollisionFree_taggedAux (viewTag : K → T) (rest : K → PK → Rest)
    (hUnif : ∀ t : T, Pr[= t | viewTag <$> ($ᵗ K)] = (Fintype.card T : ENNReal)⁻¹) :
    AuxCollisionFree (taggedAux viewTag rest) (1 / (Fintype.card T : ℝ)) := by
  intro a pk
  haveI : Nonempty T := ⟨a.1⟩
  have hmono : Pr[= true | (do let k ← ($ᵗ K); pure (decide (a = taggedAux viewTag rest k pk)))]
      ≤ Pr[= true | (do let k ← ($ᵗ K); pure (decide (viewTag k = a.1)))] := by
    refine probOutput_bind_mono fun k _ => ?_
    by_cases hk : a = taggedAux viewTag rest k pk
    · have htag : viewTag k = a.1 := by simp only [hk, taggedAux]
      simp only [hk, htag, decide_true, le_refl]
    · simp only [hk, decide_false, probOutput_pure, Bool.true_eq_false, if_false, zero_le]
  have hbridge : (do let x ← (viewTag <$> ($ᵗ K)); pure (decide (x = a.1)))
      = (do let k ← ($ᵗ K); pure (decide (viewTag k = a.1))) := by
    simp only [map_eq_bind_pure_comp, bind_assoc, pure_bind, Function.comp_apply]
  have hval : Pr[= true | (do let k ← ($ᵗ K); pure (decide (viewTag k = a.1)))]
      = (Fintype.card T : ENNReal)⁻¹ := by
    rw [← hbridge, probOutput_true_bind_decide_eq, hUnif]
  have hfin : ((Fintype.card T : ENNReal))⁻¹ ≠ ⊤ := by
    simp only [ne_eq, ENNReal.inv_eq_top, Nat.cast_eq_zero, Fintype.card_ne_zero,
      not_false_eq_true]
  have hle := ENNReal.toReal_mono hfin (hmono.trans_eq hval)
  rwa [ENNReal.toReal_inv, ENNReal.toReal_natCast, ← one_div] at hle

/-- **Detection soundness of the deployed shape**: KEM announcement, tag-led
auxiliary data. The false-positive rate is at most the tag alphabet's reciprocal
plus the real-or-random term. -/
theorem soundWithin_ofKEMFull_taggedAux {SK C : Type}
    (kem : KEM PK SK C K) (viewTag : K → T) (rest : K → PK → Rest)
    (hUnif : ∀ t : T, Pr[= t | viewTag <$> ($ᵗ K)] = (Fintype.card T : ENNReal)⁻¹) :
    (StealthScheme.ofKEMFull kem (taggedAux viewTag rest)).SoundWithin
      (1 / (Fintype.card T : ℝ) + decapsRoR kem (taggedAux viewTag rest)) :=
  falsePositiveRate_ofKEMFull_le kem (taggedAux viewTag rest) _
    (by positivity) (auxCollisionFree_taggedAux viewTag rest hUnif)

end ViewTag

/-! ## The one-byte tag

`Fintype.card (Fin (2 ^ (8 * n))) = 2 ^ (8 * n)`, so an `n`-byte tag is
`2 ^ (-8n)`; at `n = 1` this is the ERC's `1/256`. -/

section ByteTag

variable {PK SK C K Rest : Type} [SampleableType K] [DecidableEq Rest]

/-- **The ERC's tag-length rationale, machine-checked.** With an `n`-byte view
tag the false-positive rate is at most `2 ^ (-8n)` plus the real-or-random term;
`n = 1` gives `1/256`. -/
theorem soundWithin_ofKEMFull_byteTag (n : ℕ) (kem : KEM PK SK C K)
    (viewTag : K → Fin (2 ^ (8 * n))) (rest : K → PK → Rest)
    (hUnif : ∀ t : Fin (2 ^ (8 * n)),
      Pr[= t | viewTag <$> ($ᵗ K)] = ((2 ^ (8 * n) : ℕ) : ENNReal)⁻¹) :
    (StealthScheme.ofKEMFull kem (taggedAux viewTag rest)).SoundWithin
      (1 / ((2 ^ (8 * n) : ℕ) : ℝ) + decapsRoR kem (taggedAux viewTag rest)) := by
  have hcard : Fintype.card (Fin (2 ^ (8 * n))) = 2 ^ (8 * n) := Fintype.card_fin _
  have := soundWithin_ofKEMFull_taggedAux kem viewTag rest
    (by simpa only [hcard, Nat.cast_pow, Nat.cast_ofNat] using hUnif)
  rwa [hcard] at this

/-- **The ERC's one-byte view tag.** `1/256` false positives from the tag, plus
the real-or-random term: the number the scanning-cost rationale uses. -/
theorem soundWithin_ofKEMFull_oneByteTag (kem : KEM PK SK C K)
    (viewTag : K → Fin 256) (rest : K → PK → Rest)
    (hUnif : ∀ t : Fin 256, Pr[= t | viewTag <$> ($ᵗ K)] = (256 : ENNReal)⁻¹) :
    (StealthScheme.ofKEMFull kem (taggedAux viewTag rest)).SoundWithin
      (1 / 256 + decapsRoR kem (taggedAux viewTag rest)) := by
  have hcard : Fintype.card (Fin 256) = 256 := Fintype.card_fin 256
  have h := soundWithin_ofKEMFull_taggedAux kem viewTag rest
    (by simpa only [hcard, Nat.cast_ofNat] using hUnif)
  rw [hcard] at h
  exact_mod_cast h

end ByteTag

end PqStealth
