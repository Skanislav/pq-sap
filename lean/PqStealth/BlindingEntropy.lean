import PqStealth.BlindingROM
import LatticeCrypto.MLDSA.Concrete.Instance

/-! # The ROM query bound for the Construction A address point

`BlindingROM` reduced the blinding term to the two bad-query probabilities. Here each is bounded
by `qH · β`: `qH` bounds the adversary's address-oracle queries and `β` the point mass of the
address point `pack rho (power2Round (u + t))` over the uniform mask `u`
(`BlindPointMassBound`). The generic ROM pieces are in `ROMUpToBad` (§ query budget). -/

open LatticeCrypto MLDSA MLDSA.Concrete OracleComp OracleSpec ENNReal

namespace PqStealth

namespace ConstructionA

variable {R : Type} [CommRing R] {k l : ℕ} {Rho WireBytes T1 Tag Addr K : Type}
  [SampleableType Addr]

/-- The address point of a uniform mask: `pack rho (power2Round (u + t))` for `u` uniform. -/
def blindPointSample (P : Prims R Rho WireBytes T1 Tag Addr K k l)
    [SampleableType R] (rho : Rho) (t : Fin k → R) : ProbComp WireBytes :=
  do let u ← $ᵗ (Fin k → R)
     pure (P.pack rho (P.power2Round (u + t)))

/-- Point-mass (min-entropy) bound `β` on the address point over a uniform mask: no single
wire encoding is hit with probability above `β`. -/
def BlindPointMassBound (P : Prims R Rho WireBytes T1 Tag Addr K k l)
    [SampleableType R] (beta : ℝ≥0∞) : Prop :=
  ∀ (rho : Rho) (t : Fin k → R) (x : WireBytes),
    Pr[= x | blindPointSample P rho t] ≤ beta

/-- **ROM bad-query bound.** An adversary making at most `qH` address-oracle queries hits
recipient `b`'s address point with probability at most `qH · β`. -/
theorem probOutput_blindBadQuery_le
    (P : Prims R Rho WireBytes T1 Tag Addr K k l)
    [SampleableType R] [DecidableEq WireBytes]
    (tg : Tag) (rho : Bool → Rho) (t : Bool → Fin k → R)
    (adv : BlindAdvRO Tag Addr WireBytes) (qH : ℕ)
    (hq : ∀ x, IsQueryBoundP (adv x) (fun i => i.isRight = true) qH)
    (beta : ℝ≥0∞) (hB : BlindPointMassBound P beta) (b : Bool) :
    Pr[= true | blindBadQuery P tg rho t adv b] ≤ (qH : ℝ≥0∞) * beta := by
  -- the point-mass hypothesis in event form over the mask alone
  have hpt : ∀ (a : Addr) (x : WireBytes),
      Pr[fun u : Fin k → R => blindPoint P rho t b (u, a) = x | $ᵗ (Fin k → R)] ≤ beta := by
    intro a x
    have := hB (rho b) (t b) x
    rw [show blindPointSample P (rho b) (t b) =
        (fun u => blindPoint P rho t b (u, a)) <$> ($ᵗ (Fin k → R)) from by
      simp only [blindPointSample, blindPoint, map_eq_bind_pure_comp, Function.comp_def],
      probOutput_map] at this
    exact this
  -- 1. the flag of the programmed run, as an event over the prefix and the run
  unfold blindBadQuery badQueryGame
  rw [← map_bind, probOutput_map]
  -- 2. programmed flag ≤ plain-run "point cached", pointwise in the prefix
  have hstep : Pr[fun z => z.2.2 = true |
      blindPrefix (R := R) (k := k) (Addr := Addr) >>= fun x =>
        (simulateQ (programmedROImpl (pointPolicy (blindPoint P rho t b x) x.2))
          (adv (tg, x.2))).run (∅, false)] ≤
      Pr[fun w : ((Fin k → R) × Addr) × (Bool × (WireBytes →ₒ Addr).QueryCache) =>
          QueryCache.isCached w.2.2 (blindPoint P rho t b w.1) = true |
        blindPrefix (R := R) (k := k) (Addr := Addr) >>= fun x =>
          (fun z => (x, z)) <$> (simulateQ (roImpl (WireBytes →ₒ Addr)) (adv (tg, x.2))).run ∅] := by
    rw [probEvent_bind_eq_tsum, probEvent_bind_eq_tsum]
    refine ENNReal.tsum_le_tsum fun x => mul_le_mul' le_rfl ?_
    rw [probEvent_flag_programmed_eq_tracking, probEvent_map]
    exact probEvent_flag_trackingROImpl_pointPolicy_le (adv (tg, x.2)) _ _ ∅
      (QueryCache.empty_apply _)
  refine hstep.trans ?_
  -- 3. sample the mask last: it is independent of the adversary's run
  simp only [blindPrefix, bind_assoc, pure_bind]
  rw [probEvent_bind_bind_swap]
  refine probEvent_bind_le_const _ _ _ _ fun a _ => ?_
  simp only [map_eq_bind_pure_comp, Function.comp_def]
  rw [probEvent_bind_bind_swap]
  refine probEvent_bind_le_const _ _ _ _ fun z hz => ?_
  obtain ⟨S, hS, hkeys⟩ := roImpl_run_keys_subset (adv (tg, a)) qH (hq _) ∅ z hz
  rw [show (($ᵗ (Fin k → R)) >>= fun u => pure (((u, a), z))) =
      (fun u => ((u, a), z)) <$> ($ᵗ (Fin k → R)) from by
    simp only [map_eq_bind_pure_comp, Function.comp_def], probEvent_map]
  calc Pr[fun u : Fin k → R => QueryCache.isCached z.2 (blindPoint P rho t b (u, a)) = true |
          $ᵗ (Fin k → R)]
      ≤ S.card * beta :=
        probEvent_isSome_apply_le ($ᵗ (Fin k → R)) (fun u => blindPoint P rho t b (u, a)) beta
          (hpt a) z.2 S (fun t' h => by
            rcases hkeys t' h with h' | h'
            · simp at h'
            · exact h')
    _ ≤ qH * beta := mul_le_mul' (by exact_mod_cast hS) le_rfl

/-- **ROM bad-query bound, real form.** Needs `beta ≠ ⊤` so that the real bound is not the
degenerate `(⊤).toReal = 0`. -/
theorem blindBadProb_le_queryBound
    (P : Prims R Rho WireBytes T1 Tag Addr K k l)
    [SampleableType R] [DecidableEq WireBytes]
    (tg : Tag) (rho : Bool → Rho) (t : Bool → Fin k → R)
    (adv : BlindAdvRO Tag Addr WireBytes) (qH : ℕ)
    (hq : ∀ x, IsQueryBoundP (adv x) (fun i => i.isRight = true) qH)
    (beta : ℝ≥0∞) (hB : BlindPointMassBound P beta) (hβ : beta ≠ ⊤) (b : Bool) :
    blindBadProb P tg rho t adv b ≤ ((qH : ℝ≥0∞) * beta).toReal :=
  ENNReal.toReal_mono (ENNReal.mul_ne_top (ENNReal.natCast_ne_top qH) hβ)
    (probOutput_blindBadQuery_le P tg rho t adv qH hq beta hB b)

/-- **The blinding term in the ROM, closed.** With the mask idealized, a `qH`-query adversary
tells the two recipients' address points apart with advantage at most `2·qH·β`. -/
theorem blindingAdvantageRO_le_queryBound
    (P : Prims R Rho WireBytes T1 Tag Addr K k l)
    [SampleableType R] [DecidableEq WireBytes]
    (tg : Tag) (rho : Bool → Rho) (t : Bool → Fin k → R)
    (adv : BlindAdvRO Tag Addr WireBytes) (qH : ℕ)
    (hq : ∀ x, IsQueryBoundP (adv x) (fun i => i.isRight = true) qH)
    (beta : ℝ≥0∞) (hB : BlindPointMassBound P beta) (hβ : beta ≠ ⊤) :
    blindingAdvantageRO P tg rho t adv ≤ 2 * ((qH : ℝ≥0∞) * beta).toReal := by
  calc blindingAdvantageRO P tg rho t adv
      ≤ blindBadProb P tg rho t adv true + blindBadProb P tg rho t adv false :=
        blindingAdvantageRO_le_blindBadProb P tg rho t adv
    _ ≤ ((qH : ℝ≥0∞) * beta).toReal + ((qH : ℝ≥0∞) * beta).toReal :=
        add_le_add (blindBadProb_le_queryBound P tg rho t adv qH hq beta hB hβ true)
          (blindBadProb_le_queryBound P tg rho t adv qH hq beta hB hβ false)
    _ = 2 * ((qH : ℝ≥0∞) * beta).toReal := by ring

/-! ## The ML-DSA point mass

`pack rho (power2Round (u + t))` over a uniform mask `u`: with the concrete coefficient-wise
`Power2Round` (each high value has exactly `2^d` preimages, `card_power2Round_fiber_le`) and an
injective `pack`, the point mass is `(2^d / q)^(k·256)`. The translation by `t` is a bijection of
the mask space, so the bound does not depend on `t`, i.e. on the recipient. -/

/-- The ML-DSA point-mass value: each of the `k·256` coefficients of the `Power2Round` high
part has at most `2^d` preimages among the `q` residues. -/
noncomputable def mlDsaAddressPointBeta (k : ℕ) : ℝ≥0∞ :=
  ((2 ^ droppedBits : ℝ≥0∞) / modulus) ^ (k * ringDegree)

/-! ### The concrete `Power2Round` fiber -/

/-- `power2RoundCoeff` decomposes its input: `2^d · r₁ + r₀ = r` in `Coeff`. -/
theorem power2RoundCoeff_decomp (r : Coeff) :
    (power2Scale : Coeff) * ((power2RoundCoeff r).1 : Coeff) + ((power2RoundCoeff r).2 : Coeff) = r := by
  have hdam : (power2Scale : Coeff) * ((r.val / power2Scale : ℕ) : Coeff)
      + ((r.val % power2Scale : ℕ) : Coeff) = r := by
    rw [← Nat.cast_mul, ← Nat.cast_add]
    nth_rewrite 3 [← ZMod.natCast_zmod_val r]
    congr 1
    exact Nat.div_add_mod r.val power2Scale
  simp only [power2RoundCoeff]
  split_ifs with h
  · push_cast
    exact hdam
  · simp only [Nat.cast_add, Nat.cast_one, Int.cast_sub, Int.cast_natCast]
    linear_combination hdam

/-- The low part of `power2RoundCoeff` lies in `(-2^(d-1), 2^(d-1)]`: exactly `2^d` values. -/
theorem power2RoundCoeff_low_range (r : Coeff) :
    -4095 ≤ (power2RoundCoeff r).2 ∧ (power2RoundCoeff r).2 ≤ 4096 := by
  have hS : power2Scale = 8192 := by decide
  simp only [power2RoundCoeff, hS]
  have := Nat.mod_lt r.val (show 0 < 8192 by norm_num)
  split_ifs with h <;> simp only <;> omega

/-- **Fiber bound.** Each high value of `power2RoundCoeff` has at most `2^d` preimages. -/
theorem card_power2Round_fiber_le (c : Coeff) :
    (Finset.univ.filter fun r : Coeff => ((power2RoundCoeff r).1 : Coeff) = c).card
      ≤ 2 ^ droppedBits := by
  have hd : 2 ^ droppedBits = 8192 := by decide
  rw [hd]
  refine (Finset.card_le_card_of_injOn (fun r => ((power2RoundCoeff r).2 + 4095).toNat)
    (t := Finset.range 8192) ?_ ?_).trans (by rw [Finset.card_range])
  · intro r _
    simp only [Finset.coe_range, Set.mem_Iio]
    have := power2RoundCoeff_low_range r
    omega
  · intro r hr r' hr' heq
    simp only [Finset.mem_coe, Finset.mem_filter, Finset.mem_univ, true_and] at hr hr'
    have hlow : (power2RoundCoeff r).2 = (power2RoundCoeff r').2 := by
      have := power2RoundCoeff_low_range r
      have := power2RoundCoeff_low_range r'
      simp only at heq
      omega
    rw [← power2RoundCoeff_decomp r, ← power2RoundCoeff_decomp r', hr, hr', hlow]

/-- `power2RoundHigh` equality, coefficient-wise. -/
theorem power2RoundHigh_eq_iff (r h : Rq) :
    power2RoundHigh r = h ↔ ∀ i, ((power2RoundCoeff (r.get i)).1 : Coeff) = h.get i := by
  constructor
  · rintro rfl i
    simp only [power2RoundHigh, Vector.get_eq_getElem, Vector.getElem_ofFn]
  · intro hi
    refine Poly.ext_get_eq fun i => ?_
    rw [← hi i]
    simp only [power2RoundHigh, Vector.get_eq_getElem, Vector.getElem_ofFn]

/-- `Vector.ofFn` equality, entry-wise. -/
theorem vector_ofFn_eq_iff {α : Type} {n : ℕ} (f : Fin n → α) (h : Vector α n) :
    Vector.ofFn f = h ↔ ∀ j, f j = h.get j := by
  constructor
  · rintro rfl j
    simp only [Vector.get_eq_getElem, Vector.getElem_ofFn]
  · intro hj
    refine Vector.ext fun j hj' => ?_
    rw [Vector.getElem_ofFn]
    exact (hj ⟨j, hj'⟩).trans (Vector.get_eq_getElem _ _)

/-- `Rq` is finite: it is `Vector Coeff 256`. -/
instance instFintypeRq : Fintype Rq := by
  change Fintype (Vector Coeff ringDegree)
  infer_instance

/-- Coordinates of a vector of polynomials. -/
def coords (k : ℕ) : (Fin k → Rq) ≃ (Fin k → Fin ringDegree → Coeff) where
  toFun v j i := (v j).get i
  invFun w j := Vector.ofFn (w j)
  left_inv v := funext fun j => Poly.ext_get_eq fun i => by
    simp only [Vector.get_eq_getElem, Vector.getElem_ofFn]
  right_inv w := funext fun j => funext fun i => by
    simp only [Vector.get_eq_getElem, Vector.getElem_ofFn]

omit [SampleableType Addr] in
/-- **ML-DSA address-point mass.** When the primitive's `power2Round` is the concrete
coefficient-wise `Power2Round` high part and `pack rho` is injective, no wire encoding is hit
with probability above `(2^d / q)^(k·256)` over a uniform mask. -/
theorem blindPointMassBound_mldsa [SampleableType Rq]
    (P : Prims Rq Rho WireBytes (Vector Rq k) Tag Addr K k l)
    (hP2 : ∀ v : Fin k → Rq,
      P.power2Round v = Vector.ofFn fun j => MLDSA.Concrete.power2RoundHigh (v j))
    (hpack : ∀ rho, Function.Injective (P.pack rho)) :
    BlindPointMassBound P (mlDsaAddressPointBeta k) := by
  intro rho t x
  rw [show blindPointSample P rho t =
      (fun u => P.pack rho (P.power2Round (u + t))) <$> ($ᵗ (Fin k → Rq)) from by
    simp only [blindPointSample, map_eq_bind_pure_comp, Function.comp_def]
    rfl, probOutput_map]
  rcases Classical.em (∃ h, P.pack rho h = x) with hx | hx
  · obtain ⟨h, rfl⟩ := hx
    -- the fiber, in coordinates
    have hcard : (Finset.univ.filter fun u : Fin k → Rq => P.power2Round (u + t) = h).card
        ≤ (2 ^ droppedBits) ^ (k * ringDegree) := by
      rw [Finset.card_equiv (Equiv.addRight t)
        (t := Finset.univ.filter fun v : Fin k → Rq => P.power2Round v = h) (fun u => by
          simp only [Finset.mem_filter, Finset.mem_univ, true_and, Equiv.coe_addRight]
          rfl)]
      rw [Finset.card_equiv (coords k)
        (t := Fintype.piFinset fun j => Fintype.piFinset fun i =>
          Finset.univ.filter fun r : Coeff =>
            ((power2RoundCoeff r).1 : Coeff) = (h.get j).get i) (fun v => ?_)]
      · rw [Fintype.card_piFinset]
        simp only [Fintype.card_piFinset]
        calc ∏ j : Fin k, ∏ i : Fin ringDegree,
              (Finset.univ.filter fun r : Coeff =>
                ((power2RoundCoeff r).1 : Coeff) = (h.get j).get i).card
            ≤ ∏ _j : Fin k, ∏ _i : Fin ringDegree, 2 ^ droppedBits :=
              Finset.prod_le_prod' fun j _ => Finset.prod_le_prod' fun i _ =>
                card_power2Round_fiber_le _
          _ = (2 ^ droppedBits) ^ (k * ringDegree) := by
              simp only [Finset.prod_const, Finset.card_univ, Fintype.card_fin]
              rw [← pow_mul, mul_comm]
      · simp only [Finset.mem_filter, Finset.mem_univ, true_and, Fintype.mem_piFinset, hP2,
          vector_ofFn_eq_iff, power2RoundHigh_eq_iff]
        rfl
    have htot : Fintype.card (Fin k → Rq) = modulus ^ (k * ringDegree) := by
      rw [Fintype.card_congr (coords k), Fintype.card_pi]
      simp only [Fintype.card_pi, Finset.prod_const, Finset.card_univ, Fintype.card_fin, ZMod.card]
      rw [← pow_mul, mul_comm]
    calc Pr[fun u => P.pack rho (P.power2Round (u + t)) = P.pack rho h | $ᵗ (Fin k → Rq)]
        ≤ Pr[fun u => P.power2Round (u + t) = h | $ᵗ (Fin k → Rq)] :=
          probEvent_mono'' fun u hu => hpack rho hu
      _ = ((Finset.univ.filter fun u : Fin k → Rq => P.power2Round (u + t) = h).card : ℝ≥0∞)
            / Fintype.card (Fin k → Rq) := probEvent_uniformSample _ _
      _ ≤ (((2 ^ droppedBits) ^ (k * ringDegree) : ℕ) : ℝ≥0∞)
            / ((modulus ^ (k * ringDegree) : ℕ) : ℝ≥0∞) := by
          rw [htot]
          exact ENNReal.div_le_div_right (by exact_mod_cast hcard) _
      _ = mlDsaAddressPointBeta k := by
          rw [mlDsaAddressPointBeta, Nat.cast_pow, Nat.cast_pow, Nat.cast_pow, Nat.cast_ofNat,
            div_eq_mul_inv, ENNReal.inv_pow, ← mul_pow, ← div_eq_mul_inv]
  · rw [probEvent_eq_zero fun u _ hu => hx ⟨_, hu⟩]
    exact zero_le

omit [SampleableType Addr] in
/-- The ML-DSA-65 instance: `k = 6`, so the point mass is `(2^13 / q)^(6·256)`. -/
theorem blindPointMassBound_mldsa65 [SampleableType Rq]
    (P : Prims Rq (MLDSA.Bytes 32) WireBytes (Vector Rq mldsa65.k) Tag Addr K mldsa65.k mldsa65.l)
    (hP2 : ∀ v : Fin mldsa65.k → Rq,
      P.power2Round v = Vector.ofFn fun j => MLDSA.Concrete.power2RoundHigh (v j))
    (hpack : ∀ rho, Function.Injective (P.pack rho)) :
    BlindPointMassBound P (mlDsaAddressPointBeta mldsa65.k) :=
  blindPointMassBound_mldsa P hP2 hpack

end ConstructionA

end PqStealth
