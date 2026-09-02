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

/-- The ML-DSA point-mass value: each of the `k·256` coefficients of the `Power2Round` high
part has at most `2^d` preimages among the `q` residues. -/
noncomputable def mlDsaAddressPointBeta (k : ℕ) : ℝ≥0∞ :=
  ((2 ^ droppedBits : ℝ≥0∞) / modulus) ^ (k * ringDegree)

variable (prims65 : Primitives mldsa65)

theorem blindPointMassBound_mldsa65
    [SampleableType Rq]
    (P : Prims Rq (MLDSA.Bytes 32) WireBytes (Vector prims65.Power2High mldsa65.k)
      Tag Addr K mldsa65.k mldsa65.l) :
    BlindPointMassBound P (mlDsaAddressPointBeta mldsa65.k) := by
  sorry

end ConstructionA

end PqStealth
