import PqStealth.ConstructionA
import VCVio.OracleComp.QueryTracking.RandomOracle.Basic

/-!
# The address hash as a random oracle

Proved: `hashAddr ∘ pack` as VCVio's lazily sampled `randomOracle` over
`unifSpec + (Bytes →ₒ Addr)`; the fresh-query lemma (from the empty cache the
announced address is a UNIFORM `Addr` whatever was hashed — what kills the `rho`
dependence `idealAux_indep_of_t` could not remove); `blindGameRO_eq`; and the
degenerate identical-until-bad case, no address query ⇒ advantage `0`.

Assumed / NOT closed: THREE things — that `blindGameRO` is `auxKeyIndependence`
after the mask hop (a standalone abstraction, NOT identified with it here),
identical-until-bad (`BoundedByBadQuery`) and `Pr[bad]` (`BadQueryBounded`).
See `docs/announcement-model.md`.
-/

open OracleComp OracleSpec

namespace PqStealth

namespace ConstructionA

/-! ## 1. The oracle interface

The random oracle is `hashAddr ∘ pack` as one function `Bytes → Addr`: it is the
composite the blinding argument needs to be random, and it is the composite the
spec instantiates with `keccak256`. -/

/-- Oracle interface of the ROM model: uniform sampling plus the address hash. -/
@[reducible] def addrSpec (Bytes Addr : Type) := unifSpec + (Bytes →ₒ Addr)

/-- Computations with uniform sampling and the address oracle. -/
abbrev ROMComp (Bytes Addr : Type) := OracleComp (addrSpec Bytes Addr)

variable {Bytes Addr : Type}

/-- One address-oracle query: the ROM stand-in for `hashAddr (pack …)`. -/
def hashAddrRO (x : Bytes) : ROMComp Bytes Addr Addr :=
  (addrSpec Bytes Addr).query (Sum.inr x)

variable [DecidableEq Bytes] [SampleableType Addr]

/-- The lazily sampled address oracle, over transparent uniform sampling. -/
noncomputable def romImpl :
    QueryImpl (addrSpec Bytes Addr) (StateT ((Bytes →ₒ Addr).QueryCache) ProbComp) :=
  (HasQuery.toQueryImpl (spec := unifSpec) (m := ProbComp)).liftTarget
      (StateT ((Bytes →ₒ Addr).QueryCache) ProbComp) +
    (Bytes →ₒ Addr).randomOracle

/-- Uniform sampling passes through the address-oracle handler untouched. -/
theorem simulateQ_romImpl_liftComp {β : Type} (ob : ProbComp β) :
    simulateQ (romImpl (Bytes := Bytes) (Addr := Addr)) (liftComp ob (addrSpec Bytes Addr)) =
      (liftM ob : StateT ((Bytes →ₒ Addr).QueryCache) ProbComp β) := by
  simp only [romImpl, liftComp_eq_liftM, QueryImpl.simulateQ_add_liftM_left,
    simulateQ_liftTarget, QueryImpl.simulateQ_toQueryImpl]

/-- **Fresh-query uniformity at the challenger's query.** Run from the empty
cache, the address the announcement carries is a UNIFORM `Addr` — whatever byte
string was hashed. This is the step the mask alone cannot supply. -/
theorem run_hashAddrRO_empty {α : Type} (x : Bytes) (f : Addr → ROMComp Bytes Addr α) :
    (simulateQ romImpl (hashAddrRO x >>= f)).run ∅ =
      (do let a ← ($ᵗ Addr)
          (simulateQ romImpl (f a)).run ((∅ : (Bytes →ₒ Addr).QueryCache).cacheQuery x a)) := by
  simp only [romImpl, hashAddrRO, add_apply_inr, simulateQ_bind, simulateQ_query,
    OracleQuery.input_query, OracleQuery.cont_query, QueryImpl.add_apply_inr,
    QueryImpl.withCaching_apply, uniformSampleImpl, QueryCache.cacheQuery, map_bind, id_map,
    bind_assoc, StateT.run_bind, StateT.run_get, pure_bind, QueryCache.empty_apply,
    StateT.run_monadLift, monadLift_self, bind_pure_comp, StateT.run_modifyGet, Functor.map_map,
    bind_map_left]

/-! ## 2. The blinding game in the ROM

A standalone abstraction of the branch comparison with the mask already
idealized, NOT a restatement of the two games `auxKeyIndependence` compares:
the ciphertext, the KEM and the tag derivation are dropped and `tg`, `rho`, `t`
are free parameters. It asks the same question — does the address still say
whose `rho` and whose `t` built it? -/

variable {R : Type} [CommRing R] [SampleableType R] {k l : ℕ} {Rho T1 Tag K : Type}

/-- A ROM adversary against the blinding term: it sees the auxiliary data and
may query the address oracle itself. -/
abbrev BlindAdvRO (Tag Addr Bytes : Type) := Tag × Addr → ROMComp Bytes Addr Bool

/-- Branch `b` of the ideal-blinding game, instrumented with the mask it drew
and the final state of the address oracle so the bad event is on the output. -/
noncomputable def blindTraceRO (P : Prims R Rho Bytes T1 Tag Addr K k l) (tg : Tag)
    (rho : Bool → Rho) (t : Bool → (Fin k → R)) (adv : BlindAdvRO Tag Addr Bytes) (b : Bool) :
    ProbComp ((Fin k → R) × Bool × (Bytes →ₒ Addr).QueryCache) := do
  let u ← ($ᵗ (Fin k → R))
  let z ← (simulateQ romImpl
    (hashAddrRO (P.pack (rho b) (P.power2Round (u + t b))) >>= fun a => adv (tg, a))).run ∅
  pure (u, z)

/-- Branch `b` of the ideal-blinding game: the adversary's verdict alone. -/
noncomputable def blindGameRO (P : Prims R Rho Bytes T1 Tag Addr K k l) (tg : Tag)
    (rho : Bool → Rho) (t : Bool → (Fin k → R)) (adv : BlindAdvRO Tag Addr Bytes) (b : Bool) :
    ProbComp Bool := do
  let w ← blindTraceRO P tg rho t adv b
  pure w.2.1

/-- The blinding term's shape in the ROM: with the mask idealized, can the
adversary still tell whose `rho` and `t` built the address? -/
noncomputable def blindingAdvantageRO (P : Prims R Rho Bytes T1 Tag Addr K k l) (tg : Tag)
    (rho : Bool → Rho) (t : Bool → (Fin k → R)) (adv : BlindAdvRO Tag Addr Bytes) : ℝ :=
  (blindGameRO P tg rho t adv true).boolDistAdvantage (blindGameRO P tg rho t adv false)

/-- **The branches differ only in the oracle's initial state.** After the
challenger's query the two games are the SAME computation, run from caches that
differ at one point: `∅` extended at recipient `b`'s address point by the same
uniform value. This is the identical-until-bad setup, made explicit. -/
theorem blindGameRO_eq (P : Prims R Rho Bytes T1 Tag Addr K k l) (tg : Tag)
    (rho : Bool → Rho) (t : Bool → (Fin k → R)) (adv : BlindAdvRO Tag Addr Bytes) (b : Bool) :
    blindGameRO P tg rho t adv b =
      (do let u ← ($ᵗ (Fin k → R))
          let a ← ($ᵗ Addr)
          (simulateQ romImpl (adv (tg, a))).run'
            ((∅ : (Bytes →ₒ Addr).QueryCache).cacheQuery
              (P.pack (rho b) (P.power2Round (u + t b))) a)) := by
  simp only [blindGameRO, blindTraceRO, bind_assoc, pure_bind, run_hashAddrRO_empty]
  refine bind_congr fun u => bind_congr fun a => ?_
  simp only [StateT.run', map_eq_bind_pure_comp, Function.comp_def, StateT.run]

/-- **The degenerate identical-until-bad case.** An adversary that never
consults the address oracle sees a uniform address on both branches, so `rho`
AND `t` disappear — which the mask alone could not do. -/
theorem blindingAdvantageRO_eq_zero_of_no_query
    (P : Prims R Rho Bytes T1 Tag Addr K k l) (tg : Tag)
    (rho : Bool → Rho) (t : Bool → (Fin k → R)) (adv : Tag × Addr → ProbComp Bool) :
    blindingAdvantageRO P tg rho t (fun x => liftComp (adv x) (addrSpec Bytes Addr)) = 0 := by
  have key : ∀ b : Bool,
      blindGameRO P tg rho t (fun x => liftComp (adv x) (addrSpec Bytes Addr)) b =
        (do let _u ← ($ᵗ (Fin k → R)); let a ← ($ᵗ Addr); adv (tg, a)) := by
    intro b
    simp only [blindGameRO, blindTraceRO, bind_assoc, pure_bind,
      run_hashAddrRO_empty, simulateQ_romImpl_liftComp]
    refine bind_congr fun _ => bind_congr fun a => ?_
    simp only [StateT.run, liftM, monadLift, MonadLift.monadLift, StateT.lift, bind_assoc,
      pure_bind, bind_pure]
  rw [blindingAdvantageRO, key true, key false, ProbComp.boolDistAdvantage, sub_self, abs_zero]

/-! ## 3. Where the argument stops

The two branches differ only at one point of the oracle: the packed rounded
stealth key of the branch the adversary was NOT given. Both statements below are
targets, not theorems. -/

/-- The bad event on a trace: the adversary queried the address oracle at the
OTHER branch's packed rounded stealth key. -/
def BadQuery (P : Prims R Rho Bytes T1 Tag Addr K k l) (rho : Bool → Rho)
    (t : Bool → (Fin k → R)) (b : Bool)
    (w : (Fin k → R) × Bool × (Bytes →ₒ Addr).QueryCache) : Prop :=
  w.2.2 (P.pack (rho !b) (P.power2Round (w.1 + t !b))) ≠ none

/-- **Target 1 (identical until bad).** The two ROM branches agree unless the
adversary queries the other branch's address point, so the blinding term is at
most that probability. Not proved: it needs the state-separating machinery of
VCVio's `StateSeparating/IdenticalUntilBad.lean` at this handler. -/
def BoundedByBadQuery (P : Prims R Rho Bytes T1 Tag Addr K k l) (tg : Tag)
    (rho : Bool → Rho) (t : Bool → (Fin k → R)) (adv : BlindAdvRO Tag Addr Bytes) : Prop :=
  blindingAdvantageRO P tg rho t adv ≤
    (Pr[BadQuery P rho t true | blindTraceRO P tg rho t adv true]).toReal

/-- **Target 2 (the bad event is a guessing event).** After the MLWE hop that
makes the mask uniform, hitting the point costs one guess per oracle query:
`Pr[bad] ≤ mlwe + q_H · β` with `β` the min-entropy bound of `pack ∘ power2Round`
on a uniform argument. Not proved: it needs a query bound on `adv`. -/
def BadQueryBounded (P : Prims R Rho Bytes T1 Tag Addr K k l) (tg : Tag)
    (rho : Bool → Rho) (t : Bool → (Fin k → R)) (adv : BlindAdvRO Tag Addr Bytes)
    (mlwe : ℝ) (qH : ℕ) (β : ℝ) : Prop :=
  (Pr[BadQuery P rho t true | blindTraceRO P tg rho t adv true]).toReal ≤ mlwe + qH * β

/-- **The ROM reduction, type-checked.** Simulating the address oracle inside,
a ROM blinding adversary is an ordinary seeded-MLWE distinguisher: the challenge
seed becomes recipient 1's `rho` and the challenge vector the mask. -/
noncomputable def mlweAdvOfBlindAdvRO (P : Prims R Rho Bytes T1 Tag Addr K k l)
    (Smp : Samplers R Rho k l) (tg : Tag) (t : Fin k → R)
    (adv : BlindAdvRO Tag Addr Bytes) :
    LearningWithErrors.Adversary (blindingProblem P Smp) :=
  fun chal =>
    (simulateQ romImpl
      (hashAddrRO (P.pack chal.1 (P.power2Round (chal.2 + t))) >>=
        fun a => adv (tg, a))).run' ∅

end ConstructionA

end PqStealth
