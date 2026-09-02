import PqStealth.ConstructionA
import PqStealth.ROMUpToBad

/-!
# The address hash as a random oracle

Proved: `hashAddr ∘ pack` as VCVio's lazily sampled `randomOracle` over
`unifSpec + (Bytes →ₒ Addr)`; the fresh-query lemma (from the empty cache the
announced address is a UNIFORM `Addr` whatever was hashed — what kills the `rho`
dependence `idealAux_indep_of_t` could not remove); `blindGameRO_eq`; and the
degenerate identical-until-bad case, no address query ⇒ advantage `0`.

Proved in addition: identical-until-bad (`blindingAdvantageRO_le_blindBadProb`),
against VCVio's programming-oracle engine via `ROMUpToBad`.

Assumed / NOT closed: TWO things — that `blindGameRO` is `auxKeyIndependence`
after the mask hop (a standalone abstraction, NOT identified with it here), and
the bound on `Pr[bad]` (`blindBadProb`), which needs a query bound and a
min-entropy hypothesis. See `docs/announcement-model.md`.
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

/-- The lazily sampled address oracle, over transparent uniform sampling: the generic
`roImpl` of `ROMUpToBad` at the hash spec `Bytes →ₒ Addr`. -/
noncomputable def romImpl :
    QueryImpl (addrSpec Bytes Addr) (StateT ((Bytes →ₒ Addr).QueryCache) ProbComp) :=
  roImpl (Bytes →ₒ Addr)

/-- Uniform sampling passes through the address-oracle handler untouched. -/
theorem simulateQ_romImpl_liftComp {β : Type} (ob : ProbComp β) :
    simulateQ (romImpl (Bytes := Bytes) (Addr := Addr)) (liftComp ob (addrSpec Bytes Addr)) =
      (liftM ob : StateT ((Bytes →ₒ Addr).QueryCache) ProbComp β) := by
  simp only [romImpl, roImpl, unifFwdImpl, liftComp_eq_liftM, QueryImpl.simulateQ_add_liftM_left,
    simulateQ_liftTarget, QueryImpl.simulateQ_toQueryImpl]

/-- **Fresh-query uniformity at the challenger's query.** Run from the empty
cache, the address the announcement carries is a UNIFORM `Addr` — whatever byte
string was hashed. This is the step the mask alone cannot supply. -/
theorem run_hashAddrRO_empty {α : Type} (x : Bytes) (f : Addr → ROMComp Bytes Addr α) :
    (simulateQ romImpl (hashAddrRO x >>= f)).run ∅ =
      (do let a ← ($ᵗ Addr)
          (simulateQ romImpl (f a)).run ((∅ : (Bytes →ₒ Addr).QueryCache).cacheQuery x a)) := by
  simp only [romImpl, roImpl, hashAddrRO, add_apply_inr, simulateQ_bind, simulateQ_query,
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

/-! ## 3. Identical until bad, and where the argument stops

The two branches differ only at one point of the oracle: the packed rounded
stealth key of the branch the adversary was NOT given. VCVio's programming-oracle
engine, instantiated for uniform forwarding in `ROMUpToBad`, bounds each branch's
distance from the oracle-free game by the probability that the adversary queries
its point. -/

/-- The shared prefix of both branches: the mask and the (uniform) announced address. -/
noncomputable def blindPrefix : ProbComp ((Fin k → R) × Addr) := do
  let u ← ($ᵗ (Fin k → R))
  let a ← ($ᵗ Addr)
  pure (u, a)

/-- The address point branch `b` programs: recipient `b`'s packed rounded stealth key. -/
def blindPoint (P : Prims R Rho Bytes T1 Tag Addr K k l) (rho : Bool → Rho)
    (t : Bool → (Fin k → R)) (b : Bool) (x : (Fin k → R) × Addr) : Bytes :=
  P.pack (rho b) (P.power2Round (x.1 + t b))

/-- **The bad event on branch `b`**: the adversary, run against the oracle programmed at
recipient `b`'s address point, queries that point. -/
noncomputable def blindBadQuery (P : Prims R Rho Bytes T1 Tag Addr K k l) (tg : Tag)
    (rho : Bool → Rho) (t : Bool → (Fin k → R)) (adv : BlindAdvRO Tag Addr Bytes) (b : Bool) :
    ProbComp Bool :=
  badQueryGame (blindPrefix (R := R) (k := k) (Addr := Addr)) (fun x => adv (tg, x.2))
    (blindPoint P rho t b) (fun x => x.2)

/-- The probability of the bad event on branch `b`, as an `ℝ`. -/
noncomputable def blindBadProb (P : Prims R Rho Bytes T1 Tag Addr K k l) (tg : Tag)
    (rho : Bool → Rho) (t : Bool → (Fin k → R)) (adv : BlindAdvRO Tag Addr Bytes) (b : Bool) :
    ℝ :=
  (Pr[= true | blindBadQuery P tg rho t adv b]).toReal

/-- The oracle-free middle game: the adversary sees a uniform address and an empty oracle. -/
noncomputable def blindGameROFree (tg : Tag) (adv : BlindAdvRO Tag Addr Bytes) :
    ProbComp Bool :=
  blindPrefix (R := R) (k := k) >>= fun x => (simulateQ romImpl (adv (tg, x.2))).run' ∅

/-- Each branch is within its bad-query probability of the oracle-free game. -/
theorem boolDistAdvantage_blindGameRO_blindGameROFree_le
    (P : Prims R Rho Bytes T1 Tag Addr K k l) (tg : Tag)
    (rho : Bool → Rho) (t : Bool → (Fin k → R)) (adv : BlindAdvRO Tag Addr Bytes) (b : Bool) :
    ProbComp.boolDistAdvantage (blindGameRO P tg rho t adv b)
      (blindGameROFree (R := R) (k := k) tg adv) ≤ blindBadProb P tg rho t adv b := by
  have h := boolDistAdvantage_run'_cacheQuery_run'_empty_le
    (blindPrefix (R := R) (k := k) (Addr := Addr)) (fun x => adv (tg, x.2))
    (blindPoint P rho t b) (fun x => x.2)
  have hgame : blindGameRO P tg rho t adv b =
      blindPrefix >>= fun x => (simulateQ (roImpl (Bytes →ₒ Addr)) (adv (tg, x.2))).run'
        ((∅ : (Bytes →ₒ Addr).QueryCache).cacheQuery (blindPoint P rho t b x) x.2) := by
    rw [blindGameRO_eq]
    simp only [blindPrefix, blindPoint, romImpl, bind_assoc, pure_bind]
  unfold blindBadProb blindBadQuery blindGameROFree
  rw [hgame]
  exact h

/-- **Identical until bad, closed.** The blinding term is at most the sum of the two
bad-query probabilities: the adversary must query one of the two address points to
tell the branches apart. -/
theorem blindingAdvantageRO_le_blindBadProb (P : Prims R Rho Bytes T1 Tag Addr K k l)
    (tg : Tag) (rho : Bool → Rho) (t : Bool → (Fin k → R)) (adv : BlindAdvRO Tag Addr Bytes) :
    blindingAdvantageRO P tg rho t adv ≤
      blindBadProb P tg rho t adv true + blindBadProb P tg rho t adv false := by
  unfold blindingAdvantageRO
  calc ProbComp.boolDistAdvantage (blindGameRO P tg rho t adv true)
        (blindGameRO P tg rho t adv false)
      ≤ ProbComp.boolDistAdvantage (blindGameRO P tg rho t adv true)
          (blindGameROFree (R := R) (k := k) tg adv) +
        ProbComp.boolDistAdvantage (blindGameROFree (R := R) (k := k) tg adv)
          (blindGameRO P tg rho t adv false) :=
        ProbComp.boolDistAdvantage_triangle _ _ _
    _ ≤ blindBadProb P tg rho t adv true + blindBadProb P tg rho t adv false := by
        gcongr
        · exact boolDistAdvantage_blindGameRO_blindGameROFree_le P tg rho t adv true
        · rw [ProbComp.boolDistAdvantage_comm]
          exact boolDistAdvantage_blindGameRO_blindGameROFree_le P tg rho t adv false

/-! ### Where the argument stops

Bounding `blindBadProb` is the remaining target — `Pr[bad] ≤ mlwe + q_H · β`: after
the MLWE hop that makes the mask uniform, hitting the point costs one guess per
oracle query, with `β` the min-entropy bound of `pack ∘ power2Round` on a uniform
argument. It needs a query bound on `adv` (`IsTotalQueryBound`) and an
unpredictability hypothesis on the point (`HasUnpredictableSample`); neither is
stated here yet. The reduction it would consume is type-checked below. -/

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