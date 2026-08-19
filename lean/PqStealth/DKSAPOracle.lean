import PqStealth.DKSAP
import PqStealth.ROMUpToBad
import VCVio.OracleComp.QueryTracking.QueryBound
import VCVio.OracleComp.QueryTracking.LoggingOracle
import VCVio.OracleComp.QueryTracking.RandomOracle.Simulation
import VCVio.CryptoFoundations.HardnessAssumptions.DiffieHellman

/-!
# DKSAP against a real oracle: the query bound, and the ROM game

Proved: the key-recovery attack as an `OracleComp (unifSpec + (G →ₒ F))` making
EXACTLY two oracle queries whatever the number of announcements it is handed
(`≤ 2` and not `≤ 1`), and its correctness when the oracle is simulated by a
genuine discrete-log function; and, on the positive side, DKSAP restated over
the same interface with the hash as a LAZY RANDOM ORACLE, the idealized RO game
proved perfectly unlinkable, and the RO unlinkability advantage bounded by the
two bad-query probabilities — identical-until-bad closed against VCVio's
programming-oracle engine (`ROMUpToBad`).

Assumed: the CDH reduction from the bad event is defined (`cdhOfUnlinkAdvRO`,
logging through VCVio's `appendInputLog`) but its advantage inequality
`dksapROBadProb ≤ q_H · Adv_CDH` is open: it needs a query bound on the
adversary and the fact that the flag fires with the same probability in the
programmed and in the tracking run. See the "Oracle attack" and "DDH/ROM bound"
sections of `docs/dksap-asymmetry.md`.
-/

open OracleComp OracleSpec

namespace PqStealth

/-! ## The oracle interface

One interface serves both halves: uniform randomness plus a single oracle
sending a group element to a scalar. Only the IMPLEMENTATION differs — a
discrete-log function below, a lazy random oracle in the ROM section. -/

section Spec

variable {F : Type} [Field F] {G : Type} [AddCommGroup G] [Module F G]

/-- Uniform sampling plus one oracle taking a group element to a scalar. VCVio's
`+` on specs, so `unifSpec ⊂ₒ scalarSpec F G` and `ProbComp` lifts in. -/
abbrev scalarSpec (F G : Type) : OracleSpec (ℕ ⊕ G) := unifSpec + (G →ₒ F)

/-- One query to the group oracle: hand it `y`, receive a scalar. -/
def scalarQuery (y : G) : OracleComp (scalarSpec F G) F :=
  (scalarSpec F G).query (Sum.inr y)

end Spec

/-! ## The discrete-log attack, with a real oracle and a query bound

The oracle answers `y` with a scalar `x`; under `dlogImpl` that scalar really is
the discrete log. The point of this section is the COST: two queries per
victim, independent of how many payments that victim received. -/

section Attack

variable {F : Type} [Field F] {G : Type} [AddCommGroup G] [Module F G]

/-- The attack on a published meta-address `(M, V)`: two oracle queries, then
`recover` on every announcement in `l`. No query depends on `l`. -/
def dlogAttack (h : G → F) (MV : G × G) (l : List (G × G)) :
    OracleComp (scalarSpec F G) (List F) := do
  let xM ← scalarQuery (F := F) MV.1
  let xV ← scalarQuery (F := F) MV.2
  pure (l.map fun RP => recover h xM xV RP.1)

/-- **Two queries, any number of payments.** The bound does not mention `l`:
deanonymizing a whole payment history costs the same two oracle calls as
deanonymizing one. This is the HNDL retroactivity statement. -/
theorem dlogAttack_isTotalQueryBound (h : G → F) (MV : G × G) (l : List (G × G)) :
    IsTotalQueryBound (dlogAttack h MV l) 2 :=
  ⟨by norm_num, fun _ => ⟨by norm_num, fun _ => trivial⟩⟩

/-- Exactness of the previous bound: one query does not suffice. Together the
two say the attack makes exactly two queries. -/
theorem dlogAttack_not_isTotalQueryBound_one (h : G → F) (MV : G × G) (l : List (G × G)) :
    ¬ IsTotalQueryBound (dlogAttack h MV l) 1 := fun hb =>
  absurd (hb.2 (0 : F)).1 (by norm_num)

/-- The oracle simulated by an actual discrete-log function; uniform queries are
answered uniformly. This is where Shor's contribution enters, as a hypothesis. -/
noncomputable def dlogImpl (dlog : G → F) : QueryImpl (scalarSpec F G) ProbComp
  | Sum.inl n => $[0..n]
  | Sum.inr y => pure (dlog y)

/-- Under `dlogImpl` the attack is deterministic: it consumes no randomness. -/
theorem simulateQ_dlogAttack (dlog : G → F) (h : G → F) (MV : G × G) (l : List (G × G)) :
    simulateQ (dlogImpl dlog) (dlogAttack h MV l)
      = pure (l.map fun RP => recover h (dlog MV.1) (dlog MV.2) RP.1) := by
  simp only [dlogAttack, scalarQuery, add_apply_inr, bind_pure_comp, simulateQ_bind,
    simulateQ_query, OracleQuery.input_query, OracleQuery.cont_query, dlogImpl, map_pure, id_eq,
    simulateQ_map]

/-- An honest DKSAP announcement, written as a function of the ephemeral scalar
so a payment history can be indexed by a list of them. -/
def dksapAnnounce (g : G) (h : G → F) (m v r : F) : G × G :=
  (r • g, (m • g) + (h (r • (v • g))) • g)

/-- The model is not vacuous: `dksapAnnounce` is an announcement the scheme
really emits for the meta-address `(m • g, v • g)`. -/
theorem dksapAnnounce_mem_announce_support [SampleableType F] [DecidableEq G]
    (g : G) (h : G → F) (m v r : F) :
    dksapAnnounce g h m v r ∈ support ((dksap g h).announce (m • g, v • g)) := by
  simp only [dksap, dksapAnnounce, support_bind, support_pure, Set.mem_iUnion,
    Set.mem_singleton_iff, exists_prop]
  exact ⟨r, mem_support_uniformSample F, rfl⟩

/-- **The attack recovers the honest keys.** Simulated against a genuine
discrete-log function, the output list is exactly the recipient's own spending
scalars — one per announcement, from the same two queries. -/
theorem dlogAttack_key_recovery (g : G)
    (hinj : Function.Injective (fun x : F => x • g))
    (dlog : G → F) (hdlog : ∀ y : G, dlog y • g = y) (h : G → F) (m v : F)
    (l : List (G × G)) :
    simulateQ (dlogImpl dlog) (dlogAttack h (m • g, v • g) l)
      = pure (l.map fun RP => m + h (v • RP.1)) := by
  rw [simulateQ_dlogAttack]
  congr 1
  exact List.map_congr_left fun RP _ =>
    dksap_recover_eq_honest h g hinj m v _ _ (hdlog (m • g)) (hdlog (v • g)) RP.1

/-- **The break, at every payment at once.** For a history of ephemeral scalars
`rs`, each scalar the attack recovers is a secret key for that announcement's
stealth address. -/
theorem dlogAttack_forall_key_recovery (g : G)
    (hinj : Function.Injective (fun x : F => x • g))
    (dlog : G → F) (hdlog : ∀ y : G, dlog y • g = y) (h : G → F) (m v : F)
    (rs : List F) :
    List.Forall (fun r : F =>
      (recover h (dlog (m • g)) (dlog (v • g)) (r • g)) • g
        = (dksapAnnounce g h m v r).2) rs := by
  rw [List.forall_iff_forall_mem]
  exact fun r _ =>
    dksap_key_recovery h g hinj m v r _ _ (hdlog (m • g)) (hdlog (v • g))

end Attack

/-! ## DKSAP in the random-oracle model

The same interface, implemented by VCVio's lazy random oracle
(`OracleSpec.randomOracle`, uniform sampling with a cache). The scheme, the
adversary and the unlinkability game all move to `OracleComp (scalarSpec F G)`;
probabilities are taken only after `simulateQ` lands back in `ProbComp`. -/

section ROSim

variable {F : Type} [SampleableType F] {G : Type} [DecidableEq G]

/-- The ROM implementation: uniform queries pass through, hash queries are
lazily sampled and cached. -/
noncomputable def romImpl (F G : Type) [SampleableType F] [DecidableEq G] :
    QueryImpl (scalarSpec F G) (StateT ((G →ₒ F).QueryCache) ProbComp) :=
  unifFwdImpl (G →ₒ F) + OracleSpec.randomOracle (spec := (G →ₒ F))

/-- `romImpl` is the generic `roImpl` of `ROMUpToBad` at the hash spec `G →ₒ F`. -/
theorem romImpl_eq_roImpl : romImpl F G = roImpl (G →ₒ F) := rfl

/-- Lifted `ProbComp` prefixes leave the cache alone, so they can be peeled out
of a simulated computation. VCVio's `roSim.run'_liftM_bind`, at `romImpl`. -/
theorem romImpl_run'_liftM_bind {α β : Type} (oa : ProbComp α)
    (rest : α → StateT ((G →ₒ F).QueryCache) ProbComp β)
    (s : (G →ₒ F).QueryCache) :
    (simulateQ (romImpl F G) (liftM oa) >>= rest).run' s
      = oa >>= fun x => (rest x).run' s :=
  roSim.run'_liftM_bind _ oa rest s

/-- A hash query on an UNCACHED point is a fresh uniform sample that is then
written into the cache. The one lazy-sampling step the games need. -/
theorem romImpl_run'_scalarQuery_bind (Z : G)
    (rest : F → StateT ((G →ₒ F).QueryCache) ProbComp Bool)
    (cache : (G →ₒ F).QueryCache) (hc : cache Z = none) :
    (simulateQ (romImpl F G) (scalarQuery (F := F) Z) >>= rest).run' cache
      = ($ᵗ F) >>= fun s => (rest s).run' (QueryCache.cacheQuery cache Z s) := by
  have hstep : (simulateQ (romImpl F G) (scalarQuery (F := F) Z) :
      StateT ((G →ₒ F).QueryCache) ProbComp F)
      = OracleSpec.randomOracle (spec := (G →ₒ F)) Z := by
    simp only [romImpl, scalarQuery, add_apply_inr, simulateQ_query, OracleQuery.input_query,
      OracleQuery.cont_query, QueryImpl.add_apply_inr, QueryImpl.withCaching_apply, map_bind, id_map]
  rw [hstep]
  simp only [StateT.run'_eq]
  rw [StateT.run_bind, QueryImpl.withCaching_run_none (m := ProbComp) uniformSampleImpl hc]
  simp only [uniformSampleImpl, map_eq_bind_pure_comp, bind_assoc, Function.comp_apply, pure_bind]

end ROSim

/-! ### The game -/

section Game

variable {F : Type} [Field F] [SampleableType F]
  {G : Type} [AddCommGroup G] [Module F G] [DecidableEq G]

/-- RO-model unlinkability adversary: both meta-addresses, the challenge
announcement, and oracle access to the hash. -/
abbrev UnlinkAdvRO (F G : Type) :=
  (G × G) → (G × G) → (G × G) → OracleComp (scalarSpec F G) Bool

variable (F) in
/-- Two independent DKSAP recipients, public halves only. No oracle query. -/
def dksapROKeys (g : G) : ProbComp ((G × G) × (G × G)) := do
  let m0 ← ($ᵗ F); let v0 ← ($ᵗ F); let m1 ← ($ᵗ F); let v1 ← ($ᵗ F)
  pure (((m0 • g, v0 • g) : G × G), ((m1 • g, v1 • g) : G × G))

/-- The setup, lifted into the oracle monad. -/
def dksapROSetup (g : G) : OracleComp (scalarSpec F G) ((G × G) × (G × G)) :=
  liftM (dksapROKeys F g)

/-- The adversary run under the lazy random oracle, starting from `cache`. -/
noncomputable def advRunAt (adv : UnlinkAdvRO F G) (a : (G × G) × (G × G)) (c : G × G)
    (cache : (G →ₒ F).QueryCache) : ProbComp Bool :=
  (simulateQ (romImpl F G) (adv a.1 a.2 c)).run' cache

/-- Real branch `b`: the shared scalar is the hash oracle at the DH point
`r • V_b`, and the adversary sees the same oracle afterwards. -/
def dksapROBranch (g : G) (adv : UnlinkAdvRO F G) (b : Bool)
    (a : (G × G) × (G × G)) : OracleComp (scalarSpec F G) Bool := do
  let r ← liftM ($ᵗ F)
  let s ← scalarQuery (F := F) (r • (if b then a.2 else a.1).2)
  adv a.1 a.2 (r • g, (if b then a.2 else a.1).1 + s • g)

/-- Idealized branch `b`: a fresh uniform scalar, and NO oracle query. -/
def dksapROIdealBranch (g : G) (adv : UnlinkAdvRO F G) (b : Bool)
    (a : (G × G) × (G × G)) : OracleComp (scalarSpec F G) Bool := do
  let r ← liftM ($ᵗ F)
  let s ← liftM ($ᵗ F)
  adv a.1 a.2 (r • g, (if b then a.2 else a.1).1 + s • g)

/-- The real game on branch `b`, run from an empty cache. -/
noncomputable def dksapRORun (g : G) (adv : UnlinkAdvRO F G) (b : Bool) : ProbComp Bool :=
  (simulateQ (romImpl F G) (dksapROSetup g >>= dksapROBranch g adv b)).run' ∅

/-- The idealized game on branch `b`, run from an empty cache. -/
noncomputable def dksapROIdealRun (g : G) (adv : UnlinkAdvRO F G) (b : Bool) : ProbComp Bool :=
  (simulateQ (romImpl F G) (dksapROSetup g >>= dksapROIdealBranch g adv b)).run' ∅

/-! ### The idealized game is perfectly unlinkable, in the ROM -/

/-- Peeling: keygen and the two scalars are ordinary sampling, so the ideal game
is the adversary run on an announcement built from a uniform scalar. -/
theorem dksapROIdealRun_eq (g : G) (adv : UnlinkAdvRO F G) (b : Bool) :
    dksapROIdealRun g adv b =
      dksapROKeys F g >>= fun a => ($ᵗ F) >>= fun r => ($ᵗ F) >>= fun s =>
        advRunAt adv a (r • g, (if b then a.2 else a.1).1 + s • g) ∅ := by
  unfold dksapROIdealRun dksapROSetup dksapROIdealBranch advRunAt
  simp only [simulateQ_bind]
  rw [romImpl_run'_liftM_bind]
  refine bind_congr fun a => ?_
  rw [romImpl_run'_liftM_bind]
  refine bind_congr fun r => ?_
  rw [romImpl_run'_liftM_bind]

/-- **The idealized RO game is perfectly unlinkable, sorry-free.** Exactly zero,
even though the adversary holds the random oracle: the ideal announcement never
touches it, so `dksapIdeal_branch_indep` applies verbatim. -/
theorem dksapROIdeal_boolDistAdvantage_eq_zero (g : G) (adv : UnlinkAdvRO F G)
    (hbij : Function.Bijective (fun x : F => x • g)) :
    (dksapROIdealRun g adv true).boolDistAdvantage (dksapROIdealRun g adv false) = 0 := by
  rw [ProbComp.boolDistAdvantage]
  refine abs_eq_zero.mpr (sub_eq_zero.mpr ?_)
  congr 1
  rw [dksapROIdealRun_eq, dksapROIdealRun_eq, probOutput_bind_eq_tsum,
    probOutput_bind_eq_tsum]
  refine tsum_congr fun a => ?_
  congr 1
  simp only [if_true, Bool.false_eq_true, if_false]
  exact dksapIdeal_branch_indep g hbij a.1.1 a.2.1 (fun c => advRunAt adv a c ∅) true

/-! ### The two hops, in the ROM -/

/-- Unlinkability advantage of DKSAP in the random-oracle model. -/
noncomputable def unlinkAdvantageRO (g : G) (adv : UnlinkAdvRO F G) : ℝ :=
  (dksapRORun g adv true).boolDistAdvantage (dksapRORun g adv false)

/-- Hashed-DH advantage on branch `b`, in the ROM: the real hash of the DH point
against a uniform scalar. -/
noncomputable def hashedDHRO (g : G) (adv : UnlinkAdvRO F G) (b : Bool) : ℝ :=
  (dksapRORun g adv b).boolDistAdvantage (dksapROIdealRun g adv b)

/-- **DKSAP's RO unlinkability rests entirely on hashed DH**, the idealized
middle game contributing exactly zero. The ROM counterpart of
`dksap_unlinkAdvantage_le_hashedDH`. -/
theorem dksap_unlinkAdvantageRO_le_hashedDHRO (g : G) (adv : UnlinkAdvRO F G)
    (hbij : Function.Bijective (fun x : F => x • g)) :
    unlinkAdvantageRO g adv ≤ hashedDHRO g adv true + hashedDHRO g adv false := by
  unfold unlinkAdvantageRO hashedDHRO
  rw [ProbComp.boolDistAdvantage_comm (dksapRORun g adv false)]
  calc (dksapRORun g adv true).boolDistAdvantage (dksapRORun g adv false)
      ≤ (dksapRORun g adv true).boolDistAdvantage (dksapROIdealRun g adv true) +
        (dksapROIdealRun g adv true).boolDistAdvantage (dksapRORun g adv false) :=
        ProbComp.boolDistAdvantage_triangle _ _ _
    _ ≤ (dksapRORun g adv true).boolDistAdvantage (dksapROIdealRun g adv true) +
        ((dksapROIdealRun g adv true).boolDistAdvantage (dksapROIdealRun g adv false) +
          (dksapROIdealRun g adv false).boolDistAdvantage (dksapRORun g adv false)) := by
        gcongr
        exact ProbComp.boolDistAdvantage_triangle _ _ _
    _ = _ := by rw [dksapROIdeal_boolDistAdvantage_eq_zero g adv hbij, zero_add]

/-! ### Identical until bad

`dksapRORun_eq` puts the real game in the same shape as the ideal one, with the
cache PROGRAMMED at the DH point. The two then differ only on runs where the
adversary queries that point — the bad event below — and VCVio's identical-until-bad
engine, instantiated for uniform forwarding in `ROMUpToBad`, bounds the distance
by its probability. -/

/-- The real game is the ideal game run against a cache already programmed at
the DH point: the announce query is the first one, so it hits an empty cache. -/
theorem dksapRORun_eq (g : G) (adv : UnlinkAdvRO F G) (b : Bool) :
    dksapRORun g adv b =
      dksapROKeys F g >>= fun a => ($ᵗ F) >>= fun r => ($ᵗ F) >>= fun s =>
        advRunAt adv a (r • g, (if b then a.2 else a.1).1 + s • g)
          (QueryCache.cacheQuery ∅ (r • (if b then a.2 else a.1).2) s) := by
  unfold dksapRORun dksapROSetup dksapROBranch advRunAt
  simp only [simulateQ_bind]
  rw [romImpl_run'_liftM_bind]
  refine bind_congr fun a => ?_
  rw [romImpl_run'_liftM_bind]
  refine bind_congr fun r => ?_
  exact romImpl_run'_scalarQuery_bind _ _ ∅ rfl

/-- The prefix both games share: the two key pairs, the ephemeral scalar, the shared scalar. -/
def dksapROPrefix (g : G) : ProbComp (((G × G) × (G × G)) × F × F) :=
  dksapROKeys F g >>= fun a => ($ᵗ F) >>= fun r => ($ᵗ F) >>= fun s => pure (a, r, s)

/-- The adversary's computation on branch `b`, as a function of the prefix. -/
def dksapROAdvRun (g : G) (adv : UnlinkAdvRO F G) (b : Bool)
    (x : ((G × G) × (G × G)) × F × F) : OracleComp (scalarSpec F G) Bool :=
  adv x.1.1 x.1.2 (x.2.1 • g, (if b then x.1.2 else x.1.1).1 + x.2.2 • g)

/-- The DH point on branch `b`, as a function of the prefix. -/
def dksapRODHPoint (b : Bool) (x : ((G × G) × (G × G)) × F × F) : G :=
  x.2.1 • (if b then x.1.2 else x.1.1).2

/-- **The bad event.** The adversary, run against the oracle programmed at the DH point (the
real game), queries that point — the programming flag of `programmedROImpl` fires. -/
noncomputable def dksapROBad (g : G) (adv : UnlinkAdvRO F G) (b : Bool) : ProbComp Bool :=
  badQueryGame (dksapROPrefix g) (dksapROAdvRun g adv b) (dksapRODHPoint b) (fun x => x.2.2)

/-- The probability of the bad event, as an `ℝ` like every other advantage
here. -/
noncomputable def dksapROBadProb (g : G) (adv : UnlinkAdvRO F G) (b : Bool) : ℝ :=
  (Pr[= true | dksapROBad g adv b]).toReal

/-- **Identical until bad, closed.** The hashed-DH term on branch `b` is at most the
probability that the adversary queries the DH point. -/
theorem hashedDHRO_le_dksapROBadProb (g : G) (adv : UnlinkAdvRO F G) (b : Bool) :
    hashedDHRO g adv b ≤ dksapROBadProb g adv b := by
  have h := boolDistAdvantage_run'_cacheQuery_run'_empty_le (dksapROPrefix g)
    (dksapROAdvRun g adv b) (dksapRODHPoint b) (fun x => x.2.2)
  have hreal : dksapRORun g adv b =
      dksapROPrefix g >>= fun x => (simulateQ (roImpl (G →ₒ F)) (dksapROAdvRun g adv b x)).run'
        ((∅ : (G →ₒ F).QueryCache).cacheQuery (dksapRODHPoint b x) x.2.2) := by
    rw [dksapRORun_eq]
    simp only [dksapROPrefix, dksapROAdvRun, dksapRODHPoint, advRunAt, romImpl_eq_roImpl,
      bind_assoc, pure_bind]
  have hideal : dksapROIdealRun g adv b =
      dksapROPrefix g >>= fun x =>
        (simulateQ (roImpl (G →ₒ F)) (dksapROAdvRun g adv b x)).run' ∅ := by
    rw [dksapROIdealRun_eq]
    simp only [dksapROPrefix, dksapROAdvRun, advRunAt, romImpl_eq_roImpl, bind_assoc, pure_bind]
  unfold hashedDHRO dksapROBadProb dksapROBad
  rw [hreal, hideal]
  exact h

/-- **DKSAP's RO unlinkability is bounded by the two bad-query probabilities**: the
real/ideal gap on each branch is identical-until-bad, and the ideal game is
perfectly unlinkable. -/
theorem dksap_unlinkAdvantageRO_le_badProb (g : G) (adv : UnlinkAdvRO F G)
    (hbij : Function.Bijective (fun x : F => x • g)) :
    unlinkAdvantageRO g adv ≤ dksapROBadProb g adv true + dksapROBadProb g adv false :=
  (dksap_unlinkAdvantageRO_le_hashedDHRO g adv hbij).trans
    (add_le_add (hashedDHRO_le_dksapROBadProb g adv true)
      (hashedDHRO_le_dksapROBadProb g adv false))

/-! ### The reduction to CDH

Planting the CDH challenge as `(R, V_b)` is possible precisely because the
IDEALIZED announcement needs neither `r` nor `v_b`: it uses a fresh scalar. The
reduction therefore runs the tracking side of the identical-until-bad pair; that
its bad event has the probability `dksapROBadProb` measures on the programmed
side is the (unproved here) symmetric half of the fundamental lemma. -/

/-- A random oracle that also logs the queried points, so the reduction can
return one of them: VCVio's `appendInputLog` (a `preInsert`) over the lazy
random oracle, with uniform queries forwarded. -/
noncomputable def loggingROImpl (F G : Type) [SampleableType F] [DecidableEq G] :
    QueryImpl (scalarSpec F G)
      (StateT (List G) (StateT ((G →ₒ F).QueryCache) ProbComp)) :=
  (HasQuery.toQueryImpl (spec := unifSpec) (m := ProbComp)).liftTarget
      (StateT (List G) (StateT ((G →ₒ F).QueryCache) ProbComp)) +
    QueryImpl.appendInputLog (OracleSpec.randomOracle (spec := (G →ₒ F)))

/-- The CDH solver built from an RO adversary: plant `A` as the ephemeral key
and `B` as the target's viewing key, run the idealized game, and return one
logged query point uniformly at random (`0` if nothing was queried). -/
noncomputable def cdhOfUnlinkAdvRO (adv : UnlinkAdvRO F G) (b : Bool) :
    DiffieHellman.CDHAdversary F G := fun g A B => do
  let mT ← ($ᵗ F); let mO ← ($ᵗ F); let vO ← ($ᵗ F); let s ← ($ᵗ F)
  let pkT : G × G := (mT • g, B)
  let pkO : G × G := (mO • g, vO • g)
  let z ← ((simulateQ (loggingROImpl F G)
    (adv (if b then pkO else pkT) (if b then pkT else pkO) (A, mT • g + s • g))).run []).run' ∅
  let i ← ($[0..z.2.length - 1])
  pure (z.2.getD i.val 0)

end Game

end PqStealth
