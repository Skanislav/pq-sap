import VCVio.ProgramLogic.Relational.ProgrammingOracle
import VCVio.OracleComp.QueryTracking.RandomOracle.Simulation
import VCVio.CryptoFoundations.SecExp

/-!
# Identical-until-bad for the lazy random oracle with uniform forwarding

VCVio's `tvDist_simulateQ_randomOracle_withProgramming_le_probEvent_bad` bounds the distance
between a lazily sampled random oracle and a *programmed* one (the oracle forced to answer a
chosen point with a chosen value) by the probability that the programmed point is queried. It is
stated for computations whose only oracle is the hash. Our ROM games live over
`unifSpec + hashSpec` — the adversary also samples — and are simulated by
`unifFwdImpl hashSpec + hashSpec.randomOracle` (`romImpl` in `DKSAPOracle`, `BlindingROM`).

Proved, for that shape (everything here is stated over an arbitrary `hashSpec`):

* `tvDist_programmedROImpl_trackingROImpl_le`: the engine bound
  (`tvDist_simulateQ_run_le_probEvent_output_bad`) for `unifFwd + withProgramming policy` vs
  `unifFwd + withCachingTrackingPolicy policy`, with the programming flag as the bad event;
* `evalDist_run'_programmedROImpl`: the programmed run from `(cache₀, false)` is, on the output
  marginal, the plain random oracle run from the cache `cache₀` overridden by the policy;
* `evalDist_run'_trackingROImpl`: the tracking run is, on the output marginal, the plain random
  oracle run from `cache₀`;
* `tvDist_run'_romImpl_policy_le_probEvent_bad`: the three combined — the distance between the
  random oracle run from `cache₀ ⊕ policy` and from `cache₀` is at most the probability that the
  policy fires. This is the lemma `DKSAPOracle` and `BlindingROM` consume.
-/

open OracleComp OracleSpec ENNReal

namespace PqStealth

variable {ι : Type} {hashSpec : OracleSpec ι}

/-! ## The implementations -/

section Impls

variable [DecidableEq ι] [∀ t : hashSpec.Domain, SampleableType (hashSpec.Range t)]

/-- Uniform forwarding lifted to the flagged cache state `QueryCache × Bool`. -/
noncomputable def unifFwdFlagImpl (hashSpec : OracleSpec ι) :
    QueryImpl unifSpec (StateT (hashSpec.QueryCache × Bool) ProbComp) :=
  (HasQuery.toQueryImpl (spec := unifSpec) (m := ProbComp)).liftTarget
    (StateT (hashSpec.QueryCache × Bool) ProbComp)

/-- The plain ROM implementation: uniform queries forwarded, hash queries lazily sampled and
cached. `romImpl` in the scheme files is this at `hashSpec := G →ₒ F`. -/
noncomputable def roImpl (hashSpec : OracleSpec ι)
    [∀ t : hashSpec.Domain, SampleableType (hashSpec.Range t)] :
    QueryImpl (unifSpec + hashSpec) (StateT hashSpec.QueryCache ProbComp) :=
  unifFwdImpl hashSpec + hashSpec.randomOracle

/-- The programmed ROM implementation: uniform queries forwarded, hash queries answered by the
policy where it is defined (setting the bad flag), lazily sampled otherwise. -/
noncomputable def programmedROImpl (policy : hashSpec.ProgrammingPolicy) :
    QueryImpl (unifSpec + hashSpec) (StateT (hashSpec.QueryCache × Bool) ProbComp) :=
  unifFwdFlagImpl hashSpec + QueryImpl.withProgramming uniformSampleImpl policy

/-- The tracking ROM implementation: the plain random oracle, but the bad flag is set exactly
when the programmed one would have fired. -/
noncomputable def trackingROImpl (policy : hashSpec.ProgrammingPolicy) :
    QueryImpl (unifSpec + hashSpec) (StateT (hashSpec.QueryCache × Bool) ProbComp) :=
  unifFwdFlagImpl hashSpec + QueryImpl.withCachingTrackingPolicy uniformSampleImpl policy

end Impls

/-! ## A cache overridden by a policy -/

section CacheOr

variable [DecidableEq ι] (policy : hashSpec.ProgrammingPolicy)

/-- A cache overridden by a policy: the cache where it is defined, the policy otherwise. -/
def cacheOr (cache : hashSpec.QueryCache) (policy : hashSpec.ProgrammingPolicy) :
    hashSpec.QueryCache :=
  fun t => (cache t).or (policy t)

omit [DecidableEq ι] in
/-- The overridden cache, pointwise. -/
@[simp] theorem cacheOr_apply (cache : hashSpec.QueryCache) (t : hashSpec.Domain) :
    cacheOr cache policy t = (cache t).or (policy t) := rfl

/-- Caching a point commutes with overriding by a policy. -/
theorem cacheOr_cacheQuery (cache : hashSpec.QueryCache) (t : hashSpec.Domain)
    (u : hashSpec.Range t) :
    cacheOr (cache.cacheQuery t u) policy = (cacheOr cache policy).cacheQuery t u := by
  funext t'
  by_cases h : t' = t
  · subst h
    simp only [cacheOr_apply, QueryCache.cacheQuery_self, Option.some_or]
  · simp only [cacheOr_apply, QueryCache.cacheQuery_of_ne _ _ h]

/-- Overriding by a policy, then caching the programmed value at a point where the policy is
defined, is overriding alone. -/
theorem cacheOr_cacheQuery_of_policy (cache : hashSpec.QueryCache)
    (t : hashSpec.Domain) (u : hashSpec.Range t) (hc : cache t = none) (hp : policy t = some u) :
    cacheOr (cache.cacheQuery t u) policy = cacheOr cache policy := by
  funext t'
  by_cases h : t' = t
  · subst h
    simp only [cacheOr_apply, QueryCache.cacheQuery_self, Option.some_or, hc, hp,
      Option.none_or]
  · simp only [cacheOr_apply, QueryCache.cacheQuery_of_ne _ _ h]

end CacheOr

/-! ## Running the uniform forwarders -/

section Forwarders

theorem unifFwdFlagImpl_run (n : ℕ) (s : hashSpec.QueryCache × Bool) :
    (unifFwdFlagImpl hashSpec n).run s = (fun x => (x, s)) <$> ($[0..n]) :=
  rfl

theorem unifFwdImpl_run (n : ℕ) (s : hashSpec.QueryCache) :
    (unifFwdImpl hashSpec n).run s = (fun x => (x, s)) <$> ($[0..n]) :=
  rfl

open OracleComp.ProgramLogic.Relational in
/-- The uniform forwarders are coupled step by step under any state relation. -/
theorem relTriple_unifFwdFlagImpl_unifFwdImpl
    (R : hashSpec.QueryCache × Bool → hashSpec.QueryCache → Prop) (n : ℕ)
    (s₁ : hashSpec.QueryCache × Bool) (s₂ : hashSpec.QueryCache) (hs : R s₁ s₂) :
    RelTriple ((unifFwdFlagImpl hashSpec n).run s₁) ((unifFwdImpl hashSpec n).run s₂)
      (fun p₁ p₂ => p₁.1 = p₂.1 ∧ R p₁.2 p₂.2) := by
  rw [unifFwdFlagImpl_run, unifFwdImpl_run]
  refine relTriple_map (relTriple_post_mono (relTriple_refl _) ?_)
  intro x y hxy
  exact ⟨hxy, hs⟩

end Forwarders

/-! ## The engine: programmed vs tracking, identical until the flag fires -/

section Engine

variable [DecidableEq ι] [∀ t : hashSpec.Domain, SampleableType (hashSpec.Range t)]
  (policy : hashSpec.ProgrammingPolicy)

/-- On a non-bad input, the programmed and tracking hash handlers agree on every non-bad
output. (VCVio proves this for its own bridge but keeps it `private`.) -/
theorem probOutput_withProgramming_eq_withCachingTrackingPolicy_of_not_bad_output
    (t : hashSpec.Domain) (cache : hashSpec.QueryCache)
    (u : hashSpec.Range t) (cache' : hashSpec.QueryCache) :
    Pr[= (u, (cache', false)) |
        (QueryImpl.withProgramming uniformSampleImpl policy t).run (cache, false)] =
      Pr[= (u, (cache', false)) |
        (QueryImpl.withCachingTrackingPolicy uniformSampleImpl policy t).run (cache, false)] := by
  classical
  cases hcache : cache t with
  | some v =>
    simp only [QueryImpl.withProgramming_apply, StateT.run_mk, hcache, probOutput_pure,
      Prod.mk.injEq, and_true, QueryImpl.withCachingTrackingPolicy_apply, Bool.if_true_left,
      Bool.decide_eq_true, Functor.map_map]
  | none =>
    cases hpol : policy t with
    | none =>
      simp only [QueryImpl.withProgramming_apply, hpol, Functor.map_map, StateT.run_mk, hcache,
        QueryImpl.withCachingTrackingPolicy_apply, Option.isSome_none, Bool.false_eq_true,
        ↓reduceIte]
    | some v =>
      have hne : ∀ (w : hashSpec.Range t) (c : hashSpec.QueryCache),
          ((u, (cache', false)) : hashSpec.Range t × hashSpec.QueryCache × Bool)
            ≠ (w, (c, true)) := by
        intro w c hcontr
        injection hcontr with _ h2
        injection h2 with _ h3
        cases h3
      have hL : (QueryImpl.withProgramming uniformSampleImpl policy t).run (cache, false) =
          (pure (v, (cache.cacheQuery t v, true)) :
            ProbComp (hashSpec.Range t × hashSpec.QueryCache × Bool)) := by
        simp only [QueryImpl.withProgramming_apply, hpol, map_pure, StateT.run_mk, hcache]
      have hR : (QueryImpl.withCachingTrackingPolicy uniformSampleImpl policy t).run
            (cache, false) =
          (uniformSampleImpl t >>= fun u' => pure (u', (cache.cacheQuery t u', true)) :
            ProbComp (hashSpec.Range t × hashSpec.QueryCache × Bool)) := by
        simp only [QueryImpl.withCachingTrackingPolicy_apply, hpol, Option.isSome_some, ↓reduceIte,
          Functor.map_map, StateT.run_mk, hcache, bind_pure_comp]
      rw [hL, hR, probOutput_pure, if_neg (hne v _), probOutput_bind_eq_tsum]
      symm
      refine ENNReal.tsum_eq_zero.mpr (fun u' => ?_)
      rw [probOutput_pure, if_neg (hne u' _), mul_zero]

/-- **Identical until bad, with uniform forwarding.** The joint (output, cache, flag)
distributions of the programmed and tracking runs are within the probability that the flag
fires in the programmed run. -/
theorem tvDist_programmedROImpl_trackingROImpl_le {α : Type}
    (oa : OracleComp (unifSpec + hashSpec) α) (cache₀ : hashSpec.QueryCache) :
    tvDist ((simulateQ (programmedROImpl policy) oa).run (cache₀, false))
        ((simulateQ (trackingROImpl policy) oa).run (cache₀, false))
      ≤ Pr[fun z : α × hashSpec.QueryCache × Bool => z.2.2 = true |
          (simulateQ (programmedROImpl policy) oa).run (cache₀, false)].toReal := by
  refine OracleComp.ProgramLogic.Relational.tvDist_simulateQ_run_le_probEvent_output_bad
    (programmedROImpl policy) (trackingROImpl policy) oa cache₀ ?_ ?_ ?_
  · rintro (n | t) s u s'
    · rfl
    · exact probOutput_withProgramming_eq_withCachingTrackingPolicy_of_not_bad_output
        policy t s u s'
  · rintro (n | t) ⟨c, b⟩ hp z hz
    · cases (show b = true from hp)
      simp only [add_apply_inl, programmedROImpl, QueryImpl.add_apply_inl, unifFwdFlagImpl_run,
        support_map, ProbComp.support_uniformFin, Set.image_univ] at hz
      obtain ⟨x, rfl⟩ := hz
      rfl
    · cases (show b = true from hp)
      exact QueryImpl.withProgramming_bad_monotone (so := uniformSampleImpl) (policy := policy)
        t c z hz
  · rintro (n | t) ⟨c, b⟩ hp z hz
    · cases (show b = true from hp)
      simp only [add_apply_inl, trackingROImpl, QueryImpl.add_apply_inl, unifFwdFlagImpl_run,
        support_map, ProbComp.support_uniformFin, Set.image_univ] at hz
      obtain ⟨x, rfl⟩ := hz
      rfl
    · cases (show b = true from hp)
      exact QueryImpl.withCachingTrackingPolicy_bad_monotone (so := uniformSampleImpl)
        (policy := policy) t c z hz

end Engine

/-! ## Projections: programmed and tracking runs against the plain random oracle -/

section Projections

open OracleComp.ProgramLogic.Relational

variable [DecidableEq ι] [∀ t : hashSpec.Domain, SampleableType (hashSpec.Range t)]
  (policy : hashSpec.ProgrammingPolicy)

/-- **Programmed = cached.** Running the programmed oracle from `(cache₀, false)` has the same
output distribution as running the plain random oracle from `cache₀` overridden by the policy. -/
theorem relTriple_run'_programmedROImpl_roImpl {α : Type}
    (oa : OracleComp (unifSpec + hashSpec) α) (cache₀ : hashSpec.QueryCache) :
    RelTriple ((simulateQ (programmedROImpl policy) oa).run' (cache₀, false))
      ((simulateQ (roImpl hashSpec) oa).run' (cacheOr cache₀ policy)) (EqRel α) := by
  refine relTriple_simulateQ_run' (programmedROImpl policy) (roImpl hashSpec)
    (fun p c => c = cacheOr p.1 policy) oa ?_ (cache₀, false) _ rfl
  rintro (n | t) ⟨c, bad⟩ c' hc'
  · exact relTriple_unifFwdFlagImpl_unifFwdImpl (R := fun p c => c = cacheOr p.1 policy) n
      (c, bad) c' hc'
  · subst hc'
    simp only [programmedROImpl, roImpl, QueryImpl.add_apply_inr, OracleSpec.randomOracle]
    cases hcache : c t with
    | some v =>
      simp only [add_apply_inr, QueryImpl.withProgramming_apply, StateT.run_mk, hcache,
        QueryImpl.withCaching_apply, StateT.run_bind, StateT.run_get, pure_bind, cacheOr_apply,
        Option.some_or, StateT.run_pure, relTriple_iff_relWP, MAlgRelOrdered.relWP_pure, and_self]
    | none =>
      cases hpol : policy t with
      | some p =>
        simp only [add_apply_inr, QueryImpl.withProgramming_apply, hpol, map_pure, StateT.run_mk,
          hcache, QueryImpl.withCaching_apply, StateT.run_bind, StateT.run_get, pure_bind,
          cacheOr_apply, Option.or_some, Option.getD_none, StateT.run_pure, relTriple_iff_relWP,
          MAlgRelOrdered.relWP_pure, true_and]
        exact (cacheOr_cacheQuery_of_policy policy c t p hcache hpol).symm
      | none =>
        simp only [add_apply_inr, QueryImpl.withProgramming_apply, hpol, Functor.map_map,
          StateT.run_mk, hcache, QueryImpl.withCaching_apply, StateT.run_bind, StateT.run_get,
          pure_bind, cacheOr_apply, Option.or_self, StateT.run_monadLift, monadLift_self,
          bind_pure_comp, StateT.run_modifyGet]
        refine relTriple_map (relTriple_post_mono (relTriple_refl _) ?_)
        intro x y hxy
        cases hxy
        exact ⟨rfl, (cacheOr_cacheQuery policy c t x).symm⟩

/-- **Tracking = plain.** Running the tracking oracle from `(cache₀, false)` has the same output
distribution as running the plain random oracle from `cache₀`. -/
theorem relTriple_run'_trackingROImpl_roImpl {α : Type}
    (oa : OracleComp (unifSpec + hashSpec) α) (cache₀ : hashSpec.QueryCache) :
    RelTriple ((simulateQ (trackingROImpl policy) oa).run' (cache₀, false))
      ((simulateQ (roImpl hashSpec) oa).run' cache₀) (EqRel α) := by
  refine relTriple_simulateQ_run' (trackingROImpl policy) (roImpl hashSpec)
    (fun p c => c = p.1) oa ?_ (cache₀, false) _ rfl
  rintro (n | t) ⟨c, bad⟩ c' hc'
  · exact relTriple_unifFwdFlagImpl_unifFwdImpl (R := fun p c => c = p.1) n (c, bad) c' hc'
  · subst hc'
    simp only [trackingROImpl, roImpl, QueryImpl.add_apply_inr, OracleSpec.randomOracle]
    cases hcache : c' t with
    | some v =>
      simp only [add_apply_inr, QueryImpl.withCachingTrackingPolicy_apply, Bool.if_true_left,
        Bool.decide_eq_true, Functor.map_map, StateT.run_mk, hcache, QueryImpl.withCaching_apply,
        StateT.run_bind, StateT.run_get, pure_bind, StateT.run_pure, relTriple_iff_relWP,
        MAlgRelOrdered.relWP_pure, and_self]
    | none =>
      simp only [add_apply_inr, QueryImpl.withCachingTrackingPolicy_apply, Bool.if_true_left,
        Bool.decide_eq_true, Functor.map_map, StateT.run_mk, hcache, QueryImpl.withCaching_apply,
        StateT.run_bind, StateT.run_get, pure_bind, StateT.run_monadLift, monadLift_self,
        bind_pure_comp, StateT.run_modifyGet]
      refine relTriple_map (relTriple_post_mono (relTriple_refl _) ?_)
      intro x y hxy
      cases hxy
      exact ⟨rfl, rfl⟩

/-- **Identical until bad, for the plain random oracle.** The distance between the random
oracle run from a cache overridden by a policy and the run from the cache itself is at most the
probability that the programmed run fires the policy. -/
theorem tvDist_run'_roImpl_cacheOr_le_probEvent_bad {α : Type}
    (oa : OracleComp (unifSpec + hashSpec) α) (cache₀ : hashSpec.QueryCache) :
    tvDist ((simulateQ (roImpl hashSpec) oa).run' (cacheOr cache₀ policy))
        ((simulateQ (roImpl hashSpec) oa).run' cache₀)
      ≤ Pr[fun z : α × hashSpec.QueryCache × Bool => z.2.2 = true |
          (simulateQ (programmedROImpl policy) oa).run (cache₀, false)].toReal := by
  have hB := evalDist_eq_of_relTriple_eqRel (relTriple_run'_programmedROImpl_roImpl policy oa cache₀)
  have hC := evalDist_eq_of_relTriple_eqRel (relTriple_run'_trackingROImpl_roImpl policy oa cache₀)
  calc tvDist ((simulateQ (roImpl hashSpec) oa).run' (cacheOr cache₀ policy))
          ((simulateQ (roImpl hashSpec) oa).run' cache₀)
      = tvDist ((simulateQ (programmedROImpl policy) oa).run' (cache₀, false))
          ((simulateQ (trackingROImpl policy) oa).run' (cache₀, false)) := by
        rw [tvDist, tvDist, hB, hC]
    _ ≤ tvDist ((simulateQ (programmedROImpl policy) oa).run (cache₀, false))
          ((simulateQ (trackingROImpl policy) oa).run (cache₀, false)) := by
        rw [StateT.run', StateT.run']
        exact tvDist_map_le Prod.fst _ _
    _ ≤ _ := tvDist_programmedROImpl_trackingROImpl_le policy oa cache₀

end Projections

/-! ## Programming a single point, and the averaged bound -/

section Point

variable [DecidableEq ι] [∀ t : hashSpec.Domain, SampleableType (hashSpec.Range t)]

/-- The policy programming one point `t ↦ u`. -/
def pointPolicy (t : hashSpec.Domain) (u : hashSpec.Range t) : hashSpec.ProgrammingPolicy :=
  fun t' => if h : t' = t then some (h ▸ u) else none

omit [∀ t : hashSpec.Domain, SampleableType (hashSpec.Range t)] in
/-- The empty cache overridden at one point is the cache holding that point. -/
theorem cacheOr_empty_pointPolicy (t : hashSpec.Domain) (u : hashSpec.Range t) :
    cacheOr ∅ (pointPolicy t u) = (∅ : hashSpec.QueryCache).cacheQuery t u := by
  funext t'
  by_cases h : t' = t
  · subst h
    simp only [cacheOr_apply, QueryCache.empty_apply, Option.none_or, pointPolicy, dite_true,
      QueryCache.cacheQuery_self]
  · simp only [cacheOr_apply, QueryCache.empty_apply, Option.none_or, pointPolicy, h, dite_false,
      QueryCache.cacheQuery_of_ne _ _ h]

/-- The flag of the programmed run, as a `ProbComp Bool`: the adversary queried the point. -/
noncomputable def badQueryGame {γ : Type} (pre : ProbComp γ)
    (oa : γ → OracleComp (unifSpec + hashSpec) Bool)
    (pt : γ → hashSpec.Domain) (val : (x : γ) → hashSpec.Range (pt x)) : ProbComp Bool :=
  pre >>= fun x =>
    (fun z => z.2.2) <$>
      (simulateQ (programmedROImpl (pointPolicy (pt x) (val x))) (oa x)).run (∅, false)

/-- **The averaged identical-until-bad bound.** A game that draws a prefix, programs the oracle at
one prefix-dependent point, and runs an adversary is within `Pr[the adversary queries the point]`
of the same game run from the empty cache. -/
theorem boolDistAdvantage_run'_cacheQuery_run'_empty_le {γ : Type} (pre : ProbComp γ)
    (oa : γ → OracleComp (unifSpec + hashSpec) Bool)
    (pt : γ → hashSpec.Domain) (val : (x : γ) → hashSpec.Range (pt x)) :
    ProbComp.boolDistAdvantage
      (pre >>= fun x => (simulateQ (roImpl hashSpec) (oa x)).run'
        ((∅ : hashSpec.QueryCache).cacheQuery (pt x) (val x)))
      (pre >>= fun x => (simulateQ (roImpl hashSpec) (oa x)).run' ∅)
      ≤ (Pr[= true | badQueryGame pre oa pt val]).toReal := by
  classical
  set f : γ → ProbComp Bool := fun x =>
    (simulateQ (roImpl hashSpec) (oa x)).run' ((∅ : hashSpec.QueryCache).cacheQuery (pt x) (val x))
  set g : γ → ProbComp Bool := fun x => (simulateQ (roImpl hashSpec) (oa x)).run' ∅
  set bad : γ → ℝ≥0∞ := fun x =>
    Pr[fun z : Bool × hashSpec.QueryCache × Bool => z.2.2 = true |
      (simulateQ (programmedROImpl (pointPolicy (pt x) (val x))) (oa x)).run (∅, false)]
  have hterm : ∀ x, tvDist (f x) (g x) ≤ (bad x).toReal := by
    intro x
    have := tvDist_run'_roImpl_cacheOr_le_probEvent_bad (pointPolicy (pt x) (val x)) (oa x) ∅
    rwa [cacheOr_empty_pointPolicy] at this
  have hbadGame : Pr[= true | badQueryGame pre oa pt val] = ∑' x, Pr[= x | pre] * bad x := by
    rw [badQueryGame, probOutput_bind_eq_tsum]
    refine tsum_congr fun x => ?_
    rw [probOutput_map]
  have hne_top : ∀ x, Pr[= x | pre] * bad x ≠ ⊤ := fun x =>
    ENNReal.mul_ne_top (ne_top_of_le_ne_top one_ne_top probOutput_le_one)
      (ne_top_of_le_ne_top one_ne_top probEvent_le_one)
  have hsum_ne_top : (∑' x, Pr[= x | pre] * bad x) ≠ ⊤ := by
    rw [← hbadGame]
    exact ne_top_of_le_ne_top one_ne_top probOutput_le_one
  have hsummable : Summable fun x => (Pr[= x | pre] * bad x).toReal :=
    ENNReal.summable_toReal hsum_ne_top
  calc ProbComp.boolDistAdvantage (pre >>= f) (pre >>= g)
      ≤ tvDist (pre >>= f) (pre >>= g) := abs_probOutput_toReal_sub_le_tvDist _ _
    _ ≤ ∑' x, Pr[= x | pre].toReal * tvDist (f x) (g x) := tvDist_bind_left_le pre f g
    _ ≤ ∑' x, (Pr[= x | pre] * bad x).toReal := by
        refine Summable.tsum_le_tsum (fun x => ?_) ?_ hsummable
        · rw [ENNReal.toReal_mul]
          exact mul_le_mul_of_nonneg_left (hterm x) ENNReal.toReal_nonneg
        · exact hsummable.of_nonneg_of_le
            (fun x => mul_nonneg ENNReal.toReal_nonneg (tvDist_nonneg _ _))
            (fun x => by
              rw [ENNReal.toReal_mul]
              exact mul_le_mul_of_nonneg_left (hterm x) ENNReal.toReal_nonneg)
    _ = (Pr[= true | badQueryGame pre oa pt val]).toReal := by
        rw [hbadGame, ENNReal.tsum_toReal_eq hne_top]

end Point

end PqStealth
