import PqStealth.KEMAnonymity

/-!
# Parallel hybrid KEMs

A hybrid KEM runs two component KEMs independently and combines their shared
secrets with both public keys and both ciphertexts. Supplying the public-key
reconstruction functions lets decapsulation feed the same bindings to the
combiner without carrying public keys in the ciphertext.
-/

open OracleComp OracleSpec

namespace PqStealth

namespace KEM

variable {PK₁ SK₁ C₁ K₁ PK₂ SK₂ C₂ K₂ K : Type}

/-- A component KEM's secret key reconstructs the public key it was generated
with. ERC-8441 uses this for `viewing_ec ↦ viewing_pk_ec` and `(d, z) ↦ ek`. -/
def PublicKeyBound (kem : KEM PK₁ SK₁ C₁ K₁) (publicOfSecret : SK₁ → PK₁) : Prop :=
  ∀ pk sk, (pk, sk) ∈ support kem.keygen → publicOfSecret sk = pk

/-- Every reachable decapsulation of an honestly generated component ciphertext
returns the component's encapsulated secret. This is only honest-key,
honest-ciphertext correctness: it says nothing about adversarial ciphertexts
or implicit rejection. -/
def CorrectOnSupport (kem : KEM PK₁ SK₁ C₁ K₁) : Prop :=
  ∀ pk sk, (pk, sk) ∈ support kem.keygen →
    ∀ c k, (c, k) ∈ support (kem.encaps pk) →
      ∀ kOpt, kOpt ∈ support (kem.decaps sk c) → kOpt = some k

/-- Perfect correctness yields the support-level formulation needed to compose
independent KEMs. -/
theorem correctOnSupport_of_perfectlyCorrect [DecidableEq K₁]
    (kem : KEM PK₁ SK₁ C₁ K₁) (hkem : kem.PerfectlyCorrect ProbCompRuntime.probComp) :
    kem.CorrectOnSupport := by
  intro pk sk hks c k hck kOpt hkOpt
  have hmem : decide (kOpt = some k) ∈ support kem.CorrectExp := by
    simp only [KEMScheme.CorrectExp, support_bind, support_pure, Set.mem_iUnion,
      Set.mem_singleton_iff, decide_eq_decide, exists_prop, Prod.exists]
    exact ⟨pk, sk, hks, c, k, hck, kOpt, hkOpt, Iff.rfl⟩
  simpa [((probOutput_eq_one_iff (mx := kem.CorrectExp) (x := true)).mp hkem).2] using hmem

/-- Parallel composition of two KEMs. The first KEM is the ECDH component and
the second is the ML-KEM component; the combiner order is `(ecdhPublic,
kemPublic, epk, ct, ss_ec, ss_pq)`. This is exactly the input list ERC-8441
binds into its domain-separated hash. -/
def parallel (kem₁ : KEM PK₁ SK₁ C₁ K₁) (kem₂ : KEM PK₂ SK₂ C₂ K₂)
    (publicOfSecret₁ : SK₁ → PK₁) (publicOfSecret₂ : SK₂ → PK₂)
    (combine : PK₁ → PK₂ → C₁ → C₂ → K₁ → K₂ → K) :
    KEM (PK₁ × PK₂) (SK₁ × SK₂) (C₁ × C₂) K where
  keygen := do
    let ks₁ ← kem₁.keygen
    let ks₂ ← kem₂.keygen
    pure ((ks₁.1, ks₂.1), (ks₁.2, ks₂.2))
  encaps := fun pk => do
    let ck₁ ← kem₁.encaps pk.1
    let ck₂ ← kem₂.encaps pk.2
    pure ((ck₁.1, ck₂.1), combine pk.1 pk.2 ck₁.1 ck₂.1 ck₁.2 ck₂.2)
  decaps := fun sk c => do
    let k₁? ← kem₁.decaps sk.1 c.1
    let k₂? ← kem₂.decaps sk.2 c.2
    match k₁?, k₂? with
    | some k₁, some k₂ =>
      pure (some (combine (publicOfSecret₁ sk.1) (publicOfSecret₂ sk.2) c.1 c.2 k₁ k₂))
    | _, _ => pure none

/-- Support-level correctness composes in parallel when each component can
reconstruct its registered public key from its secret state. -/
theorem parallel_correctOnSupport
    (kem₁ : KEM PK₁ SK₁ C₁ K₁) (kem₂ : KEM PK₂ SK₂ C₂ K₂)
    (publicOfSecret₁ : SK₁ → PK₁) (publicOfSecret₂ : SK₂ → PK₂)
    (combine : PK₁ → PK₂ → C₁ → C₂ → K₁ → K₂ → K)
    (hpk₁ : kem₁.PublicKeyBound publicOfSecret₁)
    (hpk₂ : kem₂.PublicKeyBound publicOfSecret₂)
    (hcorrect₁ : kem₁.CorrectOnSupport) (hcorrect₂ : kem₂.CorrectOnSupport) :
    (parallel kem₁ kem₂ publicOfSecret₁ publicOfSecret₂ combine).CorrectOnSupport := by
  rintro ⟨pk₁, pk₂⟩ ⟨sk₁, sk₂⟩ hks ⟨c₁, c₂⟩ k kck kOpt hkOpt
  rw [parallel, support_bind] at hks
  simp only [Set.mem_iUnion] at hks
  obtain ⟨ks₁, hks₁, hks⟩ := hks
  rw [support_bind] at hks
  simp only [Set.mem_iUnion] at hks
  obtain ⟨ks₂, hks₂, hks⟩ := hks
  simp only [support_pure, Set.mem_singleton_iff] at hks
  have hpk : (ks₁.1, ks₂.1) = (pk₁, pk₂) := (congrArg Prod.fst hks).symm
  have hsk : (ks₁.2, ks₂.2) = (sk₁, sk₂) := (congrArg Prod.snd hks).symm
  have hpk₁eq : ks₁.1 = pk₁ := congrArg Prod.fst hpk
  have hpk₂eq : ks₂.1 = pk₂ := congrArg Prod.snd hpk
  have hsk₁eq : ks₁.2 = sk₁ := congrArg Prod.fst hsk
  have hsk₂eq : ks₂.2 = sk₂ := congrArg Prod.snd hsk
  have hkey₁ : (pk₁, sk₁) ∈ support kem₁.keygen := by
    simpa only [← hpk₁eq, ← hsk₁eq] using hks₁
  have hkey₂ : (pk₂, sk₂) ∈ support kem₂.keygen := by
    simpa only [← hpk₂eq, ← hsk₂eq] using hks₂
  rw [parallel, support_bind] at kck
  simp only [Set.mem_iUnion] at kck
  obtain ⟨ck₁, hck₁, kck⟩ := kck
  rw [support_bind] at kck
  simp only [Set.mem_iUnion] at kck
  obtain ⟨ck₂, hck₂, kck⟩ := kck
  simp only [support_pure, Set.mem_singleton_iff] at kck
  have hc : (ck₁.1, ck₂.1) = (c₁, c₂) := (congrArg Prod.fst kck).symm
  have hk : combine pk₁ pk₂ ck₁.1 ck₂.1 ck₁.2 ck₂.2 = k :=
    (congrArg Prod.snd kck).symm
  have hc₁ : ck₁.1 = c₁ := congrArg Prod.fst hc
  have hc₂ : ck₂.1 = c₂ := congrArg Prod.snd hc
  rw [parallel, support_bind] at hkOpt
  simp only [Set.mem_iUnion] at hkOpt
  obtain ⟨k₁Opt, hk₁Opt, hkOpt⟩ := hkOpt
  rw [support_bind] at hkOpt
  simp only [Set.mem_iUnion] at hkOpt
  obtain ⟨k₂Opt, hk₂Opt, hkOpt⟩ := hkOpt
  have hk₁ : k₁Opt = some ck₁.2 := by
    exact hcorrect₁ pk₁ sk₁ hkey₁ ck₁.1 ck₁.2 hck₁ k₁Opt
      (by simpa only [← hc₁] using hk₁Opt)
  have hk₂ : k₂Opt = some ck₂.2 := by
    exact hcorrect₂ pk₂ sk₂ hkey₂ ck₂.1 ck₂.2 hck₂ k₂Opt
      (by simpa only [← hc₂] using hk₂Opt)
  subst k₁Opt
  subst k₂Opt
  simp only [support_pure, Set.mem_singleton_iff] at hkOpt
  calc
    kOpt = some (combine (publicOfSecret₁ sk₁) (publicOfSecret₂ sk₂)
        c₁ c₂ ck₁.2 ck₂.2) := hkOpt
    _ = some (combine pk₁ pk₂ ck₁.1 ck₂.1 ck₁.2 ck₂.2) := by
      rw [hpk₁ pk₁ sk₁ hkey₁, hpk₂ pk₂ sk₂ hkey₂, hc₁, hc₂]
    _ = some k := congrArg some hk

/-- Support-level correctness implies VCVio's probability-one KEM correctness. -/
theorem perfectlyCorrect_of_correctOnSupport [DecidableEq K]
    (kem : KEM PK₁ SK₁ C₁ K) (hcorrect : kem.CorrectOnSupport) :
    kem.PerfectlyCorrect ProbCompRuntime.probComp := by
  change Pr[= true | kem.CorrectExp] = 1
  rw [probOutput_eq_one_iff_forall]
  refine ⟨probFailure_of_liftM_PMF _, ?_⟩
  intro verdict hverdict
  rw [KEMScheme.CorrectExp, support_bind] at hverdict
  simp only [Set.mem_iUnion] at hverdict
  obtain ⟨ks, hks, hverdict⟩ := hverdict
  rw [support_bind] at hverdict
  simp only [Set.mem_iUnion] at hverdict
  obtain ⟨ck, hck, hverdict⟩ := hverdict
  rw [support_bind] at hverdict
  simp only [Set.mem_iUnion] at hverdict
  obtain ⟨kOpt, hkOpt, hverdict⟩ := hverdict
  simp only [support_pure, Set.mem_singleton_iff] at hverdict
  have hOpt : kOpt = some ck.2 :=
    hcorrect ks.1 ks.2 hks ck.1 ck.2 hck kOpt hkOpt
  simpa only [hOpt, decide_true] using hverdict

/-- Perfect correctness of both components transfers to their parallel hybrid
KEM, provided each component secret state reconstructs its registered public
key. The combiner itself needs no algebraic property for correctness: both
sides receive the same six inputs. -/
theorem parallel_perfectlyCorrect [DecidableEq K₁] [DecidableEq K₂] [DecidableEq K]
    (kem₁ : KEM PK₁ SK₁ C₁ K₁) (kem₂ : KEM PK₂ SK₂ C₂ K₂)
    (publicOfSecret₁ : SK₁ → PK₁) (publicOfSecret₂ : SK₂ → PK₂)
    (combine : PK₁ → PK₂ → C₁ → C₂ → K₁ → K₂ → K)
    (hpk₁ : kem₁.PublicKeyBound publicOfSecret₁)
    (hpk₂ : kem₂.PublicKeyBound publicOfSecret₂)
    (hcorrect₁ : kem₁.PerfectlyCorrect ProbCompRuntime.probComp)
    (hcorrect₂ : kem₂.PerfectlyCorrect ProbCompRuntime.probComp) :
    (parallel kem₁ kem₂ publicOfSecret₁ publicOfSecret₂ combine).PerfectlyCorrect
      ProbCompRuntime.probComp :=
  perfectlyCorrect_of_correctOnSupport _ <|
    parallel_correctOnSupport kem₁ kem₂ publicOfSecret₁ publicOfSecret₂ combine hpk₁ hpk₂
      (correctOnSupport_of_perfectlyCorrect kem₁ hcorrect₁)
      (correctOnSupport_of_perfectlyCorrect kem₂ hcorrect₂)

end KEM

end PqStealth
