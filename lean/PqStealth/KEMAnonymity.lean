import PqStealth.Games
import VCVio.CryptoFoundations.KeyEncapMech

/-!
# KEM anonymity and the unlinkability reduction

Proved: `KEM` (VCVio's `KEMScheme` over `ProbComp`) and its anonymity game --
key privacy, which VCVio does not ship; `ofKEM`, whose unlinkability EQUALS the
KEM's anonymity advantage; `ofKEMFull`, the faithful scheme whose announcement
also carries `auxGen sharedSecret pk` and whose scan recomputes it, with
`unlinkAdvantage_ofKEMFull_le` bounding unlinkability by two
shared-secret-hiding terms, `auxKeyIndependence`, and anonymity; and detection
completeness of `ofKEMFull` from VCVio's `KEMScheme.PerfectlyCorrect`.

The oracle-backed recipient-anonymity games live in `OracleGames`: ANO-CPA
(two-phase wrapper over `AnonExp`) and oracle-backed ANO-CCA on a Bool-keyed,
level-0 decapsulation oracle (`anonOracleSpec spec C K = spec + ((Bool × C)
→ₒ Option K)`, matching VCVio's `IND_CCA` shape). `simulateQ_toANO_CCA` and
`toANO_CCA_pre/PostChallenge` prove the oracle-ignoring CPA adversary is
identical across the two games phase-for-phase. `ANO_CCA_Advantage_le_of_spr`
closes the reduction: a CPA anonymity adversary lifted into the CCA game is
bounded by the two per-branch SPR terms against a key-independent simulator,
under explicit runtime-coherence hypotheses (`heval_pure/bind/liftProbComp`,
and `hnf` totality on `Bool` computations) — the same pattern VCVio's
KEM+DEM reduction carries.

These are the local stand-ins for upstream `Verified-zkEVM/VCVio#848`; if that
lands, this section is what gets upstreamed and replaced. The unlinkability
chain still bottoms out in the CPA anonymity term `anonAdvantage`; the CCA
variant here is the deployed-adversary refinement.
`ANO_CCA_Advantage_le_of_spr_full` extends the bound to the **full CCA
adversary** — one that queries the decapsulation oracle: the hidden-bit
decomposition and SPR triangle were generic in the adversary all along.
Bounding the SPR terms themselves at ML-KEM-768 (seeded-MLWE chain plus the
ROM/PRF and collision terms of Maram–Xagawa's Theorem 2, per
the Maram–Xagawa Theorem 2 paper verification) is what remains.
`anonymity → MLWE` for ML-KEM is the open piece (`AnonymityFromSPR`).
-/

open OracleComp OracleSpec

universe u

namespace PqStealth

/-! ## An abstract KEM

`abbrev` rather than `def` so dot notation reaches both this namespace and
`KEMScheme`; correctness and KEM IND-CPA are therefore VCVio's own. -/

/-- A key encapsulation mechanism over `ProbComp`: key generation, encapsulation
(producing a ciphertext and a shared secret), and decapsulation. -/
abbrev KEM (PK SK C K : Type) := KEMScheme ProbComp K PK SK C

/-! ## A `Pr[= true | …] = 1` transfer lemma -/

/-- Transfer a probability-one Boolean verdict along a pointwise implication:
VCVio's `probEvent_mono` read through `probOutput_map`. Used to derive detection
completeness from the strictly stronger verdict of KEM correctness. -/
theorem probOutput_true_eq_one_of_imp {α : Type} (oa : ProbComp α) {p q : α → Bool}
    (h : ∀ a ∈ support oa, p a = true → q a = true)
    (hp : Pr[= true | (do let a ← oa; pure (p a))] = 1) :
    Pr[= true | (do let a ← oa; pure (q a))] = 1 := by
  rw [bind_pure_comp, probOutput_map] at hp ⊢
  exact le_antisymm probEvent_le_one (hp ▸ probEvent_mono h)

namespace KEM

variable {PK SK C K : Type} (kem : KEM PK SK C K)
  (adv : StealthScheme.UnlinkAdv PK C)

/-! ## Correctness

VCVio's `KEMScheme.PerfectlyCorrect`; `run` names the shared draw prefix so the
verdict can be varied. -/

/-- The draw prefix common to KEM correctness and to detection completeness:
a keypair, an encapsulation to its public key, and a decapsulation of the
result. -/
def run : ProbComp ((PK × SK) × (C × K) × Option K) := do
  let ks ← kem.keygen
  let ck ← kem.encaps ks.1
  let k? ← kem.decaps ks.2 ck.1
  pure (ks, ck, k?)

/-- VCVio's correctness experiment is `run` scored by "the decapsulated key is
the encapsulated one". -/
theorem correctExp_eq [DecidableEq K] :
    kem.CorrectExp = (do let a ← kem.run; pure (decide (a.2.2 = some a.2.1.2))) := by
  simp only [KEMScheme.CorrectExp, KEM.run, bind_assoc, pure_bind]

/-! ## Anonymity (key privacy)

The hidden bit selects which of two public keys the challenge ciphertext is
encapsulated to. The distinguisher is exactly `UnlinkAdv PK C`. -/

/-- Shared prefix: two keypairs, both public keys published. -/
def anonSetup : ProbComp (PK × PK) := do
  let (pk0, _) ← kem.keygen
  let (pk1, _) ← kem.keygen
  pure (pk0, pk1)

/-- The branch selected by the hidden bit: encapsulate to public key `b`. -/
def anonBranch (b : Bool) (a : PK × PK) : ProbComp Bool := do
  let (c, _) ← kem.encaps (if b then a.2 else a.1)
  adv a.1 a.2 c

/-- Anonymity experiment in VCVio hidden-bit form. -/
def AnonExp : ProbComp Bool := do
  let a ← kem.anonSetup
  let b ← ($ᵗ Bool)
  let z ← kem.anonBranch adv b a
  pure (b == z)

/-- Anonymity advantage. -/
noncomputable def anonAdvantage : ℝ := (kem.AnonExp adv).boolBiasAdvantage

/-- The anonymity advantage decomposes into the advantage of distinguishing an
encapsulation to key 1 from one to key 0 -- same VCVio lemma as unlinkability. -/
theorem anonAdvantage_eq_branchDistAdvantage :
    kem.anonAdvantage adv =
      (kem.anonSetup >>= kem.anonBranch adv true).boolDistAdvantage
      (kem.anonSetup >>= kem.anonBranch adv false) :=
  ProbComp.boolBiasAdvantage_bind_uniformBool_branch kem.anonSetup (kem.anonBranch adv)

/-! ## Recipient anonymity as a security game

Two variants, mirroring VCVio's `IND-CPA` / `IND-CCA` split and held back from
upstream until `Verified-zkEVM/VCVio#848` lands.

* **ANO-CPA** is the hidden-bit key-privacy game already proved above as
  `AnonExp` / `anonAdvantage`; this section adds the two-phase
  `ANO_CPA_Adversary` wrapper and a reusable experiment.

* **ANO-CCA** adds a live decapsulation oracle keyed by the recipient bit,
  modelled exactly like VCVio's `IND_CCA_Game`: the adversary runs against
  `spec + ((Bool × C) →ₒ Option K)` (base, then `(whichKey, ciphertext)`), the
  post-challenge oracle masks its own challenge ciphertext to `none` on both
  keys, and the adversary is simulated back into `OracleComp spec` with the real
  `decaps`. This is the game a deployed ERC-5564 adversary actually plays — it
  can decapsulate every registered candidate's announcements. The two recipients
  share one `Type 0` oracle (index `Bool × C`) so the whole development stays in
  VCVio's level-0 `simulateQ`/`SubSpec` API — the same shape as `IND_CCA`. -/

section OracleGames

/-- Oracle spec for the anonymity games: the base `spec` plus a decapsulation
oracle taking `(whichKey : Bool, ciphertext : C)` to the shared key `K`. Both
recipient keys share one oracle, selected by the Boolean, exactly as VCVio's
`IND_CCA_oracleSpec` shares one `C →ₒ Option K` for its single key. -/
@[reducible] def anonOracleSpec {ι : Type} (spec : OracleSpec ι) (C K : Type) :
    OracleSpec (ι ⊕ Bool × C) :=
  spec + ((Bool × C) →ₒ Option K)

/-- Two-phase ciphertext-only anonymity adversary. The hidden bit selects which
of two public keys the challenge ciphertext encapsulates to; `postChallenge`
sees both public keys and the challenge ciphertext but never the encapsulated
secret. -/
structure ANO_Adversary {ι : Type} (spec : OracleSpec ι) (PK C : Type) where
  /-- Internal adversary state carried across the challenge. -/
  State : Type
  /-- Pre-challenge phase: sees both public keys, returns a state. -/
  preChallenge : PK → PK → OracleComp spec State
  /-- Post-challenge phase: sees the state and the challenge ciphertext. -/
  postChallenge : State → C → OracleComp spec Bool

/-- Fixed-branch ANO-CPA experiment: no decapsulation oracle, matching
`IND_CPA_Exp` but on the challenge ciphertext rather than the shared key. -/
def ANO_CPA_Exp {ι : Type} {spec : OracleSpec ι} {K PK SK C : Type}
    (kem : KEMScheme (OracleComp spec) K PK SK C)
    (runtime : ProbCompRuntime (OracleComp spec)) (b : Bool)
    (adv : ANO_Adversary spec PK C) : SPMF Bool :=
  runtime.evalDist do
    let (pk0, _) ← kem.keygen
    let (pk1, _) ← kem.keygen
    let st ← adv.preChallenge pk0 pk1
    let (cStar, _) ← kem.encaps (if b then pk1 else pk0)
    adv.postChallenge st cStar

/-- Single-bit ANO-CPA experiment. -/
def ANO_CPA_Game {ι : Type} {spec : OracleSpec ι} {K PK SK C : Type}
    (kem : KEMScheme (OracleComp spec) K PK SK C)
    (runtime : ProbCompRuntime (OracleComp spec)) (adv : ANO_Adversary spec PK C) :
    SPMF Bool :=
  runtime.evalDist do
    let (pk0, _) ← kem.keygen
    let (pk1, _) ← kem.keygen
    let st ← adv.preChallenge pk0 pk1
    let b ← runtime.liftProbComp ($ᵗ Bool)
    let (cStar, _) ← kem.encaps (if b then pk1 else pk0)
    let b' ← adv.postChallenge st cStar
    return (b == b')

/-- ANO-CPA anonymity advantage: bias of the hidden-bit guessing game. -/
noncomputable def ANO_CPA_Advantage {ι : Type} {spec : OracleSpec ι} {K PK SK C : Type}
    (kem : KEMScheme (OracleComp spec) K PK SK C)
    (runtime : ProbCompRuntime (OracleComp spec)) (adv : ANO_Adversary spec PK C) : ℝ :=
  (ANO_CPA_Game kem runtime adv).boolBiasAdvantage

/-- Two-phase ANO-CCA anonymity adversary with a decapsulation oracle for both
keys. Neither phase ever sees the challenge shared secret; both phases may
query decapsulation of `(whichKey, ciphertext)` through the ambient
`OracleComp (anonOracleSpec …)`. -/
structure ANO_CCA_Adversary {ι : Type} (spec : OracleSpec ι) (PK C K : Type) where
  /-- Internal adversary state carried across the challenge. -/
  State : Type
  /-- Pre-challenge phase: sees both public keys, may decapsulate under both. -/
  preChallenge : PK → PK → OracleComp (anonOracleSpec spec C K) State
  /-- Post-challenge phase: sees the state and ciphertext, oracle still live. -/
  postChallenge : State → C → OracleComp (anonOracleSpec spec C K) Bool

/-- Pre-challenge ANO-CCA oracle implementation: real decapsulation under the
key selected by the Boolean. -/
def anoPreChallengeImpl {ι : Type} {spec : OracleSpec ι} {K PK SK C : Type}
    (kem : KEMScheme (OracleComp spec) K PK SK C) (sk0 sk1 : SK) :
    QueryImpl (anonOracleSpec spec C K) (OracleComp spec) :=
  (HasQuery.toQueryImpl (spec := spec) (m := OracleComp spec)) +
    (fun (bc : Bool × C) => if bc.1 then kem.decaps sk1 bc.2 else kem.decaps sk0 bc.2)

/-- Post-challenge ANO-CCA oracle implementation: the challenge ciphertext maps
to `none` under either key, everything else decapsulates for real. -/
def anoPostChallengeImpl {ι : Type} {spec : OracleSpec ι} {K PK SK C : Type}
    (kem : KEMScheme (OracleComp spec) K PK SK C) [DecidableEq C]
    (sk0 sk1 : SK) (cStar : C) :
    QueryImpl (anonOracleSpec spec C K) (OracleComp spec) :=
  (HasQuery.toQueryImpl (spec := spec) (m := OracleComp spec)) +
    (fun (bc : Bool × C) => if bc.2 = cStar then return none
      else if bc.1 then kem.decaps sk1 bc.2 else kem.decaps sk0 bc.2)

/-- ANO-CCA experiment: the hidden bit picks which key encapsulates the
challenge ciphertext; both decapsulation oracles stay live throughout, each
masking its own challenge. -/
def ANO_CCA_Game {ι : Type} {spec : OracleSpec ι} {K PK SK C : Type}
    (kem : KEMScheme (OracleComp spec) K PK SK C)
    (runtime : ProbCompRuntime (OracleComp spec)) [DecidableEq C]
    (adv : ANO_CCA_Adversary spec PK C K) : SPMF Bool :=
  runtime.evalDist do
    let (pk0, sk0) ← kem.keygen
    let (pk1, sk1) ← kem.keygen
    let st ← simulateQ (anoPreChallengeImpl kem sk0 sk1) (adv.preChallenge pk0 pk1)
    let b ← runtime.liftProbComp ($ᵗ Bool)
    let (cStar, _) ← kem.encaps (if b then pk1 else pk0)
    let b' ← simulateQ (anoPostChallengeImpl kem sk0 sk1 cStar) (adv.postChallenge st cStar)
    return (b == b')

/-- ANO-CCA anonymity advantage: bias of the hidden-bit guessing game. -/
noncomputable def ANO_CCA_Advantage {ι : Type} {spec : OracleSpec ι} {K PK SK C : Type}
    (kem : KEMScheme (OracleComp spec) K PK SK C)
    (runtime : ProbCompRuntime (OracleComp spec)) [DecidableEq C]
    (adv : ANO_CCA_Adversary spec PK C K) : ℝ :=
  (ANO_CCA_Game kem runtime adv).boolBiasAdvantage

/-- Embed a ciphertext-only CPA anonymity adversary into the CCA game by
ignoring the decapsulation oracle. The lift is `simulateQ` with the base-`spec`
handler `HasQuery.toQueryImpl`, which — by `HasQuery.toQueryImpl_eq_id'` — is the
identity semantics, so no randomness enters and the CPA branch is preserved
exactly. This is the anonymity analogue of VCVio's
`IND_CPA_Adversary.toIND_CCA`. -/
def ANO_Adversary.toANO_CCA {ι : Type} {spec : OracleSpec ι} {PK C K : Type}
    (adv : ANO_Adversary spec PK C) : ANO_CCA_Adversary spec PK C K where
  State := adv.State
  preChallenge pk0 pk1 := simulateQ
    (HasQuery.toQueryImpl (spec := spec) (m := OracleComp (anonOracleSpec spec C K)))
    (adv.preChallenge pk0 pk1)
  postChallenge st c := simulateQ
    (HasQuery.toQueryImpl (spec := spec) (m := OracleComp (anonOracleSpec spec C K)))
    (adv.postChallenge st c)

/-- Composing the game handler `base + decapOracle` with the oracle-ignoring
lift collapses to the identity: an adversary phase that never queries
decapsulation is simulated away exactly. This is the anonymity form of VCVio's
`IND_CPA_Game_eq_IND_CCA_Game_toIND_CCA`, at the level-0 `spec + ((Bool × C)
→ₒ Option K)` oracle so the stock `simulateQ` / `SubSpec` lemmas apply. -/
theorem simulateQ_toANO_CCA {ι : Type} {spec : OracleSpec ι} {K C : Type} (SK : Type)
    (impl₂ : QueryImpl ((Bool × C) →ₒ Option K) (OracleComp spec))
    {α : Type} (oa : OracleComp spec α) :
    simulateQ ((HasQuery.toQueryImpl (spec := spec) (m := OracleComp spec)) + impl₂)
      (simulateQ (HasQuery.toQueryImpl (spec := spec)
        (m := OracleComp (anonOracleSpec spec C K))) oa) = oa := by
  rw [← QueryImpl.simulateQ_compose]
  have : (HasQuery.toQueryImpl (spec := spec) (m := OracleComp spec) + impl₂) ∘ₛ
      HasQuery.toQueryImpl (spec := spec)
        (m := OracleComp (anonOracleSpec spec C K)) = QueryImpl.id' spec := by
    ext t
    simp only [QueryImpl.compose, QueryImpl.id']
    change simulateQ (QueryImpl.id' spec + impl₂)
      (liftM (liftM (spec.query t) : OracleQuery (anonOracleSpec spec C K) _)) = _
    simp [simulateQ_query]
  rw [this, simulateQ_id']

/-- Pre-challenge phase of the oracle-ignoring adversary is exactly the CPA
phase: the decapsulation oracle contributes nothing it does not query. -/
theorem toANO_CCA_preChallenge {ι : Type} {spec : OracleSpec ι} {K PK SK C : Type}
    (kem : KEMScheme (OracleComp spec) K PK SK C) (sk0 sk1 : SK)
    (adv : ANO_Adversary spec PK C) (pk0 pk1 : PK) :
    simulateQ (anoPreChallengeImpl kem sk0 sk1)
      ((ANO_Adversary.toANO_CCA adv).preChallenge pk0 pk1) = adv.preChallenge pk0 pk1 :=
  simulateQ_toANO_CCA SK _ _

/-- Post-challenge phase of the oracle-ignoring adversary is exactly the CPA
phase, even though the real handler masks the challenge ciphertext — the
adversary never queries it. -/
theorem toANO_CCA_postChallenge {ι : Type} {spec : OracleSpec ι} {K PK SK C : Type}
    (kem : KEMScheme (OracleComp spec) K PK SK C) [DecidableEq C]
    (sk0 sk1 : SK) (cStar : C) (adv : ANO_Adversary spec PK C) (st : adv.State) (c : C) :
    simulateQ (anoPostChallengeImpl kem sk0 sk1 cStar)
      ((ANO_Adversary.toANO_CCA adv).postChallenge st c) = adv.postChallenge st c :=
  simulateQ_toANO_CCA SK _ _

/-! ### The SPR reduction: ANO-CCA advantage ≤ sum of per-branch SPR terms

For the oracle-ignoring CPA-to-CCA lift `adv.toANO_CCA`, the hidden-bit ANO-CCA
advantage decomposes — via the fair-coin hidden-bit lemma — into the
distinguishing advantage between the two fixed-branch CCA experiments, which is
then bounded branch-by-branch by the SPR (simulated pseudo-randomness)
advantage of replacing the challenge encapsulation with the key-independent
simulator `sim`. All distribution-level steps are carried out for a general
`ProbCompRuntime`, passing the required coherence of `runtime.evalDist` with
`pure`/`>>=`, its agreement with `𝒟` on lifted `ProbComp` sampling, and its
totality on `Bool`-valued computations as explicit hypotheses — exactly the
pattern of VCVio's `ind_cpa_one_time_bias_advantage_compose_with_dem_le`. -/

/-- Fixed-branch ANO-CCA experiment: the hidden bit is fixed to `b`, so the
challenge ciphertext is always encapsulated to public key `b`; both
decapsulation oracles stay live (pre-challenge unmasked, post-challenge masking
its own challenge). -/
def ANO_CCA_Branch {ι : Type} {spec : OracleSpec ι} {K PK SK C : Type}
    (kem : KEMScheme (OracleComp spec) K PK SK C)
    (runtime : ProbCompRuntime (OracleComp spec)) [DecidableEq C]
    (adv : ANO_CCA_Adversary spec PK C K) (b : Bool) : SPMF Bool :=
  runtime.evalDist do
    let (pk0, sk0) ← kem.keygen
    let (pk1, sk1) ← kem.keygen
    let st ← simulateQ (anoPreChallengeImpl kem sk0 sk1) (adv.preChallenge pk0 pk1)
    let (cStar, _) ← kem.encaps (if b then pk1 else pk0)
    simulateQ (anoPostChallengeImpl kem sk0 sk1 cStar) (adv.postChallenge st cStar)

/-- Key-independent simulator branch: the challenge ciphertext is drawn from
`sim` instead of an encapsulation, both decapsulation oracles stay live, and the
adversary's verdict is returned. -/
def ANO_CCA_SimBranch {ι : Type} {spec : OracleSpec ι} {K PK SK C : Type}
    (kem : KEMScheme (OracleComp spec) K PK SK C)
    (runtime : ProbCompRuntime (OracleComp spec)) [DecidableEq C]
    (adv : ANO_CCA_Adversary spec PK C K) (sim : ProbComp C) : SPMF Bool :=
  runtime.evalDist do
    let (pk0, sk0) ← kem.keygen
    let (pk1, sk1) ← kem.keygen
    let st ← simulateQ (anoPreChallengeImpl kem sk0 sk1) (adv.preChallenge pk0 pk1)
    let cStar ← runtime.liftProbComp sim
    simulateQ (anoPostChallengeImpl kem sk0 sk1 cStar) (adv.postChallenge st cStar)

/-- SPR (simulated pseudo-randomness) advantage of branch `b`: the distinguishing
advantage between honestly encapsulating the challenge ciphertext under public
key `b` and drawing it from the key-independent simulator `sim`. -/
noncomputable def ANO_SPR_Term {ι : Type} {spec : OracleSpec ι} {K PK SK C : Type}
    (kem : KEMScheme (OracleComp spec) K PK SK C)
    (runtime : ProbCompRuntime (OracleComp spec)) [DecidableEq C]
    (adv : ANO_CCA_Adversary spec PK C K) (sim : ProbComp C) (b : Bool) : ℝ :=
  (ANO_CCA_Branch kem runtime adv b).boolDistAdvantage (ANO_CCA_SimBranch kem runtime adv sim)

/-- The SPR reduction: the ANO-CCA advantage of the oracle-ignoring lift
`adv.toANO_CCA` is at most the sum of the per-branch SPR terms. The proof has
two stages:

* **Hidden-bit decomposition.** The single ANO-CCA game equals a fair-coin
  branch over the two fixed-branch experiments — the branches re-run exactly
  the game's own phases for the lift `adv.toANO_CCA`, and the independent
  draws are commuted (`bind_swap` from `probOutput_bind_bind_swap`) so the coin
  sits in front — so its bias advantage equals the distinguishing advantage
  between the branches (`boolBiasAdvantage_eq_boolDistAdvantage_coin_branch`,
  with the fair-coin probabilities from `probOutput_uniformSample`).

* **Branch-wise SPR bound.** The `true` SPR term is definitionally the
  `true`-branch-to-simulator distinguishing advantage, and the `false` term is
  the same advantage with arguments flipped (`abs_sub_comm`); one application
  of `boolDistAdvantage_triangle` through the key-independent simulator branch
  bounds the inter-branch advantage by their sum.

The coherence hypotheses on the general `runtime` are the standard ones:
monad-morphism laws for `runtime.evalDist` (`heval_pure`, `heval_bind`),
agreement with `𝒟` on lifted `ProbComp` sampling (`heval_liftProbComp`, giving
the fair coin), and totality on `Bool`-valued computations (`hnf`, giving the
per-branch totality the coin-branch decomposition requires). -/
theorem ANO_CCA_Advantage_le_of_spr {ι : Type} {spec : OracleSpec ι}
    [IsUniformSpec spec]
    {K PK SK C : Type} [DecidableEq C]
    (kem : KEMScheme (OracleComp spec) K PK SK C)
    (runtime : ProbCompRuntime (OracleComp spec))
    (adv : ANO_Adversary spec PK C)
    (sim : ProbComp C)
    (heval_pure : ∀ {α : Type} (a : α),
      runtime.evalDist (pure a : OracleComp spec α) = pure a)
    (heval_bind : ∀ {α β : Type} (mx : OracleComp spec α)
      (f : α → OracleComp spec β),
      runtime.evalDist (mx >>= f) =
        runtime.evalDist mx >>= fun a => runtime.evalDist (f a))
    (heval_liftProbComp : ∀ {α : Type} (pc : ProbComp α),
      runtime.evalDist (runtime.liftProbComp pc) = 𝒟[pc])
    (hnf : ∀ (mx : OracleComp spec Bool),
      Pr[= true | runtime.evalDist mx] + Pr[= false | runtime.evalDist mx] = 1)
    {sprTrue sprFalse : ℝ}
    (hT : ANO_SPR_Term kem runtime adv.toANO_CCA sim true ≤ sprTrue)
    (hF : ANO_SPR_Term kem runtime adv.toANO_CCA sim false ≤ sprFalse) :
    ANO_CCA_Advantage kem runtime adv.toANO_CCA ≤ sprTrue + sprFalse := by
  -- Local SPMF-level commutation of independent draws (`bind_swap`), proved by
  -- pointwise `probOutput_bind_bind_swap` exactly as in VCVio's KEMDEM proof.
  have bind_swap : ∀ {α β γ : Type} (mx : SPMF α) (my : SPMF β)
      (f : α → β → SPMF γ),
      (mx >>= fun a => my >>= fun b => f a b) =
        (my >>= fun b => mx >>= fun a => f a b) := by
    intro α β γ mx my f
    ext x
    exact probOutput_bind_bind_swap mx my (fun a b => f a b) x
  have hite_false : (false : Bool) = true ↔ False := ⟨Bool.noConfusion, False.elim⟩
  have hite_true : (true : Bool) = true ↔ True := ⟨fun _ => trivial, fun _ => rfl⟩
  -- Fairness of the runtime coin: it is a uniform `Bool` sample observed via `𝒟`.
  have hcoin : Pr[= true | 𝒟[uniformSample Bool]] = 1 / 2 ∧
      Pr[= false | 𝒟[uniformSample Bool]] = 1 / 2 := by
    constructor
    · rw [show Pr[= true | 𝒟[uniformSample Bool]] =
          Pr[= true | uniformSample Bool] from rfl, probOutput_uniformSample,
        show (Fintype.card Bool : ENNReal) = 2 from by exact_mod_cast Fintype.card_bool]
      norm_num
    · rw [show Pr[= false | 𝒟[uniformSample Bool]] =
          Pr[= false | uniformSample Bool] from rfl, probOutput_uniformSample,
        show (Fintype.card Bool : ENNReal) = 2 from by exact_mod_cast Fintype.card_bool]
      norm_num
  -- The hidden-bit decomposition, packaged for arbitrary branch SPMFs.
  have coin_branch : ∀ X Y : SPMF Bool, Pr[= true | X] + Pr[= false | X] = 1 →
      Pr[= true | Y] + Pr[= false | Y] = 1 →
      (𝒟[uniformSample Bool] >>= fun b =>
          (if b then X else Y) >>= fun z => pure (b == z)).boolBiasAdvantage =
        SPMF.boolDistAdvantage X Y := fun X Y hX hY =>
    SPMF.boolBiasAdvantage_eq_boolDistAdvantage_coin_branch (𝒟[uniformSample Bool]) X Y
      hcoin.1 hcoin.2 hX hY
  -- Stage 1: the hidden-bit ANO-CCA game of the lift is the fair-coin branch
  -- over the two fixed branches, with the coin drawn first. Both sides of each
  -- branch are the same computation, because the game's adversary is exactly
  -- the lift `adv.toANO_CCA` whose phases the branch experiments re-run.
  have hgame : ANO_CCA_Game kem runtime adv.toANO_CCA =
      𝒟[uniformSample Bool] >>= fun b =>
        (if b then ANO_CCA_Branch kem runtime adv.toANO_CCA true
              else ANO_CCA_Branch kem runtime adv.toANO_CCA false) >>=
          fun z => pure (b == z) := by
    simp only [ANO_CCA_Game, ANO_CCA_Branch, ANO_Adversary.toANO_CCA,
      heval_bind, heval_pure, heval_liftProbComp]
    simp_rw [bind_swap (my := 𝒟[uniformSample Bool])]
    congr 1
    funext b
    cases b
    · simp only [hite_false, ite_false, bind_assoc]
    · simp only [ite_true, bind_assoc]
  -- Stage 2: the bias of the hidden-bit game is the distinguishing advantage
  -- between the branches; totality of each branch is `hnf` at the branch
  -- experiment (`ANO_CCA_Branch … b` is `runtime.evalDist` of an
  -- `OracleComp spec Bool` computation).
  have h_cca : ANO_CCA_Advantage kem runtime adv.toANO_CCA =
      SPMF.boolDistAdvantage (ANO_CCA_Branch kem runtime adv.toANO_CCA true)
        (ANO_CCA_Branch kem runtime adv.toANO_CCA false) := by
    have htotT : Pr[= true | ANO_CCA_Branch kem runtime adv.toANO_CCA true] +
        Pr[= false | ANO_CCA_Branch kem runtime adv.toANO_CCA true] = 1 :=
      hnf _
    have htotF : Pr[= true | ANO_CCA_Branch kem runtime adv.toANO_CCA false] +
        Pr[= false | ANO_CCA_Branch kem runtime adv.toANO_CCA false] = 1 :=
      hnf _
    change (ANO_CCA_Game kem runtime adv.toANO_CCA).boolBiasAdvantage = _
    rw [hgame, coin_branch _ _ htotT htotF]
  -- Stage 3: branch-wise SPR bounds via the triangle inequality. The `true`
  -- SPR term is definitionally the `true`-branch-to-simulator advantage; the
  -- `false` SPR term is the same advantage read on the other argument order.
  have htriT : SPMF.boolDistAdvantage
      (ANO_CCA_Branch kem runtime adv.toANO_CCA true)
      (ANO_CCA_Branch kem runtime adv.toANO_CCA false) ≤
      ANO_SPR_Term kem runtime adv.toANO_CCA sim true +
      ANO_SPR_Term kem runtime adv.toANO_CCA sim false := by
    have h := SPMF.boolDistAdvantage_triangle (ANO_CCA_Branch kem runtime
      adv.toANO_CCA true) (ANO_CCA_SimBranch kem runtime adv.toANO_CCA sim)
      (ANO_CCA_Branch kem runtime adv.toANO_CCA false)
    rw [show SPMF.boolDistAdvantage (ANO_CCA_Branch kem runtime adv.toANO_CCA true)
        (ANO_CCA_SimBranch kem runtime adv.toANO_CCA sim) =
      ANO_SPR_Term kem runtime adv.toANO_CCA sim true from rfl] at h
    rw [show SPMF.boolDistAdvantage (ANO_CCA_SimBranch kem runtime adv.toANO_CCA sim)
        (ANO_CCA_Branch kem runtime adv.toANO_CCA false) =
      ANO_SPR_Term kem runtime adv.toANO_CCA sim false from by
      unfold ANO_SPR_Term
      exact abs_sub_comm _ _] at h
    exact h
  calc ANO_CCA_Advantage kem runtime adv.toANO_CCA
      = SPMF.boolDistAdvantage (ANO_CCA_Branch kem runtime adv.toANO_CCA true)
          (ANO_CCA_Branch kem runtime adv.toANO_CCA false) := h_cca
    _ ≤ ANO_SPR_Term kem runtime adv.toANO_CCA sim true +
        ANO_SPR_Term kem runtime adv.toANO_CCA sim false := htriT
    _ ≤ sprTrue + sprFalse := add_le_add hT hF

/-- **The ANO-CCA SPR bound for the FULL CCA adversary** — the
decomposition and the branch-wise SPR triangle are generic in the adversary:
the lift-specific step in the earlier theorem (`toANO_CCA`'s phases re-running)
was never needed for the coin-branch rewrite — the game's own phases are what
the branch experiments re-run, for *any* adversary. Hence a decap-*querying*
adversary's ANO-CCA advantage is bounded by the same two per-branch SPR terms:
distinguishing honest encapsulation under key `b` from the key-independent
simulator `sim`, in the full CCA context with live decapsulation oracles.

This is the shape Maram–Xagawa (PKC 2023, eprint 2022/1696) need on the way to
their SPR-CCA ⇒ ANO-CCA corollary: what remains to close the deployed-adversary
claim is bounding the SPR terms themselves for ML-KEM-768 — the seeded-MLWE
chain of `SPRTwoHop` plus the ROM/PRF and collision terms their Theorem 2
names. Same runtime-coherence hypotheses as the lifted variant; proved with
the identical tactic structure (verified against the paper text, see
Maram–Xagawa, eprint 2022/1696). -/
theorem ANO_CCA_Advantage_le_of_spr_full {ι : Type} {spec : OracleSpec ι}
    [IsUniformSpec spec]
    {K PK SK C : Type} [DecidableEq C]
    (kem : KEMScheme (OracleComp spec) K PK SK C)
    (runtime : ProbCompRuntime (OracleComp spec))
    (adv : ANO_CCA_Adversary spec PK C K)
    (sim : ProbComp C)
    (heval_pure : ∀ {α : Type} (a : α),
      runtime.evalDist (pure a : OracleComp spec α) = pure a)
    (heval_bind : ∀ {α β : Type} (mx : OracleComp spec α)
      (f : α → OracleComp spec β),
      runtime.evalDist (mx >>= f) =
        runtime.evalDist mx >>= fun a => runtime.evalDist (f a))
    (heval_liftProbComp : ∀ {α : Type} (pc : ProbComp α),
      runtime.evalDist (runtime.liftProbComp pc) = 𝒟[pc])
    (hnf : ∀ (mx : OracleComp spec Bool),
      Pr[= true | runtime.evalDist mx] + Pr[= false | runtime.evalDist mx] = 1)
    {sprTrue sprFalse : ℝ}
    (hT : ANO_SPR_Term kem runtime adv sim true ≤ sprTrue)
    (hF : ANO_SPR_Term kem runtime adv sim false ≤ sprFalse) :
    ANO_CCA_Advantage kem runtime adv ≤ sprTrue + sprFalse := by
  have bind_swap : ∀ {α β γ : Type} (mx : SPMF α) (my : SPMF β)
      (f : α → β → SPMF γ),
      (mx >>= fun a => my >>= fun b => f a b) =
        (my >>= fun b => mx >>= fun a => f a b) := by
    intro α β γ mx my f
    ext x
    exact probOutput_bind_bind_swap mx my (fun a b => f a b) x
  have hcoin : Pr[= true | 𝒟[uniformSample Bool]] = 1 / 2 ∧
      Pr[= false | 𝒟[uniformSample Bool]] = 1 / 2 := by
    constructor
    · rw [show Pr[= true | 𝒟[uniformSample Bool]] =
          Pr[= true | uniformSample Bool] from rfl, probOutput_uniformSample,
        show (Fintype.card Bool : ENNReal) = 2 from by exact_mod_cast Fintype.card_bool]
      norm_num
    · rw [show Pr[= false | 𝒟[uniformSample Bool]] =
          Pr[= false | uniformSample Bool] from rfl, probOutput_uniformSample,
        show (Fintype.card Bool : ENNReal) = 2 from by exact_mod_cast Fintype.card_bool]
      norm_num
  have coin_branch : ∀ X Y : SPMF Bool, Pr[= true | X] + Pr[= false | X] = 1 →
      Pr[= true | Y] + Pr[= false | Y] = 1 →
      (𝒟[uniformSample Bool] >>= fun b =>
          (if b then X else Y) >>= fun z => pure (b == z)).boolBiasAdvantage =
        SPMF.boolDistAdvantage X Y := fun X Y hX hY =>
    SPMF.boolBiasAdvantage_eq_boolDistAdvantage_coin_branch (𝒟[uniformSample Bool]) X Y
      hcoin.1 hcoin.2 hX hY
  have hgame : ANO_CCA_Game kem runtime adv =
      𝒟[uniformSample Bool] >>= fun b =>
        (if b then ANO_CCA_Branch kem runtime adv true
              else ANO_CCA_Branch kem runtime adv false) >>=
          fun z => pure (b == z) := by
    have hite_false : (false : Bool) = true ↔ False := ⟨Bool.noConfusion, False.elim⟩
    simp only [ANO_CCA_Game, ANO_CCA_Branch, heval_bind, heval_pure,
      heval_liftProbComp]
    simp_rw [bind_swap (my := 𝒟[uniformSample Bool])]
    congr 1
    funext b
    cases b
    · simp only [hite_false, ite_false, bind_assoc]
    · simp only [ite_true, bind_assoc]
  have h_cca : ANO_CCA_Advantage kem runtime adv =
      SPMF.boolDistAdvantage (ANO_CCA_Branch kem runtime adv true)
        (ANO_CCA_Branch kem runtime adv false) := by
    have htotT : Pr[= true | ANO_CCA_Branch kem runtime adv true] +
        Pr[= false | ANO_CCA_Branch kem runtime adv true] = 1 :=
      hnf _
    have htotF : Pr[= true | ANO_CCA_Branch kem runtime adv false] +
        Pr[= false | ANO_CCA_Branch kem runtime adv false] = 1 :=
      hnf _
    change (ANO_CCA_Game kem runtime adv).boolBiasAdvantage = _
    rw [hgame, coin_branch _ _ htotT htotF]
  have htriT : SPMF.boolDistAdvantage
      (ANO_CCA_Branch kem runtime adv true)
      (ANO_CCA_Branch kem runtime adv false) ≤
      ANO_SPR_Term kem runtime adv sim true +
      ANO_SPR_Term kem runtime adv sim false := by
    have h := SPMF.boolDistAdvantage_triangle (ANO_CCA_Branch kem runtime adv true)
      (ANO_CCA_SimBranch kem runtime adv sim)
      (ANO_CCA_Branch kem runtime adv false)
    rw [show SPMF.boolDistAdvantage (ANO_CCA_Branch kem runtime adv true)
        (ANO_CCA_SimBranch kem runtime adv sim) =
      ANO_SPR_Term kem runtime adv sim true from rfl] at h
    rw [show SPMF.boolDistAdvantage (ANO_CCA_SimBranch kem runtime adv sim)
        (ANO_CCA_Branch kem runtime adv false) =
      ANO_SPR_Term kem runtime adv sim false from by
      unfold ANO_SPR_Term
      exact abs_sub_comm _ _] at h
    exact h
  calc ANO_CCA_Advantage kem runtime adv
      = SPMF.boolDistAdvantage (ANO_CCA_Branch kem runtime adv true)
          (ANO_CCA_Branch kem runtime adv false) := h_cca
    _ ≤ ANO_SPR_Term kem runtime adv sim true +
        ANO_SPR_Term kem runtime adv sim false := htriT
    _ ≤ sprTrue + sprFalse := add_le_add hT hF

end OracleGames

end KEM

/-! ## The KEM-based stealth scheme and the reduction -/

variable {PK SK C K : Type}

/-- Stealth scheme from a KEM: announcement = ciphertext, detection = "did
decapsulation succeed". A teaching model, not the scheme -- on an
implicit-rejection KEM its `scan` is the constant `true`. -/
def StealthScheme.ofKEM (kem : KEM PK SK C K) : StealthScheme PK SK C where
  keygen := kem.keygen
  announce pk := do
    let (c, _) ← kem.encaps pk
    pure c
  scan sk c := do
    let k ← kem.decaps sk c
    pure k.isSome

/-- **The reduction.** Unlinkability of the KEM-based stealth scheme EQUALS the
KEM's anonymity advantage: with the announcement modelled as the ciphertext, the
two experiments are the same computation. -/
theorem unlinkAdvantage_ofKEM_eq_anonAdvantage
    (kem : KEM PK SK C K) (adv : StealthScheme.UnlinkAdv PK C) :
    (StealthScheme.ofKEM kem).unlinkAdvantage adv = kem.anonAdvantage adv := by
  unfold StealthScheme.unlinkAdvantage KEM.anonAdvantage
  congr 1
  simp only [StealthScheme.UnlinkExp, KEM.AnonExp, StealthScheme.unlinkSetup,
    KEM.anonSetup, StealthScheme.unlinkBranch, KEM.anonBranch,
    StealthScheme.ofKEM, bind_assoc, pure_bind]

/-! ## Folding in the view tag and stealth address

The announcement is `(ciphertext, auxGen sharedSecret pk)`. Unlinkability then
rests on three separate things -- shared-secret hiding, key independence of the
auxiliary data, and ciphertext anonymity -- and the bound below names each
rather than merging them. See `docs/announcement-model.md`. -/

variable {Aux : Type}

/-- Stealth scheme from a KEM with a full announcement: ciphertext plus
`auxGen sharedSecret pk`. Detection recomputes the auxiliary data from the
decapsulated secret and the recipient's OWN key, hence the `SK × PK` state. -/
def StealthScheme.ofKEMFull [DecidableEq Aux] (kem : KEM PK SK C K)
    (auxGen : K → PK → Aux) : StealthScheme PK (SK × PK) (C × Aux) where
  keygen := do
    let ks ← kem.keygen
    pure (ks.1, (ks.2, ks.1))
  announce pk := do
    let ck ← kem.encaps pk
    pure (ck.1, auxGen ck.2 pk)
  scan sk ca := do
    let k? ← kem.decaps sk.1 ca.1
    pure (k?.elim false fun k => decide (ca.2 = auxGen k sk.2))

/-- **Detection completeness.** A recipient always detects an announcement
addressed to them, given only VCVio's `KEMScheme.PerfectlyCorrect`. That
hypothesis is doing the work: `deadKEM_ofKEMFull_not_perfectlyComplete`. -/
theorem perfectlyComplete_ofKEMFull [DecidableEq K] [DecidableEq Aux]
    (kem : KEM PK SK C K) (auxGen : K → PK → Aux)
    (hkem : kem.PerfectlyCorrect ProbCompRuntime.probComp) :
    (StealthScheme.ofKEMFull kem auxGen).PerfectlyComplete := by
  have hCE : (StealthScheme.ofKEMFull kem auxGen).CorrectExp =
      (do let a ← kem.run
          pure (a.2.2.elim false fun k => decide (auxGen a.2.1.2 a.1.1 = auxGen k a.1.1))) := by
    simp only [StealthScheme.CorrectExp, StealthScheme.ofKEMFull, KEM.run,
      bind_assoc, pure_bind]
  rw [StealthScheme.PerfectlyComplete, hCE]
  refine probOutput_true_eq_one_of_imp (p := fun a => decide (a.2.2 = some a.2.1.2))
    kem.run ?_ ?_
  · intro a _ ha
    simp only [decide_eq_true_eq] at ha
    simp only [ha, Option.elim_some, decide_true]
  · rw [← kem.correctExp_eq]
    exact hkem

/-- The unlinkability prefix of the full-announcement scheme is the KEM's
anonymity prefix: both draw two keypairs and publish the public keys. -/
theorem unlinkSetup_ofKEMFull [DecidableEq Aux] (kem : KEM PK SK C K)
    (auxGen : K → PK → Aux) :
    (StealthScheme.ofKEMFull kem auxGen).unlinkSetup = kem.anonSetup := by
  simp only [StealthScheme.unlinkSetup, KEM.anonSetup, StealthScheme.ofKEMFull,
    bind_assoc, pure_bind]

variable [SampleableType K]

/-- The ciphertext-anonymity adversary induced by a full-announcement one: it
synthesizes the auxiliary data from a FRESH random shared secret and a FIXED
public key, recipient 0's. See `docs/announcement-model.md`. -/
def StealthScheme.UnlinkAdv.cipherOf
    (adv : StealthScheme.UnlinkAdv PK (C × Aux)) (auxGen : K → PK → Aux) :
    StealthScheme.UnlinkAdv PK C :=
  fun pk0 pk1 c => do
    let k' ← ($ᵗ K)
    adv pk0 pk1 (c, auxGen k' pk0)

variable (kem : KEM PK SK C K) (auxGen : K → PK → Aux)
  (adv : StealthScheme.UnlinkAdv PK (C × Aux))

/-- The intermediate game on branch `b`: same ciphertext and same public key,
but the auxiliary data is built from a fresh random shared secret. -/
def randAuxBranch (b : Bool) (a : PK × PK) : ProbComp Bool := do
  let (c, _) ← kem.encaps (if b then a.2 else a.1)
  let k' ← ($ᵗ K)
  adv a.1 a.2 (c, auxGen k' (if b then a.2 else a.1))

/-- On the `b = 0` branch the intermediate game IS the anonymity game of the
induced ciphertext adversary: `cipherOf` fixes recipient 0's key, which is the
key that branch encapsulates to anyway. -/
theorem randAuxBranch_false :
    randAuxBranch kem auxGen adv false = kem.anonBranch (adv.cipherOf auxGen) false := rfl

variable [DecidableEq Aux]

/-- Shared-secret-hiding advantage on branch `b`: real shared secret versus a
fresh random key, from the SAME public key on both sides. A KEM IND-CPA
advantage (`sharedSecretHiding_eq_indCpaAdvantage`). -/
noncomputable def sharedSecretHiding (b : Bool) : ℝ :=
  ((StealthScheme.ofKEMFull kem auxGen).unlinkSetup >>=
      (StealthScheme.ofKEMFull kem auxGen).unlinkBranch adv b).boolDistAdvantage
    ((StealthScheme.ofKEMFull kem auxGen).unlinkSetup >>=
      randAuxBranch kem auxGen adv b)

/-- **The term the shared-secret-only model was missing.** With the shared secret
already idealized, does the auxiliary data still betray WHICH public key built
it? For this scheme that is the blinding argument (`ConstructionA`). -/
noncomputable def auxKeyIndependence : ℝ :=
  ((StealthScheme.ofKEMFull kem auxGen).unlinkSetup >>=
      randAuxBranch kem auxGen adv true).boolDistAdvantage
    (kem.anonSetup >>= kem.anonBranch (adv.cipherOf auxGen) true)

/-- **The faithful reduction.** With the view tag and stealth address folded in,
unlinkability is bounded by anonymity, `auxKeyIndependence`, and one
shared-secret-hiding term per branch. Triangle inequality over `randAuxBranch`. -/
theorem unlinkAdvantage_ofKEMFull_le :
    (StealthScheme.ofKEMFull kem auxGen).unlinkAdvantage adv ≤
      sharedSecretHiding kem auxGen adv true
      + auxKeyIndependence kem auxGen adv
      + kem.anonAdvantage (adv.cipherOf auxGen)
      + sharedSecretHiding kem auxGen adv false := by
  have hQf : kem.anonSetup >>= kem.anonBranch (adv.cipherOf auxGen) false =
      (StealthScheme.ofKEMFull kem auxGen).unlinkSetup >>=
        randAuxBranch kem auxGen adv false := by
    rw [randAuxBranch_false, unlinkSetup_ofKEMFull]
  rw [StealthScheme.unlinkAdvantage_eq_branchDistAdvantage,
    KEM.anonAdvantage_eq_branchDistAdvantage]
  unfold sharedSecretHiding auxKeyIndependence
  rw [hQf, ProbComp.boolDistAdvantage_comm
    ((StealthScheme.ofKEMFull kem auxGen).unlinkSetup >>=
      (StealthScheme.ofKEMFull kem auxGen).unlinkBranch adv false)]
  set Pt := (StealthScheme.ofKEMFull kem auxGen).unlinkSetup >>=
    (StealthScheme.ofKEMFull kem auxGen).unlinkBranch adv true
  set Pf := (StealthScheme.ofKEMFull kem auxGen).unlinkSetup >>=
    (StealthScheme.ofKEMFull kem auxGen).unlinkBranch adv false
  set Mt := (StealthScheme.ofKEMFull kem auxGen).unlinkSetup >>=
    randAuxBranch kem auxGen adv true
  set Mf := (StealthScheme.ofKEMFull kem auxGen).unlinkSetup >>=
    randAuxBranch kem auxGen adv false
  set Qt := kem.anonSetup >>= kem.anonBranch (adv.cipherOf auxGen) true
  calc Pt.boolDistAdvantage Pf
      ≤ Pt.boolDistAdvantage Mt + Mt.boolDistAdvantage Pf :=
        ProbComp.boolDistAdvantage_triangle Pt Mt Pf
    _ ≤ Pt.boolDistAdvantage Mt + (Mt.boolDistAdvantage Qt + Qt.boolDistAdvantage Pf) := by
        gcongr
        exact ProbComp.boolDistAdvantage_triangle Mt Qt Pf
    _ ≤ Pt.boolDistAdvantage Mt + (Mt.boolDistAdvantage Qt
          + (Qt.boolDistAdvantage Mf + Mf.boolDistAdvantage Pf)) := by
        gcongr
        exact ProbComp.boolDistAdvantage_triangle Qt Mf Pf
    _ = Pt.boolDistAdvantage Mt + Mt.boolDistAdvantage Qt
          + Qt.boolDistAdvantage Mf + Mf.boolDistAdvantage Pf := by
        ring

end PqStealth
