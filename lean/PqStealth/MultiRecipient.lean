import PqStealth.MultiUnlink
import VCVio.OracleComp.QueryTracking.RandomOracle.DeferredSampling

/-!
# `n`-recipient unlinkability (pair guessing)

Proved: the `n`-recipient left-or-right game — `n` independently generated
meta-addresses, the adversary NAMES the challenge pair after seeing all of them
and keeps a state for the guessing stage — and the pair-guessing bound `unlinkAdvantageN ≤ ∑ over ordered pairs of
unlinkAdvantage (pairGuessAdv …) ≤ n·(n−1)·ε`, over the exchangeability lemma
`evalDist_pubKeysN_embedPair` (two slots of `n` i.i.d. key generations may be
overwritten by two independently generated ones).

Assumed: the adversary names two DISTINCT recipients — an explicit hypothesis of
the headline theorems. (`keygen`/`announce` are `ProbComp`s, so they never fail:
`probFailure_of_liftM_PMF`; no totality hypothesis is carried.) See
`docs/announcement-model.md`.
-/

open OracleComp OracleSpec

namespace PqStealth

namespace StealthScheme

variable {MetaPub MetaPriv Announcement : Type}

/-! ## `n` published meta-addresses -/

/-- The public meta-addresses of `n` independently generated recipients. -/
def pubKeysN (S : StealthScheme MetaPub MetaPriv Announcement) :
    (n : ℕ) → ProbComp (Fin n → MetaPub)
  | 0 => pure Fin.elim0
  | n + 1 => do
      let ks ← S.keygen
      let f ← S.pubKeysN n
      pure (Fin.cons ks.1 f)

/-- Overwrite the two challenge slots `j` of a vector of meta-addresses. -/
def embedPair {n : ℕ} (j : Fin n × Fin n) (f : Fin n → MetaPub) (a : MetaPub × MetaPub) :
    Fin n → MetaPub :=
  Function.update (Function.update f j.1 a.1) j.2 a.2

/-- The first slot survives the second overwrite exactly when the two named
indices are distinct. -/
theorem embedPair_fst {n : ℕ} {j : Fin n × Fin n} (hj : j.1 ≠ j.2)
    (f : Fin n → MetaPub) (a : MetaPub × MetaPub) : embedPair j f a j.1 = a.1 := by
  simp only [embedPair, Function.update_of_ne hj, Function.update_self]

/-- The second slot always holds the second challenge key. -/
theorem embedPair_snd {n : ℕ} (j : Fin n × Fin n) (f : Fin n → MetaPub)
    (a : MetaPub × MetaPub) : embedPair j f a j.2 = a.2 := by
  simp only [embedPair, Function.update_self]

variable (S : StealthScheme MetaPub MetaPriv Announcement)

/-! ## Exchangeability of the `n` independent key generations -/

/-- **Exchangeability, one slot.** Overwriting one slot of the `n` independent
meta-addresses with a freshly generated one leaves the distribution unchanged;
the displaced draw disappears because a `ProbComp` never fails. -/
theorem evalDist_pubKeysN_update {β : Type} :
    ∀ (n : ℕ) (j : Fin n) (k : (Fin n → MetaPub) → ProbComp β),
      𝒟[do let f ← S.pubKeysN n
            let x ← S.keygen
            k (Function.update f j x.1)] = 𝒟[S.pubKeysN n >>= k] := by
  intro n
  induction n with
  | zero => exact fun j => j.elim0
  | succ n ih =>
      refine Fin.cases ?_ ?_
      · intro k
        have hL : (do let f ← S.pubKeysN (n + 1)
                      let x ← S.keygen
                      k (Function.update f 0 x.1)) =
            (do let _ ← S.keygen
                let f ← S.pubKeysN n
                let x ← S.keygen
                k (Fin.cons x.1 f)) := by
          simp only [pubKeysN, bind_assoc, pure_bind, Fin.update_cons_zero]
        rw [hL, OracleComp.DeferredSampling.evalDist_bind_const_neverFails S.keygen
          (probFailure_of_liftM_PMF _)]
        simp only [pubKeysN, bind_assoc, pure_bind]
        exact evalDist_bind_bind_swap (S.pubKeysN n) S.keygen fun f x => k (Fin.cons x.1 f)
      · intro i k
        have hL : (do let f ← S.pubKeysN (n + 1)
                      let x ← S.keygen
                      k (Function.update f i.succ x.1)) =
            (do let ks ← S.keygen
                let f ← S.pubKeysN n
                let x ← S.keygen
                k (Fin.cons ks.1 (Function.update f i x.1))) := by
          simp only [pubKeysN, bind_assoc, pure_bind, Fin.cons_update]
        rw [hL]
        refine (evalDist_bind_congr' S.keygen
          fun ks : MetaPub × MetaPriv => ih i fun g => k (Fin.cons ks.1 g)).trans ?_
        simp only [pubKeysN, bind_assoc, pure_bind]

/-- **Exchangeability, the challenge pair.** The two recipients of the
two-recipient game may be spliced into any two slots of `n` independently
generated meta-addresses without changing the distribution. -/
theorem evalDist_pubKeysN_embedPair {β : Type} {n : ℕ}
    (j : Fin n × Fin n) (k : (Fin n → MetaPub) → ProbComp β) :
    𝒟[do let a ← S.unlinkSetup
          let f ← S.pubKeysN n
          k (embedPair j f a)] = 𝒟[S.pubKeysN n >>= k] := by
  have h0 : (do let a ← S.unlinkSetup
                let f ← S.pubKeysN n
                k (embedPair j f a)) =
      (do let x ← S.keygen
          let y ← S.keygen
          let f ← S.pubKeysN n
          k (Function.update (Function.update f j.1 x.1) j.2 y.1)) := by
    simp only [unlinkSetup, embedPair, bind_assoc, pure_bind]
  have h1 : 𝒟[do let x ← S.keygen
                 let y ← S.keygen
                 let f ← S.pubKeysN n
                 k (Function.update (Function.update f j.1 x.1) j.2 y.1)] =
      𝒟[do let x ← S.keygen
            let f ← S.pubKeysN n
            let y ← S.keygen
            k (Function.update (Function.update f j.1 x.1) j.2 y.1)] :=
    evalDist_bind_congr' S.keygen fun x =>
      evalDist_bind_bind_swap S.keygen (S.pubKeysN n) fun y f =>
        k (Function.update (Function.update f j.1 x.1) j.2 y.1)
  have h2 : 𝒟[do let x ← S.keygen
                 let f ← S.pubKeysN n
                 let y ← S.keygen
                 k (Function.update (Function.update f j.1 x.1) j.2 y.1)] =
      𝒟[do let f ← S.pubKeysN n
            let x ← S.keygen
            let y ← S.keygen
            k (Function.update (Function.update f j.1 x.1) j.2 y.1)] :=
    evalDist_bind_bind_swap S.keygen (S.pubKeysN n) fun x f =>
      do let y ← S.keygen
         k (Function.update (Function.update f j.1 x.1) j.2 y.1)
  have h3 : 𝒟[do let f ← S.pubKeysN n
                 let x ← S.keygen
                 let y ← S.keygen
                 k (Function.update (Function.update f j.1 x.1) j.2 y.1)] =
      𝒟[do let f ← S.pubKeysN n
            let y ← S.keygen
            k (Function.update f j.2 y.1)] :=
    S.evalDist_pubKeysN_update n j.1
      fun g => do let y ← S.keygen; k (Function.update g j.2 y.1)
  rw [h0, h1, h2, h3]
  exact S.evalDist_pubKeysN_update n j.2 k

/-! ## The `n`-recipient game -/

/-- Challenge selection: after seeing all `n` published meta-addresses the
adversary names the ordered pair of recipients it wants to distinguish, and
keeps a state `St` for the guessing stage (VCVio's two-phase adversaries carry a
`State` the same way; a stateless adversary takes `St := Unit`). -/
abbrev UnlinkChooseN (MetaPub : Type) (n : ℕ) (St : Type) :=
  (Fin n → MetaPub) → ProbComp ((Fin n × Fin n) × St)

/-- Guessing stage: the state, all `n` meta-addresses, the named pair, and the
challenge announcement, which is addressed to one of the two named recipients. -/
abbrev UnlinkGuessN (MetaPub Announcement : Type) (n : ℕ) (St : Type) :=
  St → (Fin n → MetaPub) → Fin n × Fin n → Announcement → ProbComp Bool

variable {n : ℕ} {St : Type} (pick : UnlinkChooseN MetaPub n St)
  (guess : UnlinkGuessN MetaPub Announcement n St)

/-- Branch of the `n`-recipient game selected by the hidden bit: the challenge
goes to the first or to the second of the recipients the adversary named. -/
def unlinkBranchN (b : Bool) (pks : Fin n → MetaPub) : ProbComp Bool := do
  let i ← pick pks
  let c ← S.announce (pks (if b then i.1.2 else i.1.1))
  guess i.2 pks i.1 c

/-- `n`-recipient unlinkability experiment, in the hidden-bit form the
branch-decomposition lemma consumes. -/
def UnlinkExpN : ProbComp Bool := do
  let pks ← S.pubKeysN n
  let b ← ($ᵗ Bool)
  let z ← S.unlinkBranchN pick guess b pks
  pure (b == z)

/-- `n`-recipient unlinkability advantage. -/
noncomputable def unlinkAdvantageN : ℝ := (S.UnlinkExpN pick guess).boolBiasAdvantage

/-- The `n`-recipient advantage is the advantage of distinguishing an
announcement to the second named recipient from one to the first. -/
theorem unlinkAdvantageN_eq_branchDistAdvantage :
    S.unlinkAdvantageN pick guess =
      (S.pubKeysN n >>= S.unlinkBranchN pick guess true).boolDistAdvantage
        (S.pubKeysN n >>= S.unlinkBranchN pick guess false) :=
  ProbComp.boolBiasAdvantage_bind_uniformBool_branch (S.pubKeysN n)
    (S.unlinkBranchN pick guess)

/-! ## The pair-guessing reduction -/

/-- The `n`-recipient branch gated on the ordered pair `j`: the adversary's
verdict counts only when it named exactly `j`. -/
def unlinkBranchNAt (j : Fin n × Fin n) (b : Bool) (pks : Fin n → MetaPub) : ProbComp Bool := do
  let i ← pick pks
  let c ← S.announce (pks (if b then i.1.2 else i.1.1))
  if i.1 = j then guess i.2 pks i.1 c else pure false

/-- **The reduction.** Guessing the pair `j`, a two-recipient adversary splices
the two challenge meta-addresses into slots `j`, generates the other `n − 2`
itself, and forwards the verdict only when the adversary names `j`. -/
def pairGuessAdv (j : Fin n × Fin n) : UnlinkAdv MetaPub Announcement :=
  fun pk0 pk1 c => do
    let f ← S.pubKeysN n
    let i ← pick (embedPair j f (pk0, pk1))
    if i.1 = j then guess i.2 (embedPair j f (pk0, pk1)) i.1 c else pure false

/-- **Conditioned on a correct guess the games coincide.** The reduction's
two-recipient branch has exactly the distribution of the gated `n`-recipient
branch; on a wrong guess both discard the challenge announcement. -/
theorem evalDist_unlinkBranch_pairGuessAdv
    {j : Fin n × Fin n} (hj : j.1 ≠ j.2) (b : Bool) :
    𝒟[S.unlinkSetup >>= S.unlinkBranch (S.pairGuessAdv pick guess j) b] =
      𝒟[S.pubKeysN n >>= S.unlinkBranchNAt pick guess j b] := by
  have hL : (S.unlinkSetup >>= S.unlinkBranch (S.pairGuessAdv pick guess j) b) =
      (do let a ← S.unlinkSetup
          let c ← S.announce (if b then a.2 else a.1)
          let f ← S.pubKeysN n
          let i ← pick (embedPair j f a)
          if i.1 = j then guess i.2 (embedPair j f a) i.1 c else pure false) := rfl
  have hswap : 𝒟[do let a ← S.unlinkSetup
                    let c ← S.announce (if b then a.2 else a.1)
                    let f ← S.pubKeysN n
                    let i ← pick (embedPair j f a)
                    if i.1 = j then guess i.2 (embedPair j f a) i.1 c else pure false] =
      𝒟[do let a ← S.unlinkSetup
            let f ← S.pubKeysN n
            let c ← S.announce (if b then a.2 else a.1)
            let i ← pick (embedPair j f a)
            if i.1 = j then guess i.2 (embedPair j f a) i.1 c else pure false] :=
    evalDist_bind_congr' S.unlinkSetup fun a =>
      evalDist_bind_bind_swap (S.announce (if b then a.2 else a.1)) (S.pubKeysN n)
        fun c f => do
          let i ← pick (embedPair j f a)
          if i.1 = j then guess i.2 (embedPair j f a) i.1 c else pure false
  have hstep : 𝒟[do let a ← S.unlinkSetup
                    let f ← S.pubKeysN n
                    let c ← S.announce (if b then a.2 else a.1)
                    let i ← pick (embedPair j f a)
                    if i.1 = j then guess i.2 (embedPair j f a) i.1 c else pure false] =
      𝒟[S.pubKeysN n >>= fun pks => do
            let c ← S.announce (pks (if b then j.2 else j.1))
            let i ← pick pks
            if i.1 = j then guess i.2 pks i.1 c else pure false] := by
    refine Eq.trans (congrArg _ (bind_congr fun a => bind_congr fun f => ?_))
      (S.evalDist_pubKeysN_embedPair j fun pks => do
        let c ← S.announce (pks (if b then j.2 else j.1))
        let i ← pick pks
        if i.1 = j then guess i.2 pks i.1 c else pure false)
    cases b with
    | false => simp only [Bool.false_eq_true, if_false, embedPair_fst hj]
    | true => simp only [if_true, embedPair_snd]
  rw [hL, hswap, hstep]
  refine evalDist_bind_congr' (S.pubKeysN n) fun pks => ?_
  rw [evalDist_bind_bind_swap (S.announce (pks (if b then j.2 else j.1))) (pick pks)
    fun c i => if i.1 = j then guess i.2 pks i.1 c else pure false]
  simp only [unlinkBranchNAt]
  refine evalDist_bind_congr' (pick pks) fun i => ?_
  by_cases hij : i.1 = j
  · subst hij
    rfl
  · simp only [if_neg hij]
    rw [OracleComp.DeferredSampling.evalDist_bind_const_neverFails _
        (probFailure_of_liftM_PMF _) (pure false),
      OracleComp.DeferredSampling.evalDist_bind_const_neverFails _
        (probFailure_of_liftM_PMF _) (pure false)]

/-! ## Summing the gated games -/

/-- The gated branches partition the `n`-recipient branch: summed over ordered
pairs of DISTINCT indices they recover it exactly. -/
theorem sum_probOutput_unlinkBranchNAt
    (hpick : ∀ (pks : Fin n → MetaPub), ∀ i ∈ support (pick pks), i.1.1 ≠ i.1.2) (b : Bool) :
    ∑ j ∈ Finset.univ.offDiag,
        Pr[= true | S.pubKeysN n >>= S.unlinkBranchNAt pick guess j b] =
      Pr[= true | S.pubKeysN n >>= S.unlinkBranchN pick guess b] := by
  have hinner : ∀ pks : Fin n → MetaPub,
      ∑ j ∈ Finset.univ.offDiag, Pr[= true | S.unlinkBranchNAt pick guess j b pks] =
        Pr[= true | S.unlinkBranchN pick guess b pks] := by
    intro pks
    simp only [unlinkBranchNAt, unlinkBranchN, probOutput_bind_eq_tsum]
    rw [← Summable.tsum_finsetSum fun _ _ => ENNReal.summable]
    refine tsum_congr fun i => ?_
    rw [← Finset.mul_sum]
    by_cases hi : i.1.1 = i.1.2
    · have hzero : Pr[= i | pick pks] = 0 :=
        probOutput_eq_zero_of_not_mem_support fun hmem => hpick pks i hmem hi
      simp only [hzero, zero_mul]
    · have hmem : i.1 ∈ (Finset.univ.offDiag : Finset (Fin n × Fin n)) := by
        simp only [Finset.mem_offDiag, Finset.mem_univ, true_and]
        exact hi
      congr 1
      refine Finset.sum_eq_single_of_mem i.1 hmem ?_ |>.trans ?_
      · intro j _ hji
        simp only [if_neg (Ne.symm hji), probOutput_pure, Bool.true_eq_false, ↓reduceIte,
          mul_zero, tsum_zero]
      · exact tsum_congr fun x => by rw [if_pos rfl]
  simp only [probOutput_bind_eq_tsum]
  rw [← Summable.tsum_finsetSum fun _ _ => ENNReal.summable]
  exact tsum_congr fun pks => by rw [← Finset.mul_sum, hinner pks]

/-! ## The bound -/

/-- **`n`-recipient unlinkability, honest form.** The advantage is at most the
sum, over ordered pairs of distinct recipients, of the two-recipient advantage
of the reduction that guesses that pair. -/
theorem unlinkAdvantageN_le_sum
    (hpick : ∀ (pks : Fin n → MetaPub), ∀ i ∈ support (pick pks), i.1.1 ≠ i.1.2) :
    S.unlinkAdvantageN pick guess ≤
      ∑ j ∈ Finset.univ.offDiag, S.unlinkAdvantage (S.pairGuessAdv pick guess j) := by
  have hterm : ∀ j ∈ (Finset.univ.offDiag : Finset (Fin n × Fin n)),
      S.unlinkAdvantage (S.pairGuessAdv pick guess j) =
        |(Pr[= true | S.pubKeysN n >>= S.unlinkBranchNAt pick guess j true]).toReal
          - (Pr[= true | S.pubKeysN n >>= S.unlinkBranchNAt pick guess j false]).toReal| := by
    intro j hj
    rw [Finset.mem_offDiag] at hj
    rw [S.unlinkAdvantage_eq_branchDistAdvantage, ProbComp.boolDistAdvantage,
      probOutput_congr rfl (S.evalDist_unlinkBranch_pairGuessAdv pick guess hj.2.2 true),
      probOutput_congr rfl (S.evalDist_unlinkBranch_pairGuessAdv pick guess hj.2.2 false)]
  have hsum : ∀ b : Bool,
      (Pr[= true | S.pubKeysN n >>= S.unlinkBranchN pick guess b]).toReal =
        ∑ j ∈ Finset.univ.offDiag,
          (Pr[= true | S.pubKeysN n >>= S.unlinkBranchNAt pick guess j b]).toReal := by
    intro b
    rw [← S.sum_probOutput_unlinkBranchNAt pick guess hpick b,
      ENNReal.toReal_sum fun j _ => probOutput_ne_top]
  rw [S.unlinkAdvantageN_eq_branchDistAdvantage, ProbComp.boolDistAdvantage,
    hsum true, hsum false, ← Finset.sum_sub_distrib, Finset.sum_congr rfl hterm]
  exact Finset.abs_sum_le_sum_abs _ _

/-- **`n`-recipient unlinkability, `n·(n−1)` loss.** If every pair-guessing
reduction has two-recipient advantage at most `ε`, the `n`-recipient advantage
is at most `n·(n−1)·ε`. -/
theorem unlinkAdvantageN_le_mul
    (hpick : ∀ (pks : Fin n → MetaPub), ∀ i ∈ support (pick pks), i.1.1 ≠ i.1.2) {ε : ℝ}
    (h : ∀ j : Fin n × Fin n, S.unlinkAdvantage (S.pairGuessAdv pick guess j) ≤ ε) :
    S.unlinkAdvantageN pick guess ≤ (n * (n - 1) : ℕ) * ε := by
  refine le_trans (S.unlinkAdvantageN_le_sum pick guess hpick) ?_
  have hcard : (Finset.univ.offDiag : Finset (Fin n × Fin n)).card = n * (n - 1) := by
    rw [Finset.offDiag_card, Finset.card_univ, Fintype.card_fin]
    cases n with
    | zero => rfl
    | succ m => simp only [Nat.add_sub_cancel, Nat.mul_succ, Nat.succ_sub_one]
  calc ∑ j ∈ Finset.univ.offDiag, S.unlinkAdvantage (S.pairGuessAdv pick guess j)
      ≤ ∑ _j ∈ (Finset.univ.offDiag : Finset (Fin n × Fin n)), ε :=
        Finset.sum_le_sum fun j _ => h j
    _ = (n * (n - 1) : ℕ) * ε := by
        rw [Finset.sum_const, hcard, nsmul_eq_mul]

end StealthScheme

end PqStealth
