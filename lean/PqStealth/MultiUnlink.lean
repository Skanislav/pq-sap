import PqStealth.Games

/-!
# Multi-challenge unlinkability (hybrid argument)

Proved: the `q`-challenge left-or-right unlinkability game against two
recipients (`UnlinkExpMulti`), and the hybrid bound `unlinkAdvantageMulti ≤
∑ k ∈ range q, unlinkAdvantage (hybridAdv …)` with the corollary `≤ q * ε`,
over a general telescoping lemma `boolDistAdvantage_le_sum_hybrids`. By design
hybrid `k` IS the single-challenge game of the derived adversary up to ONE swap
of independent draws, so each hop is an `evalDist` equality
(`evalDist_announceList_append_cons`) rather than a re-derivation.

Assumed: nothing. The `n`-recipient game (the adversary picks the challenge
pair among `n` published meta-addresses, loss `n·(n−1)/2`) is a documented
follow-up; see `docs/announcement-model.md`.
-/

open OracleComp OracleSpec

/-! ## Telescoping a chain of hybrids -/

/-- Distinguishing advantage only sees the output distributions, so it can be
transported along `evalDist` equalities — the form every hybrid hop needs. -/
theorem ProbComp.boolDistAdvantage_congr {p p' q q' : ProbComp Bool}
    (hp : 𝒟[p] = 𝒟[p']) (hq : 𝒟[q] = 𝒟[q']) :
    p.boolDistAdvantage q = p'.boolDistAdvantage q' := by
  rw [ProbComp.boolDistAdvantage, ProbComp.boolDistAdvantage, probOutput_congr rfl hp,
    probOutput_congr rfl hq]

/-- **Telescoping.** The advantage between the ends of a chain of hybrids is at
most the sum of the advantages of the individual steps. -/
theorem ProbComp.boolDistAdvantage_le_sum_hybrids (H : ℕ → ProbComp Bool) (n : ℕ) :
    (H n).boolDistAdvantage (H 0) ≤
      ∑ k ∈ Finset.range n, (H (k + 1)).boolDistAdvantage (H k) := by
  induction n with
  | zero =>
      simp only [Finset.range_zero, Finset.sum_empty, ProbComp.boolDistAdvantage, sub_self,
        abs_zero, le_refl]
  | succ n ih =>
      rw [Finset.sum_range_succ]
      calc (H (n + 1)).boolDistAdvantage (H 0)
          ≤ (H (n + 1)).boolDistAdvantage (H n) + (H n).boolDistAdvantage (H 0) :=
            ProbComp.boolDistAdvantage_triangle _ _ _
        _ ≤ (H (n + 1)).boolDistAdvantage (H n) +
              ∑ k ∈ Finset.range n, (H (k + 1)).boolDistAdvantage (H k) :=
            by linarith [ih]
        _ = (∑ k ∈ Finset.range n, (H (k + 1)).boolDistAdvantage (H k)) +
              (H (n + 1)).boolDistAdvantage (H n) := add_comm _ _

namespace PqStealth

namespace StealthScheme

variable {MetaPub MetaPriv Announcement : Type}

/-! ## A list of announcements, one per listed recipient

The hybrids differ only in the recipient of one announcement, so the sampler is
indexed by the *list of recipients* rather than by a count. -/

/-- One independent announcement per public meta-address in the list, in order. -/
def announceList (S : StealthScheme MetaPub MetaPriv Announcement) :
    List MetaPub → ProbComp (List Announcement)
  | [] => pure []
  | pk :: pks => do
      let c ← S.announce pk
      let cs ← S.announceList pks
      pure (c :: cs)

variable (S : StealthScheme MetaPub MetaPriv Announcement)

/-- The adversary really does receive one announcement per recipient: the
`List` encoding does not silently drop the count. -/
theorem length_of_mem_support_announceList (pks : List MetaPub) :
    ∀ cs ∈ support (S.announceList pks), cs.length = pks.length := by
  induction pks with
  | nil =>
      intro cs hcs
      simp only [announceList, support_pure, Set.mem_singleton_iff] at hcs
      simp only [hcs, List.length_nil]
  | cons pk pks ih =>
      intro cs hcs
      simp only [announceList, support_bind, support_pure, Set.mem_iUnion,
        Set.mem_singleton_iff] at hcs
      obtain ⟨c, _, cs', hcs', rfl⟩ := hcs
      simp only [List.length_cons, ih cs' hcs']

/-- **The hybrid hop, once and for all.** An announcement at a marked position
of the list can be pulled to the front, at the cost of one swap of independent
draws (`evalDist_bind_bind_swap` per element of the prefix). -/
theorem evalDist_announceList_append_cons {β : Type} (pk : MetaPub) (l₂ : List MetaPub) :
    ∀ (l₁ : List MetaPub) (f : List Announcement → ProbComp β),
      𝒟[S.announceList (l₁ ++ pk :: l₂) >>= f] =
        𝒟[do
            let c ← S.announce pk
            let cs₁ ← S.announceList l₁
            let cs₂ ← S.announceList l₂
            f (cs₁ ++ c :: cs₂)] := by
  intro l₁
  induction l₁ with
  | nil =>
      intro f
      simp only [List.nil_append, announceList, bind_assoc, pure_bind]
  | cons a l₁ ih =>
      intro f
      simp only [List.cons_append, announceList, bind_assoc, pure_bind]
      refine (evalDist_bind_congr' _ fun x => ih (fun cs => f (x :: cs))).trans ?_
      exact evalDist_bind_bind_swap (S.announce a) (S.announce pk) _

/-! ## The `q`-challenge left-or-right game -/

/-- Multi-challenge unlinkability adversary: both public meta-addresses and all
`q` challenge announcements, which all go to the same hidden recipient. -/
abbrev UnlinkAdvMulti (MetaPub Announcement : Type) :=
  MetaPub → MetaPub → List Announcement → ProbComp Bool

variable (advM : UnlinkAdvMulti MetaPub Announcement)

/-- Branch of the `q`-challenge game selected by the hidden bit: all `q`
announcements are addressed to recipient `b`. -/
def unlinkBranchMulti (q : ℕ) (b : Bool) (a : MetaPub × MetaPub) : ProbComp Bool := do
  let cs ← S.announceList (List.replicate q (if b then a.2 else a.1))
  advM a.1 a.2 cs

/-- `q`-challenge unlinkability experiment, in the same hidden-bit form as
`UnlinkExp` so the branch-decomposition lemma applies unchanged. -/
def UnlinkExpMulti (q : ℕ) : ProbComp Bool := do
  let a ← S.unlinkSetup
  let b ← ($ᵗ Bool)
  let z ← S.unlinkBranchMulti advM q b a
  pure (b == z)

/-- Multi-challenge unlinkability advantage. -/
noncomputable def unlinkAdvantageMulti (q : ℕ) : ℝ :=
  (S.UnlinkExpMulti advM q).boolBiasAdvantage

/-- The multi-challenge advantage is the advantage of distinguishing `q`
announcements to recipient 1 from `q` announcements to recipient 0. -/
theorem unlinkAdvantageMulti_eq_branchDistAdvantage (q : ℕ) :
    S.unlinkAdvantageMulti advM q =
      (S.unlinkSetup >>= S.unlinkBranchMulti advM q true).boolDistAdvantage
        (S.unlinkSetup >>= S.unlinkBranchMulti advM q false) :=
  ProbComp.boolBiasAdvantage_bind_uniformBool_branch S.unlinkSetup (S.unlinkBranchMulti advM q)

/-! ## The hybrids and the derived single-challenge adversaries

Indexed by the two segment lengths `(i, j)` rather than by `(q, i)`: natural
subtraction then appears only in the final telescope. -/

/-- Hybrid `(i, j)`: the first `i` announcements go to recipient 1, the last `j`
to recipient 0. `(0, q)` and `(q, 0)` are the two branches of the game. -/
def unlinkHybrid (i j : ℕ) (a : MetaPub × MetaPub) : ProbComp Bool := do
  let cs ← S.announceList (List.replicate i a.2 ++ List.replicate j a.1)
  advM a.1 a.2 cs

/-- Derived single-challenge adversary for the hop `(i, j+1) → (i+1, j)`: it
simulates `i` announcements to recipient 1 and `j` to recipient 0 itself, and
inserts the challenge between them. -/
def hybridAdv (i j : ℕ) : UnlinkAdv MetaPub Announcement := fun pk0 pk1 c => do
  let cs₁ ← S.announceList (List.replicate i pk1)
  let cs₂ ← S.announceList (List.replicate j pk0)
  advM pk0 pk1 (cs₁ ++ c :: cs₂)

/-- Left end of the chain: no announcement goes to recipient 1. -/
theorem unlinkHybrid_zero_left (q : ℕ) (a : MetaPub × MetaPub) :
    S.unlinkHybrid advM 0 q a = S.unlinkBranchMulti advM q false a := by
  simp only [unlinkHybrid, unlinkBranchMulti, List.replicate_zero, List.nil_append,
    Bool.false_eq_true, if_false]

/-- Right end of the chain: every announcement goes to recipient 1. -/
theorem unlinkHybrid_zero_right (q : ℕ) (a : MetaPub × MetaPub) :
    S.unlinkHybrid advM q 0 a = S.unlinkBranchMulti advM q true a := by
  simp only [unlinkHybrid, unlinkBranchMulti, List.replicate_zero, List.append_nil, if_true]

/-- **One hybrid step.** The derived adversary's single-challenge branch `b` has
exactly the distribution of the hybrid it is meant to be: the announcement it
receives lands at the one position where the two hybrids differ. -/
theorem evalDist_unlinkBranch_hybridAdv (i j : ℕ) (b : Bool) (a : MetaPub × MetaPub) :
    𝒟[S.unlinkBranch (S.hybridAdv advM i j) b a] =
      𝒟[S.unlinkHybrid advM (if b then i + 1 else i) (if b then j else j + 1) a] := by
  cases b with
  | false =>
      have hlist : List.replicate i a.2 ++ List.replicate (j + 1) a.1 =
          List.replicate i a.2 ++ a.1 :: List.replicate j a.1 := by
        simp only [List.replicate_succ]
      simp only [unlinkBranch, unlinkHybrid, hybridAdv, hlist, Bool.false_eq_true, if_false]
      exact (S.evalDist_announceList_append_cons a.1 (List.replicate j a.1)
        (List.replicate i a.2) (advM a.1 a.2)).symm
  | true =>
      have hlist : List.replicate (i + 1) a.2 ++ List.replicate j a.1 =
          List.replicate i a.2 ++ a.2 :: List.replicate j a.1 := by
        simp only [List.replicate_succ', List.append_assoc, List.singleton_append]
      simp only [unlinkBranch, unlinkHybrid, hybridAdv, hlist, if_true]
      exact (S.evalDist_announceList_append_cons a.2 (List.replicate j a.1)
        (List.replicate i a.2) (advM a.1 a.2)).symm

/-- The derived adversary's unlinkability advantage IS the advantage between the
two hybrids it separates. -/
theorem unlinkAdvantage_hybridAdv_eq (i j : ℕ) :
    S.unlinkAdvantage (S.hybridAdv advM i j) =
      (S.unlinkSetup >>= S.unlinkHybrid advM (i + 1) j).boolDistAdvantage
        (S.unlinkSetup >>= S.unlinkHybrid advM i (j + 1)) := by
  rw [S.unlinkAdvantage_eq_branchDistAdvantage]
  exact ProbComp.boolDistAdvantage_congr
    (evalDist_bind_congr' _ fun a => S.evalDist_unlinkBranch_hybridAdv advM i j true a)
    (evalDist_bind_congr' _ fun a => S.evalDist_unlinkBranch_hybridAdv advM i j false a)

/-! ## The hybrid bound -/

/-- **Multi-challenge unlinkability, honest form.** The `q`-challenge advantage
is at most the sum of the `q` single-challenge advantages of the derived
adversaries. -/
theorem unlinkAdvantageMulti_le_sum (q : ℕ) :
    S.unlinkAdvantageMulti advM q ≤
      ∑ k ∈ Finset.range q, S.unlinkAdvantage (S.hybridAdv advM k (q - k - 1)) := by
  set H : ℕ → ProbComp Bool := fun k => S.unlinkSetup >>= S.unlinkHybrid advM k (q - k) with hH
  have hend : S.unlinkAdvantageMulti advM q = (H q).boolDistAdvantage (H 0) := by
    rw [S.unlinkAdvantageMulti_eq_branchDistAdvantage advM q]
    simp only [hH, Nat.sub_self, Nat.sub_zero]
    exact ProbComp.boolDistAdvantage_congr
      (evalDist_bind_congr' _ fun a => by rw [S.unlinkHybrid_zero_right advM q a])
      (evalDist_bind_congr' _ fun a => by rw [S.unlinkHybrid_zero_left advM q a])
  have hstep : ∀ k ∈ Finset.range q,
      (H (k + 1)).boolDistAdvantage (H k) =
        S.unlinkAdvantage (S.hybridAdv advM k (q - k - 1)) := by
    intro k hk
    rw [Finset.mem_range] at hk
    have key := S.unlinkAdvantage_hybridAdv_eq advM k (q - k - 1)
    have h1 : q - (k + 1) = q - k - 1 := by omega
    have h2 : q - k - 1 + 1 = q - k := by omega
    simp only [hH]
    rw [key, h1, h2]
  rw [hend]
  refine le_trans (ProbComp.boolDistAdvantage_le_sum_hybrids H q) ?_
  exact le_of_eq (Finset.sum_congr rfl hstep)

/-- **Multi-challenge unlinkability, `q`-fold loss.** If every derived
single-challenge adversary has advantage at most `ε`, the `q`-challenge
advantage is at most `q * ε`. -/
theorem unlinkAdvantageMulti_le_mul (q : ℕ) {ε : ℝ}
    (h : ∀ i j, S.unlinkAdvantage (S.hybridAdv advM i j) ≤ ε) :
    S.unlinkAdvantageMulti advM q ≤ q * ε := by
  refine le_trans (S.unlinkAdvantageMulti_le_sum advM q) ?_
  calc ∑ k ∈ Finset.range q, S.unlinkAdvantage (S.hybridAdv advM k (q - k - 1))
      ≤ ∑ _k ∈ Finset.range q, ε := Finset.sum_le_sum fun k _ => h k (q - k - 1)
    _ = q * ε := by rw [Finset.sum_const, Finset.card_range, nsmul_eq_mul]

end StealthScheme

end PqStealth
