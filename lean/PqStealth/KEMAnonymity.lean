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

Assumed: nothing here. `anonymity → MLWE` for ML-KEM is the open piece
(`AnonymityFromSPR`). See `docs/announcement-model.md`.
-/

open OracleComp OracleSpec

namespace PqStealth

/-! ## An abstract KEM

`abbrev` rather than `def` so dot notation reaches both this namespace and
`KEMScheme`; correctness and KEM IND-CPA are therefore VCVio's own. -/

/-- A key encapsulation mechanism over `ProbComp`: key generation, encapsulation
(producing a ciphertext and a shared secret), and decapsulation. -/
abbrev KEM (PK SK C K : Type) := KEMScheme ProbComp K PK SK C

/-! ## A `Pr[= true | …] = 1` transfer lemma -/

/-- Transfer a probability-one Boolean verdict along a pointwise implication.
Used to derive detection completeness from the strictly stronger verdict of KEM
correctness. -/
theorem probOutput_true_eq_one_of_imp {α : Type} (oa : ProbComp α) {p q : α → Bool}
    (h : ∀ a ∈ support oa, p a = true → q a = true)
    (hp : Pr[= true | (do let a ← oa; pure (p a))] = 1) :
    Pr[= true | (do let a ← oa; pure (q a))] = 1 := by
  rw [probOutput_eq_one_iff_forall] at hp ⊢
  obtain ⟨hfail, hall⟩ := hp
  simp only [probFailure_bind_eq_zero_iff, probFailure_pure, implies_true,
    and_true] at hfail ⊢
  refine ⟨hfail, ?_⟩
  intro y hy
  simp only [support_bind, support_pure, Set.mem_iUnion, Set.mem_singleton_iff] at hy
  obtain ⟨a, ha, rfl⟩ := hy
  refine h a ha (hall (p a) ?_)
  simp only [support_bind, support_pure, Set.mem_iUnion, Set.mem_singleton_iff]
  exact ⟨a, ha, rfl⟩

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
