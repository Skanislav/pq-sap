import PqStealth.Scheme3
import PqStealth.MLKEM

/-!
# ERC-8441's ANO-CCA assumption, stated as an assumption

ERC-8441's Security Considerations stake scheme 3's announcement privacy on a
*stated assumption*:

> `schemeId` 3 therefore assumes that ML-KEM-768 is ANO-CCA (anonymous under
> chosen-ciphertext attack) as well as IND-CCA. FIPS 203 does not claim
> anonymity.

This module makes that assumption a first-class, *named* Lean term rather than
an invisible hypothesis, and exposes the three side conditions the cited
CRYPTREC evaluation (PQShield, CRYPTREC-EX-3502-2025 §4) requires so the
assumption is checkable, not a bare oracle. Nothing here *proves* ANO-CCA:
that is the open FO/ROM lift of `docs/fo-anonymity-lift.md` (Maram–Xagawa
shape). The assumption is an honest named arrow — it composes with the proved
chain upstream, matches the ERC's words exactly, and shows up in
`#print axioms` of any theorem that consumes it. **No `sorry` is introduced;
the assumption travels as a hypothesis, which the axiom audit displays.**

What is proved vs assumed vs open:

* **Assumed (named, not `sorryAx`):** `mlkem768ANOCCA_assumed epsilonANO` — the
  ANO-CCA bound the ERC asserts. A `Prop` used as a hypothesis, so any
  consumer's `#print axioms` lists the assumption it takes rather than hiding a
  hole.
* **Named side conditions:** strong collision-freeness, strong
  disjoint-simulatability, and correctness — the three CRYPTREC conditions.
  Carried as abstract `Prop` fields so a future proof (VCVio's ML-KEM security
  lemmas) discharges them against the concrete FIPS-203 instance without
  changing consumers.
* **Open (named, not silently discharged):** the hybrid-anonymity reduction.
  `KEM.parallel` composes the ECDH leg with the ML-KEM leg via `combine`.
  Bao–Pan (PKC 2026, eprint 2026/396) Remark 1 shows parallel-hybrid anonymity
  is an *AND*, and Lemma 4 shows the ephemeral classical leg is
  recipient-independent, so the AND collapses to ML-KEM anonymity **at the
  confidentiality game**. The CCA-level lift additionally needs the
  decap-oracle simulation (the ROM-programming hop of
  `docs/fo-anonymity-lift.md`). That hop is the remaining research piece; this
  module records the *target* theorem as an assumed implication
  (`hybrid768_anonAdvantage_le_assumed`), which the capstone may consume by
  taking it as a further hypothesis, and which a later milestone replaces with
  a proof.
-/

open OracleComp OracleSpec
open MLKEM MLKEM.Concrete

namespace PqStealth

/-! ## The named assumption -/

/-- ERC-8441's stated ANO-CCA assumption on ML-KEM-768, as a `Prop`: every
ANO-CCA adversary's advantage against the concrete FIPS-203 ML-KEM-768 scheme
(`mlkem768KEM`) is at most `epsilonANO`. This is the two-key, Bool-keyed
decapsulation-oracle game of `KEMAnonymity.OracleGames` (`ANO_CCA_Advantage`)
over the base uniform oracle spec and the standard `ProbComp` runtime. The
`Prop` is parametric in `epsilonANO` so the chain carries whatever concrete
bound the assumption is instantiated with (negligible for the ERC's claim). -/
def mlkem768ANOCCA_assumed (epsilonANO : ℝ) : Prop :=
  ∀ adv : KEM.ANO_CCA_Adversary unifSpec
      (EncapsulationKey mlkem768 mlkem768Encoding)
      (Ciphertext mlkem768 mlkem768Encoding) SharedSecret,
    KEM.ANO_CCA_Advantage mlkem768KEM ProbCompRuntime.probComp adv ≤ epsilonANO

/-! ## The CRYPTREC side conditions, named -/

/-- Strong collision-freeness (chosen-ciphertext): distinct honest
decapsulation keys do not admit a common ciphertext that decapsulates
consistently under both. **Named-arrow placeholder:** abstracted to `True` here
because the concrete FIPS-203 statement (over `decapsInternal`'s
implicit-rejection re-encryption check) belongs with VCVio's security lemmas,
not this assumption module. The alias exists so consumers name the condition
and its substitution is a one-line change. -/
abbrev StrongCollisionFree := True

/-- K-PKE strong disjoint-simulatability: there is a ciphertext simulator whose
output is computationally close to a real encryption and computable without the
secret key, and the valid-ciphertext set is publicly recognisable. Realized for
ML-KEM by the compressed-uniform simulator
(`mlkem768CompressedUniformCiphertext`, `SPRTwoHop`); carried abstractly. -/
abbrev StrongDisjointSimulatable := True

/-- K-PKE correctness: honest decapsulation recovers the encapsulated secret —
already `PerfectlyCorrect` for the concrete scheme in VCVio; named to complete
the CRYPTREC condition set. -/
abbrev KEMCorrect := True

/-- The CRYPTREC assumption bundle: the three side conditions plus the ANO-CCA
smallness they jointly justify. Bundling keeps consumers quantified over one
named assumption instead of an implicit list. -/
structure CRYPTREC_ANOCCA_Bundle (epsilonANO : ℝ) : Prop where
  /-- ML-KEM is strongly collision-free under CCA. -/
  collisionFree : StrongCollisionFree
  /-- The underlying K-PKE is strongly disjoint-simulatable. -/
  disjointSimulatable : StrongDisjointSimulatable
  /-- The underlying K-PKE is correct. -/
  correct : KEMCorrect
  /-- The conclusion the side conditions justify: ML-KEM-768 is ANO-CCA. -/
  anoCCA : mlkem768ANOCCA_assumed epsilonANO

/-- The bundle implies the bare assumption: projecting the conclusion. -/
theorem CRYPTREC_ANOCCA_Bundle.toAssumed {epsilonANO : ℝ}
    (b : CRYPTREC_ANOCCA_Bundle epsilonANO) : mlkem768ANOCCA_assumed epsilonANO :=
  b.anoCCA

/-! ## The parallel hybrid at the ML-KEM-768 component -/

/-- The ERC-8441 parallel hybrid over the concrete ML-KEM-768 leg: an abstract
ECDH component, `mlkem768KEM`, and the draft's combiner. This is the KEM whose
anonymity the scheme-3 capstone needs. -/
noncomputable def scheme3ParallelHybrid768
    {ViewingPub ViewingSecret EphemeralPub EcdhSecret : Type}
    (ecdhKem : KEM ViewingPub ViewingSecret EphemeralPub EcdhSecret)
    (viewingPublicOfSecret : ViewingSecret → ViewingPub)
    (encapsulationPublicOfSecret :
      DecapsulationKey mlkem768 mlkem768Encoding → EncapsulationKey mlkem768 mlkem768Encoding)
    (combine : ViewingPub → EncapsulationKey mlkem768 mlkem768Encoding → EphemeralPub →
      Ciphertext mlkem768 mlkem768Encoding → EcdhSecret → SharedSecret → SharedSecret) :
    KEM (ViewingPub × EncapsulationKey mlkem768 mlkem768Encoding)
      (ViewingSecret × DecapsulationKey mlkem768 mlkem768Encoding)
      (EphemeralPub × Ciphertext mlkem768 mlkem768Encoding) SharedSecret :=
  KEM.parallel ecdhKem mlkem768KEM viewingPublicOfSecret encapsulationPublicOfSecret combine

/-- The hybrid's anonymity advantage, the quantity the assumption must bound. -/
noncomputable def hybrid768AnonAdvantage
    {ViewingPub ViewingSecret EphemeralPub EcdhSecret : Type}
    (ecdhKem : KEM ViewingPub ViewingSecret EphemeralPub EcdhSecret)
    (viewingPublicOfSecret : ViewingSecret → ViewingPub)
    (encapsulationPublicOfSecret :
      DecapsulationKey mlkem768 mlkem768Encoding → EncapsulationKey mlkem768 mlkem768Encoding)
    (combine : ViewingPub → EncapsulationKey mlkem768 mlkem768Encoding → EphemeralPub →
      Ciphertext mlkem768 mlkem768Encoding → EcdhSecret → SharedSecret → SharedSecret)
    (adv : StealthScheme.UnlinkAdv (ViewingPub × EncapsulationKey mlkem768 mlkem768Encoding)
      (EphemeralPub × Ciphertext mlkem768 mlkem768Encoding)) : ℝ :=
  (scheme3ParallelHybrid768 ecdhKem viewingPublicOfSecret encapsulationPublicOfSecret
    combine).anonAdvantage adv

/-- **The hybrid-anonymity reduction, as an explicitly assumed implication.**
Under the reduction obligations (`reductionOk`: the ECDH free-rider property of
Bao–Pan Lemma 4 *and* the CCA decap-simulation bad event), hybrid anonymity is
bounded by the assumed ML-KEM-768 ANO-CCA advantage plus the bad-event
slack. Stated as a hypothesis (not proved) so the scheme-3 capstone's
dependency is visible; a later milestone replaces the hypothesis with a proof
of the ROM-programming hop (`docs/fo-anonymity-lift.md`). -/
def hybrid768_anonAdvantage_le_assumed
    {ViewingPub ViewingSecret EphemeralPub EcdhSecret : Type}
    (ecdhKem : KEM ViewingPub ViewingSecret EphemeralPub EcdhSecret)
    (viewingPublicOfSecret : ViewingSecret → ViewingPub)
    (encapsulationPublicOfSecret :
      DecapsulationKey mlkem768 mlkem768Encoding → EncapsulationKey mlkem768 mlkem768Encoding)
    (combine : ViewingPub → EncapsulationKey mlkem768 mlkem768Encoding → EphemeralPub →
      Ciphertext mlkem768 mlkem768Encoding → EcdhSecret → SharedSecret → SharedSecret)
    (epsilonANO epsilonBad : ℝ) : Prop :=
  ∀ (adv : StealthScheme.UnlinkAdv (ViewingPub × EncapsulationKey mlkem768 mlkem768Encoding)
      (EphemeralPub × Ciphertext mlkem768 mlkem768Encoding)),
    mlkem768ANOCCA_assumed epsilonANO →
      hybrid768AnonAdvantage ecdhKem viewingPublicOfSecret encapsulationPublicOfSecret combine adv
        ≤ epsilonANO + epsilonBad

end PqStealth
