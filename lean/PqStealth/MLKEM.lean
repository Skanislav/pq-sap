/-
The ML-KEM instantiation, at the FIPS 203 ML-KEM-768 parameter set.

The abstract games (`Games.lean`) and the anonymity reduction
(`KEMAnonymity.lean`) are generic over a KEM. VCVio ships a concrete ML-KEM
whose checked interface is packaged as `MLKEM.asKEMScheme : KEMScheme ProbComp
...`, over the same `ProbComp` monad our `KEM` is an abbreviation for, so
`mlkem768KEM` IS that scheme rather than a transport of it. This file supplies
the instances the concrete encoding lacks and states the capstones at
`concreteNTTRingOps / mlkem768Encoding / mlkem768Primitives`, where the only
remaining arguments are the adversary and the auxiliary-data function.

Two facts about the concrete encoding shape the file.

* `MLKEM.Concrete.concreteEncoding` sets all three encoded types to `ByteArray`
  but is a plain `def`, so instance search cannot see through it. The three
  `DecidableEq` instances below close that; they are `inferInstanceAs`
  transports, definitionally `ByteArray.instDecidableEq`.

* `ByteArray` is unbounded, hence infinite, hence the ciphertext type is
  infinite (`infinite_mlkem768Ciphertext`) and admits NO `SampleableType`
  instance at all: `SampleableType` requires every element of the type to lie in
  the support of a single `ProbComp`, which forces finiteness. This is recorded
  as `isEmpty_sampleableType_mlkem768Ciphertext`, and it is why
  `unlinkAdvantage_ofKEMFull_le_full_decomposition` takes its simulator as an
  explicit argument rather than as `$ᵗ (Ciphertext params encoding)`: at the
  concrete parameter set that uniform sample does not exist.

The simulator used here is therefore not `$ᵗ (Ciphertext ...)` but
`mlkem768UniformCiphertext`: uniform over the fixed-length byte strings of the
FIPS 203 ciphertext layout, `32 * du * k = 960` bytes of `u` followed by
`32 * dv = 128` bytes of `v`, 1088 bytes in total. That is the distribution the
SPR literature means by "uniform ciphertext bytes", and it is a sharper
simulator than uniform-over-the-encoded-type would be, since the latter would
range over byte arrays of every length. `size_uEncoded_encrypt_mlkem768` checks
the `u` half of that layout against what honest K-PKE encryption actually emits.

Documented gap: the matching `v`-half check is not machine-checked here. VCVio
proves it (`byteEncode_size`, `LatticeCrypto/MLKEM/Concrete/Encoding.lean:242`)
but that theorem and the `bitsToBytes` definition it rests on are `private`, so
the fact is unavailable outside that module and the goal cannot even be stated
in terms one can unfold. The `32 * dv` figure below is therefore taken from FIPS
203 Algorithm 5 on the strength of the specification alone;
`uEncodedBytes_add_vEncodedBytes_eq_ciphertextBytes` confirms only that the two
figures chosen here sum to VCVio's `Params.ciphertextBytes`, which is arithmetic
and corroborates neither summand.

What the chain reaches, and where it stops. The shared-secret-hiding terms of
`mlkem768_unlinkAdvantage_le_indCpa` are `KEMScheme.IND_CPA_Advantage` of
explicit reduction adversaries against `MLKEM.asKEMScheme` itself
(`SharedSecretHiding.lean`). Turning those into MLWE terms needs a lemma VCVio
does not have; the statement is recorded below and in `docs/spr-two-hop.md`.
VCVio's own ML-KEM security theorems (`kpke_ind_cpa_security`,
`kpke_delta_correct`, `ind_cca_security` in `LatticeCrypto/MLKEM/Security.lean`)
are `sorry` placeholders at the pinned commit and concern K-PKE rather than the
KEM, so nothing here depends on them.
-/

import PqStealth.AnonymityFromSPR
import PqStealth.SharedSecretHiding
import VCVio.CryptoFoundations.KeyEncapMech
import LatticeCrypto.MLKEM.KEM
import LatticeCrypto.MLKEM.Concrete.Instance

open OracleComp OracleSpec MLKEM MLKEM.Concrete

namespace PqStealth

/-! ## Decidable equality on the concrete encoded types

`concreteEncoding` sets `EncodedTHat = EncodedU = EncodedV = ByteArray`, but as
a plain `def` it is opaque to instance search. These three transports make the
equality visible, so `MLKEM.asKEMScheme` and everything built on it elaborate at
`mlkem768Encoding`. -/

instance : DecidableEq mlkem768Encoding.EncodedTHat :=
  inferInstanceAs (DecidableEq ByteArray)

instance : DecidableEq mlkem768Encoding.EncodedU :=
  inferInstanceAs (DecidableEq ByteArray)

instance : DecidableEq mlkem768Encoding.EncodedV :=
  inferInstanceAs (DecidableEq ByteArray)

/-! ## The concrete ciphertext type is infinite

`SampleableType β` bundles a `ProbComp β` whose support is all of `β`; supports
of `ProbComp`s are finite, so a `SampleableType` instance forces `β` finite.
`ByteArray` is not, and neither is the concrete ciphertext type. -/

/-- `ByteArray` is infinite: the all-zero arrays have pairwise distinct lengths. -/
theorem infinite_byteArray : Infinite ByteArray :=
  Infinite.of_injective (fun n : ℕ => ByteArray.mk (Array.replicate n 0)) (by
    intro a b hab
    have h := congrArg ByteArray.size hab
    simp only [ByteArray.size, Array.size_replicate] at h
    exact h)

/-- The ML-KEM-768 ciphertext type is infinite, since its `u` component ranges
over all of `ByteArray`. -/
theorem infinite_mlkem768Ciphertext :
    Infinite (Ciphertext mlkem768 mlkem768Encoding) :=
  haveI := infinite_byteArray
  Infinite.of_injective
    (fun b : ByteArray =>
      (⟨b, ByteArray.mk #[]⟩ : Ciphertext mlkem768 mlkem768Encoding))
    (by intro a b hab; exact congrArg KPKE.Ciphertext.uEncoded hab)

/-- **No uniform distribution on the ML-KEM-768 ciphertext type exists.** A
`SampleableType` instance would make the type finite, and it is not. Hence
`$ᵗ (Ciphertext params encoding)` is unavailable at this parameter set, and the
concrete decomposition below supplies `mlkem768UniformCiphertext` as the
explicit simulator of `unlinkAdvantage_ofKEMFull_le_full_decomposition`. -/
theorem isEmpty_sampleableType_mlkem768Ciphertext :
    IsEmpty (SampleableType (Ciphertext mlkem768 mlkem768Encoding)) :=
  ⟨fun h =>
    haveI := infinite_mlkem768Ciphertext
    @not_finite _ inferInstance (@SampleableType.Finite _ h)⟩

/-! ## The FIPS 203 ciphertext byte layout -/

/-- Bytes occupied by the `u` component of an encoded ciphertext: `k`
polynomials, `du` bits per coefficient, 256 coefficients each. -/
def uEncodedBytes (params : Params) : ℕ := 32 * params.du * params.k

/-- Bytes occupied by the `v` component of an encoded ciphertext: one
polynomial, `dv` bits per coefficient, 256 coefficients. -/
def vEncodedBytes (params : Params) : ℕ := 32 * params.dv

/-- The two halves account for the whole ciphertext, as sized by VCVio's
`Params.ciphertextBytes` (1088 bytes for ML-KEM-768). -/
theorem uEncodedBytes_add_vEncodedBytes_eq_ciphertextBytes (params : Params) :
    uEncodedBytes params + vEncodedBytes params = params.ciphertextBytes := by
  simp only [uEncodedBytes, vEncodedBytes, Params.ciphertextBytes]
  ring

/-- ML-KEM-768 splits its 1088 ciphertext bytes as 960 + 128. -/
theorem uEncodedBytes_mlkem768 : uEncodedBytes mlkem768 = 960 := by decide

/-- The `v` half of the ML-KEM-768 ciphertext layout. -/
theorem vEncodedBytes_mlkem768 : vEncodedBytes mlkem768 = 128 := by decide

/-- The ML-KEM-768 `u` encoder produces exactly `uEncodedBytes` bytes. -/
theorem size_byteEncodeDUVec_mlkem768 (u : RqVec mlkem768.k) :
    (mlkem768Encoding.byteEncodeDUVec u : ByteArray).size = uEncodedBytes mlkem768 := by
  simp only [ByteArray.size, mlkem768Encoding, concreteEncoding, byteEncodeVec,
    Array.size_ofFn, uEncodedBytes]

/-- The `u` component of an honestly produced ML-KEM-768 ciphertext occupies
exactly `uEncodedBytes mlkem768` bytes, so the uniform sampler below ranges over
the same byte length that real encapsulation emits. -/
theorem size_uEncoded_encrypt_mlkem768
    (ek : EncapsulationKey mlkem768 mlkem768Encoding) (msg : Message) (coins : Coins) :
    ((KPKE.encrypt concreteNTTRingOps mlkem768Encoding mlkem768Primitives ek msg
        coins).uEncoded : ByteArray).size = uEncodedBytes mlkem768 :=
  size_byteEncodeDUVec_mlkem768 _

/-! ## The uniform-ciphertext-bytes simulator -/

/-- Uniform sampling over the ML-KEM-768 ciphertext byte space: 960 uniform
bytes for `u`, 128 for `v`. This is the key-independent simulator the SPR
(strong-pseudorandomness) argument compares real encapsulations against; its
support is the set of encoded ciphertexts of the FIPS 203 length, a strict
subset of the encoded type, which is all of `ByteArray × ByteArray`. -/
def mlkem768UniformCiphertext : ProbComp (Ciphertext mlkem768 mlkem768Encoding) := do
  let u ← $ᵗ (Bytes (uEncodedBytes mlkem768))
  let v ← $ᵗ (Bytes (vEncodedBytes mlkem768))
  return ⟨ByteArray.mk u.toArray, ByteArray.mk v.toArray⟩

/-! ## The scheme at ML-KEM-768 -/

/-- Our `KEM`, at the FIPS 203 ML-KEM-768 parameter set. Since `KEM` is
`KEMScheme` over `ProbComp` with the type arguments reordered, this IS
`MLKEM.asKEMScheme`, not a transport of it. -/
def mlkem768KEM :
    KEM (EncapsulationKey mlkem768 mlkem768Encoding)
      (DecapsulationKey mlkem768 mlkem768Encoding)
      (Ciphertext mlkem768 mlkem768Encoding) SharedSecret :=
  MLKEM.asKEMScheme concreteNTTRingOps mlkem768Encoding mlkem768Primitives

section Capstones

variable {Aux : Type} [DecidableEq Aux]
  (auxGen : SharedSecret → EncapsulationKey mlkem768 mlkem768Encoding → Aux)

/-- The post-quantum stealth scheme on ML-KEM-768: discovery via real ML-KEM,
announcement = `(ciphertext, auxGen sharedSecret encapsulationKey)` -- the view
tag and stealth address folded in, the latter depending on the recipient's own
key as well as the shared secret. -/
def mlkem768StealthScheme :
    StealthScheme (EncapsulationKey mlkem768 mlkem768Encoding)
      (DecapsulationKey mlkem768 mlkem768Encoding
        × EncapsulationKey mlkem768 mlkem768Encoding)
      (Ciphertext mlkem768 mlkem768Encoding × Aux) :=
  StealthScheme.ofKEMFull mlkem768KEM auxGen

/-- **The unlinkability bound on ML-KEM-768**, with no instance hypotheses on
the ML-KEM types left open: the only arguments are the auxiliary-data function,
decidable equality on the caller-chosen `Aux` (needed by `scan`), and the
adversary.
Unlinkability is bounded by ML-KEM-768's anonymity advantage, its two
shared-secret-hiding (IND-CPA) terms, and the auxiliary-data key-independence
term. The key-independence term is the blinding argument (`ConstructionA`); the
anonymity term is the one link neither VCVio nor FIPS 203 supplies
(Grubbs-Maram-Paterson), i.e. the novel piece. -/
theorem mlkem768_unlinkAdvantage_le
    (adv : StealthScheme.UnlinkAdv (EncapsulationKey mlkem768 mlkem768Encoding)
      (Ciphertext mlkem768 mlkem768Encoding × Aux)) :
    (mlkem768StealthScheme auxGen).unlinkAdvantage adv ≤
      sharedSecretHiding mlkem768KEM auxGen adv true
      + auxKeyIndependence mlkem768KEM auxGen adv
      + mlkem768KEM.anonAdvantage (adv.cipherOf auxGen)
      + sharedSecretHiding mlkem768KEM auxGen adv false :=
  unlinkAdvantage_ofKEMFull_le mlkem768KEM auxGen adv

/-- **Unlinkability on ML-KEM-768, fully decomposed**, with no instance
hypotheses on the ML-KEM types left open. The hiding terms are ML-KEM-768's KEM IND-CPA advantage
(`SharedSecretHiding`); the SPR terms are the key hop and the ciphertext hop
(paper-level, see `AnonymityFromSPR`). The simulator is uniform over the 1088-byte FIPS 203 ciphertext layout
rather than `$ᵗ (Ciphertext ...)`, which does not exist here
(`isEmpty_sampleableType_mlkem768Ciphertext`). -/
theorem mlkem768_unlinkAdvantage_le_full_decomposition
    (adv : StealthScheme.UnlinkAdv (EncapsulationKey mlkem768 mlkem768Encoding)
      (Ciphertext mlkem768 mlkem768Encoding × Aux)) :
    (mlkem768StealthScheme auxGen).unlinkAdvantage adv ≤
      sharedSecretHiding mlkem768KEM auxGen adv true
      + auxKeyIndependence mlkem768KEM auxGen adv
      + (mlkem768KEM.sprAdv mlkem768UniformCiphertext (adv.cipherOf auxGen) true
         + mlkem768KEM.sprAdv mlkem768UniformCiphertext (adv.cipherOf auxGen) false)
      + sharedSecretHiding mlkem768KEM auxGen adv false :=
  unlinkAdvantage_ofKEMFull_le_full_decomposition mlkem768KEM auxGen
    mlkem768UniformCiphertext adv

/-- **The ML-KEM-768 unlinkability bound in IND-CPA form.**
`mlkem768_unlinkAdvantage_le` with both hiding terms replaced by VCVio KEM
IND-CPA advantages of explicit reduction adversaries against
`MLKEM.asKEMScheme`. Bounding those two terms by MLWE is exactly the missing
upstream lemma recorded below; the remaining two terms (auxiliary-data key
independence, ML-KEM anonymity) are not KEM IND-CPA questions at all. -/
theorem mlkem768_unlinkAdvantage_le_indCpa
    (adv : StealthScheme.UnlinkAdv (EncapsulationKey mlkem768 mlkem768Encoding)
      (Ciphertext mlkem768 mlkem768Encoding × Aux)) :
    (mlkem768StealthScheme auxGen).unlinkAdvantage adv ≤
      KEMScheme.IND_CPA_Advantage ProbCompRuntime.probComp
        (indCpaAdv mlkem768KEM auxGen adv true)
      + auxKeyIndependence mlkem768KEM auxGen adv
      + mlkem768KEM.anonAdvantage (adv.cipherOf auxGen)
      + KEMScheme.IND_CPA_Advantage ProbCompRuntime.probComp
        (indCpaAdv mlkem768KEM auxGen adv false) :=
  unlinkAdvantage_ofKEMFull_le_indCpa mlkem768KEM auxGen adv

end Capstones

/-! ## The missing upstream lemma

Not a theorem: prose, recorded here because the composition that consumes it is
a one-line `calc` the day it lands. The statement elaborates as written against
the pinned VCVio, under `import LatticeCrypto.HardnessAssumptions.LearningWithErrors`
and `open MLKEM`:

```
theorem MLKEM.kem_ind_cpa_security {params : Params} (ring : NTTRingOps)
    (encoding : Encoding params) (prims : Primitives params encoding)
    [DecidableEq encoding.EncodedTHat] [DecidableEq encoding.EncodedU]
    [DecidableEq encoding.EncodedV] [SampleableType SharedSecret] :
    ∃ mlwe : LearningWithErrors.Problem
        (TqMatrix params.k params.k) (TqVec params.k) (TqVec params.k),
      ∀ cpaAdv : (MLKEM.asKEMScheme ring encoding prims).IND_CPA_Adversary,
        ∃ mlweAdv : LearningWithErrors.Adversary mlwe,
          KEMScheme.IND_CPA_Advantage ProbCompRuntime.probComp cpaAdv ≤
            |LearningWithErrors.advantage mlwe mlweAdv|
```

What `LatticeCrypto/MLKEM/Security.lean` supplies instead is
`kpke_ind_cpa_security`, which bounds `AsymmEncAlg.IND_CPA_advantage` of K-PKE --
the underlying public-key encryption scheme -- rather than
`KEMScheme.IND_CPA_Advantage` of the KEM, and which is `sorry` upstream. The
step between the two is the T-transform half of Fujisaki-Okamoto: the KEM's
shared secret is derived from a uniformly random message via a hash modelled as
a random oracle, so KEM IND-CPA follows from K-PKE IND-CPA plus message entropy.
Neither that reduction nor `kpke_ind_cpa_security` itself is in scope here, so
this file states equalities and bounds, never an MLWE bound; importing one would
import `sorryAx`. See `docs/spr-two-hop.md`. -/

/-! ## The instances resolve

These record, in the build, the synthesis checks that the abstract capstones
leave as hypotheses. -/

example : DecidableEq mlkem768Encoding.EncodedTHat := inferInstance
example : DecidableEq mlkem768Encoding.EncodedU := inferInstance
example : DecidableEq mlkem768Encoding.EncodedV := inferInstance
example : SampleableType SharedSecret := inferInstance

end PqStealth
