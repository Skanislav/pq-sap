/-
The ML-KEM-768 instantiation, with every instance hypothesis discharged.

`MLKEMInstance.lean` and `AnonymityFromSPR.lean` state the unlinkability
capstones over an abstract `(ring, encoding, prims)` triple, under instance
hypotheses on the encoding's three encoded types. This file supplies those
instances for VCVio's concrete FIPS 203 parameter set and restates the two
capstones at `concreteNTTRingOps / mlkem768Encoding / mlkem768Primitives`, where
the only remaining arguments are the adversary and the auxiliary-data function.

Two facts about the concrete encoding shape the file.

* `MLKEM.Concrete.concreteEncoding` sets all three encoded types to `ByteArray`
  but is a plain `def`, so instance search cannot see through it. The three
  `DecidableEq` instances below close that; they are `inferInstanceAs`
  transports, definitionally `ByteArray.instDecidableEq`.

* `ByteArray` is unbounded, hence infinite, hence the ciphertext type is
  infinite (`infinite_mlkem768Ciphertext`) and admits NO `SampleableType`
  instance at all: `SampleableType` requires every element of the type to lie in
  the support of a single `ProbComp`, which forces finiteness. This is recorded
  as `isEmpty_sampleableType_mlkem768Ciphertext`, and it means
  `mlkem_unlinkAdvantage_le_full_decomposition`'s
  `[SampleableType (Ciphertext params encoding)]` hypothesis is unsatisfiable at
  the concrete parameter set. The generic product instance
  `instSampleableTypeCiphertext` is still provided -- it applies to any encoding
  whose encoded components are finite, e.g. a fixed-length-vector encoding.

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
-/

import PqStealth.AnonymityFromSPR
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

/-! ## Uniform sampling of ciphertexts

A ciphertext is exactly a pair of encoded components, so uniform sampling of the
type is the product sampler -- available whenever both components are. -/

/-- A K-PKE ciphertext is its pair of encoded components. -/
def ciphertextEquivProd {params : Params} (encoding : Encoding params) :
    encoding.EncodedU × encoding.EncodedV ≃ KPKE.Ciphertext params encoding where
  toFun p := ⟨p.1, p.2⟩
  invFun c := (c.uEncoded, c.vEncoded)
  left_inv _ := rfl
  right_inv _ := rfl

/-- Uniform sampling of ciphertexts, componentwise. Requires the encoded
component types to be sampleable, which for a byte-array encoding they are not
(see `isEmpty_sampleableType_mlkem768Ciphertext`); it applies to encodings whose
encoded types are fixed-length. -/
instance instSampleableTypeCiphertext {params : Params} {encoding : Encoding params}
    [SampleableType encoding.EncodedU] [SampleableType encoding.EncodedV] :
    SampleableType (KPKE.Ciphertext params encoding) :=
  SampleableType.ofEquiv (ciphertextEquivProd encoding)

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
`mlkem_unlinkAdvantage_le_full_decomposition`, whose simulator is
`$ᵗ (Ciphertext params encoding)`, has no instance at this parameter set, and
the concrete decomposition below uses `mlkem768UniformCiphertext` instead. -/
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

/-! ## The capstones at ML-KEM-768 -/

section Capstones

variable {Aux : Type} [DecidableEq Aux]
  (auxGen : SharedSecret → EncapsulationKey mlkem768 mlkem768Encoding → Aux)

/-- Our `KEM`, at the FIPS 203 ML-KEM-768 parameter set. -/
def mlkem768KEM :
    KEM (EncapsulationKey mlkem768 mlkem768Encoding)
      (DecapsulationKey mlkem768 mlkem768Encoding)
      (Ciphertext mlkem768 mlkem768Encoding) SharedSecret :=
  mlkem concreteNTTRingOps mlkem768Encoding mlkem768Primitives

/-- The post-quantum stealth scheme on ML-KEM-768. -/
def mlkem768StealthScheme :
    StealthScheme (EncapsulationKey mlkem768 mlkem768Encoding)
      (DecapsulationKey mlkem768 mlkem768Encoding
        × EncapsulationKey mlkem768 mlkem768Encoding)
      (Ciphertext mlkem768 mlkem768Encoding × Aux) :=
  mlkemStealthScheme concreteNTTRingOps mlkem768Encoding mlkem768Primitives auxGen

/-- **The unlinkability bound on ML-KEM-768**, with no instance hypotheses on
the ML-KEM types left open: the only arguments are the auxiliary-data function,
decidable equality on the caller-chosen `Aux` (needed by `scan`), and the
adversary.
Unlinkability is bounded by ML-KEM-768's anonymity advantage, its two
shared-secret-hiding (IND-CPA) terms, and the auxiliary-data key-independence
term. -/
theorem mlkem768_unlinkAdvantage_le
    (adv : StealthScheme.UnlinkAdv (EncapsulationKey mlkem768 mlkem768Encoding)
      (Ciphertext mlkem768 mlkem768Encoding × Aux)) :
    (mlkem768StealthScheme auxGen).unlinkAdvantage adv ≤
      sharedSecretHidingTrue mlkem768KEM auxGen adv
      + auxKeyIndependence mlkem768KEM auxGen adv
      + mlkem768KEM.anonAdvantage (adv.cipherOf auxGen)
      + sharedSecretHidingFalse mlkem768KEM auxGen adv :=
  mlkem_unlinkAdvantage_le concreteNTTRingOps mlkem768Encoding mlkem768Primitives auxGen adv

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
      sharedSecretHidingTrue mlkem768KEM auxGen adv
      + auxKeyIndependence mlkem768KEM auxGen adv
      + (mlkem768KEM.sprAdvTrue mlkem768UniformCiphertext (adv.cipherOf auxGen)
         + mlkem768KEM.sprAdvFalse mlkem768UniformCiphertext (adv.cipherOf auxGen))
      + sharedSecretHidingFalse mlkem768KEM auxGen adv :=
  unlinkAdvantage_ofKEMFull_le_full_decomposition
    mlkem768KEM auxGen mlkem768UniformCiphertext adv

end Capstones

/-! ## The instances resolve

These record, in the build, the synthesis checks that the abstract capstones
leave as hypotheses. -/

example : DecidableEq mlkem768Encoding.EncodedTHat := inferInstance
example : DecidableEq mlkem768Encoding.EncodedU := inferInstance
example : DecidableEq mlkem768Encoding.EncodedV := inferInstance
example : SampleableType SharedSecret := inferInstance

example {params : Params} {encoding : Encoding params}
    [SampleableType encoding.EncodedU] [SampleableType encoding.EncodedV] :
    SampleableType (MLKEM.Ciphertext params encoding) := inferInstance

end PqStealth
