import PqStealth.AnonymityFromSPR
import PqStealth.SharedSecretHiding
import VCVio.CryptoFoundations.KeyEncapMech
import LatticeCrypto.MLKEM.KEM
import LatticeCrypto.MLKEM.Concrete.Instance

open OracleComp OracleSpec MLKEM MLKEM.Concrete

namespace PqStealth

/-! ## Decidable equality on the concrete encoded types

Transports making the `ByteArray` equality visible through the opaque `def`. -/

instance : DecidableEq mlkem768Encoding.EncodedTHat :=
  inferInstanceAs (DecidableEq ByteArray)

instance : DecidableEq mlkem768Encoding.EncodedU :=
  inferInstanceAs (DecidableEq ByteArray)

instance : DecidableEq mlkem768Encoding.EncodedV :=
  inferInstanceAs (DecidableEq ByteArray)

/-! ## The concrete ciphertext type is infinite

A `SampleableType` instance forces finiteness; `ByteArray` is not finite. -/

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

/-- **No uniform distribution on the ML-KEM-768 ciphertext type exists**, since a
`SampleableType` instance would make it finite. This is why the decomposition
takes its simulator as an explicit argument. -/
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

/-- Uniform over the ML-KEM-768 ciphertext byte space: 960 bytes of `u`, 128 of
`v`. The key-independent simulator the SPR argument compares real encapsulations
against, and sharper than uniform-over-the-encoded-type would be. -/
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
announcement `(ciphertext, auxGen sharedSecret encapsulationKey)`. -/
def mlkem768StealthScheme :
    StealthScheme (EncapsulationKey mlkem768 mlkem768Encoding)
      (DecapsulationKey mlkem768 mlkem768Encoding
        × EncapsulationKey mlkem768 mlkem768Encoding)
      (Ciphertext mlkem768 mlkem768Encoding × Aux) :=
  StealthScheme.ofKEMFull mlkem768KEM auxGen

/-- **The unlinkability bound on ML-KEM-768**, with no instance hypotheses on the
ML-KEM types left open: only the auxiliary-data function, `DecidableEq` on the
caller's `Aux`, and the adversary remain. -/
theorem mlkem768_unlinkAdvantage_le
    (adv : StealthScheme.UnlinkAdv (EncapsulationKey mlkem768 mlkem768Encoding)
      (Ciphertext mlkem768 mlkem768Encoding × Aux)) :
    (mlkem768StealthScheme auxGen).unlinkAdvantage adv ≤
      sharedSecretHiding mlkem768KEM auxGen adv true
      + auxKeyIndependence mlkem768KEM auxGen adv
      + mlkem768KEM.anonAdvantage (adv.cipherOf auxGen)
      + sharedSecretHiding mlkem768KEM auxGen adv false :=
  unlinkAdvantage_ofKEMFull_le mlkem768KEM auxGen adv

/-- **Unlinkability on ML-KEM-768, fully decomposed.** The simulator is uniform
over the 1088-byte FIPS 203 layout rather than `$ᵗ (Ciphertext ...)`, which does
not exist here (`isEmpty_sampleableType_mlkem768Ciphertext`). -/
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

/-- **The ML-KEM-768 unlinkability bound in IND-CPA form**: both hiding terms are
VCVio KEM IND-CPA advantages of explicit reduction adversaries against
`MLKEM.asKEMScheme`. Bounding them by MLWE is the missing lemma below. -/
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

`LatticeCrypto/MLKEM/Security.lean` supplies `kpke_ind_cpa_security` instead: it
is about K-PKE rather than the KEM, and is `sorry` upstream. The step between
them is the T-transform half of Fujisaki-Okamoto. See `docs/spr-two-hop.md`. -/

/-!
# ML-KEM-768

Proved: the three `DecidableEq` instances VCVio's concrete encoding lacks (it
sets all encoded types to `ByteArray` but as a plain `def`); that the concrete
ciphertext type is INFINITE, hence `SampleableType` on it is provably
uninhabited and the SPR simulator must be an explicit argument; the
uniform-1088-byte FIPS 203 simulator and the `u` half of its layout against what
honest K-PKE encryption emits; and the three capstones -- `_le`,
`_le_full_decomposition`, `_le_indCpa` -- with no instance hypotheses left open.

Assumed: the `v`-half byte count, taken from FIPS 203 because VCVio's
`byteEncode_size` is `private`; and KEM-IND-CPA → MLWE, the missing upstream
lemma recorded below. See `docs/spr-two-hop.md`.
-/

/-! ## The instances resolve -/

example : DecidableEq mlkem768Encoding.EncodedTHat := inferInstance
example : DecidableEq mlkem768Encoding.EncodedU := inferInstance
example : DecidableEq mlkem768Encoding.EncodedV := inferInstance
example : SampleableType SharedSecret := inferInstance

end PqStealth
