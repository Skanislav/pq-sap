import PqStealth.AnonymityFromSPR
import PqStealth.SharedSecretHiding
import VCVio.CryptoFoundations.KeyEncapMech
import LatticeCrypto.MLKEM.KEM
import LatticeCrypto.MLKEM.Concrete.Instance

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

open OracleComp OracleSpec MLKEM MLKEM.Concrete

namespace PqStealth

/-! ## Decidable equality on the concrete encoded types

Transports making the `ByteArray` equality visible through the opaque `def`. -/

/-- Decidable equality on encoded `t̂`, through the `ByteArray` representation. -/
instance instDecidableEqMlkem768EncodedTHat : DecidableEq mlkem768Encoding.EncodedTHat :=
  inferInstanceAs (DecidableEq ByteArray)

/-- Decidable equality on the encoded ciphertext component `u`. -/
instance instDecidableEqMlkem768EncodedU : DecidableEq mlkem768Encoding.EncodedU :=
  inferInstanceAs (DecidableEq ByteArray)

/-- Decidable equality on the encoded ciphertext component `v`. -/
instance instDecidableEqMlkem768EncodedV : DecidableEq mlkem768Encoding.EncodedV :=
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

/-! ## Uniform sampling on the ML-KEM ring

VCVio leaves these to the caller (`MLDSA` takes them as hypotheses); they are
what the uniform side of each MLWE problem, and the compressed-uniform
ciphertext simulator below, need. -/

/-- The FIPS 203 modulus is nonzero -- needed to see `ZMod modulus` as
`FinEnum`, which `modulus` being a `def` hides from instance search. -/
instance instNeZeroMlkemModulus : NeZero MLKEM.modulus := ⟨by decide⟩

/-- Uniform sampling on `R_q`, through the `Vector Coeff 256` representation
that `LatticeCrypto.Poly` is a plain `def` for. -/
instance instSampleableTypeRq : SampleableType MLKEM.Rq :=
  inferInstanceAs (SampleableType (Vector MLKEM.Coeff MLKEM.ringDegree))

/-- Uniform sampling on `T_q`, transported along the `TransformPoly` newtype. -/
instance instSampleableTypeTq : SampleableType MLKEM.Tq :=
  SampleableType.ofEquiv (α := MLKEM.Rq)
    ⟨fun f => ⟨f⟩, fun t => t.coeffs, fun _ => rfl, fun _ => rfl⟩

/-! ## Semantic constructors

`pkOf`/`ctOf` name the two places FIPS 203 leaves the algebra: a public key is a
seed plus an encoded `t̂`, a ciphertext an encoded compressed `(u, v)`. They live
here, beside the simulators, so there is one definition of each. -/

/-- The K-PKE public key carrying `rho` and the encoding of `t̂`. -/
def pkOf {params : Params} (encoding : Encoding params) (rho : Seed32)
    (tHat : TqVec params.k) : EncapsulationKey params encoding :=
  { tHatEncoded := encoding.byteEncode12Vec tHat, rho := rho }

/-- The K-PKE ciphertext carrying the compressed encodings of `u` and `v`. -/
def ctOf {params : Params} (encoding : Encoding params) (u : RqVec params.k) (v : Rq) :
    Ciphertext params encoding :=
  { uEncoded := encoding.byteEncodeDUVec (encoding.compressDU u)
    vEncoded := encoding.byteEncodeDV (encoding.compressDV v) }

/-- Key generation with `t̂` uniform: the right-hand side of the key hop. -/
def uniformKeygen {params : Params} (encoding : Encoding params) :
    ProbComp (EncapsulationKey params encoding) := do
  let rho ← $ᵗ Seed32
  let t ← $ᵗ (TqVec params.k)
  pure (pkOf encoding rho t)

/-- A ciphertext built from uniform ring elements: the right-hand side of the
ciphertext hop. Still an encoding of compressed uniform `(u, v)`, not uniform
bytes. -/
def randCt {params : Params} (encoding : Encoding params) :
    ProbComp (Ciphertext params encoding) := do
  let u ← $ᵗ (RqVec params.k)
  let v ← $ᵗ Rq
  let m ← $ᵗ Message
  pure (ctOf encoding u (v + encoding.decompress1 (encoding.byteDecode1 m)))

/-! ## The ciphertext simulators

Two key-independent simulators, only one of which is admissible.

`mlkem768CompressedUniformCiphertext` is the one every capstone in this
development uses. It draws uniform `(u, v)` in `R_q^k × R_q` and applies FIPS
203's own `compressDU`/`compressDV` then byte encoding — that is, the exact
`randCt` distribution of the last idealized game. Its encoding residual is
therefore *exactly* zero (`encodingRegularity_mlkem768CompressedUniformCiphertext`),
which is what makes the SPR bound non-vacuous.

`mlkem768UniformCiphertext` is the textbook "uniform ciphertext bytes" choice,
kept only so the reason it is unusable is stated in the code rather than in a
review comment: FIPS 203's `Compress₁₀` is a map `ZMod 3329 → ZMod 1024` and
`3329 = 3·1024 + 257`, so 257 output values have four preimages and 767 have
three. A uniform coefficient therefore hits the four-preimage set with
probability `1028/3329 ≈ 0.3088` instead of `257/1024 ≈ 0.250977`. The
single-coefficient total-variation distance from uniform 10-bit output is
`197119/3408896 ≈ 0.0578248794`; over the 768 independent `u` coefficients it is
`0.9262656353`. A constant-distance simulator cannot carry a negligible
encoding term, so `encodingRegularity` against it is bounded below by a
constant, and no theorem of the form `SPR ≤ MLWE + negligible` holds with it.
See `docs/spr-two-hop.md`. -/

/-- The exact compressed-ciphertext distribution of the final idealized MLWE
game: uniform `(u, v)` in the ring, then FIPS 203 compression and byte
encoding. Key-independent, so it is a valid SPR simulator; unlike raw uniform
bytes it is the honest ciphertext distribution up to the ring-uniform step. -/
def mlkem768CompressedUniformCiphertext :
    ProbComp (Ciphertext mlkem768 mlkem768Encoding) :=
  randCt mlkem768Encoding

/-- Uniform over the ML-KEM-768 ciphertext byte space: 960 bytes of `u`, 128 of
`v`. **Not usable as an SPR simulator** at this parameter set — see the section
docstring: FIPS 203 compression makes it a constant total-variation distance
(`0.9262656353` over the `u` half) from the honest ciphertext distribution.
Retained to state that fact where the numbers live. -/
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

/-- **Unlinkability on ML-KEM-768, fully decomposed.** The simulator is the
compressed-uniform one — uniform `(u, v)` in the ring, then FIPS 203
compression and byte encoding — rather than `$ᵗ (Ciphertext ...)`, which does not
exist here (`isEmpty_sampleableType_mlkem768Ciphertext`), and rather than
uniform ciphertext bytes, whose distance from the honest ciphertext
distribution is a constant `0.9262656353` (see the module docstring of
`MLKEM`). -/
theorem mlkem768_unlinkAdvantage_le_full_decomposition
    (adv : StealthScheme.UnlinkAdv (EncapsulationKey mlkem768 mlkem768Encoding)
      (Ciphertext mlkem768 mlkem768Encoding × Aux)) :
    (mlkem768StealthScheme auxGen).unlinkAdvantage adv ≤
      sharedSecretHiding mlkem768KEM auxGen adv true
      + auxKeyIndependence mlkem768KEM auxGen adv
      + (mlkem768KEM.sprAdv mlkem768CompressedUniformCiphertext (adv.cipherOf auxGen) true
         + mlkem768KEM.sprAdv mlkem768CompressedUniformCiphertext (adv.cipherOf auxGen) false)
      + sharedSecretHiding mlkem768KEM auxGen adv false :=
  unlinkAdvantage_ofKEMFull_le_full_decomposition mlkem768KEM auxGen
    mlkem768CompressedUniformCiphertext adv

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

/-! ## The instances resolve -/

example : DecidableEq mlkem768Encoding.EncodedTHat := inferInstance
example : DecidableEq mlkem768Encoding.EncodedU := inferInstance
example : DecidableEq mlkem768Encoding.EncodedV := inferInstance
example : SampleableType SharedSecret := inferInstance

end PqStealth
