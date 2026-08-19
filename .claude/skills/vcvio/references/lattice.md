# LatticeCrypto layout and workflows

Condensed from VCVio `docs/agents/lattice.md` @ main `ea9916db` (2026-08-19). **Pin vs main
differences are flagged** — we build against `a5f474fd`.

## Layers
- `LatticeCrypto/`: generic lattice algebra, hardness assumptions, scheme specs, security
  theorems, FFI-free executable `Concrete/` implementations.
- `Extern/`: native FFI surface — `Extern/Hashing.lean`, `Extern/*/FFI.lean`, and every
  FFI-backed module (sampling, **instances**, Falcon FFT/keygen/signing). **No proof library may
  import it** (`scripts/check-extern-isolation.sh`); backends are empty stubs without
  `third_party/` submodules (always the case for Lake dependency checkouts like ours).
  *At the pin*, the ML-KEM/ML-DSA concrete instances still live under
  `LatticeCrypto/{MLKEM,MLDSA}/Concrete/Instance.lean` (we import
  `LatticeCrypto.MLKEM.Concrete.Instance`); on main they are `Extern/MLKEM/Instance.lean`,
  `Extern/MLDSA/…` (moved in #496 "make `require VCVio` work without third_party submodules").
- `LatticeCryptoTest/`: ACVP vectors, randomized regression, differential tests vs native code.
- `csrc/`, `third_party/`: C shims and submodule backends.

Dependency direction: `{Ring/*, DiscreteGaussian} → HardnessAssumptions → {MLDSA, MLKEM, Falcon}
→ Concrete/ → Extern → LatticeCryptoTest`. `LatticeCrypto/` may import `VCVio/CryptoFoundations`,
never the reverse. Change framework abstractions in `VCVio/` (`SignatureAlg`,
`IdenSchemeWithAbort`, `GPVHashAndSign`, `FujisakiOkamoto`, `KEMScheme`); instantiate in
`LatticeCrypto/`. Update both sides in one pass; no shims.

## Entry points
Ring: `LatticeCrypto/Ring/{Core,Kernel,VectorBackend,Transform,Norms,Rounding,IntegralLift,NTTCert}.lean`
(`PolyBackend`, `PolyVec`, `PolyMatrix`, `NegacyclicQuotient`, `NegacyclicRing`, `TransformOps`,
`NormOps`, `RoundingOps`, `Power2RoundOps`), `DiscreteGaussian.lean`.
Hardness: `HardnessAssumptions/LearningWithErrors.lean` (LWE/MLWE, used by ML-KEM),
`ShortIntegerSolution.lean` (SIS, self-target SIS; ML-DSA/Falcon).

ML-KEM (`LatticeCrypto/MLKEM/`): `Params.lean` (`mlkem512/768/1024`, sizes), `Arithmetic.lean`
(`Rq`, `Tq`, `TqVec`, `TqMatrix`), `Primitives.lean` (abstract sampling/hash/encoding ops:
`Encoding params` with `EncodedTHat/U/V`, `Primitives params encoding`), `KPKE.lean`
(`PublicKey`, `SecretKey`, `Ciphertext`, `encrypt`…), `Internal.lean` (`keygenInternal`,
`encapsInternal`, `decapsInternal`), `KEM.lean` (`encapsulationKeyCheck`, `encaps`, `decaps`,
`asKEMScheme ring encoding prims : KEMScheme ProbComp …`), `Security.lean` (IND-CPA/IND-CCA
*statements*; `sorry` at the pin), `Concrete/{CBD,Encoding,NTT}.lean` (`concreteEncoding params`,
`concreteNTTRingOps`, `byteEncode`/`byteDecode`, `compressVec`…), instances
(`mlkem768Encoding := concreteEncoding mlkem768`, `mlkem768Primitives`, `mlkem768EncodingLaws`).
Generic API demands `[DecidableEq encoding.Encoded{THat,U,V}]`; the concrete `def`s don't expose
`ByteArray`'s instance → `inferInstanceAs (DecidableEq ByteArray)` (ours `PqStealth/MLKEM.lean`,
upstream's own `LatticeCryptoTest/MLKEM/Helpers.lean`).

ML-DSA (`LatticeCrypto/MLDSA/`): `Params`, `Arithmetic`, `Primitives`, `Scheme.lean` (proof-level
IDS with aborts), `Signature.lean` (FIPS signing), `Security.lean`, `SecurityNMA.lean` (short-box
MLWE key swap), `Concrete/` (+ `LawBounds.lean`), `Encoding`, `Concrete/Rounding` (we import the
last two for `Power2Round`/`HighBits` facts).

Falcon (`LatticeCrypto/Falcon/`): `Params`, `Arithmetic`, `Primitives`, `Scheme.lean` (GPV bridge),
`Security.lean`, `Concrete/` (NTT, FPR/FXR, NTRU solver).

Generic surfaces reused: ML-DSA → `IdenSchemeWithAbort` + `FiatShamirWithAbort`; Falcon →
`GPVHashAndSign` + `GenerableRelation`; ML-KEM → `AsymmEncAlg`, `KEMScheme`, Fujisaki–Okamoto
(`VCVio/CryptoFoundations/FujisakiOkamoto/{TTransform,UTransform}.lean`).

## Picking the file
- proof-level semantics / reductions → `Scheme.lean` / `Security.lean`
- FIPS algorithm structure → `Signature.lean`, `KEM.lean`, `Internal.lean`
- executable arithmetic/codec → `Concrete/`; FFI-backed → `Extern/`
- vector/differential failures → `LatticeCryptoTest/` then `Extern/` → `Concrete/` → `csrc/`
- generic game surfaces → `VCVio/CryptoFoundations/`

## Gotchas
- Keep proof-level and executable layers distinct.
- ML-DSA has IDS *and* FIPS signing layers — challenge/abort/rounding changes touch both.
- ML-KEM splits K-PKE / internal deterministic / checked KEM — change the lowest matching layer.
- Differential test breakage from pure-Lean edits → check serialization/endianness/sizes first.
- A `TqMatrix`-sampled MLWE problem shape is unusable for a reduction that must output a real
  encapsulation key (cannot invert `SampleNTT`); seed on `rho` instead (our `keyHopProblem`/
  `ctHopProblem` in `PqStealth/SPRTwoHop.lean`, `vcvio-upstream.md` item 6).
