# VCVio: what this development found missing or wrong upstream

Everything below was discovered while building `lean/PqStealth/` against
`Verified-zkEVM/VCVio @ a5f474fd` (2026-07-15, Lean `v4.32.0`; see
`vcvio-pin.md` for the pin and bump procedure). Each item says what we carry
locally because of it, where it bit, and what the upstream change would be.
Nothing here has been filed upstream yet (status as of 2026-08-19).

Grouped by what the change would cost on VCVio's side.

## A. Small, mechanical — one PR each

1. **`DecidableEq` next to `mlkem768Encoding`.**
   `LatticeCrypto/MLKEM/Concrete/Instance.lean` sets every encoded type
   (`EncodedTHat`, `EncodedU`, `EncodedV`) to `ByteArray`, but through a
   plain `def concreteEncoding`, so instance search cannot see through it.
   Consequence: `MLKEM.asKEMScheme concreteNTTRingOps mlkem768Encoding
   mlkem768Primitives` does not elaborate in a downstream file without
   hand-derived instances. We carry three in `PqStealth/MLKEM.lean`
   (`instDecidableEqMlkem768Encoded{THat,U,V} := inferInstanceAs
   (DecidableEq ByteArray)`).
   Upstream: `@[reducible]` on `concreteEncoding`, or ship the three
   instances beside `mlkem768EncodingLaws`.

2. **De-privatize `byteEncode_size`.**
   `LatticeCrypto/MLKEM/Concrete/Encoding.lean:242`:
   `private theorem byteEncode_size (d : Nat) (f : Rq) : (byteEncode d f).size = 32 * d`.
   It is exactly the fact needed for the `v` half of the FIPS 203
   ciphertext layout (`32·dv = 128` bytes at ML-KEM-768). Because it is
   `private` we take that count from the standard; it is the only
   non-cryptographic assumption in `PqStealth/MLKEM.lean`.
   Upstream: make it (or a public corollary) visible.

3. **`SampleableType` on `R_q` / `T_q`.**
   VCVio never constructs uniform sampling on its own polynomial rings
   (the MLDSA files take it as a hypothesis). Any MLWE statement over the
   concrete ring needs it; `PqStealth/SPRTwoHop.lean` adds
   `instSampleableTypeRq`, `instSampleableTypeTq` and a `NeZero` instance
   for the ML-KEM modulus.
   Upstream: provide the instances in `LatticeCrypto/MLKEM/Arithmetic.lean`
   (or wherever `Rq`/`Tq` live).

4. **`LearningWithErrors.advantage_eq_boolDistAdvantage`.**
   The bridge `advantage = (game0).boolDistAdvantage (game1)` is what lets a
   decision-MLWE term enter a `boolDistAdvantage_triangle` chain at all.
   We carry it as `PqStealth.LearningWithErrors.advantage_eq_boolDistAdvantage`
   (`SPRTwoHop.lean`); it belongs in
   `LatticeCrypto/HardnessAssumptions/LearningWithErrors.lean`.

4b. **Four small `boolDistAdvantage` lemmas** (`CryptoFoundations/SecExp.lean`
   has only `boolDistAdvantage_triangle`): `boolDistAdvantage_comm`,
   `boolDistAdvantage_congr` (transport along `𝒟[p] = 𝒟[p']`),
   `boolDistAdvantage_le_sum_hybrids` (telescoping over `ℕ`-indexed hybrids)
   and `boolBiasAdvantage_bind_uniformBool_branch` (the bit-indexed-branch
   form of `boolBiasAdvantage_bind_uniformBool_eq_boolDistAdvantage`). All
   carried under `PqStealth.ProbComp.*` (`Games.lean`, `MultiUnlink.lean`).

## B. Medium — real proving, but well-specified

5. **A KEM-level `kem_ind_cpa_security` for `MLKEM.asKEMScheme`.**
   VCVio has `kpke_ind_cpa_security` (about K-PKE, and `sorry` at the pin)
   and nothing about the KEM's `KEMScheme.IND_CPA_Advantage`. The exact
   statement we need is recorded verbatim in `PqStealth/MLKEM.lean`
   ("The missing upstream lemma") and elaborates as written:

   ```lean
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

   The gap to `kpke_ind_cpa_security` is the T-transform half of
   Fujisaki–Okamoto. When it lands, `mlkem768_unlinkAdvantage_le_indCpa`
   composes with it in a one-line `calc`.

6. **Un-`sorry` `LatticeCrypto/MLKEM/Security.lean`.**
   `kpke_ind_cpa_security`, `kpke_delta_correct`, `ind_cca_security` are
   placeholders at the pin. Downstream prose easily mistakes them for
   theorems (we did, and had to scrub "VCVio reduces … to MLWE" from our
   docs). A note worth passing along from `SPRTwoHop.lean`: the two MLWE
   hops their K-PKE proof needs are the same two we proved, but **seeded on
   `rho`** — a reduction must output a real encapsulation key and cannot
   invert `SampleNTT`, so the announced `TqMatrix`-sampled problem shape is
   unusable for the reduction adversary. The seeded shape
   (`keyHopProblem`, `ctHopProblem` in our tree) is the one that composes.

7. **KEM anonymity (ANO-CPA / ANO-CCA) in `CryptoFoundations/KeyEncapMech.lean`.**
   VCVio stops at IND-CCA. Recipient unlinkability of a stealth scheme is
   key privacy, not message privacy, so we define the anonymity game
   ourselves (`PqStealth.KEM.AnonExp`, the hidden bit picks the public
   key). Upstream should own that definition; `vcvio-pin.md` says to adopt
   theirs the moment it exists. References: Grubbs–Maram–Paterson
   (EC'22), Maram–Xagawa (PKC'23).

## C. Framework-level — the ones that blocked round 3

8. **RETRACTED (2026-08-19): the lazy-RO switching lemma exists.**
   We had recorded that only `StateSeparating/IdenticalUntilBad.lean`
   (two `QueryImpl.Stateful` handlers, explicit `σ × Bool` flag) was
   available. At the pin VCVio also has
   `ProgramLogic/Relational/ProgrammingOracle.lean`:
   `tvDist_simulateQ_randomOracle_withProgramming_le_probEvent_bad`,
   `programming_collision_bound[_qP_qH_β]`, built on the generic engine
   `tvDist_simulateQ_run_le_probEvent_output_bad`
   (`ProgramLogic/Relational/SimulateQ.lean`) and
   `QueryImpl.withProgramming` / `withCachingTrackingPolicy`
   (`OracleComp/QueryTracking/ProgrammingOracle.lean`). What it does *not*
   cover is our spec shape `unifSpec + hashSpec` with uniform forwarding
   (`unifFwdImpl + randomOracle`, the same shape as `Examples/BR93.lean`,
   whose up-to-bad step is `sorry` at the pin). We instantiated the engine
   for that shape in `PqStealth/ROMUpToBad.lean` (`programmedROImpl`,
   `trackingROImpl`, the two `relTriple_simulateQ_run'` projections, and
   the averaged `boolDistAdvantage_run'_cacheQuery_run'_empty_le`); both
   `DKSAPOracle` and `BlindingROM` now close their identical-until-bad
   steps with it.
   Remaining upstream asks from this: (a) the per-step agreement lemma
   `probOutput_withProgramming_eq_withCachingTrackingPolicy_of_not_bad_output'`
   is `private` — we had to re-prove it; (b) a `unifSpec + hashSpec`
   (`unifFwdImpl + so`) variant of the bridge, or a general lemma that a
   uniform-forwarding component can be peeled off, would make ours
   unnecessary; (c) the symmetric half of the fundamental lemma
   (`Pr[flag | programmed run] = Pr[flag | tracking run]`) is not stated.

9. **Reachability of the random-oracle modules.**
   `OracleComp/QueryTracking/RandomOracle/Basic.lean`
   (`OracleSpec.randomOracle`) and
   `OracleComp/QueryTracking/RandomOracle/DeferredSampling.lean` (+ its
   `ProbeEps` import) are not reachable from VCVio's root import; we had to
   build them into the shared packages dir by hand. An import-graph fix.
   Also: programmability ("run against a cache that already maps `x ↦ y`")
   is something we reconstructed ad hoc in `DKSAPOracle.lean`; a small API
   for it next to `randomOracle` would help.

10. **`Vector`/`Bytes` uniform-projection lemma.**
    "The first byte of a uniform 32-byte string is a uniform byte" is not
    provable in-tree at the pin, so `PqStealth/Soundness.lean`'s 1-byte
    view-tag bound carries `viewTag` uniformity as a hypothesis. A lemma
    `probOutput_map_get_uniformSample_vector` (or similar) in
    `OracleComp/Constructions/SampleableType.lean` would discharge it.

## D. Non-code

11. **`mathlibStandardSet` linters vs. `#guard_msgs in #print axioms`.**
    With `weak.linter.mathlibStandardSet = true`, the `style.commandStart`
    warning produced by a `#print axioms` on a continuation line is
    captured by `#guard_msgs` and turns every audit block into an error.
    Verified on this toolchain. It discourages exactly the build-enforced
    axiom audit a downstream user should adopt. Worth a report; the
    workaround is one-line commands.

## Suggested filing order

1, 2, 3, 4, 4b and the three residual asks under 8 as issues (each with
the failing snippet) — clear, small asks with a concrete proposed change. 5, 6, 7 as one discussion thread —
they are roadmap items for VCVio's ML-KEM security story and our seeded-hop
finding is useful input to it. 9, 10, 11 as low-priority issues.
