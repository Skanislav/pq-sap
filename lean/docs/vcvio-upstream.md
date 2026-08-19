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
   We declared it in VCVio's namespace from our tree (`SPRTwoHop.lean`);
   it belongs in `LatticeCrypto/HardnessAssumptions/LearningWithErrors.lean`.

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

8. **A game-body identical-until-bad / lazy-RO switching lemma.**
   `StateSeparating/IdenticalUntilBad.lean` compares two
   `QueryImpl.Stateful` *handlers* against a shared adversary with an
   explicit `σ × Bool` bad flag. Two of our proofs need the other shape:
   two *game bodies* that coincide unless the adversary queries a random
   oracle at one specific point, run under the plain lazily-sampled
   `OracleSpec.randomOracle`:
   - `PqStealth/DKSAPOracle.lean`: `hashedDHRO ≤ dksapROBadProb` (the real
     game is already proved equal to the ideal game against a cache
     programmed at the DH point — `dksapRORun_eq`; only the switching
     lemma is missing);
   - `PqStealth/BlindingROM.lean`: the bound on the blinding term
     (`blindGameRO_eq` shows the two branches are one computation from
     caches differing at a single point).
   One general lemma closes both. This is the highest-value upstream
   contribution on this list.

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

1, 2, 3, 4 and 8 as issues (each with the failing snippet) — clear, small
asks with a concrete proposed change. 5, 6, 7 as one discussion thread —
they are roadmap items for VCVio's ML-KEM security story and our seeded-hop
finding is useful input to it. 9, 10, 11 as low-priority issues.
