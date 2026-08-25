# Tracking the VCVio pin

Standing checklist for issue #21 in `improvements.md`. VCVio is young and the
plan's rule is "pin a commit and don't float on main", so a bump is a
deliberate, reviewed act — not something a `lake update` should do behind our
backs.

## The current pin

| | |
|---|---|
| Package | `Verified-zkEVM/VCVio` |
| Revision | `a5f474fd0e9a26266cc599d100267411690dfeb7` |
| Upstream date | 2026-07-15 |
| Toolchain | `leanprover/lean4:v4.32.0` |
| Validated | 2026-07-25 (week-1 gate: `lake build LatticeCrypto` in the VCVio checkout, green) |
| Transitive deps | frozen in `lake-manifest.json` (mathlib `v4.32.0`, loom2, PolyFun, …) |

`lakefile.toml` also sets `autoImplicit = false`, `relaxedAutoImplicit = false`
and `linter.missingDocs = true` package-wide (issue #14), matching VCVio's own
package options.

## Bump procedure

1. **Edit the pin.** Change `rev` in `lean/lakefile.toml`. Leave the comment
   above it in place and update the date it quotes.
2. `lake update VCVio` — refreshes `lake-manifest.json`. Check the diff: a
   VCVio bump usually drags mathlib and the toolchain with it. If
   `lean-toolchain` moves, install the new toolchain first.
3. `lake exe cache get` — mathlib oleans. VCVio itself is **not** in the cache
   and compiles from source; a cold build is hours, not minutes.
4. `lake build` — must be green with no `warning:` or `error:` from
   `PqStealth/`.
5. **The axiom guard re-runs itself.** There is no separate command: the 114
   `#guard_msgs (whitespace := lax) in #print axioms …` blocks in
   `PqStealth/Axioms.lean` are part of the build, and a changed axiom list or a
   `sorry` anywhere in a headline theorem's dependency cone is a compile error.
   If a guard fails, do not edit the expected list to make it pass until you
   understand which upstream change moved it.
6. **Diff two upstream files for things to adopt:**
   - `LatticeCrypto/MLKEM/Security.lean` — the three `sorry`s at the pin
     (`kpke_ind_cpa_security`, `kpke_delta_correct`, `ind_cca_security`). If any
     of them becomes a proof, `docs/spr-two-hop.md` and `MLKEM.lean`'s "missing
     upstream lemma" section need rewriting.
   - `VCVio/CryptoFoundations/KeyEncapMech.lean` — at the pin it stops at
     `IND_CPA_*` / `IND_CCA_*` and has no anonymity notion at all. If a
     KEM-level anonymity / ANO-CCA definition lands, adopt it in place of our
     `KEM.AnonExp` / `KEM.anonAdvantage` (`KEMAnonymity.lean`) rather than
     keeping a parallel one.
7. Record the new pin and validation date in `README.md` ("Pin" section) and in
   the table above.

**Cadence:** once a month, or whenever upstream announces KEM anonymity or
proves one of the ML-KEM security placeholders.

## The three upstream asks

Things we carry locally only because VCVio does not export them. Each is a
small upstream PR; when one lands, delete our copy at the next bump.

(The full list, eleven items, is in `vcvio-upstream.md`; item 8 there was
retracted on 2026-08-19 — VCVio's programming-oracle bridge exists at the pin.)

1. **Ship `DecidableEq` next to `mlkem768Encoding`.**
   `LatticeCrypto/MLKEM/Concrete/Instance.lean` sets every encoded type to
   `ByteArray`, but as a plain `def`, so the equality instance does not
   transport. We re-derive all three by hand in `MLKEM.lean`
   (`instDecidableEqMlkem768Encoded{THat,U,V}`, each
   `inferInstanceAs (DecidableEq ByteArray)`). They belong beside the encoding.

2. **De-privatize `byteEncode_size`.**
   `LatticeCrypto/MLKEM/Concrete/Encoding.lean:242`,
   `private theorem byteEncode_size (d : Nat) (f : Rq) : (byteEncode d f).size = 32 * d`.
   It is exactly the fact we need for the `v` half of the FIPS 203 ciphertext
   layout; because it is `private` we take that byte count from the standard
   instead of proving it, and `MLKEM.lean`'s docstring lists it under
   "Assumed". Making it (or a public corollary) visible closes the only
   non-cryptographic assumption in that file.

3. **A KEM-level `kem_ind_cpa_security`.**
   `Security.lean` supplies `kpke_ind_cpa_security`, which is about K-PKE, not
   the KEM, and is `sorry` at the pin. The statement we want is recorded
   verbatim in `MLKEM.lean` under "The missing upstream lemma" — it elaborates
   as written against the pinned VCVio:

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

   The gap between the two is the T-transform half of Fujisaki–Okamoto. The day
   it lands, `mlkem768_unlinkAdvantage_le_indCpa` composes with it in a one-line
   `calc`.

## What in our tree is sensitive to a bump

Ordered by how loudly it fails.

- **`PqStealth/Axioms.lean` — 114 frozen `#print axioms` messages.** Failing
  loudly is the whole point, but note the *shape* is fragile too: the blocks use
  a 3-line form with `#print axioms` indented onto a continuation line. That is
  structurally incompatible with mathlib's `style.commandStart` linter — with
  `weak.linter.mathlibStandardSet = true` the linter's own warning is captured
  by `#guard_msgs` and turns every block into an error. Verified on this
  toolchain; that is why the lakefile enables `linter.missingDocs` but not the
  mathlib standard set. If a bump turns those linters on by default, reformat
  `Axioms.lean` to one-line commands rather than suppressing the linter.
- **`PqStealth/ROMUpToBad.lean` and `SPRTwoHop.lean` — the round-4 VCVio reach.**
  `ROMUpToBad` builds on `ProgramLogic/Relational/ProgrammingOracle.lean`
  (`QueryImpl.withProgramming`, `withCachingTrackingPolicy`, the engine
  `tvDist_simulateQ_run_le_probEvent_output_bad`, `relTriple_simulateQ_run'`)
  and re-proves upstream's `private` per-step agreement lemma; its `simp only`
  lists name `withProgramming_apply`, `withCachingTrackingPolicy_apply`,
  `StateT.run_mk`, `QueryImpl.withCaching_apply`. `SPRTwoHop` imports
  `VCVio.ProgramLogic.Tactics` and uses `by_equiv` / `rvcstep swap left` /
  `rvcgen` for the branch reorder — the only tactic-layer use in the tree, so a
  tactic-surface change upstream shows up there first.
- **Three VCVio modules that entered the cone in round 3.**
  `OracleComp/QueryTracking/RandomOracle/Basic.lean` (`OracleSpec.randomOracle`,
  used by `BlindingROM.lean`) and
  `OracleComp/QueryTracking/RandomOracle/DeferredSampling.lean` (+ its import
  `ProbeEps.lean`; `evalDist_bind_const_neverFails`, used by
  `MultiRecipient.lean`). Neither is reached by VCVio's own root import, so a
  bump that moves or renames them fails at *import resolution*, not at a lemma
  name. `dksapRomImpl` (and `BlindingROM.romImpl`) mirror VCVio's `PRF.prfIdealQueryImpl` line for line —
  if that handler's shape changes, copy the change across.
- **`PqStealth/Demo.lean` — 8 `#guard_msgs` around `#eval`.** Frozen numeric
  output. Only breaks if `ZMod 23` arithmetic or `Repr` output changes.
- **The pinned `simp only` lists (issue #18).** After the round-2 pass there is
  no bare `simp` left in `PqStealth/`, so every list is explicit and a rename
  upstream is a named-lemma error rather than a silent proof change. The
  exposed ones are the VCVio-internal names: `probOutput_bind_const`,
  `probFailure_of_liftM_PMF`, `probOutput_map_const`, `bind_map_left` in
  `dksap_perfectlyComplete` (`DKSAP.lean`), and `support_bind` /
  `probFailure_bind_eq_zero_iff` / `bind_map_left` in `Controls.lean`.
- **`PqStealth/SharedSecretHiding.lean` — the `evalDist` normal-form proofs.**
  `evalDist_uniformSample_bind_const`, `evalDist_bind_pull_front`,
  `indCpaGame_eq_evalDist_normalForm`, `evalDist_rorGame_eq_normalForm` reorder
  independent samples underneath `evalDist` using
  `evalDist_bind_bind_swap` / `evalDist_bind_congr'`. These are the deepest
  reach into VCVio's monadic API in the tree; if the `evalDist` API or the
  `OracleComp` bind normal form is reworked upstream, this file is where the
  work is.
- **`PqStealth/MLKEM.lean` — everything that names concrete ML-KEM-768
  internals.** The three `DecidableEq` instances become redundant (and possibly
  ambiguous) the moment upstream ships its own; the `Ciphertext` infiniteness
  argument depends on the encoded types staying `ByteArray`; the 1088-byte
  simulator depends on the FIPS 203 layout VCVio implements.
- **Reduction lemmas that name VCVio hypotheses:**
  `probOutput_bind_bijective_uniform_cross` (`DKSAP.lean`),
  `probOutput_bind_add_right_uniform` (`ConstructionA.lean`),
  `KEMScheme.PerfectlyCorrect ProbCompRuntime.probComp`
  (`perfectlyComplete_ofKEMFull`), `SIS.matrixProblem` (`Ownership.lean`).
- **Known lint findings we do not act on** (they resurface if the linter set
  widens): mathlib's non-default `explicitVarsOfIff` wants `ownership_iff_signing`
  and `ownershipValid_mldsaShort_iff_isSigningKey` to take implicit binders — we
  keep them explicit because both are headline statements cited from `docs/`;
  and `linter.unusedSectionVars` flags `[DecidableEq G]` on the three DKSAP
  soundness theorems in `Soundness.lean`, whose fix would be an `omit`, which the
  tree deliberately does not use.
