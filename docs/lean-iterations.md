# Lean 4 core — current state and upcoming iterations

This document tracks the formal-core work separately from the main ADR log so
that the iteration queue can grow without renumbering `docs/DECISIONS.md`.
Last updated 2026-08-26.

## Current state

`lean/PqStealth/` is a **sorry-free** Lean 4 / VCVio formalization of the
post-quantum stealth-address scheme. The full `lake build` is green. Every
headline theorem's axiom list is frozen by `PqStealth/Axioms.lean`
(currently **114** `#print axioms` blocks). A `sorry` introduced anywhere
under a headline theorem's dependency cone turns the mismatch into a
compile error.

### VCVio pin

- Package: `Verified-zkEVM/VCVio`
- Revision: `a5f474fd0e9a26266cc599d100267411690dfeb7` (2026-07-15)
- Toolchain: `leanprover/lean4:v4.32.0`
- All transitive deps frozen in `lean/lake-manifest.json`
- Bump procedure, upstream asks, and bump-sensitive files:
  `lean/docs/vcvio-pin.md`

### Module inventory (18 content modules)

Algebraic core (no probability):

- `Blinding.lean` — blinded-key correctness identity over any commutative
  ring; `Power2Round` error bound generically and at ML-DSA-65 parameters.
- `Invariants.lean` — centered-norm sub-additivity, widened signer bound,
  ownership ↔ signing-key possession, byte-level meta-address roundtrips
  (5,633 B and 1,217 B variants).

Security-game layer (VCVio `OracleComp` / `ProbComp`):

- `Games.lean` — abstract `StealthScheme`, detection completeness and
  false-positive experiment, two-recipient unlinkability as recipient
  anonymity.
- `MultiUnlink.lean` — `q`-challenge hybrid bound, loss `≤ q·ε`.
- `MultiRecipient.lean` — `n`-recipient pair-guessing bound, loss
  `≤ n·(n−1)·ε`.
- `KEMAnonymity.lean` — `KEM = VCVio.KEMScheme ProbComp`; anonymity game,
  `ofKEM`/`ofKEMFull` (scan recomputes aux data using `SK × PK` state).
- `ConstructionA.lean` — real announcement model; sanity lemmas for
  `auxKeyIndependence`; seeded-MLWE reduction adversary.
- `BlindingROM.lean` — address hash as VCVio lazy random oracle; branch
  equality and identical-until-bad step.
- `ROMUpToBad.lean` — reusable programming-oracle identical-until-bad
  engine.
- `SharedSecretHiding.lean` — hiding terms equal to VCVio
  `KEMScheme.IND_CPA_Advantage`, sample reordering proved.
- `AnonymityFromSPR.lean` — full five-term unlinkability capstone.
- `MLKEM.lean` — ML-KEM-768 instances; concrete capstones with no instance
  hypotheses; explicit 1088-byte simulator (uniformity on `ByteArray` is
  provably uninhabited).
- `SPRTwoHop.lean` — SPR two-hop decomposition for ML-KEM-768; both hop
  identities proved; residual `primitiveIdealization` and `simulatorGap`
  named.
- `Ownership.lean` — spend forgery as VCVio matrix-SIS with equality of
  advantages.
- `Soundness.lean` — detection soundness / false-positive rates.

Classical comparison and controls:

- `DKSAP.lean` — classical dual-key scheme, completeness, key-recovery
  attack, ROM/DDH+ES unlinkability bound.
- `DKSAPOracle.lean` — discrete-log oracle attack with exactly two
  queries; ROM/DDH bound skeleton closed.
- `Controls.lean` — positive and negative controls.
- `Demo.lean` — runnable `ZMod 23` DKSAP instance.

Build / docs infrastructure:

- `Axioms.lean` — 114 build-checked `#print axioms` assertions.
- `lean/scripts/check_citations.py` — stdlib-only; resolves `` `File.lean:N-M` ``
  citations in `lean/docs/` and `lean/README.md` against the named declaration.
- `lean/scripts/check_sizes.py` — stdlib-only; compares proved byte sizes with
  `python/vectors/**/vectors.json`.

### Proved decomposition

```
unlinkability ≤ sharedSecretHiding true + auxKeyIndependence
                  + (sprAdv true + sprAdv false) + sharedSecretHiding false
  sharedSecretHiding = VCVio KEMScheme.IND_CPA_Advantage, exactly    [Lean]
                       (→ MLWE: paper-level; VCVio's K-PKE lemma is sorry)
  auxKeyIndependence = the blinding term of construction A           [Lean model]
                       (= 0 for tag-only aux; → MLWE needs the address hash
                        as a random oracle: documented, not proved)
  sprAdv             ≤ primitiveIdealization + 2·MLWE + simGap per branch
                       [two-hop; MLWE terms named, outer terms documented]
spend forgery        = matrix-SIS advantage on [A | I | -t]          [Lean;
                       uniform-challenge gap documented]
instantiated on VCVio's ML-KEM-768 with no instance hypotheses on ML-KEM types
```

### What is still paper-level

The bottom computational assumptions are not closed in Lean:

1. **KEM IND-CPA → MLWE.** VCVio's `kpke_ind_cpa_security` is a `sorry`
   placeholder at the pin and concerns K-PKE, not the KEM. The desired
   KEM-level lemma is recorded verbatim in `MLKEM.lean`.
2. **SPR residuals.** `primitiveIdealization` (ROM/PRF derandomisation of
   ML-KEM coins) and `simulatorGap` (encoding regularity) are named but not
   bounded.
3. **ANO-CCA lift** through the implicit-rejection Fujisaki–Okamoto
   transform.
4. **Forking-lemma SoK extraction** for the ZK ownership proof.
5. **Uniform-challenge MSIS absorption** step on the spend side.

Each is cited and stated in module docstrings and in `lean/docs/`.

## Upcoming iterations

Acceptance criterion for every item: **sorry-free, `lake build` green,
axiom guard updated if new headline theorems are added.**

### Issue #22 (part) — view-tag hash in Lean

Add the `LeanSha256` view-tag instantiation to the concrete ML-KEM-768
announcement model, and wire `lean/scripts/check_sizes.py` into CI so a
drifted byte size fails the build. Status: scripts landed; `LeanSha256`
integration and CI wiring remain.

- Acceptance: `check_sizes.py` runs in `.github/workflows/lean.yml`; a size
  mismatch is a CI failure; no `sorry`.

### Issue #16 — license headers

Now that the repo is public under MIT, add the standard SPDX MIT header to
each `lean/PqStealth/*.lean` file without disturbing the existing module
 docstring.

- Acceptance: every Lean module has a one-line `/- Copyright … MIT -/`
  header; `lake build` still green.

### SPR residual terms

- `primitiveIdealization`: bound the ROM/PRF advantage of replacing
  ML-KEM's rejection-sampled coins with uniform ones in the SPR game.
- `simulatorGap`: bound the statistical distance between the FIPS 203
  ciphertext distribution and the uniform 1088-byte simulator used in the
  ML-KEM-768 capstones.

- Acceptance: both terms become explicit named advantages with reduction
  adversaries, or a clear paper-level bound is recorded in `lean/docs/`.

### KEM IND-CPA → MLWE composition

The moment VCVio ships a KEM-level `kem_ind_cpa_security` (ask 3 in
`vcvio-pin.md`), compose it with `sharedSecretHiding_eq_indCpaAdvantage` so
that `mlkem768_unlinkAdvantage_le` closes at MLWE in one `calc` block.

- Acceptance: theorem `mlkem768_unlinkAdvantage_le_mlwe`.

### DKSAP ROM/DDH bound closure

Finish `DKSAPOracle.lean`: prove the final `Pr[bad] ≤ q_H · Adv_CDH` step.
`docs/dksap-asymmetry.md` and `ROMUpToBad.lean` contain the prerequisites;
the gap is now small and explicitly pinned.

- Acceptance: the bound is a theorem with named reduction adversary.

### BlindingROM `Pr[bad]` bound

Record the explicit `mlwe + q_H · β` bound in `BlindingROM.lean` and tie
it back to `auxKeyIndependence`. The identical-until-bad engine is ready;
what remains is the MLWE reduction for a single hash query and a clear
statement of the address-hash random-oracle model.

- Acceptance: `blindingAdvantageRO` bounded by an MLWE advantage plus a
  hash-query term, or the paper-level bound is documented.

### VCVio pin maintenance

Review the VCVio pin monthly, or immediately if upstream announces KEM
anonymity or proves one of the ML-KEM security placeholders. The bump
procedure in `lean/docs/vcvio-pin.md` is the source of truth.

- Acceptance: each bump produces a green `lake build`, an updated
  `lake-manifest.json`, and a refreshed axiom guard.

### README / doc alignment

Reconcile the README's stated axiom count (it still says 95 in places)
with the actual 114 blocks. Refresh the module map if any module names
drift. Keep `docs/lean-iterations.md` synchronized with the module
inventory.

- Acceptance: README and this file agree on the axiom count and module
  list; citation script passes.
