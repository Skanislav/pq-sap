# PqStealth — machine-checked core (Lean 4 / VCVio)

<!-- Update the slug if the repository moves. -->
[![Lean](https://github.com/Skanislav/pq-sap/actions/workflows/lean.yml/badge.svg)](https://github.com/Skanislav/pq-sap/actions/workflows/lean.yml)

The plan.md Lean deliverable: an **algebraic core** (blinded-key correctness
identity, rounding-error bounds) and a **security-game layer** (the scheme's
security experiments and their structural reductions). All of it sorry-free;
every headline theorem depends only on `propext`, `Classical.choice`,
`Quot.sound` (or fewer), and that is asserted by the build rather than checked
by hand — see [Verifying](#verifying). Full `lake build`: green.

**Reading order:** `Demo` → `DKSAP` → `DKSAPOracle` → `Blinding` → `Games` →
`MultiUnlink` → `MultiRecipient` → `KEMAnonymity` → `ConstructionA` →
`BlindingROM` → `SharedSecretHiding` → `AnonymityFromSPR` → `MLKEM` →
`SPRTwoHop` → `Ownership` → `Soundness` → `Controls`. `Demo` is a runnable toy
instance, so it is the cheapest way in.

The design essays live in [`docs/`](docs/): `announcement-model.md` (the
announcement, `auxGen`, the decomposition, construction A, the controls),
`spr-two-hop.md` (KEM anonymity from SPR, the ML-KEM instantiation, the missing
upstream lemma), `msis-reshaping.md` (the spend side), `dksap-asymmetry.md`
(the classical comparison), `encodings.md` (the byte-level wire formats and
what VCVio does not supply). The Lean modules carry short docstrings and point
here.

## The proved decomposition

```
unlinkability ≤ sharedSecretHiding true + auxKeyIndependence
                + (sprAdv true + sprAdv false) + sharedSecretHiding false
  sharedSecretHiding = VCVio KEMScheme.IND_CPA_Advantage, exactly   [Lean]
                       (→ MLWE: paper-level; VCVio's K-PKE lemma is a `sorry`)
  auxKeyIndependence = the blinding term of construction A          [Lean model]
                       (= 0 for tag-only aux; → MLWE needs the address hash
                        as a random oracle: documented, not proved)
  sprAdv             ≤ primIdeal + 2·MLWE + simGap per branch  [two-hop; MLWE terms
                                                               named, outer terms documented]
spend forgery        = matrix-SIS advantage on [A | I | -t]   [Lean; uniform-challenge
                                                               gap documented]
instantiated on VCVio's ML-KEM-768 with no instance hypotheses on the ML-KEM types
```

## Module map

Eighteen content modules plus the axiom audit and the root.

Algebraic core (no probability, no games):

- **`Blinding.lean`** — `blinded_key_correctness`: `A·s' + e' + (A·s₁ + s₂) =
  A·(s₁+s') + (s₂+e')` over any commutative ring, so the sender's published
  value is the honest ML-DSA public key of the widened secret;
  `stealth_pk_eq_blinded_keypair`; the `Power2Round` error bound generically
  (`stealth_pk_rounding_error`) and at `q = 8380417`, `d = 13` (`≤ 2^12`).
- **`Invariants.lean`** — `cInfNorm_add_le` (centered-norm sub-additivity),
  hence `blinded_norm_bound` and `beta_blinded_eq_two_beta` (the signer bound
  doubles); `ownership_iff_signing` — the ownership relation *plus* the
  coefficient bound is possession of an ML-DSA signing key — and
  `blinded_is_signing_key`; the stealth-key encoding roundtrip, and both
  meta-address wire formats as concrete byte strings — `version ‖ rho ‖
  pack23(t) ‖ ek` at 5,633 B and the D-012 ZK-spend `version ‖ commitment ‖
  ek` at 1,217 B — with `meta_address_roundtrips{,_5633}` and
  `meta_address_zk_roundtrips{,_1217}` proved from `splitBytes_append`
  (`docs/encodings.md`).

Security-game layer (VCVio `OracleComp`/`ProbComp`):

- **`Games.lean`** — the abstract `StealthScheme`; detection completeness and
  the false-positive experiment; unlinkability as **recipient anonymity** (the
  hidden bit picks the *recipient*, not the message — key privacy, not
  IND-CPA), with `unlinkAdvantage_eq_branchDistAdvantage` as the first hop.
  The adversary is a function, and every hidden-bit game is indexed by the bit.
- **`MultiUnlink.lean`** — the `q`-challenge game `UnlinkExpMulti` against two
  fixed recipients and its hybrid bound `unlinkAdvantageMulti_le_sum`
  (`≤ ∑ k ∈ range q, unlinkAdvantage (hybridAdv …)`), hence
  `unlinkAdvantageMulti_le_mul` (`≤ q · ε`): the loss is linear in the number
  of announcements. Each hop is an `evalDist` equality
  (`evalDist_announceList_append_cons`) over the general telescoping lemma
  `boolDistAdvantage_le_sum_hybrids`, not a re-derivation.
- **`MultiRecipient.lean`** — the `n`-recipient game `UnlinkExpN`: `n`
  independently generated meta-addresses, the adversary NAMES the challenge
  pair. `unlinkAdvantageN_le_sum` (`≤ ∑ over ordered pairs of distinct indices,
  unlinkAdvantage (pairGuessAdv …)`), hence `unlinkAdvantageN_le_mul`
  (`≤ n·(n−1)·ε`). The one new fact is exchangeability of the `n` independent
  key generations (`evalDist_pubKeysN_embedPair`); the loss factor is a sum over
  disjoint gated games, not a conditioning argument.
- **`KEMAnonymity.lean`** — `KEM` *is* VCVio's `KEMScheme ProbComp`; the KEM
  anonymity game (absent from VCVio, which stops at IND-CCA); `ofKEM`
  (announcement = ciphertext, unlinkability *equals* anonymity) and `ofKEMFull`
  (view tag + stealth address folded in via `auxGen`, with a scan that
  recomputes and compares them, hence the `SK × PK` private state);
  `unlinkAdvantage_ofKEMFull_le`; `perfectlyComplete_ofKEMFull` from VCVio's
  own `KEMScheme.PerfectlyCorrect`.
- **`ConstructionA.lean`** — the real announcement inside the game model:
  `auxGen` = view tag plus `hashAddr (pack rho (power2Round (A·s' + e' + t)))`,
  with the symmetric primitives bundled uninterpreted as `Prims` and the
  samplers as `Samplers`; `stealthAddr_eq_blinded_pk`,
  `announced_key_isOwnershipWitness`,
  `auxKeyIndependence_eq_zero_of_pk_independent`, the seeded-MLWE
  `blindingProblem` with its reduction adversary, and `idealAux_indep_of_t`.
  Why the blinding term is *not* closed by MLWE alone (`rho` sits outside the
  mask) is in `docs/announcement-model.md`.
- **`BlindingROM.lean`** — the missing ingredient, modelled: `hashAddr ∘ pack`
  as VCVio's lazily sampled `randomOracle` over `unifSpec + (Bytes →ₒ Addr)`.
  `run_hashAddrRO_empty` (from the empty cache the announced address is uniform
  whatever was hashed — the step the mask cannot supply),
  `blindGameRO_eq` (the two branches are the same computation from caches
  differing at one point), `blindingAdvantageRO_eq_zero_of_no_query`, and the
  identical-until-bad step `blindingAdvantageRO_le_blindBadProb` (the blinding
  term is at most the two bad-query probabilities). The `Pr[bad]` bound
  (`mlwe + q_H · β`) is the documented gap.
- **`SharedSecretHiding.lean`** — each hiding term proved equal to a
  real-or-random guessing bias and then to VCVio's
  `KEMScheme.IND_CPA_Advantage` of the explicit reduction adversary
  `indCpaAdv … b` (`sharedSecretHiding_eq_indCpaAdvantage`; the sample
  reordering is proved, not documented), hence
  `unlinkAdvantage_ofKEMFull_le_indCpa`.
- **`AnonymityFromSPR.lean`** — the open `anonymity → MLWE` arrow, structured:
  `KEM.anonAdvantage_le_sprAdv` bounds anonymity by per-branch ciphertext
  pseudorandomness (the Grubbs–Maram–Paterson / Maram–Xagawa route), and
  `unlinkAdvantage_ofKEMFull_le_full_decomposition` is the five-term capstone.
- **`MLKEM.lean`** — ML-KEM-768: the `DecidableEq` instances VCVio's concrete
  encoding lacks; a machine-checked proof that **no** uniform distribution on
  the concrete ciphertext type exists (`ByteArray` is infinite), so the
  simulator is an explicit argument; the uniform-1088-byte FIPS 203 simulator;
  and `mlkem768_unlinkAdvantage_le`, `…_le_full_decomposition`,
  `…_le_indCpa` with no instance hypotheses on the ML-KEM types. The exact
  missing upstream lemma (`MLKEM.kem_ind_cpa_security`) is recorded verbatim.
- **`SPRTwoHop.lean`** — the SPR terms decomposed for ML-KEM-768: two
  seeded decision-MLWE problems (key hop `t = A·s+e` vs uniform; ciphertext
  hop over `[Âᵀ | t̂ᵀ]`), genuine reduction adversaries, **both hop
  identities proved**, and `mlkem768_sprAdv_le_two_hop_decomposition`:
  `sprAdv ≤ primitiveIdealization + MLWE + MLWE + simulatorGap`, the two
  residual terms named and unbounded (ROM/PRF derandomisation of the coins;
  encoding regularity). Implicit rejection provably never enters.
- **`Ownership.lean`** — the spend side: forging an ownership witness for
  `A·s + e = t` as VCVio's `SIS.Problem`, with `honest_witness_valid`; the
  `[A | I | -t]` reshaping into VCVio's homogeneous matrix-SIS with an
  *equality* of advantages (`spendForgeryAdvantage_eq_sis_advantage`), scored
  by exactly `SIS.matrixProblem`'s predicate
  (`augmentedSISProblem_isValid_eq_matrixProblem`); the ML-DSA instance.
- **`Soundness.lean`** — detection soundness, i.e. the false-positive rate.
  DKSAP's is *exactly* `1 / |F|` for every hash (`dksap_falsePositiveRate_eq`)
  — the leak is the recipient's uniform spending scalar, not a hash collision.
  For the KEM scheme, `falsePositiveRate_ofKEMFull_le` gives `ε + decapsRoR`
  (a tag-collision bound plus a named real-or-random term, KEM IND-CPA again),
  and `soundWithin_ofKEMFull_oneByteTag` is the ERC's `1/256`.

Classical comparison and controls:

- **`DKSAP.lean`** — the deployed dual-key scheme (ERC-5564 scheme 1), its
  completeness, the discrete-log key-recovery attack
  (`dksap_key_recovery` — key recovery, hence universal forgery), and its
  classical unlinkability bounded by two hashed-Diffie–Hellman terms, the
  idealized middle game contributing exactly zero, and each hashed-DH term
  bounded by VCVio's named DDH advantage plus entropy-smoothing advantage of
  `h`, with explicit reductions (`hashedDH_le_ddh_add_es`,
  `dksap_unlinkAdvantage_le_ddh_add_es`).
- **`Reorder.lean`** — `evalDist_pull₃ … ₆`: pull the `k`-th of `k`
  independent draws to the front; the game hops that are permutations of
  samples are a few rewrites with these.
- **`DKSAPOracle.lean`** — the attack with a real discrete-log oracle:
  `IsTotalQueryBound … 2` for any number of announcements (and not 1), and
  key recovery for every announcement under simulation; the random-oracle
  model of the hash: the idealized RO game is perfectly unlinkable with the
  adversary holding the oracle, the real game equals the ideal game against a
  cache programmed at the DH point, identical-until-bad closed
  (`unlinkAdvantageRO ≤ Pr[bad true] + Pr[bad false]`), the CDH reduction
  adversary type-checks; `Pr[bad] ≤ q_H · Adv_CDH` is the documented gap.
- **`ROMUpToBad.lean`** — VCVio's programming-oracle identical-until-bad
  engine instantiated for games over `unifSpec + hashSpec` (uniform queries
  forwarded, hash queries lazily sampled): the programmed/tracking pair, the
  two relational projections onto the plain random oracle, and the averaged
  bound `boolDistAdvantage_run'_cacheQuery_run'_empty_le` both ROM files use.
- **`Controls.lean`** — a recipient-leaking scheme has the maximal
  `unlinkAdvantage` (`1 − keyCollisionProb`, the true ceiling of the
  two-recipient game), and likewise a KEM whose ciphertext is the public key
  for `anonAdvantage`; a rejecting KEM breaks completeness; the tag-ignoring
  scan is complete but false-positives with probability `1`; a DKSAP variant
  that drops the spending key is not complete.
- **`Demo.lean`** — a runnable `ZMod 23` instance of DKSAP and its attack, with
  every `#eval` wrapped in `#guard_msgs`.
- **`Axioms.lean`** — 95 build-checked `#print axioms` assertions.

What is *not* claimed: the computational assumptions at the bottom
(KEM IND-CPA → MLWE, the SPR two-hop, the random-oracle step for the blinding
term, the ANO-CCA lift through implicit-rejection FO, forking-lemma SoK
extraction, uniform-challenge MSIS) are paper-level, stated and cited in
`docs/`. In particular VCVio's ML-KEM security theorems are `sorry`
placeholders at the pinned commit and nothing here depends on them.

## Pin (week-1 gate, validated 2026-07-25)

- VCVio `Verified-zkEVM/VCVio @ a5f474fd0e9a26266cc599d100267411690dfeb7`
  (2026-07-15), toolchain `leanprover/lean4:v4.32.0`; all transitive deps
  locked in `lake-manifest.json`.
- Gate result: `lake build LatticeCrypto` in the VCVio checkout — **green**;
  the only `sorry`s in that tree are game-based Security files and Falcon,
  both out of scope.
- This package also builds **standalone** against the pinned dependency:
  full `lake build` green.
- Bumping the pin is a reviewed act, not a `lake update`: the checklist, the
  three upstream asks, and the list of what in this tree is bump-sensitive are
  in [`docs/vcvio-pin.md`](docs/vcvio-pin.md).

## Build

```sh
elan toolchain install leanprover/lean4:v4.32.0
lake exe cache get   # mathlib binaries (~8.6k files)
lake build
```

(If `elan`'s downloader ever times out on `release.lean-lang.org`, the
toolchain zip can be fetched from the `leanprover/lean4` GitHub release
and linked with `elan toolchain link`.)

## Verifying

`lake build` *is* the check — there is nothing to run afterwards.

- **Sorry-freedom and the axiom basis** are asserted by
  `PqStealth/Axioms.lean`, which the root module imports. It carries 95
  `#guard_msgs (whitespace := lax) in #print axioms …` blocks, one per headline
  theorem, freezing that theorem's exact axiom list (mostly
  `propext, Classical.choice, Quot.sound`; the pure-algebra facts need less).
  A `sorry` introduced anywhere in a headline theorem's dependency cone adds
  `sorryAx` to its list and turns the mismatch into a compile error.
- **The runnable DKSAP demo** is asserted the same way:
  `PqStealth/Demo.lean` wraps each `#eval` in `#guard_msgs` (8 blocks, two of them
  running the instantiated scheme's own `scan` and `CorrectExp` through VCVio's
  `OracleComp.runIO`), so the
  numbers in its docstrings are checked, and the build prints nothing.
- **CI** (`.github/workflows/lean.yml`) runs exactly the two commands above
  on every push and pull request; the badge at the top of this file reports
  the result. Note that VCVio is not in the mathlib binary cache and compiles
  from source, so a run with a cold `lean/.lake` cache takes hours.
