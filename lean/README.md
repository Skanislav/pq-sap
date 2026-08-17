# PqStealth — machine-checked core (Lean 4 / VCVio)

<!-- Update the slug if the repository moves. -->
[![Lean](https://github.com/Skanislav/pq-sap/actions/workflows/lean.yml/badge.svg)](https://github.com/Skanislav/pq-sap/actions/workflows/lean.yml)

The plan.md Lean deliverable, grown in two layers: the **algebraic core**
(blinded-key correctness identity, rounding-error bounds — the original
algebra-only scope) and the **security-game layer** (the scheme's security
experiments and their structural reductions, added 2026-07-31). All of it
sorry-free; every theorem depends only on `propext`, `Classical.choice`,
`Quot.sound`, and that is asserted by the build rather than checked by hand
(see [Verifying](#verifying)). Full `lake build`: green.

**Reading order:** `Demo` → `DKSAP` → `Blinding` → `Games` → `KEMAnonymity`
→ `ConstructionA` → `SharedSecretHiding` → `AnonymityFromSPR` → `MLKEM768`
→ `Ownership`. `Demo` is a
runnable toy instance, so it is the cheapest way in; `PqStealth.lean` carries
the same map as a module docstring.

`PqStealth/Blinding.lean` contains, all sorry-free:

- `blinded_key_correctness` — `A·s' + e' + (A·s₁ + s₂) = A·(s₁+s') + (s₂+e')`
  over any commutative ring (so it instantiates at `R_q` for every ML-DSA
  parameter set): the sender's published value is exactly the honest ML-DSA
  public key of the widened secret, which is why the recipient can sign.
- `stealth_pk_eq_blinded_keypair` — the same with the meta key abstracted.
- `stealth_pk_rounding_error` — generic restatement of VCVio's
  `Power2RoundOps.Laws.power2Round_bound` for the announced (rounded) key.
- `stealth_pk_rounding_error_concrete` — instantiated at the concrete
  ML-DSA parameters (q = 8380417, d = 13) via VCVio's proven
  `MLDSA.Concrete.concretePower2RoundLaws`: error ≤ 2^12.

`PqStealth/Invariants.lean` extends the core with three more sorry-free results
(the in-scope Lean items from `docs/DECISIONS.md`):

- **Widened-bound signing invariant** — `cInfNorm_add_le` proves the centered
  infinity norm is sub-additive (via mathlib's `natAbs_valMinAbs_add_le`), so the
  blinded secret `s₁+s'` is `2·eta`-bounded (`blinded_norm_bound`), and the
  signer bound doubles: `beta' = tau·(2·eta) = 2·beta` against VCVio's `beta`
  (`beta_blinded_eq_two_beta`).
- **Ownership ↔ signing-key bridge** — the MLWE relation the Noir circuit proves
  (`IsOwnershipWitness`) *together with the coefficient bound* is possession of an
  ML-DSA signing key (`ownership_iff_signing`, `IsSigningKey`), and the blinded
  secret is such a key for the derived stealth key at the widened bound `2·eta`
  (`blinded_is_signing_key`, from the correctness identity and `blinded_norm_bound`).
- **Encoding roundtrip** — the on-chain stealth pk roundtrips via VCVio's
  encoding law (`stealth_pk_roundtrips`), and the meta-address wrapper roundtrips
  whenever the inner key packing does (`meta_address_roundtrips`).

## Security-game layer (2026-07-31)

The game layer is formalized on VCVio's `OracleComp`/`ProbComp` framework,
mirroring its own `AsymmEncAlg`/IND-CPA idiom. The proved reduction skeleton,
with the announcement modelled faithfully as
`(ciphertext, aux(sharedSecret, recipientPk))` and detection recomputing `aux`:

```
unlinkability ≤ ssHidingTrue + auxKeyIndep + (sprTrue + sprFalse) + ssHidingFalse
  ssHiding    = VCVio KEMScheme.IND_CPA_Advantage, exactly   [Lean]
                (→ MLWE: paper-level; VCVio's own K-PKE lemma is a `sorry` placeholder)
  auxKeyIndep = the blinding term of construction A          [Lean model; = 0 for tag-only aux]
                (→ MLWE needs a random-oracle model of the address hash: documented)
  SPR → 2·MLWE                                              [two-hop, documented]
spend forgery = matrix-SIS advantage on [A | I | -t]         [Lean; uniform-challenge gap documented]
instantiated on VCVio's ML-KEM-768 with no instance hypotheses on the ML-KEM types
```

- **`Games.lean`** — abstract `StealthScheme` (keygen/announce/scan in
  `ProbComp`); detection completeness; the unlinkability game stated as
  **anonymity** (the hidden bit picks the *recipient*, not the message — this
  is key privacy, not IND-CPA). `unlinkAdvantage_eq_branchDistAdvantage` is
  the first game hop.
- **`KEMAnonymity.lean`** — abstract `KEM`; the KEM anonymity game (absent
  from VCVio, which stops at IND-CCA); `ofKEM` (announcement = ciphertext,
  unlinkability *equals* anonymity) and `ofKEMFull` (view tag + stealth
  address folded in via `auxGen`); `unlinkAdvantage_ofKEMFull_le` — the
  auxiliary data hides the recipient exactly insofar as the shared secret is
  pseudorandom. `ofKEMFull.scan` recomputes the announced auxiliary data from
  the decapsulated secret and the recipient's own public key (a test "did
  decapsulation succeed" is vacuous on an implicit-rejection KEM like ML-KEM);
  `perfectlyComplete_ofKEMFull` proves detection from `KEM.PerfectlyCorrect`.
- **`GameControls.lean`** — controls for the game layer: a scheme announcing
  the recipient's meta-address has the maximal `unlinkAdvantage`
  (`1 − Pr[key collision]`, the true ceiling of the two-recipient game), and
  likewise a KEM whose ciphertext is the public key for `anonAdvantage`; on
  the negative side a rejecting KEM breaks completeness, and the scan without
  the tag comparison is complete but flags every announcement.
- **`ConstructionA.lean`** — the announcement of construction A inside the
  game model: `auxGen` = view tag plus `hashAddr (pack rho (power2Round
  (A·s' + e' + t)))` with the symmetric primitives as parameters;
  `stealthAddr_eq_blinded_pk` (the correctness identity used in the games),
  `auxKeyIndependence_eq_zero_of_pk_independent` (the term vanishes for
  tag-only aux — a sanity control), the seeded-MLWE reduction adversary for
  the blinding hop, and the uniform-mask independence lemma. The docstring
  explains why the blinding term is *not* bounded by MLWE alone: `rho` sits
  outside the mask, so closing it needs the address hash as a random oracle.
- **`SharedSecretHiding.lean`** — each hiding term proved equal to a
  real-or-random guessing bias and then to VCVio's
  `KEMScheme.IND_CPA_Advantage` of the explicit reduction adversary
  (`sharedSecretHidingTrue/False_eq_indCpaAdvantage`; the sample-reordering is
  proved, not documented); `unlinkAdvantage_ofKEMFull_le_indCpa`.
- **`SharedSecretHidingMLWE.lean`** — the same on VCVio's ML-KEM
  (`mlkem_unlinkAdvantage_le_indCpa`), and the precise statement of the
  KEM-IND-CPA → MLWE lemma VCVio does not yet provide.
- **`MLKEMInstance.lean`** — bridge to VCVio's concrete
  `MLKEM.asKEMScheme` (same `ProbComp` monad, identical fields); the
  unlinkability bound specialized to real ML-KEM.
- **`MLKEM768.lean`** — the ML-KEM-768 parameter set: the `DecidableEq`
  instances VCVio's concrete encoding lacks, a machine-checked proof that no
  uniform distribution on the concrete ciphertext type exists (`ByteArray` is
  infinite), the uniform-1088-byte simulator, and `mlkem768_unlinkAdvantage_le`
  / `…_full_decomposition` with no instance hypotheses on the ML-KEM types.
- **`AnonymityFromSPR.lean`** — the open `anonymity → MLWE` arrow,
  structured: `anonAdvantage_le_sprAdv` proves anonymity ≤ per-branch
  ciphertext-pseudorandomness (the GMP / Maram–Xagawa route), and the
  capstone `…_full_decomposition` bounds unlinkability by named terms with an
  explicit key-independent simulator. The remaining lattice step
  (`SPR(K-PKE) ≤ 2·MLWE`, key hop then ciphertext hop) and the ANO-CCA/FO
  caveat are documented in the module docstring.
- **`Ownership.lean`** — spend-side: forging an ownership witness for
  `A·s + e = t` as VCVio's `SIS.Problem`; `honest_witness_valid` shows the
  blinded secret always spends. The inhomogeneous instance is reshaped into
  VCVio's homogeneous matrix-SIS via `[A | I | -t]` with an *equality* of
  advantages (`spendForgeryAdvantage_eq_sis_advantage`), scored by exactly
  `SIS.matrixProblem`'s predicate; the remaining uniformity gap (HNF absorption,
  MLWE pseudorandomness of `t`) is documented in the module docstring.

What is *not* claimed: the computational assumptions at the bottom
(KEM IND-CPA → MLWE, SPR two-hop, the random-oracle step for the blinding
term, ANO-CCA lift through implicit-rejection FO, forking-lemma SoK
extraction, uniform-challenge MSIS) are paper-level, stated and cited in the
docstrings. In particular VCVio's ML-KEM security theorems are `sorry`
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
  `PqStealth/Axioms.lean`, which the root module imports. It carries one
  `#guard_msgs in #print axioms …` block per headline theorem, freezing that
  theorem's exact axiom list (mostly `propext, Classical.choice, Quot.sound`;
  the pure-algebra facts need less). A `sorry` introduced anywhere in a
  headline theorem's dependency cone adds `sorryAx` to its list and turns the
  mismatch into a compile error.
- **The runnable DKSAP demo** is asserted the same way:
  `PqStealth/Demo.lean` wraps each `#eval` in `#guard_msgs`, so the numbers
  in its docstrings are checked, and the build prints nothing.
- **CI** (`.github/workflows/lean.yml`) runs exactly the two commands above
  on every push and pull request; the badge at the top of this file reports
  the result. Note that VCVio is not in the mathlib binary cache and compiles
  from source, so a run with a cold `lean/.lake` cache takes hours.
