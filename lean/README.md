# PqStealth — machine-checked core (Lean 4 / VCVio)

The plan.md Lean deliverable, grown in two layers: the **algebraic core**
(blinded-key correctness identity, rounding-error bounds — the original
algebra-only scope) and the **security-game layer** (the scheme's security
experiments and their structural reductions, added 2026-07-31). All of it
sorry-free; every theorem depends only on `propext`, `Classical.choice`,
`Quot.sound` (checked via `#print axioms`). Full `lake build`: 2,762 jobs.

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
  (`IsOwnershipWitness`) is definitionally the possession of a signing key
  (`ownership_iff_signing`), and the blinded secret is such a witness for the
  derived key (`blinded_is_ownership_witness`, from the correctness identity).
- **Encoding roundtrip** — the on-chain stealth pk roundtrips via VCVio's
  encoding law (`stealth_pk_roundtrips`), and the meta-address wrapper roundtrips
  whenever the inner key packing does (`meta_address_roundtrips`).

## Security-game layer (2026-07-31)

Five modules formalize the security analysis's game layer on VCVio's
`OracleComp`/`ProbComp` framework, mirroring its own `AsymmEncAlg`/IND-CPA
idiom. The proved reduction skeleton, with the announcement modelled
faithfully as `(ciphertext, aux(sharedSecret))`:

```
unlinkability ≤ ssHidingTrue + (sprTrue + sprFalse) + ssHidingFalse
  ssHiding = KEM IND-CPA (real-or-random) → MLWE   [bridge + VCVio]
  SPR → 2·MLWE                                     [two-hop, documented]
spend forgery ≤ MSIS   (and the honest witness is always valid)
instantiated on VCVio's concrete ML-KEM
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
  pseudorandom.
- **`SharedSecretHiding.lean`** — each hiding term proved equal to a
  real-or-random guessing bias (i.e. a KEM IND-CPA advantage), plus the
  concrete VCVio `IND_CPA_Adversary` reduction adversaries (type-checked;
  the exact advantage equality across sample-reordering is documented glue).
- **`MLKEMInstance.lean`** — bridge to VCVio's concrete
  `MLKEM.asKEMScheme` (same `ProbComp` monad, identical fields); the
  unlinkability bound specialized to real ML-KEM.
- **`AnonymityFromSPR.lean`** — the open `anonymity → MLWE` arrow,
  structured: `anonAdvantage_le_sprAdv` proves anonymity ≤ per-branch
  ciphertext-pseudorandomness (the GMP / Maram–Xagawa route), and the
  capstone `…_full_decomposition` bounds unlinkability by four named,
  MLWE-reducible terms. The remaining lattice step (`SPR(K-PKE) ≤ 2·MLWE`,
  key hop then ciphertext hop) and the ANO-CCA/FO caveat are documented in
  the module docstring.
- **`Ownership.lean`** — spend-side: forging an ownership witness for
  `A·s + e = t` cast as VCVio's `SIS.Problem` (MSIS); `honest_witness_valid`
  shows the blinded secret always spends (via the correctness identity)
  while forgery is MSIS-hard.

What is *not* claimed: the computational assumptions at the bottom
(SPR two-hop, ANO-CCA lift through implicit-rejection FO, forking-lemma SoK
extraction) are paper-level, stated and cited in the docstrings.

## Pin (week-1 gate, validated 2026-07-25)

- VCVio `Verified-zkEVM/VCVio @ a5f474fd0e9a26266cc599d100267411690dfeb7`
  (2026-07-15), toolchain `leanprover/lean4:v4.32.0`; all transitive deps
  locked in `lake-manifest.json`.
- Gate result: `lake build LatticeCrypto` in the VCVio checkout — **green**
  (3017 jobs); the only `sorry`s in that tree are game-based Security files
  and Falcon, both out of scope.
- This package also builds **standalone** against the pinned dependency:
  `lake build` — green (2715 jobs), ending in `Built PqStealth.Blinding`.

## Build

```sh
elan toolchain install leanprover/lean4:v4.32.0
lake exe cache get   # mathlib binaries (~8.6k files)
lake build
```

(If `elan`'s downloader ever times out on `release.lean-lang.org`, the
toolchain zip can be fetched from the `leanprover/lean4` GitHub release
and linked with `elan toolchain link`.)
