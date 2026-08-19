# Spend forgery as matrix-SIS: the reshaping, its gaps, and the follow-up

Background for `PqStealth/Ownership.lean`.

## The search core

Spending a stealth account means proving knowledge of a short `(s, e)` with
`A ·ᵥ s + e = t` — the signing-key relation from `Invariants.lean` — bound to
the transaction. Forging a spend therefore means producing such a witness for a
target `t` you were not given: an *inhomogeneous* Short Integer Solution
instance.

`Ownership.lean` does three things:

1. casts spend forgery as a VCVio `SIS.Problem`, with the honest side proved
   trivial (the blinded secret is always a valid witness);
2. reshapes that inhomogeneous instance into the *homogeneous* matrix-SIS shape
   VCVio's `SIS.matrixProblem` uses, via the standard `[A | I | −t]`
   augmentation, and proves the two advantages are **equal** — so the MSIS
   claim is a theorem about VCVio's predicate rather than a naming convention;
3. instantiates all of it at the ML-DSA ring `Rq` with the real centered
   infinity-norm bound, and shows the game-level validity predicate is exactly
   `IsSigningKey`.

Scope: this captures the SEARCH core (produce a witness = solve MSIS). The full
signature-of-knowledge unforgeability — message binding via Fiat–Shamir, the
forking-lemma extraction, HVZK — is the deeper reduction to `SelfTargetMSIS`;
see the follow-up at the end.

## The `[A | I | −t]` augmentation

VCVio's `SIS.matrixProblem` is the homogeneous problem: find a short nonzero
`z` with `M ·ᵥ z = 0`. The ownership problem is inhomogeneous. The standard
bridge is the augmentation `M = [A | I | −t]`, under which

```
M ·ᵥ (s, e, 1) = A ·ᵥ s + e − t
```

so kernel vectors whose last coordinate is `1` are exactly the ownership
witnesses, with `e` absorbed by the identity block. Carrying the marker `1` in
the shortness predicate (`augmentedShort`) makes the correspondence a bijection
on *valid* solutions, so the advantages are equal, not merely comparable. The
marker also supplies the `z ≠ 0` conjunct of VCVio's matrix-SIS validity for
free (`augmentedWitness_ne_zero`).

`readKey` reads the ownership key back off an augmented matrix — `A` is the
left block, `t` the negated last column — and is a left inverse of
`augmentedMatrix`. That is what lets a forger for the homogeneous problem be
built from an ownership forger (`augmentedAdversary`).

`spendForgeryAdvantage_eq_sis_advantage` is the resulting equality;
`spendForgeryAdvantage_le_augmentedSIS` is its `≤` form for chaining;
`honest_augmented_witness_valid` is the non-vacuity check — a real ownership
solution maps to a real kernel vector, so the equality is not between two
unsatisfiable predicates.

## ℝ≥0∞ versus ℝ

VCVio states search advantages in `ℝ≥0∞` (`SIS.advantage` is a `probOutput`),
while every distinguishing advantage in this development
(`ProbComp.boolDistAdvantage` and the KEM/MLWE bounds built on it) is `ℝ`. The
`ℝ≥0∞` form is kept as the definition of `spendForgeryAdvantage` — it is the
one that is definitionally VCVio's — and `spendForgeryAdvantageReal` is the `ℝ`
view used when a spend bound has to be added to, or chained with, those
advantages. Nothing is lost in the conversion: the advantage is a probability,
hence finite (`spendForgeryAdvantage_ne_top`).

## What is proved and what is assumed

`spendForgeryAdvantage_eq_sis_advantage` is an exact **reshaping**: it puts
spend forgery into VCVio's homogeneous matrix-SIS shape and shows the two
advantages are equal, with the scoring function equal on the nose to
`SIS.matrixProblem`'s (`augmentedSISProblem_isValid_eq_matrixProblem`, at
`n = k`, `m = l + k + 1`). It is **not** yet a reduction to the standard
uniform-MSIS assumption, because
`(augmentedSISProblem keyGen isShort).sampleChallenge` is the scheme's
distribution `keyGen >>= (pure ∘ augmentedMatrix)`, whereas
`(SIS.matrixProblem k (l+k+1) isShort').sampleChallenge` is
`$ᵗ Matrix (Fin k) (Fin (l+k+1)) R`.

Two statements close that gap; neither is proved.

* **HNF absorption.** A challenge of the shape `[A | I | −t]` is as hard as a
  uniform one. Precisely: for every `adv` there exists `adv'` with

  ```
  SIS.advantage (augmentedSISProblem uniformKeyGen isShort) adv ≤
  SIS.advantage (SIS.matrixProblem k (l+k+1) (augmentedShort isShort)) adv'
  ```

  where `uniformKeyGen` samples `A` and `t` uniformly. The textbook proof
  column-reduces a uniform challenge into Hermite normal form, which over a
  module ring needs an invertible `k × k` block — the `Rq`-specific step.

* **Target pseudorandomness.** The real `keyGen` is an MLWE sample: `A` is
  uniform but `t = A ·ᵥ s₁ + s₂` with `(s₁, s₂)` short. Replacing it by
  `uniformKeyGen` costs the MLWE distinguishing advantage. Precisely, for every
  `adv` the two advantages
  `SIS.advantage (augmentedSISProblem mlweKeyGen isShort) adv` and
  `SIS.advantage (augmentedSISProblem uniformKeyGen isShort) adv` differ by at
  most the advantage of the derived distinguisher against
  `LearningWithErrors.moduleMatrixProblem` — the same assumption the detection
  side of this development already uses.

Chaining the proved equality with those two gives
`spendForgeryAdvantage ≤ msisAdvantage + mlweAdvantage`, the bound the spec
claims.

## The ML-DSA instance

Everything above at `R := Rq`, with `isShort := mldsaShort bound` the real
ML-DSA range check: every coordinate polynomial of `s` and of `e` has centered
infinity norm at most the bound. The Boolean predicate the game uses is then
decidably equivalent to `IsSigningKey` from `Invariants`
(`ownershipValid_mldsaShort_iff_isSigningKey`), so "the adversary wins the SIS
game" and "the adversary produced a signing key it was never given" are the
same statement. `mldsa_spendForgeryAdvantage_eq_sis_advantage` is the
reshaping at that instance.

`Rq` is nontrivial (`rq_one_ne_zero`, and the `Nontrivial Rq` instance built on
it): the constant polynomial `1` differs from `0` in its degree-zero
coefficient. That is needed for the `z ≠ 0` conjunct of matrix-SIS validity.

## Follow-up: signature-of-knowledge unforgeability

What is proved is the *search* core: a spend is a witness for an MSIS instance,
and forging one is solving that instance. The spend actually deployed (decision
D-012) is a signature of knowledge — the ownership witness proved in zero
knowledge and bound to the transaction — so full unforgeability is EUF-CMA of a
Fiat–Shamir-with-aborts signature, not just hardness of the search problem.

The route, none of which is implemented:

* Package the ownership relation as a Sigma protocol
  (`VCVio/CryptoFoundations/SigmaProtocol.lean`): commitment `A ·ᵥ y`,
  challenge `c` from `sampleInBall`, response `z = y + c · s` with rejection
  sampling at the widened bound `2·beta` (`beta_blinded_eq_two_beta`).
* Prove special soundness and HVZK for it; the widened bound is exactly what
  the blinded secret needs (`blinded_is_signing_key`).
* Apply VCVio's Fiat–Shamir transform to get a signature of knowledge, with the
  transaction as the bound message.
* Reduce EUF-CMA of the result to `SelfTargetMSIS.Problem`
  (`LatticeCrypto/HardnessAssumptions/ShortIntegerSolution.lean`), which is the
  assumption ML-DSA's own unforgeability rests on; the extraction step is the
  forking lemma over the random oracle already modelled by
  `SelfTargetMSIS.experiment`.
