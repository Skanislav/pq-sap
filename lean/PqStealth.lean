import PqStealth.Blinding
import PqStealth.Invariants
import PqStealth.Games
import PqStealth.KEMAnonymity
import PqStealth.ConstructionA
import PqStealth.SharedSecretHiding
import PqStealth.AnonymityFromSPR
import PqStealth.MLKEM
import PqStealth.Ownership
import PqStealth.DKSAP
import PqStealth.Demo
import PqStealth.Controls
import PqStealth.Axioms

/-!
# PqStealth — machine-checked core for post-quantum stealth addresses

The library root: importing this module brings in the whole development and,
via `PqStealth.Axioms`, runs the axiom audit as part of the build.

## Module map

Algebraic core (no probability, no games):
* `PqStealth.Blinding` — the blinded-key correctness identity
  `A·s' + e' + (A·s₁ + s₂) = A·(s₁+s') + (s₂+e')` and the rounding-error
  bound for the announced (Power2Round-ed) stealth key.
* `PqStealth.Invariants` — the centered-norm sub-additivity that doubles the
  ML-DSA signer bound, the ownership ↔ signing-key bridge (with the
  coefficient bound), and the encoding roundtrips for the stealth key and the
  meta-address.

Security-game layer (VCVio `OracleComp`/`ProbComp`):
* `PqStealth.Games` — the abstract `StealthScheme`, detection completeness,
  and unlinkability stated as recipient anonymity.
* `PqStealth.KEMAnonymity` — the abstract `KEM`, its anonymity game and
  perfect correctness, and the two KEM-based schemes `ofKEM` (announcement =
  ciphertext, a teaching model) and `ofKEMFull` (view tag and stealth address
  folded in via `auxGen`, with a scan that recomputes and compares them).
* `PqStealth.ConstructionA` — the announcement of construction A
  (`auxGen` = view tag plus the hashed, packed, rounded blinded key), the
  proof that the announced key is the honest key of the widened secret, the
  aux key-independence sanity lemma, and the seeded-MLWE reduction adversary
  for the blinding hop.
* `PqStealth.SharedSecretHiding` — each hiding term as a real-or-random
  guessing bias, with the VCVio `IND_CPA_Adversary` reduction adversaries.
* `PqStealth.AnonymityFromSPR` — anonymity bounded by per-branch ciphertext
  pseudorandomness, and the full decomposition.
* `PqStealth.MLKEM` — the ML-KEM-768 instantiation: the decidable-equality
  instances VCVio's concrete encoding lacks, the uniform-ciphertext-bytes
  simulator, and the capstones with no instance hypotheses.
* `PqStealth.Ownership` — the spend side: forging an ownership witness cast
  as VCVio's `SIS.Problem`, reshaped into VCVio's matrix-SIS via
  `[A | I | -t]`, and validity of the honest witness.

Classical comparison and controls:
* `PqStealth.DKSAP` — the classical dual-key scheme, its completeness, the
  key-recovery attack a discrete-log oracle enables, and its unlinkability
  against a classical adversary, bounded by hashed-Diffie–Hellman terms.
* `PqStealth.Controls` — positive and negative controls: a recipient-leaking
  scheme has maximal unlinkability advantage, a dead KEM is not complete, a
  tag-ignoring scan is complete but not sound, and a deliberately broken DKSAP
  variant that the completeness definition rejects.
* `PqStealth.Demo` — a runnable `ZMod 23` instance of DKSAP and its attack.
* `PqStealth.Axioms` — build-checked `#print axioms` assertions for every
  headline theorem above.

## Reading order

`Demo` → `DKSAP` → `Blinding` → `Games` → `KEMAnonymity` → `ConstructionA` →
`SharedSecretHiding` → `AnonymityFromSPR` → `MLKEM` → `Ownership` →
`Controls`.
-/
