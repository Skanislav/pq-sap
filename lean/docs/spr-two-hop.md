# KEM anonymity from SPR: the two-hop route, and what is missing upstream

Background for `PqStealth/KEMAnonymity.lean`, `PqStealth/AnonymityFromSPR.lean`,
`PqStealth/SharedSecretHiding.lean` and the ML-KEM modules. It records the
lattice route the analysis takes, the caveats that route carries, and the exact
shape of the upstream lemma that is not available.

## The teaching point

A stealth scheme's UNLINKABILITY reduces to the KEM's ANONYMITY — does a
ciphertext hide which public key it was encapsulated to — NOT to IND-CCA, which
hides the message. VCVio ships ML-KEM IND-CCA statements (its MLWE reductions
are `sorry` at the pinned commit) but NOT anonymity, so the anonymity
assumption is stated in `KEMAnonymity.lean` in the same shape VCVio uses for
its own games, and the reduction is proved there.

The anonymity game is the hidden-bit game with the bit selecting which of two
public keys the challenge ciphertext is encapsulated to; the adversary sees
both public keys and the ciphertext. The distinguisher is exactly
`StealthScheme.UnlinkAdv PK C` — a key-privacy adversary and an unlinkability
adversary have the same shape.

Still open beyond that file: anonymity → MLWE for ML-KEM, the deeper piece
VCVio does not cover (Grubbs–Maram–Paterson), which is where the novel work
sits.

## The SPR route (Grubbs–Maram–Paterson EC'22; Maram–Xagawa PKC'23)

Neither VCVio nor FIPS 203 supplies `anonymity → MLWE` for ML-KEM. The route
the literature takes goes through SPR — *strong pseudorandomness* of
ciphertexts: a challenge ciphertext is indistinguishable from one produced by a
key-independent simulator (for ML-KEM: uniform bytes). If ciphertexts are
indistinguishable from key-independent, they cannot reveal which key they were
made for.

`AnonymityFromSPR.lean` machine-checks that implication and leaves the lattice
content as two named per-branch SPR quantities:

```
anonymity   ≤ SPR(branch true) + SPR(branch false)   -- proved, sorry-free
SPR(ML-KEM) ≤ 2 · MLWE                               -- the remaining lattice step
```

`KEM.simBranch sim adv` is the anonymity experiment's branch with the challenge
ciphertext replaced by a simulated one — computable without either public key,
so it carries no information about the hidden bit. `KEM.sprAdv kem sim adv b` is
the advantage of distinguishing the real branch `b` from that simulated branch,
in the full anonymity context. `KEM.anonAdvantage_le_sprAdv` is then one
triangle inequality through the simulated game.

### The two hops

The remaining step is the standard two-hop argument, recorded here for the
paper analysis:

1. Replace the challenge public key `t = A·s + e` by uniform (Decision-MLWE,
   secret `s`).
2. With `t` uniform, the ciphertext `(u, v) = (Aᵀr + e₁, tᵀr + e₂ + m)` is
   itself an MLWE sample with secret `r` over the extended matrix `[A | t]`,
   hence pseudorandom (Decision-MLWE again).

Both hops land on VCVio's `LearningWithErrors.advantage`.

### Caveats for the analysis

* This is the **CPA-level** statement. Lifting it to ANO-CCA must track ML-KEM's
  implicit-rejection Fujisaki–Okamoto transform (Maram–Xagawa).
* FIPS 203's final KDF hashes only the message-derived secret and does **not**
  hash the ciphertext. That is what makes the modular route applicable; a
  ciphertext-hashing KDF would need a different argument.

## The capstone

`unlinkAdvantage_ofKEMFull_le_full_decomposition` chains the SPR bound into
`unlinkAdvantage_ofKEMFull_le`, so stealth unlinkability with the complete
announcement decomposes into five named advantages:

* two shared-secret-hiding terms — each a KEM IND-CPA advantage
  (`SharedSecretHiding`; → MLWE is paper-level, VCVio's own K-PKE lemma being a
  `sorry` placeholder);
* the auxiliary-data key-independence term — the blinding argument
  (`ConstructionA`; needs a random-oracle model of the address hash, see
  `announcement-model.md`);
* two SPR terms — each → 2·MLWE by the two-hop argument above.

No unnamed slack: this is the complete reduction skeleton of the scheme's
privacy.

## Shared-secret hiding IS VCVio's KEM IND-CPA advantage

`unlinkAdvantage_ofKEMFull_le` bounds unlinkability by the anonymity advantage
plus two shared-secret-hiding terms. Those terms are exactly the KEM's IND-CPA
(real-or-random shared secret) advantage: the auxiliary announcement data hides
the recipient because the shared secret is pseudorandom.
`SharedSecretHiding.lean` proves that identity, sorry-free, in two steps.

1. Each hiding term is the bias of a real-or-random guessing game —
   `sharedSecretHiding_eq_rorBias`, where `rorGame kem auxGen adv b` is the KEM
   IND-CPA experiment restricted to the announcement adversary.
2. That bias equals VCVio's own `KEMScheme.IND_CPA_Advantage` of a concrete
   reduction adversary — `sharedSecretHiding_eq_indCpaAdvantage`.

### Why step 2 needs distribution-level reasoning

The two experiments draw the same independent samples (two keypairs, the hidden
bit, the encapsulation, an idealized shared secret) in different orders, and
one branch leaves one draw unused. `OracleComp`'s `bind` is a syntactic
free-monad constructor, so neither reordering nor dropping holds on the nose;
both hold after `evalDist`, which is all an advantage sees. The bridges are

* `evalDist_uniformSample_bind_const` — an unused uniform draw does not change
  the output distribution;
* `evalDist_bind_pull_front` — an independent draw may be pulled to the front
  of the prefix;
* `boolBiasAdvantage_congr` — equal output distributions, equal bias.

Both sides are put in a common normal form (`rorNormalForm kem auxGen adv b`):
hidden bit first, then the two keypairs in the order recipient 0, recipient 1,
then the challenge encapsulation, then the idealized shared secret. VCVio's
game draws the challenge keypair first and the hidden bit after the adversary's
pre-challenge phase; the real-or-random game draws the bit first and never
draws the idealized secret on the real branch.

`indCpaAdv kem auxGen adv b` is the reduction adversary: a VCVio
`KEMScheme.IND_CPA_Adversary` with `State := PK × PK`. The IND-CPA challenge
key is embedded as recipient `b`; the reduction generates the other recipient
itself, then feeds `auxGen (challenge key)` to the unlink distinguisher. The
state carries both public keys because the auxiliary data must be rebuilt from
the same key the real announcement used.

The orientation is uniform in `b`: the real shared secret sits on hidden bit
`true` on both branches, matching VCVio's convention.

Net effect: the shared-secret-hiding half of the unlinkability bound IS a KEM
IND-CPA advantage in VCVio's own formulation, so any bound proved for
`KEMScheme.IND_CPA_Advantage` transfers to it verbatim.

## What is NOT proved, because VCVio does not supply it

A bound on `KEMScheme.IND_CPA_Advantage` for ML-KEM in terms of MLWE.

`LatticeCrypto/MLKEM/Security.lean` offers `kpke_ind_cpa_security`, which is
about `AsymmEncAlg.IND_CPA_advantage` of **K-PKE** — the underlying public-key
encryption scheme — rather than `KEMScheme.IND_CPA_Advantage` of the KEM, and
which is itself `sorry` upstream, as are `kpke_delta_correct` and
`ind_cca_security` at the pinned commit.

The step between the two is the T-transform half of Fujisaki–Okamoto: the KEM's
shared secret is derived from a uniformly random message via a hash modelled as
a random oracle, so KEM IND-CPA follows from K-PKE IND-CPA plus message
entropy. Neither that reduction nor `kpke_ind_cpa_security` itself is in scope
here, so the ML-KEM modules state equalities and restated bounds, never an MLWE
bound; importing one would import `sorryAx`.

### The exact missing lemma

The statement below elaborates as written against the pinned VCVio, under
`import LatticeCrypto.HardnessAssumptions.LearningWithErrors` and `open MLKEM`:

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

The day it lands, composing it with `sharedSecretHiding_eq_indCpaAdvantage` is
a one-line `calc`.

## The ML-KEM instantiation

VCVio ships a concrete ML-KEM whose checked interface is packaged as
`MLKEM.asKEMScheme : KEMScheme ProbComp …`, over the same `ProbComp` monad the
game layer uses — so it *is* a `KEM` in this development's sense, with no
bridge. `mlkem768StealthScheme` is `ofKEMFull` at it: discovery via real
ML-KEM, announcement = ciphertext plus auxiliary data derived from the shared
secret and the recipient's encapsulation key.

What this buys: the terms of `unlinkAdvantage_ofKEMFull_le`, specialized, are
now about VCVio's ML-KEM. The shared-secret-hiding terms are exactly its KEM
IND-CPA advantage; the anonymity term is the one link neither VCVio nor FIPS
203 supplies.

### Two facts about the concrete encoding

* **`DecidableEq` is not synthesizable through the encoding.**
  `MLKEM.Concrete.concreteEncoding` sets all three encoded types
  (`EncodedTHat`, `EncodedU`, `EncodedV`) to `ByteArray`, but it is a plain
  `def`, so instance search cannot see through it. Three
  `inferInstanceAs (DecidableEq ByteArray)` transports close that; they are
  definitionally `ByteArray.instDecidableEq`. They are what lets
  `MLKEM.asKEMScheme` and everything built on it elaborate at
  `mlkem768Encoding`.

* **The concrete ciphertext type admits NO uniform distribution.**
  `SampleableType β` bundles a `ProbComp β` whose support is all of `β`, and
  supports of `ProbComp`s are finite, so a `SampleableType` instance forces `β`
  finite. `ByteArray` is unbounded, hence infinite (`infinite_byteArray`: the
  all-zero arrays have pairwise distinct lengths), hence so is the ciphertext
  type (`infinite_mlkem768Ciphertext`). Therefore
  `isEmpty_sampleableType_mlkem768Ciphertext`: `$ᵗ (Ciphertext params encoding)`
  is unavailable at this parameter set. That is why the generic ML-KEM capstone
  takes its simulator as an explicit argument rather than as a uniform sample
  over the ciphertext type.

### The simulator: uniform FIPS 203 ciphertext bytes

`mlkem768UniformCiphertext` is uniform over the fixed-length byte strings of
the FIPS 203 ciphertext layout: `32 · du · k = 960` bytes of `u` followed by
`32 · dv = 128` bytes of `v`, 1088 bytes in total. That is the distribution the
SPR literature means by "uniform ciphertext bytes", and it is a *sharper*
simulator than uniform-over-the-encoded-type would be, since the latter would
range over byte arrays of every length — its support is a strict subset of the
encoded type, which is all of `ByteArray × ByteArray`.

`size_uEncoded_encrypt_mlkem768` checks the `u` half of that layout against
what honest K-PKE encryption actually emits.

**Documented gap:** the matching `v`-half check is not machine-checked. VCVio
proves it (`byteEncode_size`,
`LatticeCrypto/MLKEM/Concrete/Encoding.lean:242`) but that theorem and the
`bitsToBytes` definition it rests on are `private`, so the fact is unavailable
outside that module and the goal cannot even be stated in terms one can unfold.
The `32 · dv` figure is therefore taken from FIPS 203 Algorithm 5 on the
strength of the specification alone;
`uEncodedBytes_add_vEncodedBytes_eq_ciphertextBytes` confirms only that the two
figures chosen sum to VCVio's `Params.ciphertextBytes`, which is arithmetic and
corroborates neither summand.

### Upstream asks

Three things would shorten this file if VCVio provided them: `DecidableEq`
instances (or a structure-eta-friendly encoding) for the concrete encoded
types, a public `byteEncode_size`, and `MLKEM.kem_ind_cpa_security` in the
shape given above.
