# The announcement model

Background for `PqStealth/Games.lean`, `PqStealth/KEMAnonymity.lean`,
`PqStealth/ConstructionA.lean` and the game-layer controls. Everything here is
design rationale: what the Lean model commits to, why, and what it deliberately
cannot say. The theorems themselves live in the modules.

## The scheme as an abstract randomized algorithm

`StealthScheme` mirrors VCVio's `AsymmEncAlg`: the algorithmic data lives in
`ProbComp`, and the security experiments are built on top. `announce` is the
sender's operation (produce an announcement addressed to a meta-address);
`scan` is the recipient's detection test; `CorrectExp` / `PerfectlyComplete`
are the correctness side, matching VCVio's `CorrectExp` / `PerfectlyCorrect`.

`MetaPub`, `MetaPriv` and `Announcement` are opaque type parameters, so the
definitions commit to no parameter set. The concrete instantiations
(ML-KEM, ML-KEM-768, construction A, DKSAP) come later and reuse the same
games.

The headline property is UNLINKABILITY (recipient anonymity): given an
announcement you cannot tell which recipient it is for. That is the key-privacy
sibling of IND-CPA — the hidden bit selects the RECIPIENT, not the message.
The one structural fact that holds before any assumption enters is
`unlinkAdvantage_eq_branchDistAdvantage`: the unlinkability advantage equals
the adversary's advantage in distinguishing an announcement to recipient 1 from
one to recipient 0. That is the first game hop, and the definitional heart of
anonymity.

## Why the adversary is a function, not a two-phase structure

The unlinkability adversary is

```lean
abbrev StealthScheme.UnlinkAdv (MetaPub Announcement : Type) :=
  MetaPub → MetaPub → Announcement → ProbComp Bool
```

— it sees both public meta-addresses and the challenge announcement, and
guesses. It depends only on the public types, not on the scheme, which is what
lets the same type serve as a KEM key-privacy adversary in `KEMAnonymity`.

Earlier the same object was a two-phase structure with a `State : Type` field:
`setup : MetaPub → MetaPub → ProbComp State` followed by
`distinguish : State → Announcement → ProbComp Bool`. The two are equivalent
for these games, and the function form is strictly better here:

* **The games are non-adaptive.** Nothing happens between the two phases that
  the adversary could react to — the challenger draws two keypairs, then
  produces one announcement. A two-phase adversary can therefore be replaced by
  the single function `fun pk0 pk1 c => adv.setup pk0 pk1 >>= fun st =>
  adv.distinguish st c`, and conversely a function is the two-phase adversary
  with `State := MetaPub × MetaPub`. Nothing in the development ever used
  `adv.setup` on its own.
* **It removes a universe bump.** `UnlinkAdv : Type` instead of `Type 1`, since
  there is no bundled `State : Type` field.
* **It makes the shared game prefix key-only.** `unlinkSetup` and
  `KEM.anonSetup` become `ProbComp (MetaPub × MetaPub)` and
  `ProbComp (PK × PK)`; they no longer take the adversary as an argument. That
  is what lets `KEM.anonSetup (adv.cipherOf auxGen)` and
  `(StealthScheme.ofKEMFull kem auxGen).unlinkSetup` be recognized as the same
  computation, which is the crux of `unlinkAdvantage_ofKEMFull_le`. With a
  bundled `State` the two prefixes ran different `setup`s and could not be
  identified.

## Two models of the announcement, and why the coarse one is not enough

`StealthScheme.ofKEM` treats the announcement as just the KEM ciphertext, and
`unlinkAdvantage_ofKEM_eq_anonAdvantage` shows that unlinkability of that
scheme EQUALS the KEM's anonymity advantage — the two experiments are the same
computation. That is a teaching model for the reduction, not the scheme. With
nothing but a ciphertext in the announcement there is nothing for the recipient
to check against, so detection is only as strong as the KEM's rejection
behaviour, and on a KEM with implicit rejection (ML-KEM) that is no strength at
all: `decaps` never returns `none`, so `scan` is the constant `true`.

`StealthScheme.ofKEMFull` is the faithful version. The announcement is
`(ciphertext, auxGen sharedSecret pk)`, with `auxGen : K → PK → Aux` modelling
the view tag together with the stealth address.

### Why `auxGen` takes the public key

The second argument is load-bearing rather than cosmetic. The view tag is a
function of the shared secret alone, but the stealth address is not: it is

```
keccak(pack_pk(rho, Power2Round(A ·ᵥ s' + e' + t)))
```

in which `rho` and `t` are the RECIPIENT's own meta-address material and only
`(s', e')` come from the shared secret. An announcement therefore carries
recipient-dependent data even once the shared secret is idealized. A model with
`auxGen : K → Aux` understates what is published — and, worse, it makes the
`auxKeyIndependence` term below identically zero, so the blinding question
becomes invisible rather than merely small.

### Why `scan` recomputes, and why the private state is `SK × PK`

`ofKEMFull.scan` decapsulates and then RECOMPUTES the auxiliary data from the
recovered shared secret and the recipient's own public key, accepting only when
it matches the announced one. Testing merely that decapsulation returned `some`
would be vacuous on any KEM with implicit rejection — ML-KEM's `decaps` is
`fun dk c => return some …` and never rejects, so that test is the constant
`true` and every recipient "detects" every announcement.

That is why the recipient's private state is `SK × PK`: a scanning wallet holds
its own meta-address next to the decapsulation key, and needs both. The
decapsulation key alone does not determine the tag.

Detection completeness (`perfectlyComplete_ofKEMFull`) is then exactly the
statement that the two sides compute the same auxiliary data: the sender builds
it from the encapsulated shared secret and the recipient's public key, the
recipient rebuilds it from the decapsulated secret and its own public key, and
KEM correctness identifies the two secrets. Correctness is VCVio's
`KEMScheme.PerfectlyCorrect ProbCompRuntime.probComp`, i.e.
`Pr[= true | kem.CorrectExp] = 1` for the experiment "generate a keypair,
encapsulate, decapsulate, compare". The hypothesis is doing real work:
`deadKEM_ofKEMFull_not_perfectlyComplete` drops it and proves the conclusion
false.

## The decomposition, term by term

Unlinkability of `ofKEMFull` rests on three separate things, and
`unlinkAdvantage_ofKEMFull_le` names each rather than merging them:

```
unlinkAdvantage ≤ sharedSecretHiding … true
                + auxKeyIndependence
                + anonAdvantage (adv.cipherOf auxGen)
                + sharedSecretHiding … false
```

* **`sharedSecretHiding kem auxGen adv b`** — the auxiliary data hides the
  recipient insofar as the shared secret is pseudorandom. This is a KEM
  IND-CPA (real-or-random) question, proved equal to VCVio's
  `KEMScheme.IND_CPA_Advantage` in `SharedSecretHiding`; its reduction to MLWE
  is the paper-level FO step (see `spr-two-hop.md`). One term per branch.
  On each branch both sides build the auxiliary data from the SAME public key,
  which is what makes it a clean real-or-random KEM question and nothing else.
* **`auxKeyIndependence`** — once the secret is idealized, the auxiliary data
  must still not betray WHICH public key produced it. For this scheme that is
  the blinding argument (`A ·ᵥ s' + e'` masking `t`), and it is again MLWE, not
  a KEM property. This is the term a shared-secret-only model cannot state at
  all.
* **`KEM.anonAdvantage`** — the ciphertext itself must hide the recipient. KEM
  anonymity (ANO-CCA), which neither VCVio nor FIPS 203 supplies; see
  `spr-two-hop.md`.

The proof is the triangle inequality over the intermediate games. The
intermediate game on branch `b` is `randAuxBranch kem auxGen adv b`: the
challenge ciphertext still goes to the selected recipient, and the auxiliary
data is still built from that recipient's own public key, but from a fresh
random shared secret rather than the real one. That game is exactly what
separates the two distinct assumptions a shared-secret-only model silently
merged into one term.

## `cipherOf`: the induced ciphertext-anonymity adversary

`StealthScheme.UnlinkAdv.cipherOf adv auxGen` turns a full-announcement
adversary into a ciphertext-only one:

```lean
fun pk0 pk1 c => do
  let k' ← ($ᵗ K)
  adv pk0 pk1 (c, auxGen k' pk0)
```

It synthesizes the auxiliary data from a FRESH random shared secret and a FIXED
public key — recipient 0, which the anonymity game hands it. Both choices carry
weight:

* the random secret removes the dependence on the real encapsulation, which is
  what makes the hop to `randAuxBranch` a pure shared-secret-hiding question;
* the fixed key is what makes the reduction constructible at all. A derived
  adversary cannot consult "whichever key the challenger used" without already
  knowing the hidden bit.

## Construction A: what is modelled and what is abstracted

`ConstructionA.lean` supplies the `auxGen` the real scheme uses
(`docs/TECHNICAL_SPEC.md` §1, §4), so that the announcement in the model is the
announcement in the spec. With

```
(s', e')        = expandBlind ss
stealthKey      = A ·ᵥ s' + e' + t          -- A = expandA rho
stealthAddress  = hashAddr (pack rho (power2Round stealthKey))
viewTag         = viewTag ss
```

matching the spec's `keccak256(pack_pk(rho, Power2Round(A·s' + e' + t)))[12:32]`
and `SHA-256(ss)[0:1]`.

Every *symmetric* primitive is a parameter, not a definition: `expandA`
(SHAKE128 matrix expansion), `expandBlind` (`ExpandS ∘ SHAKE256`),
`power2Round`, `pack` (`pack_pk`), `hashAddr` (`keccak256 … [12:32]`),
`viewTag` (`SHA-256`). "Faithful" here means the *algebraic* shape is the
spec's — which key material enters which slot, and in particular that `rho` and
`t` are the RECIPIENT's while only `(s', e')` come from the shared secret. It
does NOT mean the hash functions are modelled; they are uninterpreted
functions, so any statement proved here holds for every instantiation of them,
and any statement that NEEDS them to behave randomly cannot be proved here at
all.

The module's contents, in order:

1. `auxGen` and `stealthAddr_eq_blinded_pk`: the announced stealth key is
   `power2Round` of the honest ML-DSA public key of the widened secret
   `(s₁ + s', s₂ + e')` — `stealth_pk_eq_blinded_keypair` used in the game
   model — and that widened secret is an ownership witness for it
   (`announced_key_isOwnershipWitness`), so the ZK spend statement of
   `Invariants.lean` is satisfiable for every announcement construction A
   produces.
2. `metaKem` / `scheme`: `ofKEMFull` needs a `KEM` whose public key is exactly
   the argument `auxGen` reads. The ML-KEM keypair alone is not that, so key
   generation additionally draws the ML-DSA seed `rho` and secret `(s₁, s₂)`
   and publishes `t = A ·ᵥ s₁ + s₂`; encapsulation and decapsulation ignore the
   extra components. The spending keypair is drawn from three separate samplers
   rather than one opaque joint one, because the MLWE reduction has to resample
   `(s₁, s₂)` for a `rho` handed to it by the challenger, which a joint sampler
   cannot support. `unlinkAdvantage_scheme_le` is `unlinkAdvantage_ofKEMFull_le`
   at `metaKem` and `auxGen`; the content is that those two are the spec's
   objects.
3. `auxKeyIndependence_eq_zero_of_pk_independent` (and its corollary
   `auxKeyIndependence_tagOnly_eq_zero`): the positive control pinning the
   meaning of `auxKeyIndependence` — it is `0` for any `auxGen` that ignores
   the public key, in particular for a view-tag-only announcement. A model in
   which the term failed to vanish there would be measuring the wrong thing;
   and it is exactly the coarser model that `ofKEMFull` was introduced to
   improve on.
4. The blinding hop towards decision-MLWE: the seeded-MLWE problem
   `blindingProblem`, the reduction adversary `mlweAdvOfUnlinkAdv`, and the
   middle-game lemma `idealAux_indep_of_t`.

### The blinding hop

The hop replaces the real mask `A ·ᵥ s' + e'` inside the announced stealth key
by a uniform vector. That is a decision-MLWE step, stated in the SEEDED form
the scheme actually uses: the challenge is the seed `rho`, not the matrix,
because the reduction must be able to compute `pack rho …` and cannot invert
`expandA`. It coincides with `LearningWithErrors.moduleMatrixProblem` (up to
the transpose, since `matrixProblem` uses `vecMul`) whenever
`expandA <$> sampleRho` is uniform on matrices — the standard "expansion is a
random oracle" reading, which is not proved.

`mlweAdvOfUnlinkAdv` receives `(rho, y)`, installs `rho` as recipient 1's
matrix seed, draws recipient 1's spending secret itself, simulates recipient 0
honestly, and splices `y` in as the mask: the announced address is
`hashAddr (pack rho (power2Round (y + t₁)))`. With `y` real this is the
construction-A announcement to recipient 1 (under `ExpandIsIdeal`); with `y`
uniform it is the ideal-blinding announcement of `idealAux_indep_of_t`.

`idealAux_indep_of_t` is the lattice analogue of `dksapIdeal_announce_indep`,
with the shift `u ↦ u + (t − t')` in place of the group translation: with the
mask drawn uniformly, the announcement to a recipient with spending key `t` and
one to a recipient with spending key `t'` are the same distribution. Note what
it does NOT quantify over: `rho` is shared between the two sides. It has to be
— `rho` enters through `pack`, outside the masked argument, so the two sides
with different seeds are genuinely different distributions for a general
`hashAddr`.

### Documented gaps (statements this model cannot support — not `sorry`s)

* **`auxKeyIndependence` is not `0` for construction A, and no MLWE bound
  closes it.** A uniform mask erases `t` (proved: `idealAux_indep_of_t`) but
  `rho` sits OUTSIDE the masked term, in `pack rho …`. The adversary is handed
  both meta-addresses, hence both `rho`s; with `hashAddr` an arbitrary function
  (take it to be the identity, and `pack rho _ = rho`) the address reveals
  which `rho` produced it. The scheme is fine — `keccak` is not the identity —
  but the missing ingredient is `hashAddr ∘ pack` as a random oracle, not more
  proof effort. Closing this term therefore needs a ROM extension of the model,
  and `unlinkAdvantage_scheme_le` should be read with that in mind. (The
  non-vanishing is an argument, NOT machine-checked; a counterexample scheme
  exhibiting it belongs with the negative controls.)
* **The reduction's game 0 is faithful only under `ExpandIsIdeal`.** In the
  real scheme the view tag and the blinding pair come from the same shared
  secret; the reduction must take the mask from the MLWE challenger and
  therefore samples the tag separately. `ExpandIsIdeal` names precisely that
  assumption — `(viewTag ss, expandBlind ss)` for uniform `ss` is distributed
  as three independent samples — which is the SHAKE/SHA-as-random-oracle step.
  It is false for the concrete primitives and true in the random-oracle model.
* **Both games of the reduction still need a bind commutation.**
  `LearningWithErrors.distr` / `uniformDistr` fix the seed and the mask BEFORE
  the adversary runs, whereas `randAuxBranch … true` draws the shared secret
  after the announcement prefix. So identifying `LearningWithErrors.game0` with
  the real game (on top of `ExpandIsIdeal`) and `game1` with the
  ideal-blinding game both require commuting independent samples past one
  another (`probOutput_bind_eq_tsum` + `tsum_comm`). `idealAux_indep_of_t` is
  proved in the form the second identification consumes; the plumbing is not
  done, so **no advantage inequality is claimed**.

## Controls: why the definitions have teeth

`Controls.lean` pins one completeness claim (DKSAP) from below by proving a
deliberately broken variant broken. The game layer needs the same treatment on
both sides, because a definition can be wrong in two opposite ways: an advantage
that no scheme can make large measures nothing, and a detection test that no
scheme can fail asserts nothing.

### Positive controls: the `1 − keyCollisionProb` ceiling

`leakyScheme` publishes the recipient's meta-address outright, and
`unlinkAdvantage` is proved maximal on it — where maximal means
`1 − keyCollisionProb`, the probability that the two recipients drew the same
public key.

That ceiling is the exact obstruction to an advantage of `1`, and it is not a
proof artifact. The unlinkability game draws its two recipients independently
from the same `keygen`, so whenever they collide its two branches are literally
the same computation and no adversary whatsoever can distinguish them. Any
unlinkability or anonymity advantage against a scheme with that `keygen` is
therefore capped at `1 − keyCollisionProb`, and the one-comparison adversary
`leakyAdv` (`fun _ pk1 c => pure (decide (c = pk1))`) attains the cap. So
`unlinkAdvantage` does detect a recipient leak — it is not a quantity that
happens to be small for structural reasons.

The statement is proved for an arbitrary scheme with `announce pk = pure pk`
rather than for `leakyScheme` alone, so the KEM control reuses it: `leakyKEM`
encapsulates by echoing the public key, and `leakyKEM_anonAdvantage_eq` goes
through `unlinkAdvantage_ofKEM_eq_anonAdvantage`. The two controls are
literally the same fact seen through the reduction. This is also why
`ofKEM` is kept rather than folded into `ofKEMFull` with `Aux := Unit`: the
`Unit` version is only isomorphic to it, not the same term.

Detection in `leakyScheme` is unconditional, which is deliberate — the control
is about unlinkability, and a scheme can be perfectly complete and still
worthless.

### Negative controls: what the tag comparison buys

The negative controls are what make the tag comparison in `ofKEMFull.scan`
load-bearing, and they fail in opposite directions:

* `deadKEM` always rejects, so `deadKEM_ofKEMFull_not_perfectlyComplete`: the
  scheme is not complete. Stated as an ordinary theorem rather than a tactic
  script that fails, so the build keeps it honest.
* `ofKEMFullNoTag` drops the comparison — detection is "decapsulation returned
  `some`". Announcement and private state are unchanged, so the pair
  `ofKEMFull` / `ofKEMFullNoTag` isolates exactly the comparison. It IS
  complete under the same hypothesis (`perfectlyComplete_ofKEMFullNoTag`), so
  completeness alone cannot be the property that justifies the comparison; and
  on a KEM with implicit rejection it flags an announcement addressed to a
  different recipient with probability `1`
  (`probOutput_falsePositiveExp_ofKEMFullNoTag_eq_one`). Detection is then not
  detection: every scanner "receives" every payment.

`FalsePositiveExp` is detection soundness's counterpart to `CorrectExp` — two
independent recipients, an announcement addressed to the second, scanned with
the first one's private state; `true` is a false positive. A quantitative bound
on this probability for the real scan is separate work (it is the view-tag
length argument); what is used here is only that a tag-ignoring scan makes it
`1`.
