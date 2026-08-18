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

## Multi-challenge unlinkability

`UnlinkExp` gives the adversary one challenge announcement. plan.md's
deliverable is *unlinkability across payments*: the observer sees the whole
chain, so it sees many announcements at once. `MultiUnlink.lean` closes the gap
between the two by the standard hybrid argument.

The `q`-challenge game keeps the two recipients and the single hidden bit, and
hands the adversary all `q` announcements, all of them addressed to recipient
`b`:

```lean
abbrev StealthScheme.UnlinkAdvMulti (MetaPub Announcement : Type) :=
  MetaPub → MetaPub → List Announcement → ProbComp Bool

def unlinkBranchMulti (q : ℕ) (b : Bool) (a : MetaPub × MetaPub) : ProbComp Bool := do
  let cs ← S.announceList (List.replicate q (if b then a.2 else a.1))
  advM a.1 a.2 cs
```

`announceList` samples one independent announcement per public meta-address in a
*list of recipients* — not per index of a count — because that is exactly the
degree of freedom the hybrids need. `length_of_mem_support_announceList` records
that the adversary really does receive `q` announcements; the `List` encoding
does not silently drop the count.

**The bound.** With `hybridAdv i j` the single-challenge adversary that
simulates `i` announcements to recipient 1 and `j` to recipient 0 itself and
splices the challenge between them,

```lean
theorem unlinkAdvantageMulti_le_sum (q : ℕ) :
    S.unlinkAdvantageMulti advM q ≤
      ∑ k ∈ Finset.range q, S.unlinkAdvantage (S.hybridAdv advM k (q - k - 1))

theorem unlinkAdvantageMulti_le_mul (q : ℕ) {ε : ℝ}
    (h : ∀ i j, S.unlinkAdvantage (S.hybridAdv advM i j) ≤ ε) :
    S.unlinkAdvantageMulti advM q ≤ q * ε
```

The sum is the honest statement; the `q · ε` form is the corollary one quotes.
**The loss factor is `q`, the number of announcements the observer correlates**,
and it is linear, not quadratic: the two recipients are fixed across the whole
game, so only the announcements are hybridised. For the parameter write-up this
means the single-challenge target has to be `ε ≤ 2⁻ᵏ / q` for a `k`-bit
unlinkability claim over `q` observed payments — that inequality is algebra from
the theorem; the observation window `q` is a parameter of the threat model, and
the write-up should state the value it picks (taking the whole chain as the
window costs `log₂ q` bits off the single-payment advantage).

The composition with `unlinkAdvantage_ofKEMFull_le` is **on paper, not in Lean**:
`MultiUnlink.lean` does not import `KEMAnonymity` and no theorem here mentions
`ofKEMFull`. The composition is nevertheless legitimate, because
`unlinkAdvantage_ofKEMFull_le` holds for *every* `UnlinkAdv` and can therefore be
instantiated at each `hybridAdv k (q − k − 1)`, multiplying every term on its
right (two shared-secret-hiding terms, `auxKeyIndependence`, anonymity) by the
same `q`. Discharging that instantiation in Lean is a small follow-up.

**Why the derived adversary is legitimate.** It has to produce the other `q − 1`
announcements itself. That is free: adversaries are `ProbComp` computations and
the scheme `S` is public, so `S.announce` is available to it. It needs no secret
and makes no oracle query the game does not already allow.

**The one place probability enters.** Hybrid `k` and hybrid `k+1` differ in the
recipient of announcement number `k`. The derived adversary receives *its*
challenge first and then simulates the rest, whereas the hybrid samples the
announcements in list order; the two computations are therefore not equal in the
free monad, only equal in distribution. `evalDist_announceList_append_cons`
pulls the marked announcement to the front by one application of VCVio's
`evalDist_bind_bind_swap` per element of the prefix, and
`boolDistAdvantage_congr` transports the advantage along that `evalDist`
equality. The definitions are shaped so that this is the *only* reordering in
the argument: hybrid `k` IS `unlinkSetup >>= unlinkBranch (hybridAdv …) b` up to
that single swap, with `k` and `k+1` the `b = false` and `b = true` cases of one
lemma. Indexing the hybrid by the two segment lengths `(i, j)` rather than by
`(q, k)` keeps natural subtraction out of the core proof; it appears only in the
final telescope, where `k < q` comes from `Finset.mem_range`.

`boolDistAdvantage_le_sum_hybrids` is the general telescoping step —
`dist (H n) (H 0) ≤ ∑ k ∈ range n, dist (H (k+1)) (H k)` for any chain
`H : ℕ → ProbComp Bool`, by induction on `n` over the triangle inequality. It is
stated separately because it has nothing to do with stealth addresses.

**Follow-up: `n` recipients.** The remaining generalisation publishes `n`
meta-addresses and lets the adversary choose the challenge pair `(i₀, i₁)`. The
expected statement is `Adv_{n,q} ≤ (n·(n−1)/2)·q·ε` — guess the pair, embed the
two-recipient challenge there, generate the other `n − 2` keypairs honestly. It
is deliberately *not* proved here: unlike the hybrid above it is not a chain of
triangle inequalities but a conditioning argument
(`Pr[win] = ∑_pairs Pr[the guess was right] · Pr[win | that pair]`), which needs
real work in VCVio rather than falling out of the machinery in this file. Note
that the `n` factor is an artefact of the guessing reduction, not of the scheme:
for a left-or-right notion over independently generated meta-addresses the
usual tighter route is a second hybrid over the recipients themselves.

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
the first one's private state; `true` is a false positive. What the control uses
is only that a tag-ignoring scan makes it `1`
(`falsePositiveRate_ofKEMFullNoTag_eq_one` restates that in the vocabulary of
the next section); the quantitative bounds for the real scans are below.

## Detection soundness

`Games` defines two words on top of `FalsePositiveExp`:

* `falsePositiveRate S := (Pr[= true | S.FalsePositiveExp]).toReal` — `.toReal`
  because every other number in this development is an `ℝ` advantage, and the
  bounds below add the rate to distinguishing advantages;
* `SoundWithin S ε := S.falsePositiveRate ≤ ε`.

`Soundness` proves the two instances. They are not the same kind of statement,
and the difference is the point.

### DKSAP: exactly `1 / |F|`, and the reason is not the hash

`dksap_falsePositiveRate_eq`: for **every** hash `h`, and given only that
`x ↦ x • g` is injective,

```
falsePositiveRate (dksap g h) = 1 / |F|
```

An equality, not a bound. Unfolding, the stranger's scan fires exactly when

```
m1 + h (r • V1) = m0 + h (v0 • R)
```

where `(m0, v0)` is the scanner's key pair and `(m1, v1)` recipient 1's.
Injectivity of `x ↦ x • g` turns the group equation into this scalar one, and
recipient 1's spending scalar `m1` is uniform and independent of the other four
draws — so for each value of `(m0, v0, v1, r)` exactly one `m1` out of `|F|`
triggers, whatever `h` computes. The formal proof is the same sentence: move the
`m1` draw innermost with `probOutput_bind_bind_swap`, read it off with
`probOutput_uniformSample`, and collapse the never-failing prefix with
`probOutput_bind_of_const`.

This corrects the issue as it was originally filed (`improvements.md` #5 asked
for "exact `0` false positives modulo hash collisions of `h`"). There is no
hash-collision term and the rate is not `0`: the leak is the uniform spending
scalar, and a collision of `h` is neither necessary nor sufficient for a false
positive. At a 254-bit scalar field `1 / |F|` is of course negligible, which is
why nobody noticed the mechanism was misdescribed.

### The KEM scheme: a tag term plus a real-or-random term

For `ofKEMFull` the scan fires when

```
auxGen (sharedSecret) pk1  =  auxGen (recipient 0's decapsulation of c) pk0
```

Two things have to be true for that to be rare. First, the tag must be hard to
hit: `AuxCollisionFree auxGen ε` says that over a **uniform** secret `k`,
`auxGen k pk` lands on any prescribed value with probability at most `ε`.
Second, recipient 0's decapsulated key must actually look uniform to the
announcement — and that is a KEM question, not a tag question. It is the same
shape as `sharedSecretHiding` in the unlinkability chain, so it gets the same
treatment: a named real-or-random term rather than an assumption swept into the
statement.

`falsePositiveIdeal` is `FalsePositiveExp` with recipient 0's decapsulated key
replaced by a fresh `$ᵗ K` (the announcement is untouched — only the scanner's
secret is idealized), and

```
decapsRoR kem auxGen := boolDistAdvantage FalsePositiveExp falsePositiveIdeal
```

Then `falsePositiveRate_ofKEMFull_le`:

```
SoundWithin (ofKEMFull kem auxGen) (ε + decapsRoR kem auxGen)
```

by the triangle inequality through `falsePositiveIdeal`, whose own probability
is bounded by `ε` because at that point the verdict IS a tag collision against a
uniform secret. `decapsRoR` is again a KEM IND-CPA question: a distinguisher
that told the real decapsulated key from a fresh uniform one inside this
experiment is a real-or-random distinguisher for the shared secret of a
ciphertext the distinguisher did not create. The `0 ≤ ε` hypothesis is not
decoration — with `PK` empty the collision hypothesis is vacuous and a negative
`ε` would make the statement false.

`decapsRoR_eq_zero_of_decaps_uniform` closes the loop from the ideal side: if
`kem.decaps` returns a uniform key, the real and idealized experiments are the
same computation and `decapsRoR = 0`, hence `SoundWithin ε` outright. That
hypothesis is deliberately global and no perfectly correct KEM with `|K| ≥ 2`
satisfies it — the lemma is a sanity check pinning `decapsRoR` as the *only*
gap, not a security claim.

### Where `1/256` comes from

`taggedAux viewTag rest k pk = (viewTag k, rest k pk)` is the deployed shape:
the announcement leads with a short tag derived from the shared secret alone,
followed by whatever else the auxiliary data carries (the stealth address).
`auxCollisionFree_taggedAux` says that if `viewTag` maps a uniform secret to a
uniform tag, then

```
AuxCollisionFree (taggedAux viewTag rest) (1 / |T|)
```

The remainder can only help, so the tag alphabet is the whole bound — which is
exactly the ERC's tag-length rationale. Chaining with the previous bound gives
`soundWithin_ofKEMFull_taggedAux`, and at concrete alphabets
`soundWithin_ofKEMFull_byteTag` (`T = Fin (2 ^ (8n))`, rate `2 ^ (-8n)` plus
`decapsRoR`) and `soundWithin_ofKEMFull_oneByteTag`:

```
SoundWithin (ofKEMFull kem (taggedAux viewTag rest))
  (1 / 256 + decapsRoR kem (taggedAux viewTag rest))
```

The uniformity of `viewTag` on a uniform key is a hypothesis. For the concrete
ML-KEM shared-secret type it would be "the first byte of a uniform 32-byte
string is a uniform byte", which VCVio's `Bytes` API does not currently expose
as a projection lemma; stating it as a hypothesis keeps the theorem honest and
costs the caller one `simp`.

### What is NOT proved

Nothing bounds `decapsRoR` for ML-KEM-768 — like `sharedSecretHiding`, it is
left as a named IND-CPA term and inherits the same missing upstream lemma
(`docs/spr-two-hop.md`). The soundness statements are also single-announcement:
a scanner sweeping `n` announcements false-positives at most `n` times the rate
by a union bound, which is not formalized here.
