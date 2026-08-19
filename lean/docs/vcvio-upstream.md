# VCVio: what this development needs upstream

Revised 2026-08-19 against a fresh read-only checkout of the pinned commit
`Verified-zkEVM/VCVio @ a5f474fd` (2026-07-15, Lean `v4.32.0`; see
`vcvio-pin.md`). The previous version of this file (round 3) listed eleven
asks. This pass re-checked every one of them line by line in the upstream
tree, and **five of the eleven do not survive contact with the source**: two
are already implemented upstream in a place we had not looked, one is
factually wrong about the pin, one is derivable from lemmas that already
exist, and one is not an upstream problem at all. What remains is smaller,
sharper, and cheaper for VCVio to accept.

Nothing here has been filed upstream yet.

## Method, and what it does not cover

* Every claim carries a `file:line` from the pinned commit. Line numbers are
  the pin's, not `main`'s.
* This pass is **source reading only** — this environment has no Lean
  toolchain, so nothing was recompiled. Statements of the form "elaborates as
  written" are inherited from the round-3 build, not re-verified here. Where
  a revision proposes new Lean text, it is marked *unbuilt*.
* The "why" for each item is grounded in the Lean Language Reference; the
  cited sections are collected in § Documentation index at the end.

## Verdict table

| # | Old ask | Verdict |
|---|---|---|
| 1 | `DecidableEq` beside `mlkem768Encoding` | **Confirmed**, but the proposed fix (`@[reducible]`) is wrong — it needs two defs, not one, and upstream deliberately avoids that. Ask restated: ship the instances. |
| 2 | De-privatize `byteEncode_size` | **Confirmed**, unchanged. |
| 3 | `SampleableType` on `R_q`/`T_q` | **Confirmed**, ask relocated: it belongs in `Ring/VectorBackend.lean`'s existing forwarding-instance block, plus `NeZero MLKEM.modulus`. |
| 4 | `LearningWithErrors.advantage_eq_boolDistAdvantage` | **Already upstream** — `MLDSA.NMA.advantage_eq_game_boolDistAdvantage`, verbatim, in an ML-DSA file. Ask becomes a move, not a proof. |
| 5 | KEM-level `kem_ind_cpa_security` | **Confirmed but mis-diagnosed**: the real gap is that `asKEMScheme` and `foKEMScheme` are never identified, so upstream's FO machinery cannot reach the scheme we (and the concrete instance) use. |
| 6 | Un-`sorry` `MLKEM/Security.lean` | **Confirmed**, and strengthened: upstream's own ML-DSA hop already uses the seeded MLWE shape we advocate. |
| 7 | KEM anonymity (ANO-CPA/CCA) | **Confirmed** — no anonymity notion exists anywhere in the tree. |
| 8 | Lazy-RO identical-until-bad switching lemma | **Largely already upstream** (`withProgramming` + the TV-distance bridge at `randomOracle`). Downgraded from "highest-value contribution" to a small wrapper ask plus real work on our side. |
| 9 | Reachability of the RO modules | **False at the pin** — `VCVio.lean:134-139` imports all of them. The programmability half is also already upstream. Residual: one cross-reference. |
| 10 | `Vector`/`Bytes` uniform-projection lemma | **Derivable at the pin** from two existing lemmas. Downgraded to a convenience corollary. |
| 11 | `mathlibStandardSet` vs `#guard_msgs` | **Withdrawn** — `#guard_msgs` has a documented message filter that fixes this. Our own tree should use it. |
| 12 | *(new)* `asKEMScheme.decaps` drops the input check | **New confirmed finding**, and the cause of our own round-1 "detection is vacuous" bug. |

---

# A. One root cause: semireducible definitions (items 1, 3, 12's cousin)

Three of our local carries are the same Lean fact wearing three hats, so take
the shared reasoning once.

VCVio's concrete layers are built out of plain `def`s that hide a
representation type: `Poly Coeff n := Vector Coeff n`
(`LatticeCrypto/Ring/VectorBackend.lean:37`), `modulus : ℕ := 3329`
(`LatticeCrypto/MLKEM/Params.lean:53`), and `concreteEncoding`'s
`EncodedTHat := ByteArray` (`LatticeCrypto/MLKEM/Concrete/Encoding.lean:1002-1005`).

**Why that blocks a downstream user.** The `def` command creates
*semireducible* definitions, and the Lean Language Reference is explicit that
semireducible definitions "are not unfolded by potentially expensive
automation such as type class instance synthesis or `simp`" (*Recursive
Definitions* → "Controlling Reduction", tag `reducibility`). The instance
synthesis chapter says the same from the other side: synthesis "respects
reducibility: semireducible or irreducible definitions are not unfolded, so
instances for a definition are not automatically treated as instances for its
unfolding unless it is reducible" (*Type Classes* → "Instance Synthesis", tag
`instance-synth`). So `SampleableType (Vector Coeff n)` is *not* an instance
for `SampleableType (Poly Coeff n)`, and `NeZero 3329` is not one for
`NeZero MLKEM.modulus`, no matter that both are true by `rfl`/`decide`.

**Upstream already knows this and has a convention for it.** The docstring on
`LatticeCrypto/Ring/VectorBackend.lean:69-78` says so in as many words —
"These bridge the gap between `def Poly = Vector Coeff n` and Lean's instance
synthesis, which cannot automatically inherit `Vector` instances when `Poly`
is a non-reducible `def`" — and then forwards eight instances by
`inferInstanceAs` (`:81-97`). `Poly` is a `def` rather than an `abbrev`
*on purpose*: making it reducible would let `CommRing (Poly Coeff n)`
collapse into an elementwise `CommRing (Vector Coeff n)` and create simp
loops (docstring at `:32-37`). That is a sound design choice, and it is
exactly why the ask is "add forwarding instances", never "make it reducible".

So each of the items below is: *the forwarding-instance convention has not
been applied to the class we need.*

## 1. `DecidableEq` next to `mlkem768Encoding`

**Where it bites.** `MLKEM.asKEMScheme` takes
`[DecidableEq encoding.EncodedTHat] [DecidableEq encoding.EncodedU]
[DecidableEq encoding.EncodedV]` (`LatticeCrypto/MLKEM/KEM.lean:88-92`).
`concreteEncoding` sets all three to `ByteArray`
(`Concrete/Encoding.lean:1002-1005`) and `mlkem768Encoding` is
`concreteEncoding mlkem768` (`Concrete/Instance.lean:119`) — both plain
`def`s. Synthesis therefore cannot see `ByteArray` through the structure
projection, and
`MLKEM.asKEMScheme concreteNTTRingOps mlkem768Encoding mlkem768Primitives`
does not elaborate downstream without help. We carry the three instances in
`PqStealth/MLKEM.lean:16-25`, each `inferInstanceAs (DecidableEq ByteArray)`.

**Correction to the round-3 ask.** It proposed `@[reducible] on
concreteEncoding`. That is not sufficient: `mlkem768Encoding` is *itself* a
plain `def`, so the projection still stops one step earlier — both defs would
have to become reducible. And per the `Poly` docstring, upstream avoids
reducible structure-valued defs deliberately.

**Revised ask.** Ship the three instances beside `mlkem768EncodingLaws`
(`Concrete/Instance.lean:133`), one per parameter set, in the
`inferInstanceAs` style already used at `VectorBackend.lean:91`. Roughly
(*unbuilt*):

```lean
instance : DecidableEq (mlkem768Encoding.EncodedTHat) :=
  inferInstanceAs (DecidableEq ByteArray)
```

A cleaner alternative, if upstream prefers one place over nine: put the three
`DecidableEq` fields into `Encoding` (or into a companion structure next to
`Encoding.Laws`), so every encoding carries them by construction.

**Cost.** Nine lines, no proofs. **Value to us.** Deletes three instances
from our tree and removes a bump-sensitivity flagged in `vcvio-pin.md` (a
redundant, possibly ambiguous instance the day upstream ships its own).

## 3. `SampleableType` on `R_q` / `T_q`, and `NeZero MLKEM.modulus`

**Where it bites.** Any decision-MLWE statement over the concrete ML-KEM ring
needs uniform sampling on `Rq`/`Tq`. `LatticeCrypto/MLKEM/Arithmetic.lean`
already forwards `DecidableEq Rq` and `DecidableEq Tq` by hand (`:63-70`) —
in the `change … ; infer_instance` idiom, which is the same manoeuvre — but
stops there. The MLDSA files take `[SampleableType (RqVec p.l)]` etc. as
hypotheses (`MLDSA/SecurityNMA.lean:66`) rather than constructing them, so
the gap has never been felt upstream. We carry
`instNeZeroMlkemModulus`, `instSampleableTypeRq`, `instSampleableTypeTq` in
`PqStealth/SPRTwoHop.lean:31-41`.

**Why it must be upstream, not downstream.** Two reasons beyond convenience.
First, `SampleableType` is a *data-carrying* class (it fixes which `ProbComp`
the uniform draw is), so two developments that each define their own instance
are not obviously talking about the same distribution; upstream ownership is
what makes `$ᵗ Rq` mean one thing. Second, our `instSampleableTypeTq` goes
through `SampleableType.ofEquiv` on `TransformPoly`'s single field
(`Ring/Transform.lean:39-41`) — that is upstream's structure, and a field
rename silently changes what our instance samples.

**Revised ask (three lines, two places, *unbuilt*).** In the forwarding block
at `Ring/VectorBackend.lean:81-97`:

```lean
instance [SampleableType Coeff] : SampleableType (Poly Coeff n) :=
  inferInstanceAs (SampleableType (Vector Coeff n))
```

and beside the `DecidableEq (TransformPoly ring)` instance
(`Ring/Transform.lean:50-59`), the `ofEquiv` transport across `coeffs`. That
covers `Rq`, `Tq`, and — because `PolyVec`/`PolyMatrix` are `abbrev`s over
`Vector` (`Ring/Core.lean:34,37`) — `RqVec`, `TqVec` and `TqMatrix` for free,
for ML-KEM *and* ML-DSA, which can then drop those hypotheses. Plus
`instance : NeZero MLKEM.modulus := ⟨by decide⟩` next to
`MLKEM/Params.lean:53`, without which `SampleableType (ZMod modulus)` cannot
be found either (the `FinEnum (ZMod n)` instance is gated on `NeZero n`,
`OracleComp/Constructions/SampleableType.lean:294`).

**Precedent.** `LatticeCrypto/Falcon/Arithmetic.lean:88` is literally this
instance for Falcon's ring:
`instance {n : ℕ} : SampleableType (Rq n) := inferInstanceAs (SampleableType (Vector Coeff n))`.
ML-KEM is the odd one out.

# B. Visibility

## 2. De-privatize `byteEncode_size`

`LatticeCrypto/MLKEM/Concrete/Encoding.lean:242`:

```lean
private theorem byteEncode_size (d : Nat) (f : Rq) : (byteEncode d f).size = 32 * d
```

**Why `private` is fatal rather than annoying.** The reference manual:
"If a declaration is marked `private`, then it is not accessible outside the
module in which it is defined" (*Definitions*, tag `private`). There is no
downstream workaround — not a qualified name, not `open`. The only options
are to re-prove it (which means re-deriving the private helpers it stands on:
`bitsToBytes` size arithmetic at `:90`, the `bits.size = ringDegree * d`
chain at `:260-299`) or to assume it. We assume it: the `v` half of the FIPS
203 ciphertext layout is `32·dv = 128` bytes at ML-KEM-768
(`PqStealth/MLKEM.lean:75-79`), taken from the standard. It is the only
non-cryptographic assumption in that file, and it exists purely because of an
access modifier.

**Ask.** Drop `private`, or add a public corollary. Upstream uses it four
times internally (`:797, 800, 802, 936`), so it is already load-bearing; the
publicly visible statement costs nothing.

**Value to us.** Closes the last non-cryptographic assumption in
`PqStealth/MLKEM.lean`, and lets `encodingRegularity` (in
`docs/spr-two-hop.md`) be stated over a proved byte layout rather than a
quoted one.

# C. Already upstream — withdraw or restate

This is the part of the round-3 list that did not survive. Two of these were
"missing" only because we searched by the name we expected rather than by the
statement we needed.

## 4. `LearningWithErrors.advantage_eq_boolDistAdvantage` — **exists upstream**

`LatticeCrypto/MLDSA/SecurityNMA.lean:249-265` is our lemma, statement for
statement:

```lean
theorem advantage_eq_game_boolDistAdvantage
    {Sample Secret Output : Type} [Add Output]
    (problem : LearningWithErrors.Problem Sample Secret Output)
    (adv : LearningWithErrors.Adversary problem) :
    LearningWithErrors.advantage problem adv =
      (LearningWithErrors.game0 problem adv).boolDistAdvantage
        (LearningWithErrors.game1 problem adv)
```

It is fully generic in `Sample`/`Secret`/`Output` (the ML-DSA section
variables are `omit`ted at `:239`), and its proof is the same two steps as
ours: rewrite `experiment` into hidden-bit form and apply
`ProbComp.boolBiasAdvantage_eq_boolDistAdvantage_uniformBool_branch`
(`VCVio/CryptoFoundations/SecExp.lean:159`). Its own docstring calls it
"fully generic". But it lives in namespace `MLDSA.NMA`, in a file whose
import cone is all of ML-DSA — so a downstream ML-KEM development neither
finds it by name nor wants to import it. We re-proved it in
`PqStealth/SPRTwoHop.lean:47-62` (via
`boolBiasAdvantage_bind_uniformBool_eq_boolDistAdvantage`, `SecExp.lean:172`,
with a `pure ()` prefix — a different route to the same statement).

**Revised ask — a relocation, not a proof.** Move it to
`LatticeCrypto/HardnessAssumptions/LearningWithErrors.lean` next to
`advantage` (`:74`) and `game0`/`game1` (`:77-88`), under the
`LearningWithErrors` namespace, and have `MLDSA.NMA` re-export or call it.

**Why it is worth filing anyway.** The bridge from a bias-shaped
`advantage` to a distance-shaped `boolDistAdvantage` is the *only* way a
decision-MLWE term enters a `boolDistAdvantage_triangle` chain
(`SecExp.lean:126`), i.e. it is on the path of every game-hopping proof that
ends in MLWE. A fact that generic sitting inside one scheme's security file
guarantees the next development re-proves it too. Zero risk: it is a move.

## 8. The lazy-RO switching lemma — **the machinery is already there**

The round-3 list called this "the highest-value upstream contribution". That
was wrong, and it was wrong because we looked only at
`StateSeparating/IdenticalUntilBad.lean` (which does compare two
`QueryImpl.Stateful` handlers with a `σ × Bool` flag, as we said) and not at
`ProgramLogic/Relational/`. At the pin, upstream has:

* `QueryImpl.withProgramming` and `ProgrammingPolicy`
  (`VCVio/OracleComp/QueryTracking/ProgrammingOracle.lean:62, 117`) — run a
  cached oracle with a *policy* that answers designated points with
  designated values and raises a bad flag when one fires. This is the
  programmability API item 9 asked for.
* `tvDist_simulateQ_randomOracle_withProgramming_le_probEvent_bad`
  (`VCVio/ProgramLogic/Relational/ProgrammingOracle.lean:364`) — for the
  *lazily sampled* `OracleSpec.randomOracle`, the TV distance between the
  unprogrammed run and the programmed run is at most the probability the bad
  flag fires. That is the identical-until-bad step our
  `BoundedByBadQuery` states as an open `Prop`.
* `programming_collision_bound_qP_qH_β`
  (`ibid.:186`) — the textbook `qP · qH · β` repackaging, fed by
  `HasUnpredictableSample`
  (`VCVio/OracleComp/QueryTracking/Unpredictability.lean:318, 333`). That is
  the shape of our `BadQueryBounded` (`Pr[bad] ≤ q_H · β`).

Composition into our proofs is sound because `tvDist` dominates
`boolDistAdvantage` — the same step upstream takes at
`StateSeparating/IdenticalUntilBad.lean:57` via
`abs_probOutput_toReal_sub_le_tvDist`.

**What is actually left for upstream (small).** The `qP · qH · β` wrapper at
`:186` is stated for the *homogeneous* case (`so : QueryImpl spec (OracleComp
spec)`), while the random-oracle bridge at `:364` is the *heterogeneous* one
(`uniformSampleImpl` is `ProbComp`-valued). Ask: the same wrapper for the
heterogeneous case, so a lazy-RO user gets `tvDist ≤ (qP · qH · β).toReal`
without re-deriving the specialization.

**What is left for us (real work, and it is ours).** `DKSAPOracle.lean`'s
`dksapRORun_eq` phrases the ideal game as a run *from a pre-populated cache*;
upstream's bridge is phrased over *a programming policy*. Those are not the
same object, and the bridge is the supported one — so the ideal games in
`DKSAPOracle.lean` and `BlindingROM.lean` should be restated over
`withProgramming`, after which `hashedDHRO ≤ dksapROBadProb` and
`BoundedByBadQuery` should follow from `:364` rather than from anything new.
This is now a downstream task on our board, not an upstream blocker. See
`docs/dksap-asymmetry.md` and `docs/announcement-model.md`, both of which
still describe this as an upstream gap and need rewriting.

## 9. Reachability of the random-oracle modules — **false at the pin**

The claim was that `OracleComp/QueryTracking/RandomOracle/Basic.lean` and
`DeferredSampling.lean` are not reachable from VCVio's root import. They are:
`VCVio.lean:134-139` imports `Basic`, `DeferredSampling`, `Eager`,
`EagerTable`, `ProbeEps` and `Simulation`, and `VCVio` is the package's
`@[default_target]` (`lakefile.lean`). Our own modules import them by full
path anyway (`PqStealth/BlindingROM.lean:2`,
`PqStealth/MultiRecipient.lean:2`), which is ordinary practice and not a
workaround. Whatever we hit in round 3, it was not this. The corresponding
bullet in `vcvio-pin.md` (bump sensitivity: "neither is reached by VCVio's
own root import") is wrong and should be corrected to the accurate residual
risk — a *rename* still breaks us at import resolution rather than at a lemma
name, which is a real, if smaller, point.

The programmability half of item 9 is answered by item 8's findings.

**Residual ask (one line of prose).** `RandomOracle/Basic.lean` has no
pointer to `ProgrammingOracle`; a "See also" in its module docstring naming
`QueryImpl.withProgramming` and
`tvDist_simulateQ_randomOracle_withProgramming_le_probEvent_bad` would have
saved this development a round. Discoverability is the whole of the ask.

## 10. `Vector`/`Bytes` uniform projection — **derivable at the pin**

`PqStealth/Soundness.lean`'s one-byte view-tag bound carries "the first byte
of a uniform 32-byte string is uniform" as a hypothesis. At the pin, upstream
has both ingredients:

* `evalDist_map_fst_uniformSample_prod`
  (`OracleComp/Constructions/SampleableType.lean:496`) — "the first
  coordinate of a uniform pair is uniform";
* `evalDist_uniformSample_map_comp_injective` (`ibid.:527`) — restricting a
  uniform function table `B → R` along an injection `A ↪ B` is uniform, which
  is exactly a coordinate marginal when `A` is a point.

`Bytes n = Vector UInt8 n`, and `SampleableType (Vector α n)` exists at
`:308` while the function-table view `Vector α n ≃ (Fin n → α)` exists at
`:338` (`instSampleableTypeFinFunc`). So the ask is no longer "a missing
lemma" but two conveniences:

1. the bridge lemma identifying the two instances — the index-wise `Vector`
   instance at `:308` and the `ofEquiv`-of-`Fin n → α` instance at `:338`
   are *different terms*, and nothing in the file says they induce the same
   distribution. That identification is the only real content;
2. on top of it, `probOutput_map_get_uniformSample_vector` as a named
   corollary.

**Why upstream and not us.** (1) is a statement about upstream's own
instance diamond; a downstream `SampleableType` user has to know which of the
two instances a given `$ᵗ (Vector α n)` elaborated to before they can rewrite
with anything. That is upstream's to settle.

# D. Roadmap items — the ML-KEM security story

These three are one conversation, not three issues.

## 5. Nothing connects `asKEMScheme` to upstream's FO machinery

**Sharpened.** Round 3 asked for a KEM-level `kem_ind_cpa_security`. The
underlying problem is more specific and more interesting: upstream has *two
unrelated KEMs* for ML-KEM.

* `MLKEM.asKEMScheme` (`LatticeCrypto/MLKEM/KEM.lean:88`) — the executable
  one, wired to the concrete FIPS 203 instance, and the one every downstream
  user reaches for. It has **no security statement of any kind**.
* `MLKEM.foKEMScheme` (`LatticeCrypto/MLKEM/Security.lean:138`) — the
  Fujisaki–Okamoto composite (`FujisakiOkamoto` applied to
  `KPKE.asExplicitCoins`, with `implicitRejection (prfJ …)`), which is what
  `ind_cca_security` (`:174-194`, `sorry`) is stated about.

The two are never related, in either direction. So even if all three
`sorry`s in `Security.lean` were discharged tomorrow, *nothing would follow
about `asKEMScheme`* — the theorem would be about a different Lean term than
the one `mlkem768`'s users instantiate.

**Ask, in order of value.** (a) A bridge — `asKEMScheme ≃ foKEMScheme`, or
at minimum an advantage transfer in the IND-CPA and IND-CCA games. (b) The
KEM-level IND-CPA corollary we recorded verbatim in `PqStealth/MLKEM.lean`
("The missing upstream lemma"), which elaborates as written against the pin
and which `mlkem768_unlinkAdvantage_le_indCpa` composes with in a one-line
`calc`. (b) without (a) is still a statement about the wrong scheme.

## 6. The `sorry`s in `MLKEM/Security.lean`, and the shape of the MLWE hop

`kpke_ind_cpa_security` (`:99-109`), `kpke_delta_correct` (`:70-72`) and
`ind_cca_security` (`:174-194`) are placeholders. Upstream is honest about
this in the code — `ind_cca_security` carries a "**WARNING: this is a
placeholder statement, not the final theorem**" docstring that even explains
why its own `correctnessBound : ℝ` shape is unsound (`ENNReal.ofReal` clamps
negatives, so the bound can be driven arbitrarily negative). Downstream prose
still mistakes these for theorems; we did, and had to scrub "VCVio reduces …
to MLWE" from our docs.

**The finding worth passing along, now with upstream's own precedent.**
`kpke_ind_cpa_security` announces its MLWE instance over a *uniformly sampled
matrix*: `LearningWithErrors.Problem (TqMatrix params.k params.k) (TqVec
params.k) (TqVec params.k)` (`:100-102`). That shape is unusable by the
reduction adversary, which must output a real encapsulation key and cannot
invert `SampleNTT` to recover a seed from a matrix. The two hops must be
**seeded on `rho`** — which is precisely what our `keyHopProblem` /
`ctHopProblem` (`PqStealth/SPRTwoHop.lean`) do.

Upstream's own ML-DSA development reached the same conclusion independently:
`mldsaMLWE` (`LatticeCrypto/MLDSA/SecurityNMA.lean:201-211`, docstring at
`:179-200`) samples the
challenge as `(prims.expandSeed seed).1` and recovers the matrix on demand,
and its docstring gives our argument almost word for word — the seeded
phrasing "makes the distinguisher `B` total (no `ExpandA`-surjectivity
assumption)". So the ask is not a research question: **make ML-KEM's
announced problem shape seeded, as ML-DSA's already is**, before anyone
proves the `sorry` against the matrix shape and discovers the reduction
cannot be written.

## 7. KEM anonymity (ANO-CPA / ANO-CCA)

`VCVio/CryptoFoundations/KeyEncapMech.lean` (196 lines) defines
`KEMScheme`, correctness, `IND_CPA_*` (`:56-107`) and `IND_CCA_*`
(`:109-196`), and stops. A tree-wide search for `ANO`, `anonymity`,
`keyPrivacy`, `IK_CPA` returns **nothing**, in any scheme family.

**Why this is upstream's to own and not ours.** Recipient unlinkability of a
stealth-address scheme is *key privacy*, not message privacy: the hidden bit
picks which public key the challenge ciphertext was made under. That is a
notion about `KEMScheme`, at exactly the altitude of `IND_CPA_Adversary`,
and it is standard (Grubbs–Maram–Paterson, EC'22; Maram–Xagawa, PKC'23 for
ML-KEM specifically). We define it ourselves in `PqStealth/KEMAnonymity.lean`
(`KEM.AnonExp`, `KEM.anonAdvantage`) because we had to, and every downstream
user who needs it will define another, mutually incomparable version.
`vcvio-pin.md` already commits us to adopting upstream's the moment it
exists.

# E. New in this pass

## 12. `asKEMScheme.decaps` silently drops the input check

`LatticeCrypto/MLKEM/KEM.lean` defines a checked `decaps` at `:75-82` —

```lean
if decapsulationInputCheck encoding prims dk c then some (decapsInternal …) else none
```

— and then, at `:98`, builds the `KEMScheme` with

```lean
decaps := fun dk c => return some (decapsInternal ring encoding prims dk c)
```

i.e. the packaged scheme's decapsulation is **total**: it returns `some` on
every input, including malformed ciphertexts. The docstring says this is
deliberate ("assumes callers only supply inputs that have already passed the
public `encaps` / `decaps` checks"), which is defensible for an executable
wrapper — but `asKEMScheme` is also the term that flows into every *security*
definition in `CryptoFoundations/KeyEncapMech.lean`.

**Why it needs to change.** Any downstream notion phrased as "decapsulation
succeeds" is vacuously true at this scheme. That is not hypothetical: our
round-1 detection predicate for stealth-address scanning was exactly
"decapsulation returns `some`", and it made `scan` return `true`
unconditionally on the concrete ML-KEM instance — a formal model that read
like a theorem and said nothing. We fixed it downstream by recomputing the
aux data (`ofKEMFull`, `PqStealth/KEMAnonymity.lean`), but the trap is still
armed for the next user. Implicit rejection is also precisely the FO
behaviour `ind_cca_security` is about, so the checked and packaged versions
disagree on the security-relevant branch.

**Ask.** Either package the checked `decaps` (`:75`) into the `KEMScheme`, or
ship both (`asKEMScheme` / `asKEMSchemeChecked`) with the docstring saying
which one security statements are meant to use.

# F. Withdrawn

## 11. `mathlibStandardSet` linters vs `#guard_msgs in #print axioms`

The claim was that with `weak.linter.mathlibStandardSet = true` (which
upstream sets, `lakefile.lean`), the `style.commandStart` warning produced by
a multi-line `#print axioms` is captured by `#guard_msgs` and turns every
audit block into an error — and that this is worth reporting because it
"discourages exactly the build-enforced axiom audit a downstream user should
adopt".

The capture half is real and by design: `#guard_msgs` runs the inner command
through `elabCommandTopLevel` and collects *all* messages it produces,
linter warnings included (Lean 4.32.0, `src/Lean/Elab/GuardMsgs.lean:191-201`).
But the conclusion does not follow, because `#guard_msgs` takes message
filters exactly for this: `drop warning` deletes warnings before comparison
(*Interacting with Lean* → "Testing Output with `#guard_msgs`", tag
`hash-guard_msgs`; `FilterSpec.drop` at `GuardMsgs.lean:59-65`). The
supported spelling of our 95 audit blocks is therefore

```lean
/-- info: 'PqStealth.foo' depends on axioms: [propext, Classical.choice, Quot.sound] -/
#guard_msgs (drop warning, whitespace := lax) in
#print axioms PqStealth.foo
```

which keeps the guarded `info` message — the whole content of the audit —
while ignoring formatting warnings. Dropping warnings is safe *here*
specifically: `#print axioms` emits one `info` and nothing else, and a
`sorry` anywhere in the cone shows up inside that message as `sorryAx`
rather than as a warning on this command. The manual's own advice for
validating a proof is to read that message and check it names only
`propext`, `Classical.choice` and `Quot.sound` (*Validating a Lean Proof* →
"Printing Axioms", tag `validating-printing-axioms`) — which is exactly what
the guard freezes.

Two further facts deflate this one. The 95 guarded blocks in
`PqStealth/Axioms.lean` are *already* written as a docstring plus a single
command line (`Axioms.lean:38-39`), not the three-line continuation form
`vcvio-pin.md` still describes — so the shape the `style.commandStart`
warning objected to is not in the tree any more. And `drop warning` makes the
blocks robust to *any* future linter, not just this one.

So: not an upstream issue, and not a reason to keep `mathlibStandardSet`
off. **Our action, not theirs:** retry the mathlib standard set in
`lean/lakefile.toml` with the filter above in `PqStealth/Axioms.lean`, and
correct the corresponding bullet in `vcvio-pin.md` and the issue-14 row in
`improvements.md`.

# Suggested filing order (revised)

1. **Three mechanical PRs, no proofs, immediately mergeable:** item 3
   (`SampleableType` forwarding + `NeZero modulus`), item 1 (`DecidableEq`
   beside the concrete encodings), item 2 (de-privatize `byteEncode_size`).
   Each is a handful of lines with an in-repo precedent to point at
   (`VectorBackend.lean:81-97`, `Falcon/Arithmetic.lean:88`).
2. **Two zero-risk hygiene PRs:** item 4 (move
   `advantage_eq_game_boolDistAdvantage` into `LearningWithErrors.lean`) and
   item 9's residual (a "See also" from `RandomOracle/Basic.lean` to
   `ProgrammingOracle`). Both are moves/comments; both would have saved this
   development a round.
3. **One discussion thread on the ML-KEM security story** covering items 5,
   6 and 12: the `asKEMScheme` ↔ `foKEMScheme` disconnect, the seeded-vs-
   matrix MLWE shape (with ML-DSA's `mldsaMLWE` as the precedent), and the
   always-`some` decapsulation. These are design questions where our
   experience is input, not a patch.
4. **One feature request:** item 7, KEM anonymity in
   `CryptoFoundations/KeyEncapMech.lean`, with the two references.
5. **Two small asks, low priority:** item 8's heterogeneous `qP · qH · β`
   wrapper and item 10's instance-bridge plus corollary.

Items 11 and the reachability half of 9 are **not** to be filed.

# Our own follow-ups falling out of this revision

* Restate `DKSAPOracle.lean` and `BlindingROM.lean`'s ideal games over
  `QueryImpl.withProgramming` and close `BoundedByBadQuery` /
  `hashedDHRO ≤ dksapROBadProb` from
  `tvDist_simulateQ_randomOracle_withProgramming_le_probEvent_bad`. Update
  `docs/dksap-asymmetry.md` and `docs/announcement-model.md`, which currently
  call this an upstream gap.
* Delete `LearningWithErrors.advantage_eq_boolDistAdvantage` from
  `SPRTwoHop.lean` if upstream accepts the move (or import ML-DSA's, if not).
* Try `SampleableType`'s existing marginal lemmas on `Soundness.lean`'s
  view-tag hypothesis before asking upstream for anything.
* Retry `weak.linter.mathlibStandardSet` with `#guard_msgs (drop warning)`.
* Correct the two stale claims in `vcvio-pin.md` (RO module reachability; the
  linter incompatibility).

# Documentation index

The Lean facts cited above, in the Lean Language Reference
(<https://lean-lang.org/doc/reference/latest/>). Section titles and tags are
quoted from the manual's sources; this environment cannot reach lean-lang.org,
so deep links are given as chapter page + tag anchor rather than verified
URLs.

| Claim used here | Manual location |
|---|---|
| `def` creates semireducible definitions; semireducible definitions are "not unfolded by potentially expensive automation such as type class instance synthesis or `simp`"; `abbrev` is the reducible one | *Recursive Definitions* → "Controlling Reduction", tag `reducibility` — `/Recursive-Definitions/#reducibility` |
| Instance synthesis "respects reducibility … instances for a definition are not automatically treated as instances for its unfolding unless it is reducible"; `inferInstanceAs` preprocesses the synthesized instance so implementation details do not leak | *Type Classes* → "Instance Synthesis", tag `instance-synth` — `/Type-Classes/Instance-Synthesis/` |
| "If a declaration is marked `private`, then it is not accessible outside the module in which it is defined" | *Definitions*, tag `private` — `/Definitions/` |
| `#guard_msgs` compares the messages produced by the enclosed command against the docstring, and takes filters (`drop info`/`warning`/`error`/`all`), a whitespace mode (`exact`/`normalized`/`lax`) and an ordering | *Interacting with Lean* → "Testing Output with `#guard_msgs`", tag `hash-guard_msgs` — `/Interacting-with-Lean/#hash-guard_msgs` |
| `#print axioms` reports the axioms a proof transitively depends on; a validated proof should name only `propext`, `Classical.choice`, `Quot.sound`, and `sorryAx` means an incomplete proof | *Validating a Lean Proof* → "Printing Axioms", tag `validating-printing-axioms` — `/Validating-a-Lean-Proof/#validating-printing-axioms`; *Axioms*, tag for `#print axioms` |

Lean core sources cited for `#guard_msgs` behaviour are from the pinned
toolchain: `leanprover/lean4 @ v4.32.0`, `src/Lean/Elab/GuardMsgs.lean`
(`FilterSpec` at `:59-65`, message collection at `:191-201`, filtering at
`:211-216`).
