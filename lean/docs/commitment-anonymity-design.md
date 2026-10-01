# `CommitmentAnonymity.lean` — module design

Status: design doc for the future Lean module that closes the one
instantiation-specific gap of the format-`0x02` announcement-privacy story —
the `auxKeyIndependence` ROM bound. This is a *design*, not a proof: no
`CommitmentAnonymity.lean` exists yet, and nothing here changes the
sorry-free state of `PqStealth/`. The module is planned Lean future work
(gated on a local `lake`/VCVio toolchain, which this host lacks); the doc
exists so the module lands as a port of a settled design rather than a
from-scratch exploration, and so reviewers of
[commitment-announcement-privacy.md](../../docs/research/commitment-announcement-privacy.md)
can check the §3 sketch against a proof plan.

Companion note: `docs/research/commitment-announcement-privacy.md` (the
instantiation + ROM sketch this module must discharge);
`announcement-model.md` (the `ofKEMFull` model and the terms).

## 1. What the module must prove

The generic chain (`KEMAnonymity.lean:236`) bounds unlinkability of
`StealthScheme.ofKEMFull kem auxGen` by

```
Adv_unlink ≤ ssHiding(true) + auxKeyIndependence + KEM.anonAdvantage + ssHiding(false)
```

and everything except `auxKeyIndependence` (`KEMAnonymity.lean:228`) is
already discharged generically or named. The commitment profile's
`auxGen` is (§1 of the companion note):

```
PK   := (spend_key, kem_ek)                       — both public
Aux  := Tag × Addr
auxGen ss pk := ( SHA-256(ss)[0:1],
                  CREATE2(keccak256(COMMIT ‖ pk.spend_key ‖ SHA-256(OPEN ‖ ss))) )
```

The module's goal statement, in the shape of
`blindingAdvantageRO_le_queryBound` (`BlindingEntropy.lean:107`):

> There is a query-bounded ROM game whose advantage bounds
> `auxKeyIndependence` from above, and that advantage is at most
> `2 · qH · 2⁻²⁵⁶`.

The exact target, mirroring how `ConstructionA` handles its own gap: a
**standalone abstraction** first (like `blindGameRO`, `BlindingROM.lean:103`),
with the identification of the abstraction's advantage with the concrete
`auxKeyIndependence` term left to the instantiation layer — the module proves
the ROM half sorry-free and states the bridge explicitly.

Design principle carried over from `BlindingROM.lean:20-22`: the ROM game is
"NOT identified with it here" — the abstraction boundary is drawn on purpose,
so the generic `ofKEMFull` layer never needs to know about oracles.

## 2. Why the commitment instance is *simpler* than Construction A (and what that means for the design)

`ConstructionA`'s aux term needs three layers:
`blindingProblem` / `mlweAdvOfUnlinkAdv` (seeded-MLWE hop), the
`ExpandIsIdeal` XOF idealization, and the point-mass machinery
(`BlindingEntropy.lean`), because the address point
`pack rho (power2Round (u + t))` has *low min-entropy* per coordinate — the
fiber bound `card_power2Round_fiber_le` (`BlindingEntropy.lean:162`) gives
point mass `(2^d/q)^(k·256)` per address-point guess, and the whole
`BlindPointMassBound` hypothesis exists to price that.

The commitment address point is different in kind: the secret input is a
**uniform 256-bit string** (`ss'` from `randAuxBranch`, `KEMAnonymity.lean:203`)
and the recipient's input (`spend_key`) is a **public constant in the
preimage**. Consequences for the design:

- **No MLWE hop.** The module imports nothing from `SPRTwoHop` or
  `ConstructionA`. No `ExpandIsIdeal`.
- **No fiber combinatorics.** The point-mass bound is the trivial one: a
  uniform 256-bit string hits any fixed point with probability `2⁻²⁵⁶`. The
  analog of `BlindPointMassBound` is one line of `probEvent_uniformSample`,
  not a coordinate-wise `Finset.card` argument.
- **The hash composite is the oracle.** What must be random is the composite
  `spend_key, ss' ↦ address` — exactly the "composite as ONE function"
  reading `BlindingROM.lean` adopts for `hashAddr ∘ pack`. One oracle, not
  a chain of two.

The design risk is therefore *not* proof difficulty but **faithfulness of
the abstraction**: the ROM game must be obviously the game the commitment
profile plays. That is why the interface is parameterized on byte-level
objects (below) rather than reusing Construction A's `Prims`.

## 3. Interface: what the module is stated over

Following `BlindingROM.lean`'s parameterization style (`Prims R Rho Bytes
T1 Tag Addr K k l`) but replacing the lattice-flavored parameters with
byte-level ones:

```lean
namespace PqStealth.CommitmentAnonymity

variable {Bytes SS Tag Addr SpendKey : Type}
variable [DecidableEq Bytes] [SampleableType SS] [SampleableType Addr]
variable (openOracle  : Bytes →ₒ SS)          -- SHA-256(OPEN ‖ ·), idealized
variable (auxOracle   : Bytes →ₒ Addr)        -- composite commit+CREATE2, idealized
variable (tagOf       : SS → Tag)             -- SHA-256(ss)[0:1], un-modelled
variable (preimage    : SpendKey → SS → Bytes) -- COMMIT ‖ spend_key ‖ opener
```

Design decisions, with reasons:

1. **Two oracles, one composite — and an explicit bridge obligation
   (review F3).** The opener hash and the commitment/CREATE2 composite are
   separate oracle types in the interface (`Bytes →ₒ SS`, `Bytes →ₒ Addr`),
   but the adversary-facing game queries only through the composite — the
   challenger queries the inner oracle once (to draw the opener) and hands
   the result to the outer. This is the `addrSpec := unifSpec +
   (Bytes →ₒ Addr)` pattern (`BlindingROM.lean:38`) with one extra spec.
   Reason: the §3 sketch's union bound runs over the *outer* oracle's query
   budget (`qH` hidden-preimage guesses at 2⁻²⁵⁶ each), and keeping the inner
   oracle explicit lets the module state the uniform-output property at the
   inner level as a lemma rather than folding it into an assumption.
   **What this interface does not yet model:** the adversary's queries to
   the *real* intermediate hashes — the concrete commitment hash and the
   concrete keccak256 initcode hash — on adversarially chosen inputs. The
   composite abstraction hides that access; a faithful instantiation
   argument must either simulate those queries in the reduction or prove the
   composite inherits per-hash ROM uniformity under composed queries. That
   bridge is **open work**, recorded here and in the companion note §3;
   theorems proved over this interface are statements about the abstract
   game, not yet about the deployed commitment/CREATE2 chain.
2. **`SpendKey` is a public constant, not a secret.** The interface does not
   model `spend_key` generation — it is a parameter handed to the game,
   exactly like `rho : Bool → Rho` in `blindGameRO` (`BlindingROM.lean:103`).
   The recipient *pair* appears as `spend_key : Bool → SpendKey`, and the
   module says nothing about how the pair was drawn (the single-profile
   condition lives at the `unlinkSetup` level; see §6).
3. **`ss'` uniform by construction.** The game draws `ss' ← ($ᵗ SS)` itself —
   this is the *post-`randAuxBranch`* game, matching
   `BlindingROM`'s "with the mask already idealized" stance
   (`BlindingROM.lean:81-84`). The IND-CPA hop that gets here is already
   performed and priced by the generic chain (`sharedSecretHiding`,
   `SharedSecretHiding.lean:187`); the module must not (and does not) redo
   it. No circularity, per the companion note §3 assumption 2.
4. **`Tag` carried opaquely, with the deployed-tag condition stated
   (review F3).** The view tag is a deterministic function of `ss'` alone —
   the `taggedAux` shape (`Soundness.lean:305`) — so it is
   branch-independent once `ss'` is fixed and drops out of the
   branch-distribution advantage by the same argument as
   `blindingAdvantageRO_eq_zero_of_no_query` (`BlindingROM.lean:134`) uses
   for the tag there. **Branch-independence alone is not the harmless
   property.** An opaque `tagOf : SS → Tag` could be `tagOf ss = ss` —
   secret-revealing, and the adversary would compute both candidate
   destinations through the public hashes, breaking the game. The
   drop-out argument needs the *deployed* tag's properties jointly with
   the opener/address derivation: (i) the tag is a truncation of a hash of
   `ss'`, so it leaks nothing the oracle does not already gate behind a
   hidden-preimage query; (ii) the one-byte tag cannot steer a query
   toward the challenge address. Carrying `Tag` opaquely in the interface
   is therefore a *statement-shape* choice (aux is `Tag × Addr`,
   shape-faithful to `ofKEMFull`); instantiating the drop-out lemma for
   any concrete profile must analyze that profile's actual tag function —
   the companion note §3 assumption 4 does this for the deployed
   SHA-256(ss)[0:1].

## 4. The game, and the four planned theorems

The game mirrors `blindGameRO` (`BlindingROM.lean:103`) branch-for-branch:

```lean
/-- Branch b: draw uniform ss', draw the opener via the inner oracle,
    build the address via the composite, hand (tag, addr) to the adversary. -/
noncomputable def commitGameRO (spendKey : Bool → SpendKey) (b : Bool)
    (adv : Tag × Addr → ROMComp Bool) : ProbComp Bool := do
  let ss' ← ($ᵗ SS)
  let opener ← hashOpenRO ss'                    -- inner-oracle query
  let addr  ← auxRO (preimage (spendKey b) opener) -- composite query
  adv (tagOf ss', addr)
```

Planned theorem ladder (names provisional, statement shapes final):

1. **`commitGameRO_eq`** — the `blindGameRO_eq` (`BlindingROM.lean:119`)
   analog: after the challenger's queries, both branches are the SAME
   computation run from caches that differ at one point — the outer-oracle
   entry at `(spend_key_b, opener)` for the branch's own uniform draw.
   Proof: `run_hashAddrRO_empty` (`BlindingROM.lean:67`) applied twice
   (inner then outer); the branch enters only through the public
   `spend_key` prefix of the preimage.
2. **`commitAdvantageRO_eq_zero_of_no_query`** — the degenerate
   identical-until-bad case (`BlindingROM.lean:134` analog): an adversary
   that never queries the oracles sees a uniform address on both branches;
   advantage `0`. This is the module's **positive control**, the role
   `auxKeyIndependence_eq_zero_of_pk_independent` plays in
   `announcement-model.md` §"what the negative control pins down" — a
   sanity check that the game measures the right thing.
3. **`commitAdvantageRO_le_commitBadProb`** — identical-until-bad against
   VCVio's programming-oracle engine, via `ROMUpToBad`'s
   `tvDist_run'_romImpl_policy_le_probEvent_bad`
   (`ROMUpToBad.lean:24-26`): branch distance ≤ probability the adversary
   queries the branch's address point. Direct reuse of
   `blindingAdvantageRO_le_blindBadProb`'s proof shape.
4. **`commitBadProb_le_queryBound`** — the union bound closing the gap:
   `Pr[bad] ≤ qH · 2⁻²⁵⁶` per branch, then
   **`commitAdvantageRO_le_queryBound : commitAdvantageRO ≤ 2 · qH · 2⁻²⁵⁶`**.
   The `BlindingEntropy.lean:94-121` proof replays with two simplifications:
   the point-mass hypothesis `BlindPointMassBound` is replaced by the trivial
   uniform-draw bound (`probEvent_uniformSample`, one line — the fiber
   combinatorics of `card_power2Round_fiber_le` vanish because the secret is
   a uniform string, not a rounded lattice mask), and no `β ≠ ⊤` side
   condition is needed beyond the same `toReal` hygiene.

## 5. What the module deliberately does NOT do

Mirroring the companion note §5, so the axiom audit stays honest and no
claim creeps past what is proved:

- **No identification with `auxKeyIndependence` inside the module.** Like
  `BlindingROM.lean`'s "Assumed / NOT closed" header note, the bridge from
  `commitGameRO` to the concrete `auxKeyIndependence`
  (`KEMAnonymity.lean:228`) of `ofKEMFull commitKem commitAuxGen` is stated
  as an explicit TODO comment + docstring, not proved. The bridge needs the
  instantiation layer (concrete `K := Fin 256 → Bool`-shaped shared secret,
  `SpendKey := Bytes`, the composite-as-one-function reading of
  keccak256 ∘ CREATE2) which belongs with the ERC profile layer, not the
  generic ROM module.
- **No ROM model of SHA-256 or keccak256 themselves** — the oracles are
  VCVio lazy random oracles (`roImpl`, `ROMUpToBad.lean:49`), the same
  idealization `BlindingROM` uses. D-015's discipline (concrete primitives
  un-modelled) is unchanged.
- **No MLWE, no `ExpandIsIdeal`, no imports from `ConstructionA` /
  `SPRTwoHop`** — the module is dependency-light: `ROMUpToBad`, `Reorder` (if
  the sample-swap step needs it, as `BlindingEntropy.lean:72-77` does), and
  core `VCVio.OracleComp`. This keeps the build cone small and the axiom
  audit surface minimal.
- **No statement about profile narrowing or multi-recipient composition** —
  the composites (`MultiUnlink.lean:281`, `MultiRecipient.lean:358`) apply
  verbatim once the single-payment bound is an `auxKeyIndependence` bound,
  and the narrowing channel is auxiliary information outside `auxGen`
  (companion note §5).

## 6. Hypothesis hygiene (audit honesty)

Per the repo's testing discipline: a new theorem with a hypothesis bundle
needs an inhabitance witness so the audit stays honest. The module's
hypotheses are byte-level parameters, and the witnesses are trivial to
state:

- `IsQueryBoundP` (the adversary's outer-oracle budget, the
  `BlindingEntropy.lean:40` shape): witnessed by the constant-`false`
  adversary, which makes no queries.
- The `SampleableType`/`DecidableEq` instances: witnessed by `Bytes :=
  Fin 32 → Bool`-style finite types (or VCVio's byte-vector types) in the
  module's docstring example, keeping the statements computational where
  `#eval`-able.
- The single-profile/common-binding condition: NOT a hypothesis of any
  theorem in this module — it lives at the `unlinkSetup` layer
  (both recipients drawn from one keygen, one profile), stated in the
  companion note §3 assumption 3 and left to the ERC text. Keeping it out
  of the module is what keeps the module generic over `SpendKey`.

## 7. Build and verification plan (when a toolchain is available)

1. `lake build PqStealth.CommitmentAnonymity` first — the module imports
   only `ROMUpToBad` (+ possibly `Reorder`), so the incremental cone is
   small; no VCVio cold-build risk beyond what `BlindingROM` already
   requires.
2. Zero-warnings/sorries policy: the module lands either fully proved or
   with NO `sorry` and the bridge explicitly out of scope (§5) — the
   `Axioms.lean` `#guard_msgs #print axioms` audit must show no new axioms.
   If a step fails, the fallback is to ship theorems 1-2 (the abstraction +
   positive control, which need only `run_hashAddrRO_empty`-style lemmas)
   and mark 3-4 as the open tail — better a smaller proved surface than a
   sorry.
3. Update `lean/README.md`'s module table and regenerate
   `lean/docs-proofs/` (`scripts/gen_browser.py`) in the same change set;
   the citation checker (`scripts/check_citations.py`) must stay green —
   every `X.lean:N` in this doc resolves on `main` at `7d5e15e`.
4. `check_sizes.py` untouched — the module proves no byte sizes.
5. The companion note's §5 "future work" paragraph is the sentence to
   strike when this lands; the SECURITY_ANALYSIS.md row's "Remaining
   boundary" column (this branch's edit) is the second strike-through.

## 8. Estimated shape

~250-350 lines of Lean, roughly: interface + game ~80, theorem 1 ~40
(a `bind_congr` chain like `BlindingROM.lean:127-129`), theorem 2 ~25,
theorems 3-4 ~120 (the `BlindingEntropy.lean:42-103` skeleton with the
point-mass step replaced by `probEvent_uniformSample`), plus the docstring
header carrying the "NOT identified with `auxKeyIndependence` here" boundary
note. The dominant risk is VCVio `OracleComp` plumbing, not mathematics;
the identical-until-bad engine is fully generic (`ROMUpToBad` states
everything over an arbitrary `hashSpec`), and the commitment instance is
strictly simpler than the one `BlindingEntropy` already discharged.