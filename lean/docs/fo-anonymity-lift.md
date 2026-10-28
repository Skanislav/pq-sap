# The FO anonymity lift — `ANO-CCA` for adversaries that query decapsulation

Scope: the one **genuinely open** arrow in the ML-KEM recipient-anonymity chain.
Companion to `spr-two-hop.md` (which covers the CPA-level SPR route). This note
records why the lift is nontrivial, the honest statement shape, and the
milestone definition. Everything here is a **design/decision record**; no new
theorem is claimed until it lands in `lean/PqStealth/` behind a `lake build`.

## Where the chain already bottoms out

`KEMAnonymity.lean` (`section OracleGames`) proves, sorry-free:

- `ANO_CCA_Advantage_le_of_spr` — a **CPA adversary lifted into the CCA game**
  (`adv.toANO_CCA`, which never issues a decapsulation query) is bounded by the
  two per-branch SPR terms. The decapsulation oracle exists in the game; the
  bound only covers adversaries that ignore it.

So the deployed-adversary claim — one that *does* call `Decap(b, c)` — is open.

## Why the naive lift is FALSE (the load-bearing fact)

The tempting statement is `ANO-CCA(KEM) ≤ ANO-CPA(PKE) + (small)`. **It does not
hold.** This is the substance of Maram–Xagawa's anonymity analysis of the
Fujisaki–Okamoto transform (and why "FO preserves anonymity" needs a stronger
hypothesis than base-PKE anonymity):

- Under **implicit rejection**, `Decaps(sk, c)` recomputes a shared secret by
  decapsulating and — for the FO transform — *checking consistency by
  re-encryption* (`c =? Enc(pk, Dec(sk,c); G(Dec(sk,c)))`).
- In the **anonymity** game the adversary holds both public keys `pk0, pk1`
  (the hidden bit selects which one the *challenge* encapsulates to; the decap
  oracle is keyed by a `Bool`, so it can decapsulate under either key).
- The adversary can therefore craft a ciphertext that is a **valid
  K-PKE encryption under `pk_b` but malformed under `pk_{1-b}`**, query
  `Decap(β, c)`, and observe whether it got a consistent shared secret or an
  implicit-rejection value `J(z_β, c)`. The re-encryption/consistency **check
  outcome leaks which key** — even though the base PKE is anonymous. That is a
  concrete counterexample to naive preservation.

Consequence: `ANO-CCA ≤ ANO-CPA + FO` is not a theorem. The correct hypothesis
is an **extended base anonymity notion** that already equips the adversary with
a *checking/decapsulation* oracle (Maram–Xagawa's shape), i.e. the base PKE must
be anonymous against an adversary that can probe validity — not merely a CPA
adversary.

## The honest statement shape (milestone 1)

The deployable claim decomposes into (i) a base anonymity game that *carries* the
checking capability, plus (ii) an explicit **bad event** for the only thing the
simulator cannot answer honestly. Concretely:

```
ANO-CCA_{FO-KEM}(A)  ≤  ANO-Chk_{K-PKE}(B_lifted)          -- extended base anonymity
                        + Pr[ badDecap ]                   -- A queries a malformed ct
                                                             the sim can't resolve
```

where

- `ANO-Chk_{K-PKE}` is the extended game: keys `(pk0,sk0),(pk1,sk1)`, hidden bit
  `b`, adversary sees `pk0, pk1` and one challenge ciphertext, and may query a
  **checking oracle** `Chk(i, c) := (Enc(pk_i, Dec(sk_i, c); G(Dec(sk_i,c))) == c)`
  (equivalently a base decapsulation oracle; validity is a function of it).
- `badDecap` fires when `A` issues a decapsulation query the ROM transcript plus
  both public keys cannot resolve without a secret key — i.e. a ciphertext that is
  inconsistent under re-encryption yet whose rejection value `J(z,c)` is being
  probed. That is the single honest residual the simulator cannot fake; it is a
  random-oracle event, bounded by a query-count/entropy argument, and is the FO/
  RO step.

This composes with the existing chain rather than adding an uncontrolled term:
`eps_prim` / `eps_keyIdeal` already *name* the RO/PRF idealization for `G`,
`H`, `PRF_η` at the SPR layer (`SPRTwoHop`). The `badDecap` term is the *same*
RO discipline applied to the decapsulation oracle — one more named RO/entropy
event, not a new free-floating epsilon.

## Why VCVio can carry it (pin `a5f474fd`)

The machinery the hop sequence needs already exists in the pinned VCVio; the
milestone is assembly, not new primitives:

- `OracleComp/QueryTracking/RandomOracle/ProbeEps.lean` — random-oracle probing
  with per-query/entropy bounds. This is where `badDecap` gets bounded.
- `QueryTracking/ProgrammingOracle.lean` + `ProgramLogic/Relational/
  ProgrammingOracle.lean` — lazy RO programming for the `G`/`H`/`J` simulation.
- `StateSeparating/IdenticalUntilBad.lean`
  (`advantage_le_expectedQuerySlack_plus_probEvent_bad` and the
  `*_of_inv` variants) — the identical-until-bad lemma packaging the hop.
- Our own `PqStealth/ROMUpToBad.lean` already builds the
  `boolDistAdvantage_run'_cacheQuery_run'_empty_le`-family bridges on exactly
  this machinery, so the RO hop is a worked pattern in-tree, not a cold start.

## The four advisor questions, answered (GLM-5.3 consult, 2026-10-17)

**A. Statement shape.** Neither "≤ ANO-CPA + eps_FO" (false) nor a self-contained
"SPR_CCA with its own oracle reduction" (circular — it re-hides the checking
power). The honest form is the two-term decomposition above: an *extended* base
anonymity game that already carries the checking oracle, plus the named bad
event. The extension is the hypothesis the counterexample forces.

**B. Decap answering.** Simulate `Decaps` from the RO transcript: answer the
re-encryption check using both public keys (no secret needed for the *check*
itself when the adversary supplies a valid `(m, r)` via the `G` query); lazily
sample `J`-outputs via `CachingOracle`. Consistency with real decap holds
*except* on `badDecap`, which is precisely the malformed-ciphertext case.

**C. Seeded-MLWE.** The FO lift does **not** require inverting `SampleNTT`: the
decap simulation programs `G`/`H`/`J` and checks re-encryption from public keys
and RO queries — all seed-free. The seeded-MLWE hops (`keyHop`/`ctHop`/
`keyRestoration`) live unchanged at the SPR layer below; the CCA extension sits
strictly above and adds no seed-inversion step. Seeded shape is preserved.

**D. Pragmatic milestone.** Exactly milestone 1 above. It is the smallest step
that (1) is provable on the current pin, (2) tightens the deployed-adversary
claim from "ignores the decap oracle" to "queries decap, bounded by extended-anonymity
+ named bad event", and (3) does not fake the ROM part — the bad event is stated
and bounded, not elided. The full Maram–Xagawa *proof* (reducing the extended
game itself to MLWE through the FO transform) remains the open research piece.

## What is still NOT closed

- The extended-anonymity game `ANO-Chk_{K-PKE}` is a *named hypothesis*, not yet
  reduced to MLWE. Reducing it runs back through the FO transform with the
  checking oracle — the actual Maram–Xagawa theorem — and is out of milestone-1
  scope.
- QROM. The chain is classical ROM (`simulateQ`, level-0 oracle specs). A
  quantum adversary querying `G`/`H`/`J` in superposition needs the QROM variant,
  which VCVio does not provide. Flagged, not claimed.
