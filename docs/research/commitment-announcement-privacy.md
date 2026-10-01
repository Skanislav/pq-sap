# The commitment format in the announcement-privacy model

Status: research note feeding the security-analysis write-up
(SECURITY_ANALYSIS.md review priority 2). It instantiates the proved generic
`ofKEMFull` announcement-privacy chain at the D-024 commitment profile
(format `0x02`), states exactly which assumptions that instantiation needs,
and contrasts it with the Construction A (`0x01`) instantiation the chain was
originally built for. Analysis only; no protocol change is proposed.

Every theorem cited is sorry-free in `lean/PqStealth/` (guarded by the
`Axioms.lean` audit); line numbers are from `main` at `7d5e15e`. The ROM
argument of §3 is a sketch for review, not a theorem — §5 states the boundary
precisely.

## 1. The instantiation

The commitment derivation (`python/pq_stealth/commit.py`, D-024; wire format
`0x02 ‖ spend_key(32) ‖ kem_ek`, 1,217 B at ML-KEM-768) is a deterministic
function of the KEM shared secret `ss` and the recipient's *public*
meta-address material:

```
opener       = SHA-256(OPEN_DOMAIN ‖ ss)                       (32 B)
commitment   = keccak256(COMMIT_DOMAIN ‖ spend_key ‖ opener)    (32 B)
address      = CREATE2(factory, salt, initcode(commitment, …))   (20 B)
view_tag     = SHA-256(ss)[0:1]                                 (1 B)
announcement = (stealth_address, ct, view_tag)
```

The generic announcement-privacy model (`KEMAnonymity.lean`) is
`StealthScheme.ofKEMFull kem auxGen` with `auxGen : K → PK → Aux`, announcement
`(ct, auxGen ss pk)`, and a scan that recomputes aux from the decapsulated
secret and the recipient's own public key (`KEMAnonymity.lean:145-155`; why
the second argument is load-bearing, and why the scan must recompute rather
than test decapsulation, is in `lean/docs/announcement-model.md`). The
format-`0x02` instantiation is:

```
PK   := CommitMetaPublic  = (spend_key, kem_ek)     — both public
SK   := kem_dk            — the ML-KEM decapsulation key alone
K    := 32-byte shared secret
Aux  := Tag × Addr        — view tag + stealth address
auxGen ss pk := ( SHA-256(ss)[0:1],
                  CREATE2(keccak256(COMMIT ‖ pk.spend_key ‖ SHA-256(OPEN ‖ ss))) )
```

Two structural facts make this the faithful instance of the generic model:

- **The view tag is a function of the shared secret alone** — exactly the
  `taggedAux viewTag rest` shape (`Soundness.lean:305`), which is what the
  detection-soundness chain consumes
  (`soundWithin_ofKEMFull_oneByteTag`, `Soundness.lean:373`).
- **The address is a deterministic function of `(ss, spend_key)`** — the
  recipient dependence enters through the *public* `spend_key` slot of
  `auxGen`'s second argument and nowhere else. There is no recipient-side
  lattice mask to model at receive time: unlike Construction A, whose
  announced key is `hashAddr (pack rho (power2Round (u + t)))` with `rho` and
  `t` the recipient's own meta-address material and only `(s', e')` from the
  secret, the commitment address contains **no recipient secret-derived
  structure at all**. The account's spending scheme is behind the commitment
  hash — that is the point of D-024 (and D-018 for C13).

Everything downstream of `auxGen` in the generic chain therefore applies
verbatim, with no new Lean statement needed for the composition: the
four-term bound `unlinkAdvantage_ofKEMFull_le` (`KEMAnonymity.lean:236`), the
IND-CPA identification of the hiding terms
(`sharedSecretHiding_eq_indCpaAdvantage`, `SharedSecretHiding.lean:187`), the
multi-payment hybrid `unlinkAdvantageMulti_ofKEMFull_le` (`MultiUnlink.lean:281`),
and the n-recipient pair-guessing bound `unlinkAdvantageN_ofKEMFull_le`
(`MultiRecipient.lean:358`). The generic chain fixes the *shape* of the bound;
the only term whose value it does not fix is `auxKeyIndependence`
(`KEMAnonymity.lean:228`), because that is the term that depends on
`auxGen`'s concrete structure.

## 2. The single-payment bound, instantiated

At the commitment `auxGen`, the four-term decomposition
(`KEMAnonymity.lean:236-241`) reads

```
Adv_unlink ≤ ssHiding(true) + auxKeyIndependence + KEM.anonAdvantage + ssHiding(false)
```

with each term now concrete:

| Term | What it is at format `0x02` | Status |
| --- | --- | --- |
| `ssHiding(b)`, one per branch | Exactly the ML-KEM-768 IND-CPA advantage of the reduction adversary (`sharedSecretHiding_eq_indCpaAdvantage`, `SharedSecretHiding.lean:187`) | Named KEM term; the FO-to-MLWE bridge is the same open upstream lemma as for Construction A (`mlkem768_sprAdv_le_mlwe`, `SPRTwoHop.lean:605`, covers the anonymity side) |
| `auxKeyIndependence` | **The only commitment-specific term.** With the secret idealized to a fresh uniform `ss'` (`randAuxBranch`, `KEMAnonymity.lean:203`), aux is `(SHA-256(ss')[0:1], CREATE2(keccak256(‖spend_key‖SHA-256(ss'))))` — a deterministic function of a uniform 256-bit string and a public constant | Bounded in §3 under ROM assumptions on SHA-256 and keccak256 — **no lattice assumption enters** |
| `KEM.anonAdvantage` | ML-KEM-768 ciphertext anonymity (key privacy) | Decomposed to seeded-MLWE plus named assumption records via `anonAdvantage_le_sprAdv` (`AnonymityFromSPR.lean:49`) and `mlkem768_sprAdv_le_mlwe` (`SPRTwoHop.lean:605`) |

**What disappears relative to Construction A.** The `0x01` instantiation
needs the seeded-MLWE blinding hop (`ConstructionA.lean`'s
`blindingProblem` / `mlweAdvOfUnlinkAdv`, with its `ExpandIsIdeal`
XOF-idealization assumption), and where a proof-grade ROM bound is wanted, the
point-mass machinery of `BlindingROM.lean` / `BlindingEntropy.lean` — which
exists to handle a lattice address point of low min-entropy: at ML-DSA-65 the
point-mass is `betaAddr = (2¹³/q)^2048 ≈ 2^-20477` per address-point guess
(`blindPointMassBound_mldsa65`), and the ROM bound is `2·qH·betaAddr`
(`blindBadProb_le_queryBound`, `BlindingEntropy.lean:94`). The commitment
address point is a full 256-bit hash *preimage-slot*: the recipient's input to
the address hash is a public constant (`spend_key`), and the only secret input
is the uniform `ss'`. The aux term is therefore a plain ROM argument with
point mass `2^-256` — **no MLWE hop, no `ExpandIsIdeal`, no lattice
point-mass**. The commitment profile is not merely "less proved" than the
supporting Construction A track; its aux argument is *structurally cleaner*,
and that contrast is what the ERC security-considerations text needs to
convey. (§5 records that the ROM bound itself is a sketch, not a theorem.)

## 3. `auxKeyIndependence` at format `0x02` — ROM bound sketch

The intermediate game `randAuxBranch kem auxGen adv b` (`KEMAnonymity.lean:203`)
replaces the real `ss` by a fresh uniform `ss'` but keeps building aux from
recipient `b`'s public key. The adversary sees `(ct, tag, addr)` plus both
meta-addresses `(spend_key₀, ek₀)`, `(spend_key₁, ek₁)` — the full public
view, per `unlinkSetup`. The term asks: can aux built from `spend_key_b` and
uniform `ss'` be told from aux built from `spend_key_{1−b}` and uniform `ss'`?

The argument is the ROM argument for a hash chain whose secret input is
uniform and whose recipient-dependence enters via a public constant in the
preimage:

1. **Inner hash (opener).** Model `ss' ↦ SHA-256(OPEN_DOMAIN ‖ ss')` as a
   random oracle. For a fresh `ss'` never queried before, `opener` is a fresh
   uniform 256-bit string independent of everything the adversary has seen —
   the uniform-output property, the same shape as BlindingROM's
   `run_hashAddrRO_empty` (`BlindingROM.lean:67`): uniform output *whatever*
   the input hashed. The adversary may program/observe queries on the inner
   oracle too; each query is a fresh uniform draw, and only a query on
   exactly the challenger's `ss'` (probability `2^-256` per guess) could
   correlate the branches.
2. **Outer hash (commitment) and CREATE2 chain (address).** Model the
   composite `(spend_key, opener) ↦ address` — i.e. `keccak256(0xff ‖ factory
   ‖ salt ‖ keccak256(initcode))` with `initcode` carrying
   `keccak256(COMMIT ‖ spend_key ‖ opener)` — as one random oracle
   `Bytes → Addr`, exactly the "composite as ONE function" reading
   `BlindingROM.lean` adopts for Construction A's `hashAddr ∘ pack`. For a
   fresh `(spend_key, opener)` pair not previously queried, the address is a
   fresh uniform `2^160`-point. The recipient's `spend_key` sits in the
   *preimage*: distinguishing branches is distinguishing oracle outputs on
   two public prefixes — impossible without querying the oracle on a point
   whose preimage involves the branches' differing secret draw.
3. **Union bound.** With at most `qH` queries to the outer oracle, the
   probability any query lands on the challenger's address point is at most
   `qH · 2^-160` per branch (each query guesses one of `2^160` addresses — or,
   read at the preimage level, one of `2^256` openers through the inner
   oracle: `qH · 2^-256`). Summing both branches and both oracle levels:

```
auxKeyIndependence ≤ 2·qH·2^-256   (inner-oracle reading; the 2^-160 outer
                                     reading is looser in the exponent that
                                     matters and dominated by the same qH)
```

The bound shape is `blindBadProb_le_queryBound` (`BlindingEntropy.lean:94`)
— `blindBadProb ≤ qH·β` per branch, `2·qH·β` total — with the commitment
point mass `β = 2^-256` in place of the lattice β. `qH = 2^80` queries leave
`2·qH·2^-256 = 2^-175`.

Assumptions, stated precisely:

1. **ROM on SHA-256 (opener) and on the keccak256 composite (commitment +
   CREATE2 chain).** The standard assumption the development already carries
   everywhere it reasons about hashes (D-015's SHA-256/keccak discipline;
   the ERC evidence map keeps the concrete primitives unmodelled).
2. **`ss'` uniform by construction.** In the `randAuxBranch` game the
   challenger draws `ss'` uniform — that is *by construction*, not an
   assumption. Getting there from the real game is the IND-CPA step, which
   the four-term decomposition already performs and prices into the
   `ssHiding` terms — so the aux argument consumes, rather than duplicates,
   that assumption. No circularity.
3. **Both recipients share the deployment binding (and profile).** The
   factory, creation code, salt, verifier, and frame context enter the
   address preimage as public constants *common to both branches*. If the two
   recipients use different bindings or profiles, their aux distributions
   differ for public reasons — that channel is auxiliary information outside
   the `auxGen` model (`unlinkSetup` draws both recipients from one
   `keygen`), and SECURITY_ANALYSIS.md's profile-narrowing paragraph covers
   it. The ERC text must state the single-profile/common-binding condition
   as a property.

**Reading the bound.** The commitment-side channel contributes at most
`2·qH·2^-256` — with a generous `qH = 2^80`, `2^-175` per payment pair. The
dominant terms of the format-`0x02` privacy bound are the KEM terms — ML-KEM
IND-CPA (twice) and ML-KEM ciphertext anonymity — which remain named
MLWE-level terms exactly as for Construction A. **The privacy story for format
`0x02` is: the KEM carries all the weight; the commitment side adds only the
ROM assumptions already on the books.** That sentence is what
SECURITY_ANALYSIS.md's review priority 2 asks for ("justify its
auxiliary-data independence under explicit hash assumptions"), and it is the
argument the ERC's security-considerations section should carry.

## 4. Multi-payment and multi-recipient composition

The multi-challenge hybrid is proved generically for every `auxGen` and
adversary: `unlinkAdvantageMulti_ofKEMFull_le` (`MultiUnlink.lean:281`) gives
`Adv_unlink_q ≤ q · ε_single` for `q` announcements between the same two
recipients (linear loss — `unlinkAdvantageMulti_le_mul`, `MultiUnlink.lean:241`),
and `unlinkAdvantageN_ofKEMFull_le` (`MultiRecipient.lean:358`) gives
`Adv ≤ n·(n−1)·ε_single` when the adversary names the challenge pair among
`n` published meta-addresses. Both are *instantiations of proved theorems*,
not paper composites — the per-hybrid adversary's four-term sum is the §2
bound each time.

A concrete reading for the write-up: with `qH = 2^80`, the aux term at `q`
observed announcements is `q · 2^-175`. Even a full-chain window of
`q = 2^20` announcements to the pair keeps it at `2^-155`; a `2^40` window at
`2^-135`. Whatever window the threat model picks, the commitment-side
channel stays negligible against the KEM terms — the statement the
security-analysis write-up should make quantitative, with the window `q`
stated explicitly (`announcement-model.md`'s guidance: the single-challenge
target must be `ε ≤ 2^-k / q` for a `k`-bit claim).

**Correction to the in-tree reading.** `lean/docs/announcement-model.md` says
the composition of `MultiUnlink`/`MultiRecipient` with `unlinkAdvantage_ofKEMFull_le`
is "on paper, not in Lean" (§ multi-challenge: "the composition is
nevertheless legitimate"; § `n`-recipients: "that composition is not in
Lean"). That was true when the essay was written; it is stale now:
`unlinkAdvantageMulti_ofKEMFull_le` (`MultiUnlink.lean:281`) and
`unlinkAdvantageN_ofKEMFull_le` (`MultiRecipient.lean:358`) discharge exactly
those instantiations. The essay is updated in this branch's companion commit.

## 4b. Detection soundness (the tag side)

The scan-side question is separately proved and equally instantiation-clean.
With a one-byte view tag the false-positive rate of `ofKEMFull` is at most
`1/256 + decapsRoR` (`soundWithin_ofKEMFull_oneByteTag`, `Soundness.lean:373`),
where `decapsRoR` is the same named real-or-random IND-CPA-shaped term as in
the unlinkability chain (a distinguisher that tells the recipient's real
decapsulated secret from a fresh uniform one inside `FalsePositiveExp`;
`Soundness.lean` names it rather than sweeping it into the statement). The
commitment profile's tag is exactly the `taggedAux` shape (`Soundness.lean:305`):
tag from the secret alone, address in `rest`. No lattice term appears on the
soundness side either. The `n`-fold union bound for a scanner sweeping `n`
announcements is on paper (not in Lean), as the essay already records.

## 5. What is and is not discharged

**Discharged — generic, sorry-free, applies verbatim to format `0x02`:**

- The four-term decomposition and its IND-CPA identification
  (`KEMAnonymity.lean:236`, `SharedSecretHiding.lean:187`).
- The multi-payment and n-recipient composites (`MultiUnlink.lean:281`,
  `MultiRecipient.lean:358`).
- Detection soundness at the deployed tag shape (`Soundness.lean:373`,
  `taggedAux` at `Soundness.lean:305`).
- Detection completeness (`perfectlyComplete_ofKEMFull`, `KEMAnonymity.lean:160`).

**Instantiation-specific — argued here, not proved:**

- The `auxKeyIndependence` ROM bound (§3). The shape is
  `run_hashAddrRO_empty`'s uniform-output property plus the
  `blindBadProb_le_queryBound` union bound, but the commitment `auxGen` has a
  different input structure (public constant in the preimage vs a masked
  lattice term), so it needs its own module in the Lean tree
  (`CommitmentAnonymity.lean`, future work; the natural plan mirrors
  `BlindingROM.lean`: one composite oracle, identical-until-bad, query-budget
  bound). Until it lands, §3 is a review artifact for the ERC's
  security-considerations text — the *assumption list* is rigorous, the bound
  is a sketch.

**Explicitly not claimed:**

- No reduction of the ML-KEM IND-CPA or anonymity terms to MLWE for this
  format — the FO bridge is the same open upstream lemma as for Construction
  A (`SPRTwoHop.lean`'s open item). No ANO-CCA for active attacks; the chain
  proves the passive game. Quantum ROM access remains outside, as everywhere
  in the development.
- No theorem covers *profile narrowing*: two recipients on different profiles
  (or deployment bindings) have differently-distributed aux for public
  reasons. The model's `unlinkSetup` draws both recipients from one `keygen`,
  i.e. the same profile; the narrowing channel is auxiliary information,
  covered by SECURITY_ANALYSIS.md's existing paragraph and stated as a
  property in the ERC text.
- Nothing here covers spending: the account behind the commitment has its own
  authorization and disclosure story (D-027's linkage analysis, the widened-`z`
  route-class channel for `0x01` blinded signing). Receive-time
  privacy and spend-time linkability are separate assurance tracks, exactly
  as SECURITY_ANALYSIS.md frames them.

## Reproduce

Numbers in §2–§4 from exact arithmetic (no dependencies):

```python
from fractions import Fraction as F

beta_commitment = F(1, 2**256)        # point mass per address-point guess
qH = 2**80                            # generous joint oracle-query budget
aux_term = 2 * qH * beta_commitment   # = 2^-175
assert aux_term == F(1, 2**175)

# Construction A contrast (ML-DSA-65): lattice point-mass
# betaAddr = (2^13/q)^2048, q = 8380417  ≈ 2^-20477
# (blindPointMassBound_mldsa65; needs the seeded-MLWE hop + ExpandIsIdeal)
```

Cross-checks: the four-term shape and `randAuxBranch`/`cipherOf` definitions
are `KEMAnonymity.lean:203/228/236`; the `taggedAux` + one-byte-tag chain is
`Soundness.lean:305/373`; `1/256` is the machine-checked tag bound's own
constant; the `q`-fold linear loss is `MultiUnlink.lean:241`.