# After Poseidon: BLAKE2/3, Binius-era proving, and the hash policy for PQ stealth discovery

**Research question.** The Ethereum Foundation announced (2026-08-13) that it is abandoning
Poseidon for L1. Our discovery-layer design (`poseidon2-stark-discovery.md`, 2026-08-05) used
Poseidon2 in three places, each explicitly flagged "pending EF cryptanalysis outcome." What
happened, what do BLAKE2/BLAKE3 and Binius-style binary-field systems change, and what should
our hash policy be now?

**Date:** 2026-08-15. Sources: web research (three sweeps: EF decision primary sources; standard-
hash proving costs 2026; Binius/AO-hash landscape), citations inline. No local code is affected —
Poseidon2 was never normative in this project (spec/vectors/ERC draft use SHAKE256, SHA-256,
keccak only).

---

## Verdict in one paragraph

The EF's pivot **confirms and strengthens** the conservative track our design already kept open.
The reason Poseidon2 appeared in our architecture at all was the ~100× in-circuit penalty of
standard hashes; that penalty has collapsed to a single-digit factor in 2026 provers built for
Boolean computation (Flock, Binius64, binary GKR), while Poseidon's cryptanalytic margin visibly
eroded (full-round CICO-2 on an instance, initiative prizes paused). Consequence for us: **drop
Poseidon2 from every site in the discovery design and standardize on SHA-256** (normative,
EIP-8304-aligned), with BLAKE3/BLAKE2s permitted as prover- or indexer-internal choices. The
dual-root accumulator dies (it existed only to dodge the penalty), the tag-chain PRF becomes
SHA-256, and the ZK-spend membership path uses standard-hash Merkle paths in a Flock-class or
zkVM prover. "Binius-like hashes" (Vision Mark-32, Grøstl) are the one idea we examined and
rejected: the Binius lineage's own conclusion is that hash-friendly SNARKs beat SNARK-friendly
hashes, and the arithmetization-oriented (AO) hash family as a whole is taking cryptanalytic
hits. Our discovery pipeline is now single-hash-family and PQ-sound from standard hashes alone —
the same assumption set lean Ethereum itself is converging on.

## 1. What the EF actually decided (primary sources)

- **The announcement.** 2026-08-13, Justin Drake on X
  ([drakefjustin/2087905684180418733](https://x.com/drakefjustin/status/2087905684180418733)):
  "Goodbye, Poseidon! An epic 8-year, 8-figure rabbit hole in post-quantum cryptography reaches
  its dream conclusion. The Ethereum Foundation is abandoning Poseidon for L1, pivoting to SHA
  or BLAKE." Key rationale line (via
  [crypto.news, 2026-08-13](https://crypto.news/ethereum-l1-drops-poseidon-in-post-quantum-move/)):
  **"In hindsight the key was not SNARK-friendly hashes, but hash-friendly SNARKs."**
  Corroborated same-day/next-day by
  [Cointelegraph/TradingView](https://www.tradingview.com/news/cointelegraph:94d0d54b3094b:0-ethereum-foundation-pivots-away-from-poseidon-in-post-quantum-plan/),
  [FXStreet 2026-08-14](https://www.fxstreet.com/cryptocurrencies/news/ethereum-foundation-pivots-away-from-poseidon-in-post-quantum-plan-202608140530),
  and others.
- **What replaces it.** "SHA-2 or BLAKE2s" is the wording carried by the detailed coverage
  ([crypto.news](https://crypto.news/ethereum-l1-drops-poseidon-in-post-quantum-move/),
  [bitcoinworld](https://bitcoinworld.co.in/ethereum-foundation-shifts-to-sha2-blake2s-over-poseidon-hash/));
  some outlets say "SHA and BLAKE3"
  ([KuCoin flash](https://www.kucoin.com/news/flash/ethereum-foundation-shifts-focus-from-poseidon-to-sha-and-blake3-hashes)).
  The correct reading: **the family is decided (standard bit-oriented hashes), the exact member
  is not yet pinned** — BLAKE3 is what the record-setting prover benchmarks use, BLAKE2s is what
  the L1 write-ups name, SHA-256 is the ultra-conservative pole. Timeline attached to the
  announcement: production-grade **leanVM in 2027**, deployments across consensus/data/execution
  **in 2028**, inside the "Strawmap" roadmap (~7 forks through 2029,
  [Decrypt](https://decrypt.co/359204/ethereum-foundation-drafts-seven-fork-strawmap-through-2029)).
- **Announced direction, not shipped code.** As of 2026-08-14 the
  [leanEthereum/leanSig](https://github.com/leanEthereum/leanSig) README still hardcodes
  **Poseidon1** instantiations ("Hardcoded instantiations of this generic framework (using
  Poseidon1)…"); [leanroadmap.org](https://leanroadmap.org/) still lists the Poseidon
  Cryptanalysis Initiative at 50%. Poseidon1 was chosen over Poseidon2 in leanSig because the
  recent attacks touch Poseidon2's more aggressive structure, at a 2× slowdown (coverage of the
  hash-choice debate, KuCoin/crypto.news above). Expect the repos to follow the announcement.
- **Not a full break.** Nothing in production is broken. The pivot is a margin-plus-economics
  decision: the prover advantage that justified Poseidon's risk disappeared (see §2) exactly as
  its security margin thinned (see §3).

## 2. Leg 1 — hash-friendly SNARKs closed the gap

The 2026 proving-cost picture for **standard** hashes (laptop-class hardware unless noted):

| System (paradigm) | Standard-hash throughput | Source |
|---|---|---|
| **Flock** (R1CS-over-GF(2), zerocheck+lincheck; Bünz–Rothblum–Wang, 2026-06) | **82.1k BLAKE3 compr/s, 42.1k SHA-256/s, 30.7k Keccak-f/s — single M4 Max core; 660k BLAKE3/s on 10 cores**; overhead <250× native (~170× SHA-256, ~245× Keccak); 8.4× faster than Binius64 on SHA-256, 14× vs Binius64/Plonky3 on BLAKE3 | [eprint 2026/1329](https://eprint.iacr.org/2026/1329), [arXiv 2607.27491](https://arxiv.org/abs/2607.27491), [Succinct blog](https://blog.succinct.xyz/introducing-flock/), [Espresso blog 2026-06](https://medium.com/@espressosys/we-just-broke-the-speed-limit-on-snark-proving-0f47da6340de) |
| **SNARK.fast** (AI-assisted optimization over the same class) | **1.8M BLAKE3 compressions/s** (255% over baseline) — UNVERIFIED beyond the announcement coverage | via [crypto.news](https://crypto.news/ethereum-l1-drops-poseidon-in-post-quantum-move/) |
| **Binius64** (64-bit-word binary-field SNARK, Irreducible, 2025-09) | ~9.6k Keccak-f/s, ~9.2k BLAKE2s compr/s (C7i.16xlarge, mt: 1,365 Keccak perms in 142 ms; 2,048 BLAKE2s compr in 223 ms); was SOTA for SHA-256 until Flock | [Announcing Binius64](https://www.irreducible.com/posts/announcing-binius64), [binius.xyz/benchmarks](https://www.binius.xyz/benchmarks/) |
| **Hashcaster** (GF(2) Frobenius sumcheck) | 36–60k Keccak-f/s; hard to extend to SHA-256/BLAKE3 (u32 additions vs GKR) | [repo](https://github.com/morgana-proofs/hashcaster), [Flock paper comparison](https://eprint.iacr.org/2026/1329) |
| **Expander / binary GKR** (Polyhedra) | 14k Keccak-256/s CPU; 110k/s RTX4090; 150k/s H100 | [Polyhedra blog](https://blog.polyhedra.network/binary-gkr/) |
| **Plonky3** (prime-field AIR, no lookups for these yet) | 30k BLAKE3/s; 4k Keccak/s | [awesome-plonky3 / Flock comparisons](https://arxiv.org/html/2607.27491v1) |
| **Stwo** (Circle STARK) — *the algebraic reference point* | ~620k **Poseidon2-M31**/s (M3 laptop, 2024 demo) | [StarkWare](https://starkware.co/blog/starkware-new-proving-record/) |

Reading: our 2026-08-05 doc's "SHA-256 in-circuit ≈ 100× Poseidon2" line is dead. Per-core,
Flock's BLAKE3 is within ~7× of the Stwo Poseidon2-M31 demo figure, and multi-core (660k/s) it
matches it outright — before SNARK.fast-style tuning. Drake's summary claim: binary-field SNARKs
prove ~1M standard-hash calls/s on a laptop at ~100× native overhead
([crypto.news](https://crypto.news/ethereum-l1-drops-poseidon-in-post-quantum-move/)).

For the signature-aggregation flavor of this (leanSig/leanVM): leanVM targets **1,000 XMSS
signature aggregations/s** with 2-to-1 recursion at ~200 ms, on Plonky3+WHIR at ~0.5–1M
hashes/s CPU ([Lean Consensus 2026 plan](https://hackmd.io/@tcoratger/ryS1ElrWbx),
[proof-systems report](https://hackmd.io/@tcoratger/rk23bJfpJl),
[ZK Podcast #394](https://zeroknowledge.fm/podcast/394/)). Binius64's public benchmark suite
includes **XMSS+WOTS-with-Keccak aggregation** — hash-based signatures over standard hashes are a
first-class proving target now, which is exactly the workload our lattice-free ZK-spend variant
(D-012) would ride.

## 3. Leg 2 — Poseidon's margin eroded

Status of the [Poseidon Cryptanalysis Initiative](https://www.poseidon-initiative.info/) as of
Aug 2026:

- **Poseidon1 collision prize ($992k): PAUSED starting 2026-08-01** ("THE PROGRAM IS PAUSED
  STARTING 1 AUG 2026 AoE"); one claim verified (q=3, $32k, 2026-04-06).
- **Bounty Program 2026 ($150k): FINISHED**, multiple claims verified Apr–Jul 2026 — CICO
  RF=6/RP=10 solved 2026-07-06 ($15k); zero-test record RF=6/RP=12 claimed 2026-07-27 (two
  simultaneous submissions).
- Fresh papers pushing the frontier:
  [Slipway (Vitto, eprint 2026/1579, Aug 2026)](https://eprint.iacr.org/2026/1579) — a
  **full-round CICO-2 solution on the KoalaBear Poseidon instance** via finite subspace trails
  (effective degree 3^10 instead of the expected 3^28, using matrices that pass the official
  design checks); [Graeffe-based attacks (2025/1916)](https://eprint.iacr.org/2025/1916) — 2^13
  wall-time speedups on interpolation attacks against round-reduced/constrained instances;
  [Top Gun degree-annihilation (2026/1254)](https://eprint.iacr.org/2026/1254);
  [Gröbner-basis attacks exploiting subspace trails (2025/954)](https://eprint.iacr.org/2025/954).

None of this breaks deployed full-round parameter sets. But CICO-type properties are precisely
what a hash used **inside proof systems** must not have, the attack ceiling rose all year, and
the safer fallback (Poseidon1) costs 2× — at which point the §2 numbers make standard hashes the
better deal. That is the whole EF argument in one line.

## 4. "Binius-like hashes": examined and rejected

The user's question was specifically about the binary-field-native hash family. Findings:

- **The Binius lineage** ([Diamond–Posen, eprint 2023/1784](https://eprint.iacr.org/2023/1784) →
  [Binius64, 2025-09](https://www.irreducible.com/posts/announcing-binius64) → Flock/Hashcaster/
  binary GKR) was built to make **existing bit-oriented hashes** (Keccak-256, Grøstl, SHA-256,
  BLAKE) cheap to prove — that is its stated pitch, and in 2026 it demonstrably holds. The
  ecosystem's own conclusion, now adopted by the EF, is *don't design new circuit-friendly
  hashes; design provers for the hashes we trust.* The Flock authors state it directly: a
  SNARK-friendly hash is cheap only inside the one proof system it was designed for, while
  standard hashes "dissolve that choice"
  ([Succinct blog](https://blog.succinct.xyz/introducing-flock/)).
- **Vision Mark-32** ([eprint 2024/633](https://eprint.iacr.org/2024/633), Irreducible) is the
  binary-tower AO hash designed *for* Binius (hardware pitch: within 33% of Grøstl per LUT). It
  is young, thinly cryptanalyzed, and the Binius64 post itself demotes it to a future option.
  Adopting it would re-import exactly the "novel hash, single-prover lock-in" risk the EF just
  exited. **Grøstl** (AES-based SHA-3 finalist) is the one AO-adjacent candidate with a real
  cryptanalytic pedigree, but with Flock-class numbers for SHA-256/BLAKE3 there is no remaining
  reason to prefer it.
- **The AO-hash family is taking hits across the board**, not just Poseidon:
  [improved resultant attacks (eprint 2025/259)](https://eprint.iacr.org/2025/259) break the
  claimed security of most Griffin, Arion and Anemoi variants and one 512-bit Rescue parameter
  set; [round-reduced collision attacks on Tip5/Tip4/Tip4'/Monolith (2024/1900)](https://eprint.iacr.org/2024/1900);
  high-probability linear approximations in the S-boxes of Skyscraper, Monolith, Tip5 and
  Reinforced Concrete ([ToSC](https://tosc.iacr.org/index.php/ToSC/article/view/12245));
  the [FreeLunch Gröbner framework](https://link.springer.com/chapter/10.1007/978-3-031-68385-5_5)
  generalizes. Binary-field ports of Poseidon exist
  ([Poseidon(2)b, eprint 2025/1893](https://eprint.iacr.org/2025/1893)) but inherit the same
  research risk. **Conclusion: no AO hash anywhere in our design.**

## 5. Re-deciding our four hash sites

Site by site against `poseidon2-stark-discovery.md`:

1. **Tag-chain PRF** (§2.2 there: `tag_i = Poseidon2(cs, i)` "(or SHA-256)"). → **SHA-256.**
   Tags are computed natively by wallets and indexers; Poseidon2 was only ever there for a
   hypothetical in-circuit tag-membership proof, which standard hashes now cover at 40–80k
   hashes/s/core (§2). SHA-256 keeps the tag column byte-compatible with the EIP-8304 SSZ/SHA-256
   pipeline our PoC already implements, and the unlinkability argument (PRF hop on the chain
   secret, composing with the Lean KEM-anonymity chain) now rests on SHA-2 — the same assumption
   family lean Ethereum consensus will rest on. KEM-side KDFs stay SHAKE256 (FIPS 203/204 stack,
   unchanged and normative in the spec).
2. **Announcement accumulator** (§5 there: dual-root, SHA-256 for light clients + Poseidon2-M31
   for circuits). → **Single SHA-256 root; the dual-root idea is dead.** Its only purpose was
   dodging the ~100× circuit penalty. Recomputed: a 2^16-leaf tree costs ≈1.6 s single-core /
   ≈0.2 s on 10 cores to prove end-to-end with SHA-256 in a Flock-class prover — comfortably
   fine for indexer-side completeness proofs, and light clients/8304 verify the same root
   natively. One tree, one hash, provable and 8304-compatible.
3. **Spend-side ZK membership** (anonymity-set spend; composes with the lattice-free FRI/STARK
   ownership route of D-012). → **Standard-hash Merkle path (SHA-256 or BLAKE3) inside a
   Flock-class prover or zkVM.** A depth-20 path is 20 compressions ≈ 0.5 ms of single-core
   proving at Flock's SHA-256 rate — noise. The end-to-end PQ story ("security from hashes
   alone") is now uniform: statement, accumulator and prover internals all standard-hash.
4. **STARK-internal FRI/WHIR Merkle commitment.** → prover-internal choice, keep it conservative
   (BLAKE3 or SHA-256), matching where the field is going; see
   [SoK: hash-based polynomial commitments (eprint 2026/1367)](https://eprint.iacr.org/2026/1367)
   and [The Billion Dollar Merkle Tree (Coratger–Khovratovich, eprint 2026/089)](https://eprint.iacr.org/2026/089)
   for the current design space. Not something our spec needs to fix — but our docs should stop
   naming Poseidon2-M31 as the assumed instantiation.

**BLAKE2s vs BLAKE3 vs SHA-256, explicitly.** SHA-256: NIST-standardized, the 8304/consensus
choice, slowest natively of the three, best-studied — our **normative default**. BLAKE3: fastest
both natively (~5–13 GB/s class) and in provers (82k/s core in Flock, the SNARK.fast target),
tree-hashing built in, but not formally standardized — **allowed for indexer/prover internals**.
BLAKE2s: RFC 7693, the name in the EF's own L1 write-ups, sits between — if lean Ethereum pins
BLAKE2s normatively we can follow in a spec revision; nothing in our design is sensitive to the
choice among the three. What is settled is the *family*: bit-oriented, standard, 128-bit+
security, Grover-only quantum impact.

## 6. What this buys us (and costs us)

Gains:
- **Simplification**: dual-root machinery gone; one hash family across announcement pipeline,
  8304 PoC, accumulator, tag chains, and (future) spend circuit.
- **The D-013/D-012 "monitored risk" on Poseidon2 is resolved** — in the direction our
  conservative default already pointed. The ERC draft needs no change (it never named an AO
  hash).
- **Narrative alignment**: our discovery layer's PQ-soundness argument ("hashes alone") is now
  literally the L1's own post-quantum argument, with the same primitives; and the tag-chain +
  completeness-proof deliverables (the publishable pieces of the 2026-08-05 memo) get *cheaper*
  to defend, since no reviewer can object to a novel hash assumption.
- The lattice-free ZK-spend variant rides the exact workload (standard-hash Merkle proofs,
  XMSS-style aggregation) that leanVM/Binius64/Flock are being optimized and battle-tested for.

Costs / open items:
- In-circuit hashing is still ~5–10× Poseidon2-per-core in the worst comparison — irrelevant at
  our proof sizes (§5.2–5.3), but worth re-measuring if we ever prove ML-KEM decaps in-circuit
  (the unbenchmarked "prove my scan" territory from the 2026-08-05 memo).
- The EF's exact hash pick (SHA-2 vs BLAKE2s/3) is not final; our normative SHA-256 default is
  safe under every outcome, but track leanSpec/leanSig for the pin.
- Flock is 2026-06 work, single-team benchmarks (flagged as such); Binius64's own bench page
  retracted some early numbers. Treat all §2 figures as vendor-measured until independently
  reproduced — the *direction* (gap closed) is corroborated across ≥4 independent systems.

## 7. Recommended position (supersedes §5/§7 of poseidon2-stark-discovery.md where they touch hashes)

1. **Hash policy (D-015)**: SHA-256 normative for tags, accumulators, completeness proofs;
   SHAKE256 unchanged for KEM-side KDF/domain-separation; BLAKE3/BLAKE2s permitted
   prover/indexer-internally; **no arithmetization-oriented hash anywhere** (Poseidon/2, Vision,
   Skyscraper, Monolith, Grøstl included).
2. Tag-chain ERC extension text: specify `tag_i = SHA-256(cs || i)`-style derivation (exact
   domain-separated encoding at spec time), drop every Poseidon2 mention.
3. Accumulator design: single SHA-256 root, 8304-superset shape as before; completeness proofs
   client-verified, proven by indexers in a standard-hash-friendly prover (Flock-class or zkVM).
4. Watch items: leanSpec's final hash pin; independent reproduction of Flock-class benchmarks;
   Poseidon-initiative postmortem (for citing in the security write-up, not for design).
