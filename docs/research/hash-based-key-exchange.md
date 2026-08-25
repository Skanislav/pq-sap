# Hash-based key exchange (SHA-256 / BLAKE3 commitments) as an ML-KEM alternative: why the lattice is load-bearing

**Research question.** Our discovery layer is "just a KEM" since the ZK-spend reframe (D-012):
the sender must establish a secret with a recipient **non-interactively, from public data only**,
and the scheme is otherwise hash-only (D-015). Can that one remaining structured-assumption
component — ML-KEM — be replaced by a commitment scheme built from SHA-256 or BLAKE3, so the whole
scheme rests on hashes? The question is being used as the argument for (or against) keeping a
lattice assumption for key exchange, so it needs a precise answer, not a preference.

**Date:** 2026-08-25. Sources: theory papers (cited inline), primary parameter tables, and a new
measured benchmark `python/benchmarks/hash_kex_bench.py` (M1 Max, → `hash_kex_20260825.json`).
Companion measurements of the structured-KEM design space are in D-012 /
`discovery_kem_20260801.json`.

---

## Verdict in one paragraph

**No — and it is a theorem, not an engineering gap.** A commitment scheme is the wrong shape for
key exchange (the opening stays with the committer; a KEM needs the *recipient* to open something
the *sender* made from public data, which is a trapdoor, i.e. public-key structure). Any key
exchange whose only assumption is a hash function — SHA-256, BLAKE3, SHA3, it makes no difference
— has a provable polynomial ceiling: honest parties doing *n* hash calls can be broken with
*O(n²)* hash calls (Barak–Mahmoody, CRYPTO 2009, tightening Impagliazzo–Rudich 1989), and Merkle
puzzles already achieve that ceiling. Worse for a *post-quantum* project: against a quantum
eavesdropper Merkle's scheme has **no gap at all** (Brassard et al., CRYPTO 2011), and the best
known classical-party hash-only schemes only approach *n^{3/2}*. Turned into numbers on this
machine, the classical-attacker 128-bit setting needs 2^64 hash calls per party and a
**738 EB recipient public key**; even a 2^80 attacker budget — about 17 minutes of the Bitcoin
network — costs a 44 TB key and 64 GPU-seconds per payment, and buys zero quantum security.
The hash-only designs that *do* work in practice (pre-shared-secret tag chains; published one-time
address lists) either need a secret established some other way — our tag-chain design already does
this, seeded by **one** ML-KEM handshake — or give up unlinkability, which is the entire point of a
stealth address. So hashes **amortize** the KEM and own everything downstream of it (KDF, tags,
ZK spend, D-015); they cannot replace it. The honest comparison for "should discovery use a
lattice" is ML-KEM against the *other structured* PQ KEMs (HQC — NIST's non-lattice backup —
NTRU, Frodo, McEliece, CSIDH), which D-012 measured and ML-KEM wins on scan time and footprint.
**Recommendation: keep ML-KEM-768 as the discovery KEM; state in the ERC that a hash-only
handshake is impossible in the non-interactive setting and that tag chains + an optional
out-of-band handshake are the hash-only opt-out for pairs that have a prior channel.**

## 1. What a hash-based commitment can and cannot do

A commitment `c = H(x ‖ r)` gives *hiding* (c reveals nothing about x) and *binding* (the
committer cannot open c to x' ≠ x). Both properties serve one party — the committer — who keeps
the opening `(x, r)`. Nothing in the primitive lets a *second* party who holds only public
information recover x. A stealth-address discovery step needs exactly that: the sender publishes
one message, and the recipient — who has never interacted with the sender — must recover a secret
from it using a private key of their own. That "open with a private key" operation *is* a
public-key trapdoor. Rephrasing it as "the recipient committed to something earlier" does not
help: the recipient's commitment is public, and whatever the sender can compute from it, the
eavesdropper can compute too, because both hold the same inputs and the same hash.

The formal version of this intuition is a black-box separation:

- **Impagliazzo–Rudich (STOC 1989).** Secret-key agreement cannot be built from one-way functions
  (equivalently, from a random oracle) in a black-box way; any *n*-query protocol falls to an
  adversary making polynomially many queries (their bound: ~n^6).
- **Barak–Mahmoody, "Merkle Puzzles Are Optimal — An O(n²)-Query Attack on Any Key Exchange from
  a Random Oracle" (CRYPTO 2009).** Every key-exchange protocol in the random-oracle model in
  which the honest parties make at most *n* oracle queries is broken by an adversary making
  O(n²) queries. Merkle's 1974 puzzles need Ω(n²) to break, so the quadratic gap is tight.
  ([paper](https://www.iacr.org/archive/crypto2009/56770369/56770369.pdf),
  [Springer](https://link.springer.com/chapter/10.1007/978-3-642-03356-8_22))

Two things about these results matter for the argument being made:

1. **They are about the access model, not the hash.** SHA-256 vs BLAKE3 vs SHA3-256 is a
   throughput and precompile question (§5); it is irrelevant to whether key exchange exists. A
   hash-only KEM with a superpolynomial security gap would be a non-black-box construction nobody
   has, and would be a landmark result in complexity theory — not a design option for an ERC.
2. **"Commitment scheme" is inside the theorem's scope.** Hash commitments, Merkle trees,
   hash chains, XMSS/SPHINCS-style structures are all *n*-query random-oracle protocols. Any
   protocol composed from them is covered.

### 1.1 The quantum adversary makes it strictly worse

Brassard, Høyer, Kalach, Kaplan, Laplante, Salvail, "Merkle Puzzles in a Quantum World"
(CRYPTO 2011, [arXiv:1108.2316](https://arxiv.org/abs/1108.2316),
[IACR](https://www.iacr.org/archive/crypto2011/68410385/68410385.pdf)):

- Merkle's original scheme with **classical honest parties is broken completely by a quantum
  eavesdropper** — Grover over the puzzle set finds the sender's puzzle in effort proportional to
  the honest parties' own effort. Gap exponent 1: no security.
- They build a *classical*-party scheme a quantum adversary cannot break with effort proportional
  to the honest parties' (concretely, ~N^{7/6} in the body), and a family of classical protocols
  whose quantum-adversary cost approaches **N^{3/2}** but never reaches it.
- With **quantum honest parties** (wallets running quantum computers — out of scope for a
  wallet standard for the foreseeable future) a scheme reaches N^{5/3}, and a family approaches
  N².

So the proposition "hash-based key exchange as the post-quantum alternative" inverts the
motivation: hash-only key exchange is the one family of key exchange whose security *drops* when
the attacker becomes quantum, and the exponent it drops to is worse than the classical Merkle
gap that was already unusable.

## 2. What the gap theorems cost, measured (`hash_kex_bench.py`)

The bench measures hash rates here and converts each gap exponent *e* (attacker = n^e) into the
honest work *n* needed to force attacker work 2^W, then into wall-clock and storage. Model: one
Merkle puzzle = one hash call and 40 bytes; the recipient's "public key" is the puzzle set (n
puzzles); the sender solves one puzzle (n hash calls); attacker rates assumed 2^24.5 H/s per
native core, 2^34 per GPU, 2^70 for the 2026 Bitcoin network. Local Python-bound SHA-256 measured
at 2^21.6 calls/s.

| attacker model | gap | W = 2^80 | W = 2^128 |
|---|---|---|---|
| classical Eve, Merkle 1974 (Barak–Mahmoody optimal) | n² | n=2^40: 64 GPU-s per payment, **44 TB** recipient key, 1.8e15 gas if on-chain | n=2^64: **34 GPU-years** per payment, **738 EB** key |
| quantum Eve, classical parties, Merkle 1974 | n¹ | n=2^80 — broken | n=2^128 — broken |
| quantum Eve, classical parties, BHKKLS'11 concrete | n^{7/6} | n=2^68.6: 809 GPU-yr | n=2^109.7 |
| quantum Eve, classical parties, BHKKLS'11 family limit (unreachable) | n^{3/2} | n=2^53.3: 184 GPU-h, 454 PB | n=2^85.3 |
| quantum Eve, *quantum* honest parties, BHKKLS'11 | n^{5/3} | n=2^48: 4.6 GPU-h, 11 PB | n=2^76.8 |

Reference row, measured (D-012): **ML-KEM-768** — 1,184-B key, 1,088-B ciphertext, 17.2 µs
decaps, 1.38 s per 80k-announcement scan, 67,700-gas announcement, NIST level 3 against classical
*and* quantum attackers.

Reading the table: W = 2^80 is not a security level (it is ~17 minutes of the Bitcoin network's
hash rate), and it already requires a recipient key 3.7×10^10 times larger than ML-KEM-768's.
The only row with quantum security for classical wallets that is not "broken" is n^{7/6}, at
2^68.6 hashes per payment for the weak target. There is no parameter choice, hash function, or
implementation trick that moves these rows: they are the exponents from §1 with numbers plugged
in. A Merkle-root-on-chain / puzzles-off-chain variant removes the gas column and changes nothing
else — the sender still needs the whole puzzle set and the honest work is the same.

## 3. Hash-only designs that do exist, and what each gives up

The impossibility is specifically about **non-interactive agreement from public data**. Relaxing
that is where every hash-only "stealth" construction lives. Each is listed with the property it
trades away.

| design | how it works | what it gives up | status for us |
|---|---|---|---|
| **A. Pre-shared-secret tag chain** (symmetric stealth) | S and R share `cs`; payment *i* carries `tag_i = SHA-256(cs ‖ i)` and an address whose secret ratchets from `cs`. Scan = exact-tag lookups, O(counterparties) not O(registry). | Requires `cs` to be *established*: by one KEM handshake (HNDL then hits that handshake, so the KEM assumption still protects every relationship's root secret) or **out-of-band** (in person, an existing secure channel). Non-interactivity for first contact. | **Already our design** — `poseidon2-stark-discovery.md` §2.2, SHA-256 per D-015. Announcement ~56 B vs 1,109 B; the 1,088-B ciphertext is paid once per relationship. This is what "hash-based" legitimately buys: amortization. |
| **B. Published one-time address list** | R publishes N hash commitments / one-time public keys (Merkle root + leaves); S picks an unused leaf; ownership by hash-based signature or STARK preimage. | **Unlinkability.** The list is R's identity; every address on it is publicly R's. Also leaf exhaustion and sender collisions. Delivering the list privately instead collapses to A. | Not a stealth address — it is "publish N addresses", the thing ERC-5564 exists to avoid. |
| **C. Interactive on-chain handshake** | S posts a commitment, R responds, S opens… | Nothing: with a public transcript and only a hash, the two parties hold exactly the eavesdropper's information — the §1 theorems apply to any number of rounds. Also breaks unilateral sending and needs R online. | Dead regardless of round count. |
| **D. Merkle puzzles** | §2. | Everything (§2), and all quantum security (§1.1). | Dead. |
| **E. Hash-based ownership** (SLH-DSA / XMSS signatures; STARK hash-preimage proof) | Spend authorizes with hashes only. | Nothing — this is where hashes are the right tool. | **Already the plan** (D-008 / D-012 / D-015). |

The honest way to say "the scheme can be lattice-free" is therefore: *for a sender–recipient pair
that established `cs` out-of-band, every payment is hash-only end to end; for everyone else the
first contact needs a PQ KEM, and no hash construction can change that.* That opt-out is worth a
sentence in the ERC; it is not an alternative KEM.

## 4. The comparison that is actually open: ML-KEM vs other structured PQ KEMs

If the concern behind "consider hashes" is *assumption diversity* (a structural break in module
lattices), the alternatives are the other structured families, all measured at matched level in
D-012 (`discovery_kem_20260801.json`, 2026-08-01, M1 Max, liboqs):

| KEM | assumption | level | pk B | ct B | decaps µs | scan 80k s | announce gas |
|---|---|---|---|---|---|---|---|
| ML-KEM-512 | Module-LWE | L1 | 800 | 768 | 11.6 | 0.9 | 54,900 |
| NTRU-HPS-2048-509 | NTRU | L1 | 699 | 699 | 95.9 | 7.7 | 52,250 |
| FrodoKEM-640-AES | LWE (unstructured) | L1 | 9,616 | 9,752 | 429.0 | 34.3 | 413,350 |
| **HQC-1** (NIST backup, selected 2025-03-11) | quasi-cyclic codes | L1 | 2,241 | 4,433 | 2,373 | 190 | 201,140 |
| BIKE-L1 | quasi-cyclic codes | L1 | 1,541 | 1,573 | 5,117 | 409 | 87,160 |
| Classic-McEliece-348864 | Goppa codes | L1 | 261,120 | 96 | 18,008 | 1,441 | 28,020 |
| **ML-KEM-768 (default)** | Module-LWE | L3 | 1,184 | 1,088 | 17.2 | 1.4 | 67,700 |
| NTRU-HPS-2048-677 | NTRU | L3 | 930 | 930 | 52.4 | 4.2 | 61,680 |
| FrodoKEM-976-AES | LWE (unstructured) | L3 | 15,632 | 15,792 | 750 | 60 | 654,190 |
| HQC-3 | quasi-cyclic codes | L3 | 4,514 | 8,978 | 7,114 | 569 | 382,870 |
| Classic-McEliece-460896 | Goppa codes | L3 | 524,160 | 156 | 43,697 | 3,496 | 30,490 |
| CSIDH-512 (lit.) | isogeny NIKE | ~L1, disputed | 64 | 64 | ~80,000 | ~6,400 | 26,740 |

HQC is the standardized hedge against a lattice break — NIST selected it on 2025-03-11 exactly
for mathematical diversity ([NIST IR 8545](https://csrc.nist.rip/external/nvlpubs.nist.gov/nistpubs/ir/2025/NIST.IR.8545.pdf),
[FedScoop](https://fedscoop.com/nist-backup-algorithm-general-encryption-quantum-cyberattacks-pqc/));
its draft FIPS is not yet out, and its current parameter sizes are from
[pqc-hqc.org](https://pqc-hqc.org/) (HQC-1 2,241/4,433 B; HQC-3 4,514/8,978 B). For *this*
scheme it costs a 4× ciphertext (3× the announcement gas) and a 140× slower scan at L1. The
disciplined way to hedge the lattice assumption is therefore a **hybrid discovery KEM
(ML-KEM ‖ HQC, KDF over both secrets)** as an optional parameter set — additive cost, secure
if *either* holds — not a hash construction. Frodo (unstructured LWE) is the
"lattice-but-conservative" pole at a 15.7 kB meta-address; NTRU is the cheap same-family hedge.
None of this changes D-012's ranking: ML-KEM wins discovery on decaps latency and footprint.

## 5. Where SHA-256 and BLAKE3 do belong (and which one)

Hashes own every non-KEM site of the design, and D-015 already fixes the policy. The bench adds
the scan-side numbers so the choice can be made on facts:

| site | primitive | measured here |
|---|---|---|
| KEM-internal KDF / domain separation | SHAKE256 / SHA3-256 (FIPS 203 internals, unchanged) | inside the 17.2 µs decaps |
| view tag over the 32-B shared secret | SHA-256 | 0.28 µs (BLAKE3 0.43, SHA3-256 0.57, keccak 2.83 — Python binding) |
| tag-chain PRF `tag_i = SHA-256(cs ‖ i)` | SHA-256 (D-015) | 0.28 µs per candidate tag |
| KDF over the whole 1,088-B ciphertext | SHA-256 | 0.70 µs (BLAKE3 1.68, SHA3 2.22) |
| bulk (indexer, accumulator, prover-internal) | BLAKE3 permitted (D-015) | SHA-256 2.4 GB/s vs BLAKE3 1.8 GB/s single-thread here; BLAKE3 wins multi-threaded and in Flock-class provers (82k vs 42k compressions/s/core, D-015) |
| stealth address | keccak256 (EVM address rule) | 2.83 µs (pycryptodome; negligible) |
| ownership / spend | STARK hash-preimage (SHA-256) or SLH-DSA | D-008 / D-012 |

Per-announcement hashing is 0.3–1.7 µs against a 17.2 µs decaps: **the hash choice cannot move
scan time by more than ~5%**; the KEM decides it. SHA-256 keeps its edge for anything that
touches the chain (precompile `0x02` at 60 + 12/word gas; BLAKE3 has no precompile — only the
BLAKE2b `F` function of [EIP-152](https://eips.ethereum.org/EIPS/eip-152), and the 2023
[Magicians proposal](https://ethereum-magicians.org/t/eip-add-precompile-for-blake2s-blake3/12407)
for a BLAKE3 precompile never became an EIP), hardware acceleration, and alignment with
EIP-8304 and the EF's own post-Poseidon direction. Quantum margin is not a differentiator: both
are 256-bit, Grover halves preimage resistance to 128 bits, collision stays ≥ 2^85 (BHT) and in
practice 2^128 — fine at every parameter set we ship.

## 6. What this settles, and what it does not

**Settled.**
- A hash-based commitment scheme cannot be the discovery KEM; no hash function choice changes
  that (§1). Hash-only key exchange is *less* post-quantum than classical, not more (§1.1).
- The measured cost of the best hash-only key exchange is 10–20 orders of magnitude off in key
  size alone (§2). There is no parameter regime to explore.
- Hashes already do everything they can in the design: tag chains amortize the KEM to once per
  relationship (§3-A), and spend/KDF/tags are hash-only (D-015, §5).
- The lattice choice for discovery is justified against the real alternatives — structured
  non-lattice KEMs — on measured scan and footprint numbers (D-012, §4).

**Not settled / follow-ups.**
- Whether to *offer* a hybrid ML-KEM‖HQC parameter set in the ERC as the assumption-diversity
  hedge. Cost is additive (§4); it is a one-line spec change plus vectors. Recommend "optional,
  not default".
- ERC text: a sentence in Rationale stating the non-interactive requirement and citing
  Barak–Mahmoody, so reviewers do not re-open "why not hashes"; a sentence permitting out-of-band
  `cs` establishment for tag chains.
- Lean: the impossibility is not something to formalize (it is a query-complexity result outside
  VCVio's scope); what *is* in scope and already done is that our reductions bottom out in
  IND-CCA of the KEM (D-013) — i.e. the proofs themselves say where the structured assumption sits.

## Sources

- Impagliazzo, Rudich. *Limits on the provable consequences of one-way permutations.* STOC 1989.
- Barak, Mahmoody-Ghidary. *Merkle Puzzles Are Optimal — An O(n²)-Query Attack on Any Key Exchange from a Random Oracle.* CRYPTO 2009. https://www.iacr.org/archive/crypto2009/56770369/56770369.pdf ; https://link.springer.com/chapter/10.1007/978-3-642-03356-8_22
- Brassard, Høyer, Kalach, Kaplan, Laplante, Salvail. *Merkle Puzzles in a Quantum World.* CRYPTO 2011. https://arxiv.org/abs/1108.2316 ; https://www.iacr.org/archive/crypto2011/68410385/68410385.pdf ; slides https://www.iacr.org/conferences/crypto2011/slides/07-1-Kalach.pdf
- Brassard, Salvail. *Quantum Merkle Puzzles.* ICQNM 2008. https://www.researchgate.net/publication/4320907_Quantum_Merkle_Puzzles
- NIST IR 8545, *Status Report on the Fourth Round* (HQC selection, 2025-03-11). https://csrc.nist.rip/external/nvlpubs.nist.gov/nistpubs/ir/2025/NIST.IR.8545.pdf ; https://fedscoop.com/nist-backup-algorithm-general-encryption-quantum-cyberattacks-pqc/ ; https://postquantum.com/post-quantum/cryptography-pqc-nist/
- HQC parameter sets. https://pqc-hqc.org/
- EIP-152 (BLAKE2b `F` precompile). https://eips.ethereum.org/EIPS/eip-152 ; BLAKE3 precompile discussion https://ethereum-magicians.org/t/eip-add-precompile-for-blake2s-blake3/12407
- Aztec note discovery (tag-chain prior art). https://docs.aztec.network/developers/docs/foundational-topics/advanced/storage/note_discovery
- Local: `python/benchmarks/hash_kex_bench.py`, `hash_kex_20260825.json`, `discovery_kem_20260801.json`; `docs/DECISIONS.md` D-012, D-015; `docs/research/poseidon2-stark-discovery.md` §2.2.
