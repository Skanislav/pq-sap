# Poseidon2 + Merkle trees + zk-STARKs for a customized registry/discovery layer

**Research question.** If we are free to customize the ERC-5564 announcer and ERC-6538 registry
(instead of only registering a new scheme ID against the canonical contracts), can Poseidon2
hashing, Merkle accumulators, and zk-STARK proofs improve (a) scanning time and (b) the key
exchange for the PQ stealth scheme?

**Date:** 2026-08-05. Sources: literature survey, cost fact sheet, and registry-precedent survey
(citations inline); local measured numbers from `python/benchmarks/` (dated JSONs).

---

## Verdict in one paragraph

Poseidon2/Merkle/STARK machinery **cannot make private detection sub-linear** — that is now a
theorem, not folklore (unlinkable detection is PIR-hard; someone must do Ω(N) work per query,
eprint 2026/910). What a customized registry *can* deliver, compatibly with the bound, is
substantial and complementary: (1) **amortized O(1) discovery for repeat senders** via
Aztec-style Poseidon2 tag chains seeded by one ML-KEM handshake — collapsing both scan work and
announcement size (1,109 B → ~56 B) for everything after first contact; (2)
**completeness-by-construction**: an append-only announcement accumulator with on-chain roots
makes "these are ALL your candidate announcements" client-verifiable — an unoccupied research
niche for stealth addresses and the trust win our EIP-8304 PoC already measures; (3) a **cheaper,
quantum-safe registry**: hash-committed meta-addresses + blob-carried batched announcements fix
the 3.79M-gas naive registration and the ERC-6538 ECDSA-auth quantum hole. The linear first-contact
scan remains — and at ML-KEM-768's 17.2 µs/decaps (1.38 s per 80k announcements, measured) it is
already ~50× cheaper per message than Zcash's deployed trial-decryption baseline (~1 ms/output).

---

## 1. Why sub-linear private scanning is off the table

- **Lower bound.** UnifOMR (Fisch–Liu–Tromer–Wang, [eprint 2026/910](https://eprint.iacr.org/2026/910))
  reduces single-server PIR to any OMR with strong detection-key unlinkability: the scanning party
  must touch every message, else its access pattern leaks which messages are irrelevant. Vitalik's
  information-theoretic remark in the original
  [ethresear.ch open-problem thread](https://ethresear.ch/t/open-problem-improving-stealth-addresses/7438)
  (recipients collectively must receive Ω(N) bits) was the informal version. Every proposal in that
  thread died on exactly this.
- **Predictable tags are linkage.** Any tag the recipient can precompute (so an index could serve
  it sub-linearly) is Fuzzy Message Detection with false-positive rate → 0; Seres et al.
  ([eprint 2021/1180](https://eprint.iacr.org/2021/1180)) show FMD privacy collapses on real
  communication graphs as p shrinks, and deterministic tags are the p=0 endpoint. This formally
  confirms the view-tag analysis in our spec: our 1-byte view tag *cannot* become an index key
  without giving up unlinkability — with one exception, §3, where the tag is predictable **only to
  the two parties who already share a secret**.
- **The escapes all change the model**, and only one is PQ-sound:
  | Route | Who pays linear | PQ-sound? | State of the art |
  |---|---|---|---|
  | Lattice OMR (delegate under FHE) | server, per recipient | **yes** (LWE) | SophOMR ~1.7 ms/msg ([2024/1814](https://eprint.iacr.org/2024/1814)); PerfOMR ~$0.10/M msgs; never deployed (Zcash evaluated, passed) |
  | FMD (fuzzy tags) | server (cheap EC ops) | no (DDH) | Penumbra designed s-FMD, has not deployed it |
  | Two-server / TEE private signaling | servers | partially / hardware trust | HomeRun ([2024/188](https://eprint.iacr.org/2024/188)) ~3,830× cheaper than OMR |
  | Shared-state tag chains (sender↔recipient) | nobody after first contact | **yes** (hash-based) | **Aztec, deployed** — the route we can copy |
  | Out-of-band delivery (no on-chain detection) | nobody | yes | Zcash Tachyon direction (NU7) |
- **Everyone who stayed on-chain stayed linear.** Zcash DAGSync/warp sync = smarter/parallel
  linear. Penumbra's Poseidon **Tiered Commitment Tree** accelerates *witness maintenance* (claimed
  up to 4M× on state sync), not detection — the clean precedent that Merkle trees buy state-sync
  speed, never detection speed. Railgun scans every commitment ("initial sync can take a few
  minutes").

**Consequence.** Poseidon2/STARKs should not be aimed at the detection loop. They should be aimed
at (i) the repeat-sender path, (ii) trust/completeness, (iii) footprint — where they do win.

## 2. Where scanning time genuinely improves

### 2.1 The measured baseline (what we must beat)

- ML-KEM-768 decaps 17.2 µs native → 1.38 s / 80k announcements; our Python client steady-state
  44.3 µs/ann, linear across 2.5k–160k (R²=0.999, `registry_curve_20260802.json`).
- Mainnet canonical announcer has **202 announcements ever** (measured 2026-08-02): today the
  linear scan is a non-problem on L1; the design question is L2 registries (Fluidkey/Base) and
  future volume.

### 2.2 Tag chains: O(counterparties) instead of O(registry) for repeat senders

Copy Aztec's settled design ([note discovery docs](https://docs.aztec.network/developers/docs/foundational-topics/advanced/storage/note_discovery)),
instantiated post-quantum:

- **First contact (handshake):** sender announces the ML-KEM ciphertext exactly as in our current
  scheme. Both sides derive the chain secret `cs = KDF(ss, "tagchain/v0")` from the shared secret.
  This is the step Aztec's DH-based variant cannot do post-quantum (ML-KEM is not a NIKE); our
  KEM announcement **is** the PQ handshake channel.
- **Subsequent payments:** announcement carries `tag_i = Poseidon2(cs, i)` (or SHA-256 — see §5;
  *addendum 2026-08-15: SHA-256 is now the settled choice, see `hash-migration-blake2-binius.md`*)
  plus the stealth address; per-payment secrets ratchet from `cs`. No new KEM ciphertext.
- **Recipient scan:** exact-match lookups of expected tags `{Poseidon2(cs_j, i) : j ∈ counterparties,
  i ∈ window}` against a tag-indexed registry — cost independent of global announcement count.
  The linear decaps loop runs only over *handshake* announcements.
- **Unlinkability:** tags are pseudorandom under `cs` (PRF security of the hash), predictable only
  to the two parties — this does not contradict §1 because the index serves tags, not identities.
  New leak to manage: exact-tag queries reveal recipient interest to the indexer (Aztec documents
  the same IP↔tag correlation; mitigations: range downloads of the tag column, later PIR/OMR).
  Sender-side state loss ⇒ fall back to a fresh handshake.

**Effect on announcement size/gas (the "key exchange" win):** a chain announcement is
~32 B tag + 20 B address + 4 B index ≈ 56 B vs 1,109 B — the tx drops from the 67,580-gas
EIP-7623 floor to roughly the 21k-gas class. The 1,088-B ciphertext is paid **once per
relationship**, not once per payment. For payment patterns dominated by repeat senders
(payroll, subscriptions, exchanges — Fluidkey's actual traffic), both scan time and calldata
approach the EC scheme's numbers while staying PQ.

### 2.3 What stays linear, quantified

First-contact announcements still require trial decaps by every scanner. If x is the fraction of
handshake announcements, scan cost ≈ x·N·17.2 µs + |counterparties|·window lookups. Even at
x=100% (today's scheme) we are at 1.38 s/80k native; every repeat-sender relationship moves its
payments out of the linear term entirely.

## 3. Completeness proofs: the trust improvement (and the publishable piece)

An untrusted indexer serving stealth announcements can currently **omit** — an omitted
announcement is a payment the recipient never learns about, the one uncovered threat in our model.
Two composable answers:

1. **EIP-8304 path (SHA-256, protocol-level).** Our PoC (`eip8304_scan_poc.py`, measured
   2026-08-02): sorted index tables + SSZ `List[Hash32]` merkleization give range multiproofs with
   boundary-completeness — 1,486 proof bytes, 0.04 ms verify for 12 announcements among 35.8k
   entries. If Pureth ships, generic announcements become provably-complete-queryable with zero
   custom infrastructure. Status: EIP-7745 deferred from Glamsterdam, PFI for Amsterdam; the WG
   only ever debated SHA-2 vs SHA-3 — no ZK-friendly hash was on the table.
2. **Custom accumulator path (pre-8304, or as an 8304 superset).** The announcer maintains an
   append-only accumulator: only the **root** on-chain (never per-announcement hashing — §4),
   tree maintained off-chain by permissionless indexers, updates proven correct in a STARK
   verified **client-side**. Completeness is then by construction: "leaves 0..N under root R" is
   checkable, unlike Ethereum logs today. The literature survey found **no published work** on
   STARK-proven completeness/non-omission for stealth-address indexers (nearest: SNARKBlock,
   authenticated PIR) — this is white space our 8304 PoC already half-occupies, and it recovers
   the same guarantee 8304 gives, years earlier, at app level.

These also compose: the custom accumulator can carry the **view-tag/tag index row** that 8304
currently lacks (our WG feedback item: ~256× light-client receipt-bandwidth cut; measured 13.3 kB
→ 1.1 kB receipts in the PoC), and the tag-chain lookups of §2.2 need exactly such an indexed
column with completeness ("no announcement with tag t in range" must be provable, or omission
returns through the side door).

## 4. Cost realities that fix the architecture

Numbers from the fact sheet (sources inline there; key ones re-cited):

| Quantity | Value | Design consequence |
|---|---|---|
| Poseidon2 in EVM | ~20.3k gas/hash (Yul, BN254; Huff 14.8k); EIP-5988 **Stagnant** | never hash on-chain |
| LeanIMT insert (Semaphore v4) | ~119k gas avg; classic IMT ~560k; depth-20 binary ~768k | an on-chain tree insert costs 2–11× our whole 67.6k announcement |
| Native STARK verify on L1 | StarkWare split verification, ~2.3M gas main tx; 100 KB proof ≈ 4.1M gas calldata floor (EIP-7623) alone | no per-announcement / per-batch on-chain STARKs on L1 |
| SNARK-wrapped verify | ~270–300k gas | **kills PQ soundness** — not an option for the PQ story |
| Client-side STARK verify | milliseconds, zero gas | make the **wallet** the verifier |
| STARK proving (Stwo) | ~620k Poseidon2-M31 hashes/s on a laptop; 2^16-hash statement ≈ 0.1 s native, ~1–3 s browser (est.) | indexer proving is cheap; even wallets can prove small statements |
| SHA-256 in-circuit | ~100× Poseidon2 per hash (110–200× at Merkle-proof level); zkVM accelerators narrow but don't close it | proving over 8304's SHA-256 tables is feasible; a Poseidon2-M31 side-tree is 1–2 orders cheaper |
| Blobs | 1 blob = 128 KB ≈ 117 ML-KEM-768 ciphertexts; DA cost orders below calldata; pruned after ~18 days (archives: Blobscan/Graph/Hemera) | batch handshake announcements into blobs; on-chain = (versioned_hash, batch_root) |
| ML-KEM decaps in a zkVM | no public benchmark (gap); est. ~1–5M cycles | "prove my scan" designs are unbenchmarked territory |

Architecture that falls out (the Railgun-v3 / keystore-rollup shape, hash-based instead of KZG):

- **On-chain:** announcer stores batch roots + blob versioned hashes; registry stores meta-address
  *commitments*. No field hashing, no verifier contracts on the hot path.
- **Off-chain:** permissionless indexers maintain the accumulator + tag index, serve range/tag
  queries with STARK (or bare-Merkle) completeness proofs; wallets verify locally.
- **If on-chain proof-gating is ever needed** (e.g. enforcing root correctness rather than
  client-side checking): settle on an L2/L3 with a native STARK verifier (Starknet/Integrity
  pattern) — not L1.

## 5. Poseidon2 vs SHA-256: the honest trade

> **Addendum 2026-08-15 — this trade has since been decided, against Poseidon2.** On 2026-08-13
> the EF announced it is abandoning Poseidon for L1 ("pivoting to SHA or BLAKE", J. Drake), after
> Flock-class binary-field provers collapsed the ~100× standard-hash penalty assumed below to a
> single-digit factor (82k BLAKE3 / 42k SHA-256 compressions/s per M4 Max core) and the
> cryptanalysis initiative's results (full-round CICO-2 on an instance; prizes paused) eroded the
> margin. Everything in this section that reserves Poseidon2 for circuit-heavy paths, and the
> dual-root accumulator idea, is superseded: **single SHA-256 root, SHA-256 tag chains, no AO
> hash anywhere** (policy D-015). Full analysis and citations:
> `hash-migration-blake2-binius.md`.

- **For our PQ narrative, SHA-256 is the conservative default.** FRI/STARKs are PQ-sound from
  hashes alone; that argument is cleanest with SHA-256 (also what 8304 mandates). Poseidon2 is
  *plausibly* PQ with no full-round break, but the EF is literally paying for its cryptanalysis
  through Dec 2026 (initiative + unclaimed $992k collision prize), and protocol Ethereum will not
  adopt it near-term.
- **Poseidon2 buys prover cost, nothing else.** On-EVM it's no cheaper than Poseidon (~20k gas);
  natively SHA-256 is *faster*; the ~100× win exists only inside circuits. So: use Poseidon2 where
  proofs are generated constantly (tag-chain membership, spend-side Merkle membership for
  anonymity-set ZK spending — where it composes with our existing STARK ownership route at
  ~5M gas L1 or client-side); keep SHA-256 for the completeness/8304 layer where proofs are
  Merkle-path-only and verification is native. A dual-root accumulator (same leaves, SHA-256 root
  for light clients + Poseidon2-M31 root for circuits) costs the indexer ~1 µs/leaf extra and
  lets each consumer pick its hash.
- Pin Poseidon2 parameters conservatively and record the EF-initiative outcome (2026) as a
  monitored risk in DECISIONS.md if we adopt it anywhere normative.

## 6. Key-exchange / registry improvements (independent of scanning)

1. **Meta-address registration.** Replace ERC-6538's full-bytes storage (3.79M gas naive for
   5,633 B; ~1.2 kB after the ZK-spend reframe drops full-precision t) with an on-chain
   32-B commitment + off-chain/blob data, verified against the commitment on fetch. One SSTORE
   class instead of kilobytes.
2. **Quantum-safe registry auth.** ERC-6538's `registerKeysOnBehalf` (EIP-712/ERC-1271 = ECDSA)
   allows a future quantum adversary to *overwrite* victims' meta-addresses and divert payments —
   our ERC draft already flags this; a custom registry closes it: msg.sender-only from AA
   accounts, PQ signatures — for which ERC-7913 signers (`verifier || key`, D-014) are the
   standardized hook — or hash-based commit-reveal rotation, plus explicit rotation
   semantics (keystore-rollup precedents: Vitalik's minimal design, Scroll, Axiom live; Base's
   retreat = warning against full rollup machinery — keep it to root + events in a normal
   contract).
3. **Handshake amortization** (§2.2) is itself the big key-exchange win: one 1,088-B KEM
   ciphertext per relationship instead of per payment.
4. **Blob batching** for handshake announcements via a permissionless `announceBatch` relayer
   (Tornado-relayer/4337-bundler pattern); per-announcement DA cost collapses ~two orders vs the
   67.6k floor. Recipients syncing less often than ~18 days depend on blob archives — a liveness
   dependency only, not fund-safety, since roots on-chain remain the source of truth. No existing
   ERC covers blob-carried announcements; second unclaimed draft.

## 7. Recommended position

1. **Do not** pursue sub-linear private detection; cite the PIR-hardness result when the question
   recurs. Keep first-contact scanning linear and fast (ML-KEM decaps is already the fastest
   PQ option measured across 15 KEMs).
2. **Adopt the tag-chain extension** as the scanning/key-exchange improvement: PQ handshake via
   the existing KEM announcement, Poseidon2 (or SHA-256) tag chains after (*addendum 2026-08-15:
   SHA-256*). Spec it as an optional
   announcement type in the ERC draft (new `metadata` layout or sibling scheme ID) so plain
   per-payment KEM announcements remain valid.
3. **Build discovery trust on 8304**, not against it: our PoC + the view-tag/tag index row as WG
   input; the custom accumulator only as a pre-8304 bridge or L2 deployment, designed as an 8304
   superset (same entry encodings, same SSZ merkleization, extra index rows) so it dissolves into
   the protocol feature when Pureth ships.
4. **Registry v2** (commitment-based, PQ-auth, blob-batched) is worth a section in the ERC draft
   regardless of everything else — it fixes measured costs and a real quantum attack surface.
5. **Publishable pieces** surfaced by this research: (a) STARK-proven completeness for
   stealth-address indexers (no prior work); (b) PQ tag chains — Aztec's design has no published
   PQ analysis, and our KEM-handshake instantiation + unlinkability argument (PRF hop on the
   chain secret, composing with our Lean KEM-anonymity chain) is novel; (c) the first
   blob-carried announcement ERC.

## Appendix: what the numbers say end-to-end

Scenario: 80k-announcement registry, recipient with 20 counterparties, 90% repeat-sender traffic.

- **Today's scheme:** scan = 80k × 17.2 µs ≈ 1.38 s; every payment costs the sender 67,580 gas.
- **With tag chains + indexed registry:** scan = 8k handshakes × 17.2 µs ≈ 0.14 s + ~20×window
  tag lookups (ms, with completeness proofs at ~1.5 kB / 0.04 ms verify each, per our PoC) —
  ~10× less client work, bounded by handshake rate, not registry size; repeat payments cost
  ~21k-class gas and 56 B instead of 67.6k and 1,109 B.
- **Trust:** omission attacks closed by completeness proofs (8304 or custom accumulator);
  registry overwrite closed by PQ auth; SHA-256 pipeline keeps the whole discovery story
  PQ-sound; Poseidon2 reserved for circuit-heavy paths (spend membership), pending EF
  cryptanalysis outcome (*addendum 2026-08-15: outcome arrived — Poseidon dropped by the EF;
  circuit-heavy paths also use standard hashes now, see `hash-migration-blake2-binius.md`*).
