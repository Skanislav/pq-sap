# Post-Quantum Stealth Addresses as an ERC-5564 Scheme Extension

<!--
The cohort proposal — as written, run, and scored after the fact. Superseded
D-033 (2026-10-29), which kept a second copy of the proposal inside this
repository so the upstream cohort copy could be refreshed from it: the upstream
file was a stale snapshot of the plan, not of the work, and maintaining two
texts meant every "the proposal says" statement was ambiguous. This document is
the single surviving copy; the cohort artifact is closed.

EDITING NOTE (2026-10-29, end of cohort): this document was written before the
work and is revised *after* it. Sections marked "As proposed" preserve what was
planned; sections marked "Outcome" record what exists, measured, with links to
the artifacts. Do not rewrite this back into a pre-project plan.
-->

## Retrospective in one paragraph

The project set out to specify, implement, benchmark, and test a post-quantum
stealth-address scheme as a new ERC-5564 scheme ID, and to write up a security
analysis. All five planned deliverables exist in the repository: an executable
Python spec that is the byte-level source of truth, versioned conformance
vectors with negative cases that an independent TypeScript implementation
replays byte for byte, a reference library (send, scan, viewing keys, proof of
possession), a cost report in which every figure names its provenance, and a
Lean 4 development with no `sorry`s and a machine-checked axiom audit. Two
things went beyond the plan and one thing narrowed it. Beyond: the ownership
side — blinded ML-DSA derivation, two zero-knowledge ownership statements, and
a live receive-and-spend on Sepolia through an ERC-4337 account (all listed as
stretch goals) — landed early and is now measured, so the stretch goal "cheaper
spending during the transition" is closed with numbers rather than prose. And
the security work produced a sharper claim than expected: the *key exchange* is
where a formal argument is tractable and where the harvest-now-decrypt-later
threat actually lands, while spending is a protocol problem. That is why the
scope narrowed, mid-project, to the key exchange and address derivation
(D-024): the ERC's subject became ML-KEM detection and sender-computable
destinations, with spending delegated to the account model.

What did not go to plan: the ERC text is not frozen. It remains human-written
and pre-freeze by decision (D-024), the commitment profile still needs its own
full-announcement privacy argument composed from the generic KEM results, and
the ML-DSA verifier that exists on-chain is a level-2 Dilithium2 profile, not
the ML-DSA-65 the scheme defaults to. Those are the honest open items.

## Motivation

Ethereum is preparing for the post-quantum transition well in advance: the EF
roadmap expects post-quantum signature schemes to become available on Ethereum
following the Hegotá hard fork and EIP-8141
(ethereum.org/roadmap/security/quantum-resistance, April 2026).

Stealth address cryptography is already widely used
([Fluidkey](https://www.fluidkey.com/), [Cloaked](https://www.clkd.xyz/),
[Umbra](https://umbraprivacy.com/), and other ERC-5564-based protocols) to
preserve privacy while keeping human-readable handles — it is much cheaper than
heavier privacy systems and offers better UX for compartmentalizing funds.

To display a balance, a wallet downloads the announcement logs and in linear
time checks a one-byte view tag to skip non-matching entries without decoding
everything. On a candidate match, it computes the shared secret `S = v·R`,
confirms the payment, and with the spending key converts it into the private key
controlling the address. All of this data is public and permanent: a future
quantum computer running Shor's algorithm can recover the viewing and spending
keys from it, deanonymizing every stealth payment ever made ("harvest now,
decrypt later", NIST IR 8547).

This project addresses that at the ERC level: a new scheme ID working against
the existing ERC-5564 announcer with no protocol changes. Meta-address
distribution and the ERC-6538 registry are outside the proposal's scope
(D-014 scope update, 2026-09-28): naming services or off-chain sharing can carry
the meta-address and the deployment binding. Recent discussions like Native
UTXOs presuppose exactly such an ERC-5564 scheme for their post-quantum,
key-only recipients. And the sender-names-the-address model constrains the
derivation constructions this project evaluates.

## Project description

### Proposed solution, and what it became

**As proposed.** Use lattice-based key encapsulation — Learning With Errors
(LWE) and its Module variant (MLWE), the basis of NIST's ML-KEM — for the
key-exchange step, and produce a new ERC-5564 extension: a post-quantum-ready
scheme ID. Per [ePrint 2025/112](https://eprint.iacr.org/2025/112), the LWE
approach *in some cases* brings an increase in parsing speed together with
future-proofing the Native UTXO design and its ERC-5564 use case.

The parsing trick: the errors mixed into the polynomial equations are easy for
the recipient to discover. After plugging in their real secret values, the error
falls out as a subtraction from the publicly broadcast value. Without the key,
separating the noise from the structure is the hard problem, for quantum
computers too.

**Outcome.** Implemented and measured. The announcement carries the 1,088-byte
ML-KEM-768 ciphertext as the ephemeral key plus a one-byte view tag; scanning is
one decapsulation per announcement with the full derivation only on a tag match.
The measured detection numbers are in the [cost report](research/cost-report.md):
44.31 µs per announcement for the Python client versus 27.50 µs for the DKSAP
EC baseline it replaces (1.61×), and 22.6 µs natively versus 27.6–27.9 µs — i.e.
native lattice scanning is moderately *faster* than the scheme ERC-5564 deploys
today. The paper's 3× headline was measured against Curvy; we deliberately do
not carry that comparison because DKSAP is what the ecosystem actually runs
(D-011).

### Research question: sender-side address derivation

**As proposed.** In the SECP256K1 scheme the sender builds the recipient's
one-time address from the meta-address and a shared secret
(`P = K + hash(S)·G`) without ever seeing the private key. That does not move
over cleanly to FIPS 204/205. An ML-DSA key *can* be shifted additively, but
unlike an EC point the shift grows the secret's norm (so the signer needs a
wider bound, `β' = τ·2η`) and it has to land on the rounded public key.
Hash-based keys cannot be rerandomized at all. Two constructions were
considered:

* **(A)** Borrow key-blinding techniques from the signature literature (Tor
  onion services use them) to shift an ML-DSA key by a value derived from the
  shared secret; the stealth address is the hash of the blinded verification
  key.
* **(B)** Use ML-KEM only for the shared secret and have the recipient derive a
  fresh standardized keypair from it — standardized operations only, but the
  sender cannot compute the address, so the announcement flow changes.

**Outcome: the answer changed the scope, and that is the project's main
finding.** Construction A works and is proved: the blinding correctness
identity, the widened bound `β' = 2τη`, and the acceptance/rejection argument
are machine-checked in Lean with no `sorry`s, the signatures verify under stock
FIPS 204 verifiers (dilithium-py, liboqs) and under the ZKNOX verifier deployed
on Sepolia, and the derivation is implemented in Python and TypeScript with
deterministic vectors. But a third route turned out to be better aligned with
the threat: because harvest-now-decrypt-later hits *confidentiality*, the urgent
piece is detection, and detection does not need the spending key at all. So the
meta-address carries a **32-byte commitment** to the spending key rather than
the key material itself:

```
meta-address = 0x02 ‖ spend_key(32) ‖ ML-KEM-768 ek(1,184)      = 1,217 B
opener       = SHA-256("pq-stealth/…/open/v0" ‖ ss)
commitment   = keccak256("pq-stealth/…/commit/v0" ‖ spend_key ‖ opener)
address      = CREATE2(factory, 0, initcode(commitment, …))    (deployment binding)
```

That drops the meta-address from 5,633 B to 1,217 B, makes receive-time data
hide the spending scheme entirely, and leaves *what authorizes a spend* to the
account model — today's accounts, a frame transaction, a native key, or an
aggregation scheme later (D-024). Construction A survives as address form
`0x01` for accounts that want a per-address standard ML-DSA key, with its
`rho`-exposure linkability stated (D-027). Construction B is documented as a
separate account-transfer design (D-021).

### Threat model

Ethereum's own [PQ roadmap](http://pq.ethereum.org) points out that
harvest-now-decrypt-later hits confidentiality, not ownership: recording
announcements today does not let anyone steal funds later. So the urgent piece
is the ML-KEM detection layer, which protects who-paid-whom permanently.
Spending is a live threat, and it migrates through account abstraction whenever
a quantum computer actually shows up, which is the path the EF roadmap takes
anyway. The threat model was unchanged by the work; the work is what confirmed
it should drive the scope.

## Deliverables — planned versus delivered

| Deliverable (as proposed) | Outcome | Where |
| --- | --- | --- |
| Draft spec for the new scheme ID: meta-address encoding, announcement format, key derivation | Executable spec + technical reference. Normative text **not frozen**: format `0x02` is implemented, whether `0x01` is also normative is open, and the ERC text is human-written under D-024 | [`TECHNICAL_SPEC.md`](TECHNICAL_SPEC.md), [`commit.py`](../python/pq_stealth/commit.py) |
| Test vectors as versioned JSON, negative cases included | Delivered for five profiles/schemes (Construction A, classical hybrid, commitment, ML-DSA-44 commit, EIP-8164 native key); regenerating any of them is byte-identical in CI; an independent TypeScript port replays each byte for byte | [`python/vectors/`](../python/vectors), [`js-client/test/`](../js-client/test) |
| Reference library: scanning, viewing keys, proof of possession | Delivered in Python (authoritative) and TypeScript (independent). Primitives from audited/spec-faithful libraries, cross-checked against liboqs; only the protocol layer is ours | [`python/pq_stealth/`](../python/pq_stealth), [`js-client/src/`](../js-client/src) |
| Security analysis | Delivered as a scoped argument, not a total one: Lean 4 / VCVio games for KEM anonymity and unlinkability, algebraic invariants, plus a written analysis that separates what is proved from what is assumed. The concrete commitment/CREATE2 composition remains open | [`SECURITY_ANALYSIS.md`](SECURITY_ANALYSIS.md), [`lean/PqStealth/`](../lean/PqStealth) |
| Benchmarks as a runnable harness + cost report | Delivered: scan/KEM/view-tag/registration sweeps, on-chain gas model, spend gas per route, each with provenance and dated price anchors | [cost report](research/cost-report.md), [`python/benchmarks/`](../python/benchmarks) |

### Benchmarks, in the numbers that matter

* **Scanning.** Fitted slopes over a 64× registry range: 44.31 µs/announcement
  (PQ, Python + liboqs) vs 27.50 µs (DKSAP), R² > 0.999 both. The
  decaps+view-tag loop alone is ~19 µs, so the lattice primitive is cheaper than
  ECDH; the overhead is the ~N/256 full derivations in interpreted Python, which
  a wallet does in native code. Native: 22.6 µs vs 27.6–27.9 µs. A 1M
  announcement registry projects to ~44 s single-core, embarrassingly parallel.
* **Announcement.** 67,580 gas measured on the Sepolia fork — the **EIP-7623
  calldata floor binds** (standard cost would be 52,446). DKSAP models at
  27,342 gas, so PQ is 2.5× on L1, and the ratio is bytes, not compute. On L2 the
  same announcement's marginal L1 data cost is **~$0.004** as an EIP-4844 blob
  versus ~$1.35 as calldata (dated anchors: ETH $3,200, L1 8 gwei, blob 1 gwei).
* **Meta-address.** 5,633 B (`0x01`) → **1,217 B** (`0x02`): naive registration
  3.79 M → ~0.85 M gas, or ~264 k via SSTORE2. One-time per recipient, and
  optional if the meta-address is distributed off-chain.
* **Spend.** Per spend, at the same boundary: SPHINCS-C13 direct **188,092**;
  preimage ZK **2.94 M** (forge) / **3.54 M** live; C13-in-ZK 4.17 M live; ML-DSA
  through ERC-7913 **13.68 M** (14.91 M before moving the key-dependent NTT to
  setup); EIP-8164 native key **50,000** (proposed charge, no client
  implementation). A Sepolia `handleOps` hybrid spend is ~8.35 M whole-transaction
  (blinded ML-DSA verifying on-chain) and was sponsored live by a paymaster.
* **Blinded signing** is the one real client-side regression: the `2η`-widened
  secrets cost ~4.5× ML-DSA's rejection rounds at L3 (mean 24.8 vs 5.5), and the
  penalty is worst at the default level because `η = 2/4/2` across
  ML-DSA-44/65/87.

## Stretch goals — closed

**As proposed:** measure the speed, gas costs and end-to-end implementation of a
stealth-address protocol using ERC-4337 with post-quantum key exchange and a
zero-knowledge ownership proof, for cheaper spending during the transition.
Not part of the core deliverable.

**Outcome: delivered, and it stayed out of the core deliverable on purpose.**
The measurements exist — two end-to-end receive→scan→spend runs on real chains,
two zero-knowledge ownership statements, and a gas table per route — but they
are evidence for a *separate* claim (what a spend can cost and reveal), not
requirements of the key-exchange ERC. A wallet that implements receive/scan
never touches any of this code. Full record with provenance:
[**stretch-goal report**](research/stretch-goal-report.md).

What the measurements say, briefly:

* **ERC-4337 works today.** On Sepolia, reusing the already-deployed ZKNOX
  hybrid account, the stealth address is the counterfactual account address, and
  it was funded, deployed and spent from — self-bundled (~8.35 M) and, live,
  gasless through a paymaster (~9.3 M sponsored,
  [tx `0x4cde53ee…d948f4`](https://sepolia.etherscan.io/tx/0x4cde53eef9027514cbf181f2f0baf0980dc49cd4af28cdc53412f986bad948f4)).
  The deployed account is hybrid (ECDSA **and** ML-DSA-44); a PQ-only variant
  runs against a locally deployed factory instance on a fork.
* **A frame transaction works better.** On the frames testnet, one `0x06`
  transaction received and announced in 295,489 gas, and a later one spent with
  `[VERIFY(sponsor), createAccount, executeFrame]` authorized by a proof made
  **in the browser** — 3.54 M execution gas for proof verify plus transfer, no
  signature, no key on chain. Honest limits: the 26.3 kB verifier exceeds
  EIP-170 (the testnet does not enforce it; mainnet would need EIP-7907), and
  the UltraHonk backend is **not post-quantum sound** — the statement is,
  the proof system is not.
* **"Cheaper" needed qualification.** Against ML-DSA on the EVM the ZK route is
  ~3.9× cheaper; against a direct hash-based signature it is 19× *more*
  expensive, and it buys unlinkability rather than gas. The genuinely cheap PQ
  spend is protocol-native (EIP-8164, EIP-8288 aggregation), which is a
  protocol change, not something a scheme ID can deliver.

**Verifiable announcement discovery** (EIP-7745 / EIP-8304, under the Pureth
umbrella) was the other stretch goal. Outcome: not pursued as an integration.
EIP-8304 was deferred by the Fellowship and no proving-capable index exists on
a devnet to integrate against. A sizing PoC is committed — an inclusion proof
for 12 announcements in a 256-block window measures 1,486 B, and the receipt
shrinks from 13,308 B to 1,109 B (≈12×) if announcements are retrieved by view
tag rather than by full log payload. The sub-linear-scan question it was tied to
remains open: view tags cut the constant, not the asymptotics.

## What we would do differently

* **Start from the threat model, not the construction.** Construction A was the
  right thing to build to *learn* whether a lattice key can be blinded for a
  stealth address — it can, and that is proved. But the commitment meta-address
  (`0x02`) would have been the right thing to *ship*, and it was reachable from
  the start once detection was recognized as the priority. The detour produced
  real results (Lean invariants, a working blinded signer), so it was not wasted;
  it was just not on the critical path.
* **Freeze the ERC text earlier.** The single largest remaining risk is that the
  normative text does not exist yet. Everything else in the package is
  implemented and reproducible; the text is what a reviewer needs and it is
  deliberately human-written and unfrozen.
* **Keep one number, one provenance.** Two figures in circulation were stale
  relative to committed data (the native scan slope, and an "exactly to the gas"
  claim whose measurement predated the scheme-ID change), and the model had been
  reporting the PQ measurement on the DKSAP baseline row. All three are fixed as
  of 2026-10-29; the lesson is that the provenance column must be re-checked
  whenever an input moves, not only when the model moves.

## If a similar proposal arises again: contribute there

If another team proposes a post-quantum stealth-address scheme — or a PQ
privacy primitive of any kind — the highest-value move is **not to build a
second implementation in parallel.** This project had to build one because
nothing existed that could answer "what does the sender compute, and what does
the scanner check?" for a lattice key. That answer now exists, with vectors,
proofs, and measured costs. A new effort should spend its time where the
remaining risk actually is:

1. **The security composition.** The generic KEM results are in place; the
   concrete commitment/CREATE2 privacy argument is not. That is a cryptography
   writing and proof problem, and it is the ERC's gate.
2. **The normative text and its review.** An ERC needs a maintained human-written
   document and a Magicians discussion. Reviewing and contributing to an existing
   scheme's text is worth more than an independent seventh design.
3. **Protocol-native spending.** EIP-8164 native keys and EIP-8288 aggregation
   are the only routes where a PQ spend costs tens of thousands of gas. Nothing
   the application layer does beats them. Contributing test vectors, cost
   measurements, or a reference verifier to those efforts is more leveraged than
   another account contract.
4. **Client-side scanning at scale.** The scan is linear and every wallet pays
   it. A verifiable log index (EIP-7745/8304) or a sub-linear discovery scheme is
   a bigger win than shaving a few microseconds off a decapsulation.

Concretely: adopt the conformance vectors and the deployment-binding profile
from this repository rather than inventing new ones, and treat the
[stretch-goal report](research/stretch-goal-report.md)'s per-route gas
table as the baseline to beat, not to re-measure. Independent implementations
are still valuable — that is what cross-implementation vector replay is *for* —
but they should target byte-level agreement with a frozen spec, not a new spec.
The one thing worth rebuilding independently without hesitation is the
**security analysis**: a second pair of eyes on the commitment composition is
the contribution the project needs most.

## Specification

**As proposed.** Take the paper by the [folks from Serbia](https://eprint.iacr.org/2025/112)
and its reference implementation (`0x3327/pq-sap`, Rust) as the starting point,
and complement it with a real ERC-5564 scheme ID, a key derivation that lands on
a standardized signature scheme, conformance vectors, and execution benchmarks.

**Outcome.** The paper's scan harness was reproduced and its numbers checked
against a DKSAP baseline rather than Curvy; the scheme was implemented from
scratch around ML-KEM rather than extended from the Rust reference, because the
meta-address format, the commitment derivation and the deployment binding are
the deliverable and had no counterpart there. The final flow, as implemented
(`0x02`, the commitment profile):

```python
# --- Setup (recipient) -------------------------------------------------
sk                    = 32-byte spending secret
spend_key             = keccak256("pq-stealth/preimage/key/v0" ‖ sk)      # 32 B
ek, dk                = MLKEM768.keygen()                                 # viewing key
meta_address          = 0x02 ‖ spend_key ‖ ek                             # 1,217 B
# published via ENS, a naming service, or off-chain sharing (ERC-6538 out of scope)

# --- Send (sender) -----------------------------------------------------
spend_key, ek         = decode(meta_address)
ct, ss                = MLKEM768.encaps(ek)                               # ct = ephemeral key
opener                = SHA-256("pq-stealth/preimage/open/v0" ‖ ss)
commitment            = keccak256("pq-stealth/preimage/commit/v0" ‖ spend_key ‖ opener)
stealth_address       = CREATE2(factory, 0, initcode(commitment, verifier, frame_ctx))
view_tag              = SHA-256(ss)[0:1]
announcer.announce(SCHEME_ID, stealth_address, ct, view_tag)
send_assets(stealth_address)

# --- Scan (recipient, or any viewing-key holder) -----------------------
for ann in announcements_since(last_scan):
    ss_i = MLKEM768.decaps(dk, ann.ct)
    if SHA-256(ss_i)[0:1] != ann.view_tag:
        continue                          # cheap rejection, ~255/256 of traffic
    opener_i     = SHA-256(OPEN ‖ ss_i)
    commitment_i = keccak256(COMMIT ‖ spend_key ‖ opener_i)
    if CREATE2(...commitment_i...) == ann.stealth_address:
        record_payment(ann, commitment_i)

# --- Spend (recipient only) --------------------------------------------
# Whatever the account bound to `commitment` accepts. Implemented options:
#   UltraHonk proof of (sk, opener)  (browser-provable; backend not PQ-sound)
#   UltraHonk proof of a C13 signature opening the commitment
#   direct C13 signature (reveals the key, hence linkable)
#   ML-DSA-44 signature with a committed key (reveals the key, linkable)
#   EIP-8164 native key (Draft, no client yet)
# Construction A (`0x01`) instead blinds an ML-DSA key per payment and spends
# with the blinded key through ERC-7913/4337/8141.
```

**Notes, revised.** The viewing key alone detects and views payments; spending
needs the spending secret too — the standard viewing/spending separation, now
enforced by the meta-address layout rather than by convention.

Because the shared secret itself, not its hash, derives the address, view tags
longer than 1 byte stay safe. The paper's numbers say it barely matters: a
full-hash tag bought about 0.7% over 1 byte at 1M announcements. So 1 byte is the
default, and a view-tag sweep (`viewtag_sweep.py`) confirms it for native
clients while showing longer tags help only when derivation is the bottleneck.

ML-KEM-768 by default, parameter-agile across 512/768/1024. On-chain you are
stuck with whatever verifier is deployed, which today is a level-2 Dilithium2
profile, not the ML-DSA-65 default — the reason every spend row in the cost
report is labelled with its profile and none of it transfers to ML-DSA-65.

Decisions the spec still has to close, in order: (1) whether `0x02` is the only
normative meta-address or `0x01` is also offered, with its `rho` linkability
stated; (2) the account profiles — `sphincs-c13-commit/v0`, `preimage/v0`,
`ml-dsa-44-commit/v0` are implemented, more can exist; (3) parameter level,
given the deployed-verifier reality; (4) announcement encoding details.

## Roadmap — as run, not as planned

The plan below was written before the work; it is preserved with the actual
outcome of each item.

* **Benchmark reproduction + key-blinding bibliography — done.** The paper's
  scan numbers were reproduced and checked against DKSAP; the key-blinding
  reading (Tor v3 blinding, Eaton et al. Latincrypt 2021 and citing work) is
  recorded in [`key-blinding-bibliography.md`](research/key-blinding-bibliography.md),
  which also states the open related-key problem for lattice signatures.
* **v0 spec + conformance vectors — done, not frozen.** Executable Python spec
  and versioned JSON vectors with negatives exist for five profiles; what
  remains is the review round and the freeze, and the freeze is blocked on the
  ERC text, not on the code.
* **Security analysis — delivered, scoped.** Unlinkability across payments, the
  sender-cannot-derive-the-spending-key property, viewing/spending separation,
  and the widened-`z` distribution at `β' = τ·2η` are analysed; the algebraic
  identities and game-based bounds are machine-checked in Lean 4 with VCVio. The
  concrete commitment-profile privacy composition is explicitly *not* closed —
  see [`SECURITY_ANALYSIS.md`](SECURITY_ANALYSIS.md) and
  [`commitment-announcement-privacy.md`](research/commitment-announcement-privacy.md).
* **Reference library — done.** Python (authoritative) plus a TypeScript
  scanning client, both against the vectors, plus a small `StealthKeyExchange.sol`
  with a dependency-free Lean model and an on-chain vectors replay.
* **Benchmarks + cost report — done.** [`cost-report.md`](research/cost-report.md),
  assembled from committed harness outputs with dated anchors.
* **ERC draft + wrap-up — remaining.** The text is human-written and unfrozen
  (D-024); submission packaging (portable checker, licence scope, discussion
  link) is mapped in
  [`erc-submission-gap-analysis.md`](research/erc-submission-gap-analysis.md).
* **Stretch goals — one closed with measurements, one not pursued.** See above:
  the ERC-4337/ZK spend demonstration is measured end to end and reported; the
  verifiable-discovery integration had no devnet to integrate against.

## Possible challenges — with hindsight

* **Construction A may not survive its own security analysis.** It survived the
  parts that can be checked: the blinding identity, the widened bound and the
  rejection argument are proved in Lean, the signatures verify under stock FIPS
  204 verifiers and under the deployed ZKNOX verifier, and the derived key signs
  and spends on chain. What is *not* closed is related-key signature security
  under blinding — active research — and the scheme now discloses `rho` in every
  blinded public key, which is an identifying event on full-key disclosure
  (D-027). Mitigating this risk in practice is why the commitment format, not
  Construction A, became the default.
* **The protocol surface moves.** This played out exactly as feared: the only
  post-quantum verifier deployed on Sepolia is a level-2 Dilithium2 profile, EIP-8141
  is still a Draft, and EIP-8164 exists as text without a client. The scheme did
  not lean on any of it, which is why the key exchange shipped and the spend
  routes are labelled experiments.
* **Announcements are ~1 KB instead of 33 bytes.** Confirmed and quantified:
  2.5× on L1 because the EIP-7623 floor prices bytes, ~$0.004 marginal L1 data on
  a blob-posting L2.
* **Scanning is linear in registry size.** Confirmed; view tags cut the constant
  only. Today's registries make it a non-issue (the canonical announcer's entire
  history scans in ~9 ms); at 1M announcements it is ~44 s single-core, which is
  parallelizable but not solved.
* **We don't roll our own crypto.** Held, with two stated exceptions: the
  TypeScript scanning client re-implements the ML-DSA polynomial layer (the
  audited JS library doesn't expose it), and the Noir circuits implement the
  ownership relation directly. Both are validated against the conformance
  vectors, whose negative cases do the heavy lifting.

## Goal of the project — assessed

Success was defined as five things existing publicly. Against that bar:

1. **An ERC draft with a declared ERC-5564 scheme ID** — *partially*. Scheme ID
   `2` is declared and used on-chain in every test; the normative ERC text is
   not written to freeze quality and is deliberately left to a human author
   (D-024).
2. **Conformance vectors, negative vectors included** — *met*. Five
   vector sets, deterministic, with negatives, replayed by an independent
   TypeScript implementation and by the Solidity exchange contract; regeneration
   is byte-identical in CI.
3. **A reference library passing them: sender flow, scanning, viewing keys,
   proof of possession** — *met* in Python and TypeScript.
4. **Security analysis of the chosen derivation, with Lean 4 / VCVio proofs and
   the rejection rationale for the alternative** — *met for the algebraic and
   game-theoretic layers; open at the composition layer*. The VCVio development
   is sorry-free, axiom-audited in CI, and the widened-`z`/rejection rationale
   for Construction A is both proved and measured (24.8 vs 5.5 rejection rounds).
5. **Benchmarks and the cost report against the elliptic-curve and lattice
   baselines** — *met*, with provenance per row and an explicit refusal to
   quote the Curvy baseline or the "Fireblocks 1.23 M" figure, neither of which
   could be grounded.

## Collaborators

### Fellows

Skas

### Mentors

[Tamaghna](https://github.com/RazorClient) expressed interest in contributing

## Resources

**Papers and articles**

* Mikić, Srbakoski, Praška — _Post-Quantum Stealth Address Protocols_, ePrint 2025/112: [https://eprint.iacr.org/2025/112](https://eprint.iacr.org/2025/112)
* Mikić, Srbakoski, Praška — *More Efficient Stealth Address Protocol* (hybrid Curvy/MLWE, deliberately not quantum-secure to stay Ethereum-compatible — the gap this project closes): [https://arxiv.org/abs/2504.06744](https://arxiv.org/abs/2504.06744)
* asanso — *Towards practical post quantum stealth addresses* (CSIDH-based, ethresear.ch, April 2023 — earliest PQ stealth design for Ethereum; isogeny-based, pre-standardization): [https://ethresear.ch/t/towards-practical-post-quantum-stealth-addresses/15437](https://ethresear.ch/t/towards-practical-post-quantum-stealth-addresses/15437)
* *Post-Quantum Threats to Ethereum Privacy* (ethresear.ch, March 2026 — harvest-now-decrypt-later and why privacy migration is more time-sensitive than authentication migration): [https://ethresear.ch/t/post-quantum-threats-to-ethereum-privacy/24450](https://ethresear.ch/t/post-quantum-threats-to-ethereum-privacy/24450)
* Eaton et al. — *Post-Quantum Key-Blinding for Authentication in Anonymity Networks*, Latincrypt 2021 (primary prior art for construction A)
* Grubbs, Maram, Paterson — *Anonymous, Robust Post-Quantum Public Key Encryption*, Eurocrypt 2022 (KEM anonymity, the property detection unlinkability reduces to)
* Maram, Xagawa — *Post-Quantum Anonymity of Kyber*, PKC 2023 (settles ANO-CCA for Kyber; the route the unlinkability analysis follows)
* Lyubashevsky — *Basic Lattice Cryptography: The concepts behind Kyber (ML-KEM) and Dilithium (ML-DSA)* (tutorial, ePrint)
* Wahrstätter et al. — _BaseSAP: Modular Stealth Address Protocol for Programmable Blockchains_, IEEE TIFS 2024
* Mikić, Srbakoski — *Elliptic Curve Pairing Stealth Address Protocols* (Curvy): [https://arxiv.org/abs/2312.12131](https://arxiv.org/abs/2312.12131)
* Buterin — _An incomplete guide to stealth addresses_: [https://vitalik.eth.limo/general/2023/01/20/stealth.html](https://vitalik.eth.limo/general/2023/01/20/stealth.html)
* *Native UTXOs on Ethereum* (ethresear.ch, July 2026): [https://ethresear.ch/t/native-utxos-on-ethereum/25368](https://ethresear.ch/t/native-utxos-on-ethereum/25368)
* *VCVio: Verified Cryptography in Lean via Oracle Effects and Handlers* ePrint 2026/899: [https://eprint.iacr.org/2026/899.pdf](https://eprint.iacr.org/2026/899.pdf)

**Standards and specifications**

* ERC-5564 — Stealth Addresses: [https://eips.ethereum.org/EIPS/eip-5564](https://eips.ethereum.org/EIPS/eip-5564)
* ERC-6538 — Stealth Meta-Address Registry: [https://eips.ethereum.org/EIPS/eip-6538](https://eips.ethereum.org/EIPS/eip-6538) (out of scope, D-014)
* ERC-7913 — Signature Verifier abstraction (the spend boundary used by every account route here): [https://eips.ethereum.org/EIPS/eip-7913](https://eips.ethereum.org/EIPS/eip-7913)
* EIP-8141 — Frame Transactions (Draft): [https://eips.ethereum.org/EIPS/eip-8141](https://eips.ethereum.org/EIPS/eip-8141)
* EIP-8164 — Native Key Delegation for EOAs (Draft, no client implementation): [https://eips.ethereum.org/EIPS/eip-8164](https://eips.ethereum.org/EIPS/eip-8164)
* EIP-8288 — Signature and proof aggregation (Draft): [https://eips.ethereum.org/EIPS/eip-8288](https://eips.ethereum.org/EIPS/eip-8288)
* NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA); NIST IR 8547 (PQC transition)
* Tor rend-spec-v3, key-blinding appendix (the deployed Ed25519 blinding design)
* Ethereum post-quantum cryptography roadmap: [https://ethereum.org/roadmap/security/quantum-resistance/](https://ethereum.org/roadmap/security/quantum-resistance/) (April 2026)

**Implementations and benchmarks**

* `0x3327/pq-sap` — ePrint 2025/112 reference implementation and scan benchmarks (Rust): [https://github.com/0x3327/pq-sap](https://github.com/0x3327/pq-sap)
* `ethereum/kohaku` `packages/pq-account` — ERC-4337 post-quantum accounts (ZKNOX ML-DSA/Falcon verifiers, deployed on Sepolia and Arbitrum Sepolia); the spend route used in this project's live run: [https://github.com/ethereum/kohaku/tree/master/packages/pq-account](https://github.com/ethereum/kohaku/tree/master/packages/pq-account)
* PQClean / liboqs and the pq-crystals reference code — audited ML-KEM/ML-DSA implementations the library binds to
* `GiacomoPope/kyber-py`, `dilithium-py` — spec-faithful Python implementations, used for vector generation and cross-checking
* ScopeLift stealth-address-sdk / Umbra and Fluidkey deployments — DKSAP baseline behavior and announcer usage in production

**This project's artifacts**

* [Technical reference](TECHNICAL_SPEC.md) · [ERC evidence map](ERC_EVIDENCE.md) · [security boundaries](SECURITY_ANALYSIS.md) · [decision log](DECISIONS.md) (D-001–D-033)
* [Cost report](research/cost-report.md) · [stretch-goal report](research/stretch-goal-report.md) · [submission roadmap](research/erc-submission-gap-analysis.md)
* [Python reference + vectors](../python) · [TypeScript client](../js-client) · [demo UI](../ui) · [Lean proofs](../lean) · [Noir circuits](../noir)
