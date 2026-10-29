# Post-Quantum Stealth Addresses

A proposed post-quantum stealth-address scheme for Ethereum, targeting a new
[ERC-5564](https://eips.ethereum.org/EIPS/eip-5564) scheme ID and working
against the deployed ERC-5564 announcer with no protocol changes.
Meta-address distribution (naming services, off-chain sharing) and the
ERC-6538 registry are outside the proposal's scope (D-014 scope update,
2026-09-28).

Repository: <https://github.com/Skanislav/pq-sap> ·
Docs site: <https://skanislav.github.io/pq-sap>

- **Detection** — ML-KEM-768 (FIPS 203). The announcement's ephemeral key is a
  KEM ciphertext; the shared secret drives a one-byte view tag and the address
  derivation. This is the part "harvest now, decrypt later" threatens, so it is
  the priority.
- **Address derivation** — the commitment format (`0x02`) pairs a 32-byte
  spending-key commitment with the ML-KEM viewing key: **1,217 bytes** total.
  The sender derives a fresh commitment and account address using the shared
  secret and an agreed deployment configuration, without learning the spending
  secret. Construction A (`0x01`, 5,633 bytes) remains available for accounts
  using a per-address blinded ML-DSA key. Whether `0x02` becomes the only
  normative format remains a decision for the ERC draft (D-024).
- **Spending** — delegated to the account model. The browser demo proves
  knowledge of a spending secret and commitment opener (D-025). Its current
  UltraHonk backend is **not post-quantum sound**. Direct SPHINCS-C13,
  blinded ML-DSA, and a direct ML-DSA-44 committed-key profile
  ([D-027](docs/ml-dsa-commit-profile.md), local contract path only) provide
  separate implementation evidence, with their own privacy and security
  boundaries; the direct routes reveal the key at spend time.

The proposal's focus is **ML-KEM-secured discovery and sender-computable
addresses under existing ERC-5564 announcements**. Spending integrations have
additional account and network requirements. See the
[EIP-8288 summary](docs/research/eip-8288-summary.md) for a prospective
aggregation route and the [security analysis](docs/SECURITY_ANALYSIS.md) for
the current key-exchange review boundaries. Start with the
[ERC evidence map](docs/ERC_EVIDENCE.md); spending specialists can follow the
[separate research guide](docs/SPENDING_RESEARCH.md).

This repository is the artifact trail of our EPF cohort work: the scheme we
specified, the vectors it generates, the checks we ran, and the
[decision log](docs/DECISIONS.md) recording why. Related external proposals are
not mirrored here as code or text ([D-032](docs/DECISIONS.md)). ERC-8441 is
**not prior art**: its first public draft was committed 2026-08-30 and its ERC
merged 2026-10-29, both after this project's implementation, vectors, and
proofs existed (first commits 2026-08-06/07), so it is a concurrent design —
compared in review, not something we built on or lagged behind.

## Layout

| Path | What |
| --- | --- |
| [`docs/erc-draft.md`](docs/erc-draft.md) | Reserved for human-written ERC text (target scheme ID `2`) |
| [`docs/TECHNICAL_SPEC.md`](docs/TECHNICAL_SPEC.md) | Working technical specification |
| [`docs/DECISIONS.md`](docs/DECISIONS.md) | Dated ADR log of design decisions |
| [`python/`](python/) | Executable Python spec, reference library, test vectors, benchmarks |
| [`js-client/`](js-client/) | TypeScript scanning client that reproduces the vectors byte for byte |
| [`ui/`](ui/) | Demo web UI (Vite + React): receive, scan, and spend (EOA + ERC-4337 routes) |
| [`docs/ERC_EVIDENCE.md`](docs/ERC_EVIDENCE.md) | Required claim evidence, relevant proofs, and open commitment-profile composition |
| [`docs/research/cost-report.md`](docs/research/cost-report.md) | Measured L1/L2 announcement and spend gas, registration, and scanning costs |
| [`docs/SPENDING_RESEARCH.md`](docs/SPENDING_RESEARCH.md) | Optional account, signature, and ZK research |
| [`lean/`](lean/) | Generic KEM results, Construction A research, and maintainer tooling |
| [`wiki/`](wiki/) | Mirrored documentation site source |

## Status

The reference libraries, deterministic vectors for both address formats,
generic KEM results, Construction A security analysis, and browser ownership-proof
demo exist. Python defines the byte-level behavior; TypeScript reproduces the
vectors; Lean supports specifically scoped mathematical statements.

Next: review the security boundaries of each route, prepare a self-contained
vector checker and ERC assets, and bring the proposal to community review.
The ERC text is human-written only under D-024 and is not frozen. See the
[submission gap analysis](docs/research/erc-submission-gap-analysis.md).

The conformance vectors and checker are intended to enter the
[`ethereum/ERCs`](https://github.com/ethereum/ERCs) asset tree under CC0 when
the PR is opened.

## AI assistance

Parts of this repository were drafted with AI assistance. The disclosure is
precise rather than gestural, because a reader deciding how much to trust a
lemma or a vector deserves to know what produced it:

- **Humans are the authors** of every project-facing specification, the ERC
  text (D-024), and every security decision in
  [the decision log](docs/DECISIONS.md). No AI tool is listed as a co-author,
  and no AI tool signs off on a claim.
- **The models used were Anthropic's Claude.** Git trailers record the exact
  identifiers, so the list below is mechanical, not recalled: Claude Fable 5
  (35 commits), Claude Fable 5.1 (18), Claude Opus 4.8 (15), and Claude Opus 5
  with 1M context (2).
- **Scale.** 70 commits carry a
  `Co-Authored-By: Claude` trailer, spanning 2026-08-06 to 2026-09-10; three
  commits are authored as `Claude <noreply@anthropic.com>`. No commit after
  2026-09-10 carries an AI trailer.
- **Where it was used:** documentation drafting, test scaffolding, exploratory
  code, wiki/sync plumbing, and audit passes over the tree. The conformance
  vectors are *generated* from the Python reference — determinism, not trust in
  a model, is what makes them checkable — and every implementation claim is
  backed by a run recorded in this repository.

Read the code and the vectors, not the prose: the vectors are the contract, the
Lean proofs are audited for axioms and `sorry` on every build, and the tests
replay byte-for-byte across Python, TypeScript, and Solidity. Where that
machinery does not cover a claim, the claim is marked as an assumption or an
open obligation rather than asserted — see
[`docs/ERC_EVIDENCE.md`](docs/ERC_EVIDENCE.md).

To audit the assist rate yourself:

```sh
git log --format='%b' | grep -c 'Co-Authored-By: Claude'           # 70 co-authored commits
git log --format='%b' | grep -oE 'Co-Authored-By: Claude [^<]+' | sort | uniq -c
#   35 Co-Authored-By: Claude Fable 5
#   18 Co-Authored-By: Claude Fable 5.1
#   15 Co-Authored-By: Claude Opus 4.8
#    2 Co-Authored-By: Claude Opus 5 (1M context)
```

## License

Licensed under the [MIT License](LICENSE).

## Dependency license note

The reference implementation builds on widely used, permissively licensed
cryptography libraries. Runtime and benchmark dependencies include:

- `kyber-py` (ML-KEM): MIT / Apache-2.0
- `dilithium-py` (ML-DSA): MIT
- `pycryptodome` (Keccak/SHA-256): BSD-2-Clause / public domain
- `liboqs-python`: MIT (optional audit backend)
- `coincurve` (secp256k1): MIT / Apache-2.0 (optional, classical hybrid benchmark)
- `@noble/post-quantum`: MIT
- `viem`: MIT
- `@openzeppelin/contracts`: MIT

There is no GPL or other copyleft dependency in the hot path. The ERC
submission still intends to place the conformance vectors and checker in the
[`ethereum/ERCs`](https://github.com/ethereum/ERCs) asset tree; the ERC repo
uses its own CC0 process for the submitted spec and assets.
