# Post-Quantum Stealth Addresses

ML-KEM key exchange and sender-computable stealth destinations under existing
ERC-5564 announcements (the ERC-6538 registry is out of scope). The proposed ERC focuses on detection privacy
and address derivation. Spending belongs to the selected account model.

The implemented commitment meta-address is **1,217 bytes**: version, a 32-byte
public spending-key value/commitment, and an ML-KEM-768 viewing key. The sender
encapsulates, derives a commitment, and computes the destination using an agreed
deployment binding. The scanner decapsulates, checks the view tag, and confirms
the derived address. D-024 leaves final normative format selection open.

## Review the key-exchange proposal

1. [Technical reference](TECHNICAL_SPEC.md): exact implemented fields, domains,
   deployment inputs, and receive/scan behavior.
2. [ERC evidence](ERC_EVIDENCE.md): vectors, relevant proofs, and what remains
   to justify for the commitment profile.
3. [Security overview](SECURITY_ANALYSIS.md): confidentiality, anonymity,
   full-announcement composition, and adversary boundaries.
4. [Submission roadmap](research/erc-submission-gap-analysis.md): portable
   checker and asset-package work.

[Python](../python/README.md) is the byte-level source of truth;
[TypeScript](../js-client/README.md) independently replays its vectors.
Generic KEM proofs provide conditional support. They do not yet supply a
complete privacy proof for the concrete commitment/CREATE2 flow.

## Supporting research and tools

[Spending research](SPENDING_RESEARCH.md) covers Construction A's blinded
ML-DSA, C13, account routes, and ZK demos. The browser preimage demo is
implemented, but its current UltraHonk backend is not PQ-sound.
[EIP-8288](research/eip-8288-summary.md) is a prospective integration assessment.

The [Lean overview](../lean/README.md) separates KEM foundations from spending
proofs and classical comparisons. [Maintainer tooling](../lean/docs/tooling.md)
and the generated theorem browser serve the whole research tree; they are
not additional ERC implementation requirements.

The [current plan](../plan.md) and [decision log](DECISIONS.md) track scope.
The ERC text remains human-written and pre-freeze. This site mirrors repository
sources; edit those sources and run `pnpm sync` in `wiki/`.
